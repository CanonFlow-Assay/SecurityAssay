using System.Collections.Immutable;
using System.Globalization;
using System.Text.Json.Nodes;
using CanonFlow.Evidence;
using CanonFlow.Security.Domain;

namespace CanonFlow.Security.Adapters;

public static class Evaluator
{
    public static async Task<Receipt> Scan(string root, string manifestPath, string policyPath, string chainPath, string catalogPath,
        string bundle, DateTimeOffset asOf, string output, int timeoutSeconds = 120)
    {
        output = Path.GetFullPath(output); bundle = Path.GetFullPath(bundle);
        if (Directory.Exists(output)) throw new InvalidDataException("Choose a fresh evidence directory; prior attempts are retained.");
        Directory.CreateDirectory(output);
        if (OperatingSystem.IsLinux()) File.SetUnixFileMode(output, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        var findings = ImmutableArray.CreateBuilder<SecurityFinding>(); var missing = ImmutableArray.CreateBuilder<string>();
        var failures = ImmutableArray.CreateBuilder<string>(); var observations = ImmutableArray.CreateBuilder<ToolObservation>();
        var journal = new JsonArray(); var started = DateTimeOffset.UtcNow;
        var evaluatorHash = JsonIO.ShaFile(typeof(Evaluator).Assembly.Location); var coreHash = JsonIO.ShaFile(typeof(EvidenceDecisions).Assembly.Location);
        var inputHash = JsonIO.Digest(new JsonArray()); var manifestHash = ""; var policyHash = ""; var catalogHash = ""; var chainHash = "";
        var profile = "unresolved"; ImmutableArray<FilePin> files = []; JsonNode sbom = JsonIO.Parse("""{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[]} """);
        var vulnerabilityInput = sbom.DeepClone();
        InputSnapshot? snapshot = null; var toolStarted = false;
        try
        {
            manifestHash = JsonIO.ShaFile(manifestPath); policyHash = JsonIO.ShaFile(policyPath); chainHash = JsonIO.ShaFile(chainPath); catalogHash = JsonIO.ShaFile(catalogPath);
            var manifest = JsonIO.Load<ScanManifest>(manifestPath); var policy = JsonIO.Load<SecurityPolicy>(policyPath);
            var chain = JsonIO.Load<ToolchainLock>(chainPath); profile = policy.Profile;
            if (string.IsNullOrWhiteSpace(policy.Profile)) throw new InvalidDataException("Missing policy profile.");
            if (chain.Database is null || string.IsNullOrWhiteSpace(chain.Database.Built) || string.IsNullOrWhiteSpace(chain.Database.Version))
                throw new ToolEvidenceException("Incomplete pinned database metadata.");
            if (policy.ToolchainSha256 != chainHash || policy.CatalogSha256 != catalogHash) throw new ToolEvidenceException("Pinned toolchain/catalog identity differs from policy.");
            var ids = Normalization.CatalogIds(JsonIO.Read(catalogPath));
            missing.AddRange(PolicyRules.Missing(policy, asOf, DateTimeOffset.Parse(chain.Database.Built, CultureInfo.InvariantCulture)));
            snapshot = new(root, manifest); files = snapshot.Files; inputHash = snapshot.Digest; missing.AddRange(snapshot.Gaps);
            if (missing.Count > 0) throw new IncompleteScopeException();
            await VerifyBundle(bundle, chain);
            var mounts = new[] { Processes.Mount(snapshot.DirectoryPath, "/target"), Processes.Mount(Path.Combine(bundle, "config"), "/config") };
            toolStarted = true;
            var secretRun = await Processes.Docker(chain.ImageId, ["/usr/local/bin/gitleaks", "dir", "/target", "--config", "/config/gitleaks.toml",
                "--no-banner", "--no-color", "--redact=100", "--ignore-gitleaks-allow", "--gitleaks-ignore-path", "/config/no-ignore-file",
                "--max-decode-depth", "0", "--max-archive-depth", "0", "--exit-code", "10", "--report-format", "json", "--report-path", "-", "--log-level", "error"], mounts, timeoutSeconds);
            if (secretRun.TimedOut) throw new ToolEvidenceException("Gitleaks timed out.");
            var secretReport = JsonIO.Parse(secretRun.Output);
            var secrets = Normalization.Secrets(secretReport, secretRun.ExitCode, files, File.ReadAllText(Path.Combine(bundle, "config/gitleaks.toml")));
            findings.AddRange(secrets); SaveTool("gitleaks", secretRun, secretReport, secrets.Length);
            var sbomRun = await Processes.Docker(chain.ImageId, ["/usr/local/bin/syft", "scan", "dir:/target", "--config", "/config/syft.yaml",
                "--parallelism", "2",
                "--source-name", "declared-inputs", "--source-version", inputHash, "-o", "cyclonedx-json"], mounts, timeoutSeconds);
            JsonIO.Write(Path.Combine(output, "syft-process.json"), new { sbomRun.ExitCode, sbomRun.TimedOut, stderr = sbomRun.Error });
            RequireCompleted(sbomRun, "Syft"); var rawSbom = JsonIO.Parse(sbomRun.Output);
            JsonIO.Write(Path.Combine(output, "raw/syft.json"), rawSbom);
            sbom = Normalization.Sbom(rawSbom);
            vulnerabilityInput = Normalization.VulnerabilityInput(sbom, snapshot.FirstParty, snapshot.Packages);
            missing.AddRange(Normalization.InventoryGaps(vulnerabilityInput, snapshot.Packages, files, manifest.Inputs.Any(i => i.Kind is "nuget-lock" or "npm-lock") && snapshot.Gaps.IsEmpty)); SaveTool("syft", sbomRun, rawSbom, 0);
            using var sbomInput = new Scratch("security-assay-sbom-");
            JsonIO.Write(Path.Combine(sbomInput.Path, "sbom.json"), vulnerabilityInput);
            if (OperatingSystem.IsLinux()) File.SetUnixFileMode(sbomInput.Path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.GroupRead | UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
            var vulnerabilityRun = await Processes.Docker(chain.ImageId, ["/usr/local/bin/grype", "sbom:/sbom/sbom.json", "--config", "/config/grype.yaml", "-o", "json", "-q"],
                [Processes.Mount(sbomInput.Path, "/sbom"), Processes.Mount(Path.Combine(bundle, "config"), "/config"), Processes.Mount(Path.Combine(bundle, "db"), "/db")], timeoutSeconds);
            RequireCompleted(vulnerabilityRun, "Grype"); var rawVulnerabilities = JsonIO.Parse(vulnerabilityRun.Output);
            JsonIO.Write(Path.Combine(output, "raw/grype.json"), rawVulnerabilities);
            VerifyGrypeContext(rawVulnerabilities, chain);
            var vulnerable = Normalization.Vulnerabilities(rawVulnerabilities, snapshot.Packages); findings.AddRange(vulnerable);
            SaveTool("grype", vulnerabilityRun, rawVulnerabilities, vulnerable.Length);
            foreach (var finding in findings)
            {
                if (finding.Asvs.IsDefaultOrEmpty || finding.Asvs.Any(id => !ids.Contains(id, StringComparer.Ordinal))) missing.Add("Unmapped finding: " + finding.Id);
                if (PolicyRules.Severity(finding.Severity) < 0) missing.Add("Unknown finding severity: " + finding.Id);
            }
            snapshot.Verify(); await VerifyBundle(bundle, chain);
            if (evaluatorHash != JsonIO.ShaFile(typeof(Evaluator).Assembly.Location) || coreHash != JsonIO.ShaFile(typeof(EvidenceDecisions).Assembly.Location))
                throw new ToolEvidenceException("Evaluator/evidence core changed during evaluation.");
            if (manifestHash != JsonIO.ShaFile(manifestPath) || policyHash != JsonIO.ShaFile(policyPath) || chainHash != JsonIO.ShaFile(chainPath) || catalogHash != JsonIO.ShaFile(catalogPath))
                throw new ToolEvidenceException("Manifest/policy/toolchain/catalog changed during evaluation.");

            void SaveTool(string id, ProcessEvidence execution, JsonNode report, int count)
            {
                var raw = Path.Combine(output, "raw", id + ".json"); JsonIO.Write(raw, report);
                observations.Add(new(id, "Completed", count, chain.Tools.Single(t => t.Id == id).Version));
                journal.Add(JsonIO.Node(new { tool = id, execution.ExitCode, rawReportSha256 = JsonIO.ShaFile(raw), stderrSha256 = JsonIO.ShaText(execution.Error) }));
            }
        }
        catch (IncompleteScopeException) { /* Do not execute scanners for an already incomplete required scope. */ }
        catch (ToolEvidenceException failure) { failures.Add(failure.Message); }
        catch (Exception failure) when (failure is IOException or UnauthorizedAccessException or InvalidDataException or System.Text.Json.JsonException or ArgumentException or InvalidOperationException or FormatException)
        {
            // A parse/process failure after a tool was started is a tool failure;
            // a malformed declared input before execution is missing evidence.
            if (toolStarted) failures.Add("Invalid tool evidence: " + failure.GetType().Name + (failure is InvalidDataException ? " / " + failure.Message : ""));
            else missing.Add("Invalid/incomplete input or tool evidence: " + failure.GetType().Name);
        }
        finally { snapshot?.Dispose(); }
        var uniqueFindings = findings.GroupBy(f => f.Id, StringComparer.Ordinal).Select(g => g.First()).OrderBy(f => f.Id, StringComparer.Ordinal).ToImmutableArray();
        var threshold = File.Exists(policyPath) ? TryThreshold(policyPath) : 3;
        var blocking = uniqueFindings.Where(f => PolicyRules.Severity(f.Severity) >= threshold).Select(f => f.Id).ToImmutableArray();
        var gaps = missing.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToImmutableArray();
        var errors = failures.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToImmutableArray();
        if (observations.Count != 3 && errors.IsEmpty) gaps = gaps.Add("Required scanner execution set is incomplete.");
        var verdict = EvidenceDecisions.Code(EvidenceDecisions.Decide(new(blocking, gaps, errors, inputHash, policyHash,
            ["gitleaks", "syft", "grype"], observations.Select(o => o.Tool).ToImmutableArray())));
        JsonIO.Write(Path.Combine(output, "sbom.cdx.json"), sbom);
        JsonIO.Write(Path.Combine(output, "vulnerability-input.cdx.json"), vulnerabilityInput);
        JsonIO.Write(Path.Combine(output, "findings.sarif"), Reports.Sarif(uniqueFindings, inputHash, policyHash, verdict, gaps, errors));
        var receipt = new Receipt("security-assay-receipt/0.1", verdict, profile, asOf.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture),
            inputHash, manifestHash, files, policyHash, catalogHash, chainHash, evaluatorHash,
            coreHash, JsonIO.ShaFile(Path.Combine(output, "sbom.cdx.json")),
            JsonIO.ShaFile(Path.Combine(output, "vulnerability-input.cdx.json")),
            JsonIO.ShaFile(Path.Combine(output, "findings.sarif")), observations.ToImmutable(), uniqueFindings, gaps, errors,
            PolicyRules.Limits.Add("Gitleaks M0 scans plaintext declared regular files; archive/recursive decoding is disabled and approved upstream allowlists apply."));
        JsonIO.Write(Path.Combine(output, "receipt.json"), receipt);
        File.WriteAllText(Path.Combine(output, "receipt.sha256"), JsonIO.ShaFile(Path.Combine(output, "receipt.json")) + "  receipt.json\n");
        JsonIO.Write(Path.Combine(output, "execution.json"), new { schema = "security-assay-execution/0.1", startedUtc = started, completedUtc = DateTimeOffset.UtcNow,
            isolation = "Docker --network none; immutable image; non-root; read-only mounts/filesystem; dropped capabilities; bounded resources", tools = journal,
            receiptSha256 = JsonIO.ShaFile(Path.Combine(output, "receipt.json")), authority = "Local execution journal; not a signature or independent attestation." });
        return receipt;
    }

    private static int TryThreshold(string path)
    { try { return Math.Max(0, PolicyRules.Severity(JsonIO.Load<SecurityPolicy>(path).BlockAtSeverity)); } catch { return 3; } }
    private static void RequireCompleted(ProcessEvidence value, string tool)
    { if (value.TimedOut || value.ExitCode != 0) throw new ToolEvidenceException(tool + " did not complete successfully."); }

    public static void VerifyGrypeContext(JsonNode report, ToolchainLock chain)
    {
        var descriptor = report["descriptor"] ?? throw new InvalidDataException("Missing Grype descriptor.");
        var status = descriptor["db"]?["status"] ?? throw new InvalidDataException("Missing consumed database identity.");
        var configuration = descriptor["configuration"] ?? throw new InvalidDataException("Missing effective scanner configuration.");
        if (JsonIO.Text(descriptor, "name") != "grype" || JsonIO.Text(descriptor, "version") != "0.121.0" ||
            JsonIO.Text(status, "schemaVersion") != chain.Database.Version || JsonIO.Text(status, "built") != chain.Database.Built ||
            JsonIO.Text(status, "from") != chain.Database.Source || JsonIO.Text(status, "path") != "/db/6/vulnerability.db" || status["valid"]?.GetValue<bool>() != true ||
            configuration["check-for-app-update"]?.GetValue<bool>() != false || configuration["db"]?["auto-update"]?.GetValue<bool>() != false ||
            configuration["externalSources"]?["enable"]?.GetValue<bool>() != false || configuration["ignore"] is not JsonArray ignores ||
            ignores.Any(i => i?["package"]?["type"]?.GetValue<string>() is not ("deb" or "rpm")) ||
            configuration["only-fixed"]?.GetValue<bool>() != false || configuration["only-notfixed"]?.GetValue<bool>() != false)
            throw new InvalidDataException("Actual Grype tool/database/configuration contradicts approved offline pins.");
    }

    public static async Task VerifyBundle(string bundle, ToolchainLock chain)
    {
        try
        {
            if (chain.Schema != "security-assay-toolchain/0.1" || chain.Platform != "linux/amd64" || string.IsNullOrEmpty(chain.ImageId) || !chain.ImageId.StartsWith("sha256:", StringComparison.Ordinal) || !EvidenceDecisions.IsSha256(chain.ImageId[7..]) ||
                chain.Tools.IsDefault || chain.Tools.Length != 3 || chain.Tools.Any(t => t is null) || chain.Tools.Select(t => t.Id).Distinct(StringComparer.Ordinal).Count() != 3 ||
                chain.Configurations.IsDefault || chain.Configurations.Length != 3 || chain.Configurations.Any(c => c is null) ||
                chain.Database is null || chain.Database.Schema != 6 || chain.Database.Files.IsDefaultOrEmpty || chain.Database.Files.Any(f => f is null || f.Path is null || !f.Path.StartsWith("db/6/", StringComparison.Ordinal)))
                throw new InvalidDataException("Incomplete/unsupported toolchain pins.");
            VerifyConfigurations(bundle, chain.Configurations);
            foreach (var tool in chain.Tools)
            {
                var approved = Provisioning.Approved.Single(t => t.Id == tool.Id);
                if (tool.Version != approved.Version || tool.ArchiveSha256 != approved.ArchiveSha || tool.ReleaseUrl != approved.Url ||
                    JsonIO.ShaFile(InputSnapshot.Inside(bundle, "bin/" + tool.Id)) != tool.Sha256) throw new InvalidDataException("Tool binary/version pin mismatch.");
            }
            foreach (var pin in chain.Database.Files)
                if (!EvidenceDecisions.IsSha256(pin.Sha256) || JsonIO.ShaFile(InputSnapshot.Inside(bundle, pin.Path)) != pin.Sha256) throw new InvalidDataException("Scanner configuration/database bytes changed.");
            var databaseFiles = Directory.EnumerateFiles(Path.Combine(bundle, "db"), "*", SearchOption.AllDirectories).Select(p => Path.GetRelativePath(bundle, p).Replace('\\', '/')).Order(StringComparer.Ordinal);
            if (!databaseFiles.SequenceEqual(chain.Database.Files.Select(f => f.Path).Order(StringComparer.Ordinal)) ||
                JsonIO.ShaFile(InputSnapshot.Inside(bundle, "db-status.json")) != chain.Database.StatusSha256) throw new InvalidDataException("Database file set/status changed.");
            var inspect = await Processes.Run(["docker", "image", "inspect", chain.ImageId], 30);
            if (inspect.ExitCode != 0 || inspect.TimedOut) throw new InvalidDataException("Approved local scanner image is unavailable.");
            var image = JsonIO.Parse(inspect.Output)[0]!;
            if (JsonIO.Text(image, "Id") != chain.ImageId || JsonIO.Text(image["Config"], "User") != "65532:65532") throw new InvalidDataException("Image identity/user differs.");
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or InvalidDataException or InvalidOperationException or ArgumentException or System.Text.Json.JsonException or System.ComponentModel.Win32Exception)
        { throw new ToolEvidenceException("Approved tool/configuration/database/image pin validation failed: " + error.GetType().Name); }
    }

    public static void VerifyConfigurations(string bundle, ImmutableArray<FilePin> pins)
    {
        string[] expected = ["config/gitleaks.toml", "config/grype.yaml", "config/syft.yaml"];
        if (pins.IsDefault || pins.Any(p => p is null) || !pins.Select(p => p.Path).Order(StringComparer.Ordinal).SequenceEqual(expected))
            throw new InvalidDataException("Approved scanner configuration pins differ.");
        var actual = Directory.EnumerateFileSystemEntries(Path.Combine(bundle, "config"))
            .Select(p => "config/" + Path.GetFileName(p)).Order(StringComparer.Ordinal);
        if (!actual.SequenceEqual(expected)) throw new InvalidDataException("Undeclared/missing configuration entry could influence scanners.");
        foreach (var pin in pins)
            if (!EvidenceDecisions.IsSha256(pin.Sha256) || JsonIO.ShaFile(InputSnapshot.Inside(bundle, pin.Path)) != pin.Sha256)
                throw new InvalidDataException("Approved scanner configuration bytes changed.");
    }
}

public sealed class ToolEvidenceException(string message) : Exception(message);
public sealed class IncompleteScopeException : Exception;
