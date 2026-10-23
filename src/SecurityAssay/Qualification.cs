using System.Collections.Immutable;
using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using CanonFlow.Security.Domain;

namespace CanonFlow.Security.Adapters;

public static class Qualification
{
    public static async Task<JsonNode> Run(string repository, string bundle, string engine, string output)
    {
        repository = Path.GetFullPath(repository); bundle = Path.GetFullPath(bundle); engine = Path.GetFullPath(engine); output = Path.GetFullPath(output);
        if (!output.StartsWith(Path.Combine(repository, "artifacts") + Path.DirectorySeparatorChar, StringComparison.Ordinal) || Directory.Exists(output))
            throw new InvalidDataException("Choose a fresh ignored artifacts qualification directory.");
        Directory.CreateDirectory(output);
        var head = await Git("rev-parse", "HEAD");
        if ((await Git("status", "--porcelain")).Length != 0) throw new InvalidDataException("Qualification requires exact clean committed source.");
        var assembly = typeof(Qualification).Assembly.Location; var initialBinary = JsonIO.ShaFile(assembly); var engineHash = JsonIO.ShaFile(engine);
        var gates = new JsonArray(); var report = JsonIO.Node(new { schema = "security-assay-qualification/0.1", executionStatus = "running", sourceCommit = head,
            evaluatorSha256 = initialBinary, engineSha256 = engineHash, gates, providerRequests = 0, publication = "Local Forgejo draft review only", authority = "Executed local M0 evidence; no human/production/ASVS certification claim." });
        report["gates"] = gates;
        var reportPath = Path.Combine(output, "qualification.json"); JsonIO.Write(reportPath, report);
        var catalog = Path.Combine(repository, "standards/asvs-5.0.0/catalog.json"); var chainFile = Path.Combine(repository, "policies/toolchain.lock.json");
        var policyFile = Path.Combine(repository, "policies/m0.json"); var cleanRoot = Path.Combine(repository, "samples/clean");
        var asOf = new DateTimeOffset(2026, 10, 23, 0, 0, 0, TimeSpan.Zero);
        try
        {
            await Command("locked-restore", ["dotnet", "restore", "SecurityAssay.slnx", "--locked-mode"]);
            await Command("strict-build", ["dotnet", "build", "SecurityAssay.slnx", "--no-restore", "-c", "Release", "-m:2", "-nodeReuse:false"]);
            await Command("boundary-tests", ["dotnet", "test", "SecurityAssay.slnx", "--no-build", "--no-restore", "-c", "Release", "--max-parallel-test-modules", "1"]);
            await Command("functional-policy", ["dotnet", engine, "verify", "SecurityAssay.slnx", "--policy", ".csassay.json", "--profile", "native", "--json", Path.Combine(output, "functional.json"), "--sarif", Path.Combine(output, "functional.sarif")]);
            var first = await Scan("clean", cleanRoot, policyFile, bundle, asOf, "Pass");
            using (var variant = new Scratch("security-assay-undeclared-"))
            {
                CopyFixture(cleanRoot, variant.Path);
                File.WriteAllText(Path.Combine(variant.Path, "undeclared-private.txt"), "api_key = \"" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(24)) + "\"");
                _ = await Scan("repeat-undeclared-isolation", variant.Path, policyFile, bundle, asOf, "Pass");
                foreach (var file in new[] { "receipt.json", "findings.sarif", "sbom.cdx.json", "vulnerability-input.cdx.json" })
                    Check(JsonIO.ShaFile(Path.Combine(output, "clean", file)) == JsonIO.ShaFile(Path.Combine(output, "repeat-undeclared-isolation", file)), "Repeated normalized output drifted or undeclared bytes reached scanners: " + file);
                gates.Add(JsonIO.Node(new { name = "determinism-and-undeclared-scope", state = "Passed", byteIdentical = new[] { "receipt.json", "findings.sarif", "sbom.cdx.json", "vulnerability-input.cdx.json" } })); Save();
            }
            var vulnerable = await Scan("vulnerable-dependency", Path.Combine(repository, "samples/vulnerable"), policyFile, bundle, asOf, "Fail");
            Check(vulnerable.Findings.Any(f => f.Tool == "grype" && PolicyRules.Severity(f.Severity) >= 3 && !f.Asvs.IsDefaultOrEmpty), "Known vulnerable dependency was not mapped/blocked.");
            _ = await Scan("npm-lock", Path.Combine(repository, "samples/npm"), policyFile, bundle, asOf, "Pass");
            _ = await Scan("project-references", Path.Combine(repository, "samples/project-references"), policyFile, bundle, asOf, "Pass");
            var projectSbom = JsonIO.Read(Path.Combine(output, "project-references/sbom.cdx.json"));
            var projectInput = JsonIO.Read(Path.Combine(output, "project-references/vulnerability-input.cdx.json"));
            Check(JsonIO.Array(projectSbom, "components").Any(c => string.Equals(c?["purl"]?.GetValue<string>(), "pkg:nuget/Fixture.Domain", StringComparison.OrdinalIgnoreCase)) &&
                !JsonIO.Array(projectInput, "components").Any(c => string.Equals(c?["purl"]?.GetValue<string>(), "pkg:nuget/Fixture.Domain", StringComparison.OrdinalIgnoreCase)), "First-party evidence/projection was not retained separately.");
            using (var secret = new Scratch("security-assay-synthetic-secret-"))
            {
                CopyFixture(cleanRoot, secret.Path); var token = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(24));
                File.WriteAllText(Path.Combine(secret.Path, "App.cs"), "public static class Example { public const string api_key = \"" + token + "\"; } // gitleaks:allow\n");
                var dirty = await Scan("synthetic-secret", secret.Path, policyFile, bundle, asOf, "Fail");
                Check(dirty.Findings.Any(f => f.Tool == "gitleaks" && !f.Asvs.IsDefaultOrEmpty), "Synthetic secret was missed or inline suppression was honored.");
                foreach (var file in Directory.EnumerateFiles(Path.Combine(output, "synthetic-secret"), "*", SearchOption.AllDirectories))
                    Check(!File.ReadAllText(file).Contains(token, StringComparison.Ordinal), "Synthetic secret entered evidence artifacts.");
                gates.Add(JsonIO.Node(new { name = "redaction-and-inline-allow-refusal", state = "Passed" })); Save();
            }
            _ = await Scan("full-release-unassessed", cleanRoot, Path.Combine(repository, "policies/full-release.json"), bundle, asOf, "Inconclusive");
            var chain = JsonIO.Load<ToolchainLock>(chainFile);
            var built = DateTimeOffset.Parse(chain.Database.Built, CultureInfo.InvariantCulture);
            _ = await Scan("stale-database", cleanRoot, policyFile, bundle, built.AddDays(6), "Inconclusive");
            using (var invalid = new Scratch("security-assay-invalid-version-"))
            {
                CopyFixture(cleanRoot, invalid.Path); var invalidLock = Path.Combine(invalid.Path, "packages.lock.json");
                var metadata = JsonIO.Read(invalidLock); metadata["dependencies"]!["net11.0"]!["Newtonsoft.Json"]!["resolved"] = "latest";
                JsonIO.Write(invalidLock, metadata);
                var refused = await Scan("unsupported-package-version", invalid.Path, policyFile, bundle, asOf, "Inconclusive");
                Check(refused.Tools.IsEmpty && refused.MissingEvidence.Any(g => g.Contains("version", StringComparison.Ordinal)), "Unsupported version reached vulnerability matching.");
            }
            foreach (var mode in new[] { "missing-binary", "missing-database", "changed-binary", "changed-configuration", "undeclared-ignore-file", "changed-database" })
            {
                using var shadow = new Scratch("security-assay-pin-control-");
                foreach (var tool in chain.Tools)
                {
                    var relative = "bin/" + tool.Id; var target = Path.Combine(shadow.Path, relative); Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                    File.Copy(Path.Combine(bundle, relative), target);
                }
                foreach (var pin in chain.Configurations.Concat(chain.Database.Files))
                {
                    var target = Path.Combine(shadow.Path, pin.Path); Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                    if (pin.Path.EndsWith("vulnerability.db", StringComparison.Ordinal))
                    {
                        if (mode == "changed-database") File.WriteAllText(target, "tampered DB control");
                        else
                        {
                            var link = await Processes.Run(["ln", "--", Path.Combine(bundle, pin.Path), target], 15);
                            Check(link.ExitCode == 0 && !link.TimedOut, "Cannot link immutable baseline DB for isolated negative control.");
                        }
                    }
                    else File.Copy(Path.Combine(bundle, pin.Path), target);
                }
                File.Copy(Path.Combine(bundle, "db-status.json"), Path.Combine(shadow.Path, "db-status.json"));
                if (mode == "missing-binary") File.Delete(Path.Combine(shadow.Path, "bin/grype"));
                if (mode == "missing-database") File.Delete(Path.Combine(shadow.Path, chain.Database.Files.First(f => f.Path.EndsWith("vulnerability.db", StringComparison.Ordinal)).Path));
                if (mode == "changed-binary") Replace(Path.Combine(shadow.Path, "bin/gitleaks"), "tampered binary control");
                if (mode == "changed-configuration") Replace(Path.Combine(shadow.Path, "config/syft.yaml"), "tampered configuration control");
                if (mode == "undeclared-ignore-file") File.WriteAllText(Path.Combine(shadow.Path, "config/no-ignore-file"), "unreviewed ignore control");
                var rejected = await Scan(mode, cleanRoot, policyFile, shadow.Path, asOf, "ToolFailure");
                Check(rejected.Tools.IsEmpty, "Tampered/incomplete scanner bundle reached scanner execution.");
            }
            var timed = await Processes.Docker(chain.ImageId, ["/usr/local/bin/gitleaks", "version"], [], seconds: 0);
            Check(timed.TimedOut, "Timeout control unexpectedly completed.");
            var remaining = await Processes.Run(["docker", "ps", "-a", "--filter", "name=security-assay-", "--format", "{{.Names}}"], 15);
            Check(remaining.ExitCode == 0 && remaining.Output.Trim().Length == 0, "Owned scanner container remained after timeout.");
            gates.Add(JsonIO.Node(new { name = "timeout-and-container-cleanup", state = "Passed" })); Save();
            var functional = JsonIO.Read(Path.Combine(output, "functional.json"));
            Check(JsonIO.Text(functional, "verdict") == "pass" && functional["evidence"]?["authoritative"]?.GetValue<bool>() == true,
                "CSharpAssay did not establish admitted functional policy authority.");
            Check(await Git("rev-parse", "HEAD") == head && (await Git("status", "--porcelain")).Length == 0 && JsonIO.ShaFile(assembly) == initialBinary && JsonIO.ShaFile(engine) == engineHash, "Source/tool/engine identity changed during qualification.");
            report["executionStatus"] = "completed"; report["sourceUnchanged"] = true;
            report["limitations"] = JsonIO.Node(PolicyRules.Limits); Save(); return report;
        }
        catch (Exception error) { report["executionStatus"] = "failed"; report["failure"] = error.Message; Save(); throw; }

        void Save() => JsonIO.Write(reportPath, report);
        async Task<string> Git(params string[] arguments)
        {
            var result = await Processes.Run(["git", .. arguments], 30, repository);
            Check(result.ExitCode == 0, "Cannot inspect local source identity."); return result.Output.Trim();
        }
        async Task Command(string name, string[] command)
        {
            Console.WriteLine("Qualification gate: " + name); var result = await Processes.Run(command, 600, repository);
            var log = Path.Combine(output, name + ".log"); File.WriteAllText(log, result.Output + result.Error);
            gates.Add(JsonIO.Node(new { name, state = result.ExitCode == 0 && !result.TimedOut ? "Passed" : "Failed", result.ExitCode, log = Path.GetFileName(log), logSha256 = JsonIO.ShaFile(log) })); Save();
            Check(result.ExitCode == 0 && !result.TimedOut, "Qualification command failed: " + name);
        }
        async Task<Receipt> Scan(string name, string target, string policy, string scannerBundle, DateTimeOffset time, string expected)
        {
            Console.WriteLine("Qualification scan: " + name); var path = Path.Combine(output, name);
            var result = await Evaluator.Scan(target, Path.Combine(target, "inputs.json"), policy, chainFile, catalog, scannerBundle, time, path);
            gates.Add(JsonIO.Node(new { name, state = result.Verdict == expected ? "Passed" : "Failed", expected, observed = result.Verdict,
                receipt = Path.GetRelativePath(output, Path.Combine(path, "receipt.json")), receiptSha256 = JsonIO.ShaFile(Path.Combine(path, "receipt.json")) })); Save();
            Check(result.Verdict == expected, "Unexpected real scan result: " + name + " / " + result.Verdict); return result;
        }
    }
    private static void CopyFixture(string source, string destination)
    { foreach (var name in new[] { "App.cs", "inputs.json", "packages.lock.json" }) File.Copy(Path.Combine(source, name), Path.Combine(destination, name)); }
    private static void Replace(string path, string value)
    {
        if (OperatingSystem.IsLinux()) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        File.WriteAllText(path, value);
    }
    private static void Check(bool value, string message) { if (!value) throw new InvalidDataException(message); }
}
