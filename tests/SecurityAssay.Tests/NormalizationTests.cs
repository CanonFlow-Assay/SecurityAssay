using System.Collections.Immutable;
using System.Text.Json.Nodes;
using CanonFlow.Security.Adapters;
using CanonFlow.Security.Domain;
using Xunit;

namespace SecurityAssay.Tests;

public sealed class NormalizationTests
{
    [Theory]
    [InlineData("valid")]
    [InlineData("ignore-file")]
    [InlineData("extension")]
    [InlineData("directory")]
    [InlineData("changed")]
    [InlineData("symlink")]
    public void MountedConfigurationCannotContainUnpinnedIgnoreFilesOrExtensions(string change)
    {
        using var root = new Scratch("security-assay-test-");
        var config = Directory.CreateDirectory(Path.Combine(root.Path, "config")).FullName;
        var pins = new[] { "gitleaks.toml", "grype.yaml", "syft.yaml" }.Select(name =>
        {
            var file = Path.Combine(config, name); File.WriteAllText(file, "approved " + name);
            return new FilePin("config/" + name, JsonIO.ShaFile(file));
        }).ToImmutableArray();
        switch (change)
        {
            case "ignore-file": File.WriteAllText(Path.Combine(config, "no-ignore-file"), "unreviewed fingerprint"); break;
            case "extension": File.WriteAllText(Path.Combine(config, "extension.yaml"), "unreviewed config"); break;
            case "directory": Directory.CreateDirectory(Path.Combine(config, "extensions")); break;
            case "changed": File.AppendAllText(Path.Combine(config, "grype.yaml"), " changed"); break;
            case "symlink":
                File.Copy(Path.Combine(config, "gitleaks.toml"), Path.Combine(root.Path, "template"));
                File.Delete(Path.Combine(config, "gitleaks.toml"));
                File.CreateSymbolicLink(Path.Combine(config, "gitleaks.toml"), "../template"); break;
        }
        if (change == "valid") Evaluator.VerifyConfigurations(root.Path, pins);
        else Assert.Throws<InvalidDataException>(() => Evaluator.VerifyConfigurations(root.Path, pins));
    }

    [Fact]
    public void FailedScanCannotLookLikeAnEmptyCleanSarifRun()
    {
        var sarif = JsonIO.Node(Reports.Sarif([], new('a', 64), new('b', 64), "ToolFailure", [], ["scanner failed"]));
        Assert.False(sarif["runs"]?[0]?["invocations"]?[0]?["executionSuccessful"]?.GetValue<bool>());
        Assert.Single(sarif["runs"]![0]!["invocations"]![0]!["toolExecutionNotifications"]!.AsArray());
    }

    [Theory]
    [InlineData("valid")]
    [InlineData("database")]
    [InlineData("network")]
    [InlineData("filter")]
    [InlineData("version")]
    public void ActualGrypeDescriptorMustMatchDatabaseAndOfflineConfiguration(string change)
    {
        var chain = new ToolchainLock("security-assay-toolchain/0.1", "linux/amd64", "sha256:" + new string('a', 64), [], [], new(6, "v6.1.10", "2026-10-22T18:51:21Z", "snapshot", [], new('b', 64)));
        var report = JsonIO.Parse("""{"descriptor":{"name":"grype","version":"0.121.0","db":{"status":{"schemaVersion":"v6.1.10","built":"2026-10-22T18:51:21Z","from":"snapshot","path":"/db/6/vulnerability.db","valid":true}},"configuration":{"check-for-app-update":false,"db":{"auto-update":false},"externalSources":{"enable":false},"ignore":[],"only-fixed":false,"only-notfixed":false}}}""");
        switch (change)
        {
            case "database": report["descriptor"]!["db"]!["status"]!["built"] = "2000-01-01T00:00:00Z"; break;
            case "network": report["descriptor"]!["configuration"]!["db"]!["auto-update"] = true; break;
            case "filter": report["descriptor"]!["configuration"]!["only-fixed"] = true; break;
            case "version": report["descriptor"]!["version"] = "future"; break;
        }
        if (change == "valid") Evaluator.VerifyGrypeContext(report, chain);
        else Assert.Throws<InvalidDataException>(() => Evaluator.VerifyGrypeContext(report, chain));
    }

    [Fact]
    public void PinnedGrypeMayOmitAnEmptyIgnoredMatchesCollection()
    {
        Assert.Empty(Normalization.Vulnerabilities(JsonIO.Parse("""{"matches":[],"descriptor":{}}"""), []));
        Assert.Throws<InvalidDataException>(() => Normalization.Vulnerabilities(JsonIO.Parse("""{"matches":[],"ignoredMatches":[{}],"descriptor":{}}"""), []));
    }
    [Fact]
    public void SyftFileComponentsAreCheckedAgainstDeclaredBytesRatherThanTreatedAsPackages()
    {
        var hash = new string('a', 64);
        var sbom = JsonIO.Parse("""{"components":[{"type":"file","name":"/target/packages.lock.json","hashes":[{"alg":"SHA-256","content":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}]}""");
        Assert.Empty(Normalization.InventoryGaps(sbom, [], [new("packages.lock.json", hash)], declaredLock: true));
        Assert.Throws<InvalidDataException>(() => Normalization.InventoryGaps(sbom, [], [new("packages.lock.json", new('b', 64))], true));
    }

    private static readonly ImmutableArray<FilePin> Files = [new("App.cs", new('a', 64))];
    private static JsonNode Secret(string rule = "generic-api-key", string value = "REDACTED", string path = "/target/App.cs") => JsonIO.Node(new[] { new { Secret = value, RuleID = rule, File = path, StartLine = 1 } });
    private static JsonNode ExactSecret(string rule = "generic-api-key", string value = "REDACTED", string path = "/target/App.cs")
    {
        // Scanner wire keys are deliberately case-sensitive, unlike our receipts.
        return JsonIO.Parse("[{\"Secret\":" + System.Text.Json.JsonSerializer.Serialize(value) + ",\"RuleID\":" + System.Text.Json.JsonSerializer.Serialize(rule) + ",\"File\":" + System.Text.Json.JsonSerializer.Serialize(path) + ",\"StartLine\":1}]");
    }

    [Fact]
    public void RedactedKnownSecretHasValidAsvsAndRiskMapping()
    {
        var finding = Assert.Single(Normalization.Secrets(ExactSecret(), 10, Files, "id = \"generic-api-key\""));
        Assert.Equal("Critical", finding.Severity); Assert.Contains("v5.0.0-13.3.1", finding.Asvs); Assert.Contains("A08:2025", finding.Top10);
    }

    [Fact]
    public void UnknownRuleRemainsUnmappedAndUnknownSeverity()
    {
        var finding = Assert.Single(Normalization.Secrets(ExactSecret("future-rule"), 10, Files, "id = \"generic-api-key\""));
        Assert.Empty(finding.Asvs); Assert.Equal(-1, PolicyRules.Severity(finding.Severity));
    }

    [Fact]
    public void UnredactedSecretCannotEnterArtifacts() => Assert.Throws<InvalidDataException>(() => Normalization.Secrets(ExactSecret(value: "not-redacted-synthetic"), 10, Files, "id = \"generic-api-key\""));

    [Theory]
    [InlineData(0, true)]
    [InlineData(10, false)]
    [InlineData(2, false)]
    public void ScannerExitAndReportMustAgree(int exitCode, bool hasFinding)
    {
        Assert.Throws<InvalidDataException>(() => Normalization.Secrets(hasFinding ? ExactSecret() : new JsonArray(), exitCode, Files, "id = \"generic-api-key\""));
    }

    [Fact]
    public void ForeignFindingCannotBeAttributedToDeclaredSource() => Assert.Throws<InvalidDataException>(() => Normalization.Secrets(ExactSecret(path: "/other/private.txt"), 10, Files, "id = \"generic-api-key\""));

    [Fact]
    public void SbomNormalizationRemovesExecutionTimeAndSortsSets()
    {
        var left = JsonIO.Parse("""{"bomFormat":"CycloneDX","specVersion":"1.6","serialNumber":"uuid-a","metadata":{"timestamp":"a"},"components":[{"purl":"pkg:nuget/A@1"},{"purl":"pkg:nuget/B@1"}]}""");
        var right = JsonIO.Parse("""{"components":[{"purl":"pkg:nuget/B@1"},{"purl":"pkg:nuget/A@1"}],"metadata":{"timestamp":"b"},"serialNumber":"uuid-b","specVersion":"1.6","bomFormat":"CycloneDX"}""");
        Assert.Equal(JsonIO.Canonical(Normalization.Sbom(left)), JsonIO.Canonical(Normalization.Sbom(right)));
    }

    [Theory]
    [InlineData("pkg:nuget/Newtonsoft.Json@13.0.4", "nuget", "Newtonsoft.Json", "13.0.4")]
    [InlineData("pkg:npm/%40scope/library@1.0.0", "npm", "@scope/library", "1.0.0")]
    public void PackageIdentityKeepsEcosystemNameAndVersion(string purl, string type, string name, string version)
        => Assert.Equal((type, name, version), Normalization.ParsePurl(purl));

    [Theory]
    [InlineData("")]
    [InlineData("pkg:nuget/Thing")]
    [InlineData("pkg:pypi/Thing@1")]
    public void UnsupportedPackageIdentitiesCannotDisappear(string purl) => Assert.Throws<InvalidDataException>(() => Normalization.ParsePurl(purl));

    [Fact]
    public void MissingAndUndeclaredInventoryAreEvidenceGaps()
    {
        var sbom = JsonIO.Parse("""{"components":[{"purl":"pkg:nuget/Unexpected@1"}]}""");
        var gaps = Normalization.InventoryGaps(sbom, [new("nuget", "Expected", "1", "packages.lock.json")]);
        Assert.Equal(2, gaps.Length);
    }

    [Fact]
    public void NugetInventoryIdentityIsCaseInsensitive()
        => Assert.Empty(Normalization.InventoryGaps(JsonIO.Parse("""{"components":[{"purl":"pkg:nuget/newtonsoft.json@13.0.4"}]}"""), [new("nuget", "Newtonsoft.Json", "13.0.4", "packages.lock.json")]));

    [Fact]
    public void MappedRequirementsExistInPinnedAsvsFiveCatalog()
    {
        var ids = Normalization.CatalogIds(JsonIO.Read(System.IO.Path.Combine(TestRepository.Path, "standards/asvs-5.0.0/catalog.json")));
        Assert.Contains("v5.0.0-13.3.1", ids); Assert.Contains("v5.0.0-15.1.1", ids); Assert.Contains("v5.0.0-15.2.1", ids);
    }

    [Fact]
    public void SarifUsesSchemaAndDoesNotInventLineOneForPackageFindings()
    {
        var f = new SecurityFinding("id", "grype", "CVE-example", "High", "message", "packages.lock.json", 0, "Pkg@1", ["v5.0.0-15.2.1"], ["A03:2025"]);
        var sarif = JsonIO.Node(Reports.Sarif([f], new('a', 64), new('b', 64)));
        Assert.NotNull(sarif["$schema"]); Assert.Null(sarif["runs"]?[0]?["results"]?[0]?["locations"]?[0]?["physicalLocation"]?["region"]);
    }
}
