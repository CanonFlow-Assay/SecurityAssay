using System.Collections.Immutable;
using System.Text.Json.Nodes;
using CanonFlow.Security.Adapters;
using CanonFlow.Security.Domain;
using Xunit;

namespace SecurityAssay.Tests;

public sealed class FirstPartyTests
{
    private static JsonNode Project() => JsonIO.Parse("""{"bomFormat":"CycloneDX","specVersion":"1.7","components":[{"bom-ref":"project","type":"library","name":"fixture.domain","version":"UNKNOWN","purl":"pkg:nuget/fixture.domain","properties":[{"name":"syft:package:foundBy","value":"dotnet-packages-lock-cataloger"},{"name":"syft:package:metadataType","value":"dotnet-packages-lock-entry"},{"name":"syft:location:0:path","value":"/packages.lock.json"}]}],"dependencies":[{"ref":"project","dependsOn":[]},{"ref":"app","dependsOn":["project"]}]}""");
    private static readonly ImmutableArray<FirstPartyIdentity> Declared = [new("nuget", "Fixture.Domain", "", "packages.lock.json")];

    [Fact]
    public void ProvenanceBoundProjectRemainsInFullSbomAndIsExplicitlyClassified()
    {
        var full = Project(); var projection = Normalization.VulnerabilityInput(full, Declared, []);
        var retained = Assert.Single(full["components"]!.AsArray());
        Assert.Contains(retained!["properties"]!.AsArray(), p => p?["name"]?.GetValue<string>() == "security-assay:scope");
        Assert.Empty(projection["components"]!.AsArray());
        var edge = Assert.Single(projection["dependencies"]!.AsArray());
        Assert.Equal("app", edge!["ref"]!.GetValue<string>()); Assert.Empty(edge["dependsOn"]!.AsArray());
        Assert.Empty(Normalization.InventoryGaps(projection, [], [], true));
    }

    [Theory]
    [InlineData("undeclared")]
    [InlineData("wrong-location")]
    [InlineData("wrong-cataloger")]
    [InlineData("wrong-version")]
    [InlineData("missing-provenance")]
    public void UnprovenFirstPartyComponentsCannotBeSilentlyRemoved(string change)
    {
        var full = Project(); var component = full["components"]![0]!;
        var declared = Declared;
        switch (change)
        {
            case "undeclared": declared = []; break;
            case "wrong-location": component["properties"]![2]!["value"] = "/other/packages.lock.json"; break;
            case "wrong-cataloger": component["properties"]![0]!["value"] = "unrecognized"; break;
            case "wrong-version": component["version"] = "1.0.0"; break;
            case "missing-provenance": component.AsObject().Remove("properties"); break;
        }
        var projection = Normalization.VulnerabilityInput(full, declared, []);
        Assert.Single(projection["components"]!.AsArray());
        Assert.Throws<InvalidDataException>(() => Normalization.InventoryGaps(projection, [], [], true));
    }

    [Fact]
    public void NpmRootCannotHideSameNamedLockedDependency()
    {
        var full = Project(); var component = full["components"]![0]!;
        component["purl"] = "pkg:npm/example@1.0.0"; component["name"] = "example"; component["version"] = "1.0.0";
        component["properties"]![0]!["value"] = "javascript-lock-cataloger";
        component["properties"]![1]!["value"] = "javascript-npm-package-lock-entry";
        component["properties"]![2]!["value"] = "/package-lock.json";
        ImmutableArray<FirstPartyIdentity> root = [new("npm", "example", "1.0.0", "package-lock.json")];
        Assert.Empty(Normalization.VulnerabilityInput(full.DeepClone(), root, [])["components"]!.AsArray());
        var dependencies = ImmutableArray.Create(new PackageIdentity("npm", "example", "1.0.0", "package-lock.json"));
        var retained = Normalization.VulnerabilityInput(full, root, dependencies);
        Assert.Single(retained["components"]!.AsArray());
        Assert.Empty(Normalization.InventoryGaps(retained, dependencies));
    }

    [Fact]
    public void FirstPartyDeclarationsComeFromLockEntries()
    {
        using var project = new InputSnapshot(Path.Combine(TestRepository.Path, "samples/project-references"),
            JsonIO.Load<ScanManifest>(Path.Combine(TestRepository.Path, "samples/project-references/inputs.json")));
        Assert.Equal("Fixture.Domain", Assert.Single(project.FirstParty).Name); Assert.Single(project.Packages); Assert.Empty(project.Gaps);
        using var npm = new InputSnapshot(Path.Combine(TestRepository.Path, "samples/npm"),
            JsonIO.Load<ScanManifest>(Path.Combine(TestRepository.Path, "samples/npm/inputs.json")));
        Assert.Equal("security-assay-fixture", Assert.Single(npm.FirstParty).Name); Assert.Single(npm.Packages); Assert.Empty(npm.Gaps);
    }
}
