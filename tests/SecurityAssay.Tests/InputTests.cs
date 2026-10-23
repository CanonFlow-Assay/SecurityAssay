using CanonFlow.Security.Adapters;
using CanonFlow.Security.Domain;
using Xunit;

namespace SecurityAssay.Tests;

public sealed class InputTests
{
    [Theory]
    [InlineData("1.2.3", false, true)]
    [InlineData("1.2.3.4", true, true)]
    [InlineData("11.0.100-rc.1.26425.128", true, true)]
    [InlineData("1.0.0+build.03", false, true)]
    [InlineData("foo", false, false)]
    [InlineData("latest", true, false)]
    [InlineData("1.2", true, false)]
    [InlineData("1.2.3.4", false, false)]
    [InlineData("01.2.3", false, false)]
    [InlineData("1.2.3\n", false, false)]
    [InlineData("1.2.3-alpha..1", false, false)]
    [InlineData("1.2.3-01", false, false)]
    [InlineData("1.2.3+build+extra", false, false)]
    [InlineData("999999999999.1.0", true, false)]
    public void UnsupportedVersionsCannotPretendToBeResolvedPackageIdentity(string value, bool nuget, bool supported)
        => Assert.Equal(supported, InputSnapshot.SupportedVersion(value, nuget));

    [Theory]
    [InlineData("nuget")]
    [InlineData("npm")]
    [InlineData("npm-root")]
    public void MalformedVersionWithOtherwiseValidIntegrityIsMissingEvidence(string kind)
    {
        using var root = new Scratch("security-assay-test-");
        var file = kind == "nuget" ? "packages.lock.json" : "package-lock.json";
        var sample = kind == "nuget" ? "clean" : "npm";
        var value = JsonIO.Read(Path.Combine(TestRepository.Path, "samples", sample, file));
        if (kind == "nuget") value["dependencies"]!["net11.0"]!["Newtonsoft.Json"]!["resolved"] = "latest";
        else value["packages"]![kind == "npm" ? "node_modules/is-number" : ""]!["version"] = "latest";
        JsonIO.Write(Path.Combine(root.Path, file), value);
        using var snapshot = new InputSnapshot(root.Path, new("security-assay-inputs/0.1", [new(file, kind == "nuget" ? "nuget-lock" : "npm-lock")]));
        Assert.Contains(snapshot.Gaps, gap => gap.Contains("version", StringComparison.Ordinal));
    }

    [Fact]
    public async Task FifoCannotEnterSnapshotOrHangHashing()
    {
        using var root = new Scratch("security-assay-test-");
        var process = await Processes.Run(["mkfifo", Path.Combine(root.Path, "pipe")], 10);
        Assert.Equal(0, process.ExitCode);
        Assert.Throws<InvalidDataException>(() => InputSnapshot.Inside(root.Path, "pipe"));
    }
    [Fact]
    public void OnlyDeclaredBytesReachSnapshotAndUndeclaredFilesStayOut()
    {
        using var root = new Scratch("security-assay-test-");
        File.WriteAllText(Path.Combine(root.Path, "App.cs"), "declared"); File.WriteAllText(Path.Combine(root.Path, "private.txt"), "not declared");
        using var snapshot = new InputSnapshot(root.Path, new("security-assay-inputs/0.1", [new("App.cs", "source")]));
        Assert.Equal("declared", File.ReadAllText(Path.Combine(snapshot.DirectoryPath, "App.cs")));
        Assert.False(File.Exists(Path.Combine(snapshot.DirectoryPath, "private.txt")));
        Assert.Single(snapshot.Files); snapshot.Verify();
    }

    [Theory]
    [InlineData("")]
    [InlineData("../App.cs")]
    [InlineData("/etc/passwd")]
    [InlineData("a/../App.cs")]
    [InlineData("./App.cs")]
    [InlineData("a\\App.cs")]
    [InlineData("a//App.cs")]
    public void EscapingOrAmbiguousPathsAreRejected(string path)
    {
        using var root = new Scratch("security-assay-test-");
        Assert.Throws<InvalidDataException>(() => InputSnapshot.Inside(root.Path, path));
    }

    [Fact]
    public void EmptyOrDuplicateDeclarationsCannotProduceACompleteSnapshot()
    {
        using var root = new Scratch("security-assay-test-"); File.WriteAllText(Path.Combine(root.Path, "App.cs"), "source");
        Assert.Throws<InvalidDataException>(() => new InputSnapshot(root.Path, new("security-assay-inputs/0.1", [])));
        Assert.Throws<InvalidDataException>(() => new InputSnapshot(root.Path, new("security-assay-inputs/0.1", [new("App.cs", "source"), new("App.cs", "source")])));
    }

    [Fact]
    public void SourceReplacementIsDetectedAfterSnapshot()
    {
        using var root = new Scratch("security-assay-test-"); var source = Path.Combine(root.Path, "App.cs"); File.WriteAllText(source, "before");
        using var snapshot = new InputSnapshot(root.Path, new("security-assay-inputs/0.1", [new("App.cs", "source")]));
        File.WriteAllText(source, "after"); Assert.Throws<InvalidDataException>(snapshot.Verify);
    }

    [Fact]
    public void SymlinkAndSymlinkAncestorAreRejected()
    {
        using var root = new Scratch("security-assay-test-"); using var outside = new Scratch("security-assay-outside-");
        File.WriteAllText(Path.Combine(outside.Path, "App.cs"), "outside");
        File.CreateSymbolicLink(Path.Combine(root.Path, "App.cs"), Path.Combine(outside.Path, "App.cs"));
        Assert.Throws<InvalidDataException>(() => InputSnapshot.Inside(root.Path, "App.cs"));
        Directory.CreateSymbolicLink(Path.Combine(root.Path, "linked"), outside.Path);
        Assert.Throws<InvalidDataException>(() => InputSnapshot.Inside(root.Path, "linked/App.cs"));
    }

    [Fact]
    public void ReadableContainerSnapshotRetainsPrivateHostParent()
    {
        if (!OperatingSystem.IsLinux()) throw new InvalidOperationException("This qualification requires Linux.");
        using var root = new Scratch("security-assay-test-"); File.WriteAllText(Path.Combine(root.Path, "App.cs"), "private");
        using var snapshot = new InputSnapshot(root.Path, new("security-assay-inputs/0.1", [new("App.cs", "source")]));
        var parent = Directory.GetParent(snapshot.DirectoryPath)!.FullName;
        Assert.Equal(UnixFileMode.None, File.GetUnixFileMode(parent) & (UnixFileMode.GroupRead | UnixFileMode.OtherRead | UnixFileMode.GroupExecute | UnixFileMode.OtherExecute));
        Assert.NotEqual(UnixFileMode.None, File.GetUnixFileMode(snapshot.DirectoryPath) & UnixFileMode.OtherExecute);
    }

    [Fact]
    public void NugetDeclaredIdentitiesAndIntegrityComeFromLock()
    {
        var repo = TestRepository.Path;
        using var snapshot = new InputSnapshot(System.IO.Path.Combine(repo, "samples/clean"), JsonIO.Load<ScanManifest>(System.IO.Path.Combine(repo, "samples/clean/inputs.json")));
        Assert.Empty(snapshot.Gaps); var package = Assert.Single(snapshot.Packages);
        Assert.Equal("nuget", package.Ecosystem); Assert.Equal("Newtonsoft.Json", package.Name); Assert.Equal("13.0.4", package.Version);
    }

    [Fact]
    public void UnsupportedLockVersionRemainsMissingEvidence()
    {
        using var root = new Scratch("security-assay-test-"); File.WriteAllText(Path.Combine(root.Path, "packages.lock.json"), "{\"version\":99,\"dependencies\":{}}");
        using var snapshot = new InputSnapshot(root.Path, new("security-assay-inputs/0.1", [new("packages.lock.json", "nuget-lock")]));
        Assert.NotEmpty(snapshot.Gaps);
    }
}

internal static class TestRepository
{
    public static string Path
    {
        get
        {
            for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
                if (File.Exists(System.IO.Path.Combine(dir.FullName, "SecurityAssay.slnx"))) return dir.FullName;
            throw new InvalidOperationException("SecurityAssay repository unavailable.");
        }
    }
}
