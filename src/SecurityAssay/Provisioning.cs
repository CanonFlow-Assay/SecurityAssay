using System.Collections.Immutable;
using System.Formats.Tar;
using System.IO.Compression;
using CanonFlow.Security.Domain;

namespace CanonFlow.Security.Adapters;

public static class Provisioning
{
    public static void WritePolicies(string repository)
    {
        var catalog = JsonIO.ShaFile(Path.Combine(repository, "standards/asvs-5.0.0/catalog.json"));
        var chain = JsonIO.ShaFile(Path.Combine(repository, "policies/toolchain.lock.json"));
        JsonIO.Write(Path.Combine(repository, "policies/m0.json"), new SecurityPolicy("security-assay-policy/0.1", "m0-local-evidence", "High", 5, PolicyRules.Implemented, catalog, chain));
        JsonIO.Write(Path.Combine(repository, "policies/full-release.json"), new SecurityPolicy("security-assay-policy/0.1", "full-release", "High", 5,
            [.. PolicyRules.Implemented, "authorization", "static-security", "configuration", "exception-handling", "audit-logging", "publisher-provenance", "signed-release"], catalog, chain));
    }
    public static readonly ImmutableArray<(string Id, string Version, string ArchiveSha, string Url)> Approved = [
        ("gitleaks", "8.30.1", "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb", "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz"),
        ("syft", "1.55.0", "bb65249542db5fedeeb4d3f9b018b75e7264dbfbbb10486f044581a92f90490d", "https://github.com/anchore/syft/releases/download/v1.55.0/syft_1.55.0_linux_amd64.tar.gz"),
        ("grype", "0.121.0", "64e07133d3486115de647a66581461dccf5c732748a0a3119077395565f15519", "https://github.com/anchore/grype/releases/download/v0.121.0/grype_0.121.0_linux_amd64.tar.gz")
    ];

    // Provisioning uses previously downloaded approved archives and an explicitly
    // updated local DB. This command never turns a live scan into release evidence.
    public static async Task<ToolchainLock> Prepare(string repository, string bundle)
    {
        repository = Path.GetFullPath(repository); bundle = Path.GetFullPath(bundle);
        Directory.CreateDirectory(Path.Combine(bundle, "bin")); Directory.CreateDirectory(Path.Combine(bundle, "config"));
        var pins = ImmutableArray.CreateBuilder<BinaryPin>();
        foreach (var tool in Approved)
        {
            var archive = InputSnapshot.Inside(bundle, "downloads/" + tool.Id + ".tar.gz");
            if (JsonIO.ShaFile(archive) != tool.ArchiveSha) throw new InvalidDataException("Official release archive hash mismatch: " + tool.Id);
            var binary = Path.Combine(bundle, "bin", tool.Id); var entries = 0;
            using var gzip = new GZipStream(File.OpenRead(archive), CompressionMode.Decompress); using var reader = new TarReader(gzip);
            while (reader.GetNextEntry() is { } entry)
            {
                if (entry.Name != tool.Id) continue;
                if (++entries != 1 || entry.EntryType is not (TarEntryType.RegularFile or TarEntryType.V7RegularFile) || entry.DataStream is null)
                    throw new InvalidDataException("Ambiguous/nonregular approved binary archive.");
                var pending = binary + ".approved";
                using (var output = File.Create(pending)) entry.DataStream.CopyTo(output);
                if (File.Exists(binary) && JsonIO.ShaFile(binary) != JsonIO.ShaFile(pending)) throw new InvalidDataException("Existing binary differs from approved archive.");
                if (!File.Exists(binary)) File.Move(pending, binary); else File.Delete(pending);
            }
            if (entries != 1) throw new InvalidDataException("Approved archive has no expected binary.");
            if (OperatingSystem.IsLinux()) File.SetUnixFileMode(binary, UnixFileMode.UserRead | UnixFileMode.UserExecute | UnixFileMode.GroupRead | UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
            pins.Add(new(tool.Id, tool.Version, JsonIO.ShaFile(binary), tool.ArchiveSha, tool.Url));
        }
        var configurations = ImmutableArray.CreateBuilder<FilePin>();
        foreach (var name in new[] { "gitleaks.toml", "syft.yaml", "grype.yaml" })
        {
            var source = Path.Combine(repository, "policies/scanners", name); var target = Path.Combine(bundle, "config", name);
            File.Copy(source, target, overwrite: true); configurations.Add(new("config/" + name, JsonIO.ShaFile(target)));
        }
        var status = await Processes.Run([Path.Combine(bundle, "bin/grype"), "--config", Path.Combine(repository, "policies/scanners/grype.yaml"), "db", "status", "-o", "json"], environment: new Dictionary<string, string>
        { ["GRYPE_DB_CACHE_DIR"] = Path.Combine(bundle, "db"), ["GRYPE_DB_AUTO_UPDATE"] = "false", ["GRYPE_CHECK_FOR_APP_UPDATE"] = "false" });
        if (status.ExitCode != 0 || status.TimedOut) throw new InvalidDataException("Provision a valid local vulnerability DB before pinning.");
        var metadata = JsonIO.Parse(status.Output);
        if (metadata["valid"]?.GetValue<bool>() != true) throw new InvalidDataException("Invalid database status.");
        var built = JsonIO.Text(metadata, "built"); _ = DateTimeOffset.Parse(built, System.Globalization.CultureInfo.InvariantCulture);
        var normalizedStatus = new { schemaVersion = JsonIO.Text(metadata, "schemaVersion"), built, source = JsonIO.Text(metadata, "from"), valid = true };
        JsonIO.Write(Path.Combine(bundle, "db-status.json"), normalizedStatus);
        var databaseFiles = Directory.EnumerateFiles(Path.Combine(bundle, "db"), "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal)
            .Select(p => new FilePin(Path.GetRelativePath(bundle, p).Replace('\\', '/'), JsonIO.ShaFile(p))).ToImmutableArray();
        if (databaseFiles.IsEmpty || databaseFiles.Any(p => !p.Path.StartsWith("db/6/", StringComparison.Ordinal))) throw new InvalidDataException("Expected one complete schema-6 database; provisioning must be finished.");
        if (OperatingSystem.IsLinux())
        {
            foreach (var directory in Directory.EnumerateDirectories(Path.Combine(bundle, "db"), "*", SearchOption.AllDirectories).Prepend(Path.Combine(bundle, "db")))
                File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.GroupRead | UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
            foreach (var pin in databaseFiles) File.SetUnixFileMode(Path.Combine(bundle, pin.Path), UnixFileMode.UserRead | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
        }
        using var context = new Scratch("security-assay-image-");
        foreach (var pin in pins) File.Copy(Path.Combine(bundle, "bin", pin.Id), Path.Combine(context.Path, pin.Id));
        File.WriteAllText(Path.Combine(context.Path, "Dockerfile"), "FROM scratch\nCOPY gitleaks syft grype /usr/local/bin/\nUSER 65532:65532\nWORKDIR /\n");
        var imageFile = Path.Combine(context.Path, "image-id");
        var build = await Processes.Run(["docker", "build", "--pull=false", "--network=none", "--iidfile", imageFile, context.Path], 120);
        if (build.ExitCode != 0 || build.TimedOut) throw new InvalidDataException("Cannot build the approved local scanner image.");
        var imageId = File.ReadAllText(imageFile).Trim();
        var toolchain = new ToolchainLock("security-assay-toolchain/0.1", "linux/amd64", imageId, pins.ToImmutable(), configurations.ToImmutable(),
            new(6, normalizedStatus.schemaVersion, built, normalizedStatus.source, databaseFiles, JsonIO.ShaFile(Path.Combine(bundle, "db-status.json"))));
        JsonIO.Write(Path.Combine(repository, "policies/toolchain.lock.json"), toolchain);
        WritePolicies(repository);
        return toolchain;
    }
}

public sealed class Scratch(string prefix) : IDisposable
{
    private readonly string privateParent = Directory.CreateTempSubdirectory(prefix).FullName;
    public string Path => Directory.CreateDirectory(System.IO.Path.Combine(privateParent, "content")).FullName;
    public void Dispose() { if (Directory.Exists(privateParent)) Directory.Delete(privateParent, recursive: true); }
}
