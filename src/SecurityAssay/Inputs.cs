using System.Collections.Immutable;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using CanonFlow.Security.Domain;

namespace CanonFlow.Security.Adapters;

public sealed partial class InputSnapshot : IDisposable
{
    public string Root { get; }
    private readonly string privateParent;
    public string DirectoryPath { get; }
    public ImmutableArray<FilePin> Files { get; }
    public string Digest { get; }
    public ImmutableArray<PackageIdentity> Packages { get; }
    public ImmutableArray<FirstPartyIdentity> FirstParty { get; }
    public ImmutableArray<string> Gaps { get; }

    public InputSnapshot(string root, ScanManifest manifest)
    {
        Root = Path.GetFullPath(root);
        if (manifest.Schema != "security-assay-inputs/0.1" || manifest.Inputs.IsDefaultOrEmpty ||
            manifest.Inputs.Length > 10000 || manifest.Inputs.Any(i => i is null) ||
            manifest.Inputs.Select(i => i.Path).Distinct(StringComparer.Ordinal).Count() != manifest.Inputs.Length)
            throw new InvalidDataException("Empty, duplicate or unsupported declared input scope.");
        RejectLink(Root);
        privateParent = System.IO.Directory.CreateTempSubdirectory("security-assay-input-").FullName;
        DirectoryPath = System.IO.Directory.CreateDirectory(Path.Combine(privateParent, "snapshot")).FullName;
        var files = ImmutableArray.CreateBuilder<FilePin>(); var packages = ImmutableArray.CreateBuilder<PackageIdentity>();
        var firstParty = ImmutableArray.CreateBuilder<FirstPartyIdentity>();
        var gaps = ImmutableArray.CreateBuilder<string>(); long bytes = 0;
        try
        {
            foreach (var input in manifest.Inputs.OrderBy(i => i.Path, StringComparer.Ordinal))
            {
                if (input.Kind is not ("source" or "config" or "nuget-lock" or "npm-lock")) throw new InvalidDataException("Unsupported declared input kind.");
                var original = Inside(Root, input.Path);
                var length = new FileInfo(original).Length; bytes += length;
                if (length > 4 * 1024 * 1024 || bytes > 64 * 1024 * 1024) throw new InvalidDataException("Declared snapshot exceeds the M0 size boundary.");
                var hash = JsonIO.ShaFile(original); var target = Inside(DirectoryPath, input.Path, requireFile: false);
                Directory.CreateDirectory(Path.GetDirectoryName(target)!); File.Copy(original, target, overwrite: false);
                if (JsonIO.ShaFile(target) != hash || JsonIO.ShaFile(original) != hash) throw new InvalidDataException("Source changed while snapshotting.");
                if (OperatingSystem.IsLinux()) File.SetUnixFileMode(target, UnixFileMode.UserRead | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
                files.Add(new(input.Path, hash));
                if (input.Kind.EndsWith("-lock", StringComparison.Ordinal)) ReadLock(target, input, packages, firstParty, gaps);
            }
            if (OperatingSystem.IsLinux()) foreach (var directory in System.IO.Directory.EnumerateDirectories(DirectoryPath, "*", SearchOption.AllDirectories).Prepend(DirectoryPath))
                File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.GroupRead | UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
            Files = files.ToImmutable(); Packages = packages.Distinct().ToImmutableArray(); FirstParty = firstParty.Distinct().ToImmutableArray(); Gaps = gaps.ToImmutable();
            Digest = JsonIO.Digest(JsonIO.Node(Files)); Verify();
        }
        catch { Dispose(); throw; }
    }

    public void Verify()
    {
        foreach (var pin in Files)
            if (JsonIO.ShaFile(Inside(Root, pin.Path)) != pin.Sha256 || JsonIO.ShaFile(Inside(DirectoryPath, pin.Path)) != pin.Sha256)
                throw new InvalidDataException("Declared source/snapshot changed during evaluation.");
    }
    public static string Inside(string root, string relative, bool requireFile = true)
    {
        if (string.IsNullOrWhiteSpace(relative) || Path.IsPathRooted(relative) || relative.Contains('\\') || relative.Any(char.IsControl) ||
            relative.Split('/').Any(p => p is "" or "." or "..")) throw new InvalidDataException("Declared path escapes or ambiguously identifies scope.");
        root = Path.GetFullPath(root); RejectLink(root); var current = root;
        foreach (var component in relative.Split('/')) { current = Path.Combine(current, component); RejectLink(current); }
        if (!current.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.Ordinal) || (requireFile && !File.Exists(current)))
            throw new InvalidDataException("Declared input is missing or not a regular file.");
        if (requireFile && (File.GetAttributes(current) & FileAttributes.Directory) != 0) throw new InvalidDataException("Declare individual regular files.");
        if (requireFile) RegularFiles.Require(current);
        return current;
    }
    public static void RejectLink(string path)
    {
        for (FileInfo? info = new FileInfo(Path.GetFullPath(path)); info is not null; info = info.Directory is { } parent ? new FileInfo(parent.FullName) : null)
            if (info.LinkTarget is not null || (info.Exists && (info.Attributes & FileAttributes.ReparsePoint) != 0)) throw new InvalidDataException("Symlink/reparse input or ancestor is forbidden.");
    }
    public void Dispose() { if (System.IO.Directory.Exists(privateParent)) System.IO.Directory.Delete(privateParent, recursive: true); }

    private static void ReadLock(string file, DeclaredInput input, ImmutableArray<PackageIdentity>.Builder packages,
        ImmutableArray<FirstPartyIdentity>.Builder firstParty, ImmutableArray<string>.Builder gaps)
    {
        var value = JsonIO.Read(file);
        if (input.Kind == "nuget-lock")
        {
            if (Path.GetFileName(input.Path) != "packages.lock.json" || value["version"]?.GetValue<int>() != 1 || value["dependencies"] is not JsonObject targets)
            { gaps.Add("Unsupported NuGet lock format: " + input.Path); return; }
            foreach (var target in targets)
            {
                if (target.Value is not JsonObject dependencies) { gaps.Add("Malformed lock target: " + input.Path); continue; }
                foreach (var (name, package) in dependencies)
                {
                    if (package?["type"]?.GetValue<string>() == "Project")
                    {
                        if (string.IsNullOrWhiteSpace(name)) gaps.Add("Unnamed project reference: " + input.Path);
                        else firstParty.Add(new("nuget", name, "", input.Path));
                        continue;
                    }
                    if (package?["type"]?.GetValue<string>() is not ("Direct" or "Transitive") || package["resolved"] is null || package["contentHash"] is null)
                    { gaps.Add("Missing package identity/integrity metadata: " + input.Path); continue; }
                    var version = package["resolved"]!.GetValue<string>();
                    if (!SupportedVersion(version, nuget: true) || !StrongHash(package["contentHash"]!.GetValue<string>(), false)) gaps.Add("Incomplete/unsupported package version or integrity metadata: " + input.Path);
                    packages.Add(new("nuget", name, version, input.Path));
                }
            }
        }
        else
        {
            if (Path.GetFileName(input.Path) != "package-lock.json" || value["lockfileVersion"]?.GetValue<int>() is not (2 or 3) || value["packages"] is not JsonObject dependencies)
            { gaps.Add("Unsupported npm lock format: " + input.Path); return; }
            foreach (var (location, package) in dependencies)
            {
                if (location.Length == 0)
                {
                    var rootName = package?["name"]?.GetValue<string>(); var rootVersion = package?["version"]?.GetValue<string>();
                    if (!string.IsNullOrWhiteSpace(rootName) && !string.IsNullOrWhiteSpace(rootVersion))
                    {
                        if (!SupportedVersion(rootVersion, nuget: false)) gaps.Add("Unsupported npm root version: " + input.Path);
                        firstParty.Add(new("npm", rootName, rootVersion, input.Path));
                    }
                    continue;
                }
                var marker = location.LastIndexOf("node_modules/", StringComparison.Ordinal);
                if (marker < 0 || package?["link"]?.GetValue<bool>() == true || package?["version"] is null)
                { gaps.Add("Unresolved/link package in lock: " + input.Path); continue; }
                var name = location[(marker + 13)..]; var version = package["version"]!.GetValue<string>();
                if (package["resolved"] is { } resolved && (!Uri.TryCreate(resolved.GetValue<string>(), UriKind.Absolute, out var uri) || uri.Scheme != "https" || uri.UserInfo.Length != 0 || uri.Query.Length != 0))
                    throw new InvalidDataException("Credential-bearing or unsupported package transport metadata is not accepted by M0.");
                if (name.Length == 0 || !SupportedVersion(version, nuget: false) || !StrongHash(package["integrity"]?.GetValue<string>() ?? "", true)) gaps.Add("Incomplete/unsupported package version or integrity metadata: " + input.Path);
                packages.Add(new("npm", name, version, input.Path));
            }
        }
    }
    private static bool StrongHash(string value, bool npm)
    {
        if (npm) { if (!value.StartsWith("sha512-", StringComparison.Ordinal)) return false; value = value[7..]; }
        try { return Convert.FromBase64String(value).Length == 64; } catch (FormatException) { return false; }
    }

    public static bool SupportedVersion(string version, bool nuget)
    {
        if (string.IsNullOrEmpty(version) || version.Length > 128 || !PackageVersionRegex().IsMatch(version)) return false;
        var core = version.Split('-', '+')[0].Split('.');
        var release = version.Split('+')[0]; var hyphen = release.IndexOf('-');
        if (hyphen >= 0 && release[(hyphen + 1)..].Split('.').Any(part => part.Length > 1 && part[0] == '0' && part.All(char.IsAsciiDigit))) return false;
        return (nuget || core.Length == 3) && core.All(part => int.TryParse(part, System.Globalization.NumberStyles.None,
            System.Globalization.CultureInfo.InvariantCulture, out _));
    }

    [GeneratedRegex(@"\A(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*))?(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\z")]
    private static partial Regex PackageVersionRegex();
}
