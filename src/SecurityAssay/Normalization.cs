using System.Collections.Immutable;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using CanonFlow.Security.Domain;

namespace CanonFlow.Security.Adapters;

public static partial class Normalization
{
    public static ImmutableArray<string> CatalogIds(JsonNode catalog)
    {
        if (JsonIO.Text(catalog, "Version") != "5.0.0") throw new InvalidDataException("Unsupported ASVS catalog.");
        var ids = ImmutableArray.CreateBuilder<string>();
        void Visit(JsonNode? node)
        {
            if (node is JsonObject obj)
            {
                if (obj.ContainsKey("L") && obj["Shortcode"] is { } code) ids.Add("v5.0.0-" + code.GetValue<string>()[1..]);
                foreach (var value in obj) Visit(value.Value);
            }
            else if (node is JsonArray array) foreach (var value in array) Visit(value);
        }
        Visit(catalog);
        if (ids.Count < 100 || ids.Distinct(StringComparer.Ordinal).Count() != ids.Count) throw new InvalidDataException("Incomplete/duplicate ASVS catalog.");
        return ids.Order(StringComparer.Ordinal).ToImmutableArray();
    }

    public static JsonNode Sbom(JsonNode raw)
    {
        if (JsonIO.Text(raw, "bomFormat") != "CycloneDX" || raw["specVersion"]?.GetValue<string>() is not ("1.6" or "1.7") || raw["components"] is not JsonArray)
            throw new InvalidDataException("Unsupported/incomplete CycloneDX report.");
        var result = raw.DeepClone(); result.AsObject().Remove("serialNumber");
        if (result["metadata"] is JsonObject metadata) metadata.Remove("timestamp");
        SortSets(result, ""); return result;
    }
    private static readonly HashSet<string> SetFields = new(StringComparer.Ordinal) { "components", "dependencies", "dependsOn", "properties", "hashes", "licenses", "externalReferences", "occurrences" };
    private static void SortSets(JsonNode? node, string field)
    {
        if (node is JsonObject obj) foreach (var property in obj.ToArray()) SortSets(property.Value, property.Key);
        else if (node is JsonArray array)
        {
            foreach (var value in array) SortSets(value, field);
            if (!SetFields.Contains(field)) return;
            var sorted = array.Select(v => v?.DeepClone()).OrderBy(JsonIO.Canonical, StringComparer.Ordinal).ToArray();
            array.Clear(); foreach (var value in sorted) array.Add(value);
        }
    }

    public static JsonNode VulnerabilityInput(JsonNode sbom, ImmutableArray<FirstPartyIdentity> firstParty, ImmutableArray<PackageIdentity> dependencies)
    {
        var removed = new HashSet<string>(StringComparer.Ordinal);
        foreach (var component in JsonIO.Array(sbom, "components"))
        {
            if (component is null || !IsFirstParty(component, firstParty, dependencies)) continue;
            var reference = JsonIO.Text(component, "bom-ref");
            if (reference.Length == 0 || !removed.Add(reference)) throw new InvalidDataException("Ambiguous first-party SBOM reference.");
            if (component["properties"] is not JsonArray properties) throw new InvalidDataException("Missing first-party provenance.");
            properties.Add(new JsonObject { ["name"] = "security-assay:scope", ["value"] = "declared-first-party-code-unassessed" });
        }
        SortSets(sbom, "");
        var projection = sbom.DeepClone(); var components = JsonIO.Array(projection, "components");
        foreach (var component in components.ToArray())
            if (component?["bom-ref"] is { } reference && removed.Contains(reference.GetValue<string>())) components.Remove(component);
        if (projection["dependencies"] is JsonArray edges)
        {
            foreach (var edge in edges.ToArray())
            {
                if (edge?["ref"] is { } reference && removed.Contains(reference.GetValue<string>())) { edges.Remove(edge); continue; }
                foreach (var field in new[] { "dependsOn", "provides" })
                    if (edge?[field] is JsonArray targets)
                        foreach (var target in targets.ToArray())
                            if (target is not null && removed.Contains(target.GetValue<string>())) targets.Remove(target);
            }
        }
        return projection;
    }

    private static bool IsFirstParty(JsonNode component, ImmutableArray<FirstPartyIdentity> firstParty, ImmutableArray<PackageIdentity> dependencies)
    {
        if (firstParty.IsDefaultOrEmpty || component["purl"] is not { } purlNode || component["properties"] is not JsonArray properties) return false;
        var purl = purlNode.GetValue<string>(); var version = component["version"]?.GetValue<string>() ?? "";
        var name = component["name"]?.GetValue<string>() ?? "";
        string[] Values(string key) => properties.Where(p => p?["name"]?.GetValue<string>() == key).Select(p => JsonIO.Text(p, "value")).ToArray();
        var locations = properties.Where(p => p?["name"]?.GetValue<string>() is { } key && key.StartsWith("syft:location:", StringComparison.Ordinal) && key.EndsWith(":path", StringComparison.Ordinal))
            .Select(p => JsonIO.Text(p, "value")).ToArray();
        if (locations.Length != 1) return false;
        foreach (var identity in firstParty)
        {
            if (!SameName(identity.Name, name, identity.Ecosystem) || locations[0] != "/" + identity.LockPath ||
                dependencies.Any(d => d.Ecosystem == identity.Ecosystem && SameName(d.Name, name, d.Ecosystem) && d.Version == version)) continue;
            if (identity.Ecosystem == "nuget" && version == "UNKNOWN" && purl.StartsWith("pkg:nuget/", StringComparison.Ordinal) &&
                SameName(Uri.UnescapeDataString(purl[10..]), identity.Name, "nuget") &&
                Values("syft:package:foundBy").SequenceEqual(["dotnet-packages-lock-cataloger"]) &&
                Values("syft:package:metadataType").SequenceEqual(["dotnet-packages-lock-entry"])) return true;
            if (identity.Ecosystem == "npm" && version == identity.Version &&
                Values("syft:package:foundBy").SequenceEqual(["javascript-lock-cataloger"]) &&
                Values("syft:package:metadataType").SequenceEqual(["javascript-npm-package-lock-entry"]))
            {
                var parsed = ParsePurl(purl);
                if (parsed == ("npm", identity.Name, identity.Version)) return true;
            }
        }
        return false;
    }

    public static ImmutableArray<string> InventoryGaps(JsonNode sbom, ImmutableArray<PackageIdentity> expected, ImmutableArray<FilePin> files = default, bool declaredLock = false)
    {
        var components = JsonIO.Array(sbom, "components");
        foreach (var component in components.Where(c => c?["type"]?.GetValue<string>() == "file"))
        {
            if (files.IsDefault) throw new InvalidDataException("File component has no declared source scope.");
            var path = DeclaredPath(JsonIO.Text(component, "name"), files);
            var hash = (component?["hashes"] as JsonArray)?.SingleOrDefault(h => h?["alg"]?.GetValue<string>() == "SHA-256")?["content"]?.GetValue<string>();
            if (hash is null || !string.Equals(hash, files.Single(f => f.Path == path).Sha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("SBOM file component hash differs from declared snapshot.");
        }
        var observed = components.Where(c => c?["type"]?.GetValue<string>() != "file").Select(c => ParsePurl(JsonIO.Text(c, "purl"))).ToImmutableArray();
        var missing = ImmutableArray.CreateBuilder<string>();
        if (expected.IsEmpty && !declaredLock) missing.Add("No supported dependency lock was supplied; dependency evidence is incomplete.");
        foreach (var package in expected)
            if (!observed.Any(o => o.Ecosystem == package.Ecosystem && SameName(o.Name, package.Name, o.Ecosystem) && o.Version == package.Version))
                missing.Add("Locked package was not inventoried: " + package.LockPath + " / " + package.Name + "@" + package.Version);
        foreach (var package in observed)
            if (!expected.Any(e => e.Ecosystem == package.Ecosystem && SameName(e.Name, package.Name, e.Ecosystem) && e.Version == package.Version))
                missing.Add("SBOM contains an undeclared package identity: " + package.Name + "@" + package.Version);
        return missing.ToImmutable();
    }

    public static ImmutableArray<SecurityFinding> Secrets(JsonNode report, int exitCode, ImmutableArray<FilePin> files, string approvedConfig)
    {
        var allowed = RuleIdRegex().Matches(approvedConfig).Select(m => m.Groups[1].Value).ToHashSet(StringComparer.Ordinal);
        if (report is not JsonArray rows || (exitCode == 0 && rows.Count != 0) || (exitCode == 10 && rows.Count == 0) || exitCode is not (0 or 10))
            throw new InvalidDataException("Gitleaks exit/report contradiction or tool failure.");
        var findings = ImmutableArray.CreateBuilder<SecurityFinding>();
        foreach (var row in rows)
        {
            if (JsonIO.Text(row, "Secret") != "REDACTED") throw new InvalidDataException("Secret scanner did not enforce full redaction; raw report is not retained.");
            var rule = JsonIO.Text(row, "RuleID");
            var path = DeclaredPath(JsonIO.Text(row, "File"), files); var line = row?["StartLine"]?.GetValue<int>() ?? 0;
            if (line < 1) throw new InvalidDataException("Invalid secret source location.");
            findings.Add(Finding("gitleaks", rule, allowed.Contains(rule) ? "Critical" : "Unknown", "Secret-like material reported by the pinned Gitleaks rule.", path, line, "",
                allowed.Contains(rule) ? ["v5.0.0-13.3.1"] : [], ["A02:2025", "A08:2025"]));
        }
        return findings.ToImmutable();
    }

    public static ImmutableArray<SecurityFinding> Vulnerabilities(JsonNode report, ImmutableArray<PackageIdentity> expected)
    {
        if (report["matches"] is not JsonArray matches ||
            (report.AsObject().ContainsKey("ignoredMatches") && (report["ignoredMatches"] is not JsonArray ignored || ignored.Count != 0)) ||
            report["descriptor"] is not JsonObject)
            throw new InvalidDataException("Incomplete or filtered Grype report.");
        var findings = ImmutableArray.CreateBuilder<SecurityFinding>();
        foreach (var match in matches)
        {
            var artifact = match?["artifact"] ?? throw new InvalidDataException("Missing vulnerability artifact.");
            var package = ParsePurl(JsonIO.Text(artifact, "purl"));
            var locations = expected.Where(p => p.Ecosystem == package.Ecosystem && SameName(p.Name, package.Name, p.Ecosystem) && p.Version == package.Version).Select(p => p.LockPath).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
            if (locations.Length == 0) throw new InvalidDataException("Vulnerability finding lies outside declared lock identities.");
            var vulnerability = match?["vulnerability"] ?? throw new InvalidDataException("Missing vulnerability evidence.");
            var id = JsonIO.Text(vulnerability, "id"); var severity = JsonIO.Text(vulnerability, "severity");
            if (id.Length == 0 || JsonIO.Text(vulnerability, "namespace").Length == 0 || match?["matchDetails"] is not JsonArray details || details.Count == 0)
                throw new InvalidDataException("Missing vulnerability identity/match evidence.");
            foreach (var path in locations) findings.Add(Finding("grype", id, severity,
                "Known vulnerable dependency reported against the pinned local database; remediation policy review required.", path, 0,
                package.Name + "@" + package.Version, ["v5.0.0-15.1.1", "v5.0.0-15.2.1"], ["A03:2025"]));
        }
        return findings.Distinct().OrderBy(f => f.Id, StringComparer.Ordinal).ToImmutableArray();
    }

    private static SecurityFinding Finding(string tool, string rule, string severity, string message, string path, int line, string package,
        ImmutableArray<string> asvs, ImmutableArray<string> top10) => new(JsonIO.ShaText(string.Join('\n', tool, rule, severity, path, line.ToString(System.Globalization.CultureInfo.InvariantCulture), package)),
            tool, rule, severity, message, path, line, package, asvs, top10);

    public static string DeclaredPath(string path, ImmutableArray<FilePin> files)
    {
        if (path.StartsWith("/target/", StringComparison.Ordinal)) path = path[8..];
        else if (path.StartsWith("target/", StringComparison.Ordinal)) path = path[7..];
        if (!files.Any(f => f.Path == path)) throw new InvalidDataException("Scanner finding is outside declared input scope.");
        return path;
    }

    public static (string Ecosystem, string Name, string Version) ParsePurl(string purl)
    {
        var value = purl.Split('?', '#')[0]; var slash = value.IndexOf('/'); var at = value.LastIndexOf('@');
        if (!value.StartsWith("pkg:", StringComparison.Ordinal) || slash < 5 || at <= slash || at == value.Length - 1) throw new InvalidDataException("Missing/unsupported package URL identity.");
        var ecosystem = value[4..slash];
        if (ecosystem is not ("nuget" or "npm")) throw new InvalidDataException("Unsupported package ecosystem.");
        return (ecosystem, Uri.UnescapeDataString(value[(slash + 1)..at]), Uri.UnescapeDataString(value[(at + 1)..]));
    }
    private static bool SameName(string left, string right, string ecosystem) => string.Equals(left, right, ecosystem == "nuget" ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);

    [GeneratedRegex("(?m)^id\\s*=\\s*\"([^\"]+)\"")]
    private static partial Regex RuleIdRegex();
}
