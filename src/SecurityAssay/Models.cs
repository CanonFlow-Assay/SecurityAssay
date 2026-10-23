using System.Collections.Immutable;

namespace CanonFlow.Security.Domain;

public sealed record DeclaredInput(string Path, string Kind);
public sealed record ScanManifest(string Schema, ImmutableArray<DeclaredInput> Inputs);
public sealed record SecurityPolicy(string Schema, string Profile, string BlockAtSeverity, int MaximumDatabaseAgeDays,
    ImmutableArray<string> RequiredChecks, string CatalogSha256, string ToolchainSha256);
public sealed record FilePin(string Path, string Sha256);
public sealed record BinaryPin(string Id, string Version, string Sha256, string ArchiveSha256, string ReleaseUrl);
public sealed record DatabasePin(int Schema, string Version, string Built, string Source, ImmutableArray<FilePin> Files, string StatusSha256);
public sealed record ToolchainLock(string Schema, string Platform, string ImageId, ImmutableArray<BinaryPin> Tools,
    ImmutableArray<FilePin> Configurations, DatabasePin Database);
public sealed record PackageIdentity(string Ecosystem, string Name, string Version, string LockPath);
public sealed record FirstPartyIdentity(string Ecosystem, string Name, string Version, string LockPath);
public sealed record SecurityFinding(string Id, string Tool, string RuleId, string Severity, string Message,
    string Path, int Line, string Package, ImmutableArray<string> Asvs, ImmutableArray<string> Top10);
public sealed record ToolObservation(string Tool, string State, int Findings, string Version);
public sealed record Receipt(string Schema, string Verdict, string Profile, string AsOf,
    string InputSha256, string ManifestSha256, ImmutableArray<FilePin> Inputs, string PolicySha256, string CatalogSha256,
    string ToolchainSha256, string EvaluatorSha256, string EvidenceCoreSha256, string SbomSha256, string VulnerabilityInputSha256, string SarifSha256, ImmutableArray<ToolObservation> Tools,
    ImmutableArray<SecurityFinding> Findings, ImmutableArray<string> MissingEvidence,
    ImmutableArray<string> ToolFailures, ImmutableArray<string> Limits);

public static class PolicyRules
{
    public static readonly ImmutableArray<string> Implemented = ["secrets", "inventory", "vulnerabilities"];
    public static readonly ImmutableArray<string> Limits = [
        "Verdict applies only to declared bytes, approved tool/configuration/database pins and declared evaluation time.",
        "ASVS IDs are related requirement mappings, not certification or proof of complete requirement compliance.",
        "Package locks/SBOM hashes do not authenticate publishers, downloaded archives or signed release provenance.",
        "Declared NuGet Project references and npm lock root identities remain in the full SBOM; only their provenance-bound components are excluded from dependency vulnerability input. Their own code/version security is unassessed.",
        "Authorization, injection/deserialization/crypto, deployment, exception disclosure, audit logging and agent controls are not assessed by M0.",
        "Container isolation trusts the host Docker daemon; receipt hashing is not signing or independent execution attestation.",
        "Known-vulnerability results are bounded by the pinned database, scanner matchers and package discovery; absence of findings does not establish security."
    ];

    public static int Severity(string value) => (value is null ? "" : value.ToLowerInvariant()) switch
    { "negligible" => 0, "low" => 1, "medium" => 2, "high" => 3, "critical" => 4, _ => -1 };

    public static ImmutableArray<string> Missing(SecurityPolicy policy, DateTimeOffset asOf, DateTimeOffset databaseBuilt)
    {
        var missing = ImmutableArray.CreateBuilder<string>();
        if (policy.Schema != "security-assay-policy/0.1" || policy.Profile is not ("m0-local-evidence" or "full-release") || policy.RequiredChecks.IsDefaultOrEmpty ||
            policy.RequiredChecks.Distinct(StringComparer.Ordinal).Count() != policy.RequiredChecks.Length ||
            Severity(policy.BlockAtSeverity) < 0 || policy.MaximumDatabaseAgeDays is < 1 or > 30 ||
            !CanonFlow.Evidence.EvidenceDecisions.IsSha256(policy.CatalogSha256) ||
            !CanonFlow.Evidence.EvidenceDecisions.IsSha256(policy.ToolchainSha256)) missing.Add("Invalid or incomplete pinned security policy.");
        if (!policy.RequiredChecks.IsDefault)
            missing.AddRange(policy.RequiredChecks.Except(Implemented, StringComparer.Ordinal).Select(c => "Required check is not implemented: " + c));
        if (policy.Profile == "full-release") missing.Add("Full release controls are not covered by the M0 adapter.");
        if (databaseBuilt > asOf || asOf - databaseBuilt > TimeSpan.FromDays(Math.Max(0, policy.MaximumDatabaseAgeDays)))
            missing.Add("Vulnerability database is future-dated or stale relative to the declared evaluation time.");
        return missing.ToImmutable();
    }
}
