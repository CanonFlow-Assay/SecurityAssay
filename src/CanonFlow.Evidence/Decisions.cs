using System.Collections.Immutable;

namespace CanonFlow.Evidence;

public sealed record EvidencePass;
public sealed record EvidenceFail(ImmutableArray<string> BlockingFindings);
public sealed record EvidenceInconclusive(ImmutableArray<string> MissingEvidence);
public sealed record EvidenceToolFailure(ImmutableArray<string> Failures);
public union EvidenceVerdict(EvidencePass, EvidenceFail, EvidenceInconclusive, EvidenceToolFailure);

public sealed record EvidenceFacts(ImmutableArray<string> BlockingFindings,
    ImmutableArray<string> MissingEvidence, ImmutableArray<string> ToolFailures,
    string ScopeSha256 = "", string PolicySha256 = "", ImmutableArray<string> RequiredChecks = default,
    ImmutableArray<string> CompletedChecks = default);

public static class EvidenceDecisions
{
    public static EvidenceVerdict Decide(EvidenceFacts facts)
    {
        if (facts is null || facts.BlockingFindings.IsDefault || facts.MissingEvidence.IsDefault || facts.ToolFailures.IsDefault)
            return new EvidenceInconclusive(["Incomplete evidence facts."]);
        if (!facts.ToolFailures.IsEmpty) return new EvidenceToolFailure(facts.ToolFailures);
        if (!facts.BlockingFindings.IsEmpty) return new EvidenceFail(facts.BlockingFindings);
        if (!facts.MissingEvidence.IsEmpty) return new EvidenceInconclusive(facts.MissingEvidence);
        if (!IsSha256(facts.ScopeSha256) || !IsSha256(facts.PolicySha256) || facts.RequiredChecks.IsDefaultOrEmpty || facts.CompletedChecks.IsDefault ||
            facts.RequiredChecks.Any(string.IsNullOrWhiteSpace) || facts.CompletedChecks.Any(string.IsNullOrWhiteSpace) ||
            facts.RequiredChecks.Distinct(StringComparer.Ordinal).Count() != facts.RequiredChecks.Length ||
            facts.CompletedChecks.Distinct(StringComparer.Ordinal).Count() != facts.CompletedChecks.Length ||
            facts.RequiredChecks.Except(facts.CompletedChecks, StringComparer.Ordinal).Any() ||
            facts.CompletedChecks.Except(facts.RequiredChecks, StringComparer.Ordinal).Any())
            return new EvidenceInconclusive(["Required scope/policy/execution bindings are incomplete."]);
        return new EvidencePass();
    }

    public static string Code(EvidenceVerdict verdict) => verdict switch
    {
        EvidencePass => "Pass",
        EvidenceFail => "Fail",
        EvidenceInconclusive => "Inconclusive",
        EvidenceToolFailure => "ToolFailure"
    };

    public static bool IsSha256(string value) => value is not null && value.Length == 64 && value.All(char.IsAsciiHexDigit);
}
