using System.Collections.Immutable;

namespace CanonFlow.Security.Domain;

public sealed record SecurityContextRequired(ImmutableArray<string> Reasons);
public sealed record SecurityRepairTools(ImmutableArray<string> Failures);
public sealed record SecurityReviewFindings(ImmutableArray<string> FindingIds);
public sealed record SecurityCollectEvidence(ImmutableArray<string> Missing);
public sealed record SecurityScopeReview;
public sealed record SecurityBudgetExhausted;
public union SecurityInvestigation(SecurityContextRequired, SecurityRepairTools, SecurityReviewFindings,
    SecurityCollectEvidence, SecurityScopeReview, SecurityBudgetExhausted);

public sealed record SecurityReviewFacts(bool ArtifactAvailable, bool IntegrityMatches, bool InputsFresh,
    string OriginalVerdict, ImmutableArray<string> FindingIds, ImmutableArray<string> Missing,
    ImmutableArray<string> Failures, ImmutableArray<string> ContextGaps);

public static class SecurityAssistance
{
    // Advice never returns a verification verdict and never executes a command.
    public static SecurityInvestigation Decide(SecurityReviewFacts facts, int remainingBudget)
    {
        if (facts is null || !facts.ArtifactAvailable || !facts.IntegrityMatches || !facts.InputsFresh ||
            facts.FindingIds.IsDefault || facts.Missing.IsDefault || facts.Failures.IsDefault || facts.ContextGaps.IsDefault ||
            facts.OriginalVerdict is not ("Pass" or "Fail" or "Inconclusive" or "ToolFailure"))
            return new SecurityContextRequired(["Receipt integrity and current input/time bindings are required."]);
        if (!facts.ContextGaps.IsEmpty) return new SecurityContextRequired(facts.ContextGaps);
        if (remainingBudget < 1) return new SecurityBudgetExhausted();
        if (!facts.Failures.IsEmpty || facts.OriginalVerdict == "ToolFailure") return new SecurityRepairTools(facts.Failures);
        if (!facts.FindingIds.IsEmpty) return new SecurityReviewFindings(facts.FindingIds);
        if (!facts.Missing.IsEmpty || facts.OriginalVerdict == "Inconclusive") return new SecurityCollectEvidence(facts.Missing);
        if (facts.OriginalVerdict == "Fail") return new SecurityContextRequired(["Fail receipt has no reviewable findings."]);
        return new SecurityScopeReview();
    }

    public static string Code(SecurityInvestigation decision) => decision switch
    {
        SecurityContextRequired => "ContextRequired",
        SecurityRepairTools => "RepairTools",
        SecurityReviewFindings => "ReviewFindings",
        SecurityCollectEvidence => "CollectEvidence",
        SecurityScopeReview => "ReviewScope",
        SecurityBudgetExhausted => "BudgetExhausted"
    };
}
