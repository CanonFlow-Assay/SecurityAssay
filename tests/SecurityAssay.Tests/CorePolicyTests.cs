using System.Collections.Immutable;
using CanonFlow.Evidence;
using CanonFlow.Security.Adapters;
using CanonFlow.Security.Domain;
using Xunit;

namespace SecurityAssay.Tests;

public sealed class CorePolicyTests
{
    [Theory]
    [InlineData(false, false, false, "Pass")]
    [InlineData(false, true, false, "Inconclusive")]
    [InlineData(true, false, false, "Fail")]
    [InlineData(true, true, false, "Fail")]
    [InlineData(false, false, true, "ToolFailure")]
    [InlineData(true, true, true, "ToolFailure")]
    public void FourNativeOutcomesKeepFailureAndMissingEvidenceExplicit(bool blocked, bool missing, bool broken, string expected)
        => Assert.Equal(expected, EvidenceDecisions.Code(EvidenceDecisions.Decide(new(blocked ? ["finding"] : [], missing ? ["gap"] : [], broken ? ["failure"] : [], new('a', 64), new('b', 64), ["scanner"], ["scanner"]))));

    [Theory]
    [InlineData("empty")]
    [InlineData("missing-check")]
    [InlineData("duplicate-check")]
    [InlineData("scope")]
    [InlineData("unknown-check")]
    public void EmptyOrUnboundExecutionEvidenceNeverAuthorizesPass(string kind)
    {
        var facts = new EvidenceFacts([], [], [], new('a', 64), new('b', 64), ["scanner"], ["scanner"]);
        facts = kind switch
        {
            "empty" => new([], [], []),
            "missing-check" => facts with { CompletedChecks = [] },
            "duplicate-check" => facts with { CompletedChecks = ["scanner", "scanner"] },
            "unknown-check" => facts with { CompletedChecks = ["scanner", "unregistered"] },
            _ => facts with { ScopeSha256 = "unbound" }
        };
        Assert.Equal("Inconclusive", EvidenceDecisions.Code(EvidenceDecisions.Decide(facts)));
    }

    [Fact]
    public void DefaultEvidenceCannotPass() => Assert.Equal("Inconclusive", EvidenceDecisions.Code(EvidenceDecisions.Decide(new(default, [], []))));

    [Theory]
    [InlineData(0, false)]
    [InlineData(1, false)]
    [InlineData(63, false)]
    [InlineData(64, true)]
    [InlineData(65, false)]
    public void HashIdentityRequiresExactlySha256(int length, bool expected) => Assert.Equal(expected, EvidenceDecisions.IsSha256(new string('a', length)));

    [Theory]
    [InlineData(-1, true)]
    [InlineData(0, false)]
    [InlineData(5, false)]
    [InlineData(6, true)]
    public void DatabaseFreshnessUsesExplicitEvaluationTime(int ageDays, bool missing)
    {
        var asOf = new DateTimeOffset(2026, 10, 23, 0, 0, 0, TimeSpan.Zero);
        Assert.Equal(missing, PolicyRules.Missing(Policy(), asOf, asOf.AddDays(-ageDays)).Length > 0);
    }

    [Theory]
    [InlineData("unknown-severity")]
    [InlineData("empty-checks")]
    [InlineData("duplicate-checks")]
    [InlineData("authorization")]
    [InlineData("invalid-hash")]
    public void UnimplementedOrMalformedPolicyNeverLooksComplete(string change)
    {
        var p = Policy();
        p = change switch
        {
            "unknown-severity" => p with { BlockAtSeverity = "urgent" },
            "empty-checks" => p with { RequiredChecks = [] },
            "duplicate-checks" => p with { RequiredChecks = ["secrets", "secrets"] },
            "authorization" => p with { RequiredChecks = [.. p.RequiredChecks, "authorization"] },
            _ => p with { CatalogSha256 = "unbound" }
        };
        var time = new DateTimeOffset(2026, 10, 23, 0, 0, 0, TimeSpan.Zero);
        Assert.NotEmpty(PolicyRules.Missing(p, time, time));
    }

    [Theory]
    [InlineData("{\"a\":1,\"a\":2}")]
    [InlineData("{\"a\":[{\"b\":1,\"b\":2}]}")]
    public void DuplicateJsonFieldsCannotChangeAnEvidenceDecision(string value) => Assert.Throws<InvalidDataException>(() => JsonIO.Parse(value));

    [Fact]
    public void SharedCorePreservesMutationReviewAsIncompleteEvidence()
    {
        // An independent consumer can retain mutation survivors without treating
        // a surviving/invalid/baseline-failed row as a passing release check.
        Assert.Equal("Inconclusive", EvidenceDecisions.Code(EvidenceDecisions.Decide(new([], ["survivor-review", "invalid-mutation", "baseline-failed"], []))));
    }

    private static SecurityPolicy Policy() => new("security-assay-policy/0.1", "m0-local-evidence", "High", 5, ["secrets", "inventory", "vulnerabilities"], new('a', 64), new('b', 64));
}
