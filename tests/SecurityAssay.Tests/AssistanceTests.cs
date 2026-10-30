using CanonFlow.Security.Domain;
using Xunit;

namespace SecurityAssay.Tests;

public sealed class AssistanceTests
{
    private static SecurityReviewFacts Complete() => new(true, true, true, "Pass", [], [], [], []);
    [Theory]
    [InlineData("Pass", "ReviewScope")]
    [InlineData("Fail", "ContextRequired")]
    [InlineData("Inconclusive", "CollectEvidence")]
    [InlineData("ToolFailure", "RepairTools")]
    [InlineData("Unknown", "ContextRequired")]
    public void AdvicePreservesOriginalVerdict(string verdict, string action)
    {
        var facts = Complete() with { OriginalVerdict = verdict };
        Assert.Equal(action, SecurityAssistance.Code(SecurityAssistance.Decide(facts, 1)));
        Assert.Equal(verdict, facts.OriginalVerdict);
    }
    [Theory]
    [InlineData("missing")]
    [InlineData("tampered")]
    [InlineData("stale")]
    [InlineData("time")]
    [InlineData("default")]
    public void UnavailableOrChangedEvidenceNeverRoutesToInvestigation(string change)
    {
        var facts = change switch {
            "missing" => Complete() with { ArtifactAvailable = false },
            "tampered" => Complete() with { IntegrityMatches = false },
            "stale" => Complete() with { InputsFresh = false },
            "time" => Complete() with { ContextGaps = ["evaluation time changed"] },
            _ => Complete() with { FindingIds = default }
        };
        Assert.Equal("ContextRequired", SecurityAssistance.Code(SecurityAssistance.Decide(facts, 1)));
    }
    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void EmptyBudgetDoesNotAuthorizeInvestigation(int budget)
        => Assert.Equal("BudgetExhausted", SecurityAssistance.Code(SecurityAssistance.Decide(Complete(), budget)));
    [Fact]
    public void ToolFailuresPrecedeFindingsAndFindingsPrecedeMissingEvidence()
    {
        var facts = Complete() with { FindingIds = ["finding"], Missing = ["gap"], Failures = ["scanner failed"] };
        Assert.Equal("RepairTools", SecurityAssistance.Code(SecurityAssistance.Decide(facts, 1)));
        Assert.Equal("ReviewFindings", SecurityAssistance.Code(SecurityAssistance.Decide(facts with { Failures = [] }, 1)));
        Assert.Equal("CollectEvidence", SecurityAssistance.Code(SecurityAssistance.Decide(facts with { Failures = [], FindingIds = [] }, 1)));
    }
    [Fact]
    public void MissingReceiptIsContextRatherThanASyntheticScan()
    {
        var result = CanonFlow.Security.Adapters.ReceiptReview.Run("/nonexistent/receipt.json", "/nonexistent",
            "/nonexistent/inputs.json", "/nonexistent/policy.json", "/nonexistent/chain.json",
            "/nonexistent/catalog.json", "2026-10-29T00:00:00Z", 1);
        Assert.Equal("ContextRequired", result["reviewState"]!.GetValue<string>());
        Assert.Equal("NotAvailable", result["originalVerdict"]!.GetValue<string>());
        Assert.Equal(0, result["providerRequests"]!.GetValue<int>());
    }

    [Theory]
    [InlineData("unchanged", "CollectEvidence")]
    [InlineData("source", "ContextRequired")]
    [InlineData("artifact", "ContextRequired")]
    [InlineData("digest", "ContextRequired")]
    [InlineData("time", "ContextRequired")]
    [InlineData("offset", "CollectEvidence")]
    [InlineData("missing-arrays", "ContextRequired")]
    [InlineData("profile", "ContextRequired")]
    [InlineData("empty-limits", "ContextRequired")]
    public async Task RealIncompleteEvaluationRetainsItsVerdictAndRefusesChangedInputs(string change, string expected)
    {
        var repository = AppContext.BaseDirectory;
        while (!File.Exists(Path.Combine(repository, "policies/m0.json")))
            repository = Directory.GetParent(repository)?.FullName ?? throw new InvalidOperationException("Repository not found.");
        var scratch = Path.Combine(Path.GetTempPath(), "security-review-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(scratch);
        try
        {
            var root = Path.Combine(scratch, "source"); Directory.CreateDirectory(root);
            foreach (var file in Directory.EnumerateFiles(Path.Combine(repository, "samples/clean")))
                File.Copy(file, Path.Combine(root, Path.GetFileName(file)));
            var manifest = Path.Combine(root, "inputs.json"); var policy = Path.Combine(repository, "policies/m0.json");
            var chain = Path.Combine(repository, "policies/toolchain.lock.json"); var catalog = Path.Combine(repository, "standards/asvs-5.0.0/catalog.json");
            var output = Path.Combine(scratch, "evidence");
            // Explicitly stale evaluation: the real adapter refuses scanners. This is not a fake clean scan.
            var pins = CanonFlow.Security.Adapters.JsonIO.Load<ToolchainLock>(chain);
            var activePolicy = CanonFlow.Security.Adapters.JsonIO.Load<SecurityPolicy>(policy);
            var time = DateTimeOffset.Parse(pins.Database.Built, System.Globalization.CultureInfo.InvariantCulture)
                .AddDays(activePolicy.MaximumDatabaseAgeDays + 1).ToUniversalTime();
            var receipt = await CanonFlow.Security.Adapters.Evaluator.Scan(root, manifest, policy, chain, catalog, Path.Combine(scratch, "missing-bundle"), time, output);
            Assert.Equal("Inconclusive", receipt.Verdict);
            Assert.Empty(receipt.Tools);
            if (change == "source") File.AppendAllText(Path.Combine(root, "App.cs"), "\n// changed\n");
            if (change == "artifact") File.AppendAllText(Path.Combine(output, "findings.sarif"), " ");
            if (change == "digest") File.WriteAllText(Path.Combine(output, "receipt.sha256"), new string('0', 64) + "  receipt.json\n");
            if (change is "missing-arrays" or "profile" or "empty-limits")
            {
                var file = Path.Combine(output, "receipt.json");
                var raw = CanonFlow.Security.Adapters.JsonIO.Read(file).AsObject();
                if (change == "missing-arrays") { raw.Remove("findings"); raw.Remove("tools"); raw.Remove("limits"); }
                if (change == "profile") raw.Remove("profile");
                if (change == "empty-limits") raw["limits"] = new System.Text.Json.Nodes.JsonArray();
                CanonFlow.Security.Adapters.JsonIO.Write(file, raw);
                File.WriteAllText(Path.Combine(output, "receipt.sha256"), CanonFlow.Security.Adapters.JsonIO.ShaFile(file) + "  receipt.json\n");
            }
            var review = CanonFlow.Security.Adapters.ReceiptReview.Run(Path.Combine(output, "receipt.json"), root, manifest, policy,
                chain, catalog, change == "offset" ? receipt.AsOf : (change == "time" ? time.AddDays(1) : time).UtcDateTime.ToString("O", System.Globalization.CultureInfo.InvariantCulture), 1);
            Assert.Equal(expected, review["reviewState"]!.GetValue<string>());
            Assert.Equal("Inconclusive", review["originalVerdict"]!.GetValue<string>());
            Assert.Equal("Inconclusive", review["receipt"]!["verdict"]!.GetValue<string>());
        }
        finally { Directory.Delete(scratch, recursive: true); }
    }
}
