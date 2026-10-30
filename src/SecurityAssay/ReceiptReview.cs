using System.Collections.Immutable;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using CanonFlow.Security.Domain;

namespace CanonFlow.Security.Adapters;

public static class ReceiptReview
{
    public static JsonNode Run(string receiptPath, string root, string manifestPath, string policyPath,
        string chainPath, string catalogPath, string asOfText, int budget)
    {
        var gaps = ImmutableArray.CreateBuilder<string>();
        string original = "NotAvailable", digest = "";
        JsonNode? observed = null;
        SecurityReviewFacts facts = new(false, false, false, original, [], [], [], []);
        try
        {
            receiptPath = Path.GetFullPath(receiptPath);
            InputSnapshot.RejectLink(receiptPath);
            RegularFiles.Require(receiptPath);
            var directory = Path.GetDirectoryName(receiptPath)!;
            var beforeReceipt = JsonIO.ShaFile(receiptPath);
            var document = JsonIO.Read(receiptPath);
            observed = document.DeepClone();
            var receipt = document.Deserialize<Receipt>(JsonIO.Options) ?? throw new InvalidDataException("Missing receipt.");
            original = receipt.Verdict;
            digest = JsonIO.ShaFile(receiptPath);
            if (beforeReceipt != digest) gaps.Add("Receipt changed during inspection.");
            var declaredDigestPath = Path.Combine(directory, "receipt.sha256");
            InputSnapshot.RejectLink(declaredDigestPath);
            RegularFiles.Require(declaredDigestPath);
            var declaredDigest = File.ReadAllText(declaredDigestPath).Trim();
            var integrity = Path.GetFileName(receiptPath) == "receipt.json" && declaredDigest == digest + "  receipt.json";
            if (!integrity) gaps.Add("Receipt digest does not match its companion file.");
            foreach (var (name, expected) in new[] {
                ("findings.sarif", receipt.SarifSha256), ("sbom.cdx.json", receipt.SbomSha256),
                ("vulnerability-input.cdx.json", receipt.VulnerabilityInputSha256) })
            {
                var file = Path.Combine(directory, name);
                InputSnapshot.RejectLink(file); RegularFiles.Require(file);
                if (JsonIO.ShaFile(file) != expected) gaps.Add("An evidence artifact changed: " + name);
            }
            foreach (var inputPath in new[] { manifestPath, policyPath, chainPath, catalogPath }) { InputSnapshot.RejectLink(inputPath); RegularFiles.Require(inputPath); }
            var initial = new[] { manifestPath, policyPath, chainPath, catalogPath }.Select(JsonIO.ShaFile).ToArray();
            using var snapshot = new InputSnapshot(root, JsonIO.Load<ScanManifest>(manifestPath));
            var current = snapshot.Digest == receipt.InputSha256 && !receipt.Inputs.IsDefaultOrEmpty &&
                JsonIO.Digest(JsonIO.Node(receipt.Inputs)) == receipt.InputSha256 &&
                initial.SequenceEqual(new[] { receipt.ManifestSha256, receipt.PolicySha256, receipt.ToolchainSha256, receipt.CatalogSha256 });
            if (!current) gaps.Add("Declared source, manifest, policy, toolchain or catalog changed.");
            if (receipt.Schema != "security-assay-receipt/0.1") gaps.Add("Unsupported receipt schema.");
            if (receipt.Profile is not ("m0-local-evidence" or "full-release") || receipt.Profile != JsonIO.Load<SecurityPolicy>(policyPath).Profile)
                gaps.Add("Receipt profile does not match the current policy.");
            if (receipt.Findings.IsDefault || receipt.Tools.IsDefault || receipt.MissingEvidence.IsDefault || receipt.ToolFailures.IsDefault || receipt.Limits.IsDefaultOrEmpty)
                gaps.Add("Required receipt arrays are missing.");
            else if (receipt.Findings.Any(f => f is null || string.IsNullOrWhiteSpace(f.Id)) ||
                receipt.MissingEvidence.Any(string.IsNullOrWhiteSpace) || receipt.ToolFailures.Any(string.IsNullOrWhiteSpace) ||
                receipt.Limits.Any(string.IsNullOrWhiteSpace) ||
                receipt.Tools.Any(t => t is null || t.Tool is not ("gitleaks" or "syft" or "grype") || t.State != "Completed" || t.Findings < 0 || string.IsNullOrWhiteSpace(t.Version)) ||
                receipt.Tools.Select(t => t.Tool).Distinct(StringComparer.Ordinal).Count() != receipt.Tools.Length)
                gaps.Add("Receipt arrays contain invalid or duplicate observations.");
            if (!(asOfText.EndsWith('Z') || asOfText.EndsWith("+00:00", StringComparison.Ordinal)) || !DateTimeOffset.TryParse(asOfText, CultureInfo.InvariantCulture, DateTimeStyles.None, out var asOf) ||
                !DateTimeOffset.TryParse(receipt.AsOf, CultureInfo.InvariantCulture, DateTimeStyles.None, out var receiptTime) || asOf != receiptTime || receiptTime.Offset != TimeSpan.Zero)
                gaps.Add("Receipt evaluation time differs from the requested review time; run a new scan.");
            if (receipt.EvaluatorSha256 != JsonIO.ShaFile(typeof(ReceiptReview).Assembly.Location) ||
                receipt.EvidenceCoreSha256 != JsonIO.ShaFile(typeof(CanonFlow.Evidence.EvidenceDecisions).Assembly.Location))
                gaps.Add("Evaluator or evidence-core bytes differ from the receipt.");
            snapshot.Verify();
            if (!initial.SequenceEqual(new[] { manifestPath, policyPath, chainPath, catalogPath }.Select(JsonIO.ShaFile)))
                gaps.Add("Review inputs changed during inspection.");
            if (JsonIO.ShaFile(receiptPath) != digest || File.ReadAllText(declaredDigestPath).Trim() != declaredDigest)
                gaps.Add("Receipt/digest changed during inspection.");
            foreach (var (name, expected) in new[] { ("findings.sarif", receipt.SarifSha256), ("sbom.cdx.json", receipt.SbomSha256), ("vulnerability-input.cdx.json", receipt.VulnerabilityInputSha256) })
                if (JsonIO.ShaFile(Path.Combine(directory, name)) != expected) gaps.Add("Evidence artifacts changed during inspection.");
            facts = new(true, integrity, current, original,
                receipt.Findings.IsDefault ? default : receipt.Findings.Select(f => f.Id).ToImmutableArray(),
                receipt.MissingEvidence, receipt.ToolFailures, gaps.ToImmutable());
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or InvalidDataException or
            JsonException or ArgumentException or InvalidOperationException or FormatException or NullReferenceException)
        {
            gaps.Add("Receipt or current input evidence is missing, malformed or unreadable.");
            facts = facts with { ContextGaps = gaps.ToImmutable() };
        }
        var decision = SecurityAssistance.Decide(facts, budget);
        return JsonIO.Node(new {
            schema = "security-assay-advice/0.1",
            authority = "AdvisoryOnly",
            originalVerdict = original,
            receipt = observed,
            receiptSha256 = digest,
            reviewState = SecurityAssistance.Code(decision),
            contextGaps = gaps.ToImmutable(),
            remainingBudget = budget,
            providerRequests = 0,
            limits = new[] { "Does not execute scanners, modify evidence, grant Pass or waive controls.",
                "Input/time/artifact inspection is local integrity evidence, not signed attestation.",
                "Tool/database bytes and scanner execution must be qualified by a new scan; this command does not re-run them." }
        });
    }
}
