using System.Collections.Immutable;
using System.Text.Json.Nodes;
using CanonFlow.Security.Domain;

namespace CanonFlow.Security.Adapters;

public static class Reports
{
    public static object Sarif(ImmutableArray<SecurityFinding> findings, string input, string policy, string verdict = "Inconclusive",
        ImmutableArray<string> missing = default, ImmutableArray<string> failures = default)
    {
        var rules = findings.GroupBy(f => f.Tool + "/" + f.RuleId, StringComparer.Ordinal).OrderBy(g => g.Key, StringComparer.Ordinal)
            .Select(g => new { id = g.Key, name = g.First().RuleId, shortDescription = new { text = "Pinned scanner observation" },
                properties = new { asvs = g.First().Asvs, top10 = g.First().Top10, mappingRelation = "related-requirement-evidence" } }).ToArray();
        var document = JsonIO.Node(new { version = "2.1.0", runs = new[] { new {
            tool = new { driver = new { name = "SecurityAssay", version = "0.1.0-preview.1", rules } },
            properties = new { verdict, inputSha256 = input, policySha256 = policy, authority = "Declared M0 evidence only; not complete ASVS verification." },
            invocations = new[] { new { executionSuccessful = verdict is "Pass" or "Fail",
                toolExecutionNotifications = (failures.IsDefault ? [] : failures).Select(e => new { level = "error", message = new { text = e } })
                    .Concat((missing.IsDefault ? [] : missing).Select(e => new { level = "warning", message = new { text = e } })).ToArray() } },
            results = findings.Select(f => new { ruleId = f.Tool + "/" + f.RuleId,
                level = PolicyRules.Severity(f.Severity) >= 3 ? "error" : "warning", message = new { text = f.Message },
                locations = new[] { Location(f) },
                partialFingerprints = new Dictionary<string, string> { ["securityAssay/v1"] = f.Id },
                properties = new { f.Tool, f.Package, f.Severity, asvs = f.Asvs, top10 = f.Top10, mappingRelation = "related-requirement-evidence" }
            }).ToArray()
        } } });
        document["$schema"] = "https://json.schemastore.org/sarif-2.1.0.json";
        return document;
    }
    private static JsonObject Location(SecurityFinding finding)
    {
        var physical = new JsonObject { ["artifactLocation"] = new JsonObject { ["uri"] = string.Join('/', finding.Path.Split('/').Select(Uri.EscapeDataString)) } };
        if (finding.Line > 0) physical["region"] = new JsonObject { ["startLine"] = finding.Line };
        return new JsonObject { ["physicalLocation"] = physical };
    }
}
