using System.Globalization;
using CanonFlow.Security.Adapters;

try
{
    if (args is ["advise", var receiptFile, var currentRoot, var currentManifest, var currentPolicy, var currentChain, var currentCatalog, var evaluationTime, var reviewBudget] && int.TryParse(reviewBudget, out var budget))
    { Console.WriteLine(JsonIO.Canonical(ReceiptReview.Run(receiptFile, currentRoot, currentManifest, currentPolicy, currentChain, currentCatalog, evaluationTime, budget))); return 0; }
    if (args is ["qualify", var qualificationRepository, var qualificationBundle, var engine, var qualificationOutput])
    { Console.WriteLine(JsonIO.Canonical(await Qualification.Run(qualificationRepository, qualificationBundle, engine, qualificationOutput))); return 0; }
    if (args is ["qualify", var timedRepository, var timedBundle, var timedEngine, var timedInstant, var timedOutput])
    { Console.WriteLine(JsonIO.Canonical(await Qualification.Run(timedRepository, timedBundle, timedEngine, EvaluationTime.ParseUtc(timedInstant), timedOutput))); return 0; }
    if (args is ["policies", var policyRepository]) { Provisioning.WritePolicies(policyRepository); return 0; }
    if (args is ["provision", var repository, var bundle])
    { Console.WriteLine(JsonIO.Canonical(JsonIO.Node(await Provisioning.Prepare(repository, bundle)))); return 0; }
    if (args is ["scan", var root, var manifest, var policy, var chain, var catalog, var scannerBundle, var asOf, var output])
    {
        if (!asOf.EndsWith('Z')) throw new ArgumentException("Use an explicit UTC evaluation timestamp ending in Z.");
        var receipt = await Evaluator.Scan(root, manifest, policy, chain, catalog, scannerBundle, DateTimeOffset.Parse(asOf, CultureInfo.InvariantCulture), output);
        Console.WriteLine(JsonIO.Canonical(JsonIO.Node(new { receipt.Verdict, output = Path.GetFullPath(output) })));
        return receipt.Verdict switch { "Pass" => 0, "Fail" => 1, "Inconclusive" => 2, _ => 3 };
    }
    Console.Error.WriteLine("SecurityAssay advise <receipt> <root> <manifest> <policy> <toolchain> <catalog> <as-of-UTC> <budget> | qualify <repo> <bundle> <engine> [<as-of-UTC>] <fresh-output> | provision <repo> <bundle> | policies <repo> | scan <root> <manifest> <policy> <toolchain> <catalog> <bundle> <as-of-UTC> <fresh-output>");
    return 64;
}
catch (Exception failure) when (failure is IOException or UnauthorizedAccessException or InvalidDataException or ArgumentException or InvalidOperationException or FormatException)
{ Console.Error.WriteLine("SecurityAssay could not execute: " + failure.GetType().Name); return 3; }
