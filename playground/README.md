# Security evidence playground

This local application of the CSAssay workflow preserves SecurityAssay's pinned, offline scanner boundary. The domain exposes native-union investigation outcomes. Advice never grants a verdict or executes a suggested action.

Run from the repository root with the exact SDK in `global.json`:

```sh
bash eng/try-playground.sh --output artifacts/playground/current
```

The script builds and tests, evaluates only the declared clean fixture at the current explicit UTC time, and reviews the resulting receipt. It uses `SECURITYASSAY_BUNDLE` or the workstation's existing `~/.cache/securityassay-m0` bundle. It never provisions, updates databases, pulls images or calls providers. Choose a fresh output directory for every run.

The committed database is dated 22 October 2026 and the policy permits five days. A current run on 29 October must retain stale-database evidence and `Inconclusive`; the adapter refuses to execute scanners for already incomplete scope. Do not relabel that outcome as a clean scan. A deliberately historical `--as-of` describes only that historical evaluation instant.

The script exits with the original scan status: 0 Pass, 1 Fail, 2 Inconclusive, 3 ToolFailure. Its successful build/tests do not change that status.

## Inspect a receipt separately

```sh
dotnet src/SecurityAssay/bin/Release/net11.0/SecurityAssay.dll advise \
  artifacts/playground/current/clean/receipt.json \
  samples/clean samples/clean/inputs.json policies/m0.json \
  policies/toolchain.lock.json standards/asvs-5.0.0/catalog.json \
  2026-10-29T00:00:00Z 1
```

Use the exact `asOf` from the receipt if reviewing that evaluation. A different time requests new context. The envelope embeds the original receipt unchanged and records its digest separately. It checks the companion digest, SARIF/SBOM/vulnerability input, current declared bytes/manifest/policy/catalog/toolchain, evaluator/core identities and explicit evaluation time. Missing, malformed, modified or stale inputs route to `ContextRequired`.

Eligible local advice is `RepairTools`, `ReviewFindings`, `CollectEvidence` or `ReviewScope`; zero budget yields `BudgetExhausted`. `ReviewScope` asks for human examination of the bounded M0 scope; it is not a release grant. This command inspects evidence rather than re-running scanners or independently attesting tool/database bytes.

Requirements and expected controls are in [requirements.json](requirements.json). Existing scanner qualification and historical raw evidence remain separate.

See [phase-1 portable convergence](CONVERGENCE.md) for the receipt-ingress
candidate and the security scope exclusions that remain in force.
