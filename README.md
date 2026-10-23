# SecurityAssay

C# M0 adapter over pinned Gitleaks, Syft and Grype, with **Pass / Fail /
Inconclusive / ToolFailure** receipts. It scans exactly declared source, lock and
configuration bytes inside offline containers, relates findings to pinned OWASP
ASVS 5.0.0 requirements and Top 10:2025 risk categories, and emits SARIF, a
CycloneDX SBOM and a SHA-256 receipt. A scoped M0 Pass is not application-security
certification or proof of an entire ASVS requirement.

`CanonFlow.Evidence` supplies pure native-union decisions and scope/policy/check
bindings. SecurityAssay keeps processes, files, package metadata parsing and tool
normalization in adapters. Source targets the exact .NET 11 RC1 SDK in global.json,
`net11.0`, preview C#, nullable analysis and warnings-as-errors. No Python tooling.

## Build and tests

```sh
dotnet restore SecurityAssay.slnx --locked-mode
dotnet build SecurityAssay.slnx --no-restore -c Release
dotnet test SecurityAssay.slnx --no-build --no-restore -c Release --max-parallel-test-modules 1
```

The initial restore may need NuGet access for the pinned test framework. This is
separate from security evaluation. See [provisioning](docs/PROVISIONING.md) for
the approved local tool/database bundle. Evaluation requires Linux and Docker;
it never pulls an image, updates a DB or performs an online vulnerability query.

## Evaluate declared inputs

After provisioning a bundle whose pins match the committed policy:

```sh
dotnet src/SecurityAssay/bin/Release/net11.0/SecurityAssay.dll scan \
  samples/clean samples/clean/inputs.json policies/m0.json \
  policies/toolchain.lock.json standards/asvs-5.0.0/catalog.json \
  /absolute/path/to/approved-bundle 2026-10-23T00:00:00Z artifacts/example
```

Use a fresh output directory. Exit codes: 0 Pass, 1 Fail, 2 Inconclusive,
3 ToolFailure, 64 bad command shape. A missing/incomplete scope cannot Pass.
Timestamps are explicit UTC evaluation instants; database freshness is assessed
against that instant, not silently inferred from a live database. Release callers
must establish the correct release time; historical receipts do not assert
current freshness.

`receipt.json` binds manifest/source/policy/catalog/toolchain and evaluator/core
binary hashes, normalized outputs and limits. `receipt.sha256` hashes its actual
bytes. `execution.json` and private raw reports retain execution-specific data
separately; they are not signatures or independent execution attestations.
The full SBOM retains declared first-party projects; the separately hashed
vulnerability input limits dependency matching to package identities. See the
evidence contract for the exact classification checks and unassessed-code limit.

## Profiles and scope

M0 checks secret-like material, declared NuGet/npm lock metadata, package
inventory coverage and vulnerability matches from the local DB. Packages are
never restored or executed. Lock metadata/SBOM hashes do not authenticate package
publishers or installed package archives. The manifest is the scope declaration;
omitting a source/project/lock means it is unassessed, not implicitly clean.

`policies/full-release.json` requires controls M0 does not implement and therefore
returns Inconclusive. Authorization, injection/deserialization/crypto rules,
deployment/debug/open-port settings, exception disclosure, audit logging,
publisher/signing evidence and AI-agent controls remain later scope. Specialist
scanner heuristics/default false-positive processing still apply. Every emitted
finding is retained and mapped; unrecognized mappings/severity prevent Pass.

See [M0 contract](docs/M0-CONTRACT.md), [evidence model](docs/EVIDENCE.md) and
[third-party notices](THIRD_PARTY_NOTICES.md). This undertaking stops at local
Forgejo draft review. Current qualification results are recorded separately;
documentation alone never grants verification authority.
