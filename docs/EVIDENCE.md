# Evidence contract

`CanonFlow.Evidence` projects native unions to the four external verdict names.
Missing/default facts or missing/duplicate/unregistered check bindings cannot
Pass. Known tool failure takes precedence, followed by known blocking findings,
then incomplete scope; findings stay visible regardless. Empty failure lists
alone are insufficient: scope/policy hashes and all registered completed checks
are required. A test exercises the same core's mutation-review use without
claiming that the older MutationAssay/DAA code was migrated to this new library.

The evaluator records declared file SHA-256 values, raw manifest/policy/catalog/
toolchain identities and hashes of its own/evidence-core DLLs. Source snapshots
are copied and verified before/after use. Linux statx rejects nonregular objects
such as FIFOs/devices; symlinks, path escapes and missing/duplicate declarations
are rejected. Read limits apply. An adversarial privileged/concurrently mutating
host remains outside the isolation claim.

Syft's CycloneDX includes file components as well as packages. File paths and
SHA-256 values must bind to declared files. Package identities must reconcile
with supported lock metadata; foreign/missing packages remain evidence gaps.
NuGet `type: Project` lock entries and npm's root lock entry declare first-party
identities. They remain in the full SBOM, with an explicit unassessed-code marker.
The separately hashed `vulnerability-input.cdx.json` removes only components
whose identity, cataloger and exact declared lock location prove that origin;
dependency edges are pruned with them. Unknown or unversioned third-party entries
cannot disappear through this classification. A same-named/versioned locked npm
dependency is retained for matching. First-party code security remains unassessed.
Resolved versions must be supported normalized versions: three numeric components
(NuGet also permits four), bounded Int32 components, optional prerelease/build
identifiers, and no numeric leading zeros except build identifiers. Unsupported
versions remain missing evidence before scanners run, even with a valid hash.
Normalization removes document UUID/execution timestamps and orders known set
collections. It does not assert RFC 8785 or arbitrary-format equivalence.

Grype must report the pinned tool, actual DB version/build/source/path, disabled
updates/external sources and no fix-only filtering. Its stock deb/rpm ignores are
outside M0's NuGet/npm ecosystem scope; ignored findings within the actual output
are refused rather than silently dropped. Known severity is required to Pass.

Gitleaks uses the pinned upstream rule configuration, complete redaction,
disabled inline allow comments and no project ignore file. Archive/recursive
decoding is disabled; upstream allowlists remain part of the declared rule scope.
The mounted configuration directory must contain exactly the three approved
regular files; additional ignore files, extensions, directories or symlinks are
refused, and each configuration hash is verified before and after execution.
Raw unredacted secret reports are rejected before being persisted. SARIF records
related versioned ASVS IDs and Top 10 categories. Requirements are not labeled
fully verified by one scanner finding or a lack of findings.

Receipts, normalized SARIF, full SBOM and vulnerability input must repeat byte-for-byte for equal inputs,
pins, policy, evaluator/core binaries and evaluation time. Raw scanner reports
and execution journals may differ and are kept private/ignored. SARIF explicitly
marks incomplete/tool-failed execution and includes notifications so an empty
result set cannot masquerade as a clean run.

## Source-bound qualification

From a clean committed candidate, prebuild without changing source, then run:

```sh
dotnet src/SecurityAssay/bin/Release/net11.0/SecurityAssay.dll qualify \
  /absolute/SecurityAssay /absolute/approved-bundle \
  /absolute/CSharpAssay-Depth/src/CsAssay.Runner/bin/Release/net11.0/cs-assay.dll \
  /absolute/SecurityAssay/artifacts/qualification
```

It retains locked restore/build/unit results, authoritative CSharpAssay evidence,
actual clean/vulnerable/NuGet/npm/synthetic-secret scans, repeated normalized
identity despite an undeclared extra file, redaction checks, full-profile/stale
refusals, actual missing/changed binary/config/DB controls and timeout cleanup.
Each tampering control changes only its named variable. The large immutable DB
is hard-linked read-only into Linux fixture bundles; only the changed-DB control
creates different DB bytes, and the missing-DB control removes its fixture link.
The record binds exact source/tool/engine identity. An incomplete/failed attempt
remains incomplete/failed; choose a fresh directory after correcting a problem.
Synthetic parser/unit cases are distinguished from actual offline tool scans.
No human adjudication, live provider qualification or production readiness is
inferred from local qualification. Nothing is published to GitHub or NuGet.
