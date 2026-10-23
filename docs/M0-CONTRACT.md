# M0: declared-input offline security evidence

Use a reusable CanonFlow evidence core and C# SecurityAssay adapters. Preserve
the already-qualified CSharpAssay/DAA worktrees; no new rule admission or rewrite
of those engines is implied.

## Requirements registered before implementation

1. A manifest enumerates individual regular source, lock and configuration
   files. Reject empty/duplicate/escaping paths, symlinks and scope drift.
   Scanners see a read-only snapshot of exactly those bytes, never the whole
   checkout or its host environment. Hash originals before and after execution.
2. Approved Gitleaks, Syft and Grype binaries, their configuration and the
   vulnerability DB are pinned by content and version. Provisioning may download
   verified official releases; evaluation never downloads or updates. Scanner
   processes run in an immutable local container image with network disabled,
   non-root identity, no capabilities, read-only filesystem and bounded resources.
   The host Docker daemon is trusted infrastructure, not a hostile-host sandbox.
3. Use ASVS 5.0.0 identifiers from the pinned official catalog. Every finding
   gets related requirement IDs and Top 10:2025 risk categories. Unknown mapping
   or unsupported evidence remains visible and cannot authorize Pass.
4. M0 implements secret detection, dependency SBOM and local vulnerability
   matching for declared supported NuGet/npm locks. Package discovery is checked
   against declared lock identities. Lock hashes are evidence of integrity, not
   publisher authentication or signed release provenance.
5. Policy pins severity threshold, required checks, supported input formats,
   database identity and explicit evaluation time/freshness window. Unknown
   severity, stale/future database, incomplete package discovery or missing
   required control cannot Pass. Do not hide low-severity findings or survivors.
6. Emit canonical SARIF, normalized CycloneDX SBOM and a deterministic receipt
   binding source/policy/catalog/tool/config/DB identities and limits. SHA-256
   receipt integrity is not a signature or an independent execution attestation.
   Raw tool output and execution metadata remain in a separate ignored journal.
   Secrets are redacted by Gitleaks before reports cross the process boundary.
7. Native domain outcomes project to four verdicts: tool execution/format failure
   → ToolFailure; known blocking finding → Fail; missing/unsupported evidence →
   Inconclusive; otherwise Pass only for the declared M0 profile. Findings remain
   visible regardless of precedence. An empty scan is never a complete policy.
8. Test clean/dirty actual scans, vulnerable package and synthetic fake secret
   controls, missing/stale/tampered evidence, malformed output, scope escapes,
   timeout and repeated byte-identical normalized output. Keep real evidence
   distinct from synthetic test adapters and make qualification source-bound.

## Explicit limits

M0 does not verify authorization, injection/deserialization/cryptography rules,
deployment/open-port/debug settings, exception disclosure, audit logging or AI
agent permissions. A broader release profile requiring these returns
Inconclusive. No ASVS level, certification, complete application security,
package publisher provenance or production-readiness assertion follows from an
M0 Pass. AISVS/agent rules and C#/F#/TypeScript security packs are later scope.

Official sources: https://asvs.owasp.org/ ; https://top10.owasp.org/2025/ ;
https://oss.anchore.com/docs/guides/vulnerability/database/ .
