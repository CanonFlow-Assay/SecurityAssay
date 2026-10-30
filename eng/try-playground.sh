#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bundle="${SECURITYASSAY_BUNDLE:-$HOME/.cache/securityassay-m0}"
as_of="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
output=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --bundle) bundle="$2"; shift 2 ;;
    --as-of) as_of="$2"; shift 2 ;;
    --output) output="$2"; shift 2 ;;
    *) echo "Usage: eng/try-playground.sh --output <fresh-directory> [--bundle <approved-bundle>] [--as-of <UTC>]" >&2; exit 64 ;;
  esac
done
if [[ -z "$output" || -e "$output" ]]; then echo "Choose a fresh output directory." >&2; exit 64; fi
mkdir -p "$output"
output="$(cd "$output" && pwd)"
cd "$root"
dotnet build SecurityAssay.slnx --no-restore -c Release -m:2 -nodeReuse:false > "$output/build.log" 2>&1
dotnet test SecurityAssay.slnx --no-build --no-restore -c Release --max-parallel-test-modules 1 > "$output/tests.log" 2>&1
cli="$root/src/SecurityAssay/bin/Release/net11.0/SecurityAssay.dll"
set +e
dotnet "$cli" scan "$root/samples/clean" "$root/samples/clean/inputs.json" "$root/policies/m0.json" \
  "$root/policies/toolchain.lock.json" "$root/standards/asvs-5.0.0/catalog.json" "$bundle" "$as_of" "$output/clean" > "$output/scan.log" 2>&1
observed="$?"
set -e
if [[ "$observed" -gt 3 || ! -f "$output/clean/receipt.json" ]]; then
  echo "Evaluation did not produce a complete receipt. Inspect $output/scan.log" >&2
  exit 3
fi
dotnet "$cli" advise "$output/clean/receipt.json" "$root/samples/clean" "$root/samples/clean/inputs.json" \
  "$root/policies/m0.json" "$root/policies/toolchain.lock.json" "$root/standards/asvs-5.0.0/catalog.json" "$as_of" 1 > "$output/advice.json"
echo "Observed scan exit $observed. Receipt and separate advice: $output"
echo "A stale database or unavailable bundle cannot Pass. No provisioning or network operation was requested."
exit "$observed"
