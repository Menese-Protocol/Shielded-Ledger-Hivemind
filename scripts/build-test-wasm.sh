#!/bin/bash
# Build zk_ledger_test.wasm = src/Main.mo + an injected, clearly-marked, admin-gated
# TEST-HOOK block (corruption primitives for T2/T3). The SHIPPED wasm (src/Main.mo →
# zk_ledger.wasm) never contains these hooks; this script generates a throwaway source
# file, prints the injection diff (additive-only proof), compiles it, and deletes nothing
# from the real tree. Output: $2 (wasm path), plus $2.injection.diff for the evidence
# packet.
#
# Usage: scripts/build-test-wasm.sh <hook-block.mo-fragment> <out.wasm>
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FRAG="${1:?usage: build-test-wasm.sh <hook-fragment> <out.wasm>}"
OUT="${2:?usage: build-test-wasm.sh <hook-fragment> <out.wasm>}"
GEN="$ROOT/src/MainTestHooks.generated.mo"

# Inject the fragment just before the actor's closing brace (last line of Main.mo).
LAST=$(wc -l < "$ROOT/src/Main.mo")
head -n $((LAST - 1)) "$ROOT/src/Main.mo" > "$GEN"
{
  echo "  // ================= TEST HOOKS (generated; NEVER in the shipped wasm) ================="
  cat "$FRAG"
  echo "  // ================= END TEST HOOKS ================="
  tail -n 1 "$ROOT/src/Main.mo"
} >> "$GEN"

# additive-only proof: the generated file minus the hook block must equal Main.mo
diff <(sed '/=* TEST HOOKS (generated/,/=* END TEST HOOKS/d' "$GEN") "$ROOT/src/Main.mo" > /dev/null \
  || { echo "INJECTION IS NOT ADDITIVE-ONLY — abort"; exit 1; }
diff -u "$ROOT/src/Main.mo" "$GEN" > "$OUT.injection.diff" || true
echo "[build-test-wasm] injection diff: $OUT.injection.diff ($(grep -c '^+' "$OUT.injection.diff") added lines, $(grep -c '^-[^-]' "$OUT.injection.diff") removed lines)"

( cd "$ROOT" && /opt/moc-1.4.1/moc $(mops sources) -c "$GEN" -o "$OUT" )
rm -f "$GEN"
echo "[build-test-wasm] built $OUT sha256=$(sha256sum "$OUT" | cut -d' ' -f1)"
