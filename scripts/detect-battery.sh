#!/usr/bin/env bash
# Detect-chain battery — one deterministic offline gate over the AC-1 frontier proofs and
# the detect-chain unit surface. Chains, in order:
#   1. frozen-vector reproducibility: regenerate tests/detect-frontier-vectors.json from
#      the JS reference and byte-diff against the committed file (security-gate §2 style)
#   2. Motoko differential + TEETH: tests/DetectFrontierDifferential.mo under wasmtime
#      (4 families incl. 24,414-boundary scale; planted off-by-one mutant must go RED)
#   3. cross-language: tests/DetectFrontierCross.mo (frontier + production append path)
#      byte-compared against the frozen vectors by check-frontier-cross.mjs
#   4. detect-chain unit vectors: tests/DetectChainVectors.mo output byte-diffed against
#      tests/detect-chain-vectors.json
#   5. certified-tuple byte-identity: tests/DetectStreamByteIdentity.mo (flag-off digest
#      == pre-feature baseline; flag-on differs)
# The stateful AC-2 half (audit teeth, rebuild, upgrade drill) is the PocketIC battery:
#   cargo run --release --manifest-path soak/Cargo.toml --bin detect_battery
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
MOC="${SOAK_MOC:-/opt/moc-1.4.1/moc}"
[[ -x "$MOC" ]] || MOC="$(command -v moc)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "== detect battery 1/5: frozen frontier-vector reproducibility =="
cp tests/detect-frontier-vectors.json "$TMP/frozen.json"
( cd demo-frontend && node scripts/restore/gen-frontier-vectors.mjs > /dev/null )
diff "$TMP/frozen.json" tests/detect-frontier-vectors.json
echo "   frozen vectors regenerate byte-identically"

echo "== detect battery 2/5: Motoko frontier differential + teeth (wasmtime) =="
"$MOC" $(mops sources) -wasi-system-api --incremental-gc tests/DetectFrontierDifferential.mo -o "$TMP/diff.wasm" 2>/dev/null
wasmtime "$TMP/diff.wasm"

echo "== detect battery 3/5: cross-language frontier + append-path vectors =="
"$MOC" $(mops sources) -wasi-system-api --incremental-gc tests/DetectFrontierCross.mo -o "$TMP/cross.wasm" 2>/dev/null
wasmtime "$TMP/cross.wasm" > "$TMP/cross.out"
node demo-frontend/scripts/restore/check-frontier-cross.mjs < "$TMP/cross.out"

echo "== detect battery 4/5: detect-chain unit vectors vs frozen json =="
"$MOC" $(mops sources) -r tests/DetectChainVectors.mo 2>/dev/null > "$TMP/vec.out"
node - "$TMP/vec.out" <<'EOF'
const { readFileSync } = require("node:fs");
const out = readFileSync(process.argv[2], "utf8");
const v = JSON.parse(readFileSync("tests/detect-chain-vectors.json", "utf8"));
const got = Object.fromEntries(out.trim().split("\n").map((l) => l.split("=")));
const expect = { cTip: v.cTip, detectLeaf: v.detectLeaf_root0_cTip_count10, merkleRoot: v.merkleRoot, leafHash0: v.leafHashes[0] };
for (const [k, e] of Object.entries(expect)) {
  if (got[k] !== e) { console.error(`MISMATCH ${k}: got ${got[k]} expect ${e}`); process.exit(1); }
}
console.log("   4/4 unit vectors byte-identical to tests/detect-chain-vectors.json");
EOF

echo "== detect battery 5/5: certified-tuple byte-identity =="
"$MOC" $(mops sources) -r tests/DetectStreamByteIdentity.mo 2>/dev/null | tee "$TMP/ident.out"
grep -q "flag-off == baseline (byte-identical): PASS" "$TMP/ident.out"
grep -q "flag-on  != baseline (label present)  : PASS" "$TMP/ident.out"

echo "DETECT BATTERY: ALL 5 SECTIONS GREEN"
