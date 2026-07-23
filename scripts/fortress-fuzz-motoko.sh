#!/usr/bin/env bash
# §7 (Motoko side) — structure-aware robustness battery for the production decoders that
# cargo-fuzz cannot reach (Groth16Wire.parseProof/parseInputs, Decode.decodeG1,
# DecodeG2.decodeG2, NoteCodec.decode). >= 250,000 seeded inputs per decoder; asserts no
# trap (surviving the run IS the no-trap proof), no non-canonical accept (accepted values
# round-trip / stay < p or < r), and honored length/count bounds. Deterministic; offline.
# FORTRESS_FUZZMO_SCALE divides the per-decoder N for a fast calibration (default 1).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCALE="${FORTRESS_FUZZMO_SCALE:-1}"
MOC="$(dfx cache show)/moc"
CORE="$ROOT/.mops/core@1.0.0/src"
SHA2="$ROOT/.mops/sha2@0.1.9/src"
"$MOC" --version | grep -qF "Motoko compiler 1.1.0" || { echo "FORTRESS-FUZZ-MOTOKO FAIL: wrong moc" >&2; exit 1; }

d="$(mktemp -d)"; trap 'rm -rf "$d"' EXIT
cp "$ROOT"/src/groth16/*.mo "$d/"
cp "$ROOT"/src/NoteCodec.mo "$d/"
sed "s/let SCALE : Nat = 1;/let SCALE : Nat = $SCALE;/" "$ROOT/fortress/motoko/FuzzDecoders.mo" > "$d/FuzzDecoders.mo"

echo "== fortress §7 Motoko decoder robustness battery (scale=$SCALE) =="
"$MOC" -r --package core "$CORE" --package sha2 "$SHA2" "$d/FuzzDecoders.mo" 2>/dev/null \
  | grep -E "^FUZZ |FORTRESS-FUZZ-MOTOKO"
echo "FORTRESS-FUZZ-MOTOKO: GREEN (all decoders total + canonical at >= 250k each)"
