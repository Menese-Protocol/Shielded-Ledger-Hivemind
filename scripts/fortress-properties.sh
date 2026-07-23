#!/usr/bin/env bash
# §3 algebraic-property battery (a DISTINCT detector class from §2's differential).
#
# Runs the algebraic identities on the PRODUCTION L2/L3 layers (field a*a^-1=1, sqr=mul,
# distributivity, Frobenius order; curve [a+b]P=[a]P+[b]P, P+O, P+(-P), [r]P=O, [2]P=P+P;
# pairing bilinearity, additivity, degeneracy) at the committed tiers, then the TEETH: a
# broken-distributivity Fp2 mutant must turn the battery RED. Deterministic, offline;
# FORTRESS_PROP_SCALE divides the tiers for a fast calibration (default 1 = committed).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCALE="${FORTRESS_PROP_SCALE:-1}"
MOC="$(dfx cache show)/moc"
CORE="$ROOT/.mops/core@1.0.0/src"
SHA2="$ROOT/.mops/sha2@0.1.9/src"

EXPECT_MOC="Motoko compiler 1.1.0"
"$MOC" --version | grep -qF "$EXPECT_MOC" || { echo "FORTRESS-PROPERTIES FAIL: moc is not $EXPECT_MOC" >&2; exit 1; }

# stage <scale> [sed-expr-on-TowerMont]  -> prints the staged dir
stage() {
  local sc="$1"; local mut="${2:-}"; local d; d="$(mktemp -d)"
  cp "$ROOT"/src/groth16/*.mo "$d/"
  [[ -n "$mut" ]] && sed -i "$mut" "$d/TowerMont.mo"
  sed "s/let SCALE : Nat = 1;/let SCALE : Nat = $sc;/" "$ROOT/fortress/motoko/Properties.mo" > "$d/Properties.mo"
  echo "$d"
}

echo "== fortress §3 algebraic-property battery (scale=$SCALE) =="
d="$(stage "$SCALE")"
"$MOC" -r --package core "$CORE" --package sha2 "$SHA2" "$d/Properties.mo" 2>/dev/null \
  | grep -E "^PROP |FORTRESS-PROPERTIES"
rm -rf "$d"

echo "== §3 TEETH: broken-distributivity Fp2 mutant must go RED =="
# break TowerMont.fp2Mul's imaginary term (add -> sub): destroys distributivity/commutativity.
d="$(stage 20000 's/c1 = FpM.add(FpM.montMul(a.c0, b.c1), FpM.montMul(a.c1, b.c0));/c1 = FpM.sub(FpM.montMul(a.c0, b.c1), FpM.montMul(a.c1, b.c0));/')"
if "$MOC" -r --package core "$CORE" --package sha2 "$SHA2" "$d/Properties.mo" >/dev/null 2>&1; then
  echo "FORTRESS-PROPERTIES TEETH FAILED: broken Fp2 mutant did NOT trap the battery" >&2
  rm -rf "$d"; exit 1
fi
echo "  RED-as-required: broken-distributivity Fp2 mutant tripped the property battery"
rm -rf "$d"
echo "FORTRESS-PROPERTIES: GREEN (identities hold + teeth RED)"
