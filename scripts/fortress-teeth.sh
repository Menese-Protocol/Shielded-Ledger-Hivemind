#!/usr/bin/env bash
# TEETH for §2/§3: prove every differential detector goes RED on a planted bug.
#
# A detector never shown to catch a planted bug is a stub. For each
# planted mutation we stage a COPY of the production module with ONE wrong element,
# run the relevant Motoko differential program against the (unmutated) oracle, and
# assert the affected class(es) DIVERGE — and that at least one class does. The mutation
# lives only in the throwaway stage dir; the production tree is never touched.
#
# Determinism: uses a small DIV so teeth run fast; the divergence is a pure function of
# the planted bug, not of scale.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SEED="${FORTRESS_SEED:-20260721}"
DIV="${FORTRESS_TEETH_DIV:-2000}"
MOC="$(dfx cache show)/moc"
CORE="$ROOT/.mops/core@1.0.0/src"
SHA2="$ROOT/.mops/sha2@0.1.9/src"
ORACLE="$ROOT/target/release/arith_oracle"

pass=0
fail=0

# $1 planted-bug name; $2 program; $3 oracle suite; $4 sed expr applied to ONE module;
# $5 module file; $6 space-separated class tags that MUST diverge.
plant() {
  local name="$1" prog="$2" suite="$3" sedexpr="$4" module="$5" expect="$6"
  local stage; stage="$(mktemp -d)"
  cp "$ROOT"/src/groth16/*.mo "$stage/"
  sed -i "$sedexpr" "$stage/$module"
  # verify the sed actually changed something
  if diff -q "$ROOT/src/groth16/$module" "$stage/$module" >/dev/null; then
    echo "  TEETH-BROKEN  $name: planted mutation did not change $module" >&2
    fail=$((fail+1)); rm -rf "$stage"; return
  fi
  sed -e "s/let SEED : Nat64 = [0-9]*;/let SEED : Nat64 = $SEED;/" \
      -e "s/let DIV : Nat = [0-9]*;/let DIV : Nat = $DIV;/" \
      "$ROOT/fortress/motoko/$prog" > "$stage/$prog"
  "$MOC" -r --package core "$CORE" --package sha2 "$SHA2" "$stage/$prog" 2>/dev/null \
    | grep -E '^CLASS' | sort > "$stage/mutant.motoko" || true
  "$ORACLE" --suite "$suite" --seed "$SEED" --div "$DIV" | grep -E '^CLASS' | sort \
    > "$stage/oracle" || true
  local reddened=0 ok=1
  for tag in $expect; do
    local m o
    m="$(grep -E "^CLASS $tag " "$stage/mutant.motoko" || true)"
    o="$(grep -E "^CLASS $tag " "$stage/oracle" || true)"
    if [[ -z "$o" ]]; then
      echo "  TEETH-BROKEN  $name: oracle has no class $tag" >&2; ok=0; continue
    fi
    if [[ "$m" != "$o" ]]; then reddened=$((reddened+1)); fi
  done
  if [[ "$reddened" -ge 1 && "$ok" -eq 1 ]]; then
    echo "  RED-as-required  $name  ($reddened of [$expect] diverged)"
    pass=$((pass+1))
  else
    echo "  TEETH-FAILED     $name  (planted bug did NOT redden any of [$expect])" >&2
    fail=$((fail+1))
  fi
  rm -rf "$stage"
}

echo "== fortress §2/§3 TEETH (seed=$SEED div=$DIV) =="

# 1. wrong-limb Montgomery constant (RR low nibble) — must redden fpm.* multiplicative.
plant "fpm-RR-wrong-limb" ArithDiff.mo arith \
  's/0x11988fe592cae3aa9a793e85b519952d67eb88a9939d83c08de5476c4c95b6d50a76e6a609d104f1f4df1f341c341746/0x11988fe592cae3aa9a793e85b519952d67eb88a9939d83c08de5476c4c95b6d50a76e6a609d104f1f4df1f341c341747/' \
  FpMont.mo "fpm.mul fpm.sqr fpm.inv fpm.roundtrip"

# 2. wrong L1 modulus (flip a low bit of Fp.P) — must redden fp1.* reductions.
plant "fp1-modulus-wrong-bit" ArithDiff.mo arith \
  's/0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab/0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaa9/' \
  Fp.mo "fp1.add fp1.mul fp1.sqr fp1.inv"

# 3. broken Fp2 mul real part (sub -> add in the c0 term) — must redden t2.mul.
plant "t2-mul-broken-realpart" TowerDiff.mo tower \
  's/c0 = Fp.sub(Fp.mul(a.c0, b.c0), Fp.mul(a.c1, b.c1));/c0 = Fp.add(Fp.mul(a.c0, b.c0), Fp.mul(a.c1, b.c1));/' \
  Tower.mo "t2.mul"

# 4. broken distributivity in FpMont.mul (drop the reduction) is not expressible by a
#    one-liner safely; instead corrupt the Montgomery PINV constant — reddens fpm mul path.
plant "fpm-PINV-wrong-limb" ArithDiff.mo arith \
  's/0xceb06106feaafc9468b316fee268cf5819ecca0e8eb2db4c16ef2ef0c8e30b48286adb92d9d113e889f3fffcfffcfffd/0xceb06106feaafc9468b316fee268cf5819ecca0e8eb2db4c16ef2ef0c8e30b48286adb92d9d113e889f3fffcfffcffff/' \
  FpMont.mo "fpm.mul fpm.sqr"

# 5. wrong curve b-constant in on-curve check (4 -> 5) — must redden c1.oncurve.
plant "c1-oncurve-wrong-b" CurveDiff.mo curve \
  's/let rhs = Fp.add(Fp.mul(Fp.sqr(q.x), q.x), 4);/let rhs = Fp.add(Fp.mul(Fp.sqr(q.x), q.x), 5);/' \
  Curve.mo "c1.oncurve"

echo "TEETH SUMMARY: $pass reddened as required, $fail failed"
if [[ "$fail" -ne 0 ]]; then
  echo "FORTRESS-TEETH: FAILED — a detector did not catch its planted bug" >&2
  exit 1
fi
echo "FORTRESS-TEETH: ALL PLANTED BUGS CAUGHT"
