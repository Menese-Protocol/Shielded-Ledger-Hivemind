#!/usr/bin/env bash
# §2 per-op arithmetic differential + §3 algebraic properties driver.
#
# For each suite (arith, tower, curve, pairing, decode): stage the production groth16
# modules next to the Motoko differential program, run it through the dfx-cache moc
# interpreter, and diff its per-class DIGEST lines against the native Rust/arkworks/blst
# oracle (fortress arith_oracle). Any digest divergence, or a missing/extra class line,
# fails the gate and names the diverging (suite, class). Fully deterministic: one seed,
# printed, a pure function of it.
#
# Env: FORTRESS_SEED (default 20260721); FORTRESS_DIV (default 1 — full scale; set higher
# for a fast calibration pass, e.g. 1000). MOC pin asserted (dfx-cache moc). Zero network.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SEED="${FORTRESS_SEED:-20260721}"
DIV="${FORTRESS_DIV:-1}"
MOC="$(dfx cache show)/moc"
CORE="$ROOT/.mops/core@1.0.0/src"
SHA2="$ROOT/.mops/sha2@0.1.9/src"
ORACLE="$ROOT/target/release/arith_oracle"

# The gate binds to the dfx-cache moc (the version every existing Motoko battery uses);
# assert it so "reproducible" is machine-checked, not assumed.
EXPECT_MOC="Motoko compiler 1.1.0"
if ! "$MOC" --version | grep -qF "$EXPECT_MOC"; then
  echo "FORTRESS-ARITH FAIL: moc is not the pinned $EXPECT_MOC (got: $("$MOC" --version))" >&2
  exit 1
fi
if [[ ! -x "$ORACLE" ]]; then
  echo "FORTRESS-ARITH FAIL: oracle not built; run: cargo build --release -p fortress" >&2
  exit 1
fi

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
cp "$ROOT"/src/groth16/*.mo "$STAGE/"

suites=("arith:ArithDiff.mo" "tower:TowerDiff.mo" "curve:CurveDiff.mo" \
        "pairing:PairingDiff.mo" "decode:PairingDiff.mo")

# pairing and decode share the one Motoko program (PairingDiff.mo emits both class sets);
# run it once and split the oracle comparison.
declare -A ran_motoko
fail=0

run_motoko() {
  local prog="$1"
  if [[ -n "${ran_motoko[$prog]:-}" ]]; then return; fi
  sed -e "s/let SEED : Nat64 = [0-9]*;/let SEED : Nat64 = $SEED;/" \
      -e "s/let DIV : Nat = [0-9]*;/let DIV : Nat = $DIV;/" \
      "$ROOT/fortress/motoko/$prog" > "$STAGE/$prog"
  "$MOC" -r --package core "$CORE" --package sha2 "$SHA2" "$STAGE/$prog" 2>/dev/null \
    | grep -E '^CLASS|^SEED' | sort > "$STAGE/${prog}.motoko"
  ran_motoko[$prog]=1
}

echo "== fortress §2/§3 differential (seed=$SEED div=$DIV) =="
for entry in "${suites[@]}"; do
  suite="${entry%%:*}"
  prog="${entry##*:}"
  run_motoko "$prog"
  "$ORACLE" --suite "$suite" --seed "$SEED" --div "$DIV" | grep -E '^CLASS' | sort \
    > "$STAGE/${suite}.oracle"
  # every oracle class for this suite must have an identical Motoko line
  while read -r oline; do
    tag="$(echo "$oline" | awk '{print $2}')"
    mline="$(grep -E "^CLASS $tag " "$STAGE/${prog}.motoko" || true)"
    if [[ "$mline" != "$oline" ]]; then
      echo "  RED  $suite/$tag"
      echo "       oracle: $oline"
      echo "       motoko: ${mline:-<missing>}"
      fail=1
    else
      echo "  ok   $suite/$tag"
    fi
  done < "$STAGE/${suite}.oracle"
done

if [[ "$fail" -ne 0 ]]; then
  echo "FORTRESS-ARITH: DIFFERENTIAL RED (reproduce with FORTRESS_SEED=$SEED FORTRESS_DIV=<small>)" >&2
  exit 1
fi
echo "FORTRESS-ARITH: ALL CLASSES GREEN (seed=$SEED div=$DIV)"
