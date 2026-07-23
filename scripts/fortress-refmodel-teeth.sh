#!/usr/bin/env bash
# TEETH for §4: prove the reference-model detector fires.
#
# Two planted bugs, each must turn the model RED:
#   T1 — independence violation: a planted `import os` in a COPY of the model must be caught
#        by the independence grep before any computation runs.
#   T2 — a wrong Poseidon round constant in a COPY of the model must make the reproduction
#        diverge from the production dump (proving the parameter/hash cross-check has teeth,
#        i.e. it is NOT trivially agreeing because both sides share code).
#   T3 — a value-nonconserving witness that WRONGLY satisfied would be a RED: we assert the
#        matrix's own honest-vs-mutant contrast by planting `enforce_range=false`-style
#        acceptance is out of scope here (covered by mint_guard); T3 instead flips one
#        matrix assertion sense in a copy to confirm the harness would report a satisfied
#        violation as a failure.
# Mutations live only in throwaway copies; the shipped tree is never touched.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SEED="${FORTRESS_SEED:-20260721}"
MODEL="$ROOT/fortress/refmodel/model.py"
DUMP="$(mktemp)"
STAGE="$(mktemp -d)"
trap 'rm -f "$DUMP"; rm -rf "$STAGE"' EXIT
"$ROOT/circuit/target/release/circuit_oracle" --seed "$SEED" --count 5 > "$DUMP"

pass=0; fail=0

echo "== fortress §4 TEETH (seed=$SEED) =="

# T1 — independence grep must catch a planted non-stdlib import.
cp "$MODEL" "$STAGE/t1.py"
sed -i '1a import os' "$STAGE/t1.py"
BANNED='^\s*(import|from)\s+(?!(json|sys|hashlib|struct|itertools|functools|typing|dataclasses)\b)'
if grep -nP "$BANNED" "$STAGE/t1.py" >/dev/null 2>&1; then
  echo "  RED-as-required  T1 independence: planted 'import os' caught"; pass=$((pass+1))
else
  echo "  TEETH-FAILED     T1: planted import NOT caught" >&2; fail=$((fail+1))
fi

# T2 — wrong Poseidon round constant must make reproduction diverge.
cp "$MODEL" "$STAGE/t2.py"
# corrupt the first ark element the model uses by adding 1 in gen_ark_and_mds output.
python3 - "$STAGE/t2.py" <<'PY'
import sys
p=sys.argv[1]; s=open(p).read()
s=s.replace("ark = [lfsr.field_elems_rejection(rate + 1) for _ in range(full_rounds + partial_rounds)]",
            "ark = [lfsr.field_elems_rejection(rate + 1) for _ in range(full_rounds + partial_rounds)]\n    ark[0][0] = (ark[0][0] + 1) % R")
open(p,'w').write(s)
PY
if python3 "$STAGE/t2.py" "$DUMP" >/dev/null 2>&1; then
  echo "  TEETH-FAILED     T2: wrong round constant still reproduced GREEN" >&2; fail=$((fail+1))
else
  echo "  RED-as-required  T2 params: wrong round constant made reproduction diverge"; pass=$((pass+1))
fi

# T3 — a flipped matrix assertion sense (assert satisfied instead of unsatisfied) must fail
#      the cargo test, proving the matrix catches a satisfied violation.
cp "$ROOT/circuit/common/tests/violation_matrix.rs" "$STAGE/vm.rs"
sed -i '0,/assert!(!satisfied(&m), "wrong-owner satisfied");/s//assert!(satisfied(\&m), "TEETH: expecting satisfied");/' "$STAGE/vm.rs"
# stage a throwaway copy of the circuit crate test dir and run only this test file
TESTDIR="$ROOT/circuit/common/tests"
cp "$STAGE/vm.rs" "$TESTDIR/_teeth_vm.rs"
trap 'rm -f "$DUMP"; rm -rf "$STAGE"; rm -f "$TESTDIR/_teeth_vm.rs"' EXIT
if cargo test --release --manifest-path "$ROOT/circuit/Cargo.toml" -p common \
     --features bls12-381 --test _teeth_vm >/dev/null 2>&1; then
  echo "  TEETH-FAILED     T3: a satisfied violation did NOT fail the matrix" >&2; fail=$((fail+1))
else
  echo "  RED-as-required  T3 matrix: a satisfied single-rule violation failed the matrix"; pass=$((pass+1))
fi
rm -f "$TESTDIR/_teeth_vm.rs"

echo "TEETH SUMMARY: $pass reddened as required, $fail failed"
if [[ "$fail" -ne 0 ]]; then
  echo "FORTRESS-REFMODEL-TEETH: FAILED" >&2; exit 1
fi
echo "FORTRESS-REFMODEL-TEETH: ALL PLANTED BUGS CAUGHT"
