#!/usr/bin/env bash
# §4 circuit soundness + independent reference model driver.
#
# 1. INDEPENDENCE grep: the reference model must import nothing beyond the Python standard
#    library (no ark*, no common, no ffi) — a planted violation turns this RED.
# 2. Reproduce: the independent Python model recomputes Poseidon params, hash vectors, and
#    the full transfer public-input vector from the production dump and must match every
#    value (the honest path is computed independently-correctly).
# 3. Violation matrix: every single-rule violation is UNSATISFIABLE; a violated witness
#    yields no verifying proof; recipient binding holds at the verifier (the dishonest
#    paths are rejected by the circuit).
# Deterministic: one seed, printed. Offline. Zero network.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SEED="${FORTRESS_SEED:-20260721}"
COUNT="${FORTRESS_REFMODEL_COUNT:-5000}"
MODEL="$ROOT/fortress/refmodel/model.py"
DUMP="$(mktemp)"
trap 'rm -f "$DUMP"' EXIT

echo "== fortress §4 circuit soundness + independent reference model (seed=$SEED) =="

# 1. Independence check (teeth-bearing): only stdlib imports allowed. Python has no ambient
#    imports, so a model that imports stdlib only cannot USE any production helper — the
#    import line is the enforceable boundary (prose mentions of "common"/"arkworks" in the
#    docstring are documentation, not a dependency).
BANNED='^[[:space:]]*(import|from)[[:space:]]+(?!(json|sys|hashlib|struct|itertools|functools|typing|dataclasses)\b)'
if grep -nP "$BANNED" "$MODEL" >/dev/null 2>&1; then
  echo "FORTRESS-REFMODEL FAIL: reference model imports a non-stdlib module (independence broken):" >&2
  grep -nP "$BANNED" "$MODEL" >&2
  exit 1
fi
echo "  ok   independence: model imports stdlib only"

# 2. Reproduce the production witness generator's values, independently.
"$ROOT/circuit/target/release/circuit_oracle" --seed "$SEED" --count "$COUNT" > "$DUMP"
python3 "$MODEL" "$DUMP"

# 3. Circuit violation matrix (cargo test in the circuit workspace).
echo "  running single-rule-violation matrix + proof-fail + recipient-binding ..."
cargo test --release --manifest-path "$ROOT/circuit/Cargo.toml" -p common \
  --features bls12-381 --test violation_matrix -- --nocapture 2>&1 \
  | grep -E 'VIOLATION-MATRIX|VIOLATION-PROOF|RECIPIENT-BINDING|test result'

echo "FORTRESS-REFMODEL: GREEN (independence + reproduction + violation matrix)"
