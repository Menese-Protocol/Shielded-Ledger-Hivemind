#!/usr/bin/env bash
# §5 under-constrained / constraint-coverage detection driver.
#
# Runs the R1CS export analysis + full witness-mutation scan over the transfer circuit
# (every witness variable perturbed and rechecked) AND the teeth (a planted
# under-constrained circuit must be flagged; the fixed version must be clean). One command,
# offline, deterministic (seeded inside the test). The scan is O(vars x constraints) and
# takes ~90 s at full circuit size — the committed cost.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo "== fortress §5 under-constrained / constraint-coverage detection =="
cargo test --release --manifest-path "$ROOT/circuit/Cargo.toml" -p common \
  --features bls12-381 --test under_constrained -- --nocapture 2>&1 \
  | grep -E 'R1CS-EXPORT|WITNESS-SCAN|UNDER-CONSTRAINED|test result'
echo "FORTRESS-CONSTRAINTS: GREEN (export + full witness scan + teeth)"
