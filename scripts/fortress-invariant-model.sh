#!/usr/bin/env bash
# §9 stateful-invariant MODEL TIER: millions of seeded ops against an abstract shielded
# ledger tracked two independent ways, asserting INV-1 (custody == shielded + pending),
# INV-2 (pool_value == shielded), INV-3 (global conservation), INV-4 (deposit/unshield/
# nullifier once, no double-pay) after every op, with seam-fault injection at all logical
# seams (atomic rollback). Teeth: a planted double-mint is caught. FORTRESS_INV_OPS (default 2M).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo "== fortress §9 stateful-invariant model tier =="
cargo run --release --manifest-path "$ROOT/soak/Cargo.toml" --bin invariant_model_tier 2>&1 \
  | grep -E 'MODEL-TIER GREEN|MODEL-TIER RED|TEETH|FORTRESS-INVARIANT-MODEL'
