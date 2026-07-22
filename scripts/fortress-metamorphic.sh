#!/usr/bin/env bash
# §6 metamorphic gate: validity-preserving transforms (re-randomized proofs) stay accepted;
# validity-destroying transforms (statement/key mutations) are rejected — all checked 3-way
# (Motoko production verifier on PocketIC == arkworks == blst). Teeth: a mislabeled
# destroying transform trips the suite. FORTRESS_META_N base transfers (default 40; full 200).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo "== fortress §6 metamorphic gate =="
cargo run --release --manifest-path "$ROOT/soak/Cargo.toml" --bin metamorphic_gate 2>&1 \
  | grep -E 'GATE GREEN|GATE RED|TEETH|FORTRESS-METAMORPHIC|DISAGREE|expected'
