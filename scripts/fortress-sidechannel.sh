#!/usr/bin/env bash
# §10 differential side-channel gate: over many equal-public-shape/different-secret verifies,
# split by a secret bit (input byte-10 parity) and assert the group-mean instruction counts
# differ by < 0.5% of the mean (the secret bit is not recoverable from the count); response
# size + error class constant. Teeth: a planted branch keyed on that bit makes the split leak.
# FORTRESS_SC_N cases (default 40).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo "== fortress §10 differential side-channel gate =="
cargo run --release --manifest-path "$ROOT/soak/Cargo.toml" --bin sidechannel_gate 2>&1 \
  | grep -E 'GATE GREEN|GATE RED|TEETH|FORTRESS-SIDECHANNEL|split'
