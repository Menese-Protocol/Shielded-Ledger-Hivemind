#!/usr/bin/env bash
# §1 three-verifier full-taxonomy gate.
#
# Boots PocketIC, compiles + installs the PRODUCTION Motoko verifier harness
# (fortress/harness/Verifier.mo -> Groth16Wire.tryVerify -> the L3 flat path the ledger
# uses), then runs the full mutation taxonomy (1017 cases: valid base; every proof byte;
# every public input x {bitflip, =r, =2^256-1}; wrong input count; proof truncation +
# oversize; infinity at A/B/C + every vk slot; non-canonical/off-curve/off-subgroup A;
# wrong vk; vk truncation; every vk byte) and asserts Motoko == arkworks == blst on every
# case. Then the TEETH: recompiles the harness with one wrong Montgomery limb and asserts
# the valid base diverges 3-way (the gate would go RED on a planted verifier bug).
#
# Deterministic, offline (PocketIC is local; needs the pocket-ic server binary + moc 1.4.1).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo "== fortress §1 three-verifier taxonomy gate =="
cargo run --release --manifest-path "$ROOT/soak/Cargo.toml" --bin taxonomy_gate 2>&1 \
  | grep -E 'taxonomy:|GATE GREEN|GATE RED|TEETH|FORTRESS-TAXONOMY|DISAGREE'
