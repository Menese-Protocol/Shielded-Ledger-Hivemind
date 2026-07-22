#!/usr/bin/env bash
# §9 live in-canister seam battery: installs the hook-wasm ledger (build-test-wasm.sh,
# additive-only; shipped zk_ledger.wasm unchanged) + token fixture + tree oracle, then injects
# failures at the two live seams the model tier covered abstractly — "during certified-state
# update" (real cert update then trap -> atomic rollback verified) and "during the token call"
# (fixture traps transfer_from mid-shield -> pending intent rolled back), >= 25 injections each.
# Teeth: a planted double-mint breaks the solvency invariant. Deterministic; local PocketIC.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo "== fortress §9 live seam battery =="
cargo run --release --manifest-path "$ROOT/soak/Cargo.toml" --bin seam_battery 2>&1 \
  | grep -E 'SEAM GREEN|SEAM RED|TEETH|FORTRESS-SEAM'
