#!/usr/bin/env bash
# THE VERIFICATION FORTRESS — one deterministic offline gate over every section.
#
# Chains all section drivers, each of which asserts its detectors AND runs its teeth (a
# planted bug proven to turn the detector RED). Fully deterministic; every suite prints its
# seed. The heavy PocketIC/proving sections default to their GATE tier (env-overridable to the
# committed full tier). No network: cargo-fuzz + moc + the pocket-ic server binary are
# provisioned out of band (see the per-section READMEs); the gate itself installs nothing.
#
# Tiers (env): FORTRESS_DIV (§2, default 1 = full; set 1000 for a fast calibration),
#   FORTRESS_META_N (§6, default 40), FORTRESS_INV_OPS (§9 model, default 2_000_000),
#   FORTRESS_SC_N (§10, default 40), FORTRESS_FUZZ_RUNS (§7, default 200000).
#
# Usage: scripts/fortress.sh [--fast]   (--fast lowers the tiers for a smoke pass)
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ "${1:-}" == "--fast" ]]; then
  export FORTRESS_DIV=1000 FORTRESS_META_N=8 FORTRESS_INV_OPS=200000 FORTRESS_SC_N=12 FORTRESS_FUZZ_RUNS=20000
fi

MOC="$(dfx cache show)/moc"
CORE="$ROOT/.mops/core@1.0.0/src"

banner() { printf '\n########## %s ##########\n' "$1"; }
fail=0
run() { # run <label> <command...>
  local label="$1"; shift
  banner "$label"
  if "$@"; then echo "[$label] PASS"; else echo "[$label] FAIL" >&2; fail=1; fi
}

# Build the Rust drivers once (release).
banner "build fortress + soak drivers"
cargo build --release -p fortress
cargo build --release --manifest-path circuit/Cargo.toml -p gen --features bls12-381 --bin circuit_oracle
cargo build --release --manifest-path soak/Cargo.toml --bin taxonomy_gate --bin metamorphic_gate --bin invariant_model_tier --bin sidechannel_gate

# §2/§3 arithmetic differential + algebraic properties (+ teeth)
run "§2/§3 arithmetic differential" ./scripts/fortress-arith.sh
run "§2/§3 teeth" ./scripts/fortress-teeth.sh

# §4 independent reference model + violation matrix (+ teeth)
run "§4 reference model" ./scripts/fortress-refmodel.sh
run "§4 teeth" ./scripts/fortress-refmodel-teeth.sh

# §5 under-constrained detection (+ teeth in-test)
run "§5 constraint coverage" ./scripts/fortress-constraints.sh

# §1 three-verifier taxonomy gate (+ teeth) — PocketIC
run "§1 three-verifier taxonomy" ./scripts/fortress-taxonomy.sh

# §6 metamorphic (+ teeth) — PocketIC
run "§6 metamorphic" ./scripts/fortress-metamorphic.sh

# §9 stateful invariants, model tier (+ teeth)
run "§9 invariant model tier" ./scripts/fortress-invariant-model.sh

# §10 differential side-channel (+ teeth) — PocketIC
run "§10 side-channel" ./scripts/fortress-sidechannel.sh

# §7 coverage-guided fuzzing (+ teeth). SKIPs (exit 2) if the fuzz toolchain is absent.
banner "§7 coverage-guided fuzzing"
set +e
./scripts/fortress-fuzz.sh; fz=$?
set -e
if [[ $fz -eq 0 ]]; then
  echo "[§7 fuzz] PASS"
elif [[ $fz -eq 2 ]]; then
  echo "[§7 fuzz] SKIP (fuzz toolchain not installed — documented, not a silent pass)"
else
  echo "[§7 fuzz] FAIL" >&2; fail=1
fi

# Ceremony cross-language PoK verifier (extend existing coverage into the gate)
banner "ceremony PoK Motoko==Rust vector"
if "$MOC" $(mops sources) -r coordinator/test/PokVectorTest.mo; then
  echo "[ceremony PoK] PASS"
else
  echo "[ceremony PoK] FAIL" >&2; fail=1
fi

banner "FORTRESS SUMMARY"
if [[ "$fail" -ne 0 ]]; then
  echo "THE VERIFICATION FORTRESS: RED — a section or its teeth failed" >&2
  exit 1
fi
echo "THE VERIFICATION FORTRESS: ALL SECTIONS GREEN (every detector proven RED-capable by its teeth)"
