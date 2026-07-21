#!/usr/bin/env bash
# §7 coverage-guided fuzzing — offline gate tier.
#
# Runs every REAL decode target for a fixed deterministic budget (no crash allowed) plus the
# full seed-corpus replay, then runs the TEETH target and asserts it DOES crash (proving the
# harness detects a real decode bug). Zero network — the targets are pre-built; cargo-fuzz +
# nightly are provisioned out-of-band (see fortress/fuzz/README.md). Requires a nightly
# toolchain + cargo-fuzz on the machine; if absent the gate reports that and skips (the
# security gate treats a missing fuzz toolchain as a documented-skip, never a silent pass).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FUZZDIR="$ROOT/fortress"
RUNS="${FORTRESS_FUZZ_RUNS:-200000}"
REAL=(decode_g1 decode_g2 decode_fr decode_proof decode_vk)

if ! command -v cargo-fuzz >/dev/null 2>&1 || ! rustup toolchain list 2>/dev/null | grep -q nightly; then
  echo "FORTRESS-FUZZ SKIP: cargo-fuzz or a nightly toolchain is not installed" >&2
  echo "  provision once (network): cargo install cargo-fuzz && rustup toolchain install nightly" >&2
  exit 2
fi

echo "== fortress §7 coverage-guided fuzzing (gate tier, runs=$RUNS) =="
cd "$FUZZDIR"
fail=0
for t in "${REAL[@]}"; do
  echo "  fuzzing $t ..."
  if cargo +nightly fuzz run "$t" -- -runs="$RUNS" -seed=1 >/tmp/fuzz_$t.log 2>&1; then
    echo "  ok   $t (no crash in $RUNS runs + corpus replay)"
  else
    echo "  RED  $t crashed — see /tmp/fuzz_$t.log" >&2
    fail=1
  fi
done

echo "  TEETH: teeth_planted_panic must crash ..."
if cargo +nightly fuzz run teeth_planted_panic -- -runs=2000000 -max_total_time=90 -seed=1 \
     >/tmp/fuzz_teeth.log 2>&1; then
  echo "  TEETH-FAILED: planted-panic target did NOT crash — fuzz harness cannot detect bugs" >&2
  fail=1
else
  if grep -qE 'panicked|deadly signal' /tmp/fuzz_teeth.log; then
    echo "  RED-as-required  teeth_planted_panic crashed (harness detects decode bugs)"
  else
    echo "  TEETH-FAILED: target exited nonzero without a detected panic" >&2
    fail=1
  fi
fi

if [[ "$fail" -ne 0 ]]; then
  echo "FORTRESS-FUZZ: FAILED" >&2
  exit 1
fi
echo "FORTRESS-FUZZ: GREEN (5 targets clean, teeth crashes as required)"
