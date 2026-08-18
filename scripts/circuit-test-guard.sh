#!/usr/bin/env bash
# The circuit suite must not report success while executing nothing.
#
# Thresholds: docs/thresholds/THRESHOLDS-circuit-test-guard.md, committed before measurement.
#
# Five of six files in circuit/common/tests/ open `#![cfg(feature = "bls12-381")]`, and that feature
# is NOT default. `cargo test` therefore prints "ok. 0 passed; 0 failed" for the soundness matrix,
# under-constrained detection, statement<->vk binding, dimension pins and security properties — and
# that gate concealed a genuinely failing soundness assertion
# (docs/thresholds/THRESHOLDS-prover-negative-path.md).
#
# THIS GUARD ASSERTS AN EXECUTED TEST COUNT, NOT AN EXIT STATUS. A pass/fail check cannot tell
# "everything passed" from "nothing ran"; only a count can. That distinction IS the defect.
#
# Usage: scripts/circuit-test-guard.sh [--no-feature]   (--no-feature is G-1, and must FAIL)
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
MIN_PER_FILE=1
FEAT="--features bls12-381"; [ "${1:-}" = "--no-feature" ] && FEAT=""

echo "=== circuit test guard — asserting a NON-ZERO executed count per file ==="
[ -n "$FEAT" ] && echo "  running WITH bls12-381" || echo "  running WITHOUT the feature (G-1: this must FAIL)"

OUT=$(cargo test --offline --manifest-path circuit/common/Cargo.toml $FEAT --tests 2>&1)
STATUS=$?

# Pair each "Running tests/<file>" with the "running N tests" that follows it.
# EXECUTED = passed + failed from the "test result:" line. NOT the "running N tests" line:
# cargo counts #[ignore]d tests in "running N", so an all-ignored file would report N>0 while
# executing nothing -- the exact vacuous green this guard exists to catch. G-3 proves the
# difference by ignoring a file's tests and requiring the guard to still fail.
PAIRS=$(echo "$OUT" | awk '
  /Running tests\// { f=$0; sub(/.*Running tests\//,"",f); sub(/[ (].*/,"",f); next }
  /^test result:/ {
    if (f!="") {
      p=0; fl=0;
      for (i=1;i<=NF;i++) { if ($(i+1)~/^passed/) p=$i; if ($(i+1)~/^failed/) fl=$i }
      print f, p+fl; f=""
    }
  }')

EMPTY=0; TOTAL=0
while read -r file n; do
  [ -z "$file" ] && continue
  TOTAL=$(( TOTAL + n ))
  if [ "$n" -lt "$MIN_PER_FILE" ]; then
    echo "  ZERO TESTS EXECUTED: $file"; EMPTY=$(( EMPTY + 1 ))
  else
    echo "  ok  $file executed $n"
  fi
done <<< "$PAIRS"

FILES=$(echo "$PAIRS" | grep -c . )
echo "  total executed: $TOTAL   files with zero: $EMPTY   files parsed: $FILES"

# A build that produces NO test binaries parses zero files, so the per-file check above passes
# VACUOUSLY -- with cargo exiting 0 this guard would have printed PASSED on a suite that ran
# nothing. That is the very failure this row exists to catch, in the guard itself. G-3 exposed it.
# The expected population is the six files in circuit/common/tests/.
MIN_FILES=$(ls circuit/common/tests/*.rs 2>/dev/null | wc -l)
if [ "$FILES" -lt "$MIN_FILES" ]; then
  echo "  PARSED $FILES TEST FILES, EXPECTED $MIN_FILES — the run did not produce a binary per file"
  echo "=== GUARD FAILED: too few test files parsed; a per-file check over an empty set proves nothing ==="
  [ "$STATUS" -ne 0 ] && echo "$OUT" | grep -E "^error" | head -3 | sed 's/^/    /'
  exit 1
fi

# G-4: a non-zero cargo status is reported, never swallowed.
if [ "$STATUS" -ne 0 ]; then
  echo "  CARGO REPORTED FAILURE (status $STATUS) — surfaced, not swallowed:"
  echo "$OUT" | grep -E "^test .* FAILED|^    [a-z_]+$" | head -5 | sed 's/^/    /'
fi

if [ "$EMPTY" -gt 0 ]; then
  echo "=== GUARD FAILED: $EMPTY file(s) executed zero tests — a green here would be vacuous ==="
  exit 1
fi
if [ "$STATUS" -ne 0 ]; then
  echo "=== GUARD FAILED: tests executed but cargo reported failure ==="
  exit 1
fi
echo "=== GUARD PASSED: every file executed at least $MIN_PER_FILE test, cargo status 0 ==="
