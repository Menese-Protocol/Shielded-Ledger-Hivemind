#!/usr/bin/env bash
# Rebuild the RED-leg baseline for D-4: the ICP ledger fixture as it stood immediately before the
# self-disarm fix landed, built with today's toolchain.
#
# Why a builder rather than a checked-in wasm. The red leg has to show the SECOND armed
# `icrc2_transfer_from` trapping — the behaviour the fix removes. A control that cannot be
# rebuilt is a control nobody can re-run, and a control shipped only as a prebuilt binary cannot
# be audited by the reader either. Only `tests/IcpLedgerFixture.mo` is rolled back; every
# other file, and the compiler, come from HEAD, so the single difference between baseline and
# HEAD is the fix under test.
#
# Usage: scripts/build-d4-baseline-fixture.sh <fix-commit> <out.wasm>
#   The baseline is <fix-commit>^ — the tree immediately before the fix landed.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 1
export PATH="${DFX_BIN_DIR:-/root/.local/share/dfx/bin}:$PATH"

COMMIT="${1:?usage: build-d4-baseline-fixture.sh <fix-commit> <out.wasm>}"
OUT="${2:?missing output wasm path}"
FIXTURE="tests/IcpLedgerFixture.mo"

git rev-parse --verify "$COMMIT^" >/dev/null 2>&1 || {
  echo "[baseline] ABORT: $COMMIT^ is not a commit in this repo"; exit 2; }
git show "$COMMIT^:$FIXTURE" >/dev/null 2>&1 || {
  echo "[baseline] ABORT: $FIXTURE does not exist at $COMMIT^"; exit 2; }

STASH="$ROOT/.d4-fixture-stash"
cp -a "$ROOT/$FIXTURE" "$STASH"
restore(){ cp -a "$STASH" "$ROOT/$FIXTURE" && rm -f "$STASH"; }
trap restore EXIT

git show "$COMMIT^:$FIXTURE" > "$ROOT/$FIXTURE" || { echo "[baseline] ABORT: export failed"; exit 2; }
# TWO-SIDED, and anchored to CODE rather than prose. The defect line must be present with its
# `if (...) {` prefix on the same line, and the post-fix entry point must be absent. An earlier
# version of this guard grepped for the bare assignment-then-trap text, which also matched the
# fix's own explanatory comment — so it passed on a post-fix file and could not reject a wrong
# commit. A guard that cannot fail is not a guard.
grep -q 'if (trap_next_transfer_from) { trap_next_transfer_from := false; Runtime.trap' "$ROOT/$FIXTURE" || {
  echo "[baseline] ABORT: $COMMIT^ does not carry the inline-disarm defect — wrong commit"; exit 2; }
if grep -q '__consume_transfer_from_trap' "$ROOT/$FIXTURE"; then
  echo "[baseline] ABORT: $COMMIT^ already carries the fix (__consume_transfer_from_trap) — wrong commit"; exit 2
fi
echo "[baseline] $FIXTURE from $COMMIT^ (inline disarm present, fix absent)"

rm -rf "$ROOT/.dfx/local/canisters/icp_ledger_fixture"
dfx build icp_ledger_fixture 2>&1 | grep -v "^WARNING" | sed "s|$ROOT/||g" \
  | grep -viE "warning \[M0(155|194)\]|^  Nat$" | tail -3
built=".dfx/local/canisters/icp_ledger_fixture/icp_ledger_fixture.wasm"
if [ ! -f "$built" ]; then
  echo "[baseline] ABORT: build produced no wasm"; exit 2
fi
mkdir -p "$(dirname "$OUT")"
cp "$built" "$OUT"

restore
trap - EXIT
rm -rf "$ROOT/.dfx/local/canisters/icp_ledger_fixture"
dfx build icp_ledger_fixture >/dev/null 2>&1
echo "[baseline] built $OUT sha256=$(sha256sum "$OUT" | cut -d' ' -f1)"
