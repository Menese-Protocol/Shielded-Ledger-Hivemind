#!/usr/bin/env bash
# Build a WindowFixture whose headroom GROWS UNCONDITIONALLY — a reservation rather than a predicate.
#
# The waste property asserts that a repeated PREPARE-then-abort grows nothing. A battery that has never seen the
# growth case cannot tell "nothing moved because the predicate is idempotent" from "nothing moved
# because nothing was ever asked for". This is the build that moves.
#
# The diff is proved, not asserted: one function body, or this aborts.
#
# Usage: scripts/build-leaky-headroom.sh <out.wasm>
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT" || exit 1
export PATH="${DFX_BIN_DIR:-/root/.local/share/dfx/bin}:$PATH"
OUT="${1:?usage: build-leaky-headroom.sh <out.wasm>}"
BACKUP="$ROOT/src/StableLog.mo.leaky"
cp "$ROOT/src/StableLog.mo" "$BACKUP"
restore(){ mv -f "$BACKUP" "$ROOT/src/StableLog.mo" 2>/dev/null || true; }
trap restore EXIT

python3 - "$ROOT/src/StableLog.mo" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1]); s = p.read_text()
good = """    ensureCapacity(state.data_region, state.data_offset + bytes);
    ensureCapacity(state.index_region, HEADER_SIZE + (state.entry_count + entries) * INDEX_ENTRY_SIZE);"""
leaky = """    ensureCapacity(state.data_region, capacity(state.data_region) + bytes);
    ensureCapacity(state.index_region, capacity(state.index_region) + entries * INDEX_ENTRY_SIZE);"""
if good not in s:
    print("ABORT: ensureHeadroom is not the shape this script knows how to break"); sys.exit(2)
p.write_text(s.replace(good, leaky, 1))
PY
[ $? -eq 0 ] || { echo "[leaky] ABORT: could not generate the baseline"; exit 2; }
changed=$(diff "$BACKUP" "$ROOT/src/StableLog.mo" | grep -c '^[<>]')
[ "$changed" -le 6 ] || { echo "[leaky] ABORT: reverted $changed lines, wider than ensureHeadroom"; exit 2; }
echo "[leaky] baseline differs in $changed lines, all inside StableLog.ensureHeadroom"
rm -rf "$ROOT/.dfx/local/canisters/window_fixture"
dfx build window_fixture 2>&1 | grep -v "^WARNING" | sed "s|$ROOT/||g" | grep -viE "warning \[M0(155|194)\]|^ +Nat" | tail -2
built=".dfx/local/canisters/window_fixture/window_fixture.wasm"
[ -f "$built" ] || { echo "[leaky] ABORT: no wasm"; exit 2; }
mkdir -p "$(dirname "$OUT")"; cp "$built" "$OUT"
restore; trap - EXIT
rm -rf "$ROOT/.dfx/local/canisters/window_fixture"; dfx build window_fixture >/dev/null 2>&1
echo "[leaky] built $OUT sha256=$(sha256sum "$OUT" | cut -d' ' -f1)"
