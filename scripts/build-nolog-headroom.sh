#!/usr/bin/env bash
# Build a ledger with the NOTE-LOG headroom removed from PREPARE — everything else identical.
#
# The set-headroom rows of the PREPARE property test are staged by the grow-boundary leg, and
# three of the five substitution rows are vacuous. That leaves the note log at a
# region boundary as one of only two non-vacuous rows, and the waste property exercised StableLog.ensureHeadroom in
# a fixture rather than the LEDGER finalizing at a real boundary. This is the build that puts the log
# grow back inside the commit, so the difference is observable.
#
# Usage: scripts/build-nolog-headroom.sh <out.wasm>
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT" || exit 1
export PATH="${DFX_BIN_DIR:-/root/.local/share/dfx/bin}:$PATH"
OUT="${1:?usage: build-nolog-headroom.sh <out.wasm>}"
BACKUP="$ROOT/src/Main.mo.nolog"
cp "$ROOT/src/Main.mo" "$BACKUP"
restore(){ mv -f "$BACKUP" "$ROOT/src/Main.mo" 2>/dev/null || true; }
trap restore EXIT

python3 - "$ROOT/src/Main.mo" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1]); s = p.read_text()
good = """    switch (StableLog.ensureHeadroom(note_log,
      Nat64.fromNat(encoded1.size() + encoded2.size()), 2)) {
      case (#err(message)) return #err("REJECT:prepare-headroom:" # message); case (_) {};
    };
"""
if good not in s:
    print("ABORT: the log-headroom call is not the shape this script knows how to remove"); sys.exit(2)
p.write_text(s.replace(good, "", 1))
PY
[ $? -eq 0 ] || { echo "[nolog] ABORT: could not generate the baseline"; exit 2; }
changed=$(diff "$BACKUP" "$ROOT/src/Main.mo" | grep -c '^[<>]')
[ "$changed" -le 6 ] || { echo "[nolog] ABORT: removed $changed lines, wider than the headroom call"; exit 2; }
echo "[nolog] baseline differs in $changed lines, all the note-log headroom call"
rm -rf "$ROOT/.dfx/local/canisters/zk_ledger"
dfx build zk_ledger 2>&1 | grep -v "^WARNING" | sed "s|$ROOT/||g" | grep -viE "warning \[M0(155|194)\]|^ +Nat" | tail -2
built=".dfx/local/canisters/zk_ledger/zk_ledger.wasm"
[ -f "$built" ] || { echo "[nolog] ABORT: no wasm"; exit 2; }
mkdir -p "$(dirname "$OUT")"; cp "$built" "$OUT"
restore; trap - EXIT
rm -rf "$ROOT/.dfx/local/canisters/zk_ledger"; dfx build zk_ledger >/dev/null 2>&1
echo "[nolog] built $OUT sha256=$(sha256sum "$OUT" | cut -d' ' -f1)"
