#!/usr/bin/env bash
# Build the RED-CONTROL ledger for the finalize frontier cross-check: HEAD with the cross-check
# REMOVED, and nothing else changed.
#
# Why this build has to exist. total-commit, lying-receipt and archive-reconcile all reach finalize
# in real-frontier mode, where the recomputed root AGREES with root_after. A battery that only ever
# sees the check agree stays green when the check is deleted, so its green says nothing about the
# check. Each of the three now carries a leg that stages a DIVERGENT root_after and requires the
# named refusal; this wasm is what proves that leg can fail. Against it, the refusal does not
# happen and the corrupted root lands.
#
# What is removed, exactly: the comparison `local.root != blobToHex(pending.root_after)` at both
# finalize sites, and only that. `frontierAppend` still runs and its #err arm still refuses, so the
# difference between this build and HEAD is the cross-check itself rather than the whole frontier
# path -- an inverted or ripped-out frontier would fail the matching legs too and tell you less.
#
# Usage: scripts/build-nocrosscheck-ledger.sh <out.wasm>
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 1
export PATH="${DFX_BIN_DIR:-/root/.local/share/dfx/bin}:$PATH"

OUT="${1:?usage: build-nocrosscheck-ledger.sh <out.wasm>}"
MAIN="src/Main.mo"
NEEDLE='if (local.root != blobToHex(pending.root_after)) {'

BEFORE=$(grep -cF "$NEEDLE" "$ROOT/$MAIN")
[ "$BEFORE" = "2" ] || { echo "[nocheck] ABORT: expected 2 cross-check sites in $MAIN, found $BEFORE"; exit 2; }

STASH="$ROOT/.nocheck-main-stash"
cp -a "$ROOT/$MAIN" "$STASH"
restore(){ cp -a "$STASH" "$ROOT/$MAIN" && rm -f "$STASH"; }
trap restore EXIT

# `if (false)` keeps the recomputation and the binding in place and disables only the comparison.
perl -pi -e "s/\Qif (local.root != blobToHex(pending.root_after)) {\E/if (false) {/g" "$ROOT/$MAIN"
AFTER=$(grep -cF "$NEEDLE" "$ROOT/$MAIN")
[ "$AFTER" = "0" ] || { echo "[nocheck] ABORT: $AFTER cross-check sites survived the patch"; exit 2; }
DISABLED=$(grep -c 'if (false) {' "$ROOT/$MAIN")
[ "$DISABLED" = "2" ] || { echo "[nocheck] ABORT: expected 2 disabled sites, found $DISABLED"; exit 2; }
echo "[nocheck] both finalize cross-checks disabled in $MAIN; everything else is HEAD"

rm -rf "$ROOT/.dfx/local/canisters/zk_ledger"
dfx build zk_ledger 2>&1 | grep -v "^WARNING" | sed "s|$ROOT/||g" \
  | grep -viE "warning \[M0(155|194|244)\]|^  Nat$" | tail -3
built=".dfx/local/canisters/zk_ledger/zk_ledger.wasm"
[ -f "$built" ] || { echo "[nocheck] ABORT: build produced no wasm"; exit 2; }
mkdir -p "$(dirname "$OUT")"
cp "$built" "$OUT"

restore
trap - EXIT
grep -cF "$NEEDLE" "$ROOT/$MAIN" | grep -qx 2 || { echo "[nocheck] ABORT: $MAIN was not restored"; exit 2; }
rm -rf "$ROOT/.dfx/local/canisters/zk_ledger"
dfx build zk_ledger >/dev/null 2>&1
echo "[nocheck] built $OUT sha256=$(sha256sum "$OUT" | cut -d' ' -f1)"
