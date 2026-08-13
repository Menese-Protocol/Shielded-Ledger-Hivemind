#!/usr/bin/env bash
# Rebuild a battery's RED-leg baseline: the ledger as it stood immediately before a given fix, but
# carrying TODAY's StableBlobSet.
#
# Why the mix. Each red leg installs its baseline over a fixture whose stable state was written by
# the current scale_fixture. Since the layout-2 bump (3a5f4c1) that state is a layout-2 set, and a
# ledger built before the bump refuses it in postupgrade with
# 'postupgrade:roots:stable-set:layout-version' — so every pre-bump baseline wasm became
# un-installable and four committed batteries have been aborting rather than running. Taking the old
# src/ and putting the current storage module back into it keeps the baseline different from HEAD in
# the FIX under test and the same in the storage layout, which is what a red leg needs.
#
# Usage: scripts/build-fix-baseline.sh <git-repo> <fix-commit> <out.wasm>
#   The baseline is <fix-commit>^ — the tree immediately before the fix landed.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 1
export PATH="${DFX_BIN_DIR:-/root/.local/share/dfx/bin}:$PATH"

REPO="${1:?usage: build-fix-baseline.sh <git-repo> <fix-commit> <out.wasm>}"
COMMIT="${2:?missing fix commit}"
OUT="${3:?missing output wasm path}"

git -C "$REPO" rev-parse --verify "$COMMIT^" >/dev/null 2>&1 || {
  echo "[baseline] ABORT: $COMMIT^ is not a commit in that repo"; exit 2; }

STASH="$ROOT/.src-baseline-stash"
rm -rf "$STASH"
cp -a "$ROOT/src" "$STASH"
restore(){ rm -rf "$ROOT/src"; mv "$STASH" "$ROOT/src" 2>/dev/null || true; }
trap restore EXIT

rm -rf "$ROOT/src"
mkdir -p "$ROOT/src"
git -C "$REPO" archive "$COMMIT^" src | tar -x -C "$ROOT" || { echo "[baseline] ABORT: could not export src"; exit 2; }
# The storage module comes from TODAY, so the only difference from HEAD is the fix, not the layout.
cp "$STASH/StableBlobSet.mo" "$ROOT/src/StableBlobSet.mo"
echo "[baseline] src/ from $COMMIT^ with the current StableBlobSet.mo"

rm -rf "$ROOT/.dfx/local/canisters/zk_ledger"
dfx build zk_ledger 2>&1 | grep -v "^WARNING" | sed "s|$ROOT/||g" | grep -viE "warning \[M0(155|194)\]|^  Nat$" | tail -3
built=".dfx/local/canisters/zk_ledger/zk_ledger.wasm"
if [ ! -f "$built" ]; then
  echo "[baseline] ABORT: build produced no wasm — $COMMIT^ does not compile against the current StableBlobSet"
  exit 2
fi
mkdir -p "$(dirname "$OUT")"
cp "$built" "$OUT"

restore
trap - EXIT
rm -rf "$ROOT/.dfx/local/canisters/zk_ledger"
dfx build zk_ledger >/dev/null 2>&1
echo "[baseline] built $OUT sha256=$(sha256sum "$OUT" | cut -d' ' -f1)"
