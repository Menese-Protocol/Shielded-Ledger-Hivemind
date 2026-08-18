#!/usr/bin/env bash
# A committed threshold must never change content. This checks each THRESHOLDS-*.md against its
# first-commit sha256, recorded in THRESHOLDS-MANIFEST.txt in the same directory.
#
# Why a guard and not a resolution to be careful: a real excursion happened ninety minutes after
# the rule was stated correctly and applied correctly twice. Intention is not sufficient.
#
# REPORT ONLY -- never restores. Auto-restoring would erase the evidence that an excursion happened,
# which is the opposite of the purpose. Thresholds: docs/thresholds/THRESHOLDS-frozen-guard.md.
#
# Usage: frozen-thresholds-guard.sh [<dir-with-thresholds-files>]
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR=${1:-"$ROOT/docs/thresholds"}
# The manifest MUST come from the same tree as the files it governs. It was previously pinned to
# $ROOT while DIR came from $1, so one tree's files were checked against another tree's
# manifest, and a threshold registered beside its own files was invisible to the check.
MAN="$DIR/THRESHOLDS-MANIFEST.txt"
[ -f "$MAN" ] || { echo "no manifest at $MAN"; exit 2; }

bad=0; seen=0
while read -r want commit file; do
  case "$want" in \#*|"") continue;; esac
  seen=$((seen+1))
  path="$DIR/$file"
  if [ ! -f "$path" ]; then echo "  MISSING   $file (frozen at $want in $commit)"; bad=$((bad+1)); continue; fi
  live=$(sha256sum "$path" | cut -c1-16)
  if [ "$live" != "$want" ]; then
    echo "  CHANGED   $file"; echo "            frozen $want ($commit)  live $live"; bad=$((bad+1))
  fi
done < "$MAN"

# COMPLETENESS. The loop above walks the MANIFEST, so a threshold the manifest omits is never
# visited and cannot fail: the guard once passed at 35 while 42 files existed (one file was
# registered and the class closed without enumerating the rest). An allowlist walker cannot detect an incomplete
# allowlist, so the disk set is enumerated here and compared against the manifest set.
#
# This is not a convenience check. The manifest header says "Generated once; never edited by hand",
# which means every NEW threshold is born unprotected -- registration fixes today, not tomorrow.
unlisted=0
for path in "$DIR"/THRESHOLDS-*.md; do
  [ -f "$path" ] || continue
  file=$(basename "$path")
  case "$file" in THRESHOLDS-MANIFEST.txt) continue;; esac
  if ! awk -v f="$file" '!/^[[:space:]]*(#|$)/ && $3 == f { found=1 } END { exit !found }' "$MAN"; then
    echo "  UNLISTED  $file (exists on disk, absent from the manifest — it is NOT protected)"
    unlisted=$((unlisted+1))
  fi
done

# The count line is a CONTRACT with any harness that ignores the exit code and extracts
# "N divergence(s)" -- a runner/gate contract mismatch is invisible from a green run.
# So the reported divergence count MUST include unlisted files -- otherwise an
# unregistered threshold exits 1 here while the harness reads "0 divergence(s)" and prints PASS.
# The breakdown line below keeps the two categories distinguishable without breaking that contract.
total=$((bad + unlisted))
echo "  breakdown: $bad changed-or-missing, $unlisted unlisted"
echo "  checked $seen frozen threshold(s); $total divergence(s)"
if [ "$total" -ne 0 ]; then
  [ "$bad" -ne 0 ] && echo "=== FAIL: a committed threshold diverged from its first-commit hash (CHANGED, or MISSING from disk) ==="
  [ "$unlisted" -ne 0 ] && echo "=== FAIL: $unlisted threshold(s) on disk are unregistered — 'committed before measurement' is unenforceable for them ==="
  exit 1
fi
echo "=== PASS: manifest and disk agree, and every committed threshold matches its first-commit hash ==="
