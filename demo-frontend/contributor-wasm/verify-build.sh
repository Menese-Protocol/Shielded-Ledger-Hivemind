#!/usr/bin/env bash
# Rebuild the contributor wasm from source and assert it matches the published PKG-HASHES.txt.
#
# Anyone can run this to confirm that the client their browser runs during a ceremony contribution
# was built from exactly this source. With scripts/verify-published-page.py -- which compares the
# same hashes against what the live canister actually serves -- it closes the chain
# source -> binary -> served page for the one artifact that touches a participant's secret.
#
# It performs TWO builds and requires both to match the record:
#
#   build A   from this checkout
#   build B   from a copy of this checkout at a DIFFERENT path
#
# The second build is the point, and it is not redundant. Cargo derives each crate's `-C metadata`
# from the package's absolute path, and that seeds every symbol hash, so before this was handled a
# checkout in another directory produced a different binary from identical source -- a contributor
# would have seen a mismatch and been unable to distinguish it from tampering. build.sh --canonical
# stages the sources to a fixed path so the result does not depend on where you cloned. Build B is
# what proves that actually works rather than being asserted.
#
# Usage: demo-frontend/contributor-wasm/verify-build.sh [--fast]
#   --fast  skip build B (checks the build reproduces, not that it does so from any checkout)
#
# Exit: 0 verified | 1 source mismatch on the pinned toolchain | 3 toolchain mismatch | 2 usage
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
HASHES="$SCRIPT_DIR/PKG-HASHES.txt"
FAST=0
[ "${1:-}" = "--fast" ] && FAST=1

if [ ! -f "$HASHES" ]; then
  echo "no PKG-HASHES.txt; run demo-frontend/contributor-wasm/build.sh --canonical --record first" >&2
  exit 2
fi

EXPECT_RUSTC="1.95.0"; EXPECT_WASM_PACK="0.13.1"; EXPECT_WASM_OPT="123"
rustc_ver="$(rustc --version 2>/dev/null | awk '{print $2}')"
wp_ver="$(wasm-pack --version 2>/dev/null | awk '{print $2}')"
wo_ver="$(wasm-opt --version 2>/dev/null | awk '{print $3}')"
toolchain_ok=1
[ "$rustc_ver" = "$EXPECT_RUSTC" ]  || toolchain_ok=0
[ "$wp_ver" = "$EXPECT_WASM_PACK" ] || toolchain_ok=0
[ "$wo_ver" = "$EXPECT_WASM_OPT" ]  || toolchain_ok=0
echo "toolchain: rustc $rustc_ver (pinned $EXPECT_RUSTC), wasm-pack $wp_ver (pinned $EXPECT_WASM_PACK), wasm-opt $wo_ver (pinned $EXPECT_WASM_OPT)"

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# Compare only against a snapshot taken before any build runs. build.sh is invoked below WITHOUT
# --record so it cannot rewrite the record, but this does not rely on that staying true: comparing
# a build against a file that same build produced would pass unconditionally, and reading an
# immutable copy makes that impossible rather than merely unlikely.
PUBLISHED="$TMP/published-hashes.txt"
cp "$HASHES" "$PUBLISHED"

# Both directions: a build that omits a recorded file, or emits one that is not recorded, is not a
# match. A subset comparison would accept a client with something added to it.
compare() {
  local dir="$1" label="$2" bad=0
  while read -r want name; do
    [ -n "${name:-}" ] || continue
    if [ ! -f "$dir/$name" ]; then echo "  MISSING  $label  $name"; bad=1; continue; fi
    local got; got="$(sha256sum "$dir/$name" | awk '{print $1}')"
    if [ "$got" != "$want" ]; then
      echo "  DIFFERS  $label  $name"; echo "             recorded $want"; echo "             built    $got"; bad=1
    fi
  done < <(grep -v '^#' "$PUBLISHED" | grep -v '^[[:space:]]*$')
  while IFS= read -r f; do
    grep -qE "  ${f//./\\.}\$" "$PUBLISHED" || { echo "  EXTRA    $label  $f  (built but not recorded)"; bad=1; }
  done < <(cd "$dir" && find . -type f ! -name '.*' -printf '%P\n' | LC_ALL=C sort)
  return $bad
}

echo
echo "build A: this checkout ($REPO_ROOT)"
if ! CARGO_TARGET_DIR="$TMP/ta" bash "$SCRIPT_DIR/build.sh" --canonical "$TMP/pkg-a" > "$TMP/a.log" 2>&1; then
  echo "build A failed:"; tail -20 "$TMP/a.log"; exit 1
fi
rc_a=0; compare "$TMP/pkg-a" "A" || rc_a=1
[ "$rc_a" -eq 0 ] && echo "  A matches PKG-HASHES.txt"

rc_b=0
if [ "$FAST" -eq 1 ]; then
  echo; echo "build B: skipped (--fast); independence from the checkout location NOT checked"
else
  echo; echo "build B: a copy of this checkout at a different path"
  COPY="$TMP/elsewhere"; mkdir -p "$COPY"
  # Copy the WORKING TREE, not `git archive HEAD`: an auditor is checking the tree in front of
  # them, and verifying HEAD instead would silently skip every uncommitted change and report a
  # clean result for source that is not the source being read.
  tar -C "$REPO_ROOT" -cf - \
      --exclude=target --exclude=pkg --exclude=.git --exclude=node_modules \
      ceremony circuit demo-frontend/contributor-wasm | tar -x -C "$COPY"
  if ! CARGO_TARGET_DIR="$TMP/tb" bash "$COPY/demo-frontend/contributor-wasm/build.sh" --canonical "$TMP/pkg-b" > "$TMP/b.log" 2>&1; then
    echo "build B failed:"; tail -20 "$TMP/b.log"; exit 1
  fi
  compare "$TMP/pkg-b" "B" || rc_b=1
  [ "$rc_b" -eq 0 ] && echo "  B matches PKG-HASHES.txt (checkout at $COPY)"
fi

echo
if [ "$rc_a" -eq 0 ] && [ "$rc_b" -eq 0 ]; then
  [ "$toolchain_ok" -eq 1 ] || echo "NOTE: hashes match despite an unpinned toolchain." >&2
  if [ "$FAST" -eq 1 ]; then
    echo "REPRODUCIBLE BUILD VERIFIED (one checkout only; re-run without --fast to check independence)."
  else
    echo "REPRODUCIBLE BUILD VERIFIED: the contributor wasm rebuilds to the published hashes from"
    echo "two checkouts at different paths, so the result does not depend on where you cloned it."
  fi
  exit 0
fi

if [ "$toolchain_ok" -eq 0 ]; then
  echo "TOOLCHAIN MISMATCH, NOT NECESSARILY A SOURCE MISMATCH." >&2
  echo "  This machine is not on the pinned toolchain, so different bytes are expected and prove" >&2
  echo "  nothing about the source. Reproduce on the pin before drawing any conclusion:" >&2
  echo "    docker build -t ceremony-contributor-build -f demo-frontend/contributor-wasm/Dockerfile ." >&2
  exit 3
fi

echo "MISMATCH ON THE PINNED TOOLCHAIN: the source does NOT produce the published client." >&2
echo "  This is the real failure. Do not contribute a secret through a page built from this tree." >&2
exit 1
