#!/usr/bin/env bash
# Deterministic build of the browser contributor client wasm.
#
# WHY THIS IS STRICTER THAN AN ORDINARY WASM BUILD. This wasm is where a ceremony participant's
# secret is sampled and destroyed. It is the artifact a contributor most needs to check, and a hash
# only they cannot reproduce is worth nothing to them.
#
# THE PATH IS PART OF THE BUILD. Two things had to be fixed, and they are different:
#
#   1. rustc records absolute source paths inside the binary. --remap-path-prefix rewrites those.
#   2. Cargo derives each crate's `-C metadata` -- which seeds every symbol hash -- from the
#      package's absolute path. --remap-path-prefix does NOT reach that, because it is Cargo's
#      input to rustc rather than something rustc emits. Building the same source from a different
#      directory therefore produced a different binary, and measurably so: six checkouts at six
#      paths gave six distinct wasm files. wasm-bindgen and wasm-opt then collapsed those into two
#      end results, which is why the surviving difference looked like a mere constant reordering.
#
# So the build is only reproducible when it happens at an agreed path. --canonical stages the
# sources to one ($ZK_CANONICAL_SRC, default /src) and builds there; the Dockerfile does exactly
# this with WORKDIR /src, which is why the container build is the normative one. Verified: three
# separate checkouts, staged to the canonical path, produce a byte-identical wasm.
#
# Reproducibility contract:
#   - rustc/cargo : pinned by rust-toolchain.toml (1.95.0, wasm32-unknown-unknown)
#   - wasm-pack   : 0.13.1
#   - wasm-opt    : binaryen 123. wasm-pack runs it on the output; its version changes the bytes.
#   - deps        : pinned by Cargo.lock (the `ceremony` path dep means the contribution maths in
#                   the browser is the same code the verifier and the coordinator use)
#   - paths       : --remap-path-prefix for the source root and CARGO_HOME, and --canonical for the
#                   build location. Both are needed; neither alone is sufficient.
#
# Usage: demo-frontend/contributor-wasm/build.sh [--canonical] [--record] [out-dir]
#   Default out-dir is demo-frontend/contributor-client/pkg -- the directory the page serves.
#   Prints the SHA-256 of every output and compares it against PKG-HASHES.txt if that exists.
#
#   --canonical  stage the sources to $ZK_CANONICAL_SRC (default /src) and build there. Required
#                for a hash that is comparable with anyone else's. Needs write access to that path.
#   --record     ALSO overwrite PKG-HASHES.txt with this build's hashes.
#
# Why recording is opt-in. PKG-HASHES.txt is the published record that
# scripts/verify-published-page.py and verify-build.sh check against, so a build that rewrote it by
# default would let anyone who merely ran this script replace the reference with their own output --
# and a later verify would then compare a tree against itself and report success no matter what the
# source said. That is not hypothetical: it happened here during development, and the verification
# reported "REPRODUCIBLE BUILD VERIFIED" for deliberately tampered source. A record that any build
# can silently overwrite is not a record.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CANON="${ZK_CANONICAL_SRC:-/src}"
RECORD=0; CANONICAL=0
while [ "${1:-}" = "--record" ] || [ "${1:-}" = "--canonical" ]; do
  [ "$1" = "--record" ] && RECORD=1
  [ "$1" = "--canonical" ] && CANONICAL=1
  shift
done
OUT_DIR="${1:-$REPO_ROOT/demo-frontend/contributor-client/pkg}"
HASHES="$SCRIPT_DIR/PKG-HASHES.txt"
mkdir -p "$OUT_DIR"; OUT_DIR="$(cd "$OUT_DIR" && pwd)"   # absolute: we build from another directory

EXPECT_RUSTC="1.95.0"
EXPECT_WASM_PACK="0.13.1"
EXPECT_WASM_OPT="123"

rustc_ver="$(rustc --version 2>/dev/null | awk '{print $2}')"
wp_ver="$(wasm-pack --version 2>/dev/null | awk '{print $2}')"
wo_ver="$(wasm-opt --version 2>/dev/null | awk '{print $3}')"

[ "$rustc_ver" = "$EXPECT_RUSTC" ]   || echo "WARNING: rustc $rustc_ver != pinned $EXPECT_RUSTC (build will not be bit-reproducible)" >&2
[ "$wp_ver" = "$EXPECT_WASM_PACK" ]  || echo "WARNING: wasm-pack $wp_ver != pinned $EXPECT_WASM_PACK (build will not be bit-reproducible)" >&2
[ "$wo_ver" = "$EXPECT_WASM_OPT" ]   || echo "WARNING: wasm-opt $wo_ver != pinned $EXPECT_WASM_OPT (build will not be bit-reproducible)" >&2

CARGO_HOME_DIR="${CARGO_HOME:-$HOME/.cargo}"

# Decide where the compiler will actually see the sources.
if [ "$CANONICAL" -eq 1 ]; then
  if ! mkdir -p "$CANON" 2>/dev/null; then
    echo "cannot create the canonical source path $CANON." >&2
    echo "  Set ZK_CANONICAL_SRC to a writable path, or build in the container:" >&2
    echo "    docker build -t ceremony-contributor-build -f demo-frontend/contributor-wasm/Dockerfile ." >&2
    echo "  Note that the path is part of the hash, so a different one gives a different (still" >&2
    echo "  self-consistent) result that will not match the published record." >&2
    exit 2
  fi
  STAGED=1
  rm -rf "${CANON:?}/ceremony" "${CANON:?}/circuit" "${CANON:?}/demo-frontend"
  # Only what the wasm links; build outputs are excluded so the copy compiles from scratch.
  tar -C "$REPO_ROOT" -cf - --exclude=target --exclude=pkg --exclude=.git --exclude=node_modules \
      ceremony circuit demo-frontend/contributor-wasm | tar -x -C "$CANON"
  BUILD_ROOT="$CANON"
  echo "canonical build: sources staged to $CANON"
else
  STAGED=0
  BUILD_ROOT="$REPO_ROOT"
  echo "NOTE: building in place. The hash depends on this directory's path, so it is only" >&2
  echo "      comparable with the published record if that record was built here too. Use" >&2
  echo "      --canonical (or the Dockerfile) for a hash anyone else can reproduce." >&2
fi
BUILD_CRATE="$BUILD_ROOT/demo-frontend/contributor-wasm"

cleanup() {
  [ "$STAGED" -eq 1 ] && rm -rf "${CANON:?}/ceremony" "${CANON:?}/circuit" "${CANON:?}/demo-frontend"
  return 0
}
trap cleanup EXIT

echo "building contributor wasm (rustc $rustc_ver, wasm-pack $wp_ver, wasm-opt $wo_ver) ..."
cd "$BUILD_CRATE"
# Both prefixes matter. The source root covers this crate and its in-repo path deps (ceremony,
# circuit/common); CARGO_HOME covers the registry dependencies, whose paths differ per machine.
RUSTFLAGS="--remap-path-prefix=$BUILD_ROOT=/src --remap-path-prefix=$CARGO_HOME_DIR=/cargo" \
  wasm-pack build --target web --release --out-dir "$OUT_DIR"

# Hash every served artifact, not just the wasm: the JS shim wasm-bindgen generates is loaded by
# the page too, so it is equally part of what a contributor's browser executes.
BUILT="$(cd "$OUT_DIR" && find . -type f ! -name '.*' -printf '%P\n' | LC_ALL=C sort \
    | while IFS= read -r f; do echo "$(sha256sum "$f" | awk '{print $1}')  $f"; done)"

echo
echo "wrote: $OUT_DIR"
echo "$BUILT"

if [ "$RECORD" -eq 1 ]; then
  {
    echo "# SHA-256 of every file demo-frontend/contributor-wasm/build.sh --canonical produces."
    echo "#"
    echo "# The built pkg/ is intentionally NOT tracked -- a ceremony contributor should build the"
    echo "# client from source rather than receive a binary from us. These hashes are what makes"
    echo "# that stance checkable: verify-build.sh rebuilds them from source, and"
    echo "# scripts/verify-published-page.py compares them against what the live page serves."
    echo "#"
    echo "# Reproduce with:  demo-frontend/contributor-wasm/build.sh --canonical"
    echo "# The build path is part of the hash; --canonical fixes it at /src, as the Dockerfile does."
    echo "# Written only by build.sh --record."
    echo "# rustc $EXPECT_RUSTC / wasm-pack $EXPECT_WASM_PACK / wasm-opt $EXPECT_WASM_OPT"
    echo "$BUILT"
  } > "$HASHES"
  echo "recorded: $HASHES"
elif [ -f "$HASHES" ]; then
  if [ "$BUILT" = "$(grep -v '^#' "$HASHES" | grep -v '^[[:space:]]*$')" ]; then
    echo "matches PKG-HASHES.txt"
  else
    echo "DOES NOT match PKG-HASHES.txt" >&2
    [ "$CANONICAL" -eq 1 ] || echo "  (this was an in-place build; re-run with --canonical before concluding anything)" >&2
  fi
fi
