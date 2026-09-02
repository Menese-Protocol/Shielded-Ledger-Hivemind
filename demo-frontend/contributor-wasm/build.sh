#!/usr/bin/env bash
# Deterministic build of the browser contributor client wasm.
#
# WHY THIS IS STRICTER THAN AN ORDINARY WASM BUILD. This wasm is where a ceremony participant's
# secret is sampled and destroyed. It is the artifact a contributor most needs to check, and it
# was for a period the one artifact nobody could check -- including us. The built pkg/ is
# deliberately untracked (a contributor should build the client, not receive a binary), and two
# correct builds from different directories produced different bytes, because rustc bakes the
# absolute source path into the binary. A hash nobody else can reproduce proves nothing, so the
# page's central promise -- "what your browser runs is the source you reviewed" -- could not be
# checked for the one file that matters most.
#
# Reproducibility contract:
#   - rustc/cargo : pinned by rust-toolchain.toml (1.95.0, wasm32-unknown-unknown)
#   - wasm-pack   : 0.13.1
#   - wasm-opt    : binaryen 123. wasm-pack runs it on the output; its version changes the bytes,
#                   so it is asserted here rather than assumed.
#   - deps        : pinned by Cargo.lock (the `ceremony` crate is a path dep, so the contribution
#                   maths in the browser is the same code the verifier and coordinator use)
#   - paths       : --remap-path-prefix rewrites the repo root to /src and CARGO_HOME to /cargo,
#                   so the hash does not depend on where the repository is checked out
#
# KNOWN LIMITATION, and the reason no byte-level guarantee is claimed anywhere for this artifact:
# the remapping above removed the gross path dependence (builds in different directories no longer
# produce wholly different output), but the result still settles into one of TWO wasm files that
# differ in three bytes -- the order of three 48-byte constants in the data section. It survives
# codegen-units = 1 and lto = false; wasm-opt and wasm-bindgen are each deterministic in isolation.
# Until that is resolved, do not treat a matching hash from this script as proof of anything more
# than that your build agreed with ours this time. See docs/CEREMONY.md section 7.
#
# Usage: demo-frontend/contributor-wasm/build.sh [--record] [out-dir]
#   Default out-dir is demo-frontend/contributor-client/pkg -- the directory the page serves.
#   Prints the SHA-256 of every output, and compares it against PKG-HASHES.txt if that exists.
#
#   --record  ALSO overwrite PKG-HASHES.txt with this build's hashes.
#
# Why recording is opt-in. PKG-HASHES.txt is the published record that
# scripts/verify-published-page.py checks against, so a build that rewrote it by default would let anyone
# who merely ran this script replace the reference with their own output -- and a later verify
# would then compare a tree against itself and report success no matter what the source said.
# That is not hypothetical: it happened here during development, and the verification reported
# "REPRODUCIBLE BUILD VERIFIED" for deliberately tampered source. A record that any build can
# silently overwrite is not a record.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
RECORD=0
if [ "${1:-}" = "--record" ]; then RECORD=1; shift; fi
OUT_DIR="${1:-$REPO_ROOT/demo-frontend/contributor-client/pkg}"
HASHES="$SCRIPT_DIR/PKG-HASHES.txt"

EXPECT_RUSTC="1.95.0"
EXPECT_WASM_PACK="0.13.1"
EXPECT_WASM_OPT="123"

rustc_ver="$(rustc --version 2>/dev/null | awk '{print $2}')"
wp_ver="$(wasm-pack --version 2>/dev/null | awk '{print $2}')"
wo_ver="$(wasm-opt --version 2>/dev/null | awk '{print $3}')"

[ "$rustc_ver" = "$EXPECT_RUSTC" ]   || echo "WARNING: rustc $rustc_ver != pinned $EXPECT_RUSTC (build may not be bit-reproducible)" >&2
[ "$wp_ver" = "$EXPECT_WASM_PACK" ]  || echo "WARNING: wasm-pack $wp_ver != pinned $EXPECT_WASM_PACK (build may not be bit-reproducible)" >&2
[ "$wo_ver" = "$EXPECT_WASM_OPT" ]   || echo "WARNING: wasm-opt $wo_ver != pinned $EXPECT_WASM_OPT (build may not be bit-reproducible)" >&2

CARGO_HOME_DIR="${CARGO_HOME:-$HOME/.cargo}"

echo "building contributor wasm (rustc $rustc_ver, wasm-pack $wp_ver, wasm-opt $wo_ver) ..."
cd "$SCRIPT_DIR"
# Both prefixes matter. The repo root covers this crate and its in-repo path deps (ceremony,
# circuit/common); CARGO_HOME covers the registry dependencies, whose paths differ per machine.
RUSTFLAGS="--remap-path-prefix=$REPO_ROOT=/src --remap-path-prefix=$CARGO_HOME_DIR=/cargo" \
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
    echo "# SHA-256 of every file demo-frontend/contributor-wasm/build.sh produces."
    echo "#"
    echo "# The built pkg/ is intentionally NOT tracked -- a ceremony contributor should build the"
    echo "# client from source rather than receive a binary from us. These hashes are what makes"
    echo "# that stance checkable instead of merely stated: scripts/verify-published-page.py"
    echo "# compares the assets the live page serves against this list when the built pkg/ is"
    echo "# absent. It records what we built and deployed; it is NOT a derivation from source,"
    echo "# because the client does not yet rebuild to identical bytes (docs/CEREMONY.md 7)."
    echo "#"
    echo "# Written only by build.sh --record. rustc $EXPECT_RUSTC / wasm-pack $EXPECT_WASM_PACK / wasm-opt $EXPECT_WASM_OPT"
    echo "$BUILT"
  } > "$HASHES"
  echo "recorded: $HASHES"
elif [ -f "$HASHES" ]; then
  if [ "$BUILT" = "$(grep -v '^#' "$HASHES" | grep -v '^[[:space:]]*$')" ]; then
    echo "matches PKG-HASHES.txt"
  else
    echo "DOES NOT match PKG-HASHES.txt -- see the KNOWN LIMITATION note at the top of this script" >&2
  fi
fi
