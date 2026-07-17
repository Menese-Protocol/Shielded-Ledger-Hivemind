#!/usr/bin/env bash
# Deterministic one-command build of the Phase-2 ceremony coordinator wasm.
#
# Reproducibility contract (a ceremony coordinator whose binary cannot be reproduced is worthless):
#   - moc      : 1.1.0  (shipped with dfx 0.31.0; we invoke $(dfx cache show)/moc, never /usr/bin/moc)
#   - dfx      : 0.31.0
#   - mops     : 2.8.0 CLI, packages pinned in ../mops.lock (core 1.0.0, sha2 0.1.9)
#   - sources  : coordinator/src/*.mo + the in-repo BLS12-381 tower src/groth16/*.mo
# Two runs on the same toolchain produce a byte-identical wasm (identical SHA-256). For
# cross-machine reproduction use the pinned Docker image (see Dockerfile).
#
# Usage: coordinator/build.sh            # writes coordinator/coordinator.wasm + .did + BUILD-HASH.txt
set -euo pipefail

# Resolve repo root (this script lives in coordinator/).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

EXPECT_DFX="0.31.0"
EXPECT_MOC="1.1.0"

dfx_ver="$(dfx --version 2>/dev/null | awk '{print $2}')"
if [ "$dfx_ver" != "$EXPECT_DFX" ]; then
  echo "WARNING: dfx $dfx_ver != pinned $EXPECT_DFX (build may not be bit-reproducible)" >&2
fi
MOC="$(dfx cache show)/moc"
moc_ver="$("$MOC" --version 2>/dev/null | awk '{print $3}')"
if [ "$moc_ver" != "$EXPECT_MOC" ]; then
  echo "WARNING: moc $moc_ver != pinned $EXPECT_MOC (build may not be bit-reproducible)" >&2
fi

PKG_ARGS="$(mops sources)"
OUT_WASM="$SCRIPT_DIR/coordinator.wasm"
OUT_DID="$SCRIPT_DIR/coordinator.did"

echo "building coordinator wasm with moc $moc_ver ..."
"$MOC" $PKG_ARGS --idl --stable-types -o "$OUT_WASM" coordinator/src/Main.mo
# moc emits the .did next to the actor when --idl is set; normalize its location.
if [ -f "$REPO_ROOT/coordinator/src/Main.did" ]; then mv "$REPO_ROOT/coordinator/src/Main.did" "$OUT_DID"; fi

HASH="$(sha256sum "$OUT_WASM" | awk '{print $1}')"
echo "$HASH" > "$SCRIPT_DIR/BUILD-HASH.txt"
echo "coordinator.wasm SHA-256: $HASH"
echo "wrote: $OUT_WASM"
echo "wrote: $SCRIPT_DIR/BUILD-HASH.txt"
