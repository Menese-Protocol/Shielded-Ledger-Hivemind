#!/usr/bin/env bash
# Rebuild the coordinator wasm from source and assert its SHA-256 matches the published BUILD-HASH.txt.
# Anyone can run this to confirm a deployed coordinator wasm was built from exactly this source with
# the pinned toolchain: deployed-hash == this-hash == source. That trustless auditability is the
# entire point of the coordinator being reproducible.
#
# Usage: coordinator/verify-build.sh [expected-sha256]
#   With no argument it checks against coordinator/BUILD-HASH.txt.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

EXPECTED="${1:-}"
if [ -z "$EXPECTED" ]; then
  if [ ! -f "$SCRIPT_DIR/BUILD-HASH.txt" ]; then
    echo "no BUILD-HASH.txt and no expected hash given" >&2
    exit 2
  fi
  EXPECTED="$(cat "$SCRIPT_DIR/BUILD-HASH.txt")"
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Build into a scratch location without touching the tracked artifacts.
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"
MOC="$(dfx cache show)/moc"
"$MOC" $(mops sources) --idl --stable-types -o "$TMP/coordinator.wasm" coordinator/src/Main.mo >/dev/null
ACTUAL="$(sha256sum "$TMP/coordinator.wasm" | awk '{print $1}')"

echo "expected: $EXPECTED"
echo "actual:   $ACTUAL"
if [ "$EXPECTED" = "$ACTUAL" ]; then
  echo "REPRODUCIBLE BUILD VERIFIED: coordinator wasm hash matches source."
  exit 0
else
  echo "MISMATCH: the coordinator wasm does NOT reproduce from this source + toolchain." >&2
  exit 1
fi
