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
# The toolchain is checked BEFORE the hash is compared, and reported separately, because the two
# failures mean opposite things. A hash mismatch on the PINNED toolchain says the source no longer
# produces the published binary — the thing this script exists to detect. The same mismatch on a
# DIFFERENT toolchain says almost nothing: moc encodes its own version into the wasm, so any other
# compiler yields a different hash from identical source. Reporting both as a bare "MISMATCH" reads
# as tampering when it is usually just an unpinned machine, which is exactly the wrong alarm to
# raise at someone deciding whether to trust a ceremony coordinator.
EXPECT_DFX="0.32.0"
EXPECT_MOC="1.4.1"

MOC="$(dfx cache show)/moc"
dfx_ver="$(dfx --version 2>/dev/null | awk '{print $2}')"
moc_ver="$("$MOC" --version 2>/dev/null | awk '{print $3}')"
toolchain_ok=1
[ "$dfx_ver" = "$EXPECT_DFX" ] || toolchain_ok=0
[ "$moc_ver" = "$EXPECT_MOC" ] || toolchain_ok=0

echo "toolchain: dfx $dfx_ver (pinned $EXPECT_DFX), moc $moc_ver (pinned $EXPECT_MOC)"

# --idl makes moc drop Main.did beside the source; keep the working tree clean either way.
"$MOC" $(mops sources) --idl --stable-types -o "$TMP/coordinator.wasm" coordinator/src/Main.mo >/dev/null
rm -f "$REPO_ROOT/coordinator/src/Main.did"
ACTUAL="$(sha256sum "$TMP/coordinator.wasm" | awk '{print $1}')"

echo "expected: $EXPECTED"
echo "actual:   $ACTUAL"

if [ "$EXPECTED" = "$ACTUAL" ]; then
  [ "$toolchain_ok" -eq 1 ] || echo "NOTE: hashes match despite an unpinned toolchain." >&2
  echo "REPRODUCIBLE BUILD VERIFIED: coordinator wasm hash matches source."
  exit 0
fi

if [ "$toolchain_ok" -eq 0 ]; then
  echo "TOOLCHAIN MISMATCH, NOT A SOURCE MISMATCH." >&2
  echo "  This machine is not on the pinned toolchain, so a different hash is expected and" >&2
  echo "  proves nothing about the source. Reproduce on the pin before drawing any conclusion:" >&2
  echo "    docker build -t ceremony-coordinator-build -f coordinator/Dockerfile ." >&2
  exit 3
fi

echo "MISMATCH ON THE PINNED TOOLCHAIN: the source does NOT produce the published binary." >&2
echo "  This is the real failure. Do not trust a coordinator built from this tree." >&2
exit 1
