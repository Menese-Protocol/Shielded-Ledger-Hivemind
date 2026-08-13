#!/usr/bin/env bash
# Build a ScaleFixture wasm bound to the FROZEN layout-1 StableBlobSet, so a genuine layout-1 ->
# layout-2 upgrade can be exercised on the replica.
#
# The generated source is tests/ScaleFixture.mo with exactly ONE line changed: the StableBlobSet
# import. That is proved here rather than asserted — the diff against ScaleFixture.mo must be a
# single changed line, or this script aborts. Anything else would mean the two builds differ in
# something other than the module under test, and the comparison would be worthless.
#
# Usage: scripts/build-layout1-fixture.sh <out.wasm>
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 1
export PATH="${DFX_BIN_DIR:-/root/.local/share/dfx/bin}:$PATH"

OUT="${1:?usage: build-layout1-fixture.sh <out.wasm>}"
GEN="$ROOT/tests/ScaleFixtureLayout1.generated.mo"
FROZEN_SHA="c9195aaeb0e3970a4e530dc5f04837ff4767531256f07c10eb2af9a740038657"

have=$(sha256sum "$ROOT/tests/layout1/StableBlobSet.mo" | cut -d' ' -f1)
if [ "$have" != "$FROZEN_SHA" ]; then
  echo "[layout1] ABORT: tests/layout1/StableBlobSet.mo is not the frozen 3a5f4c1^ blob"
  echo "[layout1]   expected $FROZEN_SHA"
  echo "[layout1]   actual   $have"
  exit 2
fi
echo "[layout1] frozen module verified: $have"

sed 's|import StableBlobSet "../src/StableBlobSet";|import StableBlobSet "./layout1/StableBlobSet";|' \
  "$ROOT/tests/ScaleFixture.mo" > "$GEN"

changed=$(diff "$ROOT/tests/ScaleFixture.mo" "$GEN" | grep -c '^[<>]')
if [ "$changed" != "2" ]; then
  echo "[layout1] ABORT: the generated source differs from ScaleFixture.mo in $((changed / 2)) lines, expected 1"
  diff "$ROOT/tests/ScaleFixture.mo" "$GEN"
  rm -f "$GEN"
  exit 2
fi
echo "[layout1] generated source differs from ScaleFixture.mo in exactly one line (the import)"

# Paths are made project-relative: an evidence artefact must not carry the auditor's checkout path.
dfx build scale_fixture_layout1 2>&1 | grep -v "^WARNING" | sed "s|$ROOT/||g" | tail -3
built=".dfx/local/canisters/scale_fixture_layout1/scale_fixture_layout1.wasm"
if [ ! -f "$built" ]; then
  echo "[layout1] ABORT: build produced no wasm at $built"
  rm -f "$GEN"
  exit 2
fi
mkdir -p "$(dirname "$OUT")"
cp "$built" "$OUT"
rm -f "$GEN"
echo "[layout1] built $OUT sha256=$(sha256sum "$OUT" | cut -d' ' -f1)"
