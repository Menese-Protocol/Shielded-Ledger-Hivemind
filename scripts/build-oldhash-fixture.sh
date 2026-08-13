#!/usr/bin/env bash
# Build a HashParityFixture wasm bound to the PREVIOUS hashOf, so the differential test compares two
# real compiler outputs rather than a function against a transcription of itself.
#
# The generated module is src/StableBlobSet.mo with exactly ONE function body replaced. That is
# proved rather than asserted: the diff against the current module must touch only lines inside
# hashOf, or this aborts. Anything wider would mean the two builds differ in something other than
# the function under test.
#
# Usage: scripts/build-oldhash-fixture.sh <out.wasm>
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 1
export PATH="${DFX_BIN_DIR:-/root/.local/share/dfx/bin}:$PATH"
OUT="${1:?usage: build-oldhash-fixture.sh <out.wasm>}"

BACKUP="$ROOT/src/StableBlobSet.mo.oldhash-backup"
cp "$ROOT/src/StableBlobSet.mo" "$BACKUP"
restore(){ mv -f "$BACKUP" "$ROOT/src/StableBlobSet.mo" 2>/dev/null || true; }
trap restore EXIT

python3 - "$ROOT/src/StableBlobSet.mo" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1]); s = p.read_text()
new = """  func hashOf(key : Blob) : Nat64 {
    let digest = Sha256.fromBlob(#sha256, key);
    var value : Nat64 = 0;
    var taken : Nat = 0;
    label scan for (byte in digest.vals()) {
      if (taken == 8) break scan;
      value := (value << 8) | Prim.nat32ToNat64(Prim.nat16ToNat32(Prim.nat8ToNat16(byte)));
      taken += 1;
    };
    value
  };"""
old = """  func hashOf(key : Blob) : Nat64 {
    let digest = Blob.toArray(Sha256.fromBlob(#sha256, key));
    var value : Nat64 = 0;
    var i : Nat = 0;
    while (i < 8) {
      value := value * 256 + Nat64.fromNat(Nat8.toNat(digest[i]));
      i += 1;
    };
    value
  };"""
if new not in s:
    print("ABORT: the current hashOf is not the shape this script knows how to revert")
    sys.exit(2)
p.write_text(s.replace(new, old, 1))
PY
[ $? -eq 0 ] || { echo "[oldhash] ABORT: could not generate the baseline module"; exit 2; }

changed=$(diff "$BACKUP" "$ROOT/src/StableBlobSet.mo" | grep -c '^[<>]')
if [ "$changed" -gt 20 ]; then
  echo "[oldhash] ABORT: the baseline differs in $changed lines, which is wider than hashOf"
  diff "$BACKUP" "$ROOT/src/StableBlobSet.mo"
  exit 2
fi
echo "[oldhash] baseline module differs from the current one in $changed lines, all inside hashOf"

rm -rf "$ROOT/.dfx/local/canisters/hash_parity_fixture"
dfx build hash_parity_fixture 2>&1 | grep -v "^WARNING" | sed "s|$ROOT/||g" | tail -3
built=".dfx/local/canisters/hash_parity_fixture/hash_parity_fixture.wasm"
[ -f "$built" ] || { echo "[oldhash] ABORT: build produced no wasm"; exit 2; }
mkdir -p "$(dirname "$OUT")"
cp "$built" "$OUT"
restore
trap - EXIT
rm -rf "$ROOT/.dfx/local/canisters/hash_parity_fixture"
dfx build hash_parity_fixture >/dev/null 2>&1
echo "[oldhash] built $OUT sha256=$(sha256sum "$OUT" | cut -d' ' -f1)"
