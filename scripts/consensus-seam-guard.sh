#!/usr/bin/env bash
# Consensus-seam source guard (audit §4 rec 3).
#
# Three decode seams are consensus-critical: for a LEGACY verifying key they are the ONLY
# defense against value doubling (duplicate input note), field-wrap over-issuance (fee /
# v_pub_out >= 2^64), and the non-canonical-encoding double-spend. This guard is a structural
# assertion over the LIVE SOURCE: it fails the security gate if any seam is deleted, retyped,
# reduced-instead-of-rejected, or reordered past the state write it protects.
#
#   seam 1  Main.mo   duplicate-nullifier + canonicity guards, ordered before the spent-set
#   seam 2  Main.mo   nat64Field(Nat64) embedding + Nat64-typed fee/v_pub_out/shield value
#   seam 3  Fr.mo + Groth16Wire.mo   isCanonical strict-rejection decode (never reduce mod r)
#
# Behavioral (adversarial-input) coverage of the same seams lives in
# scripts/consensus-decode-regression.mjs and the e2e replica battery; this file pins the
# source shape so a "refactor" cannot silently move a defense out from under them.
#
# Usage: consensus-seam-guard.sh [tree-root]   (default: the repo containing this script)
set -euo pipefail

ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
MAIN="$ROOT/src/Main.mo"
FR="$ROOT/src/groth16/Fr.mo"
WIRE="$ROOT/src/groth16/Groth16Wire.mo"
TREE="$ROOT/src/PoseidonTree.mo"

fail() { echo "CONSENSUS SEAM GUARD FAIL: $1" >&2; exit 1; }
pass() { echo "  seam-guard PASS: $1"; }

for f in "$MAIN" "$FR" "$WIRE" "$TREE"; do
  [[ -f "$f" ]] || fail "missing source file $f"
done

# must_line <file> <fixed-string> <label>  -> prints the first matching line number
must_line() {
  local n
  n="$(grep -nF -- "$2" "$1" | head -1 | cut -d: -f1)" || true
  [[ -n "$n" ]] || fail "$3 — expected literal not found in $(basename "$1"): $2"
  echo "$n"
}

# ---- seam 3: strict-canonical Fr decode (Fr.mo + Groth16Wire.mo) ----
must_line "$FR" 'public func isCanonical(a : Nat) : Bool { a < P };' \
  "Fr.isCanonical must be the strict a < P predicate" >/dev/null
must_line "$FR" '0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;' \
  "Fr.P must be the BLS12-381 scalar modulus" >/dev/null
pass "Fr.isCanonical is strict (a < P) over the pinned BLS12-381 r"

FRFROM="$(must_line "$WIRE" 'func frFromLe(b : [Nat8], from : Nat) : ?Nat {' \
  'Groth16Wire.frFromLe must exist')"
REJLINE="$(must_line "$WIRE" 'if (not Fr.isCanonical(x)) { return null };' \
  'frFromLe must REJECT (return null on) a non-canonical encoding, never reduce')"
(( REJLINE > FRFROM && REJLINE <= FRFROM + 8 )) \
  || fail "the isCanonical rejection is no longer inside frFromLe (decl line $FRFROM, rejection line $REJLINE)"
must_line "$WIRE" 'switch (frFromLe(bytes, 8 + 32 * i)) {' \
  "parseInputs must decode every public input through frFromLe" >/dev/null
grep -qF 'x % Fr.P' "$WIRE" && fail "Groth16Wire reduces an input mod Fr.P — decode must reject, not reduce"
pass "Groth16Wire.frFromLe rejects non-canonical encodings; parseInputs routes through it"

# ---- blobToNat (the ledger-side canonicity primitive the seam-1 guard uses) ----
BTN="$(must_line "$TREE" 'public func blobToNat(value : Blob) : ?Nat {' \
  'PoseidonTree.blobToNat must exist')"
BTNREJ="$(tail -n "+$BTN" "$TREE" | grep -nF -- 'if (result >= Fr.P) return null;' | head -1 | cut -d: -f1)" || true
[[ -n "$BTNREJ" ]] || fail "blobToNat must REJECT (return null on) a value >= Fr.P"
(( BTNREJ > 1 && BTNREJ <= 12 )) \
  || fail "blobToNat's >= Fr.P rejection moved out of the function (offset $BTNREJ from decl $BTN)"
pass "PoseidonTree.blobToNat rejects non-canonical 32-byte encodings"

# ---- seam 1: nullifier canonicity + distinctness, ordered before the spent-set ----
NONCANON="$(must_line "$MAIN" 'if (PoseidonTree.blobToNat(args.nullifier_1) == null or' \
  'confidential_transfer must canonicity-check nullifier_1/2 via blobToNat')"
must_line "$MAIN" '        PoseidonTree.blobToNat(args.nullifier_2) == null) {' \
  "confidential_transfer must canonicity-check nullifier_2" >/dev/null
must_line "$MAIN" '"REJECT:nullifier-noncanonical"' \
  "the canonicity refusal class must be REJECT:nullifier-noncanonical" >/dev/null
DUP="$(must_line "$MAIN" 'if (args.nullifier_1 == args.nullifier_2) {' \
  'confidential_transfer must reject equal nullifiers in one transaction')"
must_line "$MAIN" '"REJECT:duplicate-nullifier-in-tx"' \
  "the duplicate refusal class must be REJECT:duplicate-nullifier-in-tx" >/dev/null
SPENT="$(must_line "$MAIN" 'if (StableBlobSet.contains(spent_nullifiers, args.nullifier_1) or' \
  'confidential_transfer must check the spent set')"
VERIFY="$(must_line "$MAIN" 'let verdict = verifyTransferProof(args.proof_hex, inputs);' \
  'confidential_transfer must call the verifier after the nullifier guards')"
(( NONCANON < DUP && DUP < SPENT && SPENT < VERIFY )) \
  || fail "nullifier guard ordering broken: canonicity($NONCANON) < duplicate($DUP) < spent-set($SPENT) < verify($VERIFY) must hold"
pass "nullifier canonicity ($NONCANON) precedes duplicate ($DUP) precedes spent-set ($SPENT) precedes verify ($VERIFY)"

# ---- seam 2: Nat64 embedding of the public conservation terms ----
must_line "$MAIN" 'func nat64Field(valueInput : Nat64) : Blob {' \
  "nat64Field must take Nat64 (a wider type would let a >= 2^64 term reach the verifier)" >/dev/null
must_line "$MAIN" 'nat64Field(args.fee),' \
  "confidential_transfer must embed fee through nat64Field" >/dev/null
must_line "$MAIN" 'nat64Field(args.v_pub_out),' \
  "confidential_transfer must embed v_pub_out through nat64Field" >/dev/null
must_line "$MAIN" 'nat64Field(args.value)' \
  "shield must embed the deposit value through nat64Field (audit F3)" >/dev/null
# fee / v_pub_out typing INSIDE TransferArgs specifically
TA_BLOCK="$(awk '/public type TransferArgs = \{/,/^  \};/' "$MAIN")"
[[ -n "$TA_BLOCK" ]] || fail "TransferArgs record not found in Main.mo"
grep -qF 'fee : Nat64;' <<<"$TA_BLOCK" \
  || fail "TransferArgs.fee is no longer Nat64 — the legacy statement's fee range bound is gone"
grep -qF 'v_pub_out : Nat64;' <<<"$TA_BLOCK" \
  || fail "TransferArgs.v_pub_out is no longer Nat64 — the legacy statement's range bound is gone"
pass "nat64Field(Nat64) embeds fee / v_pub_out / shield value; TransferArgs keeps Nat64 typing"

echo "CONSENSUS SEAM GUARD: ALL STRUCTURAL ASSERTIONS HOLD ($(basename "$ROOT"))"
