/// Motoko side of the per-op arithmetic differential (field layers).
///
/// Implements the shared deterministic stream spec (fortress/src/lib.rs doc-comment)
/// independently, and computes every op class through the PRODUCTION modules:
/// `fp1.*` through the L1 reference `Fp.mo`, `fpm.*` through the L2 Montgomery
/// `FpMont.mo`, `fr.*` through `Fr.mo`. Emits the same `CLASS <tag> N=<n> DIGEST=<hex>`
/// lines as fortress/src/bin/arith_oracle.rs; the harness sorts and diffs the line sets.
/// A digest divergence localizes to (layer, op class); the failing case index is then
/// recovered by re-running both sides with the printed seed at smaller DIV.
///
/// Run (staged next to src/groth16 modules by scripts/fortress-arith.sh):
///   moc -r --package core <core> --package sha2 <sha2> ArithDiff.mo

import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Char "mo:core/Char";
import Debug "mo:core/Debug";
import Nat "mo:core/Nat";
import Nat8 "mo:core/Nat8";
import Nat32 "mo:core/Nat32";
import Nat64 "mo:core/Nat64";
import Text "mo:core/Text";
import Sha256 "mo:sha2/Sha256";
import Fp "Fp";
import FpM "FpMont";
import Fr "Fr";

// The harness may rewrite the two lines below (calibration / seed override). The values
// printed in the output are always the ones actually used.
let SEED : Nat64 = 20260721;
let DIV : Nat = 1;

// ---- shared-stream primitives (independent implementation of the spec) ----

var smState : Nat64 = 0;

func classSeed(tag : Text) : Nat64 {
  let tagBytes = Blob.toArray(Text.encodeUtf8(tag));
  let joined = Array.tabulate<Nat8>(tagBytes.size() + 8, func(i : Nat) : Nat8 {
    if (i < tagBytes.size()) {
      tagBytes[i]
    } else {
      let shift : Nat64 = Nat64.fromNat(8 * (7 - (i - tagBytes.size())));
      Nat8.fromNat(Nat64.toNat((SEED >> shift) & 0xff))
    }
  });
  let digest = Blob.toArray(Sha256.fromBlob(#sha256, Blob.fromArray(joined)));
  var w : Nat64 = 0;
  var i = 0;
  while (i < 8) {
    w := (w << 8) | Nat64.fromNat(Nat8.toNat(digest[i]));
    i += 1;
  };
  w;
};

func smNext() : Nat64 {
  smState := smState +% 0x9E3779B97F4A7C15;
  var z = smState;
  z := (z ^ (z >> 30)) *% 0xBF58476D1CE4E5B9;
  z := (z ^ (z >> 27)) *% 0x94D049BB133111EB;
  z ^ (z >> 31);
};

func raw512() : Nat {
  var n : Nat = 0;
  var j = 0;
  while (j < 8) {
    n := n * 0x10000000000000000 + Nat64.toNat(smNext());
    j += 1;
  };
  n;
};

// ---- transcript fold ----
let FOLD_M : Nat = 2 ** 255 - 19;
let FOLD_B : Nat = 2 ** 128 + 51;
let INV_NONE : Nat = 7777777777777777777;

var foldAcc : Nat = 0;
func foldPut(x : Nat) { foldAcc := (foldAcc * FOLD_B + x) % FOLD_M };

func hexDigit(d : Nat) : Char {
  if (d < 10) { Char.fromNat32(Nat32.fromNat(48 + d)) } else {
    Char.fromNat32(Nat32.fromNat(87 + d))
  };
};

func toHex(n : Nat) : Text {
  if (n == 0) { return "0" };
  var x = n;
  var out = "";
  while (x > 0) {
    out := Text.fromChar(hexDigit(x % 16)) # out;
    x := x / 16;
  };
  out;
};

// ---- edges ----
func edgesOf(m : Nat) : [Nat] { [0, 1, 2, m - 1, m, m + 1, 2 * m - 1] };

// ---- class runner ----
func runClass(tag : Text, n : Nat, drawB : Bool, m : Nat, op : (Nat, Nat) -> Nat) {
  smState := classSeed(tag);
  foldAcc := 0;
  let ed = edgesOf(m);
  var i = 0;
  while (i < n) {
    var a = raw512();
    var b : Nat = 0;
    if (drawB) { b := raw512() };
    if (i % 17 == 0) { a := ed[(i / 17) % ed.size()] };
    if (drawB and i % 19 == 0) { b := ed[(i / 19) % ed.size()] };
    foldPut(op(a, b));
    i += 1;
  };
  Debug.print("CLASS " # tag # " N=" # Nat.toText(n) # " DIGEST=" # toHex(foldAcc));
};

// ---- committed Ns (divided by DIV for calibration; printed N is the divided one) ----
let N_BIG = 1_000_000 / DIV;
let N_INV = 100_000 / DIV;
let N_RT = 500_000 / DIV;

// fp1.* — L1 reference Fp.mo
runClass("fp1.add", N_BIG, true, Fp.P, func(a, b) { Fp.add(a, b) });
runClass("fp1.sub", N_BIG, true, Fp.P, func(a, b) { Fp.sub(a, b) });
runClass("fp1.mul", N_BIG, true, Fp.P, func(a, b) { Fp.mul(a, b) });
runClass("fp1.sqr", N_BIG, false, Fp.P, func(a, _b) { Fp.sqr(a) });
runClass("fp1.inv", N_INV, false, Fp.P, func(a, _b) {
  switch (Fp.invOpt(a)) { case (?v) v; case null INV_NONE };
});

// fpm.* — L2 Montgomery FpMont.mo
runClass("fpm.add", N_BIG, true, FpM.P, func(a, b) { FpM.add(a, b) });
runClass("fpm.sub", N_BIG, true, FpM.P, func(a, b) { FpM.sub(a, b) });
runClass("fpm.mul", N_BIG, true, FpM.P, func(a, b) { FpM.mul(a, b) });
runClass("fpm.sqr", N_BIG, false, FpM.P, func(a, _b) { FpM.sqr(a) });
runClass("fpm.inv", N_INV, false, FpM.P, func(a, _b) {
  switch (FpM.invOpt(a)) { case (?v) v; case null INV_NONE };
});
runClass("fpm.roundtrip", N_RT, false, FpM.P, func(a, _b) {
  FpM.montMul(FpM.toMont(a), 1);
});

// fr.* — Fr.mo
runClass("fr.add", N_BIG, true, Fr.P, func(a, b) { Fr.add(a, b) });
runClass("fr.sub", N_BIG, true, Fr.P, func(a, b) { Fr.sub(a, b) });
runClass("fr.mul", N_BIG, true, Fr.P, func(a, b) { Fr.mul(a, b) });
runClass("fr.sqr", N_BIG, false, Fr.P, func(a, _b) { Fr.sqr(a) });
runClass("fr.inv", N_INV, false, Fr.P, func(a, _b) {
  switch (Fr.invOpt(a)) { case (?v) v; case null INV_NONE };
});

Debug.print("SEED " # Nat64.toText(SEED));
