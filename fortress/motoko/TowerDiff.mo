/// Motoko side of the tower-layer differential (Fp2/Fp6/Fp12, Frobenius, cyclotomic).
///
/// Implements the tower draw spec (fortress/src/lib.rs) independently and computes every
/// class through the PRODUCTION modules: `t*` through L1 `Tower.mo`, `tm*`/`pfe.*` through
/// L2 `TowerMont.mo`/`PairingFinalExp.mo` (the final-exponentiation path the verifier runs).
/// Line format and comparison as in ArithDiff.mo.
///
/// Run (staged next to src/groth16 modules by scripts/fortress-arith.sh):
///   moc -r --package core <core> --package sha2 <sha2> TowerDiff.mo

import Blob "mo:core/Blob";
import Array "mo:core/Array";
import Char "mo:core/Char";
import Debug "mo:core/Debug";
import Nat "mo:core/Nat";
import Nat8 "mo:core/Nat8";
import Nat32 "mo:core/Nat32";
import Nat64 "mo:core/Nat64";
import Text "mo:core/Text";
import Sha256 "mo:sha2/Sha256";
import Fp "Fp";
import T "Tower";
import TM "TowerMont";
import PFE "PairingFinalExp";

let SEED : Nat64 = 20260721;
let DIV : Nat = 1;

// ---- shared-stream primitives (same spec, independent implementation) ----
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
  while (x > 0) { out := Text.fromChar(hexDigit(x % 16)) # out; x := x / 16 };
  out;
};

// ---- tower draws ----
let EDGE_CANON : [Nat] = [0, 1, 2, Fp.P - 1];
var elemCounter : Nat = 0;

func drawCoeffs(k : Nat) : [Nat] {
  let e = elemCounter;
  let drawn = Array.tabulate<Nat>(k, func(_j : Nat) : Nat { raw512() % Fp.P });
  let out = if (e % 17 == 0) {
    Array.tabulate<Nat>(k, func(j : Nat) : Nat { EDGE_CANON[(e / 17 + j) % 4] });
  } else { drawn };
  elemCounter += 1;
  out;
};

func toFp2(c : [Nat]) : T.Fp2 { { c0 = c[0]; c1 = c[1] } };
func toFp6(c : [Nat]) : T.Fp6 {
  {
    c0 = { c0 = c[0]; c1 = c[1] };
    c1 = { c0 = c[2]; c1 = c[3] };
    c2 = { c0 = c[4]; c1 = c[5] };
  };
};
func toFp12(c : [Nat]) : T.Fp12 {
  {
    c0 = toFp6(Array.tabulate<Nat>(6, func(j : Nat) : Nat { c[j] }));
    c1 = toFp6(Array.tabulate<Nat>(6, func(j : Nat) : Nat { c[6 + j] }));
  };
};

func fold2(x : T.Fp2) { foldPut(x.c0); foldPut(x.c1) };
func fold6(x : T.Fp6) { fold2(x.c0); fold2(x.c1); fold2(x.c2) };
func fold12(x : T.Fp12) { fold6(x.c0); fold6(x.c1) };

func startClass(tag : Text) {
  smState := classSeed(tag);
  foldAcc := 0;
  elemCounter := 0;
};
func endClass(tag : Text, n : Nat) {
  Debug.print("CLASS " # tag # " N=" # Nat.toText(n) # " DIGEST=" # toHex(foldAcc));
};

func nOf(base : Nat) : Nat { let v = base / DIV; if (v == 0) { 1 } else { v } };

// ---- L1 Tower.mo classes ----
do {
  let n = nOf(100_000);
  startClass("t2.mul");
  var i = 0;
  while (i < n) {
    let a = toFp2(drawCoeffs(2));
    let b = toFp2(drawCoeffs(2));
    fold2(T.fp2Mul(a, b));
    i += 1;
  };
  endClass("t2.mul", n);
};
do {
  let n = nOf(100_000);
  startClass("t2.sqr");
  var i = 0;
  while (i < n) { fold2(T.fp2Sqr(toFp2(drawCoeffs(2)))); i += 1 };
  endClass("t2.sqr", n);
};
do {
  let n = nOf(20_000);
  startClass("t2.inv");
  var i = 0;
  while (i < n) {
    switch (T.fp2InvOpt(toFp2(drawCoeffs(2)))) {
      case (?z) fold2(z);
      case null foldPut(INV_NONE);
    };
    i += 1;
  };
  endClass("t2.inv", n);
};
do {
  let n = nOf(100_000);
  startClass("t2.nonres");
  var i = 0;
  while (i < n) { fold2(T.fp2MulByNonresidue(toFp2(drawCoeffs(2)))); i += 1 };
  endClass("t2.nonres", n);
};
do {
  let n = nOf(100_000);
  startClass("t2.conj");
  var i = 0;
  while (i < n) { fold2(T.fp2Conj(toFp2(drawCoeffs(2)))); i += 1 };
  endClass("t2.conj", n);
};
do {
  let n = nOf(50_000);
  startClass("t6.mul");
  var i = 0;
  while (i < n) {
    let a = toFp6(drawCoeffs(6));
    let b = toFp6(drawCoeffs(6));
    fold6(T.fp6Mul(a, b));
    i += 1;
  };
  endClass("t6.mul", n);
};
do {
  let n = nOf(10_000);
  startClass("t6.inv");
  var i = 0;
  while (i < n) {
    switch (T.fp6InvOpt(toFp6(drawCoeffs(6)))) {
      case (?z) fold6(z);
      case null foldPut(INV_NONE);
    };
    i += 1;
  };
  endClass("t6.inv", n);
};
do {
  let n = nOf(50_000);
  startClass("t6.mulv");
  var i = 0;
  while (i < n) { fold6(T.fp6MulByV(toFp6(drawCoeffs(6)))); i += 1 };
  endClass("t6.mulv", n);
};
do {
  let n = nOf(20_000);
  startClass("t12.mul");
  var i = 0;
  while (i < n) {
    let a = toFp12(drawCoeffs(12));
    let b = toFp12(drawCoeffs(12));
    fold12(T.fp12Mul(a, b));
    i += 1;
  };
  endClass("t12.mul", n);
};
do {
  let n = nOf(20_000);
  startClass("t12.sqr");
  var i = 0;
  while (i < n) { fold12(T.fp12Sqr(toFp12(drawCoeffs(12)))); i += 1 };
  endClass("t12.sqr", n);
};
do {
  let n = nOf(5_000);
  startClass("t12.inv");
  var i = 0;
  while (i < n) {
    switch (T.fp12InvOpt(toFp12(drawCoeffs(12)))) {
      case (?z) fold12(z);
      case null foldPut(INV_NONE);
    };
    i += 1;
  };
  endClass("t12.inv", n);
};
do {
  let n = nOf(20_000);
  startClass("t12.conj");
  var i = 0;
  while (i < n) { fold12(T.fp12Conj(toFp12(drawCoeffs(12)))); i += 1 };
  endClass("t12.conj", n);
};
// L1 literal Frobenius x^(p^i); power cycles 1..=11 by case order.
do {
  let n = nOf(50);
  startClass("t12.frob");
  var i = 0;
  while (i < n) {
    let a = toFp12(drawCoeffs(12));
    fold12(T.fp12Frobenius(a, (i % 11) + 1));
    i += 1;
  };
  endClass("t12.frob", n);
};

// ---- L2 TowerMont.mo / PairingFinalExp.mo classes ----
do {
  let n = nOf(100_000);
  startClass("tm2.mul");
  var i = 0;
  while (i < n) {
    let a = TM.toM2(toFp2(drawCoeffs(2)));
    let b = TM.toM2(toFp2(drawCoeffs(2)));
    fold2(TM.fromM2(TM.fp2Mul(a, b)));
    i += 1;
  };
  endClass("tm2.mul", n);
};
do {
  let n = nOf(100_000);
  startClass("tm2.sqrfast");
  var i = 0;
  while (i < n) {
    fold2(TM.fromM2(TM.fp2SqrFast(TM.toM2(toFp2(drawCoeffs(2))))));
    i += 1;
  };
  endClass("tm2.sqrfast", n);
};
do {
  let n = nOf(20_000);
  startClass("tm2.inv");
  var i = 0;
  while (i < n) {
    let a = toFp2(drawCoeffs(2));
    if (a.c0 == 0 and a.c1 == 0) { foldPut(INV_NONE) } else {
      fold2(TM.fromM2(TM.fp2Inv(TM.toM2(a))));
    };
    i += 1;
  };
  endClass("tm2.inv", n);
};
do {
  let n = nOf(20_000);
  startClass("tm12.mul");
  var i = 0;
  while (i < n) {
    let a = TM.toM12(toFp12(drawCoeffs(12)));
    let b = TM.toM12(toFp12(drawCoeffs(12)));
    fold12(TM.fromM12(TM.fp12Mul(a, b)));
    i += 1;
  };
  endClass("tm12.mul", n);
};
do {
  let n = nOf(20_000);
  startClass("tm12.sqrfast");
  var i = 0;
  while (i < n) {
    fold12(TM.fromM12(TM.fp12SqrFast(TM.toM12(toFp12(drawCoeffs(12))))));
    i += 1;
  };
  endClass("tm12.sqrfast", n);
};
do {
  let n = nOf(5_000);
  startClass("tm12.inv");
  var i = 0;
  while (i < n) {
    let aC = toFp12(drawCoeffs(12));
    let z = TM.toM12(aC);
    if (TM.fp12IsZero(z)) { foldPut(INV_NONE) } else {
      fold12(TM.fromM12(TM.fp12Inv(z)));
    };
    i += 1;
  };
  endClass("tm12.inv", n);
};
do {
  let n = nOf(20_000);
  startClass("tm12.by014");
  var i = 0;
  while (i < n) {
    let a = TM.toM12(toFp12(drawCoeffs(12)));
    let s = drawCoeffs(6);
    let b0 = TM.toM2({ c0 = s[0]; c1 = s[1] });
    let b1 = TM.toM2({ c0 = s[2]; c1 = s[3] });
    let b4 = TM.toM2({ c0 = s[4]; c1 = s[5] });
    fold12(TM.fromM12(TM.fp12MulBy014(a, b0, b1, b4)));
    i += 1;
  };
  endClass("tm12.by014", n);
};
// pfe.frob: fast table-based Frobenius; power cycles 0..=11 by case order.
do {
  let n = nOf(20_000);
  startClass("pfe.frob");
  var i = 0;
  while (i < n) {
    let a = TM.toM12(toFp12(drawCoeffs(12)));
    fold12(TM.fromM12(PFE.fp12Frobenius(a, i % 12)));
    i += 1;
  };
  endClass("pfe.frob", n);
};
// pfe.cycsqr / pfe.expbyx: inputs mapped into the cyclotomic subgroup by the production
// easy part.
do {
  let n = nOf(5_000);
  startClass("pfe.cycsqr");
  var i = 0;
  while (i < n) {
    let z = PFE.easyPart(TM.toM12(toFp12(drawCoeffs(12))));
    fold12(TM.fromM12(PFE.cyclotomicSquare(z)));
    i += 1;
  };
  endClass("pfe.cycsqr", n);
};
do {
  let n = nOf(100);
  startClass("pfe.expbyx");
  var i = 0;
  while (i < n) {
    let z = PFE.easyPart(TM.toM12(toFp12(drawCoeffs(12))));
    fold12(TM.fromM12(PFE.expByX(z)));
    i += 1;
  };
  endClass("pfe.expbyx", n);
};

Debug.print("SEED " # Nat64.toText(SEED));
