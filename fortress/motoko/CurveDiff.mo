/// Motoko side of the curve-layer differential (G1/G2 group ops, subgroup, on-curve, MSM).
///
/// Implements the curve draw spec (fortress/src/curvepair.rs doc-comment) independently:
/// point pools from shared scalar streams, chained add/double walks, literal-integer
/// scalar mults, deterministic off-subgroup on-curve points, and the vk_x MSM — computed
/// through the PRODUCTION layers: `c1.chain`/`c1.mull1`/`c*.subgrpl1` through L1
/// `Curve.mo` (with an in-program L2 cross-assert on the chain), everything else through
/// L2 `CurveJac.mo`. Line format as in ArithDiff.mo.
///
/// Run (staged next to src/groth16 modules by scripts/fortress-arith.sh):
///   moc -r --package core <core> --package sha2 <sha2> CurveDiff.mo

import Blob "mo:core/Blob";
import Array "mo:core/Array";
import Char "mo:core/Char";
import Debug "mo:core/Debug";
import Nat "mo:core/Nat";
import Nat8 "mo:core/Nat8";
import Nat32 "mo:core/Nat32";
import Nat64 "mo:core/Nat64";
import Runtime "mo:core/Runtime";
import Text "mo:core/Text";
import Sha256 "mo:sha2/Sha256";
import Fp "Fp";
import C "Curve";
import CJ "CurveJac";
import T "Tower";
import Dec2 "DecodeG2";

let SEED : Nat64 = 20260721;
let DIV : Nat = 1;

// ---- shared-stream primitives ----
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
  while (i < 8) { w := (w << 8) | Nat64.fromNat(Nat8.toNat(digest[i])); i += 1 };
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
  while (j < 8) { n := n * 0x10000000000000000 + Nat64.toNat(smNext()); j += 1 };
  n;
};

let FOLD_M : Nat = 2 ** 255 - 19;
let FOLD_B : Nat = 2 ** 128 + 51;
let PT_INF : Nat = 12648430;

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

func startClass(tag : Text) { smState := classSeed(tag); foldAcc := 0 };
func endClass(tag : Text, n : Nat) {
  Debug.print("CLASS " # tag # " N=" # Nat.toText(n) # " DIGEST=" # toHex(foldAcc));
};
func nOf(base : Nat) : Nat { let v = base / DIV; if (v == 0) { 1 } else { v } };

func foldG1(p : C.G1) {
  switch (p) {
    case (#inf) foldPut(PT_INF);
    case (#pt(q)) { foldPut(q.x); foldPut(q.y) };
  };
};
func foldG2(p : C.G2) {
  switch (p) {
    case (#inf) foldPut(PT_INF);
    case (#pt(q)) { foldPut(q.x.c0); foldPut(q.x.c1); foldPut(q.y.c0); foldPut(q.y.c1) };
  };
};

// The standard G2 generator (no constant in Curve.mo; this literal is the same one
// verifier-lab/CurveJacTest.mo pins and cross_oracle verifies against blst's generator).
let g2Gen : C.G2 = #pt({
  x = {
    c0 = 0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8;
    c1 = 0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e;
  };
  y = {
    c0 = 0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801;
    c1 = 0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be;
  };
});

// ---- pools (shared scalar streams; scalar mult by the literal unreduced integer) ----
let poolG1 : [C.G1] = do {
  smState := classSeed("pool.g1");
  Array.tabulate<C.G1>(64, func(_k : Nat) : C.G1 {
    CJ.g1ToAffine(CJ.g1Mul(CJ.g1FromAffine(C.g1Gen), raw512()));
  });
};
let poolG2 : [C.G2] = do {
  smState := classSeed("pool.g2");
  Array.tabulate<C.G2>(64, func(_k : Nat) : C.G2 {
    CJ.g2ToAffine(CJ.g2Mul(CJ.g2FromAffine(g2Gen), raw512()));
  });
};

// ---- chain classes ----
// c1.chain: L1 affine walk with an in-program L2 cross-assert every 500 cases.
do {
  let n = nOf(10_000);
  startClass("c1.chain");
  var cur = poolG1[0];
  var curJ = CJ.g1FromAffine(poolG1[0]);
  var i = 1;
  while (i <= n) {
    let w = smNext();
    if (w & 1 == 0) {
      let q = poolG1[Nat64.toNat((w >> 1) % 64)];
      cur := C.g1Add(cur, q);
      curJ := CJ.g1Add(curJ, CJ.g1FromAffine(q));
    } else {
      cur := C.g1Dbl(cur);
      curJ := CJ.g1Dbl(curJ);
    };
    if (i % 500 == 0) {
      if (not C.g1Eq(cur, CJ.g1ToAffine(curJ))) {
        Runtime.trap("c1.chain: L1/L2 divergence at case " # Nat.toText(i));
      };
    };
    if (i % 1_000 == 0 or i == n) { foldG1(cur) };
    i += 1;
  };
  endClass("c1.chain", n);
};
// c1.chainfast: L2 Jacobian walk.
do {
  let n = nOf(200_000);
  startClass("c1.chainfast");
  var cur = CJ.g1FromAffine(poolG1[0]);
  var i = 1;
  while (i <= n) {
    let w = smNext();
    if (w & 1 == 0) {
      cur := CJ.g1Add(cur, CJ.g1FromAffine(poolG1[Nat64.toNat((w >> 1) % 64)]));
    } else {
      cur := CJ.g1Dbl(cur);
    };
    if (i % 10_000 == 0 or i == n) { foldG1(CJ.g1ToAffine(cur)) };
    i += 1;
  };
  endClass("c1.chainfast", n);
};
do {
  let n = nOf(5_000);
  startClass("c2.chain");
  var cur = poolG2[0];
  var curJ = CJ.g2FromAffine(poolG2[0]);
  var i = 1;
  while (i <= n) {
    let w = smNext();
    if (w & 1 == 0) {
      let q = poolG2[Nat64.toNat((w >> 1) % 64)];
      cur := C.g2Add(cur, q);
      curJ := CJ.g2Add(curJ, CJ.g2FromAffine(q));
    } else {
      cur := C.g2Dbl(cur);
      curJ := CJ.g2Dbl(curJ);
    };
    if (i % 500 == 0) {
      if (not C.g2Eq(cur, CJ.g2ToAffine(curJ))) {
        Runtime.trap("c2.chain: L1/L2 divergence at case " # Nat.toText(i));
      };
    };
    if (i % 500 == 0 or i == n) { foldG2(cur) };
    i += 1;
  };
  endClass("c2.chain", n);
};
do {
  let n = nOf(100_000);
  startClass("c2.chainfast");
  var cur = CJ.g2FromAffine(poolG2[0]);
  var i = 1;
  while (i <= n) {
    let w = smNext();
    if (w & 1 == 0) {
      cur := CJ.g2Add(cur, CJ.g2FromAffine(poolG2[Nat64.toNat((w >> 1) % 64)]));
    } else {
      cur := CJ.g2Dbl(cur);
    };
    if (i % 5_000 == 0 or i == n) { foldG2(CJ.g2ToAffine(cur)) };
    i += 1;
  };
  endClass("c2.chainfast", n);
};

// ---- scalar-mul classes ----
do {
  let n = nOf(2_000);
  startClass("c1.mul");
  var i = 0;
  while (i < n) {
    let k = raw512();
    let idx = Nat64.toNat(smNext() % 64);
    foldG1(CJ.g1ToAffine(CJ.g1Mul(CJ.g1FromAffine(poolG1[idx]), k)));
    i += 1;
  };
  endClass("c1.mul", n);
};
do {
  let n = nOf(100);
  startClass("c1.mull1");
  var i = 0;
  while (i < n) {
    let k = raw512();
    let idx = Nat64.toNat(smNext() % 64);
    foldG1(C.g1Mul(poolG1[idx], k));
    i += 1;
  };
  endClass("c1.mull1", n);
};
do {
  let n = nOf(1_000);
  startClass("c2.mul");
  var i = 0;
  while (i < n) {
    let k = raw512();
    let idx = Nat64.toNat(smNext() % 64);
    foldG2(CJ.g2ToAffine(CJ.g2Mul(CJ.g2FromAffine(poolG2[idx]), k)));
    i += 1;
  };
  endClass("c2.mul", n);
};

// ---- deterministic off-subgroup on-curve points ----
func offSubgroupG1() : C.G1 {
  loop {
    let x = raw512() % Fp.P;
    let rhs = Fp.add(Fp.mul(Fp.mul(x, x), x), 4);
    switch (Fp.sqrtOpt(rhs)) {
      case (?cand) {
        let y = if (Fp.isLargerRoot(cand)) { cand } else { Fp.sub(0, cand) };
        return #pt({ x; y });
      };
      case null {};
    };
  };
};
func offSubgroupG2() : C.G2 {
  loop {
    let c0 = raw512() % Fp.P;
    let c1 = raw512() % Fp.P;
    let x : T.Fp2 = { c0; c1 };
    let rhs = T.fp2Add(T.fp2Mul(T.fp2Mul(x, x), x), { c0 = 4; c1 = 4 });
    switch (Dec2.sqrtFp2Opt(rhs)) {
      case (?cand) {
        let y = if (Dec2.isLargerRootFp2(cand)) { cand } else { T.fp2Neg(cand) };
        return #pt({ x; y });
      };
      case null {};
    };
  };
};

// ---- subgroup classes ----
do {
  let n = nOf(1_000);
  startClass("c1.subgrp");
  var i = 0;
  while (i < n) {
    let verdict = if (i % 2 == 0) {
      CJ.g1IsInSubgroup(poolG1[Nat64.toNat(smNext() % 64)]);
    } else { CJ.g1IsInSubgroup(offSubgroupG1()) };
    foldPut(if (verdict) 1 else 0);
    i += 1;
  };
  endClass("c1.subgrp", n);
};
do {
  let n = nOf(100);
  startClass("c1.subgrpl1");
  var i = 0;
  while (i < n) {
    let verdict = if (i % 2 == 0) {
      C.g1IsInSubgroup(poolG1[Nat64.toNat(smNext() % 64)]);
    } else { C.g1IsInSubgroup(offSubgroupG1()) };
    foldPut(if (verdict) 1 else 0);
    i += 1;
  };
  endClass("c1.subgrpl1", n);
};
do {
  let n = nOf(500);
  startClass("c2.subgrp");
  var i = 0;
  while (i < n) {
    let verdict = if (i % 2 == 0) {
      CJ.g2IsInSubgroup(poolG2[Nat64.toNat(smNext() % 64)]);
    } else { CJ.g2IsInSubgroup(offSubgroupG2()) };
    foldPut(if (verdict) 1 else 0);
    i += 1;
  };
  endClass("c2.subgrp", n);
};
do {
  let n = nOf(50);
  startClass("c2.subgrpl1");
  var i = 0;
  while (i < n) {
    let verdict = if (i % 2 == 0) {
      C.g2IsInSubgroup(poolG2[Nat64.toNat(smNext() % 64)]);
    } else { C.g2IsInSubgroup(offSubgroupG2()) };
    foldPut(if (verdict) 1 else 0);
    i += 1;
  };
  endClass("c2.subgrpl1", n);
};

// ---- on-curve classes ----
do {
  let n = nOf(100_000);
  startClass("c1.oncurve");
  var i = 0;
  while (i < n) {
    let verdict = if (i % 10 == 0) {
      C.g1IsOnCurve(poolG1[Nat64.toNat(smNext() % 64)]);
    } else {
      let x = raw512() % Fp.P;
      let y = raw512() % Fp.P;
      C.g1IsOnCurve(#pt({ x; y }));
    };
    foldPut(if (verdict) 1 else 0);
    i += 1;
  };
  endClass("c1.oncurve", n);
};
do {
  let n = nOf(50_000);
  startClass("c2.oncurve");
  var i = 0;
  while (i < n) {
    let verdict = if (i % 10 == 0) {
      C.g2IsOnCurve(poolG2[Nat64.toNat(smNext() % 64)]);
    } else {
      let x : T.Fp2 = { c0 = raw512() % Fp.P; c1 = raw512() % Fp.P };
      let y : T.Fp2 = { c0 = raw512() % Fp.P; c1 = raw512() % Fp.P };
      C.g2IsOnCurve(#pt({ x; y }));
    };
    foldPut(if (verdict) 1 else 0);
    i += 1;
  };
  endClass("c2.oncurve", n);
};

// ---- vk_x MSM ----
do {
  let n = nOf(500);
  startClass("c1.vkx");
  var i = 0;
  while (i < n) {
    let k = 1 + Nat64.toNat(smNext() % 8);
    let ic = Array.tabulate<C.G1>(k + 1, func(_j : Nat) : C.G1 {
      poolG1[Nat64.toNat(smNext() % 64)];
    });
    let inputs = Array.tabulate<Nat>(k, func(_j : Nat) : Nat { raw512() % C.R });
    foldG1(CJ.vkX(ic, inputs));
    i += 1;
  };
  endClass("c1.vkx", n);
};

Debug.print("SEED " # Nat64.toText(SEED));
