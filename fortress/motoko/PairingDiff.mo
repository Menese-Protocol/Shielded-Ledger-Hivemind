/// Motoko side of the pairing and wire-decode differentials.
///
/// Pairing classes run through the PRODUCTION L2 layers (`PairingProjective` — the
/// prepared path the verifier uses — plus the affine `PairingMont` variant and the NAF
/// final exponentiation in `PairingFinalExp`); the interleaved multi-Miller runs through
/// `Groth16Multi.multiMillerLoopPrepared`. Decode classes run the PRODUCTION wire
/// decoders (`Decode.decodeG1`, `DecodeG2.decodeG2`, `Groth16Wire.parseInputs`) against
/// the blst oracle (fortress/src/curvepair.rs). Specs in that file's doc-comment.
///
/// Run (staged next to src/groth16 modules by scripts/fortress-arith.sh):
///   moc -r --package core <core> --package sha2 <sha2> PairingDiff.mo

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
import C "Curve";
import CJ "CurveJac";
import T "Tower";
import TM "TowerMont";
import PP "PairingProjective";
import PM "PairingMont";
import PFE "PairingFinalExp";
import GM "Groth16Multi";
import Dec "Decode";
import Dec2 "DecodeG2";
import W "Groth16Wire";

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

func fold2(x : T.Fp2) { foldPut(x.c0); foldPut(x.c1) };
func fold6(x : T.Fp6) { fold2(x.c0); fold2(x.c1); fold2(x.c2) };
func fold12(x : T.Fp12) { fold6(x.c0); fold6(x.c1) };

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

// ---- pools (identical spec to CurveDiff.mo) ----
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

// ---- pairing classes ----
do {
  let n = nOf(500);
  startClass("pm.miller");
  var i = 0;
  while (i < n) {
    let a = poolG1[Nat64.toNat(smNext() % 64)];
    let b = poolG2[Nat64.toNat(smNext() % 64)];
    fold12(TM.fromM12(PP.millerLoop(a, b)));
    i += 1;
  };
  endClass("pm.miller", n);
};
// PM's affine Miller loop is a final-exp-equivalent VARIANT of the projective one
// (probed: raw Fp12 differs, value after final exponentiation identical) — so this
// class compares at the pairing level, where the value is well-defined.
do {
  let n = nOf(100);
  startClass("pm.millermont");
  var i = 0;
  while (i < n) {
    let a = poolG1[Nat64.toNat(smNext() % 64)];
    let b = poolG2[Nat64.toNat(smNext() % 64)];
    fold12(TM.fromM12(PFE.finalExponentiate(PM.millerLoop(a, b))));
    i += 1;
  };
  endClass("pm.millermont", n);
};
do {
  let n = nOf(200);
  startClass("pfe.finalexp");
  var i = 0;
  while (i < n) {
    let a = poolG1[Nat64.toNat(smNext() % 64)];
    let b = poolG2[Nat64.toNat(smNext() % 64)];
    fold12(TM.fromM12(PFE.finalExponentiate(PP.millerLoop(a, b))));
    i += 1;
  };
  endClass("pfe.finalexp", n);
};
do {
  let n = nOf(300);
  startClass("pm.pair");
  var i = 0;
  while (i < n) {
    let a = poolG1[Nat64.toNat(smNext() % 64)];
    let b = poolG2[Nat64.toNat(smNext() % 64)];
    fold12(TM.fromM12(PFE.finalExponentiate(PP.millerLoop(a, b))));
    i += 1;
  };
  endClass("pm.pair", n);
};
do {
  let n = nOf(200);
  startClass("gm.multi");
  var i = 0;
  while (i < n) {
    let k = 2 + Nat64.toNat(smNext() % 3);
    let aa = Array.tabulate<C.G1>(k, func(_j : Nat) : C.G1 {
      poolG1[Nat64.toNat(smNext() % 64)];
    });
    let bb = Array.tabulate<C.G2>(k, func(_j : Nat) : C.G2 {
      poolG2[Nat64.toNat(smNext() % 64)];
    });
    let pairs = Array.tabulate<(C.G1, PP.G2Prepared)>(k, func(j : Nat) : (C.G1, PP.G2Prepared) {
      (aa[j], PP.prepareG2(bb[j]));
    });
    fold12(TM.fromM12(GM.multiMillerLoopPrepared(pairs)));
    i += 1;
  };
  endClass("gm.multi", n);
};

// ---- decode classes ----
func natToBE(x : Nat, len : Nat) : [Nat8] {
  var v = x;
  let out = Array.tabulate<Nat8>(len, func(_i : Nat) : Nat8 { 0 });
  let outv = Array.toVarArray<Nat8>(out);
  var i = len;
  while (i > 0) {
    i -= 1;
    outv[i] := Nat8.fromNat(v % 256);
    v := v / 256;
  };
  Array.fromVarArray<Nat8>(outv);
};

func compressG1(p : C.G1) : [Nat8] {
  switch (p) {
    case (#inf) {
      Array.tabulate<Nat8>(48, func(i : Nat) : Nat8 { if (i == 0) { 0xc0 } else { 0 } });
    };
    case (#pt(q)) {
      let xb = natToBE(q.x, 48);
      let sort = Fp.isLargerRoot(q.y);
      Array.tabulate<Nat8>(48, func(i : Nat) : Nat8 {
        if (i == 0) {
          var b0 = Nat8.toNat(xb[0]) + 128; // 0x80 compression
          if (sort) { b0 += 32 };            // 0x20 sort
          Nat8.fromNat(b0);
        } else { xb[i] };
      });
    };
  };
};

func compressG2(p : C.G2) : [Nat8] {
  switch (p) {
    case (#inf) {
      Array.tabulate<Nat8>(96, func(i : Nat) : Nat8 { if (i == 0) { 0xc0 } else { 0 } });
    };
    case (#pt(q)) {
      let c1b = natToBE(q.x.c1, 48);
      let c0b = natToBE(q.x.c0, 48);
      let sort = Dec2.isLargerRootFp2(q.y);
      Array.tabulate<Nat8>(96, func(i : Nat) : Nat8 {
        if (i == 0) {
          var b0 = Nat8.toNat(c1b[0]) + 128;
          if (sort) { b0 += 32 };
          Nat8.fromNat(b0);
        } else if (i < 48) { c1b[i] } else { c0b[i - 48] };
      });
    };
  };
};

func randBytes(words : Nat) : [Nat8] {
  let ws = Array.tabulate<Nat64>(words, func(_i : Nat) : Nat64 { smNext() });
  Array.tabulate<Nat8>(words * 8, func(i : Nat) : Nat8 {
    let w = ws[i / 8];
    let shift : Nat64 = Nat64.fromNat(8 * (7 - (i % 8)));
    Nat8.fromNat(Nat64.toNat((w >> shift) & 0xff));
  });
};

func setB0(bytes : [Nat8], f : Nat8 -> Nat8) : [Nat8] {
  Array.tabulate<Nat8>(bytes.size(), func(i : Nat) : Nat8 {
    if (i == 0) { f(bytes[0]) } else { bytes[i] };
  });
};

do {
  let n = nOf(20_000);
  startClass("dec.g1");
  var i = 0;
  while (i < n) {
    let v = smNext() % 8;
    let bytes : [Nat8] = if (v == 0 or v == 1) {
      compressG1(poolG1[Nat64.toNat(smNext() % 64)]);
    } else if (v == 2) {
      compressG1(#inf);
    } else if (v == 3) {
      setB0(compressG1(poolG1[Nat64.toNat(smNext() % 64)]), func(b) { b ^ 0x20 });
    } else if (v == 4) {
      setB0(compressG1(poolG1[Nat64.toNat(smNext() % 64)]), func(b) { b & 0x7f });
    } else if (v == 5) {
      let xb = natToBE(Fp.P + Nat64.toNat(smNext() % 4), 48);
      setB0(xb, func(b) { b | 0x80 });
    } else {
      setB0(randBytes(6), func(b) { (b | 0x80) & 0xbf });
    };
    switch (Dec.decodeG1(bytes)) {
      case (#err(_)) foldPut(0);
      case (#ok(#inf)) { foldPut(1); foldPut(PT_INF) };
      case (#ok(#pt(q))) { foldPut(1); foldPut(q.x); foldPut(q.y) };
    };
    i += 1;
  };
  endClass("dec.g1", n);
};

do {
  let n = nOf(5_000);
  startClass("dec.g2");
  var i = 0;
  while (i < n) {
    let v = smNext() % 8;
    let bytes : [Nat8] = if (v == 0 or v == 1) {
      compressG2(poolG2[Nat64.toNat(smNext() % 64)]);
    } else if (v == 2) {
      compressG2(#inf);
    } else if (v == 3) {
      setB0(compressG2(poolG2[Nat64.toNat(smNext() % 64)]), func(b) { b ^ 0x20 });
    } else if (v == 4) {
      setB0(compressG2(poolG2[Nat64.toNat(smNext() % 64)]), func(b) { b & 0x7f });
    } else if (v == 5) {
      // valid compress, then first 48 bytes replaced by BE(p + w%4) with 0x80 set
      let base = compressG2(poolG2[Nat64.toNat(smNext() % 64)]);
      let xb = natToBE(Fp.P + Nat64.toNat(smNext() % 4), 48);
      Array.tabulate<Nat8>(96, func(j : Nat) : Nat8 {
        if (j == 0) { xb[0] | 0x80 } else if (j < 48) { xb[j] } else { base[j] };
      });
    } else {
      setB0(randBytes(12), func(b) { (b | 0x80) & 0xbf });
    };
    switch (Dec2.decodeG2(bytes)) {
      case (#err(_)) foldPut(0);
      case (#ok(#inf)) { foldPut(1); foldPut(PT_INF) };
      case (#ok(#pt(q))) {
        foldPut(1);
        foldPut(q.x.c0); foldPut(q.x.c1); foldPut(q.y.c0); foldPut(q.y.c1);
      };
    };
    i += 1;
  };
  endClass("dec.g2", n);
};

do {
  let n = nOf(250_000);
  startClass("dec.frle");
  var i = 0;
  while (i < n) {
    let v = smNext() % 8;
    let value : Nat = if (v <= 4) {
      var x : Nat = 0;
      var j = 0;
      while (j < 4) { x := x * 0x10000000000000000 + Nat64.toNat(smNext()); j += 1 };
      x;
    } else if (v == 5) { C.R } else if (v == 6) { C.R - 1 } else { 2 ** 256 - 1 };
    // ark-serialize Vec<Fr> framing: u64 LE count (= 1), then the 32-byte LE element
    var tmp = value;
    let le = Array.tabulate<Nat8>(40, func(j : Nat) : Nat8 {
      if (j < 8) { if (j == 0) { 1 } else { 0 } } else {
        let b = Nat8.fromNat(tmp % 256);
        tmp := tmp / 256;
        b;
      };
    });
    switch (W.parseInputs(le)) {
      case (?vals) { foldPut(1); foldPut(vals[0]) };
      case null foldPut(0);
    };
    i += 1;
  };
  endClass("dec.frle", n);
};

Debug.print("SEED " # Nat64.toText(SEED));
