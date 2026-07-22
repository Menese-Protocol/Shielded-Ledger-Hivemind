/// §3 — Algebraic property tests (a DISTINCT detector class from §2's differential).
///
/// Where §2 compares each production op against an independent oracle value, §3 asserts the
/// ALGEBRAIC IDENTITIES those ops must satisfy — the identity itself is the oracle, so this
/// catches shared parsing/representation mistakes that value-comparison can miss. Everything
/// runs on the PRODUCTION L2/L3 layers (FpMont, TowerMont, PairingProjective/Mont/FinalExp,
/// CurveJac) — the exact code the verifier uses.
///
/// Committed tiers (THRESHOLDS §3): field 100,000 per family; curve 2,000 scalar-identity +
/// 50,000 point-arith; pairing bilinearity 30, additivity 30, degeneracy 10. Seeded,
/// deterministic; traps (RED) on the first violated identity.
///
/// Run: moc -r --package core <core> --package sha2 <sha2> Properties.mo

import Blob "mo:core/Blob";
import Array "mo:core/Array";
import Debug "mo:core/Debug";
import Nat "mo:core/Nat";
import Nat8 "mo:core/Nat8";
import Nat64 "mo:core/Nat64";
import Runtime "mo:core/Runtime";
import Text "mo:core/Text";
import Sha256 "mo:sha2/Sha256";
import Fp "Fp";
import FpM "FpMont";
import Fr "Fr";
import T "Tower";
import TM "TowerMont";
import C "Curve";
import CJ "CurveJac";
import PP "PairingProjective";
import PFE "PairingFinalExp";

let SEED : Nat64 = 20260722;
let SCALE : Nat = 1; // divides tiers for a fast calibration (SCALE>1); 1 = committed.

// ---- deterministic stream ----
var smState : Nat64 = 0;
func classSeed(tag : Text) : Nat64 {
  let tb = Blob.toArray(Text.encodeUtf8(tag));
  let joined = Array.tabulate<Nat8>(tb.size() + 8, func(i : Nat) : Nat8 {
    if (i < tb.size()) { tb[i] } else {
      let sh : Nat64 = Nat64.fromNat(8 * (7 - (i - tb.size())));
      Nat8.fromNat(Nat64.toNat((SEED >> sh) & 0xff))
    }
  });
  let d = Blob.toArray(Sha256.fromBlob(#sha256, Blob.fromArray(joined)));
  var w : Nat64 = 0; var i = 0;
  while (i < 8) { w := (w << 8) | Nat64.fromNat(Nat8.toNat(d[i])); i += 1 };
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
  var n : Nat = 0; var j = 0;
  while (j < 8) { n := n * 0x10000000000000000 + Nat64.toNat(smNext()); j += 1 };
  n;
};
func fpElem() : Nat { raw512() % Fp.P };
func frElem() : Nat { raw512() % Fr.P };
func fp2Elem() : T.Fp2 { { c0 = fpElem(); c1 = fpElem() } };
func fp12Elem() : T.Fp12 {
  { c0 = { c0 = fp2Elem(); c1 = fp2Elem(); c2 = fp2Elem() };
    c1 = { c0 = fp2Elem(); c1 = fp2Elem(); c2 = fp2Elem() } };
};
func nOf(base : Nat) : Nat { let v = base / SCALE; if (v == 0) { 1 } else { v } };
func check(cond : Bool, msg : Text) { if (not cond) { Runtime.trap("PROPERTY FAIL: " # msg) } };

let g2Gen : C.G2 = #pt({
  x = { c0 = 0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8;
        c1 = 0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e };
  y = { c0 = 0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801;
        c1 = 0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be };
});

// ============ FIELD IDENTITIES (production L2: FpMont + TowerMont) ============
// Fp family: commutativity, associativity, distributivity, a*a^-1=1, sqr=mul.
do {
  smState := classSeed("prop.fp");
  let n = nOf(100_000);
  var i = 0;
  while (i < n) {
    let a = fpElem(); let b = fpElem(); let c = fpElem();
    check(FpM.mul(a, b) == FpM.mul(b, a), "fp mul comm");
    check(FpM.add(a, b) == FpM.add(b, a), "fp add comm");
    check(FpM.mul(FpM.mul(a, b), c) == FpM.mul(a, FpM.mul(b, c)), "fp mul assoc");
    check(FpM.mul(a, FpM.add(b, c)) == FpM.add(FpM.mul(a, b), FpM.mul(a, c)), "fp distributivity");
    check(FpM.sqr(a) == FpM.mul(a, a), "fp sqr=mul");
    if (a != 0) { check(FpM.mul(a, FpM.inv(a)) == 1 % Fp.P, "fp a*a^-1=1") };
    i += 1;
  };
  Debug.print("PROP fp: " # Nat.toText(n) # " OK (comm/assoc/distributivity/sqr=mul/a*a^-1=1)");
};
// Fp2 family.
do {
  smState := classSeed("prop.fp2");
  let n = nOf(100_000);
  var i = 0;
  while (i < n) {
    let a = TM.toM2(fp2Elem()); let b = TM.toM2(fp2Elem()); let c = TM.toM2(fp2Elem());
    check(T.fp2Eq(TM.fromM2(TM.fp2Mul(a, b)), TM.fromM2(TM.fp2Mul(b, a))), "fp2 mul comm");
    check(T.fp2Eq(TM.fromM2(TM.fp2Mul(a, TM.fp2Add(b, c))),
                  TM.fromM2(TM.fp2Add(TM.fp2Mul(a, b), TM.fp2Mul(a, c)))), "fp2 distributivity");
    check(T.fp2Eq(TM.fromM2(TM.fp2SqrFast(a)), TM.fromM2(TM.fp2Mul(a, a))), "fp2 sqrfast=mul");
    let a0 = fp2Elem();
    if (not (a0.c0 == 0 and a0.c1 == 0)) {
      let am = TM.toM2(a0);
      check(T.fp2Eq(TM.fromM2(TM.fp2Mul(am, TM.fp2Inv(am))), TM.fromM2(TM.fp2OneM())), "fp2 a*a^-1=1");
    };
    i += 1;
  };
  Debug.print("PROP fp2: " # Nat.toText(n) # " OK (comm/distributivity/sqrfast=mul/a*a^-1=1)");
};
// Fp12 family + Frobenius order.
do {
  smState := classSeed("prop.fp12");
  let n = nOf(100_000);
  var i = 0;
  while (i < n) {
    let a = TM.toM12(fp12Elem()); let b = TM.toM12(fp12Elem()); let c = TM.toM12(fp12Elem());
    check(TM.fp12Eq(TM.fp12Mul(a, b), TM.fp12Mul(b, a)), "fp12 mul comm");
    check(TM.fp12Eq(TM.fp12Mul(a, TM.fp12Add(b, c)),
                    TM.fp12Add(TM.fp12Mul(a, b), TM.fp12Mul(a, c))), "fp12 distributivity");
    check(TM.fp12Eq(TM.fp12SqrFast(a), TM.fp12Mul(a, a)), "fp12 sqrfast=mul");
    let a0 = fp12Elem();
    if (not TM.fp12IsZero(TM.toM12(a0))) {
      let am = TM.toM12(a0);
      check(TM.fp12Eq(TM.fp12Mul(am, TM.fp12Inv(am)), TM.fp12OneM()), "fp12 a*a^-1=1");
    };
    // Frobenius order: applying the p-power map 12 times returns the element (frob^12 = id).
    var y = a; var k = 0;
    while (k < 12) { y := PFE.fp12Frobenius(y, 1); k += 1 };
    check(TM.fp12Eq(y, a), "fp12 frobenius order 12");
    i += 1;
  };
  Debug.print("PROP fp12: " # Nat.toText(n) # " OK (comm/distributivity/sqrfast=mul/a*a^-1=1/frob^12=id)");
};

// ============ CURVE IDENTITIES (production L2: CurveJac) ============
// scalar identities: [a+b]P=[a]P+[b]P, P+O=P, P+(-P)=O, [r]P=O.
do {
  smState := classSeed("prop.curve.scalar");
  let n = nOf(2_000);
  let g1 = CJ.g1FromAffine(C.g1Gen);
  let g2 = CJ.g2FromAffine(g2Gen);
  var i = 0;
  while (i < n) {
    let a = frElem(); let b = frElem();
    // [a+b]P == [a]P + [b]P  (G1 and G2)
    let lhs1 = CJ.g1Mul(g1, a + b);
    let rhs1 = CJ.g1Add(CJ.g1Mul(g1, a), CJ.g1Mul(g1, b));
    check(C.g1Eq(CJ.g1ToAffine(lhs1), CJ.g1ToAffine(rhs1)), "G1 [a+b]P=[a]P+[b]P");
    let lhs2 = CJ.g2Mul(g2, a + b);
    let rhs2 = CJ.g2Add(CJ.g2Mul(g2, a), CJ.g2Mul(g2, b));
    check(C.g2Eq(CJ.g2ToAffine(lhs2), CJ.g2ToAffine(rhs2)), "G2 [a+b]P=[a]P+[b]P");
    // P + O = P
    let pa = CJ.g1Mul(g1, a);
    check(C.g1Eq(CJ.g1ToAffine(CJ.g1Add(pa, CJ.g1Inf())), CJ.g1ToAffine(pa)), "G1 P+O=P");
    // P + (-P) = O
    let negP = CJ.g1FromAffine(C.g1Neg(CJ.g1ToAffine(pa)));
    check(CJ.g1IsInf(CJ.g1Add(pa, negP)), "G1 P+(-P)=O");
    // [r]P = O  (r = group order)
    check(CJ.g1IsInf(CJ.g1Mul(g1, C.R)), "G1 [r]P=O");
    check(CJ.g2IsInf(CJ.g2Mul(g2, C.R)), "G2 [r]P=O");
    i += 1;
  };
  Debug.print("PROP curve-scalar: " # Nat.toText(n) # " OK ([a+b]P/P+O/P+(-P)/[r]P=O)");
};
// point-arith: [2]P = P+P over random subgroup points.
do {
  smState := classSeed("prop.curve.point");
  let n = nOf(50_000);
  let g1 = CJ.g1FromAffine(C.g1Gen);
  var i = 0;
  while (i < n) {
    let k = frElem();
    let p = CJ.g1Mul(g1, k);
    check(C.g1Eq(CJ.g1ToAffine(CJ.g1Dbl(p)), CJ.g1ToAffine(CJ.g1Add(p, p))), "G1 [2]P=P+P");
    i += 1;
  };
  Debug.print("PROP curve-point: " # Nat.toText(n) # " OK ([2]P=P+P)");
};

// ============ PAIRING IDENTITIES (production: PP.millerLoop + PFE.finalExponentiate) ============
func pairing(p : C.G1, q : C.G2) : TM.Fp12M { PFE.finalExponentiate(PP.millerLoop(p, q)) };
// bilinearity: e([a]P,[b]Q) = e(P,Q)^{ab}
do {
  smState := classSeed("prop.pair.bilin");
  let n = nOf(30);
  let g1 = CJ.g1FromAffine(C.g1Gen);
  let g2 = CJ.g2FromAffine(g2Gen);
  var i = 0;
  while (i < n) {
    let a = frElem(); let b = frElem();
    let pa = CJ.g1ToAffine(CJ.g1Mul(g1, a));
    let qb = CJ.g2ToAffine(CJ.g2Mul(g2, b));
    let lhs = pairing(pa, qb);
    let base = pairing(C.g1Gen, g2Gen);
    // e(P,Q)^{ab} — Fp12 exponentiation by the integer product a*b.
    let rhs = TM.fp12Pow(base, a * b);
    check(TM.fp12Eq(lhs, rhs), "pairing bilinearity e([a]P,[b]Q)=e(P,Q)^ab");
    i += 1;
  };
  Debug.print("PROP pairing-bilinearity: " # Nat.toText(n) # " OK");
};
// additivity: e(P1+P2,Q) = e(P1,Q)*e(P2,Q)
do {
  smState := classSeed("prop.pair.add");
  let n = nOf(30);
  let g1 = CJ.g1FromAffine(C.g1Gen);
  let g2 = CJ.g2FromAffine(g2Gen);
  var i = 0;
  while (i < n) {
    let a = frElem(); let b = frElem();
    let p1 = CJ.g1Mul(g1, a); let p2 = CJ.g1Mul(g1, b);
    let q = CJ.g2ToAffine(CJ.g2Mul(g2, frElem()));
    let lhs = pairing(CJ.g1ToAffine(CJ.g1Add(p1, p2)), q);
    let rhs = TM.fp12Mul(pairing(CJ.g1ToAffine(p1), q), pairing(CJ.g1ToAffine(p2), q));
    check(TM.fp12Eq(lhs, rhs), "pairing additivity e(P1+P2,Q)=e(P1,Q)e(P2,Q)");
    i += 1;
  };
  Debug.print("PROP pairing-additivity: " # Nat.toText(n) # " OK");
};
// degeneracy: e(O,Q)=1, e(P,O)=1, e(G1,G2)!=1
do {
  smState := classSeed("prop.pair.degen");
  let n = nOf(10);
  let g1 = CJ.g1FromAffine(C.g1Gen);
  let g2 = CJ.g2FromAffine(g2Gen);
  var i = 0;
  while (i < n) {
    let q = CJ.g2ToAffine(CJ.g2Mul(g2, frElem()));
    let p = CJ.g1ToAffine(CJ.g1Mul(g1, frElem()));
    check(TM.fp12Eq(pairing(#inf, q), TM.fp12OneM()), "pairing e(O,Q)=1");
    check(TM.fp12Eq(pairing(p, #inf), TM.fp12OneM()), "pairing e(P,O)=1");
    i += 1;
  };
  check(not TM.fp12Eq(pairing(C.g1Gen, g2Gen), TM.fp12OneM()), "pairing e(G1,G2)!=1 (nondegeneracy)");
  Debug.print("PROP pairing-degeneracy: " # Nat.toText(n) # " OK (e(O,Q)=e(P,O)=1, e(G1,G2)!=1)");
};

Debug.print("FORTRESS-PROPERTIES: ALL ALGEBRAIC IDENTITIES HOLD (seed=" # Nat64.toText(SEED) # ")");
