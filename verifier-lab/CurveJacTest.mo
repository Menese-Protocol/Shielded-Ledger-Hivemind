/// Verifier gate — Jacobian Montgomery group ops against the literal L1 `Curve`.
///
/// The Jacobian layer exists ONLY because affine-with-inversion scalar mult cannot fit the message
/// ceiling; it must therefore be bit-identical (after the single affine conversion) to L1 on every
/// path the verifier uses: scalar multiples, the vk_x MSM, and the subgroup checks — including the
/// pinned wrong-subgroup adversarial points, which MUST be rejected. A live formula mutant must
/// turn the differential RED.
/// Run: moc -r --package core <core> CurveJacTest.mo

import Debug "mo:core/Debug";
import Nat "mo:core/Nat";
import Runtime "mo:core/Runtime";
import FpM "FpMont";
import T "Tower";
import C "Curve";
import CJ "CurveJac";
import D "OracleData";

func fail(m : Text) { Runtime.trap("jacobian-battery FAIL: " # m) };

let g2Gen : C.G2 = #pt({
  x = T.fp2(0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8,
            0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e);
  y = T.fp2(0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801,
            0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be);
});

// Pinned adversarial points from the arkworks curve oracle: on-curve, WRONG subgroup.
let g1WrongSubgroup : C.G1 = #pt({
  x = 0x07d9851e94630245314c0497f59c81e2594901d1546c675a61c65ceab2b72cbdc264d4280ba057fa9471e2775896526a;
  y = 0x07c48c0dfabf425ce5f59bd384d78f4b43dfb406d8f239393b3d4b1fd33438d19ff116bd197f945e6b77128c64021f1a;
});
let g2WrongSubgroup : C.G2 = #pt({
  x = T.fp2(0x03287adcc6c5612217f4744d790962b42f76f6ea3a2c9f94908b679b256002e92c97066a0724eeba5663dc04fdb5016b,
            0x0a0f085f3a5f38d0351daf90c42470fc39a5d8a572e28d911012c9ad758630e33a97ccccc94f4df9ae0885e9beec7f2d);
  y = T.fp2(0x12d8800d4099109ffb6082c4e99d3ffff456bad27048f0062dab5e58b96b672aadf7ba1e75beefe3cd08b63bb01b2c66,
            0x0cab3e779f37a90c63ad1876f5f07672b1479a653bcbdfada1a095bcd215e58a6eaafd612ef2dd770d5a3dbbd4751ece);
});

// The scalar battery: identity/small/BLS-parameter/order-boundary/full-width.
let big255 : Nat = 0x515f0bb1f0c76a6a9c2882fdb17c72b245e6f9b02fcaa1d9c74b8ba2d78af7de;
let scalars : [Nat] = [0, 1, 2, 3, 5, 0xd201000000010000, C.R - 1, C.R, C.R + 1, big255];

// ---- G1 differential on generator and both real proof G1 points ----
func diffG1(name : Text, p : C.G1) {
  for (k in scalars.vals()) {
    let want = C.g1Mul(p, k);
    let got = CJ.g1ToAffine(CJ.g1Mul(CJ.g1FromAffine(p), k));
    if (not C.g1Eq(got, want)) { fail(name # " scalar " # Nat.toText(k) # " diverges from L1") };
  };
};
diffG1("G1 generator", C.g1Gen);
diffG1("G1 proofA", D.proofA);
diffG1("G1 proofC", D.proofC);

// ---- G1 structural edges ----
let pj = CJ.g1FromAffine(D.proofA);
if (not C.g1Eq(CJ.g1ToAffine(CJ.g1Add(pj, CJ.g1Inf())), D.proofA)) { fail("G1 P+inf") };
if (not C.g1Eq(CJ.g1ToAffine(CJ.g1Add(CJ.g1Inf(), pj)), D.proofA)) { fail("G1 inf+P") };
if (not CJ.g1IsInf(CJ.g1Add(pj, CJ.g1FromAffine(C.g1Neg(D.proofA))))) { fail("G1 P+(-P) != inf") };
if (not C.g1Eq(CJ.g1ToAffine(CJ.g1Add(pj, pj)), C.g1Add(D.proofA, D.proofA))) { fail("G1 P+P (u1==u2 doubling path)") };

// ---- G2 differential on generator and the real vk/proof G2 points ----
func diffG2(name : Text, p : C.G2) {
  for (k in scalars.vals()) {
    let want = C.g2Mul(p, k);
    let got = CJ.g2ToAffine(CJ.g2Mul(CJ.g2FromAffine(p), k));
    if (not C.g2Eq(got, want)) { fail(name # " scalar " # Nat.toText(k) # " diverges from L1") };
  };
};
diffG2("G2 generator", g2Gen);
diffG2("G2 proofB", D.proofB);
diffG2("G2 delta", D.delta);

let qj = CJ.g2FromAffine(D.proofB);
if (not C.g2Eq(CJ.g2ToAffine(CJ.g2Add(qj, CJ.g2Inf())), D.proofB)) { fail("G2 P+inf") };
if (not CJ.g2IsInf(CJ.g2Add(qj, CJ.g2FromAffine(C.g2Neg(D.proofB))))) { fail("G2 P+(-P) != inf") };
if (not C.g2Eq(CJ.g2ToAffine(CJ.g2Add(qj, qj)), C.g2Add(D.proofB, D.proofB))) { fail("G2 P+P (doubling path)") };

// ---- validation: every real verifier input accepts, and the codes match L1 exactly ----
func codeOf(v : { #ok; #err : Text }) : Text { switch (v) { case (#ok) { "OK" }; case (#err(e)) { e } } };
func diffValidateG1(name : Text, p : C.G1) {
  let l1 = codeOf(C.g1Validate(p));
  let jac = codeOf(CJ.g1Validate(p));
  if (l1 != jac) { fail(name # " validate code mismatch: L1=" # l1 # " jac=" # jac) };
};
func diffValidateG2(name : Text, p : C.G2) {
  let l1 = codeOf(C.g2Validate(p));
  let jac = codeOf(CJ.g2Validate(p));
  if (l1 != jac) { fail(name # " validate code mismatch: L1=" # l1 # " jac=" # jac) };
};
diffValidateG1("proofA", D.proofA);
diffValidateG1("proofC", D.proofC);
diffValidateG1("alpha", D.alpha);
diffValidateG2("proofB", D.proofB);
diffValidateG2("beta", D.beta);
diffValidateG2("gamma", D.gamma);
diffValidateG2("delta", D.delta);

// The adversarial rejects — on-curve wrong-subgroup MUST fail with the subgroup code.
if (codeOf(CJ.g1Validate(g1WrongSubgroup)) != "E_NOT_IN_SUBGROUP") { fail("G1 wrong-subgroup point ACCEPTED") };
if (codeOf(CJ.g2Validate(g2WrongSubgroup)) != "E_NOT_IN_SUBGROUP") { fail("G2 wrong-subgroup point ACCEPTED") };
if (codeOf(CJ.g1Validate(#pt({ x = 7; y = 11 }))) != "E_NOT_ON_CURVE") { fail("G1 off-curve point not rejected") };
if (codeOf(CJ.g1Validate(#pt({ x = FpM.P; y = 1 }))) != "E_NONCANONICAL") { fail("G1 noncanonical not rejected") };

// ---- the vk_x MSM: differential vs L1 AND byte-anchored to the arkworks oracle ----
let vkxL1 = C.g1Add(D.gammaAbc[0], C.g1Add(C.g1Mul(D.gammaAbc[1], D.inputs[0]), C.g1Mul(D.gammaAbc[2], D.inputs[1])));
let vkxJac = CJ.vkX(D.gammaAbc, D.inputs);
if (not C.g1Eq(vkxJac, vkxL1)) { fail("vk_x MSM diverges from L1") };
// oracle-vectors/multimiller-battery-vectors.txt [valid] vk_x
let vkxOracle : C.G1 = #pt({
  x = 0x158025f128e95e718dd44fc6b3a761504d4baec1d01aa1973813014d14d2acf9fa4b54438456b996edc777c231b53417;
  y = 0x0858a195cf90b094273f51d2106ca2683ba9dc8c35be2ecac83e30e45e2ac36414a0834685d445a55c8aa1b719c334bc;
});
if (not C.g1Eq(vkxJac, vkxOracle)) { fail("vk_x MSM diverges from the arkworks oracle") };

// ---- live mutant: drop the 8·C term of Jacobian doubling to 4·C; MUST diverge from L1 ----
func mutantDbl(p : CJ.G1J) : CJ.G1J {
  let a = FpM.montMul(p.x, p.x);
  let b = FpM.montMul(p.y, p.y);
  let c = FpM.montMul(b, b);
  let xb = FpM.add(p.x, b);
  let d0 = FpM.sub(FpM.sub(FpM.montMul(xb, xb), a), c);
  let d = FpM.add(d0, d0);
  let e = FpM.add(FpM.add(a, a), a);
  let f = FpM.montMul(e, e);
  let x3 = FpM.sub(f, FpM.add(d, d));
  let c4 = FpM.add(FpM.add(c, c), FpM.add(c, c)); // MUTANT: 4C where 8C is required
  let y3 = FpM.sub(FpM.montMul(e, FpM.sub(d, x3)), c4);
  let yz = FpM.montMul(p.y, p.z);
  { x = x3; y = y3; z = FpM.add(yz, yz) };
};
let mutant2P = CJ.g1ToAffine(mutantDbl(CJ.g1FromAffine(D.proofA)));
if (C.g1Eq(mutant2P, C.g1Add(D.proofA, D.proofA))) { fail("MUTANT dbl (4C) was NOT caught — differential has no power") };

Debug.print("jacobian-battery: ALL GREEN");
Debug.print("  - G1/G2 scalar battery (0,1,2,3,5,x,r-1,r,r+1,255-bit) == L1 on generator + real proof/vk points");
Debug.print("  - add/dbl degeneracies (inf, P+(-P), u1==u2) == L1");
Debug.print("  - validation codes == L1; wrong-subgroup G1+G2 REJECTED; off-curve/noncanonical REJECTED");
Debug.print("  - vk_x MSM == L1 == arkworks oracle (both coordinates)");
Debug.print("  - live mutant (4C dbl) turned the differential RED");
