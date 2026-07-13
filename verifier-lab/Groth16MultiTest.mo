/// Verifier gate — the assembled one-message verifier against the arkworks multimilleroracle.
///
/// Layer by layer, each with a live negative control:
///   1. interleaved multi-Miller: FULL 12-coefficient byte-diff vs the oracle, on the VALID proof
///      AND the forged-A proof (a non-trivial target); mutant control = dropping the final
///      conjugation must break the diff; structural control = interleave == product of the four
///      single prepared Miller loops.
///   2. ONE shared final exponentiation: valid product → exactly one (all 12 coefficients);
///      forged product → the oracle's NON-trivial Fp12 (the control that the layer isn't
///      an always-one stub).
///   3. assembled verify: valid ACCEPTS; tampered A, tampered C, wrong public input, wrong vk
///      each REJECT (arkworks-confirmed verdicts); wrong-subgroup B rejects at validation.
/// Run: moc -r --package core <core> Groth16MultiTest.mo

import Debug "mo:core/Debug";
import Nat "mo:core/Nat";
import Runtime "mo:core/Runtime";
import T "Tower";
import TM "TowerMont";
import C "Curve";
import CJ "CurveJac";
import PP "PairingProjective";
import PF "PairingFinalExp";
import GM "Groth16Multi";
import D "OracleData";

func fail(m : Text) { Runtime.trap("multimiller-battery FAIL: " # m) };

func flat12(x : T.Fp12) : [Nat] {
  [ x.c0.c0.c0, x.c0.c0.c1, x.c0.c1.c0, x.c0.c1.c1, x.c0.c2.c0, x.c0.c2.c1,
    x.c1.c0.c0, x.c1.c0.c1, x.c1.c1.c0, x.c1.c1.c1, x.c1.c2.c0, x.c1.c2.c1 ];
};
func expectFull(name : Text, got : TM.Fp12M, want : [Nat]) {
  let g = flat12(TM.fromM12(got));
  var i : Nat = 0;
  while (i < 12) {
    if (g[i] != want[i]) { fail(name # " coefficient " # Nat.toText(i) # " differs") };
    i += 1;
  };
};
func differsSomewhere(got : TM.Fp12M, want : [Nat]) : Bool {
  let g = flat12(TM.fromM12(got));
  var i : Nat = 0;
  while (i < 12) { if (g[i] != want[i]) { return true }; i += 1 };
  false;
};

// ---- pinned oracle targets (oracle-vectors/multimiller-battery-vectors.txt) ----
let oracleRawValid : [Nat] = [
  0x1230e17341ba374e3a9a31684da3ad43af4f6b8287def62eca1a144ee21a5bb9c9c7bdf1d5cf0073ecd117e33b3486e0,
  0x0c75963d1f83fb6cc3042fe08b64e32f6a23b1b0319c84df10d13e6779c3f5f68243dd8dea2a06667c53d96743b1652a,
  0x099cdd07f7e88cb84b9687cb3b8675b579fec4a356a3e24cb4ab8ffea345bf42f33fcf8ec69be8d458cb1a0e8f979869,
  0x180e7c75c2da45267f1eb993d9dcc9baa25f49e4d462a65b90e62e229bede6fe3a026695a036973a13ced25e7e01b0cf,
  0x165baf34221ad9f6453804d1256b5429374401bb00230d5d3abf9dc4d4c51e54bc1ba3405cbffc3c9b1cf590ee45a08e,
  0x0077fdb4f590a73229e3dd28485d0633370e3a62ea74b5af9e238cd150108aed9353145cde9a9cfddaabf1b11a29ab6f,
  0x0394f6709a732dbb3696fa597455b3176c0d3cf65f18f973da92e34e6698a6b3c072ef8b25b9544b0a1e289b9006306c,
  0x16ecb580cdc27fa5ad20c4f15cb6a6d9a417f65480e3a84cde3d1424f04a644c9727186ce50550184c88624c6a2f6b82,
  0x0181a6dccdb991d834de83f0aca28e4bc5244b0f9163b33747cf9b235c00ea2aef5044f661c01edc522c8f16594e6f3b,
  0x0876120688cdc26e53b0fbd745cfa57713102cc7207f0f43d16a49d6409766753041df35ad20c92b0845048c484573b0,
  0x0bf0506c4099c2e13344078c103327ae656c4e1992a2cd6fc81a3efe98667303569781869d36772f5f4d2c22aeaf7574,
  0x075e93da56a658541c30ee22aa390e6fe269371eb38020e1b16ca48c922f8b451d60c290ff5a6109de1de2d5e165388e,
];
let oracleRawForgedA : [Nat] = [
  0x07b9fa16725677c7811ff7675bcec2b7bc11b70bd43f85dcb7f3260ae490cbb0963915e7404658bfdc8ece93af853458,
  0x09df489dc9d603fe52c11e18075fc8076528b83f5fca3766a608d904e402c29dd1fc271b546018f0c4f30ab6cb4cc3cd,
  0x05ff8a687ff3ec56f8add3f7f5c53c1e5dcc2ad0c8487431af07678134f0a2fb8fe8e1935c05fd0417ca0e966f80b133,
  0x16bbfdfd80f98d57993e651046c6a8a532b3dd64338d43fd169916794835a7af4d75c47fbbd606a2ab5b93d2aad73620,
  0x0e9e50d297a86c25fe90dae9258b8fdd9335ed947f4437154c5e39b299a31dffa7fb56d5955c5f0e4c2177cada53aee6,
  0x155e84050e1c5b18cec9559fcccccece7cb8b9ef3a5b0e0d720348f352080bf79c47b9e81212cad5f586d4bb6e930865,
  0x118d55008458732407180c7237f94137a9669cbd9621e98be885a14f5ee0ff48ba63aeea81f8df8bbf36bc12f725e20c,
  0x08f2811ecc2807a557814107ee9ac58d092014d069c289d3996307dc968ac14c1e0f229abd6b6f40347d7679b82fcbe8,
  0x179a4ebb406416ad98ec968ecc1f3eef9fae06f21bf600404a95d8f651c46739cd555e89da6e64a4b283935cf85a1165,
  0x011b84c872a4ed5af2cc6d93bb462d6892d63ba1416f91501974e42441a402f36a919dc9a1776e4964667232eb7f9c89,
  0x09d77d1de609b28bb01002c9fb2cccd6368daf901d1d36865c78f8a36ff9609b69fa106fb39bcdfdc3bde004a1ffc324,
  0x0e2111242fe858bacdda3b158b437a304a1266e310abb5bf4c70905ccdb8dd1871f8317deb78eb74b5a38144c749e869,
];
let oracleFinalExpForgedA : [Nat] = [
  0x0f5099d19b6e93d9c9285d74ae224f9c2c9b89071ef3e0d9fd5d3c0dc25997e02c43df80e3dcfbc79801bdbc6e495920,
  0x0593c894e95649367124bc96d107d8a6e2136290f518b2d4a144c22126a443ced49c11502b2241145fb729e94ab919a7,
  0x132739481b4621aec5f0ffdec7e813cf00adbe55469b1b79968b9946da78c4abbaf71ca2006c8aab122911a129ea3cbc,
  0x024617eeb6d9e6af50b059e64c5cfc248db3a773af5b4a9aea2951c438fb539e99cbcbce53cf980163796f13ddac984f,
  0x036f64bfcc37d72a2abecc97ab5838e3e4c93142cd0d26044f595febb9f46bd05e1707c34850ca4b0f7c842bef430498,
  0x163b6fbf6a418d2e3a50e97cb485706890075d27202b66d9a2eb8a5f7f79343a3d0e13714b9f9282881a29239afdf51b,
  0x05e5c8dcdc9370e919c6e789bf3d47d089a778e2607b8274f78dc99dfcd5906bd19639de743af4630d31ba164f5ef8f3,
  0x02143e7421dc2ecc318b9464435c2f7ae3af46fc91cf8067ac404601b420080c7294c46b1b71803ec673b5a4dc176390,
  0x14cf157bc16cd538891b36fadced9ae6273dbf29074251953fdc708fce161cfae6a44b6c70485414b1aef6e13b069026,
  0x0c2df4b07ed60468060ad375b63b7506feaf969ce846e90b8b3b5027db76d9f551625324167ac0ba427eea0e615a7830,
  0x0de7167a5f038bf93499b722ee54f87284746dfe5c6b6a76a2d4e61bb99d37351f684deede7121888bddb0c3d9b38222,
  0x0794d69d5de8f68ca2fe27e83a6a5dd3ee7f0980b7c2b8c3ef496f6edbabde509fca5c10d207f2af2d43bead6e87be78,
];
let oracleOne : [Nat] = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

// Forgery coordinates, arkworks-confirmed REJECT (multimilleroracle [tamperedC]/[wrongvk]).
let tamperedC : C.G1 = #pt({
  x = 0x150cbb94979bd59373c6b9a4e932f19a5475f065b833ab09cacf20de268bf04707e0ef010a4427876059d62f29580d33;
  y = 0x176b0d36fd760da5abe443f761adef1fa282e502a18f508c75081a053069b2e3e2d52a7ed277d091aded7f4205c465a3;
});
let tamperedDelta : C.G2 = #pt({
  x = T.fp2(0x0580de56d5b0608492bf0d126eee6ad57a18b3849de6a95be1f475a0396e78819fb12d0e74b2db9424f6ae397c7dbaab,
            0x0cf1f2d44bb48db5801cd638598e2fd4bdd6cd56b0e101a000e43420579ce898cef81902a098c9844e3e01b663f8f58b);
  y = T.fp2(0x13e9d0e3b5587bb2f8bf68956ff7ae7a547a573bc6d42a81912155f331e6eeebfcc44576c13a399fef7e37ce4d66d803,
            0x08f34470fe3a2c15e0dfa8a21c039ffd8b62b8245361c087e08cc56a63c01da625600a367376ec358a1b5b2e901ec092);
});
// On-curve wrong-subgroup G2 (pinned adversarial vector): validation inside verify MUST fire.
let g2WrongSubgroup : C.G2 = #pt({
  x = T.fp2(0x03287adcc6c5612217f4744d790962b42f76f6ea3a2c9f94908b679b256002e92c97066a0724eeba5663dc04fdb5016b,
            0x0a0f085f3a5f38d0351daf90c42470fc39a5d8a572e28d911012c9ad758630e33a97ccccc94f4df9ae0885e9beec7f2d);
  y = T.fp2(0x12d8800d4099109ffb6082c4e99d3ffff456bad27048f0062dab5e58b96b672aadf7ba1e75beefe3cd08b63bb01b2c66,
            0x0cab3e779f37a90c63ad1876f5f07672b1479a653bcbdfada1a095bcd215e58a6eaafd612ef2dd770d5a3dbbd4751ece);
});

// ---- the fixed vk, prepared once (as at canister init) ----
let vk = switch (GM.prepareVk(D.alpha, D.beta, D.gamma, D.delta, D.gammaAbc)) {
  case (#ok(v)) { v };
  case (#err(e)) { fail("prepareVk rejected the pinned vk: " # e); Runtime.trap("") };
};

// =================================================================================================
// Layer 1 — interleaved multi-Miller, byte-diffed on all 12 coefficients.
// =================================================================================================
let vkx = CJ.vkX(D.gammaAbc, D.inputs);
let bPrep = PP.prepareG2(D.proofB);
let rawValid = GM.multiMillerRaw(vk, D.proofA, bPrep, D.proofC, vkx);
expectFull("multi-Miller (valid proof)", rawValid, oracleRawValid);

// Structural control: interleave == product of the four single prepared Miller loops (`PairingProjective`).
let single = TM.fp12Mul(
  TM.fp12Mul(PP.millerLoopPrepared(D.proofA, bPrep), PP.millerLoopPrepared(C.g1Neg(vkx), vk.gammaPrep)),
  TM.fp12Mul(PP.millerLoopPrepared(C.g1Neg(D.proofC), vk.deltaPrep), PP.millerLoopPrepared(vk.alphaNeg, vk.betaPrep)),
);
expectFull("interleave == product of single Millers", single, oracleRawValid);

// Non-trivial second point: the forged-A proof's product.
let rawForged = GM.multiMillerRaw(vk, D.forgedA, bPrep, D.proofC, vkx);
expectFull("multi-Miller (forged A)", rawForged, oracleRawForgedA);

// Live mutant: without the final conjugation (negative BLS x) the diff MUST break.
let mutantNoConj = TM.fp12Conj(rawValid); // conj is an involution: this is the pre-conjugation value
if (not differsSomewhere(mutantNoConj, oracleRawValid)) {
  fail("MUTANT (dropped final conjugation) not caught — Miller byte-diff has no power");
};

// =================================================================================================
// Layer 2 — ONE shared final exponentiation over the product.
// =================================================================================================
let feValid = PF.finalExponentiate(rawValid);
expectFull("shared final exp (valid) == one", feValid, oracleOne);

let feForged = PF.finalExponentiate(rawForged);
expectFull("shared final exp (forged A) == oracle non-trivial value", feForged, oracleFinalExpForgedA);
if (not differsSomewhere(feForged, oracleOne)) { fail("forged final exp is one — always-one collusion possible") };

// =================================================================================================
// Layer 3 — the assembled verifier: accept + FOUR live forgery rejects.
// =================================================================================================
func codeOf(v : GM.Verdict) : Text { switch (v) { case (#ok) { "OK" }; case (#err(e)) { e } } };

let vValid = GM.verify(vk, D.proofA, D.proofB, D.proofC, D.inputs);
if (codeOf(vValid) != "OK") { fail("valid proof REJECTED: " # codeOf(vValid)) };

let vForgedA = GM.verify(vk, D.forgedA, D.proofB, D.proofC, D.inputs);
if (codeOf(vForgedA) != "E_PAIRING_FAIL") { fail("tampered A not rejected by the equation: " # codeOf(vForgedA)) };

let vTamperedC = GM.verify(vk, D.proofA, D.proofB, tamperedC, D.inputs);
if (codeOf(vTamperedC) != "E_PAIRING_FAIL") { fail("tampered C not rejected by the equation: " # codeOf(vTamperedC)) };

let vBadInput = GM.verify(vk, D.proofA, D.proofB, D.proofC, D.badInputs);
if (codeOf(vBadInput) != "E_PAIRING_FAIL") { fail("wrong public input not rejected: " # codeOf(vBadInput)) };

let wrongVk = switch (GM.prepareVk(D.alpha, D.beta, D.gamma, tamperedDelta, D.gammaAbc)) {
  case (#ok(v)) { v };
  case (#err(e)) { fail("tamperedDelta is a valid subgroup point; prepareVk must accept it: " # e); Runtime.trap("") };
};
let vWrongVk = GM.verify(wrongVk, D.proofA, D.proofB, D.proofC, D.inputs);
if (codeOf(vWrongVk) != "E_PAIRING_FAIL") { fail("wrong vk (tampered delta) not rejected: " # codeOf(vWrongVk)) };

// Validation stays live inside the assembled path: wrong-subgroup B must fail BEFORE the pairing.
let vWrongSubB = GM.verify(vk, D.proofA, g2WrongSubgroup, D.proofC, D.inputs);
if (codeOf(vWrongSubB) != "B:E_NOT_IN_SUBGROUP") { fail("wrong-subgroup B not rejected at validation: " # codeOf(vWrongSubB)) };

// negA (fifth pinned forgery, from the reference oracle): equation must reject.
let vNegA = GM.verify(vk, D.negA, D.proofB, D.proofC, D.inputs);
if (codeOf(vNegA) != "E_PAIRING_FAIL") { fail("negated A not rejected: " # codeOf(vNegA)) };

Debug.print("multimiller-battery: ALL GREEN");
Debug.print("  1. interleaved multi-Miller == arkworks multi_miller_loop, all 12 coeffs, valid AND forged-A");
Debug.print("     interleave == product of 4 single prepared Millers; dropped-conjugation mutant RED");
Debug.print("  2. ONE shared final exp: valid -> one (12 coeffs); forged -> oracle non-trivial value (12 coeffs)");
Debug.print("  3. assembled verify: valid ACCEPTS; tampered A / tampered C / wrong input / wrong vk REJECT;");
Debug.print("     wrong-subgroup B rejected at validation; negA rejected");
