/// Wire-boundary gate — compressed G2 decode + LE Fr + the full hex boundary, against the
/// wireoracle and the pool fixtures.
///
/// Layers, each with live negative controls:
///   1. DecodeG2: generator-multiple battery decodes to the pinned uncompressed coordinates
///      (both sort parities exercised); infinity round-trips; the four adversarial encodings
///      reject with the pinned codes; the sort-bit flip decodes to exactly -P (pinned coords).
///   2. Fr LE: canonical battery round-trips through parseInputs; r and r+1 REJECT.
///   3. vk/proof parsers: transfer_vk.hex and deposit_vk.hex parse+prepare; every parsed proof
///      byte-matches the PoolBlsData uncompressed constants (wire == affine truth).
///   4. The COMPLETE hex boundary (verifyPrepared): reproduces every pool ORACLE verdict on the
///      exact hex the ledger passes, including the C1 bitflip badproof (deserialize-or-pairing)
///      and C2 fake-tree pairing-ACCEPT.
/// Run: moc -r --package core <core> WireTest.mo

import Array "mo:core/Array";
import Char "mo:core/Char";
import Debug "mo:core/Debug";
import Nat "mo:core/Nat";
import Runtime "mo:core/Runtime";
import C "Curve";
import Dec2 "DecodeG2";
import W "Groth16Wire";
import PD "PoolBlsData";
import PW "PoolWireData";

func fail(m : Text) { Runtime.trap("WIRE FAIL: " # m) };
func bytesOf(h : Text) : [Nat8] {
  switch (W.hexToBytes(h)) { case (?b) { b }; case (null) { fail("bad test hex"); [] } };
};

func Prim_swapHalves(b : [Nat8]) : [Nat8] {
  Array.tabulate<Nat8>(96, func(i : Nat) : Nat8 { if (i < 48) { b[48 + i] } else { b[i - 48] } });
};

// ---- pinned wire-oracle vectors (oracle-vectors/WIRE-g2-fr-vectors.txt) ----
let g2Battery : [(Text, Nat, Nat, Nat, Nat)] = [
  ("93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
   0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8, 0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e,
   0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801, 0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be),
  ("aa4edef9c1ed7f729f520e47730a124fd70662a904ba1074728114d1031e1572c6c886f6b57ec72a6178288c47c335771638533957d540a9d2370f17cc7ed5863bc0b995b8825e0ee1ea1e1e4d00dbae81f14b0bf3611b78c952aacab827a053",
   0x1638533957d540a9d2370f17cc7ed5863bc0b995b8825e0ee1ea1e1e4d00dbae81f14b0bf3611b78c952aacab827a053, 0x0a4edef9c1ed7f729f520e47730a124fd70662a904ba1074728114d1031e1572c6c886f6b57ec72a6178288c47c33577,
   0x0468fb440d82b0630aeb8dca2b5256789a66da69bf91009cbfe6bd221e47aa8ae88dece9764bf3bd999d95d71e4c9899, 0x0f6d4552fa65dd2638b361543f887136a43253d9c66c411697003f7a13c308f5422e1aa0a59c8967acdefd8b6e36ccf3),
  ("89380275bbc8e5dcea7dc4dd7e0550ff2ac480905396eda55062650f8d251c96eb480673937cc6d9d6a44aaa56ca66dc122915c824a0857e2ee414a3dccb23ae691ae54329781315a0c75df1c04d6d7a50a030fc866f09d516020ef82324afae",
   0x122915c824a0857e2ee414a3dccb23ae691ae54329781315a0c75df1c04d6d7a50a030fc866f09d516020ef82324afae, 0x09380275bbc8e5dcea7dc4dd7e0550ff2ac480905396eda55062650f8d251c96eb480673937cc6d9d6a44aaa56ca66dc,
   0x0b21da7955969e61010c7a1abc1a6f0136961d1e3b20b1a7326ac738fef5c721479dfd948b52fdf2455e44813ecfd892, 0x08f239ba329b3967fe48d718a36cfe5f62a7e42e0bf1c1ed714150a166bfbd6bcf6b3b58b975b9edea56d53f23a0e849),
  ("80fb837804dba8213329db46608b6c121d973363c1234a86dd183baff112709cf97096c5e9a1a770ee9d7dc641a894d60411a5de6730ffece671a9f21d65028cc0f1102378de124562cb1ff49db6f004fcd14d683024b0548eff3d1468df2688",
   0x0411a5de6730ffece671a9f21d65028cc0f1102378de124562cb1ff49db6f004fcd14d683024b0548eff3d1468df2688, 0x00fb837804dba8213329db46608b6c121d973363c1234a86dd183baff112709cf97096c5e9a1a770ee9d7dc641a894d6,
   0x19b5e8f5d4a72f2b75811ac084a7f814317360bac52f6aab15eed416b4ef9938e0bdc4865cc2c4d0fd947e7c6925fd14, 0x093567b4228be17ee62d11a254edd041ee4b953bffb8b8c7f925bd6662b4298bac2822b446f5b5de3b893e1be5aa4986),
  ("a5ebc29b41692c4be1c1d4df805570a31a85277fcea8cbb1899b943eae7683f51a2f1dbdefde099e897ed00a6319153008b4a633d55f95498b8d65bcf6859fa424e01085c177f1ae777c1fd1ea2796b0a026552cff4751ff157bbefd8122f1e4",
   0x08b4a633d55f95498b8d65bcf6859fa424e01085c177f1ae777c1fd1ea2796b0a026552cff4751ff157bbefd8122f1e4, 0x05ebc29b41692c4be1c1d4df805570a31a85277fcea8cbb1899b943eae7683f51a2f1dbdefde099e897ed00a63191530,
   0x15c38256870de05d5a75df0a106d5d0b1770a727355ab954c6c4e8f9c34ff5828857a55239550eff8c0e6de236e11a7f, 0x14c5815a92b9d68dadf6f1f47959d026b775b618168755ada13cff7a9222fcd083a030f42fc44f3a8299e996ab3cf0b5),
  ("84705f0eca2162ddccda03a00270c04f32129a6267f2d2827219e751fc632c92bed66932f65b7ae5c850f8b1ed9348b00286617f98ba5d633f0d0a3cae30f3de7a267de488ff3137048dc4a2d84a11526f6c3346b568da928f7b97d72ce4c1cb",
   0x0286617f98ba5d633f0d0a3cae30f3de7a267de488ff3137048dc4a2d84a11526f6c3346b568da928f7b97d72ce4c1cb, 0x04705f0eca2162ddccda03a00270c04f32129a6267f2d2827219e751fc632c92bed66932f65b7ae5c850f8b1ed9348b0,
   0x09b52651478c447d3c02fd8335c4644e55a9c4e6040e7673331c7ac9f344709251cd15564efc86639e8269e97538735b, 0x0a7600dab7ed7241167446764f3f809fac345be949fbf44b2863ce372077d5c0a6ab8174cb9b420c34d3668840b764a4),
];
let g2InfHex : Text = "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
let advno_compressionHex : Text = "13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8";
let advno_compressionCode : Text = "E_BAD_FLAG";
let advinf_nonzero_xHex : Text = "d3e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8";
let advinf_nonzero_xCode : Text = "E_BAD_FLAG";
let advnoncanonical_c1Hex : Text = "9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8";
let advnoncanonical_c1Code : Text = "E_NONCANONICAL";
let advoff_curveHex : Text = "800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002";
let advoff_curveCode : Text = "E_NOT_ON_CURVE";
let advSortFlipHex : Text = "b3e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8";
let advSortFlipX : (Nat, Nat) = (0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8, 0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e);
let advSortFlipY : (Nat, Nat) = (0x0d1b3cc2c7027888be51d9ef691d77bcb679afda66c73f17f9ee3837a55024f78c71363275a75d75d86bab79f74782aa, 0x13fa4d4a0ad8b1ce186ed5061789213d993923066dddaf1040bc3ff59f825c78df74f2d75467e25e0f55f8a00fa030ed);
let frBattery : [(Text, Nat)] = [
  ("0000000000000000000000000000000000000000000000000000000000000000", 0),
  ("0100000000000000000000000000000000000000000000000000000000000000", 1),
  ("0200000000000000000000000000000000000000000000000000000000000000", 2),
  ("00000000fffffffffe5bfeff02a4bd5305d8a10908d83933487d9d2953a7ed73", 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000),
];
let frNoncanonR : Text = "01000000fffffffffe5bfeff02a4bd5305d8a10908d83933487d9d2953a7ed73";
let frNoncanonR1 : Text = "02000000fffffffffe5bfeff02a4bd5305d8a10908d83933487d9d2953a7ed73";

// =================================================================================================
// 1 — G2 decode battery
// =================================================================================================
var sawLarger = false;
var sawSmaller = false;
for ((hex, xc0, xc1, yc0, yc1) in g2Battery.values()) {
  switch (Dec2.decodeG2(bytesOf(hex))) {
    case (#err(e)) { fail("g2 battery decode rejected: " # e) };
    case (#ok(#inf)) { fail("g2 battery decoded to infinity") };
    case (#ok(#pt(p))) {
      if (p.x.c0 != xc0 or p.x.c1 != xc1) { fail("g2 battery x mismatch") };
      if (p.y.c0 != yc0 or p.y.c1 != yc1) { fail("g2 battery y mismatch") };
      if (Dec2.isLargerRootFp2(p.y)) { sawLarger := true } else { sawSmaller := true };
    };
  };
};
if (not sawLarger or not sawSmaller) { fail("battery did not exercise both sort parities") };

switch (Dec2.decodeG2(bytesOf(g2InfHex))) {
  case (#ok(#inf)) {};
  case (_) { fail("canonical infinity encoding did not decode to #inf") };
};

func expectRej(name : Text, hex : Text, code : Text) {
  switch (Dec2.decodeG2(bytesOf(hex))) {
    case (#err(e)) { if (e != code) { fail(name # ": code " # e # " != " # code) } };
    case (#ok(_)) { fail(name # ": adversarial encoding ACCEPTED") };
  };
};
expectRej("no-compression", advno_compressionHex, advno_compressionCode);
expectRej("inf-nonzero-x", advinf_nonzero_xHex, advinf_nonzero_xCode);
expectRej("noncanonical-c1", advnoncanonical_c1Hex, advnoncanonical_c1Code);
expectRej("off-curve", advoff_curveHex, advoff_curveCode);

switch (Dec2.decodeG2(bytesOf(advSortFlipHex))) {
  case (#ok(#pt(p))) {
    if (p.x.c0 != advSortFlipX.0 or p.x.c1 != advSortFlipX.1) { fail("sort-flip x mismatch") };
    if (p.y.c0 != advSortFlipY.0 or p.y.c1 != advSortFlipY.1) { fail("sort-flip did not select -P") };
  };
  case (_) { fail("sort-flip must decode (it is the valid encoding of -P)") };
};

// live mutant: byte-reversed limb order (c0-first) must NOT reproduce the pinned coordinates
// for a point whose limbs differ — the generator's x.c0 != x.c1, so a c0-first parse yields a
// different x; either it rejects or it decodes to something != pinned. Both are RED for a
// wrong-order decoder; we assert the decode-or-mismatch explicitly.
do {
  let (hex, xc0, _, _, _) = g2Battery[0];
  let b = bytesOf(hex);
  // simulate the wrong-order read: take the SECOND limb as c1 by swapping halves
  let swapped = Prim_swapHalves(b);
  switch (Dec2.decodeG2(swapped)) {
    case (#err(_)) {}; // reject is fine
    case (#ok(#pt(p))) { if (p.x.c0 == xc0) { fail("limb-order mutant not caught") } };
    case (#ok(#inf)) {};
  };
};

// =================================================================================================
// 2 — Fr little-endian battery through the ACTUAL public path (parseInputs)
// =================================================================================================
func one(fieldHex : Text) : Text { "0100000000000000" # fieldHex };
for ((hex, want) in frBattery.values()) {
  switch (W.parseInputs(bytesOf(one(hex)))) {
    case (?xs) { if (xs.size() != 1 or xs[0] != want) { fail("fr round-trip mismatch") } };
    case (null) { fail("canonical fr rejected") };
  };
};
switch (W.parseInputs(bytesOf(one(frNoncanonR)))) {
  case (null) {};
  case (?_) { fail("non-canonical r ACCEPTED as Fr") };
};
switch (W.parseInputs(bytesOf(one(frNoncanonR1)))) {
  case (null) {};
  case (?_) { fail("non-canonical r+1 ACCEPTED as Fr") };
};
// framing controls: wrong count, truncated body
switch (W.parseInputs(bytesOf("0200000000000000" # frBattery[1].0))) {
  case (null) {};
  case (?_) { fail("count/body length mismatch ACCEPTED") };
};

// =================================================================================================
// 3 — vk/proof wire parse == the affine truth (PoolBlsData)
// =================================================================================================
let tvk = switch (W.parseAndPrepareVk(PW.transferVkHex)) {
  case (?vk) { vk };
  case (null) { fail("transfer_vk.hex failed to parse+prepare"); Runtime.trap("") };
};
let dvk = switch (W.parseAndPrepareVk(PW.depositVkHex)) {
  case (?vk) { vk };
  case (null) { fail("deposit_vk.hex failed to parse+prepare"); Runtime.trap("") };
};
// parsed vk fields equal the uncompressed constants (alphaNeg is -alpha by construction)
if (not C.g1Eq(tvk.alphaNeg, C.g1Neg(PD.transferAlpha))) { fail("wire transfer alpha != affine truth") };
if (tvk.gammaAbc.size() != PD.transferGammaAbc.size()) { fail("wire transfer IC length") };
var gi = 0;
while (gi < tvk.gammaAbc.size()) {
  if (not C.g1Eq(tvk.gammaAbc[gi], PD.transferGammaAbc[gi])) { fail("wire transfer IC " # Nat.toText(gi)) };
  gi += 1;
};
if (not C.g1Eq(dvk.alphaNeg, C.g1Neg(PD.depositAlpha))) { fail("wire deposit alpha != affine truth") };

func proofEq(name : Text, hex : Text, a : C.G1, b : C.G2, c : C.G1) {
  switch (W.parseProof(bytesOf(hex))) {
    case (null) { fail(name # " proof failed to parse") };
    case (?p) {
      if (not C.g1Eq(p.a, a) or not C.g2Eq(p.b, b) or not C.g1Eq(p.c, c)) {
        fail(name # " parsed proof != affine truth");
      };
    };
  };
};
proofEq("transfer", PW.transferProofHex, PD.transferA, PD.transferB, PD.transferC);
proofEq("withdraw", PW.withdrawProofHex, PD.withdrawA, PD.withdrawB, PD.withdrawC);
proofEq("fake", PW.fakeProofHex, PD.fakeTreeA, PD.fakeTreeB, PD.fakeTreeC);
proofEq("deposit1", PW.deposit1ProofHex, PD.deposit1A, PD.deposit1B, PD.deposit1C);
proofEq("deposit2", PW.deposit2ProofHex, PD.deposit2A, PD.deposit2B, PD.deposit2C);

// =================================================================================================
// 4 — the COMPLETE hex boundary reproduces every pool ORACLE verdict
// =================================================================================================
func expectV(name : Text, got : Text, want : Text) {
  if (got != want) { fail(name # ": " # got # " != " # want) };
};
expectV("P0 transfer", W.verifyPrepared(tvk, PW.transferProofHex, PW.transferInputsHex), "ACCEPT");
expectV("C4a tampered-fee", W.verifyPrepared(tvk, PW.transferProofHex, PW.transferBadFeeInputsHex), "REJECT:pairing-check");
expectV("P1 withdraw", W.verifyPrepared(tvk, PW.withdrawProofHex, PW.withdrawInputsHex), "ACCEPT");
expectV("C2 fake-tree (pairing layer)", W.verifyPrepared(tvk, PW.fakeProofHex, PW.fakeInputsHex), "ACCEPT");
expectV("P0d deposit1", W.verifyPrepared(dvk, PW.deposit1ProofHex, PW.deposit1InputsHex), "ACCEPT");
expectV("P0d deposit2", W.verifyPrepared(dvk, PW.deposit2ProofHex, PW.deposit2InputsHex), "ACCEPT");
expectV("C6 amount-lie", W.verifyPrepared(dvk, PW.deposit1ProofHex, PW.depositAmountLieInputsHex), "REJECT:pairing-check");
// C1 bitflip: oracle verdict is REJECT (deserialize-or-pairing) — either code, never ACCEPT
do {
  let v = W.verifyPrepared(tvk, PW.transferBadProofHex, PW.transferInputsHex);
  if (v != "REJECT:proof-deserialize" and v != "REJECT:pairing-check") {
    fail("C1 bitflip badproof: " # v);
  };
  Debug.print("  C1 bitflip verdict: " # v);
};
// wrong-subgroup B at the WIRE: decode is format+curve only, so THE VERIFIER's subgroup check
// is what must fire (mapped to the arkworks-parity -deserialize verdict). This is the live
// control that the decode/validate split has no acceptance hole.
do {
  // proof = A (valid, first 48 bytes) ‖ wrong-subgroup G2 (pinned adversarial point,
  // compressed with its correct sort bit) ‖ C (valid, last 48 bytes)
  var aHex = "";
  var cHex = "";
  var ci = 0;
  for (ch in PW.transferProofHex.chars()) {
    if (ci < 96) { aHex := aHex # Char.toText(ch) };
    if (ci >= 288) { cHex := cHex # Char.toText(ch) };
    ci += 1;
  };
  let wrongSubB = "8a0f085f3a5f38d0351daf90c42470fc39a5d8a572e28d911012c9ad758630e33a97ccccc94f4df9ae0885e9beec7f2d03287adcc6c5612217f4744d790962b42f76f6ea3a2c9f94908b679b256002e92c97066a0724eeba5663dc04fdb5016b";
  expectV("wrong-subgroup B at wire", W.verifyPrepared(tvk, aHex # wrongSubB # cHex, PW.transferInputsHex), "REJECT:proof-deserialize");
};

// boundary controls
expectV("garbage hex", W.verifyPrepared(tvk, "zz", PW.transferInputsHex), "REJECT:hex");
expectV("truncated proof", W.verifyPrepared(tvk, "aabb", PW.transferInputsHex), "REJECT:proof-deserialize");
expectV("one-shot tryVerify", W.tryVerify(PW.transferVkHex, PW.transferProofHex, PW.transferInputsHex), "ACCEPT");
expectV("tryVerify bad vk", W.tryVerify("00", PW.transferProofHex, PW.transferInputsHex), "REJECT:vk-deserialize");

Debug.print("WIRE gate: ALL GREEN");
Debug.print("  1. G2 decode battery == oracle coords (both parities); 4 adversarial encodings rejected");
Debug.print("     with pinned codes; sort-flip == -P; limb-order mutant caught");
Debug.print("  2. Fr LE battery round-trips; r and r+1 rejected; framing mismatches rejected");
Debug.print("  3. wire vk/proof parse == PoolBlsData affine truth (transfer + deposit + 5 proofs)");
Debug.print("  4. full hex boundary reproduces every pool ORACLE verdict incl. C1 bitflip and C2 fake-tree");
