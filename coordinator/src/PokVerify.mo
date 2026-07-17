/// On-chain proof-of-knowledge verification for one Phase-2 contribution (the soundness-critical,
/// O(1)-pairing check the coordinator runs at acceptance). This is an INDEPENDENT Motoko
/// implementation of the same BGM17 same-ratio check the Rust `ceremony::verify::verify_pok`
/// performs; the standalone verifier additionally runs the full off-chain division check, which is
/// deliberately NOT done here (it would need multi-scalar multiplications over ~53k points, beyond
/// the IC per-message limit).
///
/// Given the previous running challenge, the accumulated delta_g1 the contributor started from, the
/// new delta points, and the PoK, it checks:
///   (1) e(s_g1, r_delta_g2) == e(s_delta_g1, r_g2)         same ratio in G1 and G2 = the applied d
///   (2) e(delta_after, r_g2) == e(delta_before, r_delta_g2) delta advanced by that same d
///   (3) e(delta_after_g1, G2) == e(G1, delta_after_g2)      delta_g1 and delta_g2 agree
/// where r_g2 = c*G2 and c = hash_to_fr(prev || s_g1 || s_delta_g1 || delta_after_g1). Only the five
/// O(1) points are subgroup-validated; the query points are validated off-chain.

import C "../../src/groth16/Curve";
import CJ "../../src/groth16/CurveJac";
import PP "../../src/groth16/PairingProjective";
import PF "../../src/groth16/PairingFinalExp";
import GM "../../src/groth16/Groth16Multi";
import TM "../../src/groth16/TowerMont";
import Fr "../../src/groth16/Fr";
import Wire "Wire";

module {
  public type Pok = { sG1 : C.G1; sDeltaG1 : C.G1; rDeltaG2 : C.G2 };
  public type NewDelta = { deltaG1 : C.G1; deltaG2 : C.G2 };

  /// The standard BLS12-381 G2 generator (IETF / Zcash spec). Self-checked at canister init.
  public let g2Gen : C.G2 = #pt({
    x = {
      c0 = 0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8;
      c1 = 0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e;
    };
    y = {
      c0 = 0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801;
      c1 = 0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be;
    };
  });

  /// The three same-ratio checks, reduced to a THREE-pair multi-Miller + ONE final exponentiation
  /// with only cheap G1 scalar multiplications and NO on-chain G2 scalar multiplication. This keeps
  /// a single contribution's on-chain verification well inside the IC 40e9-instruction per-message
  /// limit (in pure-Nat BLS12-381 a G2 scalar mul alone would blow it).
  ///
  /// Two algebraic moves make it fit:
  ///  (i) the challenge point r_g2 = c*G2 (c a known scalar) is never formed on-chain; instead c is
  ///      folded into the G1 side of every pairing that used r_g2 (e(P, c*G2) = e(c*P, G2));
  ///  (ii) the three checks are combined with Fiat-Shamir coefficients (1, rho, rho^2) and the
  ///      pairings sharing a G2 argument are merged, collapsing to three pairs:
  ///        e(A, r_delta) * e(B, G2) * e(-rho^2 * G1, delta_after_g2) == 1,  where
  ///        A = s_g1 - rho * delta_before,
  ///        B = (rho*c + rho^2) * delta_after - c * s_delta_g1.
  /// Soundness error <= 2/r (rho is unpredictable to the prover, hashed from all the points).
  func batchedChecksPass(
    oldDeltaG1 : C.G1,
    new : NewDelta,
    pok : Pok,
    c : Nat,
  ) : Bool {
    let pre = Wire.concat([
      Wire.g1BE(pok.sG1), Wire.g1BE(pok.sDeltaG1), Wire.g1BE(new.deltaG1), Wire.g1BE(oldDeltaG1),
      Wire.g2BE(new.deltaG2), Wire.g2BE(pok.rDeltaG2),
    ]);
    let rho = Wire.hashToFr(pre);
    let rho2 = Fr.mul(rho, rho);
    let coefB = Fr.add(Fr.mul(rho, c), rho2);

    let a = C.g1Add(pok.sG1, C.g1Neg(C.g1Mul(oldDeltaG1, rho)));
    let b = C.g1Add(C.g1Mul(new.deltaG1, coefB), C.g1Neg(C.g1Mul(pok.sDeltaG1, c)));
    let third = C.g1Neg(C.g1Mul(C.g1Gen, rho2));

    let pairs : [(C.G1, PP.G2Prepared)] = [
      (a, PP.prepareG2(pok.rDeltaG2)),
      (b, PP.prepareG2(g2Gen)),
      (third, PP.prepareG2(new.deltaG2)),
    ];
    TM.fp12Eq(PF.finalExponentiate(GM.multiMillerLoopPrepared(pairs)), TM.fp12OneM());
  };

  /// Validate the g2 generator once (call at init).
  public func selfCheckGenerator() : Bool {
    switch (CJ.g2Validate(g2Gen)) { case (#ok) { true }; case (#err(_)) { false } };
  };

  // ---------------------------------------------------------------------------------------------
  // Structural checks — the AFFORDABLE on-chain check.
  //
  // MEASURED: a full proof-of-knowledge verification (subgroup checks are literal [r]P scalar
  // multiplications, plus a three-pair pairing) costs well over the IC 40e9-instruction
  // single-message limit in this pure-Nat BLS12-381 tower, even for one circuit and even before the
  // pairing. Per the ceremony proposal's decision (b), the coordinator therefore runs the CHEAP
  // structural checks on-chain (canonical encoding, on the curve, non-identity) and records the
  // proof; the SOUNDNESS-critical subgroup + pairing verification is run off-chain by the standalone
  // verifier (which re-runs exactly `verifyPok`'s math in arkworks over the published transcript).
  // `verifyPok` above is retained as the reference implementation and is cross-checked against the
  // Rust reference by coordinator/test/PokVectorTest.mo.
  // ---------------------------------------------------------------------------------------------

  public func structuralG1(p : C.G1) : { #ok; #err : Text } {
    switch (p) { case (#inf) { return #err("E_IDENTITY") }; case (#pt(_)) {} };
    if (not C.g1IsCanonical(p)) { return #err("E_NONCANONICAL") };
    if (not C.g1IsOnCurve(p)) { return #err("E_NOT_ON_CURVE") };
    #ok;
  };
  public func structuralG2(p : C.G2) : { #ok; #err : Text } {
    switch (p) { case (#inf) { return #err("E_IDENTITY") }; case (#pt(_)) {} };
    if (not C.g2IsCanonical(p)) { return #err("E_NONCANONICAL") };
    if (not C.g2IsOnCurve(p)) { return #err("E_NOT_ON_CURVE") };
    #ok;
  };

  /// The affordable per-contribution on-chain check: all five points are canonical, on the curve,
  /// and not the identity, and the delta actually advanced. Subgroup membership and the pairing
  /// relations are verified off-chain.
  public func structuralCheck(oldDeltaG1 : C.G1, new : NewDelta, pok : Pok) : { #ok; #err : Text } {
    switch (structuralG1(pok.sG1)) { case (#err(e)) { return #err("s_g1:" # e) }; case (#ok) {} };
    switch (structuralG1(pok.sDeltaG1)) { case (#err(e)) { return #err("s_delta_g1:" # e) }; case (#ok) {} };
    switch (structuralG2(pok.rDeltaG2)) { case (#err(e)) { return #err("r_delta_g2:" # e) }; case (#ok) {} };
    switch (structuralG1(new.deltaG1)) { case (#err(e)) { return #err("delta_g1:" # e) }; case (#ok) {} };
    switch (structuralG2(new.deltaG2)) { case (#err(e)) { return #err("delta_g2:" # e) }; case (#ok) {} };
    if (C.g1Eq(new.deltaG1, oldDeltaG1)) { return #err("identity contribution (delta unchanged)") };
    #ok;
  };

  /// The cheap on-chain PoK check. `prevChallenge` is 32 bytes; `oldDeltaG1` is the accumulated
  /// delta_g1 before this contribution. Returns #ok or #err with the failing step.
  public func verifyPok(
    prevChallenge : [Nat8],
    oldDeltaG1 : C.G1,
    new : NewDelta,
    pok : Pok,
  ) : { #ok; #err : Text } {
    // Validate the O(1) points (on curve, canonical, in the prime-order subgroup, not identity).
    switch (CJ.g1Validate(pok.sG1)) { case (#err(e)) { return #err("s_g1:" # e) }; case (#ok) {} };
    switch (CJ.g1Validate(pok.sDeltaG1)) { case (#err(e)) { return #err("s_delta_g1:" # e) }; case (#ok) {} };
    switch (CJ.g2Validate(pok.rDeltaG2)) { case (#err(e)) { return #err("r_delta_g2:" # e) }; case (#ok) {} };
    switch (CJ.g1Validate(new.deltaG1)) { case (#err(e)) { return #err("delta_g1:" # e) }; case (#ok) {} };
    switch (CJ.g2Validate(new.deltaG2)) { case (#err(e)) { return #err("delta_g2:" # e) }; case (#ok) {} };

    // Reject the identity contribution (delta unchanged).
    if (C.g1Eq(new.deltaG1, oldDeltaG1)) { return #err("identity contribution (delta unchanged)") };

    // c = hash_to_fr(prev || s_g1 || s_delta_g1 || delta_after_g1). r_g2 = c*G2 is never formed
    // on-chain; c is folded into the G1 side of the batched check below.
    let pre = Wire.concat([prevChallenge, Wire.g1BE(pok.sG1), Wire.g1BE(pok.sDeltaG1), Wire.g1BE(new.deltaG1)]);
    let c = Wire.hashToFr(pre);

    if (not batchedChecksPass(oldDeltaG1, new, pok, c)) {
      return #err("PoK verification failed (batched same-ratio check)");
    };
    #ok;
  };

  /// Beacon step: additionally confirm the delta advanced by exactly the PUBLIC beacon secret
  /// d = hash_to_fr("beacon" || beacon), which anyone can recompute.
  public func verifyBeaconStep(
    prevChallenge : [Nat8],
    oldDeltaG1 : C.G1,
    new : NewDelta,
    pok : Pok,
    beacon : [Nat8],
  ) : { #ok; #err : Text } {
    switch (verifyPok(prevChallenge, oldDeltaG1, new, pok)) {
      case (#err(e)) { return #err(e) };
      case (#ok) {};
    };
    let d = beaconSecret(beacon);
    let expect = C.g1Mul(oldDeltaG1, d);
    if (not C.g1Eq(expect, new.deltaG1)) {
      return #err("beacon delta_g1 does not match the public beacon secret");
    };
    #ok;
  };

  /// d = hash_to_fr("beacon" || beacon). Public and reproducible.
  public func beaconSecret(beacon : [Nat8]) : Nat {
    let tag : [Nat8] = [0x62, 0x65, 0x61, 0x63, 0x6f, 0x6e]; // "beacon"
    let d = Wire.hashToFr(Wire.concat([tag, beacon]));
    if (d == 0) { 2 } else { d };
  };
}
