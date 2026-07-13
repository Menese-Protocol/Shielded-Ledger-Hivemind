/// The ASSEMBLED one-message Groth16 verifier.
///
/// Menese DeFi Team. Composition of the proven components:
///   - `PairingProjective`: inversion-free prepared-coefficient Miller steps,
///     here INTERLEAVED so the FOUR Groth16 pairings share ONE Fp12 squaring chain
///     (arkworks 0.5 `multi_miller_loop` shape: one square per doubling step, then one sparse
///     line multiplication per pair);
///   - `PairingFinalExp`: ONE shared cyclotomic final exponentiation over the product —
///     never per pairing;
///   - `CurveJac`: inversion-free vk_x public-input MSM and `[r]P` subgroup checks (the pieces
///     the g10d projection EXCLUDED — included here so the fit verdict is honest).
///
/// The three fixed verifying-key G2 points (beta/gamma/delta) are prepared ONCE via `prepareVk`,
/// outside the per-proof message; only the proof's B is prepared per proof. −alpha is negated once.
///
/// Verify equation (arkworks convention, product form):
///   e(A,B) · e(−vk_x, γ) · e(−C, δ) · e(−α, β) == 1,   vk_x = γ_abc[0] + Σ inputᵢ·γ_abc[i+1]
///
/// Correctness boundary (Groth16MultiTest.mo): the raw multi-Miller Fp12 and the shared final
/// exponentiation are byte-diffed on ALL 12 coefficients against the arkworks multimilleroracle
/// — for the VALID proof and for a FORGED one (non-trivial target) — and the assembled verify
/// must accept the valid proof and reject all four forgery classes.

import List "mo:core/List";
import Runtime "mo:core/Runtime";
import FpM "FpMont";
import TM "TowerMont";
import C "Curve";
import CJ "CurveJac";
import PP "PairingProjective";
import PF "PairingFinalExp";

module {
  public type Verdict = { #ok; #err : Text };

  public type PreparedVk = {
    alphaNeg : C.G1;
    betaPrep : PP.G2Prepared;
    gammaPrep : PP.G2Prepared;
    deltaPrep : PP.G2Prepared;
    gammaAbc : [C.G1];
  };

  /// Validate and prepare the fixed verifying key. Runs once (canister init / vk registration),
  /// so its cost is deliberately OUTSIDE the per-proof message; everything per-proof is in `verify`.
  public func prepareVk(
    alpha : C.G1, beta : C.G2, gamma : C.G2, delta : C.G2, gammaAbc : [C.G1]
  ) : { #ok : PreparedVk; #err : Text } {
    switch (CJ.g1Validate(alpha)) { case (#err(e)) { return #err("alpha:" # e) }; case (#ok) {} };
    switch (CJ.g2Validate(beta)) { case (#err(e)) { return #err("beta:" # e) }; case (#ok) {} };
    switch (CJ.g2Validate(gamma)) { case (#err(e)) { return #err("gamma:" # e) }; case (#ok) {} };
    switch (CJ.g2Validate(delta)) { case (#err(e)) { return #err("delta:" # e) }; case (#ok) {} };
    for (p in gammaAbc.vals()) {
      switch (CJ.g1Validate(p)) { case (#err(e)) { return #err("gamma_abc:" # e) }; case (#ok) {} };
    };
    #ok({
      alphaNeg = C.g1Neg(alpha);
      betaPrep = PP.prepareG2(beta);
      gammaPrep = PP.prepareG2(gamma);
      deltaPrep = PP.prepareG2(delta);
      gammaAbc;
    });
  };

  /// Interleaved Miller loop: ONE shared Fp12 squaring chain, one sparse line multiplication per
  /// live pair per step. Equal by construction to the product of the per-pair Miller values
  /// ((f·g)² = f²·g²), which the gate checks explicitly on the real proof.
  public func multiMillerLoopPrepared(pairs : [(C.G1, PP.G2Prepared)]) : TM.Fp12M {
    // Pairs with an infinite side contribute the constant 1 — drop them up front.
    let liveList = List.empty<(Nat, Nat, PP.G2Prepared)>();
    for ((p, q) in pairs.values()) {
      switch (p) {
        case (#inf) {};
        case (#pt(pp)) {
          if (not q.infinity) {
            List.add(liveList, (FpM.toMont(pp.x), FpM.toMont(pp.y), q));
          };
        };
      };
    };
    let live = List.toArray(liveList);
    var f = TM.fp12OneM();
    if (live.size() == 0) { return f };
    let n = live[0].2.ellCoeffs.size();
    for ((_, _, q) in live.values()) {
      if (q.ellCoeffs.size() != n) { Runtime.trap("E_MULTI_COEFF_COUNT") };
    };
    var at : Nat = 0;
    var i : Nat = bitLen(PP.X_ABS) - 1;
    while (i > 0) {
      i -= 1;
      f := TM.fp12SqrFast(f);
      for ((px, py, q) in live.values()) { f := PP.ell(f, q.ellCoeffs[at], px, py) };
      at += 1;
      if (bitAt(PP.X_ABS, i)) {
        for ((px, py, q) in live.values()) { f := PP.ell(f, q.ellCoeffs[at], px, py) };
        at += 1;
      };
    };
    if (at != n) { Runtime.trap("E_MULTI_SCHEDULE") };
    if (PP.X_IS_NEGATIVE) { TM.fp12Conj(f) } else { f };
  };

  /// The raw four-pair Groth16 Miller product, before the shared final exponentiation.
  /// Exposed separately so the gate can byte-diff this exact intermediate against the oracle.
  public func multiMillerRaw(vk : PreparedVk, a : C.G1, bPrep : PP.G2Prepared, c : C.G1, vkx : C.G1) : TM.Fp12M {
    multiMillerLoopPrepared([
      (a, bPrep),
      (C.g1Neg(vkx), vk.gammaPrep),
      (C.g1Neg(c), vk.deltaPrep),
      (vk.alphaNeg, vk.betaPrep),
    ]);
  };

  /// The COMPLETE per-proof verifier: A/B/C validation (subgroup checks included), vk_x MSM,
  /// per-proof B preparation, interleaved multi-Miller, ONE shared final exponentiation.
  public func verify(vk : PreparedVk, a : C.G1, b : C.G2, c : C.G1, inputs : [Nat]) : Verdict {
    if (vk.gammaAbc.size() != inputs.size() + 1) { return #err("E_BAD_LENGTH") };
    switch (CJ.g1Validate(a)) { case (#err(e)) { return #err("A:" # e) }; case (#ok) {} };
    switch (CJ.g2Validate(b)) { case (#err(e)) { return #err("B:" # e) }; case (#ok) {} };
    switch (CJ.g1Validate(c)) { case (#err(e)) { return #err("C:" # e) }; case (#ok) {} };

    let vkx = CJ.vkX(vk.gammaAbc, inputs);
    let bPrep = PP.prepareG2(b);
    let raw = multiMillerRaw(vk, a, bPrep, c, vkx);
    let out = PF.finalExponentiate(raw);
    if (TM.fp12Eq(out, TM.fp12OneM())) { #ok } else { #err("E_PAIRING_FAIL") };
  };

  func bitLen(n : Nat) : Nat {
    var v = n; var b : Nat = 0;
    while (v > 0) { b += 1; v /= 2 };
    b;
  };
  func bitAt(n : Nat, i : Nat) : Bool { (n / (2 ** i)) % 2 == 1 };
}
