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
import VarArray "mo:core/VarArray";
import FpM "FpMont";
import TM "TowerMont";
import C "Curve";
import CF "CurveFlat";
import CJ "CurveJac";
import FF "FpFlat";
import PFl "PairingFlat";
import PP "PairingProjective";
import PF "PairingFinalExp";
import TFl "TowerFlat";

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
  /// Flat point validation — same predicate order and codes as CJ.g1Validate/g2Validate
  /// (canonical + on-curve are the unchanged L1/L2 predicates; the [r]P subgroup half runs on
  /// the gate-proven flat backend so vk registration no longer allocates ~500 MB of Nat churn).
  func validateG1Flat(z : [var Nat32], p : C.G1) : ?Text {
    if (not C.g1IsCanonical(p)) { return ?"E_NONCANONICAL" };
    if (not C.g1IsOnCurve(p)) { return ?"E_NOT_ON_CURVE" };
    CF.g1FromAffineInto(z, 576, p, ARENA_S);
    if (not CF.g1InSubgroup(z, 576, 0, ARENA_S)) { return ?"E_NOT_IN_SUBGROUP" };
    null
  };
  func validateG2Flat(z : [var Nat32], p : C.G2) : ?Text {
    if (not C.g2IsCanonical(p)) { return ?"E_NONCANONICAL" };
    if (not C.g2IsOnCurve(p)) { return ?"E_NOT_ON_CURVE" };
    CF.g2FromAffineInto(z, 240, p, ARENA_S);
    if (not CF.g2InSubgroup(z, 240, 36, ARENA_S)) { return ?"E_NOT_IN_SUBGROUP" };
    null
  };

  public func prepareVk(
    alpha : C.G1, beta : C.G2, gamma : C.G2, delta : C.G2, gammaAbc : [C.G1]
  ) : { #ok : PreparedVk; #err : Text } {
    let z = VarArray.repeat<Nat32>(0, 8640);
    switch (validateG1Flat(z, alpha)) { case (?e) { return #err("alpha:" # e) }; case null {} };
    switch (validateG2Flat(z, beta)) { case (?e) { return #err("beta:" # e) }; case null {} };
    switch (validateG2Flat(z, gamma)) { case (?e) { return #err("gamma:" # e) }; case null {} };
    switch (validateG2Flat(z, delta)) { case (?e) { return #err("delta:" # e) }; case null {} };
    for (p in gammaAbc.vals()) {
      switch (validateG1Flat(z, p)) { case (?e) { return #err("gamma_abc:" # e) }; case null {} };
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

  /// The COMPLETE per-proof verifier — allocation-flat pipeline.
  ///
  /// Same statement, same validation order, same verdict codes, same pair schedule and final
  /// exponentiation as `verifyReference` below (the original record-based L2 assembly, kept
  /// verbatim as the in-repo differential anchor). The only change is HOW values are stored:
  /// one arena allocation per call, every field/curve/pairing operation in place via the L3
  /// flat backend (FpFlat/TowerFlat/CurveFlat/PairingFlat), each layer of which is
  /// differential-gated against its L2 anchor. A full-verify differential test additionally proves verdict parity
  /// of THIS function against `verifyReference` on the frozen fixture + adversarial classes.
  //
  // Arena layout (limb offsets; scratch base S = 20232, total 23328 limbs ≈ one ~190 KB
  // allocation per verify — replacing ~460 MB of immutable-record churn):
  //   0     G1 subgroup scratch point (36)      36    G2 subgroup scratch point (72)
  //   108   A affine Mont px/py (24)            132   −C affine Mont px/py (24)
  //   156   vk_x Jacobian (36)                  192   −vk_x affine Mont px/py (24)
  //   216   alphaNeg affine Mont px/py (24)     240   B affine Mont (48)
  //   288   Miller f (144)                      432   final-exp output (144)
  //   576   MSM accumulator Jacobian (36)       612   MSM point / conversion spare (36)
  //   648   B prepared (4896)
  //   (beta/gamma/delta prepared limbs live in the FlatVk cache arrays, not the arena)
  let ARENA_S : Nat = 5544;

  func loadG1AffineMont(z : [var Nat32], d : Nat, p : { x : Nat; y : Nat }) {
    FF.fromNat(p.x, z, 612);
    FF.toMontInto(z, d, z, 612, z, 624, z, ARENA_S);
    FF.fromNat(p.y, z, 612);
    FF.toMontInto(z, d + 12, z, 612, z, 624, z, ARENA_S);
  };

  /// The fixed verifying-key preparations converted ONCE to flat limbs (18.7 MB of Nat→limb
  /// conversion per verify when done inline — measured). An empty array marks an
  /// infinity preparation (dead pair). Held by the ledger actor in a TRANSIENT cache that is
  /// invalidated at every vk write site and wiped by upgrades — it is a pure deterministic
  /// function of the PreparedVk, never persisted.
  public type FlatVk = {
    beta : [var Nat32];
    gamma : [var Nat32];
    delta : [var Nat32];
  };

  func prepToLimbs(prep : PP.G2Prepared) : [var Nat32] {
    if (prep.infinity) { return VarArray.repeat<Nat32>(0, 0) };
    if (prep.ellCoeffs.size() != PFl.COEFF_COUNT) { Runtime.trap("E_MULTI_COEFF_COUNT") };
    let out = VarArray.repeat<Nat32>(0, PFl.PREPARED_LIMBS);
    var k = 0;
    for (coeff in prep.ellCoeffs.vals()) {
      let o = 72 * k;
      FF.fromNat(coeff.c0.c0, out, o);
      FF.fromNat(coeff.c0.c1, out, o + 12);
      FF.fromNat(coeff.c1.c0, out, o + 24);
      FF.fromNat(coeff.c1.c1, out, o + 36);
      FF.fromNat(coeff.c2.c0, out, o + 48);
      FF.fromNat(coeff.c2.c1, out, o + 60);
      k += 1;
    };
    out
  };

  /// Convert a PreparedVk's fixed pairs to flat limb arrays — run once per vk registration
  /// (or once per post-upgrade lazy rebuild), never per proof.
  public func prepareFlatVk(vk : PreparedVk) : FlatVk {
    {
      beta = prepToLimbs(vk.betaPrep);
      gamma = prepToLimbs(vk.gammaPrep);
      delta = prepToLimbs(vk.deltaPrep);
    }
  };

  /// The COMPLETE per-proof verifier: A/B/C validation (subgroup checks included), vk_x MSM,
  /// per-proof B preparation, interleaved multi-Miller, ONE shared final exponentiation.
  /// Uncached form — converts the fixed vk pairs on the fly. The ledger uses
  /// `verifyWithFlat` with its transient FlatVk cache instead.
  public func verify(vk : PreparedVk, a : C.G1, b : C.G2, c : C.G1, inputs : [Nat]) : Verdict {
    verifyWithFlat(vk, prepareFlatVk(vk), a, b, c, inputs)
  };

  public func verifyWithFlat(vk : PreparedVk, flat : FlatVk, a : C.G1, b : C.G2, c : C.G1, inputs : [Nat]) : Verdict {
    if (vk.gammaAbc.size() != inputs.size() + 1) { return #err("E_BAD_LENGTH") };

    let z = VarArray.repeat<Nat32>(0, 8640); // ARENA_S + PairingFlat scratch (5544 + 3096)
    let s = ARENA_S;

    // A/B/C validation — same order and codes as CJ.g1Validate/g2Validate (canonical and
    // on-curve halves are the unchanged L1/L2 predicates; the [r]P subgroup half is flat).
    // (validateG2Flat leaves B as a Jacobian at 240 for its check; reloaded as affine below.)
    switch (validateG1Flat(z, a)) { case (?e) { return #err("A:" # e) }; case null {} };
    switch (validateG2Flat(z, b)) { case (?e) { return #err("B:" # e) }; case null {} };
    switch (validateG1Flat(z, c)) { case (?e) { return #err("C:" # e) }; case null {} };

    // vk_x = gammaAbc[0] + Σ inputᵢ·gammaAbc[i+1] — flat Jacobian MSM (scalars mod r, as L2).
    CF.g1FromAffineInto(z, 156, vk.gammaAbc[0], s);
    var i = 0;
    while (i < inputs.size()) {
      CF.g1FromAffineInto(z, 612, vk.gammaAbc[i + 1], s);
      CF.g1MulInto(z, 612, 612, CF.scalarLimbs(inputs[i] % C.R), s);
      CF.g1AddInto(z, 156, 156, 612, s);
      i += 1;
    };

    // Pair schedule (order identical to multiMillerRaw):
    //   0: (A, B)   1: (−vk_x, gamma)   2: (−C, delta)   3: (alphaNeg, beta)
    var liveA = false;
    switch (a) {
      case (#inf) {};
      case (#pt(p)) { loadG1AffineMont(z, 108, p); liveA := true };
    };
    var liveB = true;
    switch (b) {
      case (#inf) { liveB := false };
      case (#pt(q)) {
        // B affine Montgomery (x,y as Fp2) at 240, then flat preparation into 648.
        FF.fromNat(q.x.c0, z, 612);
        FF.toMontInto(z, 240, z, 612, z, 624, z, s);
        FF.fromNat(q.x.c1, z, 612);
        FF.toMontInto(z, 252, z, 612, z, 624, z, s);
        FF.fromNat(q.y.c0, z, 612);
        FF.toMontInto(z, 264, z, 612, z, 624, z, s);
        FF.fromNat(q.y.c1, z, 612);
        FF.toMontInto(z, 276, z, 612, z, 624, z, s);
        PFl.prepareG2Into(z, 648, 240, s);
      };
    };
    var liveVkx = false;
    if (not CF.g1IsInf(z, 156)) {
      CF.g1ToAffineInto(z, 192, 204, 156, s);
      FF.negInto(z, 204, z, 204); // −vk_x
      liveVkx := true;
    };
    var liveC = false;
    switch (c) {
      case (#inf) {};
      case (#pt(p)) {
        loadG1AffineMont(z, 132, p);
        FF.negInto(z, 144, z, 144); // −C
        liveC := true;
      };
    };
    var liveAlpha = false;
    switch (vk.alphaNeg) {
      case (#inf) {};
      case (#pt(p)) { loadG1AffineMont(z, 216, p); liveAlpha := true };
    };
    let liveBeta = flat.beta.size() != 0;
    let liveGamma = flat.gamma.size() != 0;
    let liveDelta = flat.delta.size() != 0;

    PFl.multiMillerInto(
      z,
      288,
      [liveA and liveB, liveVkx and liveGamma, liveC and liveDelta, liveAlpha and liveBeta],
      [108, 192, 132, 216],
      [120, 204, 144, 228],
      [z, flat.gamma, flat.delta, flat.beta],
      [648, 0, 0, 0],
      s,
    );
    PFl.finalExponentiateInto(z, 432, 288, s);
    if (TFl.fp12IsOneMont(z, 432)) { #ok } else { #err("E_PAIRING_FAIL") };
  };

  /// The ORIGINAL record-based assembly, kept verbatim as the differential anchor for the flat
  /// `verify` above (the differential tests prove verdict parity; the per-layer tests prove value
  /// identity). Not called by the ledger.
  public func verifyReference(vk : PreparedVk, a : C.G1, b : C.G2, c : C.G1, inputs : [Nat]) : Verdict {
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
