/// Inversion-free BLS12-381 Miller loop with reusable G2 preparation.
///
/// Menese DeFi Team. This is a literal Motoko port of the homogeneous-projective line formulas in
/// `ark-ec 0.5.0/src/models/bls12/g2.rs` (ePrint 2013/722), plus ark-ff's sparse `mul_by_014` line
/// multiplication.  It keeps the proven Montgomery field/tower and removes the affine L2 loop's
/// Fp12 inversion at every doubling/addition step.
///
/// Correctness boundary:
/// - `prepareG2` uses arkworks' exact 68-coefficient schedule and projective formulas.
/// - The composed `millerLoopPrepared` is byte-diffed on the FULL 12-coefficient raw Miller output,
///   before final exponentiation, against the pinned arkworks oracle.
/// - Fixed verifying-key G2 points can be prepared once and reused; the proof's variable B is
///   prepared per proof.  Measurement reports both prepared-loop-only and prepare+loop costs.

import Array "mo:core/Array";
import Runtime "mo:core/Runtime";
import VarArray "mo:core/VarArray";
import FpM "FpMont";
import TM "TowerMont";
import C "Curve";
import PM "PairingMont";

module {
  public let X_ABS : Nat = 0xd201000000010000;
  public let X_IS_NEGATIVE : Bool = true;

  public type EllCoeff = { c0 : TM.Fp2M; c1 : TM.Fp2M; c2 : TM.Fp2M };
  public type G2Prepared = { ellCoeffs : [EllCoeff]; infinity : Bool };
  type G2HomProjective = { x : TM.Fp2M; y : TM.Fp2M; z : TM.Fp2M };

  let zero2 : TM.Fp2M = { c0 = 0; c1 = 0 };
  let zeroCoeff : EllCoeff = { c0 = zero2; c1 = zero2; c2 = zero2 };

  func fp2Double(a : TM.Fp2M) : TM.Fp2M { TM.fp2Add(a, a) };
  func fp2Triple(a : TM.Fp2M) : TM.Fp2M { TM.fp2Add(fp2Double(a), a) };
  func twoInvM() : Nat { FpM.toMont((FpM.P + 1) / 2) };
  func twistBM() : TM.Fp2M { { c0 = FpM.toMont(4); c1 = FpM.toMont(4) } };

  /// ark-ec 0.5 `G2HomProjective::double_in_place`, TwistType::M.
  func doubleStep(r : G2HomProjective) : (G2HomProjective, EllCoeff) {
    let a = TM.fp2MulByFp(TM.fp2Mul(r.x, r.y), twoInvM());
    let b = TM.fp2SqrFast(r.y);
    let c = TM.fp2SqrFast(r.z);
    let e = TM.fp2Mul(twistBM(), fp2Triple(c));
    let f = fp2Triple(e);
    let g = TM.fp2MulByFp(TM.fp2Add(b, f), twoInvM());
    let h = TM.fp2Sub(TM.fp2SqrFast(TM.fp2Add(r.y, r.z)), TM.fp2Add(b, c));
    let i = TM.fp2Sub(e, b);
    let j = TM.fp2SqrFast(r.x);
    let eSquare = TM.fp2SqrFast(e);
    let next : G2HomProjective = {
      x = TM.fp2Mul(a, TM.fp2Sub(b, f));
      y = TM.fp2Sub(TM.fp2SqrFast(g), fp2Triple(eSquare));
      z = TM.fp2Mul(b, h);
    };
    (next, { c0 = i; c1 = fp2Triple(j); c2 = TM.fp2Neg(h) });
  };

  /// ark-ec 0.5 `G2HomProjective::add_in_place`, TwistType::M.
  func addStep(r : G2HomProjective, qx : TM.Fp2M, qy : TM.Fp2M) : (G2HomProjective, EllCoeff) {
    let theta = TM.fp2Sub(r.y, TM.fp2Mul(qy, r.z));
    let lambda = TM.fp2Sub(r.x, TM.fp2Mul(qx, r.z));
    let c = TM.fp2SqrFast(theta);
    let d = TM.fp2SqrFast(lambda);
    let e = TM.fp2Mul(lambda, d);
    let f = TM.fp2Mul(r.z, c);
    let g = TM.fp2Mul(r.x, d);
    let h = TM.fp2Sub(TM.fp2Add(e, f), fp2Double(g));
    let next : G2HomProjective = {
      x = TM.fp2Mul(lambda, h);
      y = TM.fp2Sub(TM.fp2Mul(theta, TM.fp2Sub(g, h)), TM.fp2Mul(e, r.y));
      z = TM.fp2Mul(r.z, e);
    };
    let j = TM.fp2Sub(TM.fp2Mul(theta, qx), TM.fp2Mul(lambda, qy));
    (next, { c0 = j; c1 = TM.fp2Neg(theta); c2 = lambda });
  };

  public func coefficientCount() : Nat {
    bitLen(X_ABS) - 1 + popCount(X_ABS) - 1;
  };

  /// Prepare a G2 point into reusable projective line coefficients.  No inversions.
  public func prepareG2(q : C.G2) : G2Prepared {
    switch (q) {
      case (#inf) { { ellCoeffs = []; infinity = true } };
      case (#pt(p)) {
        let qx = TM.toM2(p.x);
        let qy = TM.toM2(p.y);
        var r : G2HomProjective = { x = qx; y = qy; z = TM.fp2OneM() };
        let coeffs = VarArray.repeat<EllCoeff>(zeroCoeff, coefficientCount());
        var at : Nat = 0;
        var i : Nat = bitLen(X_ABS) - 1;
        while (i > 0) {
          i -= 1;
          let (rd, dc) = doubleStep(r);
          r := rd;
          coeffs[at] := dc;
          at += 1;
          if (bitAt(X_ABS, i)) {
            let (ra, ac) = addStep(r, qx, qy);
            r := ra;
            coeffs[at] := ac;
            at += 1;
          };
        };
        if (at != coeffs.size()) { Runtime.trap("E_PREP_COEFF_COUNT") };
        { ellCoeffs = Array.fromVarArray<EllCoeff>(coeffs); infinity = false };
      };
    };
  };

  /// Evaluate one prepared M-twist line at a G1 affine point and multiply it sparsely into `f`.
  /// Public so the multi-Miller interleave in `Groth16Multi` uses THIS formula, not a second copy of it.
  public func ell(f : TM.Fp12M, c : EllCoeff, pxM : Nat, pyM : Nat) : TM.Fp12M {
    let c1 = TM.fp2MulByFp(c.c1, pxM);
    let c4 = TM.fp2MulByFp(c.c2, pyM);
    TM.fp12MulBy014(f, c.c0, c1, c4);
  };

  /// Inversion-free Miller loop over already-prepared G2 coefficients.
  public func millerLoopPrepared(p : C.G1, q : G2Prepared) : TM.Fp12M {
    switch (p) {
      case (#inf) { TM.fp12OneM() };
      case (#pt(pp)) {
        if (q.infinity) { return TM.fp12OneM() };
        let pxM = FpM.toMont(pp.x);
        let pyM = FpM.toMont(pp.y);
        var f = TM.fp12OneM();
        var at : Nat = 0;
        var i : Nat = bitLen(X_ABS) - 1;
        while (i > 0) {
          i -= 1;
          f := ell(TM.fp12SqrFast(f), q.ellCoeffs[at], pxM, pyM);
          at += 1;
          if (bitAt(X_ABS, i)) {
            f := ell(f, q.ellCoeffs[at], pxM, pyM);
            at += 1;
          };
        };
        if (at != q.ellCoeffs.size()) { Runtime.trap("E_MILLER_COEFF_COUNT") };
        if (X_IS_NEGATIVE) { TM.fp12Conj(f) } else { f };
      };
    };
  };

  /// Variable-pair convenience path: preparation cost is included by callers that meter this call.
  public func millerLoop(p : C.G1, q : C.G2) : TM.Fp12M {
    millerLoopPrepared(p, prepareG2(q));
  };

  /// Uses the already-green final exponentiation.  `PairingFinalExp` replaces that implementation separately.
  public func pairingPrepared(p : C.G1, q : G2Prepared) : TM.Fp12M {
    PM.finalExponentiate(millerLoopPrepared(p, q));
  };

  func bitLen(n : Nat) : Nat {
    var v = n; var b : Nat = 0;
    while (v > 0) { b += 1; v /= 2 };
    b;
  };
  func popCount(n : Nat) : Nat {
    var v = n; var c : Nat = 0;
    while (v > 0) { c += v % 2; v /= 2 };
    c;
  };
  func bitAt(n : Nat, i : Nat) : Bool { (n / (2 ** i)) % 2 == 1 };
}
