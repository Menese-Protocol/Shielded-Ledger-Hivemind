/// L2 / **OPTIMIZED** — BLS12-381 optimal-ate pairing, Montgomery-native (TowerMont backend).
///
/// Menese DeFi Team. L2 counterpart to L1 `Pairing.mo` (untouched). SAME algorithm, same untwist,
/// same line functions, same negative-x conjugation, and — kept front and center per a hard-won pairing lesson —
/// the **cofactor-3 final exponentiation** (arkworks convention: f^(3·(p¹²−1)/r)). Only the field
/// backend differs: every Fp12 op is TowerMont Montgomery-native, so the thousands of Fp muls in the
/// Miller loop + final exp avoid division-by-p. This is the dominant pairing-cost lever.
///
/// This is the highest-risk layer (silent forged-proof acceptance is its failure mode), so it is
/// diffed against green L1 at the pairing value AND against the arkworks pairing oracle, with M6/M7/cofactor mutants
/// and a private adversarial vector held out of the digest (in the gate).

import FpM "FpMont";
import TM "TowerMont";
import Fp "Fp";
import T "Tower";
import C "Curve";

module {
  public let X_ABS : Nat = 0xd201000000010000;
  public let X_IS_NEGATIVE : Bool = true;

  // v ∈ Fp12 (Mont): Fp6 element (0, 1, 0). w ∈ Fp12 (Mont): (0, 1).
  func v12() : TM.Fp12M { { c0 = { c0 = TM.fp2ZeroMv; c1 = TM.fp2OneM(); c2 = TM.fp2ZeroMv }; c1 = TM.fp6ZeroMv } };
  func w12() : TM.Fp12M { { c0 = TM.fp6ZeroMv; c1 = TM.fp6OneM() } };

  public type P12 = { #inf; #pt : { x : TM.Fp12M; y : TM.Fp12M } };

  /// Untwist ψ : E'(Fp2) → E(Fp12), (x,y) ↦ (x/v, y/(v·w)), inputs converted to Montgomery.
  public func untwist(q : C.G2) : P12 {
    switch (q) {
      case (#inf) { #inf };
      case (#pt(pt)) {
        let x12 = TM.fp2ToFp12(TM.toM2(pt.x));
        let y12 = TM.fp2ToFp12(TM.toM2(pt.y));
        let vw = TM.fp12Mul(v12(), w12());
        #pt({ x = TM.fp12Mul(x12, TM.fp12Inv(v12())); y = TM.fp12Mul(y12, TM.fp12Inv(vw)) });
      };
    };
  };

  public func p12Add(a : P12, b : P12) : P12 {
    switch (a, b) {
      case (#inf, _) { b };
      case (_, #inf) { a };
      case (#pt(p), #pt(q)) {
        if (TM.fp12Eq(p.x, q.x)) {
          if (not TM.fp12Eq(p.y, q.y)) { return #inf };
          let three = TM.fpToFp12M(FpM.toMont(3));
          let two = TM.fpToFp12M(FpM.toMont(2));
          let lam = TM.fp12Mul(TM.fp12Mul(three, TM.fp12Sqr(p.x)), TM.fp12Inv(TM.fp12Mul(two, p.y)));
          let x3 = TM.fp12Sub(TM.fp12Sqr(lam), TM.fp12Mul(two, p.x));
          let y3 = TM.fp12Sub(TM.fp12Mul(lam, TM.fp12Sub(p.x, x3)), p.y);
          #pt({ x = x3; y = y3 });
        } else {
          let lam = TM.fp12Mul(TM.fp12Sub(q.y, p.y), TM.fp12Inv(TM.fp12Sub(q.x, p.x)));
          let x3 = TM.fp12Sub(TM.fp12Sub(TM.fp12Sqr(lam), p.x), q.x);
          let y3 = TM.fp12Sub(TM.fp12Mul(lam, TM.fp12Sub(p.x, x3)), p.y);
          #pt({ x = x3; y = y3 });
        };
      };
    };
  };

  func line(tp : P12, qp : P12, px : TM.Fp12M, py : TM.Fp12M) : TM.Fp12M {
    switch (tp, qp) {
      case (#pt(t), #pt(q)) {
        let lam = if (TM.fp12Eq(t.x, q.x) and TM.fp12Eq(t.y, q.y)) {
          let three = TM.fpToFp12M(FpM.toMont(3));
          let two = TM.fpToFp12M(FpM.toMont(2));
          TM.fp12Mul(TM.fp12Mul(three, TM.fp12Sqr(t.x)), TM.fp12Inv(TM.fp12Mul(two, t.y)));
        } else {
          TM.fp12Mul(TM.fp12Sub(q.y, t.y), TM.fp12Inv(TM.fp12Sub(q.x, t.x)));
        };
        TM.fp12Sub(TM.fp12Sub(py, t.y), TM.fp12Mul(lam, TM.fp12Sub(px, t.x)));
      };
      case (_, _) { TM.fp12OneM() };
    };
  };

  public func millerLoop(p : C.G1, q : C.G2) : TM.Fp12M {
    switch (p, q) {
      case (#inf, _) { TM.fp12OneM() };
      case (_, #inf) { TM.fp12OneM() };
      case (#pt(pp), _) {
        let px = TM.fpToFp12M(FpM.toMont(pp.x));
        let py = TM.fpToFp12M(FpM.toMont(pp.y));
        let qq = untwist(q);
        var f = TM.fp12OneM();
        var tacc = qq;
        var i : Nat = bitLen(X_ABS) - 1;
        while (i > 0) {
          i -= 1;
          f := TM.fp12Mul(TM.fp12Sqr(f), line(tacc, tacc, px, py));
          tacc := p12Add(tacc, tacc);
          if (bitAt(X_ABS, i)) {
            f := TM.fp12Mul(f, line(tacc, qq, px, py));
            tacc := p12Add(tacc, qq);
          };
        };
        if (X_IS_NEGATIVE) { f := TM.fp12Conj(f) };
        f;
      };
    };
  };

  func bitLen(n : Nat) : Nat { var v = n; var b : Nat = 0; while (v > 0) { b += 1; v /= 2 }; b };
  func bitAt(n : Nat, i : Nat) : Bool { (n / (2 ** i)) % 2 == 1 };

  public func canonicalFinalExpE() : Nat { ((Fp.P ** 12) - 1) / C.R };

  /// f^(3·(p¹²−1)/r) — the arkworks cofactor-3 convention (lesson: this cube is load-bearing and
  /// FORCED by the vk's precomputed e(α,β); dropping it fails the diff).
  public func finalExponentiate(f : TM.Fp12M) : TM.Fp12M {
    let base = TM.fp12Pow(f, canonicalFinalExpE());
    TM.fp12Mul(TM.fp12Sqr(base), base);
  };

  public func pairing(p : C.G1, q : C.G2) : TM.Fp12M { finalExponentiate(millerLoop(p, q)) };
}
