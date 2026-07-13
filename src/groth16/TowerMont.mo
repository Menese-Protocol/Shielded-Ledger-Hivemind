/// L2 / **OPTIMIZED** — BLS12-381 extension tower Fp2→Fp6→Fp12, Montgomery-NATIVE.
///
/// Menese DeFi Team. L2 counterpart to the L1 reference `Tower.mo`; does NOT touch L1. The speed lever
/// vs L1: coefficients stay in **Montgomery form** across the whole tower, so every coefficient
/// multiply is a `FpMont.montMul` (Mont×Mont→Mont, REDC only — no division-by-p and, crucially, NO
/// per-op toMont/fromMont conversion). Conversion happens ONLY at the tower boundary (`toM`/`fromM`).
/// This is where a pairing's cost actually lives (thousands of Fp muls), so this is the real cost lever.
///
/// Byte-identity FIRST (methodology): the gate diffs L2 (converted back to normal form) against the
/// green L1 tower AND reproduces the G2 oracle digest. Same tower formulas as L1 — only the field
/// backend differs — so a divergence localizes to the Montgomery backend by construction.
///
/// Element convention: an `Fp2M`/`Fp6M`/`Fp12M` holds its Fp coefficients in MONTGOMERY form.

import FpM "FpMont";
import T "Tower";

module {
  public type Fp2M = { c0 : Nat; c1 : Nat };
  public type Fp6M = { c0 : Fp2M; c1 : Fp2M; c2 : Fp2M };
  public type Fp12M = { c0 : Fp6M; c1 : Fp6M };

  // ---- boundary conversions (the ONLY place toMont/fromMont happen) ----
  public func toM2(a : T.Fp2) : Fp2M { { c0 = FpM.toMont(a.c0); c1 = FpM.toMont(a.c1) } };
  public func fromM2(a : Fp2M) : T.Fp2 { { c0 = FpM.montMul(a.c0, 1); c1 = FpM.montMul(a.c1, 1) } };
  public func toM6(a : T.Fp6) : Fp6M { { c0 = toM2(a.c0); c1 = toM2(a.c1); c2 = toM2(a.c2) } };
  public func fromM6(a : Fp6M) : T.Fp6 { { c0 = fromM2(a.c0); c1 = fromM2(a.c1); c2 = fromM2(a.c2) } };
  public func toM12(a : T.Fp12) : Fp12M { { c0 = toM6(a.c0); c1 = toM6(a.c1) } };
  public func fromM12(a : Fp12M) : T.Fp12 { { c0 = fromM6(a.c0); c1 = fromM6(a.c1) } };

  // ---- Fp2 = Fp[u]/(u²+1), all coeffs in Montgomery form ----
  public func fp2Add(a : Fp2M, b : Fp2M) : Fp2M { { c0 = FpM.add(a.c0, b.c0); c1 = FpM.add(a.c1, b.c1) } };
  public func fp2Sub(a : Fp2M, b : Fp2M) : Fp2M { { c0 = FpM.sub(a.c0, b.c0); c1 = FpM.sub(a.c1, b.c1) } };
  public func fp2Neg(a : Fp2M) : Fp2M { { c0 = FpM.sub(0, a.c0); c1 = FpM.sub(0, a.c1) } };

  public func fp2Mul(a : Fp2M, b : Fp2M) : Fp2M {
    {
      c0 = FpM.sub(FpM.montMul(a.c0, b.c0), FpM.montMul(a.c1, b.c1));
      c1 = FpM.add(FpM.montMul(a.c0, b.c1), FpM.montMul(a.c1, b.c0));
    };
  };
  public func fp2Sqr(a : Fp2M) : Fp2M { fp2Mul(a, a) };
  /// Optimized square used by the projective Miller loop.  This is the exact quadratic-extension
  /// identity used by ark-ff 0.5: (a+bu)^2 = (a-b)(a+b) + 2ab*u for u^2=-1.
  public func fp2SqrFast(a : Fp2M) : Fp2M {
    let ab = FpM.montMul(a.c0, a.c1);
    {
      c0 = FpM.montMul(FpM.sub(a.c0, a.c1), FpM.add(a.c0, a.c1));
      c1 = FpM.add(ab, ab);
    };
  };
  /// Multiply an Fp2 element by a base-field value; all inputs and outputs remain Montgomery-form.
  public func fp2MulByFp(a : Fp2M, b : Nat) : Fp2M {
    { c0 = FpM.montMul(a.c0, b); c1 = FpM.montMul(a.c1, b) };
  };
  public func fp2MulByNonresidue(a : Fp2M) : Fp2M { { c0 = FpM.sub(a.c0, a.c1); c1 = FpM.add(a.c0, a.c1) } };

  /// Montgomery inverse: invert the norm in Montgomery form. norm = c0²+c1² (Mont). We need
  /// norm⁻¹ in Mont form; do it via the field boundary once (inv is rare — once per fp2Inv).
  func fp2NormInv(norm : Nat) : Nat { FpM.toMont(FpM.inv(FpM.montMul(norm, 1))) };
  public func fp2Inv(a : Fp2M) : Fp2M {
    let norm = FpM.add(FpM.montMul(a.c0, a.c0), FpM.montMul(a.c1, a.c1));
    let ni = fp2NormInv(norm);
    { c0 = FpM.montMul(a.c0, ni); c1 = FpM.montMul(FpM.sub(0, a.c1), ni) };
  };

  // ---- Fp6 = Fp2[v]/(v³−ξ) ----
  public func fp6Add(a : Fp6M, b : Fp6M) : Fp6M { { c0 = fp2Add(a.c0, b.c0); c1 = fp2Add(a.c1, b.c1); c2 = fp2Add(a.c2, b.c2) } };
  public func fp6Sub(a : Fp6M, b : Fp6M) : Fp6M { { c0 = fp2Sub(a.c0, b.c0); c1 = fp2Sub(a.c1, b.c1); c2 = fp2Sub(a.c2, b.c2) } };

  public func fp6Mul(a : Fp6M, b : Fp6M) : Fp6M {
    let t = fp2Add(fp2Mul(a.c1, b.c2), fp2Mul(a.c2, b.c1));
    let c0 = fp2Add(fp2Mul(a.c0, b.c0), fp2MulByNonresidue(t));
    let c1 = fp2Add(fp2Add(fp2Mul(a.c0, b.c1), fp2Mul(a.c1, b.c0)), fp2MulByNonresidue(fp2Mul(a.c2, b.c2)));
    let c2 = fp2Add(fp2Add(fp2Mul(a.c0, b.c2), fp2Mul(a.c1, b.c1)), fp2Mul(a.c2, b.c0));
    { c0; c1; c2 };
  };
  public func fp6Sqr(a : Fp6M) : Fp6M { fp6Mul(a, a) };

  func fp2Eq(a : Fp2M, b : Fp2M) : Bool { a.c0 == b.c0 and a.c1 == b.c1 };
  let fp2ZeroM : Fp2M = { c0 = 0; c1 = 0 };

  public func fp6Inv(a : Fp6M) : Fp6M {
    let t0 = fp2Sub(fp2Sqr(a.c0), fp2MulByNonresidue(fp2Mul(a.c1, a.c2)));
    let t1 = fp2Sub(fp2MulByNonresidue(fp2Sqr(a.c2)), fp2Mul(a.c0, a.c1));
    let t2 = fp2Sub(fp2Sqr(a.c1), fp2Mul(a.c0, a.c2));
    let f = fp2Add(fp2Mul(a.c0, t0), fp2MulByNonresidue(fp2Add(fp2Mul(a.c2, t1), fp2Mul(a.c1, t2))));
    let fi = fp2Inv(f);
    { c0 = fp2Mul(t0, fi); c1 = fp2Mul(t1, fi); c2 = fp2Mul(t2, fi) };
  };

  public func fp6MulByV(a : Fp6M) : Fp6M { { c0 = fp2MulByNonresidue(a.c2); c1 = a.c0; c2 = a.c1 } };

  /// Sparse Fp6 multiply by (0,c1,0), ported literally from ark-ff 0.5 `Fp6::mul_by_1`.
  public func fp6MulBy1(a : Fp6M, c1 : Fp2M) : Fp6M {
    let bb = fp2Mul(a.c1, c1);
    let t1 = fp2MulByNonresidue(fp2Sub(fp2Mul(c1, fp2Add(a.c1, a.c2)), bb));
    let t2 = fp2Sub(fp2Mul(c1, fp2Add(a.c0, a.c1)), bb);
    { c0 = t1; c1 = t2; c2 = bb };
  };

  /// Sparse Fp6 multiply by (c0,c1,0), ported literally from ark-ff 0.5 `Fp6::mul_by_01`.
  public func fp6MulBy01(a : Fp6M, c0 : Fp2M, c1 : Fp2M) : Fp6M {
    let aa = fp2Mul(a.c0, c0);
    let bb = fp2Mul(a.c1, c1);
    let t1 = fp2Add(
      fp2MulByNonresidue(fp2Sub(fp2Mul(c1, fp2Add(a.c1, a.c2)), bb)),
      aa,
    );
    let t3 = fp2Add(fp2Sub(fp2Mul(c0, fp2Add(a.c0, a.c2)), aa), bb);
    let t2 = fp2Sub(
      fp2Sub(fp2Mul(fp2Add(c0, c1), fp2Add(a.c0, a.c1)), aa),
      bb,
    );
    { c0 = t1; c1 = t2; c2 = t3 };
  };

  // ---- Fp12 = Fp6[w]/(w²−v) ----
  public func fp12Add(a : Fp12M, b : Fp12M) : Fp12M { { c0 = fp6Add(a.c0, b.c0); c1 = fp6Add(a.c1, b.c1) } };
  public func fp12Sub(a : Fp12M, b : Fp12M) : Fp12M { { c0 = fp6Sub(a.c0, b.c0); c1 = fp6Sub(a.c1, b.c1) } };

  public func fp12Mul(a : Fp12M, b : Fp12M) : Fp12M {
    let c0 = fp6Add(fp6Mul(a.c0, b.c0), fp6MulByV(fp6Mul(a.c1, b.c1)));
    let c1 = fp6Add(fp6Mul(a.c0, b.c1), fp6Mul(a.c1, b.c0));
    { c0; c1 };
  };
  public func fp12Sqr(a : Fp12M) : Fp12M { fp12Mul(a, a) };

  /// Optimized quadratic-extension square, ported from ark-ff 0.5 `QuadExtField::square_in_place`.
  /// Uses two Fp6 multiplications instead of the generic Fp12 multiplication's four.
  public func fp12SqrFast(a : Fp12M) : Fp12M {
    let v0 = fp6Sub(a.c0, a.c1);
    let v3 = fp6Sub(a.c0, fp6MulByV(a.c1));
    let v2 = fp6Mul(a.c0, a.c1);
    {
      c0 = fp6Add(fp6Mul(v0, v3), fp6Add(v2, fp6MulByV(v2)));
      c1 = fp6Add(v2, v2);
    };
  };

  /// Sparse Fp12 multiply by coefficients at tower positions 0,1,4.  This is ark-ff 0.5's
  /// `Fp12::mul_by_014`, the line-evaluation shape for a BLS12 M-twist Miller loop.
  public func fp12MulBy014(a : Fp12M, c0 : Fp2M, c1 : Fp2M, c4 : Fp2M) : Fp12M {
    let aa = fp6MulBy01(a.c0, c0, c1);
    let bb = fp6MulBy1(a.c1, c4);
    let out1 = fp6Sub(
      fp6Sub(fp6MulBy01(fp6Add(a.c0, a.c1), c0, fp2Add(c1, c4)), aa),
      bb,
    );
    { c0 = fp6Add(fp6MulByV(bb), aa); c1 = out1 };
  };

  func fp6Neg(a : Fp6M) : Fp6M { { c0 = fp2Neg(a.c0); c1 = fp2Neg(a.c1); c2 = fp2Neg(a.c2) } };
  func fp6IsZero(a : Fp6M) : Bool { fp2Eq(a.c0, fp2ZeroM) and fp2Eq(a.c1, fp2ZeroM) and fp2Eq(a.c2, fp2ZeroM) };

  public func fp12Inv(a : Fp12M) : Fp12M {
    let d = fp6Sub(fp6Sqr(a.c0), fp6MulByV(fp6Sqr(a.c1)));
    let di = fp6Inv(d);
    { c0 = fp6Mul(a.c0, di); c1 = fp6Neg(fp6Mul(a.c1, di)) };
  };

  // ---- helpers the L2 Miller loop / final exp need (all Montgomery form) ----

  /// Fp2 constants in Montgomery form. `oneM` = toMont(1); built lazily (module-level calls are static).
  public func fp2OneM() : Fp2M { { c0 = FpM.toMont(1); c1 = 0 } };
  public let fp2ZeroMv : Fp2M = { c0 = 0; c1 = 0 };
  public func fp6OneM() : Fp6M { { c0 = fp2OneM(); c1 = fp2ZeroMv; c2 = fp2ZeroMv } };
  public let fp6ZeroMv : Fp6M = { c0 = fp2ZeroMv; c1 = fp2ZeroMv; c2 = fp2ZeroMv };
  public func fp12OneM() : Fp12M { { c0 = fp6OneM(); c1 = fp6ZeroMv } };
  public let fp12ZeroMv : Fp12M = { c0 = fp6ZeroMv; c1 = fp6ZeroMv };

  public func fp12Eq(a : Fp12M, b : Fp12M) : Bool {
    fp6Eq(a.c0, b.c0) and fp6Eq(a.c1, b.c1);
  };
  func fp6Eq(a : Fp6M, b : Fp6M) : Bool { fp2Eq(a.c0, b.c0) and fp2Eq(a.c1, b.c1) and fp2Eq(a.c2, b.c2) };
  public func fp12IsZero(a : Fp12M) : Bool { fp6IsZero(a.c0) and fp6IsZero(a.c1) };

  /// Conjugation over Fp6: c0 + c1·w ↦ c0 − c1·w.
  public func fp12Conj(a : Fp12M) : Fp12M { { c0 = a.c0; c1 = fp6Neg(a.c1) } };

  /// Embeddings (Montgomery form).
  public func fp2ToFp12(a : Fp2M) : Fp12M { { c0 = { c0 = a; c1 = fp2ZeroMv; c2 = fp2ZeroMv }; c1 = fp6ZeroMv } };
  public func fpToFp12M(aMont : Nat) : Fp12M { fp2ToFp12({ c0 = aMont; c1 = 0 }) };

  /// x^e over Fp12 (Montgomery form), square-and-multiply.
  public func fp12Pow(a : Fp12M, e : Nat) : Fp12M {
    var result = fp12OneM();
    var base = a;
    var exp = e;
    while (exp > 0) {
      if (exp % 2 == 1) { result := fp12Mul(result, base) };
      base := fp12Sqr(base);
      exp := exp / 2;
    };
    result;
  };
}
