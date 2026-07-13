/// G2 / **L1 REFERENCE** — BLS12-381 extension tower Fp2 → Fp6 → Fp12, in pure `Nat`.
///
/// Menese DeFi Team. Per `ORACLE-METHODOLOGY-motoko-verifier.md` §1: L1 is the **correctness anchor**.
/// Maximally literal transcription of the mathematics. ZERO optimization. **Do not optimize this file.**
///
/// Tower:
///   Fp2  = Fp[u]/(u² + 1)
///   Fp6  = Fp2[v]/(v³ − ξ),  ξ = 1 + u   (the "nonresidue")
///   Fp12 = Fp6[w]/(w² − v)
///
/// ### The deliberate choice that defends against mutant M8 (a wrong Frobenius coefficient)
///
/// Optimized pairing code computes Frobenius from **precomputed coefficient tables**, and a single
/// wrong table entry is a classic, catastrophic, SILENT bug — it changes no honest-path output in
/// many code paths, so value-matching valid inputs never sees it.
///
/// **So L1 does NOT use tables at all: Frobenius here is LITERAL EXPONENTIATION x^(p^i).** It is
/// absurdly slow and that is precisely the point — it depends on no constant anyone could mistype.
/// When L2 later introduces coefficient tables for speed, **a wrong entry is caught automatically by
/// the L2-vs-L1 differential**, because L1 has nothing to be wrong about. That is the two-level
/// oracle earning its keep.

import Fp "Fp";
import Runtime "mo:core/Runtime";

module {
  // ---------------------------------------------------------------------------------------------
  // Fp2 = Fp[u]/(u² + 1)   — element (c0, c1) means c0 + c1·u
  // ---------------------------------------------------------------------------------------------
  public type Fp2 = { c0 : Nat; c1 : Nat };

  public func fp2(c0 : Nat, c1 : Nat) : Fp2 { { c0; c1 } };
  public let fp2Zero : Fp2 = { c0 = 0; c1 = 0 };
  public let fp2One : Fp2 = { c0 = 1; c1 = 0 };

  public func fp2Add(a : Fp2, b : Fp2) : Fp2 {
    { c0 = Fp.add(a.c0, b.c0); c1 = Fp.add(a.c1, b.c1) };
  };

  public func fp2Sub(a : Fp2, b : Fp2) : Fp2 {
    { c0 = Fp.sub(a.c0, b.c0); c1 = Fp.sub(a.c1, b.c1) };
  };

  public func fp2Neg(a : Fp2) : Fp2 {
    { c0 = Fp.sub(0, a.c0); c1 = Fp.sub(0, a.c1) };
  };

  /// (a0 + a1·u)(b0 + b1·u) = (a0b0 − a1b1) + (a0b1 + a1b0)·u,   since u² = −1
  public func fp2Mul(a : Fp2, b : Fp2) : Fp2 {
    {
      c0 = Fp.sub(Fp.mul(a.c0, b.c0), Fp.mul(a.c1, b.c1));
      c1 = Fp.add(Fp.mul(a.c0, b.c1), Fp.mul(a.c1, b.c0));
    };
  };

  public func fp2Sqr(a : Fp2) : Fp2 { fp2Mul(a, a) };

  /// Conjugation: c0 + c1·u ↦ c0 − c1·u. (For BLS12-381, p ≡ 3 mod 4, so this IS the Fp2 Frobenius.)
  public func fp2Conj(a : Fp2) : Fp2 { { c0 = a.c0; c1 = Fp.sub(0, a.c1) } };

  /// inv(a) = conj(a) / norm(a),  norm = c0² + c1².
  public func fp2Inv(a : Fp2) : Fp2 {
    let norm = Fp.add(Fp.mul(a.c0, a.c0), Fp.mul(a.c1, a.c1));
    if (norm == 0) { Runtime.trap("E_INV_ZERO") };
    let ninv = Fp.inv(norm);
    { c0 = Fp.mul(a.c0, ninv); c1 = Fp.mul(Fp.sub(0, a.c1), ninv) };
  };

  public func fp2InvOpt(a : Fp2) : ?Fp2 {
    let norm = Fp.add(Fp.mul(a.c0, a.c0), Fp.mul(a.c1, a.c1));
    if (norm == 0) { return null };
    ?fp2Inv(a);
  };

  public func fp2Eq(a : Fp2, b : Fp2) : Bool { a.c0 == b.c0 and a.c1 == b.c1 };

  /// Multiply by the Fp6 nonresidue ξ = 1 + u:
  ///   (a0 + a1·u)(1 + u) = (a0 − a1) + (a0 + a1)·u
  public func fp2MulByNonresidue(a : Fp2) : Fp2 {
    { c0 = Fp.sub(a.c0, a.c1); c1 = Fp.add(a.c0, a.c1) };
  };

  // ---------------------------------------------------------------------------------------------
  // Fp6 = Fp2[v]/(v³ − ξ)   — element (c0, c1, c2) means c0 + c1·v + c2·v²
  // ---------------------------------------------------------------------------------------------
  public type Fp6 = { c0 : Fp2; c1 : Fp2; c2 : Fp2 };

  public let fp6Zero : Fp6 = { c0 = fp2Zero; c1 = fp2Zero; c2 = fp2Zero };
  public let fp6One : Fp6 = { c0 = fp2One; c1 = fp2Zero; c2 = fp2Zero };

  public func fp6Add(a : Fp6, b : Fp6) : Fp6 {
    { c0 = fp2Add(a.c0, b.c0); c1 = fp2Add(a.c1, b.c1); c2 = fp2Add(a.c2, b.c2) };
  };

  public func fp6Sub(a : Fp6, b : Fp6) : Fp6 {
    { c0 = fp2Sub(a.c0, b.c0); c1 = fp2Sub(a.c1, b.c1); c2 = fp2Sub(a.c2, b.c2) };
  };

  public func fp6Neg(a : Fp6) : Fp6 {
    { c0 = fp2Neg(a.c0); c1 = fp2Neg(a.c1); c2 = fp2Neg(a.c2) };
  };

  /// Schoolbook, with v³ = ξ:
  ///   c0 = a0b0 + ξ(a1b2 + a2b1)
  ///   c1 = a0b1 + a1b0 + ξ(a2b2)
  ///   c2 = a0b2 + a1b1 + a2b0
  public func fp6Mul(a : Fp6, b : Fp6) : Fp6 {
    let t = fp2Add(fp2Mul(a.c1, b.c2), fp2Mul(a.c2, b.c1));
    let c0 = fp2Add(fp2Mul(a.c0, b.c0), fp2MulByNonresidue(t));
    let c1 = fp2Add(
      fp2Add(fp2Mul(a.c0, b.c1), fp2Mul(a.c1, b.c0)),
      fp2MulByNonresidue(fp2Mul(a.c2, b.c2)),
    );
    let c2 = fp2Add(fp2Add(fp2Mul(a.c0, b.c2), fp2Mul(a.c1, b.c1)), fp2Mul(a.c2, b.c0));
    { c0; c1; c2 };
  };

  public func fp6Sqr(a : Fp6) : Fp6 { fp6Mul(a, a) };

  /// Multiply by v:  (a0 + a1·v + a2·v²)·v = ξ·a2 + a0·v + a1·v²
  public func fp6MulByV(a : Fp6) : Fp6 {
    { c0 = fp2MulByNonresidue(a.c2); c1 = a.c0; c2 = a.c1 };
  };

  /// Standard Fp6 inversion.
  ///   t0 = a0² − ξ·a1·a2 ;  t1 = ξ·a2² − a0·a1 ;  t2 = a1² − a0·a2
  ///   f  = a0·t0 + ξ·(a2·t1 + a1·t2)
  ///   a⁻¹ = (t0, t1, t2) · f⁻¹
  public func fp6Inv(a : Fp6) : Fp6 {
    let t0 = fp2Sub(fp2Sqr(a.c0), fp2MulByNonresidue(fp2Mul(a.c1, a.c2)));
    let t1 = fp2Sub(fp2MulByNonresidue(fp2Sqr(a.c2)), fp2Mul(a.c0, a.c1));
    let t2 = fp2Sub(fp2Sqr(a.c1), fp2Mul(a.c0, a.c2));
    let f = fp2Add(
      fp2Mul(a.c0, t0),
      fp2MulByNonresidue(fp2Add(fp2Mul(a.c2, t1), fp2Mul(a.c1, t2))),
    );
    if (fp2Eq(f, fp2Zero)) { Runtime.trap("E_INV_ZERO") };
    let fi = fp2Inv(f);
    { c0 = fp2Mul(t0, fi); c1 = fp2Mul(t1, fi); c2 = fp2Mul(t2, fi) };
  };

  public func fp6IsZero(a : Fp6) : Bool {
    fp2Eq(a.c0, fp2Zero) and fp2Eq(a.c1, fp2Zero) and fp2Eq(a.c2, fp2Zero);
  };

  public func fp6InvOpt(a : Fp6) : ?Fp6 {
    if (fp6IsZero(a)) { return null };
    ?fp6Inv(a);
  };

  public func fp6Eq(a : Fp6, b : Fp6) : Bool {
    fp2Eq(a.c0, b.c0) and fp2Eq(a.c1, b.c1) and fp2Eq(a.c2, b.c2);
  };

  // ---------------------------------------------------------------------------------------------
  // Fp12 = Fp6[w]/(w² − v)   — element (c0, c1) means c0 + c1·w
  // ---------------------------------------------------------------------------------------------
  public type Fp12 = { c0 : Fp6; c1 : Fp6 };

  public let fp12Zero : Fp12 = { c0 = fp6Zero; c1 = fp6Zero };
  public let fp12One : Fp12 = { c0 = fp6One; c1 = fp6Zero };

  public func fp12Add(a : Fp12, b : Fp12) : Fp12 {
    { c0 = fp6Add(a.c0, b.c0); c1 = fp6Add(a.c1, b.c1) };
  };

  public func fp12Sub(a : Fp12, b : Fp12) : Fp12 {
    { c0 = fp6Sub(a.c0, b.c0); c1 = fp6Sub(a.c1, b.c1) };
  };

  /// (a0 + a1·w)(b0 + b1·w) = (a0b0 + v·a1b1) + (a0b1 + a1b0)·w,   since w² = v
  public func fp12Mul(a : Fp12, b : Fp12) : Fp12 {
    let c0 = fp6Add(fp6Mul(a.c0, b.c0), fp6MulByV(fp6Mul(a.c1, b.c1)));
    let c1 = fp6Add(fp6Mul(a.c0, b.c1), fp6Mul(a.c1, b.c0));
    { c0; c1 };
  };

  public func fp12Sqr(a : Fp12) : Fp12 { fp12Mul(a, a) };

  /// Conjugation over Fp6: c0 + c1·w ↦ c0 − c1·w.
  /// The PROPERTY test asserts this equals frobenius^6 — the check that catches a wrong tower.
  public func fp12Conj(a : Fp12) : Fp12 { { c0 = a.c0; c1 = fp6Neg(a.c1) } };

  /// a⁻¹ = (a0 − a1·w) / (a0² − v·a1²)
  public func fp12Inv(a : Fp12) : Fp12 {
    let d = fp6Sub(fp6Sqr(a.c0), fp6MulByV(fp6Sqr(a.c1)));
    if (fp6IsZero(d)) { Runtime.trap("E_INV_ZERO") };
    let di = fp6Inv(d);
    { c0 = fp6Mul(a.c0, di); c1 = fp6Neg(fp6Mul(a.c1, di)) };
  };

  public func fp12IsZero(a : Fp12) : Bool { fp6IsZero(a.c0) and fp6IsZero(a.c1) };

  public func fp12InvOpt(a : Fp12) : ?Fp12 {
    if (fp12IsZero(a)) { return null };
    ?fp12Inv(a);
  };

  public func fp12Eq(a : Fp12, b : Fp12) : Bool {
    fp6Eq(a.c0, b.c0) and fp6Eq(a.c1, b.c1);
  };

  /// **Frobenius, the LITERAL way: x ↦ x^(p^i).**
  ///
  /// This is the M8 defence described in the module header. No coefficient tables, so there is no
  /// table entry to get wrong. Square-and-multiply over Fp12 with a 381-bit exponent — grotesquely
  /// slow, and correct by construction.
  public func fp12Frobenius(a : Fp12, i : Nat) : Fp12 {
    var r = a;
    var k = 0;
    while (k < i) {
      r := fp12Pow(r, Fp.P);
      k += 1;
    };
    r;
  };

  /// x^e over Fp12, square-and-multiply, MSB-agnostic (literal).
  public func fp12Pow(a : Fp12, e : Nat) : Fp12 {
    var result = fp12One;
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
