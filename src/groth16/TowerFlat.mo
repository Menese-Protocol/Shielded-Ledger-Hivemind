/// L3 / **ALLOCATION-FLAT** — BLS12-381 tower Fp2→Fp6→Fp12, in-place on a [var Nat32] arena.
///
/// Menese DeFi Team. Flat counterpart of L2 `TowerMont.mo` (untouched — it is this layer's
/// differential anchor). SAME algebraic formulas, literally transcribed; only the storage
/// changes: a tower element is a run of 12-limb Fp coefficients inside one caller-owned arena,
/// and every operation writes IN PLACE — zero heap allocation per op (profiling measured
/// L2's record-tree churn at 20.7 KB per fp2Mul, 197 KB per fp6Mul, 421 KB per fp12SqrFast).
///
/// Layout (offsets in limbs, little-endian limb order within each Fp):
///   Fp2  @ d : c0 @ d, c1 @ d+12                                  (24 limbs)
///   Fp6  @ d : c0 @ d, c1 @ d+24, c2 @ d+48                       (72 limbs)
///   Fp12 @ d : c0 @ d, c1 @ d+72                                  (144 limbs)
///
/// Scratch discipline (the collision-freedom argument): every function takes the scratch BASE
/// `s` and uses ONLY the region of its own layer, plus the regions of strictly lower layers via
/// the functions it calls. Layers never call sideways or upward, so regions never collide:
///   T    @ s        : 16 limbs  — FpFlat CIOS scratch (14 used)
///   FP2S @ s + 16   : 48 limbs  — fp2-layer temporaries (4 slots of 12)
///   FP6S @ s + 64   : 240 limbs — fp6-layer temporaries (10 slots of 24)
///   FP12S@ s + 304  : 432 limbs — fp12-layer temporaries (6 slots of 72)
///   total SCRATCH_LIMBS = 736
/// Destinations may alias inputs everywhere below: results are computed into scratch (or, where
/// noted, written only after all reads of the aliased input are complete) — the same guarantee
/// FpFlat's CIOS gives at the field layer.

import F "FpFlat";

module {
  public let SCRATCH_LIMBS : Nat = 736;

  // region bases relative to the scratch base
  func tO(s : Nat) : Nat { s };
  func f2(s : Nat, k : Nat) : Nat { s + 16 + 12 * k }; // 4 fp slots
  func f6(s : Nat, k : Nat) : Nat { s + 64 + 24 * k }; // 10 fp2 slots
  func g12(s : Nat, k : Nat) : Nat { s + 304 + 72 * k }; // 6 fp6 slots

  // ================================ Fp2 ================================

  public func fp2Copy(z : [var Nat32], d : Nat, a : Nat) {
    F.copy(z, d, z, a);
    F.copy(z, d + 12, z, a + 12);
  };

  public func fp2SetZero(z : [var Nat32], d : Nat) {
    F.setZero(z, d);
    F.setZero(z, d + 12);
  };

  public func fp2SetOneMont(z : [var Nat32], d : Nat) {
    F.oneMontInto(z, d);
    F.setZero(z, d + 12);
  };

  public func fp2Eq(z : [var Nat32], a : Nat, b : Nat) : Bool {
    F.equal(z, a, z, b) and F.equal(z, a + 12, z, b + 12)
  };

  public func fp2IsZero(z : [var Nat32], a : Nat) : Bool {
    F.isZero(z, a) and F.isZero(z, a + 12)
  };

  public func fp2AddInto(z : [var Nat32], d : Nat, a : Nat, b : Nat) {
    F.addInto(z, d, z, a, z, b);
    F.addInto(z, d + 12, z, a + 12, z, b + 12);
  };

  public func fp2SubInto(z : [var Nat32], d : Nat, a : Nat, b : Nat) {
    F.subInto(z, d, z, a, z, b);
    F.subInto(z, d + 12, z, a + 12, z, b + 12);
  };

  public func fp2NegInto(z : [var Nat32], d : Nat, a : Nat) {
    F.negInto(z, d, z, a);
    F.negInto(z, d + 12, z, a + 12);
  };

  /// (a0 + a1·u)(b0 + b1·u) = (a0b0 − a1b1) + (a0b1 + a1b0)·u — the literal 4-mul L2 formula.
  public func fp2MulInto(z : [var Nat32], d : Nat, a : Nat, b : Nat, s : Nat) {
    let t = tO(s);
    F.montMulInto(z, f2(s, 0), z, a, z, b, z, t); // a0·b0
    F.montMulInto(z, f2(s, 1), z, a + 12, z, b + 12, z, t); // a1·b1
    F.montMulInto(z, f2(s, 2), z, a, z, b + 12, z, t); // a0·b1
    F.montMulInto(z, f2(s, 3), z, a + 12, z, b, z, t); // a1·b0
    F.subInto(z, d, z, f2(s, 0), z, f2(s, 1));
    F.addInto(z, d + 12, z, f2(s, 2), z, f2(s, 3));
  };

  /// (a−b)(a+b) + 2ab·u — L2 `fp2SqrFast`.
  public func fp2SqrFastInto(z : [var Nat32], d : Nat, a : Nat, s : Nat) {
    let t = tO(s);
    F.montMulInto(z, f2(s, 0), z, a, z, a + 12, z, t); // ab
    F.subInto(z, f2(s, 1), z, a, z, a + 12);
    F.addInto(z, f2(s, 2), z, a, z, a + 12);
    F.montMulInto(z, d, z, f2(s, 1), z, f2(s, 2), z, t);
    F.addInto(z, d + 12, z, f2(s, 0), z, f2(s, 0));
  };

  /// Multiply both coefficients by the Fp element at `bFp`. `d` may alias `a`; `bFp` is copied
  /// to scratch first so it may alias anything.
  public func fp2MulByFpInto(z : [var Nat32], d : Nat, a : Nat, bFp : Nat, s : Nat) {
    let t = tO(s);
    F.copy(z, f2(s, 0), z, bFp);
    F.montMulInto(z, d, z, a, z, f2(s, 0), z, t);
    F.montMulInto(z, d + 12, z, a + 12, z, f2(s, 0), z, t);
  };

  /// ξ = 1+u: (a0 − a1) + (a0 + a1)·u.
  public func fp2MulByNonresidueInto(z : [var Nat32], d : Nat, a : Nat, s : Nat) {
    F.subInto(z, f2(s, 0), z, a, z, a + 12);
    F.addInto(z, f2(s, 1), z, a, z, a + 12);
    F.copy(z, d, z, f2(s, 0));
    F.copy(z, d + 12, z, f2(s, 1));
  };

  /// L2 `fp2Inv`: ni = (c0²+c1²)⁻¹; (a0·ni, (−a1)·ni). Traps E_INV_ZERO on zero norm.
  public func fp2InvInto(z : [var Nat32], d : Nat, a : Nat, s : Nat) {
    let t = tO(s);
    F.montMulInto(z, f2(s, 0), z, a, z, a, z, t); // a0²
    F.montMulInto(z, f2(s, 1), z, a + 12, z, a + 12, z, t); // a1²
    F.addInto(z, f2(s, 0), z, f2(s, 0), z, f2(s, 1)); // norm
    F.montInvInto(z, f2(s, 1), z, f2(s, 0), z, f2(s, 2), z, t); // ni
    F.negInto(z, f2(s, 2), z, a + 12); // −a1 (before d writes, in case d == a)
    F.montMulInto(z, d, z, a, z, f2(s, 1), z, t);
    F.montMulInto(z, d + 12, z, f2(s, 2), z, f2(s, 1), z, t);
  };

  // ================================ Fp6 ================================

  public func fp6Copy(z : [var Nat32], d : Nat, a : Nat) {
    fp2Copy(z, d, a);
    fp2Copy(z, d + 24, a + 24);
    fp2Copy(z, d + 48, a + 48);
  };

  public func fp6SetZero(z : [var Nat32], d : Nat) {
    fp2SetZero(z, d);
    fp2SetZero(z, d + 24);
    fp2SetZero(z, d + 48);
  };

  public func fp6SetOneMont(z : [var Nat32], d : Nat) {
    fp2SetOneMont(z, d);
    fp2SetZero(z, d + 24);
    fp2SetZero(z, d + 48);
  };

  public func fp6Eq(z : [var Nat32], a : Nat, b : Nat) : Bool {
    fp2Eq(z, a, b) and fp2Eq(z, a + 24, b + 24) and fp2Eq(z, a + 48, b + 48)
  };

  public func fp6IsZero(z : [var Nat32], a : Nat) : Bool {
    fp2IsZero(z, a) and fp2IsZero(z, a + 24) and fp2IsZero(z, a + 48)
  };

  public func fp6AddInto(z : [var Nat32], d : Nat, a : Nat, b : Nat) {
    fp2AddInto(z, d, a, b);
    fp2AddInto(z, d + 24, a + 24, b + 24);
    fp2AddInto(z, d + 48, a + 48, b + 48);
  };

  public func fp6SubInto(z : [var Nat32], d : Nat, a : Nat, b : Nat) {
    fp2SubInto(z, d, a, b);
    fp2SubInto(z, d + 24, a + 24, b + 24);
    fp2SubInto(z, d + 48, a + 48, b + 48);
  };

  public func fp6NegInto(z : [var Nat32], d : Nat, a : Nat) {
    fp2NegInto(z, d, a);
    fp2NegInto(z, d + 24, a + 24);
    fp2NegInto(z, d + 48, a + 48);
  };

  /// Schoolbook with v³ = ξ — the literal L2 `fp6Mul`.
  /// FP6S slots: 0=p, 1=q, 2=t, 3=r0, 4=r1, 5=r2.
  public func fp6MulInto(z : [var Nat32], d : Nat, a : Nat, b : Nat, s : Nat) {
    // t = a1·b2 + a2·b1
    fp2MulInto(z, f6(s, 0), a + 24, b + 48, s);
    fp2MulInto(z, f6(s, 1), a + 48, b + 24, s);
    fp2AddInto(z, f6(s, 2), f6(s, 0), f6(s, 1));
    // r0 = a0·b0 + ξ·t
    fp2MulInto(z, f6(s, 0), a, b, s);
    fp2MulByNonresidueInto(z, f6(s, 1), f6(s, 2), s);
    fp2AddInto(z, f6(s, 3), f6(s, 0), f6(s, 1));
    // r1 = a0·b1 + a1·b0 + ξ·(a2·b2)
    fp2MulInto(z, f6(s, 0), a, b + 24, s);
    fp2MulInto(z, f6(s, 1), a + 24, b, s);
    fp2AddInto(z, f6(s, 0), f6(s, 0), f6(s, 1));
    fp2MulInto(z, f6(s, 1), a + 48, b + 48, s);
    fp2MulByNonresidueInto(z, f6(s, 1), f6(s, 1), s);
    fp2AddInto(z, f6(s, 4), f6(s, 0), f6(s, 1));
    // r2 = a0·b2 + a1·b1 + a2·b0
    fp2MulInto(z, f6(s, 0), a, b + 48, s);
    fp2MulInto(z, f6(s, 1), a + 24, b + 24, s);
    fp2AddInto(z, f6(s, 0), f6(s, 0), f6(s, 1));
    fp2MulInto(z, f6(s, 1), a + 48, b, s);
    fp2AddInto(z, f6(s, 5), f6(s, 0), f6(s, 1));
    fp2Copy(z, d, f6(s, 3));
    fp2Copy(z, d + 24, f6(s, 4));
    fp2Copy(z, d + 48, f6(s, 5));
  };

  /// (a0,a1,a2)·v = (ξ·a2, a0, a1).
  public func fp6MulByVInto(z : [var Nat32], d : Nat, a : Nat, s : Nat) {
    fp2MulByNonresidueInto(z, f6(s, 0), a + 48, s);
    fp2Copy(z, f6(s, 1), a);
    fp2Copy(z, f6(s, 2), a + 24);
    fp2Copy(z, d, f6(s, 0));
    fp2Copy(z, d + 24, f6(s, 1));
    fp2Copy(z, d + 48, f6(s, 2));
  };

  /// Sparse multiply by (0, c1, 0) — literal L2 `fp6MulBy1`. `c1` must not be inside FP6S/FP2S/T.
  public func fp6MulBy1Into(z : [var Nat32], d : Nat, a : Nat, c1 : Nat, s : Nat) {
    // bb = a1·c1
    fp2MulInto(z, f6(s, 0), a + 24, c1, s);
    // t1 = ξ·(c1·(a1+a2) − bb)
    fp2AddInto(z, f6(s, 1), a + 24, a + 48);
    fp2MulInto(z, f6(s, 2), c1, f6(s, 1), s);
    fp2SubInto(z, f6(s, 2), f6(s, 2), f6(s, 0));
    fp2MulByNonresidueInto(z, f6(s, 3), f6(s, 2), s);
    // t2 = c1·(a0+a1) − bb
    fp2AddInto(z, f6(s, 1), a, a + 24);
    fp2MulInto(z, f6(s, 2), c1, f6(s, 1), s);
    fp2SubInto(z, f6(s, 4), f6(s, 2), f6(s, 0));
    fp2Copy(z, d + 48, f6(s, 0)); // c2 = bb (write after all reads of a)
    fp2Copy(z, d, f6(s, 3));
    fp2Copy(z, d + 24, f6(s, 4));
  };

  /// Sparse multiply by (c0, c1, 0) — literal L2 `fp6MulBy01`. c0/c1 must not be in scratch.
  /// FP6S slots: 0=aa, 1=bb, 2=tmp, 3=sum, 4=r0, 5=r1, 6=r2, 7=c0+c1.
  public func fp6MulBy01Into(z : [var Nat32], d : Nat, a : Nat, c0 : Nat, c1 : Nat, s : Nat) {
    fp2MulInto(z, f6(s, 0), a, c0, s); // aa
    fp2MulInto(z, f6(s, 1), a + 24, c1, s); // bb
    // r0 = ξ·(c1·(a1+a2) − bb) + aa
    fp2AddInto(z, f6(s, 3), a + 24, a + 48);
    fp2MulInto(z, f6(s, 2), c1, f6(s, 3), s);
    fp2SubInto(z, f6(s, 2), f6(s, 2), f6(s, 1));
    fp2MulByNonresidueInto(z, f6(s, 2), f6(s, 2), s);
    fp2AddInto(z, f6(s, 4), f6(s, 2), f6(s, 0));
    // r2 = (c0·(a0+a2) − aa) + bb
    fp2AddInto(z, f6(s, 3), a, a + 48);
    fp2MulInto(z, f6(s, 2), c0, f6(s, 3), s);
    fp2SubInto(z, f6(s, 2), f6(s, 2), f6(s, 0));
    fp2AddInto(z, f6(s, 6), f6(s, 2), f6(s, 1));
    // r1 = (c0+c1)·(a0+a1) − aa − bb
    fp2AddInto(z, f6(s, 7), c0, c1);
    fp2AddInto(z, f6(s, 3), a, a + 24);
    fp2MulInto(z, f6(s, 2), f6(s, 7), f6(s, 3), s);
    fp2SubInto(z, f6(s, 2), f6(s, 2), f6(s, 0));
    fp2SubInto(z, f6(s, 5), f6(s, 2), f6(s, 1));
    fp2Copy(z, d, f6(s, 4));
    fp2Copy(z, d + 24, f6(s, 5));
    fp2Copy(z, d + 48, f6(s, 6));
  };

  /// Literal L2 `fp6Inv` (generic fp2Sqr = fp2Mul(a,a), exactly as L2 uses).
  /// FP6S slots: 0=p, 1=q, 2=f, 3=t0, 4=t1, 5=t2, 6=fi.
  public func fp6InvInto(z : [var Nat32], d : Nat, a : Nat, s : Nat) {
    // t0 = a0² − ξ·(a1·a2)
    fp2MulInto(z, f6(s, 0), a, a, s);
    fp2MulInto(z, f6(s, 1), a + 24, a + 48, s);
    fp2MulByNonresidueInto(z, f6(s, 1), f6(s, 1), s);
    fp2SubInto(z, f6(s, 3), f6(s, 0), f6(s, 1));
    // t1 = ξ·a2² − a0·a1
    fp2MulInto(z, f6(s, 0), a + 48, a + 48, s);
    fp2MulByNonresidueInto(z, f6(s, 0), f6(s, 0), s);
    fp2MulInto(z, f6(s, 1), a, a + 24, s);
    fp2SubInto(z, f6(s, 4), f6(s, 0), f6(s, 1));
    // t2 = a1² − a0·a2
    fp2MulInto(z, f6(s, 0), a + 24, a + 24, s);
    fp2MulInto(z, f6(s, 1), a, a + 48, s);
    fp2SubInto(z, f6(s, 5), f6(s, 0), f6(s, 1));
    // f = a0·t0 + ξ·(a2·t1 + a1·t2)
    fp2MulInto(z, f6(s, 0), a + 48, f6(s, 4), s);
    fp2MulInto(z, f6(s, 1), a + 24, f6(s, 5), s);
    fp2AddInto(z, f6(s, 0), f6(s, 0), f6(s, 1));
    fp2MulByNonresidueInto(z, f6(s, 0), f6(s, 0), s);
    fp2MulInto(z, f6(s, 1), a, f6(s, 3), s);
    fp2AddInto(z, f6(s, 2), f6(s, 1), f6(s, 0));
    // fi = f⁻¹ ; result = (t0, t1, t2)·fi
    fp2InvInto(z, f6(s, 6), f6(s, 2), s);
    fp2MulInto(z, d, f6(s, 3), f6(s, 6), s);
    fp2MulInto(z, d + 24, f6(s, 4), f6(s, 6), s);
    fp2MulInto(z, d + 48, f6(s, 5), f6(s, 6), s);
  };

  // ================================ Fp12 ================================

  public func fp12Copy(z : [var Nat32], d : Nat, a : Nat) {
    fp6Copy(z, d, a);
    fp6Copy(z, d + 72, a + 72);
  };

  public func fp12SetOneMont(z : [var Nat32], d : Nat) {
    fp6SetOneMont(z, d);
    fp6SetZero(z, d + 72);
  };

  public func fp12Eq(z : [var Nat32], a : Nat, b : Nat) : Bool {
    fp6Eq(z, a, b) and fp6Eq(z, a + 72, b + 72)
  };

  /// Is the element the Montgomery one (the pairing-check target)?
  public func fp12IsOneMont(z : [var Nat32], a : Nat) : Bool {
    if (not F.isOneMont(z, a)) return false;
    var j = 12;
    while (j < 144) { if (z[a + j] != 0) return false; j += 1 };
    true
  };

  /// Literal L2 `fp12Mul`. FP12S slots: 0=p, 1=q, 2=r0, 3=r1.
  public func fp12MulInto(z : [var Nat32], d : Nat, a : Nat, b : Nat, s : Nat) {
    fp6MulInto(z, g12(s, 0), a, b, s);
    fp6MulInto(z, g12(s, 1), a + 72, b + 72, s);
    fp6MulByVInto(z, g12(s, 1), g12(s, 1), s);
    fp6AddInto(z, g12(s, 2), g12(s, 0), g12(s, 1));
    fp6MulInto(z, g12(s, 0), a, b + 72, s);
    fp6MulInto(z, g12(s, 1), a + 72, b, s);
    fp6AddInto(z, g12(s, 3), g12(s, 0), g12(s, 1));
    fp6Copy(z, d, g12(s, 2));
    fp6Copy(z, d + 72, g12(s, 3));
  };

  /// Literal L2 `fp12SqrFast`. FP12S slots: 0=v0, 1=v3, 2=v2, 3=p, 4=q.
  public func fp12SqrFastInto(z : [var Nat32], d : Nat, a : Nat, s : Nat) {
    fp6SubInto(z, g12(s, 0), a, a + 72); // v0
    fp6MulByVInto(z, g12(s, 1), a + 72, s);
    fp6SubInto(z, g12(s, 1), a, g12(s, 1)); // v3
    fp6MulInto(z, g12(s, 2), a, a + 72, s); // v2
    fp6MulInto(z, g12(s, 3), g12(s, 0), g12(s, 1), s); // v0·v3
    fp6MulByVInto(z, g12(s, 4), g12(s, 2), s);
    fp6AddInto(z, g12(s, 4), g12(s, 2), g12(s, 4)); // v2 + v·v2
    fp6AddInto(z, d, g12(s, 3), g12(s, 4)); // c0
    fp6AddInto(z, d + 72, g12(s, 2), g12(s, 2)); // c1 = 2·v2
  };

  /// Literal L2 `fp12MulBy014` (line-evaluation sparse multiply).
  /// c0/c1/c4 are fp2 offsets outside all scratch regions.
  /// FP12S slots: 0=aa, 1=bb, 2=sum(a0+a1), 3=c1+c4 (fp2, low 24 of slot), 4=o1 tmp.
  public func fp12MulBy014Into(
    z : [var Nat32], d : Nat, a : Nat, c0 : Nat, c1 : Nat, c4 : Nat, s : Nat,
  ) {
    fp6MulBy01Into(z, g12(s, 0), a, c0, c1, s); // aa
    fp6MulBy1Into(z, g12(s, 1), a + 72, c4, s); // bb
    fp2AddInto(z, g12(s, 3), c1, c4); // c1+c4 (fp2)
    fp6AddInto(z, g12(s, 2), a, a + 72); // a0+a1
    fp6MulBy01Into(z, g12(s, 4), g12(s, 2), c0, g12(s, 3), s);
    fp6SubInto(z, g12(s, 4), g12(s, 4), g12(s, 0));
    fp6SubInto(z, g12(s, 4), g12(s, 4), g12(s, 1)); // o1
    fp6MulByVInto(z, g12(s, 2), g12(s, 1), s); // v·bb
    fp6AddInto(z, d, g12(s, 2), g12(s, 0)); // c0' = v·bb + aa
    fp6Copy(z, d + 72, g12(s, 4)); // c1' = o1
  };

  public func fp12ConjInto(z : [var Nat32], d : Nat, a : Nat) {
    fp6Copy(z, d, a);
    fp6NegInto(z, d + 72, a + 72);
  };

  /// Literal L2 `fp12Inv`. FP12S slots: 0=p, 1=q, 2=d6, 3=di, 4=t.
  public func fp12InvInto(z : [var Nat32], d : Nat, a : Nat, s : Nat) {
    fp6MulInto(z, g12(s, 0), a, a, s); // a0²
    fp6MulInto(z, g12(s, 1), a + 72, a + 72, s); // a1²
    fp6MulByVInto(z, g12(s, 1), g12(s, 1), s);
    fp6SubInto(z, g12(s, 2), g12(s, 0), g12(s, 1)); // d6
    fp6InvInto(z, g12(s, 3), g12(s, 2), s); // di
    fp6MulInto(z, g12(s, 4), a + 72, g12(s, 3), s); // a1·di (before d writes)
    fp6MulInto(z, d, a, g12(s, 3), s); // c0 = a0·di
    fp6NegInto(z, d + 72, g12(s, 4)); // c1 = −(a1·di)
  };
}
