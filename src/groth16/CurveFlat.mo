/// L3 / **ALLOCATION-FLAT** — BLS12-381 G1/G2 Jacobian group ops, in-place on a [var Nat32] arena.
///
/// Menese DeFi Team. Flat counterpart of L2 `CurveJac.mo` (untouched — the differential anchor).
/// SAME formulas (EFD dbl-2009-l / add-2007-bl, a = 0), same branch structure for the doubling
/// and infinity degeneracies, same `[r]P == O ⟺ Z == 0` subgroup definition. Only the storage
/// changes: Jacobian coordinates are limb runs inside one caller-owned arena; every operation
/// writes in place — zero allocation per group op (profiled: L2 g1Add = 87 KB garbage,
/// one 255-bit scalar mul ≈ 22 MB → the A/C/B validates + 8-input MSM were 55% of the per-op
/// churn).
///
/// Layout: G1 point @ d : X @ d, Y @ d+12, Z @ d+24 (36 limbs, Montgomery form).
///         G2 point @ d : X @ d, Y @ d+24, Z @ d+48 (72 limbs, Fp2 coefficients Montgomery).
///
/// Scratch: extends the TowerFlat region scheme upward (collision-free — this layer calls only
/// downward into TowerFlat/FpFlat, and the scalar-mul sub-layer uses its own region distinct
/// from the primitive dbl/add region it calls):
///   G1PRIM @ s + 736  : 144 limbs (12 Fp slots)   — g1Dbl/g1Add/g1ToAffine temporaries
///   G1MUL  @ s + 880  :  96 limbs                 — g1Mul base + result points
///   G2PRIM @ s + 976  : 288 limbs (12 Fp2 slots)  — g2Dbl/g2Add temporaries
///   G2MUL  @ s + 1264 : 168 limbs                 — g2Mul base + result points
///   total SCRATCH_LIMBS = 1432 (superset of TowerFlat.SCRATCH_LIMBS = 736)
///
/// Scalars are immutable `[Nat32]` little-endian limb arrays (a reference — passing one never
/// copies). `R_LIMBS` is the group order for subgroup checks; per-input MSM scalars are built
/// once per verify by `scalarLimbs` (one small boundary allocation per scalar).

import Array "mo:core/Array";
import Nat32Core "mo:core/Nat32";
import F "FpFlat";
import TF "TowerFlat";
import C "Curve";

module {
  public let SCRATCH_LIMBS : Nat = 1432;

  /// The BLS12-381 group order r, little-endian 32-bit limbs (python-generated from Curve.R;
  /// gate-validated against CurveJac subgroup verdicts).
  public let R_LIMBS : [Nat32] = [
    0x00000001, 0xffffffff, 0xfffe5bfe, 0x53bda402, 0x09a1d805, 0x3339d808,
    0x299d7d48, 0x73eda753,
  ];

  func c1(s : Nat, k : Nat) : Nat { s + 736 + 12 * k }; // G1PRIM fp slots (12)
  func m1(s : Nat) : Nat { s + 880 }; // G1MUL: base@+0(36) res@+36(36)
  func c2(s : Nat, k : Nat) : Nat { s + 976 + 24 * k }; // G2PRIM fp2 slots (12)
  func m2(s : Nat) : Nat { s + 1264 }; // G2MUL: base@+0(72) res@+72(72)

  /// A Nat scalar (< 2^256) as 8 little-endian Nat32 limbs. Boundary-only (one small alloc).
  public func scalarLimbs(k : Nat) : [Nat32] {
    var v = k;
    let out = Array.tabulate<Nat32>(8, func(_) {
      let limb = Nat32Core.fromNat(v % 0x100000000);
      v := v / 0x100000000;
      limb
    });
    assert v == 0;
    out
  };

  // ================================ G1 ================================

  public func g1InfInto(z : [var Nat32], d : Nat) {
    F.oneMontInto(z, d);
    F.oneMontInto(z, d + 12);
    F.setZero(z, d + 24);
  };

  public func g1IsInf(z : [var Nat32], d : Nat) : Bool { F.isZero(z, d + 24) };

  public func g1Copy(z : [var Nat32], d : Nat, a : Nat) {
    F.copy(z, d, z, a);
    F.copy(z, d + 12, z, a + 12);
    F.copy(z, d + 24, z, a + 24);
  };

  /// Load an affine L2 point (normal-form Nat coords) into Montgomery Jacobian limbs.
  /// Boundary-only. Uses G1PRIM slots 10/11 as conversion spares.
  public func g1FromAffineInto(z : [var Nat32], d : Nat, p : C.G1, s : Nat) {
    switch (p) {
      case (#inf) { g1InfInto(z, d) };
      case (#pt(q)) {
        F.fromNat(q.x, z, c1(s, 10));
        F.toMontInto(z, d, z, c1(s, 10), z, c1(s, 11), z, s);
        F.fromNat(q.y, z, c1(s, 10));
        F.toMontInto(z, d + 12, z, c1(s, 10), z, c1(s, 11), z, s);
        F.oneMontInto(z, d + 24);
      };
    };
  };

  /// Literal L2 `g1Dbl` (EFD dbl-2009-l, a = 0). d may alias a.
  /// G1PRIM slots: 0=A 1=B 2=C 3=D 4=E 5=F 6=x3 7=y3 8=z3 9=tmp.
  public func g1DblInto(z : [var Nat32], d : Nat, a : Nat, s : Nat) {
    if (F.isZero(z, a + 24)) { if (d != a) g1Copy(z, d, a); return };
    if (F.isZero(z, a + 12)) { g1InfInto(z, d); return };
    F.montMulInto(z, c1(s, 0), z, a, z, a, z, s); // A = X²
    F.montMulInto(z, c1(s, 1), z, a + 12, z, a + 12, z, s); // B = Y²
    F.montMulInto(z, c1(s, 2), z, c1(s, 1), z, c1(s, 1), z, s); // C = B²
    F.addInto(z, c1(s, 9), z, a, z, c1(s, 1)); // X+B
    F.montMulInto(z, c1(s, 9), z, c1(s, 9), z, c1(s, 9), z, s); // (X+B)²
    F.subInto(z, c1(s, 9), z, c1(s, 9), z, c1(s, 0));
    F.subInto(z, c1(s, 9), z, c1(s, 9), z, c1(s, 2)); // d0
    F.addInto(z, c1(s, 3), z, c1(s, 9), z, c1(s, 9)); // D = 2·d0
    F.addInto(z, c1(s, 4), z, c1(s, 0), z, c1(s, 0));
    F.addInto(z, c1(s, 4), z, c1(s, 4), z, c1(s, 0)); // E = 3A
    F.montMulInto(z, c1(s, 5), z, c1(s, 4), z, c1(s, 4), z, s); // F = E²
    F.addInto(z, c1(s, 9), z, c1(s, 3), z, c1(s, 3)); // 2D
    F.subInto(z, c1(s, 6), z, c1(s, 5), z, c1(s, 9)); // x3 = F − 2D
    F.addInto(z, c1(s, 9), z, c1(s, 2), z, c1(s, 2));
    F.addInto(z, c1(s, 9), z, c1(s, 9), z, c1(s, 9));
    F.addInto(z, c1(s, 9), z, c1(s, 9), z, c1(s, 9)); // 8C
    F.subInto(z, c1(s, 7), z, c1(s, 3), z, c1(s, 6)); // D − x3
    F.montMulInto(z, c1(s, 7), z, c1(s, 4), z, c1(s, 7), z, s); // E·(D−x3)
    F.subInto(z, c1(s, 7), z, c1(s, 7), z, c1(s, 9)); // y3
    F.montMulInto(z, c1(s, 8), z, a + 12, z, a + 24, z, s); // YZ
    F.addInto(z, c1(s, 8), z, c1(s, 8), z, c1(s, 8)); // z3 = 2YZ
    F.copy(z, d, z, c1(s, 6));
    F.copy(z, d + 12, z, c1(s, 7));
    F.copy(z, d + 24, z, c1(s, 8));
  };

  /// Literal L2 `g1Add` (EFD add-2007-bl with explicit degeneracies). d may alias a or b.
  /// G1PRIM slots: 0=Z1Z1 1=Z2Z2 2=U1/x3 3=U2/y3 4=S1/z3 5=S2 6=H 7=I 8=J|S1J 9=r 10=V 11=tmp.
  public func g1AddInto(z : [var Nat32], d : Nat, a : Nat, b : Nat, s : Nat) {
    if (F.isZero(z, a + 24)) { if (d != b) g1Copy(z, d, b); return };
    if (F.isZero(z, b + 24)) { if (d != a) g1Copy(z, d, a); return };
    F.montMulInto(z, c1(s, 0), z, a + 24, z, a + 24, z, s); // Z1Z1
    F.montMulInto(z, c1(s, 1), z, b + 24, z, b + 24, z, s); // Z2Z2
    F.montMulInto(z, c1(s, 2), z, a, z, c1(s, 1), z, s); // U1
    F.montMulInto(z, c1(s, 3), z, b, z, c1(s, 0), z, s); // U2
    F.montMulInto(z, c1(s, 4), z, a + 12, z, b + 24, z, s);
    F.montMulInto(z, c1(s, 4), z, c1(s, 4), z, c1(s, 1), z, s); // S1
    F.montMulInto(z, c1(s, 5), z, b + 12, z, a + 24, z, s);
    F.montMulInto(z, c1(s, 5), z, c1(s, 5), z, c1(s, 0), z, s); // S2
    if (F.equal(z, c1(s, 2), z, c1(s, 3))) {
      if (F.equal(z, c1(s, 4), z, c1(s, 5))) { g1DblInto(z, d, a, s); return };
      g1InfInto(z, d);
      return;
    };
    F.subInto(z, c1(s, 6), z, c1(s, 3), z, c1(s, 2)); // H = U2 − U1
    F.addInto(z, c1(s, 11), z, c1(s, 6), z, c1(s, 6)); // 2H
    F.montMulInto(z, c1(s, 7), z, c1(s, 11), z, c1(s, 11), z, s); // I = (2H)²
    F.montMulInto(z, c1(s, 8), z, c1(s, 6), z, c1(s, 7), z, s); // J = H·I
    F.subInto(z, c1(s, 9), z, c1(s, 5), z, c1(s, 4)); // r0 = S2 − S1
    F.addInto(z, c1(s, 9), z, c1(s, 9), z, c1(s, 9)); // r = 2·r0
    F.montMulInto(z, c1(s, 10), z, c1(s, 2), z, c1(s, 7), z, s); // V = U1·I
    // x3 = r² − J − 2V   (slot 2: U1 dead)
    F.montMulInto(z, c1(s, 2), z, c1(s, 9), z, c1(s, 9), z, s);
    F.subInto(z, c1(s, 2), z, c1(s, 2), z, c1(s, 8));
    F.addInto(z, c1(s, 11), z, c1(s, 10), z, c1(s, 10)); // 2V
    F.subInto(z, c1(s, 2), z, c1(s, 2), z, c1(s, 11));
    // y3 = r·(V − x3) − 2·(S1·J)   (slot 3: U2 dead; slot 8 → S1J)
    F.montMulInto(z, c1(s, 8), z, c1(s, 4), z, c1(s, 8), z, s); // S1·J
    F.subInto(z, c1(s, 11), z, c1(s, 10), z, c1(s, 2)); // V − x3
    F.montMulInto(z, c1(s, 3), z, c1(s, 9), z, c1(s, 11), z, s);
    F.addInto(z, c1(s, 11), z, c1(s, 8), z, c1(s, 8)); // 2·S1J
    F.subInto(z, c1(s, 3), z, c1(s, 3), z, c1(s, 11));
    // z3 = ((Z1+Z2)² − Z1Z1 − Z2Z2)·H   (slot 4: S1 dead)
    F.addInto(z, c1(s, 11), z, a + 24, z, b + 24);
    F.montMulInto(z, c1(s, 4), z, c1(s, 11), z, c1(s, 11), z, s);
    F.subInto(z, c1(s, 4), z, c1(s, 4), z, c1(s, 0));
    F.subInto(z, c1(s, 4), z, c1(s, 4), z, c1(s, 1));
    F.montMulInto(z, c1(s, 4), z, c1(s, 4), z, c1(s, 6), z, s);
    F.copy(z, d, z, c1(s, 2));
    F.copy(z, d + 12, z, c1(s, 3));
    F.copy(z, d + 24, z, c1(s, 4));
  };

  /// Double-and-add, structurally identical to L2 `g1Mul` (LSB-first). d may alias p.
  public func g1MulInto(z : [var Nat32], d : Nat, p : Nat, e : [Nat32], s : Nat) {
    let base = m1(s);
    let res = m1(s) + 36;
    g1Copy(z, base, p);
    g1InfInto(z, res);
    var li = 0;
    while (li < e.size()) {
      var bits = Nat32Core.toNat64(e[li]);
      var bit = 0;
      while (bit < 32) {
        if (bits & 1 == 1) { g1AddInto(z, res, res, base, s) };
        g1DblInto(z, base, base, s);
        bits := bits >> 1;
        bit += 1;
      };
      li += 1;
    };
    g1Copy(z, d, res);
  };

  /// `[r]P == O` — the same literal definition as L1/L2. `tmpPt` is a caller-owned 36-limb area.
  public func g1InSubgroup(z : [var Nat32], p : Nat, tmpPt : Nat, s : Nat) : Bool {
    g1MulInto(z, tmpPt, p, R_LIMBS, s);
    g1IsInf(z, tmpPt)
  };

  /// Jacobian → Montgomery affine (X/Z², Y/Z³) written to dx/dy (12 limbs each).
  /// PRECONDITION: not infinity (caller checks `g1IsInf`). One Fermat inversion.
  /// G1PRIM slots: 0=zInv 1=zInv2 2=zInv3 3=work.
  public func g1ToAffineInto(z : [var Nat32], dx : Nat, dy : Nat, a : Nat, s : Nat) {
    F.montInvInto(z, c1(s, 0), z, a + 24, z, c1(s, 3), z, s);
    F.montMulInto(z, c1(s, 1), z, c1(s, 0), z, c1(s, 0), z, s);
    F.montMulInto(z, c1(s, 2), z, c1(s, 1), z, c1(s, 0), z, s);
    F.montMulInto(z, dx, z, a, z, c1(s, 1), z, s);
    F.montMulInto(z, dy, z, a + 12, z, c1(s, 2), z, s);
  };

  // ================================ G2 ================================

  public func g2InfInto(z : [var Nat32], d : Nat) {
    TF.fp2SetOneMont(z, d);
    TF.fp2SetOneMont(z, d + 24);
    TF.fp2SetZero(z, d + 48);
  };

  public func g2IsInf(z : [var Nat32], d : Nat) : Bool { TF.fp2IsZero(z, d + 48) };

  public func g2Copy(z : [var Nat32], d : Nat, a : Nat) {
    TF.fp2Copy(z, d, a);
    TF.fp2Copy(z, d + 24, a + 24);
    TF.fp2Copy(z, d + 48, a + 48);
  };

  /// Load an affine L2 G2 point (normal-form Fp2 Nat coords) into Montgomery Jacobian limbs.
  /// Uses G2PRIM slot 11 (as two Fp spares) for the conversions.
  public func g2FromAffineInto(z : [var Nat32], d : Nat, p : C.G2, s : Nat) {
    switch (p) {
      case (#inf) { g2InfInto(z, d) };
      case (#pt(q)) {
        let sp = c2(s, 11);
        F.fromNat(q.x.c0, z, sp);
        F.toMontInto(z, d, z, sp, z, sp + 12, z, s);
        F.fromNat(q.x.c1, z, sp);
        F.toMontInto(z, d + 12, z, sp, z, sp + 12, z, s);
        F.fromNat(q.y.c0, z, sp);
        F.toMontInto(z, d + 24, z, sp, z, sp + 12, z, s);
        F.fromNat(q.y.c1, z, sp);
        F.toMontInto(z, d + 36, z, sp, z, sp + 12, z, s);
        TF.fp2SetOneMont(z, d + 48);
      };
    };
  };

  /// Literal L2 `g2Dbl` (same formula sequence, fp2SqrFast where L2 uses it). d may alias a.
  /// G2PRIM slots: 0=A 1=B 2=C 3=D 4=E 5=F 6=x3 7=y3 8=z3 9=tmp.
  public func g2DblInto(z : [var Nat32], d : Nat, a : Nat, s : Nat) {
    if (TF.fp2IsZero(z, a + 48)) { if (d != a) g2Copy(z, d, a); return };
    if (TF.fp2IsZero(z, a + 24)) { g2InfInto(z, d); return };
    TF.fp2SqrFastInto(z, c2(s, 0), a, s); // A = X²
    TF.fp2SqrFastInto(z, c2(s, 1), a + 24, s); // B = Y²
    TF.fp2SqrFastInto(z, c2(s, 2), c2(s, 1), s); // C = B²
    TF.fp2AddInto(z, c2(s, 9), a, c2(s, 1)); // X+B
    TF.fp2SqrFastInto(z, c2(s, 9), c2(s, 9), s);
    TF.fp2SubInto(z, c2(s, 9), c2(s, 9), c2(s, 0));
    TF.fp2SubInto(z, c2(s, 9), c2(s, 9), c2(s, 2)); // d0
    TF.fp2AddInto(z, c2(s, 3), c2(s, 9), c2(s, 9)); // D
    TF.fp2AddInto(z, c2(s, 4), c2(s, 0), c2(s, 0));
    TF.fp2AddInto(z, c2(s, 4), c2(s, 4), c2(s, 0)); // E = 3A
    TF.fp2SqrFastInto(z, c2(s, 5), c2(s, 4), s); // F = E²
    TF.fp2AddInto(z, c2(s, 9), c2(s, 3), c2(s, 3)); // 2D
    TF.fp2SubInto(z, c2(s, 6), c2(s, 5), c2(s, 9)); // x3
    TF.fp2AddInto(z, c2(s, 9), c2(s, 2), c2(s, 2));
    TF.fp2AddInto(z, c2(s, 9), c2(s, 9), c2(s, 9));
    TF.fp2AddInto(z, c2(s, 9), c2(s, 9), c2(s, 9)); // 8C
    TF.fp2SubInto(z, c2(s, 7), c2(s, 3), c2(s, 6)); // D − x3
    TF.fp2MulInto(z, c2(s, 7), c2(s, 4), c2(s, 7), s);
    TF.fp2SubInto(z, c2(s, 7), c2(s, 7), c2(s, 9)); // y3
    TF.fp2MulInto(z, c2(s, 8), a + 24, a + 48, s); // YZ
    TF.fp2AddInto(z, c2(s, 8), c2(s, 8), c2(s, 8)); // z3
    TF.fp2Copy(z, d, c2(s, 6));
    TF.fp2Copy(z, d + 24, c2(s, 7));
    TF.fp2Copy(z, d + 48, c2(s, 8));
  };

  /// Literal L2 `g2Add`. d may alias a or b.
  /// G2PRIM slots: 0=Z1Z1 1=Z2Z2 2=U1/x3 3=U2/y3 4=S1/z3 5=S2 6=H 7=I 8=J|S1J 9=r 10=V 11=tmp.
  public func g2AddInto(z : [var Nat32], d : Nat, a : Nat, b : Nat, s : Nat) {
    if (TF.fp2IsZero(z, a + 48)) { if (d != b) g2Copy(z, d, b); return };
    if (TF.fp2IsZero(z, b + 48)) { if (d != a) g2Copy(z, d, a); return };
    TF.fp2SqrFastInto(z, c2(s, 0), a + 48, s); // Z1Z1
    TF.fp2SqrFastInto(z, c2(s, 1), b + 48, s); // Z2Z2
    TF.fp2MulInto(z, c2(s, 2), a, c2(s, 1), s); // U1
    TF.fp2MulInto(z, c2(s, 3), b, c2(s, 0), s); // U2
    TF.fp2MulInto(z, c2(s, 4), a + 24, b + 48, s);
    TF.fp2MulInto(z, c2(s, 4), c2(s, 4), c2(s, 1), s); // S1
    TF.fp2MulInto(z, c2(s, 5), b + 24, a + 48, s);
    TF.fp2MulInto(z, c2(s, 5), c2(s, 5), c2(s, 0), s); // S2
    if (TF.fp2Eq(z, c2(s, 2), c2(s, 3))) {
      if (TF.fp2Eq(z, c2(s, 4), c2(s, 5))) { g2DblInto(z, d, a, s); return };
      g2InfInto(z, d);
      return;
    };
    TF.fp2SubInto(z, c2(s, 6), c2(s, 3), c2(s, 2)); // H
    TF.fp2AddInto(z, c2(s, 11), c2(s, 6), c2(s, 6)); // 2H
    TF.fp2SqrFastInto(z, c2(s, 7), c2(s, 11), s); // I
    TF.fp2MulInto(z, c2(s, 8), c2(s, 6), c2(s, 7), s); // J
    TF.fp2SubInto(z, c2(s, 9), c2(s, 5), c2(s, 4));
    TF.fp2AddInto(z, c2(s, 9), c2(s, 9), c2(s, 9)); // r
    TF.fp2MulInto(z, c2(s, 10), c2(s, 2), c2(s, 7), s); // V
    TF.fp2SqrFastInto(z, c2(s, 2), c2(s, 9), s); // r²
    TF.fp2SubInto(z, c2(s, 2), c2(s, 2), c2(s, 8));
    TF.fp2AddInto(z, c2(s, 11), c2(s, 10), c2(s, 10));
    TF.fp2SubInto(z, c2(s, 2), c2(s, 2), c2(s, 11)); // x3
    TF.fp2MulInto(z, c2(s, 8), c2(s, 4), c2(s, 8), s); // S1J
    TF.fp2SubInto(z, c2(s, 11), c2(s, 10), c2(s, 2));
    TF.fp2MulInto(z, c2(s, 3), c2(s, 9), c2(s, 11), s);
    TF.fp2AddInto(z, c2(s, 11), c2(s, 8), c2(s, 8));
    TF.fp2SubInto(z, c2(s, 3), c2(s, 3), c2(s, 11)); // y3
    TF.fp2AddInto(z, c2(s, 11), a + 48, b + 48);
    TF.fp2SqrFastInto(z, c2(s, 4), c2(s, 11), s);
    TF.fp2SubInto(z, c2(s, 4), c2(s, 4), c2(s, 0));
    TF.fp2SubInto(z, c2(s, 4), c2(s, 4), c2(s, 1));
    TF.fp2MulInto(z, c2(s, 4), c2(s, 4), c2(s, 6), s); // z3
    TF.fp2Copy(z, d, c2(s, 2));
    TF.fp2Copy(z, d + 24, c2(s, 3));
    TF.fp2Copy(z, d + 48, c2(s, 4));
  };

  public func g2MulInto(z : [var Nat32], d : Nat, p : Nat, e : [Nat32], s : Nat) {
    let base = m2(s);
    let res = m2(s) + 72;
    g2Copy(z, base, p);
    g2InfInto(z, res);
    var li = 0;
    while (li < e.size()) {
      var bits = Nat32Core.toNat64(e[li]);
      var bit = 0;
      while (bit < 32) {
        if (bits & 1 == 1) { g2AddInto(z, res, res, base, s) };
        g2DblInto(z, base, base, s);
        bits := bits >> 1;
        bit += 1;
      };
      li += 1;
    };
    g2Copy(z, d, res);
  };

  /// `[r]P == O` for G2. `tmpPt` is a caller-owned 72-limb area.
  public func g2InSubgroup(z : [var Nat32], p : Nat, tmpPt : Nat, s : Nat) : Bool {
    g2MulInto(z, tmpPt, p, R_LIMBS, s);
    g2IsInf(z, tmpPt)
  };
}
