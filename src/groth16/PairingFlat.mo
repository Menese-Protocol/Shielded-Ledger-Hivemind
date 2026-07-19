/// L3 / **ALLOCATION-FLAT** — BLS12-381 pairing pipeline in place: projective G2 preparation,
/// interleaved multi-Miller loop, and the ePrint 2020/875 final exponentiation.
///
/// Menese DeFi Team. Flat counterpart of L2 `PairingProjective.mo` + `PairingFinalExp.mo`
/// (both untouched — the differential anchors). SAME coefficient schedule (ark-ec 0.5
/// `bls12/g2.rs`, ePrint 2013/722 homogeneous projective, TwistType::M), SAME sparse
/// `mul_by_014` line multiplication, SAME Granger-Scott cyclotomic squaring, NAF exp-by-x and
/// table Frobenius. Only the storage changes: everything operates on limb runs inside one
/// caller-owned arena — zero allocation in the loop bodies (profiled: the L2 Miller +
/// final exp allocated 208 MB per transfer verify).
///
/// The Frobenius/nonresidue constants below are the SAME pinned values as L2's private tables
/// (normal-form Nats). They are duplicated here because Motoko modules cannot export values
/// computed at init; the duplication is guarded by a differential test that byte-diffs every flat
/// Frobenius power and the assembled final exponentiation against L2 — a wrong digit cannot
/// pass (the same defence L2's own tables get from L1's literal x^(p^i)).
///
/// Scratch regions (continue the CurveFlat scheme; this layer calls only downward):
///   PAIR @ s + 1432 : 512 limbs — prepare/ell temporaries + finalexp fp2/fp4 temporaries
///   FEXP @ s + 1944 : 1152 limbs — Frobenius coeff table (6 Fp2) + 6 Fp12 chain temporaries
///   total SCRATCH_LIMBS = 3096 (superset of CurveFlat.SCRATCH_LIMBS = 1432)
///
/// A prepared G2 is 68 coefficients × 3 Fp2 = 4896 limbs, laid out coeff-major:
///   coeff k @ base + 72·k : c0 @ +0, c1 @ +24, c2 @ +48.

import Nat64Core "mo:core/Nat64";
import Runtime "mo:core/Runtime";
import F "FpFlat";
import TF "TowerFlat";
import FpM "FpMont";

module {
  public let SCRATCH_LIMBS : Nat = 3096;

  public let X_ABS64 : Nat64 = 0xd201000000010000; // BLS parameter |x|; X_IS_NEGATIVE = true
  public let COEFF_COUNT : Nat = 68; // bitLen(X_ABS)−1 + popCount(X_ABS)−1 = 63 + 5
  public let PREPARED_LIMBS : Nat = 4896; // COEFF_COUNT × 72 (module lets must be static)

  // ---- region bases ----
  func pr(s : Nat) : Nat { s + 1432 }; // PAIR
  func fe(s : Nat) : Nat { s + 1944 }; // FEXP

  // PAIR sub-layout (limb offsets from pr(s)):
  //   prepare: R proj @ +0 (72), step temps @ +72..312 (10 fp2), twoInv @ +312 (12),
  //            twistB @ +324 (24), qx/qy stay caller-side
  //   ell:     c1 @ +348 (24), c4 @ +372 (24)
  //   finalexp: cyclo t0..t5 @ +72..216 (6 fp2), fp4sq temps @ +216..312 (4 fp2),
  //             small fp2 temp @ +324 (24) (twistB slot, dead outside prepare)

  // FEXP sub-layout (from fe(s)): frob coeffs 6 fp2 @ +0..144
  //   (order: frob6c1p1, frob6c2p1, frob12c1p1, frob6c1p2, frob6c2p2, frob12c1p2)
  //   fp12 temps: T0 @ +144, T1 @ +288, T2 @ +432, T3 @ +576, T4 @ +720, T5 @ +864.
  func feT(s : Nat, k : Nat) : Nat { fe(s) + 144 + 144 * k };

  // ================= pinned constants (normal form; loaded via toMont at use sites) =========
  // Same values as PairingFinalExp.mo's private table (gate-validated, see module header).
  let CA : Nat = 793479390729215512621379701633421447060886740281060493010456487427281649075476305620758731620350;
  let P_MINUS_A : Nat = 4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939437;
  let P_MINUS_A_MINUS_1 : Nat = 4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939436;
  let F12_1_C0 : Nat = 3850754370037169011952147076051364057158807420970682438676050522613628423219637725072182697113062777891589506424760;
  let F12_1_C1 : Nat = 151655185184498381465642749684540099398075398968325446656007613510403227271200139370504932015952886146304766135027;

  func loadFp2Const(z : [var Nat32], d : Nat, c0 : Nat, c1 : Nat, s : Nat) {
    // toMont both coefficients through the arena (spare = ell c1 slot, dead at load time)
    let sp = pr(s) + 348;
    F.fromNat(c0, z, sp);
    F.toMontInto(z, d, z, sp, z, sp + 12, z, s);
    F.fromNat(c1, z, sp);
    F.toMontInto(z, d + 12, z, sp, z, sp + 12, z, s);
  };

  /// Load the six Frobenius coefficients (powers 1 and 2) into the FEXP table. Once per
  /// final exponentiation. Values mirror PairingFinalExp.frob6c1/frob6c2/frob12c1.
  public func loadFrobConstants(z : [var Nat32], s : Nat) {
    let base = fe(s);
    loadFp2Const(z, base, 0, P_MINUS_A_MINUS_1, s); // frob6c1(1)
    loadFp2Const(z, base + 24, P_MINUS_A, 0, s); // frob6c2(1)
    loadFp2Const(z, base + 48, F12_1_C0, F12_1_C1, s); // frob12c1(1)
    loadFp2Const(z, base + 72, CA, 0, s); // frob6c1(2)
    loadFp2Const(z, base + 96, P_MINUS_A_MINUS_1, 0, s); // frob6c2(2)
    loadFp2Const(z, base + 120, CA + 1, 0, s); // frob12c1(2)
  };

  // ================================ G2 preparation ================================

  func fp2Triple(z : [var Nat32], d : Nat, a : Nat) {
    TF.fp2AddInto(z, d, a, a);
    TF.fp2AddInto(z, d, d, a);
  };

  /// Load the two prepare constants (2⁻¹ and the twist B = 4+4u) into PAIR slots.
  func loadPrepareConstants(z : [var Nat32], s : Nat) {
    let sp = pr(s) + 348;
    F.fromNat((FpM.P + 1) / 2, z, sp);
    F.toMontInto(z, pr(s) + 312, z, sp, z, sp + 12, z, s); // twoInv (Fp)
    F.fromNat(4, z, sp);
    F.toMontInto(z, pr(s) + 324, z, sp, z, sp + 12, z, s); // twistB.c0
    F.copy(z, pr(s) + 336, z, pr(s) + 324); // twistB.c1 = same
  };

  /// ark-ec 0.5 `double_in_place` (TwistType::M) — literal L2 `doubleStep`.
  /// R @ rOff (x,y,z fp2 = 72), coeff written @ cOff (c0,c1,c2 fp2 = 72).
  /// PAIR temps: a@+72 b@+96 c@+120 e@+144 f@+168 g@+192 h@+216 i@+240 j@+264 e2/tmp@+288.
  func doubleStep(z : [var Nat32], rOff : Nat, cOff : Nat, s : Nat) {
    let p = pr(s);
    let twoInv = p + 312;
    let twistB = p + 324;
    let rx = rOff;
    let ry = rOff + 24;
    let rz = rOff + 48;
    TF.fp2MulInto(z, p + 72, rx, ry, s);
    TF.fp2MulByFpInto(z, p + 72, p + 72, twoInv, s); // a
    TF.fp2SqrFastInto(z, p + 96, ry, s); // b
    TF.fp2SqrFastInto(z, p + 120, rz, s); // c
    fp2Triple(z, p + 288, p + 120);
    TF.fp2MulInto(z, p + 144, twistB, p + 288, s); // e = twistB·3c
    fp2Triple(z, p + 168, p + 144); // f = 3e
    TF.fp2AddInto(z, p + 192, p + 96, p + 168);
    TF.fp2MulByFpInto(z, p + 192, p + 192, twoInv, s); // g = (b+f)/2
    TF.fp2AddInto(z, p + 216, ry, rz);
    TF.fp2SqrFastInto(z, p + 216, p + 216, s);
    TF.fp2SubInto(z, p + 216, p + 216, p + 96);
    TF.fp2SubInto(z, p + 216, p + 216, p + 120); // h = (y+z)² − (b+c)
    TF.fp2SubInto(z, p + 240, p + 144, p + 96); // i = e − b
    TF.fp2SqrFastInto(z, p + 264, rx, s); // j = x²
    TF.fp2SqrFastInto(z, p + 288, p + 144, s); // e²
    // next R
    TF.fp2SubInto(z, rx, p + 96, p + 168); // b − f (rx dead after j)
    TF.fp2MulInto(z, rx, p + 72, rx, s); // x' = a·(b−f)
    TF.fp2SqrFastInto(z, ry, p + 192, s); // g² (ry dead after h)
    fp2Triple(z, p + 72, p + 288); // 3e² (a dead)
    TF.fp2SubInto(z, ry, ry, p + 72); // y' = g² − 3e²
    TF.fp2MulInto(z, rz, p + 96, p + 216, s); // z' = b·h
    // coeff = (i, 3j, −h)
    TF.fp2Copy(z, cOff, p + 240);
    fp2Triple(z, cOff + 24, p + 264);
    TF.fp2NegInto(z, cOff + 48, p + 216);
  };

  /// ark-ec 0.5 `add_in_place` (TwistType::M) — literal L2 `addStep`. qx/qy affine fp2 offsets.
  /// PAIR temps: theta@+72 lambda@+96 c@+120 d@+144 e@+168 f@+192 g@+216 h@+240 tmp@+264,+288.
  func addStep(z : [var Nat32], rOff : Nat, cOff : Nat, qx : Nat, qy : Nat, s : Nat) {
    let p = pr(s);
    let rx = rOff;
    let ry = rOff + 24;
    let rz = rOff + 48;
    TF.fp2MulInto(z, p + 72, qy, rz, s);
    TF.fp2SubInto(z, p + 72, ry, p + 72); // theta = y − qy·z
    TF.fp2MulInto(z, p + 96, qx, rz, s);
    TF.fp2SubInto(z, p + 96, rx, p + 96); // lambda = x − qx·z
    TF.fp2SqrFastInto(z, p + 120, p + 72, s); // c = theta²
    TF.fp2SqrFastInto(z, p + 144, p + 96, s); // d = lambda²
    TF.fp2MulInto(z, p + 168, p + 96, p + 144, s); // e = lambda·d
    TF.fp2MulInto(z, p + 192, rz, p + 120, s); // f = z·c
    TF.fp2MulInto(z, p + 216, rx, p + 144, s); // g = x·d
    TF.fp2AddInto(z, p + 240, p + 168, p + 192);
    TF.fp2AddInto(z, p + 264, p + 216, p + 216);
    TF.fp2SubInto(z, p + 240, p + 240, p + 264); // h = e + f − 2g
    // next R
    TF.fp2MulInto(z, rx, p + 96, p + 240, s); // x' = lambda·h
    TF.fp2MulInto(z, p + 264, p + 168, ry, s); // e·y
    TF.fp2SubInto(z, p + 288, p + 216, p + 240); // g − h
    TF.fp2MulInto(z, ry, p + 72, p + 288, s);
    TF.fp2SubInto(z, ry, ry, p + 264); // y' = theta·(g−h) − e·y
    TF.fp2MulInto(z, rz, rz, p + 168, s); // z' = z·e
    // coeff = (theta·qx − lambda·qy, −theta, lambda)
    TF.fp2MulInto(z, p + 264, p + 72, qx, s);
    TF.fp2MulInto(z, p + 288, p + 96, qy, s);
    TF.fp2SubInto(z, cOff, p + 264, p + 288);
    TF.fp2NegInto(z, cOff + 24, p + 72);
    TF.fp2Copy(z, cOff + 48, p + 96);
  };

  /// Prepare an affine Montgomery G2 point (qx/qy at `q`, `q`+24) into 68 line coefficients at
  /// `coeffsBase`. Literal L2 `prepareG2` schedule. NOT for infinity (caller filters).
  public func prepareG2Into(z : [var Nat32], coeffsBase : Nat, q : Nat, s : Nat) {
    loadPrepareConstants(z, s);
    let r = pr(s); // R projective @ +0
    TF.fp2Copy(z, r, q);
    TF.fp2Copy(z, r + 24, q + 24);
    TF.fp2SetOneMont(z, r + 48);
    var at = 0;
    var i : Nat = 63; // bitLen(X_ABS) − 1
    while (i > 0) {
      i -= 1;
      doubleStep(z, r, coeffsBase + at * 72, s);
      at += 1;
      if (bitAt(i)) {
        addStep(z, r, coeffsBase + at * 72, q, q + 24, s);
        at += 1;
      };
    };
    if (at != COEFF_COUNT) { Runtime.trap("E_PREP_COEFF_COUNT") };
  };

  func bitAt(i : Nat) : Bool {
    (X_ABS64 >> Nat64Core.fromNat(i)) & 1 == 1
  };

  // ================================ Miller loop ================================

  /// Evaluate prepared coefficient `cOff` at the G1 affine Montgomery point (px, py — Fp
  /// offsets) and multiply sparsely into the Fp12 at `f`. Literal L2 `ell`.
  public func ellInto(z : [var Nat32], f : Nat, cOff : Nat, px : Nat, py : Nat, s : Nat) {
    let p = pr(s);
    TF.fp2MulByFpInto(z, p + 348, cOff + 24, px, s); // c1·px
    TF.fp2MulByFpInto(z, p + 372, cOff + 48, py, s); // c2·py
    TF.fp12MulBy014Into(z, f, f, cOff, p + 348, p + 372, s);
  };

  /// Interleaved multi-Miller over up to 4 prepared pairs — literal port of
  /// `Groth16Multi.multiMillerLoopPrepared` (one shared squaring chain, one sparse line
  /// multiplication per live pair per step, final conjugation for negative x).
  /// Pair k is described by G1 offsets (pxs/pys, in `z`), a coefficient BUFFER + base (the
  /// buffer may be `z` itself for the per-proof B, or a cached flat-vk array for the fixed
  /// pairs), and a live flag. Each step's coefficient is staged into PAIR+400 (72 limbs,
  /// Nat32 copies — zero allocation) so the tower ops always work within one arena.
  public func multiMillerInto(
    z : [var Nat32],
    f : Nat,
    live : [Bool],
    pxs : [Nat],
    pys : [Nat],
    coeffBufs : [[var Nat32]],
    coeffBases : [Nat],
    s : Nat,
  ) {
    TF.fp12SetOneMont(z, f);
    var any = false;
    for (l in live.vals()) { if (l) any := true };
    if (not any) return;
    let stage = pr(s) + 400;
    func ellStaged(k : Nat, at : Nat) {
      let buf = coeffBufs[k];
      let src = coeffBases[k] + at * 72;
      var j = 0;
      while (j < 72) { z[stage + j] := buf[src + j]; j += 1 };
      ellInto(z, f, stage, pxs[k], pys[k], s);
    };
    var at = 0;
    var i : Nat = 63;
    while (i > 0) {
      i -= 1;
      TF.fp12SqrFastInto(z, f, f, s);
      var k = 0;
      while (k < live.size()) {
        if (live[k]) { ellStaged(k, at) };
        k += 1;
      };
      at += 1;
      if (bitAt(i)) {
        k := 0;
        while (k < live.size()) {
          if (live[k]) { ellStaged(k, at) };
          k += 1;
        };
        at += 1;
      };
    };
    if (at != COEFF_COUNT) { Runtime.trap("E_MULTI_SCHEDULE") };
    TF.fp12ConjInto(z, f, f); // X_IS_NEGATIVE
  };

  // ================================ final exponentiation ================================

  /// Fp4 square — literal L2 `fp4Square`. Outputs at t0/t1 (fp2 offsets), inputs a0/a1.
  /// PAIR temps @ +216..312 (ab, s1, s2, nr).
  func fp4Square(z : [var Nat32], t0 : Nat, t1 : Nat, a0 : Nat, a1 : Nat, s : Nat) {
    let p = pr(s);
    TF.fp2MulInto(z, p + 216, a0, a1, s); // ab
    TF.fp2AddInto(z, p + 240, a0, a1); // a0+a1
    TF.fp2MulByNonresidueInto(z, p + 264, a1, s);
    TF.fp2AddInto(z, p + 264, p + 264, a0); // ξa1 + a0
    TF.fp2MulInto(z, p + 240, p + 240, p + 264, s);
    TF.fp2SubInto(z, p + 240, p + 240, p + 216);
    TF.fp2MulByNonresidueInto(z, p + 264, p + 216, s);
    TF.fp2SubInto(z, t0, p + 240, p + 264);
    TF.fp2AddInto(z, t1, p + 216, p + 216);
  };

  func tripleMinusDouble(z : [var Nat32], d : Nat, t : Nat, r : Nat, s : Nat) {
    // 2(t − r) + t, literal L2
    let tmp = pr(s) + 324;
    TF.fp2SubInto(z, tmp, t, r);
    TF.fp2AddInto(z, tmp, tmp, tmp);
    TF.fp2AddInto(z, d, tmp, t);
  };

  func triplePlusDouble(z : [var Nat32], d : Nat, t : Nat, r : Nat, s : Nat) {
    let tmp = pr(s) + 324;
    TF.fp2AddInto(z, tmp, t, r);
    TF.fp2AddInto(z, tmp, tmp, tmp);
    TF.fp2AddInto(z, d, tmp, t);
  };

  /// Granger–Scott cyclotomic square, literal L2 `cyclotomicSquare`. In place safe (d==x).
  /// PAIR temps: t0..t5 @ +72..216; fp4Square uses +216..312; helpers use +324.
  public func cyclotomicSquareInto(z : [var Nat32], d : Nat, x : Nat, s : Nat) {
    let p = pr(s);
    // tower positions: r0=x.c0.c0 r4=x.c0.c1 r3=x.c0.c2 r2=x.c1.c0 r1=x.c1.c1 r5=x.c1.c2
    fp4Square(z, p + 72, p + 96, x, x + 96, s); // (t0,t1) ← (r0, r1)
    fp4Square(z, p + 120, p + 144, x + 72, x + 48, s); // (t2,t3) ← (r2, r3)
    fp4Square(z, p + 168, p + 192, x + 24, x + 120, s); // (t4,t5) ← (r4, r5)
    // outputs are slot-aligned with their r inputs → in-place writes are safe (see gate)
    tripleMinusDouble(z, d, p + 72, x, s); // c0.c0 ← 3t0 − 2r0
    tripleMinusDouble(z, d + 24, p + 120, x + 24, s); // c0.c1 ← 3t2 − 2r4
    tripleMinusDouble(z, d + 48, p + 168, x + 48, s); // c0.c2 ← 3t4 − 2r3
    // c1.c0 ← 3·ξ(t5) + 2r2
    TF.fp2MulByNonresidueInto(z, p + 216, p + 192, s);
    triplePlusDouble(z, d + 72, p + 216, x + 72, s);
    triplePlusDouble(z, d + 96, p + 96, x + 96, s); // c1.c1 ← 3t1 + 2r1
    triplePlusDouble(z, d + 120, p + 144, x + 120, s); // c1.c2 ← 3t3 + 2r5
  };

  /// Table Frobenius for powers 1 and 2 ONLY (all the final exponentiation needs) — literal
  /// L2 `fp12Frobenius` with the FEXP coefficient table. d must not alias a.
  public func fp12FrobeniusInto(z : [var Nat32], d : Nat, a : Nat, power : Nat, s : Nat) {
    let base = fe(s);
    let (c61, c62, c121) = if (power == 1) { (base, base + 24, base + 48) } else if (power == 2) {
      (base + 72, base + 96, base + 120)
    } else { Runtime.trap("E_FROB_POWER") };
    let odd = power % 2 == 1;
    // fp6Frobenius on both halves; then c1 half gets ×frob12c1(power) per coefficient
    var half = 0;
    while (half < 2) {
      let src = a + 72 * half;
      let dst = d + 72 * half;
      // c0' = frob(c0)
      fp2FrobCopy(z, dst, src, odd);
      // c1' = frob(c1)·frob6c1
      fp2FrobCopy(z, dst + 24, src + 24, odd);
      TF.fp2MulInto(z, dst + 24, dst + 24, c61, s);
      // c2' = frob(c2)·frob6c2
      fp2FrobCopy(z, dst + 48, src + 48, odd);
      TF.fp2MulInto(z, dst + 48, dst + 48, c62, s);
      half += 1;
    };
    // c1 half × frob12c1
    TF.fp2MulInto(z, d + 72, d + 72, c121, s);
    TF.fp2MulInto(z, d + 96, d + 96, c121, s);
    TF.fp2MulInto(z, d + 120, d + 120, c121, s);
  };

  func fp2FrobCopy(z : [var Nat32], d : Nat, a : Nat, odd : Bool) {
    F.copy(z, d, z, a);
    if (odd) { F.negInto(z, d + 12, z, a + 12) } else { F.copy(z, d + 12, z, a + 12) };
  };

  /// NAF cyclotomic exponentiation by |x|, conjugated at the end (negative x) — literal L2
  /// `expByX`. d must not alias x. Uses FEXP T5 for the conjugate.
  public func expByXInto(z : [var Nat32], d : Nat, x : Nat, s : Nat) {
    let inv = feT(s, 5);
    TF.fp12ConjInto(z, inv, x);
    TF.fp12SetOneMont(z, d);
    var found = false;
    var i : Nat = 65;
    while (i > 0) {
      i -= 1;
      let digit = nafDigit(i);
      if (found) { cyclotomicSquareInto(z, d, d, s) };
      if (digit != 0) {
        found := true;
        if (digit > 0) { TF.fp12MulInto(z, d, d, x, s) } else { TF.fp12MulInto(z, d, d, inv, s) };
      };
    };
    TF.fp12ConjInto(z, d, d);
  };

  // NAF of 0xd201000000010000 — same table as L2.
  func nafDigit(i : Nat) : Int {
    if (i == 16 or i == 48 or i == 57 or i == 60 or i == 64) { 1 } else if (i == 62) { -1 } else {
      0
    }
  };

  /// f^((p⁶−1)(p²+1)) — literal L2 `easyPart`. d must not alias f. Uses FEXP T4.
  public func easyPartInto(z : [var Nat32], d : Nat, f : Nat, s : Nat) {
    let t = feT(s, 4);
    TF.fp12InvInto(z, t, f, s); // f2 = f⁻¹
    TF.fp12ConjInto(z, d, f); // f1 = conj(f)
    TF.fp12MulInto(z, t, d, t, s); // r0 = f1·f2
    fp12FrobeniusInto(z, d, t, 2, s);
    TF.fp12MulInto(z, d, d, t, s);
  };

  /// Exact L2 / ePrint 2020/875 final exponentiation chain. d must not alias f.
  /// FEXP temps: r=T0 y0=T1 y1=T2 y2=T3 (T4 easyPart, T5 expByX-conjugate).
  public func finalExponentiateInto(z : [var Nat32], d : Nat, f : Nat, s : Nat) {
    loadFrobConstants(z, s);
    let r = feT(s, 0);
    let y0 = feT(s, 1);
    let y1 = feT(s, 2);
    let y2 = feT(s, 3);
    easyPartInto(z, r, f, s);
    cyclotomicSquareInto(z, y0, r, s);
    expByXInto(z, y1, r, s);
    TF.fp12ConjInto(z, y2, r);
    TF.fp12MulInto(z, y1, y1, y2, s);
    expByXInto(z, y2, y1, s);
    TF.fp12ConjInto(z, y1, y1);
    TF.fp12MulInto(z, y1, y1, y2, s);
    expByXInto(z, y2, y1, s);
    fp12FrobeniusInto(z, d, y1, 1, s); // d as staging for frob(y1,1)
    TF.fp12Copy(z, y1, d);
    TF.fp12MulInto(z, y1, y1, y2, s);
    TF.fp12MulInto(z, r, r, y0, s);
    expByXInto(z, y0, y1, s);
    expByXInto(z, y2, y0, s);
    fp12FrobeniusInto(z, d, y1, 2, s);
    TF.fp12Copy(z, y0, d);
    TF.fp12ConjInto(z, y1, y1);
    TF.fp12MulInto(z, y1, y1, y2, s);
    TF.fp12MulInto(z, y1, y1, y0, s);
    TF.fp12MulInto(z, d, r, y1, s);
  };
}
