/// **ALLOCATION-FLAT** — BLS12-381 SCALAR field Fr on 8×32-bit limbs, in-place Montgomery.
///
/// Menese DeFi Team. Scalar-field counterpart of `FpFlat.mo` (same layer discipline):
/// `Fr.mo` (literal Nat) stays untouched as the L1 correctness anchor; this module exists
/// because the frontier cost probe measured the Nat path at 32.07M instructions and
/// 1.38 MB of garbage PER POSEIDON PERMUTATION (44 MB per tree append) — the same
/// immutable-bignum churn class the churnfix eliminated.
///
/// Two probe-driven design points (measured, not assumed):
///   1. element = 8 little-endian 32-bit limbs in a caller-owned `[var Nat32]` arena
///      (in-place stores, zero allocation per field op);
///   2. the CIOS multiply keeps BOTH operands and the whole 10-word accumulator in
///      unboxed Nat64 locals with the inner loops unrolled — the array-walking variant
///      measured ~60k instructions per multiply on IC metering (index arithmetic +
///      bounds checks dominate), the locals variant is the same algorithm with 16
///      loads + 8 stores of array traffic per call.
///
/// CIOS is ported from `FpFlat.montMulInto` (N = 12 → 8) and was re-proven for these
/// parameters against the mathematical definition a·b·R⁻¹ mod r (R = 2^256) in python
/// over a 64-pair edge grid (0/1/2/r−1/r−2/2^64/2^128/2^255) + 2000 random pairs before
/// the first version of this file; the in-loop word-overflow bounds were asserted on
/// every pair. Constants below are from that python run and are TRANSITIVELY VALIDATED
/// by the Poseidon differential gate (18,360 arkworks byte-identity comparisons re-run
/// on every backend change): a wrong limb anywhere diverges the very first vector.
///
/// Only the operations Poseidon needs are provided (add, CIOS mul/sqr, to/from-Montgomery,
/// constant loads, boundary Nat conversions) — no inverse, no pow: nothing here is a stub.

import VarArray "mo:core/VarArray";
import Runtime "mo:core/Runtime";
import Prim "mo:⛔";

module {
  public let N : Nat = 8; // limbs per field element

  /// r, little-endian 32-bit limbs (python-generated from Fr.P; gate-validated).
  public let P_LIMBS : [Nat32] = [
    0x00000001, 0xffffffff, 0xfffe5bfe, 0x53bda402,
    0x09a1d805, 0x3339d808, 0x299d7d48, 0x73eda753,
  ];

  // r limbs as static Nat64 values (the unrolled CIOS and subtract read these).
  let PL0 : Nat64 = 0x00000001; let PL1 : Nat64 = 0xffffffff;
  let PL2 : Nat64 = 0xfffe5bfe; let PL3 : Nat64 = 0x53bda402;
  let PL4 : Nat64 = 0x09a1d805; let PL5 : Nat64 = 0x3339d808;
  let PL6 : Nat64 = 0x299d7d48; let PL7 : Nat64 = 0x73eda753;

  /// −r⁻¹ mod 2^32 (r ≡ 1 mod 2^32, so this is 2^32 − 1; python-validated: r·r⁻¹ ≡ 1).
  let N0INV : Nat64 = 0xffffffff;

  let MASK : Nat64 = 0xFFFFFFFF;

  public func newBuf(elements : Nat) : [var Nat32] {
    VarArray.repeat<Nat32>(0, elements * N)
  };

  public func copy(z : [var Nat32], zo : Nat, a : [var Nat32], ao : Nat) {
    var j = 0;
    while (j < N) { z[zo + j] := a[ao + j]; j += 1 };
  };

  /// Load an immutable constant table entry (e.g. a Montgomery-form round constant)
  /// into the arena.
  public func loadConst(z : [var Nat32], zo : Nat, c : [Nat32], co : Nat) {
    var j = 0;
    while (j < N) { z[zo + j] := c[co + j]; j += 1 };
  };

  public func setZero(z : [var Nat32], zo : Nat) {
    var j = 0;
    while (j < N) { z[zo + j] := 0; j += 1 };
  };

  /// limbs(z) >= r ?
  func geP(z : [var Nat32], zo : Nat) : Bool {
    var j = N;
    while (j > 0) {
      j -= 1;
      let l = z[zo + j];
      let p = P_LIMBS[j];
      if (l > p) return true;
      if (l < p) return false;
    };
    true // equal
  };

  /// z -= r (in place, borrow-propagating; caller guarantees z >= r).
  func subP(z : [var Nat32], zo : Nat) {
    var borrow : Nat64 = 0;
    var j = 0;
    while (j < N) {
      let zj = Prim.nat32ToNat64(z[zo + j]);
      let pj = Prim.nat32ToNat64(P_LIMBS[j]);
      let d = (zj +% 0x100000000) -% pj -% borrow;
      z[zo + j] := Prim.nat64ToNat32(d & MASK);
      borrow := 1 -% (d >> 32);
      j += 1;
    };
  };

  /// z := (a + b) mod r. Aliasing of z with a and/or b is safe (single LSB→MSB pass).
  public func addInto(z : [var Nat32], zo : Nat, a : [var Nat32], ao : Nat, b : [var Nat32], bo : Nat) {
    var carry : Nat64 = 0;
    var j = 0;
    while (j < N) {
      let s = Prim.nat32ToNat64(a[ao + j]) +% Prim.nat32ToNat64(b[bo + j]) +% carry;
      z[zo + j] := Prim.nat64ToNat32(s & MASK);
      carry := s >> 32;
      j += 1;
    };
    // r has 255 bits; two reduced elements sum to < 2r < 2^256, so the top carry is
    // always 0 and a single conditional subtract restores canonical range.
    if (carry != 0 or geP(z, zo)) { subP(z, zo) };
  };

  /// z := (a + c) mod r with `c` an immutable constant table (e.g. Montgomery-form
  /// round constants). Same single-pass body as `addInto`; aliasing of z with a is safe.
  public func addConstInto(z : [var Nat32], zo : Nat, a : [var Nat32], ao : Nat, c : [Nat32], co : Nat) {
    var carry : Nat64 = 0;
    var j = 0;
    while (j < N) {
      let s = Prim.nat32ToNat64(a[ao + j]) +% Prim.nat32ToNat64(c[co + j]) +% carry;
      z[zo + j] := Prim.nat64ToNat32(s & MASK);
      carry := s >> 32;
      j += 1;
    };
    if (carry != 0 or geP(z, zo)) { subP(z, zo) };
  };

  /// z := a·b·R⁻¹ mod r — Montgomery multiply, CIOS, operand limbs and the whole
  /// 10-word accumulator held in unboxed Nat64 LOCALS (the inner j-loops are unrolled;
  /// bounds-checked array traffic is 16 loads + 8 stores per call instead of ~200 —
  /// the cost probe measured the array-walking variant at ~60k instructions/mul on IC
  /// metering, dominated by index arithmetic + bounds checks, not the multiplies).
  /// Same algorithm word-for-word as the python-proven CIOS; z MAY alias a or b.
  public func montMulInto(
    z : [var Nat32], zo : Nat,
    a : [var Nat32], ao : Nat,
    b : [var Nat32], bo : Nat,
  ) {
    let a0 = Prim.nat32ToNat64(a[ao + 0]);
    let a1 = Prim.nat32ToNat64(a[ao + 1]);
    let a2 = Prim.nat32ToNat64(a[ao + 2]);
    let a3 = Prim.nat32ToNat64(a[ao + 3]);
    let a4 = Prim.nat32ToNat64(a[ao + 4]);
    let a5 = Prim.nat32ToNat64(a[ao + 5]);
    let a6 = Prim.nat32ToNat64(a[ao + 6]);
    let a7 = Prim.nat32ToNat64(a[ao + 7]);
    var t0 : Nat64 = 0;
    var t1 : Nat64 = 0;
    var t2 : Nat64 = 0;
    var t3 : Nat64 = 0;
    var t4 : Nat64 = 0;
    var t5 : Nat64 = 0;
    var t6 : Nat64 = 0;
    var t7 : Nat64 = 0;
    var t8 : Nat64 = 0;
    var t9 : Nat64 = 0;
    var i = 0;
    while (i < 8) {
      let bi = Prim.nat32ToNat64(b[bo + i]);
      var cs : Nat64 = t0 +% a0 *% bi; t0 := cs & MASK; var c = cs >> 32;
      cs := t1 +% a1 *% bi +% c; t1 := cs & MASK; c := cs >> 32;
      cs := t2 +% a2 *% bi +% c; t2 := cs & MASK; c := cs >> 32;
      cs := t3 +% a3 *% bi +% c; t3 := cs & MASK; c := cs >> 32;
      cs := t4 +% a4 *% bi +% c; t4 := cs & MASK; c := cs >> 32;
      cs := t5 +% a5 *% bi +% c; t5 := cs & MASK; c := cs >> 32;
      cs := t6 +% a6 *% bi +% c; t6 := cs & MASK; c := cs >> 32;
      cs := t7 +% a7 *% bi +% c; t7 := cs & MASK; c := cs >> 32;
      let cs0 = t8 +% c; t8 := cs0 & MASK; t9 := cs0 >> 32;
      let m = (t0 *% N0INV) & MASK;
      var cr = (t0 +% m *% PL0) >> 32;
      cs := t1 +% m *% PL1 +% cr; t0 := cs & MASK; cr := cs >> 32;
      cs := t2 +% m *% PL2 +% cr; t1 := cs & MASK; cr := cs >> 32;
      cs := t3 +% m *% PL3 +% cr; t2 := cs & MASK; cr := cs >> 32;
      cs := t4 +% m *% PL4 +% cr; t3 := cs & MASK; cr := cs >> 32;
      cs := t5 +% m *% PL5 +% cr; t4 := cs & MASK; cr := cs >> 32;
      cs := t6 +% m *% PL6 +% cr; t5 := cs & MASK; cr := cs >> 32;
      cs := t7 +% m *% PL7 +% cr; t6 := cs & MASK; cr := cs >> 32;
      let cs1 = t8 +% cr; t7 := cs1 & MASK; t8 := t9 +% (cs1 >> 32);
      i += 1;
    };
    // conditional final subtraction (t8 is the top word; also subtract when t7..t0 >= r)
    let ge = if (t8 != 0) true
    else if (t7 != PL7) (t7 > PL7)
    else if (t6 != PL6) (t6 > PL6)
    else if (t5 != PL5) (t5 > PL5)
    else if (t4 != PL4) (t4 > PL4)
    else if (t3 != PL3) (t3 > PL3)
    else if (t2 != PL2) (t2 > PL2)
    else if (t1 != PL1) (t1 > PL1)
    else (t0 >= PL0);
    if (ge) {
      var d : Nat64 = (t0 +% 0x100000000) -% PL0; t0 := d & MASK; var bw = 1 -% (d >> 32);
      d := (t1 +% 0x100000000) -% PL1 -% bw; t1 := d & MASK; bw := 1 -% (d >> 32);
      d := (t2 +% 0x100000000) -% PL2 -% bw; t2 := d & MASK; bw := 1 -% (d >> 32);
      d := (t3 +% 0x100000000) -% PL3 -% bw; t3 := d & MASK; bw := 1 -% (d >> 32);
      d := (t4 +% 0x100000000) -% PL4 -% bw; t4 := d & MASK; bw := 1 -% (d >> 32);
      d := (t5 +% 0x100000000) -% PL5 -% bw; t5 := d & MASK; bw := 1 -% (d >> 32);
      d := (t6 +% 0x100000000) -% PL6 -% bw; t6 := d & MASK; bw := 1 -% (d >> 32);
      d := (t7 +% 0x100000000) -% PL7 -% bw; t7 := d & MASK; bw := 1 -% (d >> 32);
    };
    z[zo + 0] := Prim.nat64ToNat32(t0);
    z[zo + 1] := Prim.nat64ToNat32(t1);
    z[zo + 2] := Prim.nat64ToNat32(t2);
    z[zo + 3] := Prim.nat64ToNat32(t3);
    z[zo + 4] := Prim.nat64ToNat32(t4);
    z[zo + 5] := Prim.nat64ToNat32(t5);
    z[zo + 6] := Prim.nat64ToNat32(t6);
    z[zo + 7] := Prim.nat64ToNat32(t7);
  };

  public func montSqrInto(z : [var Nat32], zo : Nat, a : [var Nat32], ao : Nat) {
    montMulInto(z, zo, a, ao, a, ao);
  };

  /// R² mod r, little-endian limbs (python-generated; gate-validated).
  let RR_LIMBS : [Nat32] = [
    0xf3f29c6d, 0xc999e990, 0x87925c23, 0x2b6cedcb,
    0x7254398f, 0x05d31496, 0x9f59ff11, 0x0748d9d9,
  ];

  /// The integer 1 (NOT Montgomery form): montMul(a, 1) = a·R⁻¹ = fromMont(a).
  let ONE_LIMBS : [Nat32] = [1, 0, 0, 0, 0, 0, 0, 0];

  /// z := toMont(a) = a·R mod r. `rr` is one spare element slot for the RR constant.
  public func toMontInto(
    z : [var Nat32], zo : Nat,
    a : [var Nat32], ao : Nat,
    rr : [var Nat32], ro : Nat,
  ) {
    loadConst(rr, ro, RR_LIMBS, 0);
    montMulInto(z, zo, a, ao, rr, ro);
  };

  /// z := fromMont(a) = a·R⁻¹ mod r. `one` is one spare element slot for the 1 constant.
  public func fromMontInto(
    z : [var Nat32], zo : Nat,
    a : [var Nat32], ao : Nat,
    one : [var Nat32], oo : Nat,
  ) {
    loadConst(one, oo, ONE_LIMBS, 0);
    montMulInto(z, zo, a, ao, one, oo);
  };

  // ---- boundary conversions (bignum ops only at the arena boundary) ----

  /// Load a canonical Nat into limbs. Traps if the value needs more than 8 limbs.
  public func fromNat(x : Nat, z : [var Nat32], zo : Nat) {
    var v = x;
    var j = 0;
    while (j < N) {
      z[zo + j] := Prim.natToNat32(v % 0x100000000);
      v := v / 0x100000000;
      j += 1;
    };
    if (v != 0) { Runtime.trap("E_LIMB_OVERFLOW") };
  };

  /// Read limbs back into a Nat.
  public func toNat(z : [var Nat32], zo : Nat) : Nat {
    var v : Nat = 0;
    var j = N;
    while (j > 0) {
      j -= 1;
      v := v * 0x100000000 + Prim.nat32ToNat(z[zo + j]);
    };
    v
  };
}
