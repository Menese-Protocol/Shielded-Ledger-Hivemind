/// L3 / **ALLOCATION-FLAT** — BLS12-381 base field Fp on 12×32-bit limbs, in-place Montgomery.
///
/// Menese DeFi Team. Third backend layer under the oracle methodology: L1 (`Fp.mo`, literal Nat)
/// and L2 (`FpMont.mo`, Montgomery Nat) stay untouched as correctness anchors; L3 exists to remove
/// the ALLOCATION of L2, whose immutable-Nat REDC was measured at
/// **4,763 bytes of garbage + 144k instructions per field multiply** — the proven root cause of the
/// ledger's ~340–490 MB/op EOP high-water churn.
///
/// Representation (probe-measured, not assumed):
///   - element = 12 little-endian 32-bit limbs inside a caller-owned `[var Nat32]` arena,
///     addressed by offset. `[var Nat32]` stores are 0 bytes/op; full-width Nat64 stores box.
///   - all arithmetic in unboxed Nat64 LOCALS (0 bytes/op); nothing captured by closures.
///   - every operation writes IN PLACE into the arena: zero allocation per field op.
///   - Montgomery form is IDENTICAL to L2 (R = 2^384), so limb values are diffed directly
///     against `FpMont` outputs — the differential gate that transitively validates the
///     constants below (they are ALSO python-validated against the same identities).
///
/// Montgomery multiply is CIOS (Koç–Acar–Kaliski), 32-bit word, N=12, ported line-for-line from
/// a python reference proven against the mathematical definition a·b·R⁻¹ mod P over 2000 random
/// pairs and the 0/1/P−1/P−2 edge grid before this file was written.
///
/// Scratch: `montMulInto` needs 14 Nat32 slots (`T_SLOTS`), owned by the caller inside the same
/// arena (`to` offset). The destination may alias either input (the result is written from the
/// scratch accumulator only after both inputs are fully consumed). The scratch must not overlap
/// the inputs or the destination.

import VarArray "mo:core/VarArray";
import Runtime "mo:core/Runtime";
import Prim "mo:⛔";

module {
  public let N : Nat = 12; // limbs per field element
  public let T_SLOTS : Nat = 14; // CIOS scratch slots

  /// P, little-endian 32-bit limbs (python-generated from Fp.P; gate-validated vs FpMont).
  public let P_LIMBS : [Nat32] = [
    0xffffaaab, 0xb9feffff, 0xb153ffff, 0x1eabfffe, 0xf6b0f624, 0x6730d2a0,
    0xf38512bf, 0x64774b84, 0x434bacd7, 0x4b1ba7b6, 0x397fe69a, 0x1a0111ea,
  ];

  /// P − 2, the Fermat-inverse exponent, little-endian limbs.
  let PM2_LIMBS : [Nat32] = [
    0xffffaaa9, 0xb9feffff, 0xb153ffff, 0x1eabfffe, 0xf6b0f624, 0x6730d2a0,
    0xf38512bf, 0x64774b84, 0x434bacd7, 0x4b1ba7b6, 0x397fe69a, 0x1a0111ea,
  ];

  /// −P⁻¹ mod 2^32 (equals the low limb of L2's PINV — cross-checked).
  let N0INV : Nat64 = 0xfffcfffd;

  let MASK : Nat64 = 0xFFFFFFFF;

  public func newBuf(elements : Nat) : [var Nat32] {
    VarArray.repeat<Nat32>(0, elements * N)
  };

  public func copy(z : [var Nat32], zo : Nat, a : [var Nat32], ao : Nat) {
    var j = 0;
    while (j < N) { z[zo + j] := a[ao + j]; j += 1 };
  };

  public func setZero(z : [var Nat32], zo : Nat) {
    var j = 0;
    while (j < N) { z[zo + j] := 0; j += 1 };
  };

  public func isZero(z : [var Nat32], zo : Nat) : Bool {
    var j = 0;
    while (j < N) { if (z[zo + j] != 0) return false; j += 1 };
    true
  };

  public func equal(a : [var Nat32], ao : Nat, b : [var Nat32], bo : Nat) : Bool {
    var j = 0;
    while (j < N) { if (a[ao + j] != b[bo + j]) return false; j += 1 };
    true
  };

  /// limbs(z) >= P ?
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

  /// z -= P (in place, borrow-propagating; caller guarantees z >= P).
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

  /// z := (a + b) mod P. Aliasing of z with a and/or b is safe (single LSB→MSB pass).
  public func addInto(z : [var Nat32], zo : Nat, a : [var Nat32], ao : Nat, b : [var Nat32], bo : Nat) {
    var carry : Nat64 = 0;
    var j = 0;
    while (j < N) {
      let s = Prim.nat32ToNat64(a[ao + j]) +% Prim.nat32ToNat64(b[bo + j]) +% carry;
      z[zo + j] := Prim.nat64ToNat32(s & MASK);
      carry := s >> 32;
      j += 1;
    };
    // P has 381 bits; two reduced elements sum to < 2P < 2^382, so the top carry is always 0
    // and a single conditional subtract restores canonical range.
    if (carry != 0 or geP(z, zo)) { subP(z, zo) };
  };

  /// z := (a − b) mod P. Aliasing safe.
  public func subInto(z : [var Nat32], zo : Nat, a : [var Nat32], ao : Nat, b : [var Nat32], bo : Nat) {
    var borrow : Nat64 = 0;
    var j = 0;
    while (j < N) {
      let aj = Prim.nat32ToNat64(a[ao + j]);
      let bj = Prim.nat32ToNat64(b[bo + j]);
      let d = (aj +% 0x100000000) -% bj -% borrow;
      z[zo + j] := Prim.nat64ToNat32(d & MASK);
      borrow := 1 -% (d >> 32);
      j += 1;
    };
    if (borrow != 0) {
      // went negative: add P back
      var carry : Nat64 = 0;
      var k = 0;
      while (k < N) {
        let s = Prim.nat32ToNat64(z[zo + k]) +% Prim.nat32ToNat64(P_LIMBS[k]) +% carry;
        z[zo + k] := Prim.nat64ToNat32(s & MASK);
        carry := s >> 32;
        k += 1;
      };
    };
  };

  /// z := (−a) mod P. Aliasing safe.
  public func negInto(z : [var Nat32], zo : Nat, a : [var Nat32], ao : Nat) {
    if (isZero(a, ao)) { setZero(z, zo); return };
    // P − a, borrow-free because 0 < a < P
    var borrow : Nat64 = 0;
    var j = 0;
    while (j < N) {
      let pj = Prim.nat32ToNat64(P_LIMBS[j]);
      let aj = Prim.nat32ToNat64(a[ao + j]);
      let d = (pj +% 0x100000000) -% aj -% borrow;
      z[zo + j] := Prim.nat64ToNat32(d & MASK);
      borrow := 1 -% (d >> 32);
      j += 1;
    };
  };

  /// z := a·b·R⁻¹ mod P — Montgomery multiply, CIOS, in place.
  /// `t` is the 14-slot scratch at offset `to` (must not overlap a, b, or z; z MAY alias a or b).
  public func montMulInto(
    z : [var Nat32], zo : Nat,
    a : [var Nat32], ao : Nat,
    b : [var Nat32], bo : Nat,
    t : [var Nat32], to : Nat,
  ) {
    var k = 0;
    while (k < T_SLOTS) { t[to + k] := 0; k += 1 };
    var i = 0;
    while (i < N) {
      let bi = Prim.nat32ToNat64(b[bo + i]);
      // multiplication step
      var c : Nat64 = 0;
      var j = 0;
      while (j < N) {
        let cs = Prim.nat32ToNat64(t[to + j]) +% Prim.nat32ToNat64(a[ao + j]) *% bi +% c;
        t[to + j] := Prim.nat64ToNat32(cs & MASK);
        c := cs >> 32;
        j := j + 1;
      };
      let cs0 = Prim.nat32ToNat64(t[to + N]) +% c;
      t[to + N] := Prim.nat64ToNat32(cs0 & MASK);
      t[to + N + 1] := Prim.nat64ToNat32((cs0 >> 32) & MASK);
      // reduction step
      let m = (Prim.nat32ToNat64(t[to]) *% N0INV) & MASK;
      var cr = (Prim.nat32ToNat64(t[to]) +% m *% Prim.nat32ToNat64(P_LIMBS[0])) >> 32;
      j := 1;
      while (j < N) {
        let cs = Prim.nat32ToNat64(t[to + j]) +% m *% Prim.nat32ToNat64(P_LIMBS[j]) +% cr;
        t[to + j - 1] := Prim.nat64ToNat32(cs & MASK);
        cr := cs >> 32;
        j := j + 1;
      };
      let cs1 = Prim.nat32ToNat64(t[to + N]) +% cr;
      t[to + N - 1] := Prim.nat64ToNat32(cs1 & MASK);
      t[to + N] := t[to + N + 1] +% Prim.nat64ToNat32((cs1 >> 32) & MASK);
      i += 1;
    };
    // conditional final subtraction, then write out
    if (t[to + N] != 0 or geP(t, to)) { subP(t, to) };
    var j = 0;
    while (j < N) { z[zo + j] := t[to + j]; j += 1 };
  };

  public func montSqrInto(z : [var Nat32], zo : Nat, a : [var Nat32], ao : Nat, t : [var Nat32], to : Nat) {
    montMulInto(z, zo, a, ao, a, ao, t, to);
  };

  /// z := 1 in Montgomery form (= R mod P): computed once per arena setup via fromNat boundary
  /// is avoided — callers use `oneMontInto`.
  public let ONE_MONT_LIMBS : [Nat32] = [
    // R mod P = 2^384 mod P, python-generated, gate-validated (equals FpMont.toMont(1)).
    0x0002fffd, 0x76090000, 0xc40c0002, 0xebf4000b, 0x53c758ba, 0x5f489857,
    0x70525745, 0x77ce5853, 0xa256ec6d, 0x5c071a97, 0xfa80e493, 0x15f65ec3,
  ];

  public func oneMontInto(z : [var Nat32], zo : Nat) {
    var j = 0;
    while (j < N) { z[zo + j] := ONE_MONT_LIMBS[j]; j += 1 };
  };

  public func isOneMont(z : [var Nat32], zo : Nat) : Bool {
    var j = 0;
    while (j < N) { if (z[zo + j] != ONE_MONT_LIMBS[j]) return false; j += 1 };
    true
  };

  /// z := a^e (Montgomery in/out), e as little-endian Nat32 limbs, LSB-first square-and-multiply.
  /// `work` provides one element at `wo` (mutable base); z must not alias a or work.
  public func montPowInto(
    z : [var Nat32], zo : Nat,
    a : [var Nat32], ao : Nat,
    e : [Nat32],
    work : [var Nat32], wo : Nat,
    t : [var Nat32], to : Nat,
  ) {
    oneMontInto(z, zo);
    copy(work, wo, a, ao);
    var li = 0;
    while (li < e.size()) {
      var bits = Prim.nat32ToNat64(e[li]);
      var bit = 0;
      while (bit < 32) {
        if (bits & 1 == 1) { montMulInto(z, zo, z, zo, work, wo, t, to) };
        montSqrInto(work, wo, work, wo, t, to);
        bits := bits >> 1;
        bit += 1;
      };
      li += 1;
    };
  };

  /// z := a⁻¹ (Montgomery in/out) by Fermat: a^(P−2). Traps on zero exactly like L1/L2
  /// (`E_INV_ZERO`) so trap parity is preserved.
  public func montInvInto(
    z : [var Nat32], zo : Nat,
    a : [var Nat32], ao : Nat,
    work : [var Nat32], wo : Nat,
    t : [var Nat32], to : Nat,
  ) {
    if (isZero(a, ao)) { Runtime.trap("E_INV_ZERO") };
    montPowInto(z, zo, a, ao, PM2_LIMBS, work, wo, t, to);
  };

  /// R² mod P, little-endian limbs (python-generated from FpMont.RR; gate-validated).
  let RR_LIMBS : [Nat32] = [
    0x1c341746, 0xf4df1f34, 0x09d104f1, 0x0a76e6a6, 0x4c95b6d5, 0x8de5476c,
    0x939d83c0, 0x67eb88a9, 0xb519952d, 0x9a793e85, 0x92cae3aa, 0x11988fe5,
  ];

  /// z := toMont(a) = a·R mod P, in place (montMul by R² without leaving the arena).
  /// `rr` is one spare element slot the caller provides for the RR constant.
  public func toMontInto(
    z : [var Nat32], zo : Nat,
    a : [var Nat32], ao : Nat,
    rr : [var Nat32], ro : Nat,
    t : [var Nat32], to : Nat,
  ) {
    var j = 0;
    while (j < N) { rr[ro + j] := RR_LIMBS[j]; j += 1 };
    montMulInto(z, zo, a, ao, rr, ro, t, to);
  };

  // ---- boundary conversions (allocate; used only at the arena boundary, never in hot loops) ----

  /// Load a Nat (any form — caller decides normal vs Montgomery semantics) into limbs.
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
