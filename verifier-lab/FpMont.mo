/// L2 / **OPTIMIZED** — BLS12-381 base field Fp via Montgomery reduction (REDC).
///
/// Menese DeFi Team. This is the L2 counterpart to the L1 reference `Fp.mo`. It does NOT touch or
/// replace L1 — L1 stays the correctness anchor. L2 exists to remove the expensive bignum
/// **division-by-p** in every multiply: L1 does `(a*b) % P` (a division); L2 does Montgomery REDC,
/// whose only division is by `R = 2^384` (a bit-shift). The win is realized by staying in Montgomery
/// form across the many multiplies of a pairing; the byte-identity gate here proves correctness first
/// (methodology: byte-identity BEFORE cost — the actual speed is the on-canister measurement, not claimed here).
///
/// **The whole point of L2 is that it is diffed against L1.** The gate re-runs the SAME 10,000-input
/// differential as G1 and must reproduce the SAME digest. If any Montgomery constant (RR, PINV) or the
/// REDC is wrong, the digest diverges from L1 → RED. So the constants are TRANSITIVELY VALIDATED by the
/// diff, not trusted. (They were also cross-checked in python: (P·PINV) mod R ≡ −1, and REDC(a·b) ≡
/// a·b·R⁻¹ over 1000 random pairs.)
///
/// REDC(t), t < P·R:  m = ((t mod R)·PINV) mod R ;  u = (t + m·P)/R ;  u −= P if u ≥ P.  ⇒ t·R⁻¹ mod P.

import Runtime "mo:core/Runtime";

module {
  public let P : Nat =
    0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab;

  /// R = 2^384. `mod R` = mask low 384 bits; `/R` = shift right 384. Both cheap (no division-by-p).
  let R : Nat = 0x1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000;

  /// R² mod P (converts to Montgomery form). GENERATED + python-validated; digest-gate re-validates.
  let RR : Nat =
    0x11988fe592cae3aa9a793e85b519952d67eb88a9939d83c08de5476c4c95b6d50a76e6a609d104f1f4df1f341c341746;

  /// −P⁻¹ mod R (the Montgomery constant). GENERATED + python-validated; digest-gate re-validates.
  let PINV : Nat =
    0xceb06106feaafc9468b316fee268cf5819ecca0e8eb2db4c16ef2ef0c8e30b48286adb92d9d113e889f3fffcfffcfffd;

  /// Montgomery reduction. Input t must be < P·R (holds for a product of two reduced field elements).
  func redc(t : Nat) : Nat {
    let m = ((t % R) * PINV) % R;
    let u = (t + m * P) / R;
    if (u >= P) { u - P : Nat } else { u };
  };

  /// Convert a normal-form element to Montgomery form: aR mod P = REDC(a · R²).
  public func toMont(a : Nat) : Nat { redc((a % P) * RR) };

  /// Montgomery multiply: (xR)(yR)R⁻¹ = (xy)R — Montgomery-form in, Montgomery-form out.
  public func montMul(x : Nat, y : Nat) : Nat { redc(x * y) };

  // ---- normal-form API mirroring L1 (values are byte-identical to Fp.mo) ----

  /// add/sub are linear, identical to L1 (Montgomery form is not needed for them).
  public func add(a : Nat, b : Nat) : Nat { (a + b) % P };
  public func sub(a : Nat, b : Nat) : Nat { (a + P - b % P) % P };

  /// Normal-form multiply via Montgomery: REDC(a · toMont(b)) = a·(bR)·R⁻¹ = ab mod P.
  /// Removes the division-by-p that L1's `(a*b) % P` performs.
  public func mul(a : Nat, b : Nat) : Nat { redc((a % P) * toMont(b)) };

  public func sqr(a : Nat) : Nat { mul(a, a) };

  /// Fermat inverse, using the Montgomery `mul` (square-and-multiply). Same value as L1.
  public func inv(a : Nat) : Nat {
    let x = a % P;
    if (x == 0) { Runtime.trap("E_INV_ZERO") };
    powNormal(x, P - 2 : Nat);
  };
  public func invOpt(a : Nat) : ?Nat {
    let x = a % P;
    if (x == 0) { return null };
    ?powNormal(x, P - 2 : Nat);
  };

  func powNormal(a : Nat, e : Nat) : Nat {
    var result : Nat = 1 % P;
    var base = a % P;
    var exp = e;
    while (exp > 0) {
      if (exp % 2 == 1) { result := mul(result, base) };
      base := sqr(base);
      exp := exp / 2;
    };
    result;
  };
}
