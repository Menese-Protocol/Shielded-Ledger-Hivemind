/// **L1 REFERENCE** — BLS12-381 SCALAR field Fr (mod r), in pure `Nat`.
///
/// Menese DeFi Team. This is the field the **circuit and the Merkle tree** live over (the SNARK
/// constraint system is over the scalar field r), distinct from the base field Fp (mod q) used by the
/// pairing tower. Flavor-independent: every PLONK-KZG flavor works over Fr. Mirrors `Fp.mo` exactly,
/// with the scalar modulus. ZERO optimization — the correctness anchor.
///
/// r ≡ 1 (mod 4), so the p ≡ 3 mod 4 sqrt shortcut used in `Fp` does NOT apply here — and Fr needs no
/// square root anyway (point decompression is a base-field operation). No `sqrtOpt` is provided.

import Runtime "mo:core/Runtime";

module {
  /// BLS12-381 scalar field modulus r. Cross-checked against the froracle `[modulus] p=` line and
  /// equal to `Curve.R` (the scalar field modulus IS the group order).
  public let P : Nat =
    0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;

  public func isCanonical(a : Nat) : Bool { a < P };

  public func add(a : Nat, b : Nat) : Nat { (a + b) % P };
  public func sub(a : Nat, b : Nat) : Nat { (a + P - b % P) % P };
  public func mul(a : Nat, b : Nat) : Nat { (a * b) % P };
  public func sqr(a : Nat) : Nat { (a * a) % P };

  public func pow(a : Nat, e : Nat) : Nat {
    if (e == 0) { return 1 % P };
    var result : Nat = 1;
    var base : Nat = a % P;
    var exp : Nat = e;
    while (exp > 0) {
      if (exp % 2 == 1) { result := (result * base) % P };
      base := (base * base) % P;
      exp := exp / 2;
    };
    result;
  };

  public func inv(a : Nat) : Nat {
    let x = a % P;
    if (x == 0) { Runtime.trap("E_INV_ZERO") };
    pow(x, P - 2);
  };

  public func invOpt(a : Nat) : ?Nat {
    let x = a % P;
    if (x == 0) { return null };
    ?pow(x, P - 2);
  };
}
