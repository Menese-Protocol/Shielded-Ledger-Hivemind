/// G1 / **L1 REFERENCE** — BLS12-381 base field Fq, in pure arbitrary-precision `Nat`.
///
/// Menese DeFi Team. Per `ORACLE-METHODOLOGY-motoko-verifier.md` §1: L1 is the **correctness anchor** —
/// maximally literal transcription of the mathematics, ZERO optimization, no limbs, no Montgomery.
/// It must byte-match the arkworks oracle (L0) on every vector class BEFORE any optimized L2 exists.
/// Then L2 is written as a diff against a green L1, so an L2 divergence localizes to the optimization
/// by construction.
///
/// **Do not optimize this file.** Its only job is to be obviously correct. Slowness is the point:
/// it is the thing an optimized implementation is measured against.
///
/// Why this layer is the foundation of a SILENT-ACCEPTANCE defense: a verifier bug that accepts
/// forged proofs can be a single wrong limb here. There is nothing "just arithmetic" about it.

import Runtime "mo:core/Runtime";

module {
  /// BLS12-381 base field modulus p (381 bits). Verified against the oracle's own `Fq::MODULUS`
  /// (see `oracle-vectors/G1-fp-vectors.txt` `[modulus]`) — not copied from a web page.
  public let P : Nat =
    0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab;

  /// A canonical field element is strictly less than p. Non-canonical encodings must be REJECTED,
  /// never silently reduced — a port that reduces here has an acceptance hole at the lowest layer.
  public func isCanonical(a : Nat) : Bool { a < P };

  public func add(a : Nat, b : Nat) : Nat { (a + b) % P };

  /// Subtraction in Nat cannot go negative, so add P before subtracting.
  public func sub(a : Nat, b : Nat) : Nat { (a + P - b % P) % P };

  public func mul(a : Nat, b : Nat) : Nat { (a * b) % P };

  public func sqr(a : Nat) : Nat { (a * a) % P };

  /// Modular exponentiation, square-and-multiply, MSB-first. Literal; not windowed.
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

  /// Inversion by Fermat's little theorem: a^(p-2) mod p.
  ///
  /// **inv(0) has NO inverse and this TRAPS.** The oracle emits `E_INV_ZERO` for it. A port that
  /// silently returns 0 here would disagree with the oracle on an adversarial input while agreeing
  /// on every honest one — exactly the class of divergence that value-matching valid inputs cannot
  /// see. Trapping is the correct behaviour and it is tested (§ adversarial class).
  public func inv(a : Nat) : Nat {
    let x = a % P;
    if (x == 0) { Runtime.trap("E_INV_ZERO") };
    pow(x, P - 2);
  };

  /// Same as `inv`, but returns `null` instead of trapping on zero — so the ADVERSARIAL control
  /// (`inv(0)` must not silently succeed) is an assertable test rather than a comment. A trap cannot
  /// be caught in Motoko, and an untested guard is not a guard.
  public func invOpt(a : Nat) : ?Nat {
    let x = a % P;
    if (x == 0) { return null };
    ?pow(x, P - 2);
  };

  /// Modular square root, for compressed-point decode.
  ///
  /// BLS12-381 has **p ≡ 3 (mod 4)**, so the candidate root is `a^((p+1)/4)`, and it is a genuine
  /// root iff its square is `a`. Returns `null` when `a` is a non-residue (no y on the curve) — which
  /// the decoder maps to `E_NOT_ON_CURVE`. Literal; not Tonelli–Shanks (which p ≡ 3 mod 4 does not
  /// need, and whose generality is exactly the kind of cleverness a correctness anchor should avoid).
  public func sqrtOpt(a : Nat) : ?Nat {
    let x = a % P;
    if (x == 0) { return ?0 };
    let cand = pow(x, (P + 1) / 4);
    if (sqr(cand) == x) { ?cand } else { null };
  };

  /// The ZCash/IETF "sort" convention: y is the LARGER of the two roots {y, p−y} iff y > (p−1)/2.
  /// The compressed encoding's sort bit selects this root; a decoder that picks the wrong one
  /// silently decodes to −P of the intended point.
  public func isLargerRoot(y : Nat) : Bool { y > (P - 1) / 2 };
}
