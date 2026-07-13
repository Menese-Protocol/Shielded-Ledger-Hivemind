/// **L1 REFERENCE** — compressed BLS12-381 G2 point decode, in pure `Nat`.
///
/// Menese DeFi Team. Companion to `Decode.mo` (G1); same ZCash/IETF format,
/// verified against the arkworks oracle:
///   - 96 bytes. The FIRST 48 bytes are x.c1 big-endian (flags in the top 3 bits of byte[0]);
///     the SECOND 48 bytes are x.c0 big-endian. (ZCash serializes the c1 limb first.)
///   - flags: 0x80 = compression (must be 1), 0x40 = infinity, 0x20 = sort.
///   - BOTH limbs must be canonical (< p); infinity requires x == 0 and sort == 0.
///   - sort selects the y root that is lexicographically LARGER, where Fp2 comparison is
///     (c1 first, then c0): y is larger iff y.c1 > (p−1)/2, or y.c1 == 0 and y.c0 > (p−1)/2.
///
/// The square root in Fp2 uses the complex method over Fp[u]/(u²+1) (norm + two half-trace
/// candidates), each candidate root VERIFIED BY SQUARING — a non-residue rhs (x off the curve)
/// returns `null`, never a wrong root. Reason codes match Decode.mo:
///   E_BAD_LENGTH · E_BAD_FLAG · E_NONCANONICAL · E_NOT_ON_CURVE.
/// Subgroup membership is NOT decode's job (Curve.g2Validate / CurveJac.g2Validate own it) —
/// same split as G1.

import Fp "Fp";
import T "Tower";
import C "Curve";
import Nat8 "mo:core/Nat8";

module {
  public type Result = { #ok : C.G2; #err : Text };

  /// sqrt in Fp2 = Fp[u]/(u²+1), p ≡ 3 (mod 4). Complex method:
  /// N(a) = a0² + a1² must be a QR in Fp (iff a is a QR in Fp2); with s = √N(a),
  /// one of α = (a0 ± s)/2 is a QR in Fp; then x0 = √α, x1 = a1/(2·x0).
  /// Every returned root satisfies root² == a BY CHECK, not by construction.
  public func sqrtFp2Opt(a : T.Fp2) : ?T.Fp2 {
    if (a.c1 == 0) {
      // a is in the base field: either a0 is a QR (root in Fp) or −a0 is (root on the u-axis,
      // since (t·u)² = −t²).
      switch (Fp.sqrtOpt(a.c0)) {
        case (?s) { return checked(a, { c0 = s; c1 = 0 }) };
        case (null) {
          switch (Fp.sqrtOpt(Fp.sub(0, a.c0))) {
            case (?t) { return checked(a, { c0 = 0; c1 = t }) };
            case (null) { return null };
          };
        };
      };
    };
    let norm = Fp.add(Fp.sqr(a.c0), Fp.sqr(a.c1));
    switch (Fp.sqrtOpt(norm)) {
      case (null) { null };
      case (?s) {
        // One of the two half-trace candidates carries the root; a candidate with x0 = 0 is
        // degenerate (would need a1 = 0) and the OTHER candidate must be tried. The final
        // verify-by-squaring is what accepts — never the construction.
        let inv2 = Fp.inv(2);
        for (alpha in [Fp.mul(Fp.add(a.c0, s), inv2), Fp.mul(Fp.sub(a.c0, s), inv2)].values()) {
          switch (Fp.sqrtOpt(alpha)) {
            case (null) {};
            case (?x0) {
              if (x0 != 0) {
                let x1 = Fp.mul(a.c1, Fp.inv(Fp.add(x0, x0)));
                switch (checked(a, { c0 = x0; c1 = x1 })) {
                  case (?root) { return ?root };
                  case (null) {};
                };
              };
            };
          };
        };
        null;
      };
    };
  };

  func checked(a : T.Fp2, root : T.Fp2) : ?T.Fp2 {
    if (T.fp2Eq(T.fp2Sqr(root), a)) { ?root } else { null };
  };

  /// The ZCash lexicographic-largest convention on Fp2: compare c1 first, then c0.
  public func isLargerRootFp2(y : T.Fp2) : Bool {
    if (y.c1 != 0) { Fp.isLargerRoot(y.c1) } else { Fp.isLargerRoot(y.c0) };
  };

  /// Decode 96 bytes into a validated G2 point (format + canonical + on-curve; subgroup checked
  /// separately, same split as `Decode.decodeG1`).
  public func decodeG2(bytes : [Nat8]) : Result {
    if (bytes.size() != 96) { return #err("E_BAD_LENGTH") };

    let b0 = Nat8.toNat(bytes[0]);
    let compression = (b0 / 128) % 2 == 1; // 0x80
    let infinity = (b0 / 64) % 2 == 1;     // 0x40
    let sort = (b0 / 32) % 2 == 1;         // 0x20

    if (not compression) { return #err("E_BAD_FLAG") };

    // First limb (with flags masked) is x.c1; second is x.c0.
    var xc1 : Nat = b0 % 32;
    var i : Nat = 1;
    while (i < 48) { xc1 := xc1 * 256 + Nat8.toNat(bytes[i]); i += 1 };
    var xc0 : Nat = 0;
    while (i < 96) { xc0 := xc0 * 256 + Nat8.toNat(bytes[i]); i += 1 };

    if (infinity) {
      if (xc0 != 0 or xc1 != 0 or sort) { return #err("E_BAD_FLAG") };
      return #ok(#inf);
    };

    // Canonical check on BOTH limbs, before any arithmetic.
    if (not Fp.isCanonical(xc0) or not Fp.isCanonical(xc1)) { return #err("E_NONCANONICAL") };

    // y² = x³ + 4(1+u)
    let x : T.Fp2 = { c0 = xc0; c1 = xc1 };
    let rhs = T.fp2Add(T.fp2Mul(T.fp2Sqr(x), x), { c0 = 4; c1 = 4 });
    switch (sqrtFp2Opt(rhs)) {
      case (null) { #err("E_NOT_ON_CURVE") };
      case (?y0) {
        let y = if (isLargerRootFp2(y0) == sort) { y0 } else { T.fp2Neg(y0) };
        #ok(#pt({ x; y }));
      };
    };
  };
}
