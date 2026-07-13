/// **L1 REFERENCE** — compressed BLS12-381 G1 point decode, in pure `Nat`.
///
/// Menese DeFi Team. This is where the verifier meets bytes from the wire. Format = ZCash/IETF
/// (the arkworks ark-bls12-381 convention, verified against the oracle):
///   - 48 bytes, BIG-ENDIAN x.
///   - the top 3 bits of byte[0] are FLAGS, not data:
///       0x80 = compression (must be 1),  0x40 = infinity,  0x20 = sort (y is the larger root).
///   - the x-coordinate is byte[0..48] with those 3 bits masked off, and MUST be canonical (< p).
///
/// Every step here is an attack surface, so every step returns a reason CODE the oracle also emits:
///   E_BAD_LENGTH · E_BAD_FLAG · E_NONCANONICAL · E_NOT_ON_CURVE.
/// A decoder that skips the `x < p` check accepts DUPLICATE encodings of a valid point; one that
/// picks the wrong y-root silently decodes to −P. Both are wrong-accepts, so both are tested.

import Fp "Fp";
import C "Curve";
import Nat8 "mo:core/Nat8";

module {
  public type Result = { #ok : C.G1; #err : Text };

  /// Decode 48 big-endian bytes into a validated G1 point (canonical + on-curve; subgroup is checked
  /// separately by `Curve.g1Validate` — decode does the FORMAT + on-curve half).
  public func decodeG1(bytes : [Nat8] ) : Result {
    if (bytes.size() != 48) { return #err("E_BAD_LENGTH") };

    let b0 = nat8(bytes[0]);
    let compression = (b0 / 128) % 2 == 1; // 0x80
    let infinity = (b0 / 64) % 2 == 1;     // 0x40
    let sort = (b0 / 32) % 2 == 1;         // 0x20

    if (not compression) { return #err("E_BAD_FLAG") };

    // x = big-endian bytes with the top 3 flag bits of byte[0] masked off.
    let b0data = b0 % 32; // clear bits 7,6,5
    var x : Nat = b0data;
    var i : Nat = 1;
    while (i < 48) {
      x := x * 256 + nat8(bytes[i]);
      i += 1;
    };

    if (infinity) {
      // Infinity: x must be 0 and the sort bit must be 0 (canonical infinity encoding).
      if (x != 0 or sort) { return #err("E_BAD_FLAG") };
      return #ok(#inf);
    };

    // Canonical check — must be BEFORE computing y, or a non-canonical duplicate slips through.
    if (not Fp.isCanonical(x)) { return #err("E_NONCANONICAL") };

    // y² = x³ + 4
    let rhs = Fp.add(Fp.mul(Fp.sqr(x), x), 4);
    switch (Fp.sqrtOpt(rhs)) {
      case (null) { #err("E_NOT_ON_CURVE") };
      case (?y0) {
        // pick the root matching the sort bit
        let y = if (Fp.isLargerRoot(y0) == sort) { y0 } else { Fp.sub(0, y0) };
        #ok(#pt({ x; y }));
      };
    };
  };

  func nat8(b : Nat8) : Nat { Nat8.toNat(b) };
}
