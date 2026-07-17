/// Wire encoding and Fiat-Shamir hashing for the Phase-2 ceremony coordinator, byte-for-byte
/// identical to the Rust `ceremony::transcript` module so the canister recomputes the exact same
/// challenges. Points travel UNCOMPRESSED, big-endian, 48 bytes per base-field coordinate:
///   G1 = x(48) || y(48)                               (96 bytes)
///   G2 = x.c0(48) || x.c1(48) || y.c0(48) || y.c1(48) (192 bytes)
///   Fr scalar = 32 bytes big-endian.
/// hash_to_fr(input) = reduce_LE( SHA256(0x00||input) || SHA256(0x01||input) ) mod r.

import Sha256 "mo:sha2/Sha256";
import Blob "mo:core/Blob";
import Nat8 "mo:core/Nat8";
import Array "mo:core/Array";
import List "mo:core/List";
import Runtime "mo:core/Runtime";
import C "../../src/groth16/Curve";
import Fr "../../src/groth16/Fr";

module {
  public let FR_MOD : Nat = Fr.P;

  // ---- big-endian Nat <-> bytes ----

  /// `n` as `len` big-endian bytes. Traps if `n` does not fit in `len` bytes.
  public func natToBE(n : Nat, len : Nat) : [Nat8] {
    if (n >= 256 ** len) { Runtime.trap("natToBE overflow") };
    Array.tabulate<Nat8>(len, func(i) { Nat8.fromNat((n / (256 ** (len - 1 - i))) % 256) });
  };

  public func beToNat(bytes : [Nat8], start : Nat, len : Nat) : Nat {
    var acc : Nat = 0;
    var i = 0;
    while (i < len) {
      acc := acc * 256 + Nat8.toNat(bytes[start + i]);
      i += 1;
    };
    acc;
  };

  public func concat(parts : [[Nat8]]) : [Nat8] {
    let out = List.empty<Nat8>();
    for (p in parts.vals()) { for (b in p.vals()) { List.add(out, b) } };
    List.toArray(out);
  };

  // ---- point encodings ----

  public func g1BE(p : C.G1) : [Nat8] {
    switch (p) {
      case (#inf) { Runtime.trap("g1BE on identity") };
      case (#pt(q)) { concat([natToBE(q.x, 48), natToBE(q.y, 48)]) };
    };
  };

  public func g2BE(p : C.G2) : [Nat8] {
    switch (p) {
      case (#inf) { Runtime.trap("g2BE on identity") };
      case (#pt(q)) {
        concat([natToBE(q.x.c0, 48), natToBE(q.x.c1, 48), natToBE(q.y.c0, 48), natToBE(q.y.c1, 48)]);
      };
    };
  };

  /// Decode a 96-byte G1 (validate separately on the curve/subgroup).
  public func g1FromBE(bytes : [Nat8], off : Nat) : C.G1 {
    #pt({ x = beToNat(bytes, off, 48); y = beToNat(bytes, off + 48, 48) });
  };

  /// Decode a 192-byte G2.
  public func g2FromBE(bytes : [Nat8], off : Nat) : C.G2 {
    #pt({
      x = { c0 = beToNat(bytes, off, 48); c1 = beToNat(bytes, off + 48, 48) };
      y = { c0 = beToNat(bytes, off + 96, 48); c1 = beToNat(bytes, off + 144, 48) };
    });
  };

  // ---- SHA-256 ----

  public func sha256(bytes : [Nat8]) : [Nat8] {
    Blob.toArray(Sha256.fromArray(#sha256, bytes));
  };
  public func sha256Blob(b : Blob) : [Nat8] {
    Blob.toArray(Sha256.fromBlob(#sha256, b));
  };

  /// hash_to_fr: two tagged SHA-256 blocks concatenated, read LITTLE-endian, reduced mod r.
  public func hashToFr(input : [Nat8]) : Nat {
    let a = sha256(concat([[0 : Nat8], input]));
    let b = sha256(concat([[1 : Nat8], input]));
    var acc : Nat = 0;
    var mul : Nat = 1;
    var i = 0;
    while (i < 32) { acc += Nat8.toNat(a[i]) * mul; mul *= 256; i += 1 };
    i := 0;
    while (i < 32) { acc += Nat8.toNat(b[i]) * mul; mul *= 256; i += 1 };
    acc % FR_MOD;
  };
}
