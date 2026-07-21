/// In-canister Poseidon Merkle frontier over the BLS12-381 scalar field Fr.
///
/// Byte-identical port of the tree oracle's reference implementation
/// (`vendor/tree_common`, arkworks `ark-crypto-primitives` 0.5.0 `PoseidonSponge`):
///   - width t = 3 (rate 2, capacity 1), 8 full + 57 partial rounds, alpha = 5;
///     constants in `PoseidonConstants.mo`, extracted by `frontier_oracle`
///     from `find_poseidon_ark_and_mds::<Fr>(255, 2, 8, 57, 0)`.
///   - state layout [capacity | rate]: absorption writes state[1..2], the partial
///     S-box acts on state[0], squeeze reads state[1] — exactly arkworks.
///   - `merkleCompress(l, r)` = permutation of [0, l, r], lane 1 out.
///   - `append` = the incremental-frontier algorithm of `IncrementalTree::append`
///     (one cached left sibling per level, 32 compressions per append).
///
/// Field arithmetic is `groth16/Fr.mo` (plain Nat mod r — the correctness anchor the
/// Groth16 port measured as affordable; an append is ~32 permutations, orders of
/// magnitude below the in-process pairing check that already runs per operation).
///
/// Differential gate: `tests/PoseidonDifferential.mo` proves every function here
/// byte-identical to arkworks on the seeded fixtures before Main.mo may call it.
///
/// Menese DeFi Team.

import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Nat "mo:core/Nat";
import Nat8 "mo:core/Nat8";
import Nat64 "mo:core/Nat64";
import Runtime "mo:core/Runtime";
import Prim "mo:⛔";
import C "PoseidonConstants";
import Fr "groth16/Fr";

module {
  public let DEPTH : Nat = 32;
  let FULL_ROUNDS : Nat = 8;
  let PARTIAL_ROUNDS : Nat = 57;

  /// One Poseidon permutation on state (s0, s1, s2); s0 is the capacity lane.
  /// Round schedule (arkworks `permute`): 4 full, 57 partial, 4 full; each round is
  /// ARK add, S-box (all lanes on full rounds, lane 0 on partial), MDS mat-vec.
  public func permute(s0 : Nat, s1 : Nat, s2 : Nat) : (Nat, Nat, Nat) {
    var a = s0;
    var b = s1;
    var c = s2;
    let half = FULL_ROUNDS / 2;
    let ark = C.ARK;
    let mds = C.MDS;
    let m00 = mds[0][0]; let m01 = mds[0][1]; let m02 = mds[0][2];
    let m10 = mds[1][0]; let m11 = mds[1][1]; let m12 = mds[1][2];
    let m20 = mds[2][0]; let m21 = mds[2][1]; let m22 = mds[2][2];
    var round : Nat = 0;
    let total = FULL_ROUNDS + PARTIAL_ROUNDS;
    while (round < total) {
      let keys = ark[round];
      a := Fr.add(a, keys[0]);
      b := Fr.add(b, keys[1]);
      c := Fr.add(c, keys[2]);
      let isFull = round < half or round >= half + PARTIAL_ROUNDS;
      if (isFull) {
        a := sbox(a);
        b := sbox(b);
        c := sbox(c);
      } else {
        a := sbox(a);
      };
      let na = Fr.add(Fr.add(Fr.mul(m00, a), Fr.mul(m01, b)), Fr.mul(m02, c));
      let nb = Fr.add(Fr.add(Fr.mul(m10, a), Fr.mul(m11, b)), Fr.mul(m12, c));
      let nc = Fr.add(Fr.add(Fr.mul(m20, a), Fr.mul(m21, b)), Fr.mul(m22, c));
      a := na;
      b := nb;
      c := nc;
      round += 1;
    };
    (a, b, c)
  };

  /// x^5 — 2 squarings and 1 multiplication.
  func sbox(x : Nat) : Nat {
    Fr.mul(Fr.sqr(Fr.sqr(x)), x)
  };

  /// arkworks `PoseidonSponge` absorb/squeeze for the reference `hash_n` call shape:
  /// each input absorbed with its own `absorb` call (single field element), then one
  /// `squeeze_field_elements(1)`. Duplex schedule: permute when a third element
  /// arrives on a full rate section, and once more before the squeeze.
  public func hashN(inputs : [Nat]) : Nat {
    var s0 : Nat = 0;
    var s1 : Nat = 0;
    var s2 : Nat = 0;
    var absorbed : Nat = 0; // next_absorb_index within the rate section (0..2)
    for (x in inputs.vals()) {
      if (absorbed == 2) {
        let (t0, t1, t2) = permute(s0, s1, s2);
        s0 := t0; s1 := t1; s2 := t2;
        absorbed := 0;
      };
      if (absorbed == 0) { s1 := Fr.add(s1, x) } else { s2 := Fr.add(s2, x) };
      absorbed += 1;
    };
    let (_, out, _) = permute(s0, s1, s2);
    out
  };

  /// 2-to-1 Merkle compression: `hash_n([l, r])` = one permutation of [0, l, r].
  public func merkleCompress(l : Nat, r : Nat) : Nat {
    let (_, out, _) = permute(0, l, r);
    out
  };

  /// zeros[0] = 0 (the empty leaf); zeros[i+1] = compress(zeros[i], zeros[i]).
  /// zeros[32] is the empty-tree root. 33 entries.
  public func zeroHashes() : [Nat] {
    let zeros = Prim.Array_init<Nat>(DEPTH + 1, 0);
    var i : Nat = 0;
    while (i < DEPTH) {
      zeros[i + 1] := merkleCompress(zeros[i], zeros[i]);
      i += 1;
    };
    Array.fromVarArray(zeros)
  };

  /// The frontier: one cached left sibling per level plus the next leaf index.
  /// Mirrors `IncrementalTree` (and the wire `TreeState` minus the root).
  public type Frontier = {
    filled : [Nat]; // 32 entries, level 0 (leaves) upward
    nextIndex : Nat64;
  };

  public func emptyFrontier(zeros : [Nat]) : Frontier {
    { filled = Array.tabulate<Nat>(DEPTH, func(i) { zeros[i] }); nextIndex = 0 }
  };

  /// Append one leaf: returns the updated frontier and the new root — the exact
  /// `IncrementalTree::append` walk (32 compressions). Traps only on a full tree,
  /// which `append` callers must pre-check exactly as the oracle does.
  public func append(frontier : Frontier, zeros : [Nat], leaf : Nat) : (Frontier, Nat) {
    if (frontier.nextIndex >= (1 : Nat64) << 32) { Runtime.trap("tree full") };
    let filled = Array.toVarArray<Nat>(frontier.filled);
    var idx = frontier.nextIndex;
    var cur = leaf;
    var level : Nat = 0;
    while (level < DEPTH) {
      if (idx % 2 == 0) {
        filled[level] := cur;
        cur := merkleCompress(cur, zeros[level]);
      } else {
        cur := merkleCompress(filled[level], cur);
      };
      idx /= 2;
      level += 1;
    };
    (
      { filled = Array.fromVarArray(filled); nextIndex = frontier.nextIndex + 1 },
      cur,
    )
  };

  // ---- wire codec: canonical field element ⇄ 32-byte little-endian hex ----
  // Matches the reference `f_to_hex`/`f_from_hex` (arkworks compressed Fr = 32 LE
  // bytes of the canonical integer; deserialization REJECTS values >= r).

  func nibbleText(n : Nat) : Text {
    switch (n) {
      case 0 "0"; case 1 "1"; case 2 "2"; case 3 "3";
      case 4 "4"; case 5 "5"; case 6 "6"; case 7 "7";
      case 8 "8"; case 9 "9"; case 10 "a"; case 11 "b";
      case 12 "c"; case 13 "d"; case 14 "e"; case _ "f";
    }
  };

  public func natToHex(valueInput : Nat) : Text {
    if (valueInput >= Fr.P) { Runtime.trap("non-canonical field element") };
    var value = valueInput;
    var result = "";
    var i : Nat = 0;
    while (i < 32) {
      let byte = value % 256;
      result #= nibbleText(byte / 16) # nibbleText(byte % 16);
      value /= 256;
      i += 1;
    };
    result
  };

  public func natToBlob(valueInput : Nat) : Blob {
    if (valueInput >= Fr.P) { Runtime.trap("non-canonical field element") };
    let bytes = Prim.Array_init<Nat8>(32, 0);
    var value = valueInput;
    var i : Nat = 0;
    while (i < 32) {
      bytes[i] := Nat8.fromNat(value % 256);
      value /= 256;
      i += 1;
    };
    Blob.fromArray(Array.fromVarArray(bytes))
  };

  func hexNibble(c : Char) : ?Nat {
    let n = Nat64.toNat(Nat64.fromNat32(Prim.charToNat32(c)));
    if (n >= 48 and n <= 57) return ?(n - 48);
    if (n >= 97 and n <= 102) return ?(n - 87);
    if (n >= 65 and n <= 70) return ?(n - 55);
    null
  };

  /// Parse 64 hex chars as a little-endian 32-byte field element; null on bad
  /// length, bad digit, or a non-canonical (>= r) value — the same rejections
  /// `f_from_hex` performs.
  public func hexToNat(value : Text) : ?Nat {
    var result : Nat = 0;
    var shift : Nat = 1;
    var count : Nat = 0;
    var high : ?Nat = null;
    for (c in value.chars()) {
      let nibble = switch (hexNibble(c)) { case (?n) n; case null return null };
      switch (high) {
        case null { high := ?nibble };
        case (?h) {
          result += (h * 16 + nibble) * shift;
          shift *= 256;
          high := null;
          count += 1;
        };
      };
    };
    if (count != 32 or high != null) return null;
    if (result >= Fr.P) return null;
    ?result
  };

  /// Parse a 32-byte little-endian blob as a canonical field element.
  public func blobToNat(value : Blob) : ?Nat {
    if (value.size() != 32) return null;
    var result : Nat = 0;
    var shift : Nat = 1;
    for (byte in value.vals()) {
      result += Nat8.toNat(byte) * shift;
      shift *= 256;
    };
    if (result >= Fr.P) return null;
    ?result
  };
}
