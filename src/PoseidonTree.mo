/// In-canister Poseidon Merkle frontier over the BLS12-381 scalar field Fr.
///
/// Byte-identical port of the tree oracle's reference implementation
/// (`vendor/tree_common`, arkworks `ark-crypto-primitives` 0.5.0 `PoseidonSponge`):
///   - width t = 3 (rate 2, capacity 1), 8 full + 57 partial rounds, alpha = 5;
///     constants in `PoseidonConstants.mo`, extracted by `frontier_oracle`
///     from `find_poseidon_ark_and_mds::<Fr>(255, 2, 8, 57, 0)`.
///   - state layout [capacity | rate]: absorption writes lanes 1..2, the partial
///     S-box acts on lane 0, squeeze reads lane 1 — exactly arkworks.
///   - `merkleCompress(l, r)` = permutation of [0, l, r], lane 1 out.
///   - `append` = the incremental-frontier algorithm of `IncrementalTree::append`
///     (one cached left sibling per level, 32 compressions per append).
///
/// Field arithmetic is `groth16/FrFlat.mo` — in-place Montgomery on 8×32-bit limbs
/// (the flat, allocation-disciplined style). The first port ran
/// on plain-Nat `Fr.mo` and was proven byte-identical to arkworks (18,360-comparison
/// differential, 2 passes, 4 seeds); the cost probe then measured it at 32.07M
/// instructions + 1.38 MB garbage per permutation (44 MB per append) — churnfix-class
/// allocation — so the internals moved to FrFlat and the ENTIRE differential gate is
/// re-run on this backend. Round constants are converted to Montgomery form once at
/// module init; the permutation itself allocates nothing.
///
/// Differential gate: `tests/PoseidonDifferential.mo` proves every public function
/// here byte-identical to arkworks on the seeded fixtures before Main.mo may call it.
///
/// Menese DeFi Team.

import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Nat "mo:core/Nat";
import Nat8 "mo:core/Nat8";
import Nat64 "mo:core/Nat64";
import Runtime "mo:core/Runtime";
import VarArray "mo:core/VarArray";
import Prim "mo:⛔";
import C "PoseidonConstants";
import Fr "groth16/Fr";
import F "groth16/FrFlat";

module {
  public let DEPTH : Nat = 32;
  let PARTIAL_ROUNDS : Nat = 57;
  let ROUNDS : Nat = 65; // 8 full + 57 partial
  let HALF_FULL : Nat = 4; // full_rounds / 2

  // ---- working arena layout (Nat32 limb offsets; one element = 8 limbs) ----
  // 0..55   perm slots: s0 s1 s2 n0 n1 n2 tmp
  // 56..63  spare element (RR / ONE / MDS-constant slot)
  // 64..71  cur (chained value, Montgomery form)
  // 72..79  sib (sibling / conversion scratch)
  let S0 : Nat = 0;
  let S1 : Nat = 8;
  let S2 : Nat = 16;
  let N0 : Nat = 24;
  let TMP : Nat = 48;
  let SPARE : Nat = 56;
  let CUR : Nat = 64;
  let SIB : Nat = 72;
  let ARENA : Nat = 80;

  func newArena() : [var Nat32] { VarArray.repeat<Nat32>(0, ARENA) };

  /// Round constants in Montgomery form: static literal tables emitted by the oracle
  /// (`C.ARK_MONT[(round*3 + lane)*8 ..]`, `C.MDS_MONT[(i*3 + j)*8 ..]` — arkworks'
  /// internal a·2^256 mod r repr, the exact operand form of the FrFlat CIOS). The
  /// canonical `C.ARK`/`C.MDS` stay alongside; the differential gate validates both
  /// forms transitively (any wrong limb diverges the first vector).
  let ARK_M : [Nat32] = C.ARK_MONT;
  let MDS_M : [Nat32] = C.MDS_MONT;

  /// x := x^5 for the element at offset `off` (2 squarings + 1 multiply, in place).
  func sboxAt(w : [var Nat32], off : Nat) {
    F.montSqrInto(w, TMP, w, off);
    F.montSqrInto(w, TMP, w, TMP);
    F.montMulInto(w, off, w, TMP, w, off);
  };

  /// One full 65-round permutation on slots S0..S2 (Montgomery form), in place.
  /// Round = ARK add; S-box on all lanes (full rounds) or lane 0 (partial); MDS mat-vec.
  func permuteCore(w : [var Nat32]) {
    var round = 0;
    while (round < ROUNDS) {
      let arkBase = round * 24;
      F.addConstInto(w, S0, w, S0, ARK_M, arkBase);
      F.addConstInto(w, S1, w, S1, ARK_M, arkBase + 8);
      F.addConstInto(w, S2, w, S2, ARK_M, arkBase + 16);
      if (round < HALF_FULL or round >= HALF_FULL + PARTIAL_ROUNDS) {
        sboxAt(w, S0);
        sboxAt(w, S1);
        sboxAt(w, S2);
      } else {
        sboxAt(w, S0);
      };
      var i = 0;
      while (i < 3) {
        let outOff = N0 + i * 8;
        F.loadConst(w, SPARE, MDS_M, (i * 3) * 8);
        F.montMulInto(w, outOff, w, SPARE, w, S0);
        F.loadConst(w, SPARE, MDS_M, (i * 3 + 1) * 8);
        F.montMulInto(w, TMP, w, SPARE, w, S1);
        F.addInto(w, outOff, w, outOff, w, TMP);
        F.loadConst(w, SPARE, MDS_M, (i * 3 + 2) * 8);
        F.montMulInto(w, TMP, w, SPARE, w, S2);
        F.addInto(w, outOff, w, outOff, w, TMP);
        i += 1;
      };
      F.copy(w, S0, w, N0);
      F.copy(w, S1, w, N0 + 8);
      F.copy(w, S2, w, N0 + 16);
      round += 1;
    };
  };

  func loadMont(w : [var Nat32], off : Nat, value : Nat) {
    F.fromNat(value, w, off);
    F.toMontInto(w, off, w, off, w, SPARE);
  };

  func readCanonical(w : [var Nat32], off : Nat) : Nat {
    F.fromMontInto(w, SIB, w, off, w, SPARE);
    F.toNat(w, SIB)
  };

  /// One Poseidon permutation on canonical state (s0, s1, s2); s0 is the capacity lane.
  public func permute(s0 : Nat, s1 : Nat, s2 : Nat) : (Nat, Nat, Nat) {
    let w = newArena();
    loadMont(w, S0, s0);
    loadMont(w, S1, s1);
    loadMont(w, S2, s2);
    permuteCore(w);
    let o2 = readCanonical(w, S2); // SIB is scratch for reads; order irrelevant
    let o1 = readCanonical(w, S1);
    let o0 = readCanonical(w, S0);
    (o0, o1, o2)
  };

  /// `n` chained permutations on canonical state — permute applied n times (one
  /// boundary conversion pair total). n = 1 is exactly `permute`. Exists so the cost
  /// probe can separate the round-loop cost from the Nat⇄limb boundary cost.
  public func permuteN(s0 : Nat, s1 : Nat, s2 : Nat, n : Nat) : (Nat, Nat, Nat) {
    let w = newArena();
    loadMont(w, S0, s0);
    loadMont(w, S1, s1);
    loadMont(w, S2, s2);
    var i = 0;
    while (i < n) { permuteCore(w); i += 1 };
    let o2 = readCanonical(w, S2);
    let o1 = readCanonical(w, S1);
    let o0 = readCanonical(w, S0);
    (o0, o1, o2)
  };

  /// arkworks `PoseidonSponge` absorb/squeeze for the reference `hash_n` call shape:
  /// each input absorbed with its own `absorb` call (single field element), then one
  /// `squeeze_field_elements(1)`. Duplex schedule: permute when a third element
  /// arrives on a full rate section, and once more before the squeeze.
  public func hashN(inputs : [Nat]) : Nat {
    let w = newArena();
    var absorbed : Nat = 0; // next_absorb_index within the rate section (0..2)
    for (x in inputs.vals()) {
      if (absorbed == 2) {
        permuteCore(w);
        absorbed := 0;
      };
      loadMont(w, CUR, x);
      let lane = if (absorbed == 0) S1 else S2;
      F.addInto(w, lane, w, lane, w, CUR);
      absorbed += 1;
    };
    permuteCore(w);
    readCanonical(w, S1)
  };

  /// 2-to-1 Merkle compression: `hash_n([l, r])` = one permutation of [0, l, r].
  public func merkleCompress(l : Nat, r : Nat) : Nat {
    let w = newArena();
    loadMont(w, S1, l);
    loadMont(w, S2, r);
    permuteCore(w);
    readCanonical(w, S1)
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
  /// `IncrementalTree::append` walk (32 compressions, `cur` chained in Montgomery
  /// form across levels). Traps only on a full tree, which callers must pre-check
  /// exactly as the oracle does.
  public func append(frontier : Frontier, zeros : [Nat], leaf : Nat) : (Frontier, Nat) {
    if (frontier.nextIndex >= (1 : Nat64) << 32) { Runtime.trap("tree full") };
    let filled = Array.toVarArray<Nat>(frontier.filled);
    let w = newArena();
    loadMont(w, CUR, leaf);
    var idx = frontier.nextIndex;
    var level : Nat = 0;
    while (level < DEPTH) {
      if (idx % 2 == 0) {
        filled[level] := readCanonical(w, CUR);
        loadMont(w, SIB, zeros[level]);
        F.setZero(w, S0);
        F.copy(w, S1, w, CUR);
        F.copy(w, S2, w, SIB);
      } else {
        loadMont(w, SIB, filled[level]);
        F.setZero(w, S0);
        F.copy(w, S1, w, SIB);
        F.copy(w, S2, w, CUR);
      };
      permuteCore(w);
      F.copy(w, CUR, w, S1);
      idx /= 2;
      level += 1;
    };
    (
      { filled = Array.fromVarArray(filled); nextIndex = frontier.nextIndex + 1 },
      readCanonical(w, CUR),
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
