/// In-canister Poseidon Merkle frontier over the BLS12-381 scalar field Fr.
///
/// Byte-identical port of the tree oracle's reference implementation
/// (`vendor/tree_common`, arkworks `ark-crypto-primitives` 0.5.0 `PoseidonSponge`).
///
/// TWO POSEIDON INSTANCES, and keeping them apart is the whole game:
///   - NOTE, t = 3 (rate 2, capacity 1) — the pk / nf / cm images, via `hashN`.
///     Constants `C.ARK_NOTE*` / `C.MDS_NOTE*`, from
///     `find_poseidon_ark_and_mds::<Fr>(255, 2, 8, 57, 0)`.
///   - TREE, t = 5 (rate 4, capacity 1) — one permutation absorbs a whole 4-ary Merkle
///     row with the domain tag in the capacity. Constants `C.ARK_TREE*` / `C.MDS_TREE*`,
///     from `find_poseidon_ark_and_mds::<Fr>(255, 4, 8, 57, 0)`.
/// The two sets are DIFFERENT round constants and a DIFFERENT MDS. That — not the domain
/// tag alone — is why a note image and a tree node cannot collide.
///
/// In Rust the `TreeCfg` newtype makes handing one instance's config to the other's
/// function a COMPILE error, after exactly that mistake silently built a different tree.
/// Motoko has no cheap newtype, so the equivalent guarantee is structural: `permuteCoreW`
/// is private and takes its tables as arguments, and the only ways in are `permuteNote`
/// and `permuteTree`, which each hard-wire their own instance. No caller ever selects a
/// table, so no caller can select the wrong one.
///
/// Shape: 4-ary, 16 levels, 4^16 = 2^32 leaves EXACTLY — the tree covers the addressable
/// index space with nothing wasted and nothing unreachable. It was 2-ary / 32 levels
/// before 2026-08-27.
///   - state layout [capacity | rate]: absorption writes lanes 1..t-1, the partial S-box
///     acts on lane 0, squeeze reads lane 1 — exactly arkworks.
///   - `merkleCompress(children)` = permutation of [TAG_MERGE, c0..c3], lane 1 out — the
///     domain tag rides in the CAPACITY lane, so ONE permutation compresses a level.
///   - `append` = the incremental-frontier algorithm of `IncrementalTree::append`
///     (ARITY-1 cached siblings per level, 16 compressions per append).
///
/// WHY 4-ARY AND NOT 5: in-circuit the MDS matrix-vector product is a linear combination,
/// which R1CS charges nothing for, so a level costs only its S-boxes and widening is
/// nearly free. NATIVELY — which is what THIS file pays — the MDS is t^2 field
/// multiplications and dominates: 65*t^2 + 3*(8t + 57) is 828 mults at t=3, 1,916 at
/// t=5, 2,655 at t=6. Arity 4 costs 16 x 1,916 = 30,656 against 2-ary's 32 x 828 =
/// 26,496 (measured by `frontier-oracle bench` at 0.99x — break-even), while arity 5
/// would cost 14 x 2,655 = 37,170 (1.15x measured, worse still under FrFlat's plain CIOS)
/// to buy only 3.4% more circuit win. Both arities land in the same 2^14 QAP domain, so
/// the proving key — the headline cold-start number — is identical either way. Arity 4
/// therefore takes the download win for free.
///
/// Field arithmetic is `groth16/FrFlat.mo` — in-place Montgomery on 8×32-bit limbs
/// (the flat, allocation-disciplined style). The first port ran on plain-Nat `Fr.mo` and
/// was proven byte-identical to arkworks; the cost probe then measured that at 32.07M
/// instructions + 1.38 MB garbage per permutation — allocation-churn class — so the
/// internals moved to FrFlat and the ENTIRE differential gate is re-run on this backend.
/// Round constants are stored in Montgomery form; the permutation allocates nothing
/// beyond its one arena.
///
/// Differential gate: `tests/PoseidonDifferential.mo` proves every public function here
/// byte-identical to arkworks on the seeded fixtures before Main.mo may call it.
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
  // ---- tree shape ----
  /// Merkle arity. 4^16 = 2^32 exactly; see the module header for why 4 and not 5.
  public let ARITY : Nat = 4;
  public let LEVELS : Nat = 16;
  /// Frontier `filled` is FLAT and row-major: index `lvl * ARITY + j`. This is also the
  /// wire shape (`tree_oracle`'s `TreeState.filled`) and the fixture shape, so the
  /// canister, the oracle canister and the differential all index it identically.
  public let FILLED_LEN : Nat = 64; // = LEVELS * ARITY (literal: Motoko libraries need static inits)
  /// Addressable leaves. `ARITY ** LEVELS == CAPACITY` holds exactly at this arity; the
  /// Rust side pins it with a compile-time assertion and `tests/PoseidonDifferential.mo`
  /// re-checks it here, because a mismatch is either leaves the ledger can index but the
  /// tree cannot hold, or levels that can never be reached.
  public let CAPACITY : Nat64 = 4294967296; // = 2^32 = ARITY ** LEVELS, exactly

  /// Domain tag carried in the sponge CAPACITY by the Merkle compression (mirrors
  /// `TAG_MERGE = 4` in `common`/`tree_common`), so an inner-node image is separated from
  /// the pk/nf/cm note images and from a bare row hash. MUST match the circuit or roots
  /// diverge silently.
  let TAG_MERGE : Nat = 4;
  let PARTIAL_ROUNDS : Nat = 57;
  let ROUNDS : Nat = 65; // 8 full + 57 partial
  let HALF_FULL : Nat = 4; // full_rounds / 2

  // ---- arena layout, as a function of the sponge width t ----
  // One element = 8 Nat32 limbs. For width t:
  //     state lanes   i        at  i*8            (i = 0..t-1; lane 0 is the capacity)
  //     next lanes    n_i      at  (t+i)*8
  //     TMP                    at  (2t)*8
  //     SPARE                  at  (2t+1)*8
  //     CUR                    at  (2t+2)*8
  //     SIB                    at  (2t+3)*8
  //     arena size             =   (2t+4)*8
  // At t = 3 this reproduces the previously-shipped layout (0/8/16, 24/32/40, 48, 56, 64,
  // 72, 80) to the limb — the proven t=3 path is not being re-laid-out, only generalised.
  // These are LITERALS, not expressions: a Motoko library binding must have a static
  // initialiser (M0014), so the formula above cannot be written as code here. A mistyped
  // offset is not a silent risk — every one of them is exercised by the permutation
  // vectors in `tests/PoseidonDifferential.mo`, which are byte-identical comparisons
  // against arkworks and diverge on the very first vector if any lane lands wrong.
  let NOTE_T : Nat = 3; //  t = 3
  let NOTE_NBASE : Nat = 24; //  t*8
  let NOTE_TMP : Nat = 48; // (2t)*8
  let NOTE_SPARE : Nat = 56; // (2t+1)*8
  let NOTE_CUR : Nat = 64; // (2t+2)*8
  let NOTE_SIB : Nat = 72; // (2t+3)*8
  let NOTE_ARENA : Nat = 80; // (2t+4)*8

  let TREE_T : Nat = 5; //  t = ARITY + 1 = rate 4 + capacity 1
  let TREE_NBASE : Nat = 40; //  t*8
  let TREE_TMP : Nat = 80; // (2t)*8
  let TREE_SPARE : Nat = 88; // (2t+1)*8
  let TREE_CUR : Nat = 96; // (2t+2)*8
  let TREE_SIB : Nat = 104; // (2t+3)*8
  let TREE_ARENA : Nat = 112; // (2t+4)*8

  /// Round constants in Montgomery form: static literal tables emitted by the oracle
  /// (arkworks' internal a·2^256 mod r repr, the exact operand form of the FrFlat CIOS).
  /// Strides differ per instance — `(round*t + lane)*8` and `(i*t + j)*8` — which is the
  /// only thing standing between a correct tree and a silently wrong one, so the tables
  /// and their widths are never passed separately from one another (see `permuteNote` /
  /// `permuteTree`). The canonical `C.ARK_*`/`C.MDS_*` stay alongside; the differential
  /// gate validates both forms transitively (any wrong limb diverges the first vector).
  let ARK_NOTE_M : [Nat32] = C.ARK_NOTE_MONT;
  let MDS_NOTE_M : [Nat32] = C.MDS_NOTE_MONT;
  let ARK_TREE_M : [Nat32] = C.ARK_TREE_MONT;
  let MDS_TREE_M : [Nat32] = C.MDS_TREE_MONT;

  func newArena(size : Nat) : [var Nat32] { VarArray.repeat<Nat32>(0, size) };

  /// x := x^5 for the element at offset `off` (2 squarings + 1 multiply, in place).
  func sboxAt(w : [var Nat32], off : Nat, tmp : Nat) {
    F.montSqrInto(w, tmp, w, off);
    F.montSqrInto(w, tmp, w, tmp);
    F.montMulInto(w, off, w, tmp, w, off);
  };

  /// One full 65-round permutation of width `t` on lanes 0..t-1 (Montgomery form), in
  /// place. Round = ARK add; S-box on all lanes (full rounds) or lane 0 (partial); MDS
  /// mat-vec into the next-lane block, then copy back.
  ///
  /// PRIVATE, and it takes its tables as arguments rather than reading a module-level
  /// pair: that is what makes selecting the wrong instance impossible for any caller.
  func permuteCoreW(
    w : [var Nat32],
    t : Nat,
    ark : [Nat32],
    mds : [Nat32],
    nBase : Nat,
    tmp : Nat,
    spare : Nat,
  ) {
    var round = 0;
    while (round < ROUNDS) {
      let arkBase = round * t * 8;
      var i = 0;
      while (i < t) {
        F.addConstInto(w, i * 8, w, i * 8, ark, arkBase + i * 8);
        i += 1;
      };
      if (round < HALF_FULL or round >= HALF_FULL + PARTIAL_ROUNDS) {
        i := 0;
        while (i < t) { sboxAt(w, i * 8, tmp); i += 1 };
      } else {
        sboxAt(w, 0, tmp);
      };
      // next[i] = sum_j MDS[i][j] * state[j]
      i := 0;
      while (i < t) {
        let outOff = nBase + i * 8;
        F.loadConst(w, spare, mds, (i * t) * 8);
        F.montMulInto(w, outOff, w, spare, w, 0);
        var j = 1;
        while (j < t) {
          F.loadConst(w, spare, mds, (i * t + j) * 8);
          F.montMulInto(w, tmp, w, spare, w, j * 8);
          F.addInto(w, outOff, w, outOff, w, tmp);
          j += 1;
        };
        i += 1;
      };
      i := 0;
      while (i < t) { F.copy(w, i * 8, w, nBase + i * 8); i += 1 };
      round += 1;
    };
  };

  /// The NOTE instance (t = 3). The only entry point that touches the note tables.
  func permuteNote(w : [var Nat32]) {
    permuteCoreW(w, NOTE_T, ARK_NOTE_M, MDS_NOTE_M, NOTE_NBASE, NOTE_TMP, NOTE_SPARE);
  };

  /// The TREE instance (t = ARITY + 1). The only entry point that touches the tree tables.
  func permuteTreeCore(w : [var Nat32]) {
    permuteCoreW(w, TREE_T, ARK_TREE_M, MDS_TREE_M, TREE_NBASE, TREE_TMP, TREE_SPARE);
  };

  func loadMont(w : [var Nat32], off : Nat, value : Nat, spare : Nat) {
    F.fromNat(value, w, off);
    F.toMontInto(w, off, w, off, w, spare);
  };

  func readCanonical(w : [var Nat32], off : Nat, sib : Nat, spare : Nat) : Nat {
    F.fromMontInto(w, sib, w, off, w, spare);
    F.toNat(w, sib)
  };

  // ---------------------------------------------------------------- NOTE instance

  /// One NOTE permutation on canonical state (s0, s1, s2); s0 is the capacity lane.
  public func permute(s0 : Nat, s1 : Nat, s2 : Nat) : (Nat, Nat, Nat) {
    let w = newArena(NOTE_ARENA);
    loadMont(w, 0, s0, NOTE_SPARE);
    loadMont(w, 8, s1, NOTE_SPARE);
    loadMont(w, 16, s2, NOTE_SPARE);
    permuteNote(w);
    let o2 = readCanonical(w, 16, NOTE_SIB, NOTE_SPARE);
    let o1 = readCanonical(w, 8, NOTE_SIB, NOTE_SPARE);
    let o0 = readCanonical(w, 0, NOTE_SIB, NOTE_SPARE);
    (o0, o1, o2)
  };

  /// `n` chained NOTE permutations on canonical state (one boundary conversion pair
  /// total). n = 1 is exactly `permute`. Exists so the cost probe can separate the
  /// round-loop cost from the Nat⇄limb boundary cost.
  public func permuteN(s0 : Nat, s1 : Nat, s2 : Nat, n : Nat) : (Nat, Nat, Nat) {
    let w = newArena(NOTE_ARENA);
    loadMont(w, 0, s0, NOTE_SPARE);
    loadMont(w, 8, s1, NOTE_SPARE);
    loadMont(w, 16, s2, NOTE_SPARE);
    var i = 0;
    while (i < n) { permuteNote(w); i += 1 };
    let o2 = readCanonical(w, 16, NOTE_SIB, NOTE_SPARE);
    let o1 = readCanonical(w, 8, NOTE_SIB, NOTE_SPARE);
    let o0 = readCanonical(w, 0, NOTE_SIB, NOTE_SPARE);
    (o0, o1, o2)
  };

  /// arkworks `PoseidonSponge` absorb/squeeze for the reference `hash_n` call shape:
  /// each input absorbed with its own `absorb` call (single field element), then one
  /// `squeeze_field_elements(1)`. Duplex schedule: permute when an element arrives on a
  /// full rate section, and once more before the squeeze. NOTE instance, rate 2.
  public func hashN(inputs : [Nat]) : Nat {
    let w = newArena(NOTE_ARENA);
    var absorbed : Nat = 0; // next_absorb_index within the rate section (0..1)
    for (x in inputs.vals()) {
      if (absorbed == 2) {
        permuteNote(w);
        absorbed := 0;
      };
      loadMont(w, NOTE_CUR, x, NOTE_SPARE);
      let lane = if (absorbed == 0) 8 else 16;
      F.addInto(w, lane, w, lane, w, NOTE_CUR);
      absorbed += 1;
    };
    permuteNote(w);
    readCanonical(w, 8, NOTE_SIB, NOTE_SPARE)
  };

  // ---------------------------------------------------------------- TREE instance

  /// One TREE permutation on canonical state of width `TREE_T`; lane 0 is the capacity.
  /// Exposed for the differential gate, which verifies the width-5 permutation against
  /// arkworks BEFORE anything built on it (compress, zeros, append) is trusted — bottom
  /// of the tower first.
  public func permuteTree(state : [Nat]) : [Nat] {
    if (state.size() != TREE_T) { Runtime.trap("permuteTree: wrong state width") };
    let w = newArena(TREE_ARENA);
    var i = 0;
    while (i < TREE_T) { loadMont(w, i * 8, state[i], TREE_SPARE); i += 1 };
    permuteTreeCore(w);
    Array.tabulate<Nat>(TREE_T, func(k) { readCanonical(w, k * 8, TREE_SIB, TREE_SPARE) })
  };

  /// ARITY-to-1 Merkle compression: the domain tag rides in the CAPACITY lane, so the
  /// state entering the permutation is `[TAG_MERGE, c0..c3]` and one permutation suffices.
  /// This is deliberately NOT `hashN([TAG_MERGE, ...])`: absorbing the tag as a leading
  /// rate element cost a second permutation on every level of every path, and `hashN` is
  /// the wrong instance besides.
  ///
  /// The rate lanes start at zero in a fresh arena, so loading the children directly IS
  /// the absorb (arkworks absorbs by adding into a zeroed lane). Mirrors
  /// `common::merkle_compress`; the two must never move apart.
  public func merkleCompress(children : [Nat]) : Nat {
    if (children.size() != ARITY) { Runtime.trap("merkleCompress: wrong child count") };
    let w = newArena(TREE_ARENA);
    loadMont(w, 0, TAG_MERGE, TREE_SPARE); // capacity carries the domain tag
    var j = 0;
    while (j < ARITY) { loadMont(w, (j + 1) * 8, children[j], TREE_SPARE); j += 1 };
    permuteTreeCore(w);
    readCanonical(w, 8, TREE_SIB, TREE_SPARE)
  };

  /// zeros[0] = 0 (the empty leaf); zeros[i+1] = compress([zeros[i]; ARITY]).
  /// zeros[LEVELS] is the empty-tree root. LEVELS + 1 entries.
  public func zeroHashes() : [Nat] {
    let zeros = Prim.Array_init<Nat>(LEVELS + 1, 0);
    var i : Nat = 0;
    while (i < LEVELS) {
      zeros[i + 1] := merkleCompress(Array.tabulate<Nat>(ARITY, func(_) { zeros[i] }));
      i += 1;
    };
    Array.fromVarArray(zeros)
  };

  /// The frontier: the children already fixed at each level, plus the next leaf index.
  /// Mirrors `IncrementalTree` (and the wire `TreeState` minus the root).
  ///
  /// `filled` is FLAT, row-major, `FILLED_LEN` entries: `filled[lvl * ARITY + j]` is the
  /// j-th child already fixed at level `lvl`. Entries at or beyond the current position
  /// in a row are stale and must never be read — `append` only reads `j <= pos`, exactly
  /// as the reference does.
  public type Frontier = {
    filled : [Nat]; // FILLED_LEN entries, level-major then slot
    nextIndex : Nat64;
  };

  public func emptyFrontier(zeros : [Nat]) : Frontier {
    {
      filled = Array.tabulate<Nat>(FILLED_LEN, func(i) { zeros[i / ARITY] });
      nextIndex = 0;
    }
  };

  /// Append one leaf: returns the updated frontier and the new root — the exact
  /// `IncrementalTree::append` walk (LEVELS compressions, `cur` chained in Montgomery
  /// form across levels). Traps only on a full tree, which callers must pre-check exactly
  /// as the oracle does.
  public func append(frontier : Frontier, zeros : [Nat], leaf : Nat) : (Frontier, Nat) {
    if (frontier.nextIndex >= CAPACITY) { Runtime.trap("tree full") };
    let filled = Array.toVarArray<Nat>(frontier.filled);
    let w = newArena(TREE_ARENA);
    loadMont(w, TREE_CUR, leaf, TREE_SPARE);
    var idx = frontier.nextIndex;
    var level : Nat = 0;
    while (level < LEVELS) {
      let base = level * ARITY;
      let pos = Nat64.toNat(idx % Nat64.fromNat(ARITY));
      // The node carried up from below occupies slot `pos` of this row. Slots before it
      // are children already fixed on earlier appends; slots after it are still empty, so
      // they take the empty-subtree hash for this level. Reading `filled` beyond `pos`
      // would read stale data — that is the one indexing rule this walk must not break.
      filled[base + pos] := readCanonical(w, TREE_CUR, TREE_SIB, TREE_SPARE);
      var j = 0;
      while (j < ARITY) {
        let lane = (j + 1) * 8; // rate lane j; lane 0 is the capacity
        if (j == pos) {
          F.copy(w, lane, w, TREE_CUR); // the node itself, still in Montgomery form
        } else if (j < pos) {
          loadMont(w, lane, filled[base + j], TREE_SPARE);
        } else {
          loadMont(w, lane, zeros[level], TREE_SPARE);
        };
        j += 1;
      };
      loadMont(w, 0, TAG_MERGE, TREE_SPARE); // capacity carries the domain tag
      permuteTreeCore(w);
      F.copy(w, TREE_CUR, w, 8); // chain the node image (rate lane 0, Montgomery form)
      idx /= Nat64.fromNat(ARITY);
      level += 1;
    };
    (
      { filled = Array.fromVarArray(filled); nextIndex = frontier.nextIndex + 1 },
      readCanonical(w, TREE_CUR, TREE_SIB, TREE_SPARE),
    )
  };

  /// The root of the tree this frontier already describes, with NO leaf appended.
  ///
  /// Every position at or beyond `nextIndex` is empty, so that root is exactly what
  /// appending the EMPTY leaf at `nextIndex` produces: the same walk, with the updated
  /// frontier discarded. Reusing `append` rather than writing a second walk is deliberate
  /// — a second implementation of the same walk is a second thing to drift, and this one
  /// would drift silently because both would agree on the empty tree.
  ///
  /// The property that pins it: for any frontier `f` and leaf `L`, if
  /// `append(f, zeros, L)` returns `(f', root)` then `frontierRootOf(f', zeros) == root`.
  /// That is checkable against existing code with no oracle, and
  /// `tests/FrontierRootProperty.mo` checks it.
  public func frontierRootOf(frontier : Frontier, zeros : [Nat]) : Nat {
    let (_, root) = append(frontier, zeros, zeros[0]);
    root
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

  /// Parse 64 hex chars as a little-endian 32-byte field element; null on bad length, bad
  /// digit, or a non-canonical (>= r) value — the same rejections `f_from_hex` performs.
  /// THE ONLY WAY A FIELD ELEMENT ENTERS STORED STATE. "Parse, don't validate": a value
  /// that has passed through here is a canonical field element by construction, so every
  /// downstream reader may rely on it without re-checking. The canonicality asymmetry this
  /// closes existed precisely BECAUSE two sites each decided for themselves what a valid
  /// field element was; adding a third check at a third site would repeat the mistake.
  ///
  /// REJECTS, NEVER REDUCES. Reducing mod Fr.P would give one value two encodings — the
  /// RFC 8032 / BIP-146 malleability class — and roots here are compared AS HEX TEXT, so a
  /// reduced value would no longer compare equal to the text it came from. Refusal is the
  /// only correct outcome.
  ///
  /// Returns the input UNCHANGED on success, so callers store exactly the bytes they were
  /// given.
  public func parseFieldElement(value : Text) : ?Text {
    switch (hexToNat(value)) { case (?_) ?value; case null null }
  };

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
