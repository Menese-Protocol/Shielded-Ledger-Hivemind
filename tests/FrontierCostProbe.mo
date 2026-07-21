/// MEASUREMENT HARNESS — in-canister Poseidon frontier cost :
/// instructions + allocation for 1 permutation, 1 merkle compress, 1 frontier append
/// (32 compresses), a 2-leaf append (the transfer shape), and the one-time
/// zeroHashes() init. AuditCostProbe.mo pattern: TEST/HARNESS INFRASTRUCTURE ONLY,
/// never installed as the ledger. Menese DeFi Team.

import Nat64 "mo:core/Nat64";
import Prim "mo:⛔";
import PoseidonTree "../src/PoseidonTree";
import Fr "../src/groth16/Fr";

persistent actor FrontierCostProbe {
  var sink : Nat = 0;

  func counters() : (Nat64, Nat) {
    (Prim.performanceCounter(0), Prim.rts_total_allocation())
  };

  /// `iters` chained permutations (each input depends on the previous output —
  /// no folding, realistic operand mix).
  public func measure_perm(iters : Nat) : async (Nat64, Nat) {
    var a : Nat = 1;
    var b : Nat = 2;
    var c : Nat = 3;
    let (i0, a0) = counters();
    var i : Nat = 0;
    while (i < iters) {
      let (x, y, z) = PoseidonTree.permute(a, b, c);
      a := x; b := y; c := z;
      i += 1;
    };
    let (i1, a1) = counters();
    sink := a;
    (i1 - i0, a1 - a0)
  };

  /// `iters` permutations with ONE boundary conversion pair (isolates the round loop).
  public func measure_perm_core(iters : Nat) : async (Nat64, Nat) {
    let (i0, a0) = counters();
    let (a, _, _) = PoseidonTree.permuteN(1, 2, 3, iters);
    let (i1, a1) = counters();
    sink := a;
    (i1 - i0, a1 - a0)
  };

  /// `iters` chained 2-to-1 compressions.
  public func measure_compress(iters : Nat) : async (Nat64, Nat) {
    var l : Nat = 1;
    var r : Nat = 2;
    let (i0, a0) = counters();
    var i : Nat = 0;
    while (i < iters) {
      let out = PoseidonTree.merkleCompress(l, r);
      l := r;
      r := out;
      i += 1;
    };
    let (i1, a1) = counters();
    sink := r;
    (i1 - i0, a1 - a0)
  };

  /// `count` sequential appends from the empty tree (each = 32 compresses + frontier
  /// rebuild). Returns (instr, alloc, final nextIndex).
  public func measure_append(count : Nat) : async (Nat64, Nat, Nat) {
    let zeros = PoseidonTree.zeroHashes();
    var frontier = PoseidonTree.emptyFrontier(zeros);
    var leaf : Nat = 7;
    let (i0, a0) = counters();
    var i : Nat = 0;
    while (i < count) {
      let (next, root) = PoseidonTree.append(frontier, zeros, leaf);
      frontier := next;
      leaf := root; // chain
      i += 1;
    };
    let (i1, a1) = counters();
    sink := leaf;
    (i1 - i0, a1 - a0, Nat64.toNat(frontier.nextIndex))
  };

  /// One-time zeroHashes() init cost (32 compresses + array build).
  public func measure_zero_hashes() : async (Nat64, Nat) {
    let (i0, a0) = counters();
    let zeros = PoseidonTree.zeroHashes();
    let (i1, a1) = counters();
    sink := zeros[32];
    (i1 - i0, a1 - a0)
  };

  /// The full transfer-shaped tree step: 2 appends + both wire codec directions
  /// (hex parse of 32 filled + root, hex emit of 32 filled + root), i.e. everything
  /// the in-canister transition adds to one confidential_transfer message.
  public func measure_transfer_step() : async (Nat64, Nat) {
    let zeros = PoseidonTree.zeroHashes();
    var frontier = PoseidonTree.emptyFrontier(zeros);
    // pre-fill a few so the walk mixes odd/even branches
    var k : Nat = 0;
    var seed : Nat = 11;
    while (k < 5) {
      let (next, root) = PoseidonTree.append(frontier, zeros, seed);
      frontier := next;
      seed := root;
      k += 1;
    };
    let filledHex = Prim.Array_tabulate<Text>(32, func(i) { PoseidonTree.natToHex(frontier.filled[i]) });
    let (i0, a0) = counters();
    // parse the wire frontier (what Main.mo does with tree_state)
    var parsed : [var Nat] = Prim.Array_init<Nat>(32, 0);
    var i : Nat = 0;
    while (i < 32) {
      switch (PoseidonTree.hexToNat(filledHex[i])) {
        case (?v) parsed[i] := v;
        case null Prim.trap("bad fixture");
      };
      i += 1;
    };
    var f : PoseidonTree.Frontier = {
      filled = Prim.Array_tabulate<Nat>(32, func(i) { parsed[i] });
      nextIndex = frontier.nextIndex;
    };
    let (f1, _r1) = PoseidonTree.append(f, zeros, seed);
    let (f2, r2) = PoseidonTree.append(f1, zeros, Fr.add(seed, 1));
    // emit the wire frontier back
    var emitted : Text = "";
    i := 0;
    while (i < 32) {
      emitted #= PoseidonTree.natToHex(f2.filled[i]);
      i += 1;
    };
    emitted #= PoseidonTree.natToHex(r2);
    let (i1, a1) = counters();
    sink := emitted.size();
    (i1 - i0, a1 - a0)
  };
}
