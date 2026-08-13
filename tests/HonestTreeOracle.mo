/// A tree oracle that returns the transition the ledger's OWN frontier walk produces. Test-only.
///
/// Exists because `tests/EvilTreeOracle.mo` returns `root = before.root` unchanged — a well-formed
/// lie — so with `tree_frontier_enabled` true (the shipped default) every real
/// `shield` / `confidential_transfer` is refused `GUARDED:tree-frontier-mismatch`, and no genuine
/// intent can be created in this harness. That blocks two committed criteria:
///
///   * detect-chain disable refused while the chain is ON, which needs a real note
///     appended after the chain is armed;
///   * a genuine `intent_id` produced by `unshieldIntentId`, since
///     `ScaleFixture` hard-codes `intent_id = deterministicBlob(7, 1, 32)` and never calls it.
///     A witness staged on that constant would test the fixture, not the ledger.
///
/// It agrees with `Main.mo`'s `frontierCrossCheck` (`:2049`) BY CONSTRUCTION, not by being trusted:
/// the body below is `Main.mo`'s `frontierAppend` (`:1983`) over the same `src/PoseidonTree`
/// module, with the same validation order and the same error strings, which `frontierAppend`'s own
/// comment requires so "a cross-checked oracle can never disagree on the rejection surface".
///
/// The vendored oracle at vendor/tree_oracle_bls is not modified.
import Array "mo:core/Array";
import Nat "mo:core/Nat";
import Nat64 "mo:core/Nat64";
import Prim "mo:⛔";
import PoseidonTree "../src/PoseidonTree";

persistent actor HonestTreeOracle {

  public type TreeState = { filled : [Text]; root : Text; next_index : Nat64 };
  public type TreeTransition = { state : ?TreeState; error : ?Text };

  func zeros() : [Nat] { PoseidonTree.zeroHashes() };

  /// Byte-for-byte the ledger's frontierAppend, including the order of the six rejections.
  func frontierAppend(state : TreeState, leaves : [Text]) : TreeTransition {
    if (state.filled.size() != PoseidonTree.DEPTH) return { state = null; error = ?"REJECT:frontier-length" };
    if (leaves.size() == 0 or leaves.size() > 2) return { state = null; error = ?"REJECT:leaf-count" };
    if (state.next_index > ((1 : Nat64) << 32) -% Nat64.fromNat(leaves.size())) {
      return { state = null; error = ?"REJECT:tree-full" };
    };
    let filled = Prim.Array_init<Nat>(PoseidonTree.DEPTH, 0);
    var level : Nat = 0;
    while (level < PoseidonTree.DEPTH) {
      switch (PoseidonTree.hexToNat(state.filled[level])) {
        case (?value) filled[level] := value;
        case null return { state = null; error = ?"REJECT:frontier-field" };
      };
      level += 1;
    };
    if (PoseidonTree.hexToNat(state.root) == null) return { state = null; error = ?"REJECT:root-field" };
    let parsedLeaves = Prim.Array_init<Nat>(leaves.size(), 0);
    var i : Nat = 0;
    while (i < leaves.size()) {
      switch (PoseidonTree.hexToNat(leaves[i])) {
        case (?value) parsedLeaves[i] := value;
        case null return { state = null; error = ?"REJECT:leaf-field" };
      };
      i += 1;
    };
    let z = zeros();
    var frontier : PoseidonTree.Frontier = {
      filled = Array.fromVarArray(filled);
      nextIndex = state.next_index;
    };
    var root : Nat = 0;
    i := 0;
    while (i < leaves.size()) {
      let (next, newRoot) = PoseidonTree.append(frontier, z, parsedLeaves[i]);
      frontier := next;
      root := newRoot;
      i += 1;
    };
    {
      state = ?{
        filled = Array.map<Nat, Text>(frontier.filled, PoseidonTree.natToHex);
        root = PoseidonTree.natToHex(root);
        next_index = frontier.nextIndex;
      };
      error = null;
    }
  };

  public func append(before : TreeState, leaves : [Text]) : async TreeTransition {
    frontierAppend(before, leaves)
  };

  /// The empty tree: the zero-hash frontier, and the empty root, which is the top zero hash.
  public func empty() : async TreeTransition {
    let z = zeros();
    let f = PoseidonTree.emptyFrontier(z);
    {
      state = ?{
        filled = Array.map<Nat, Text>(f.filled, PoseidonTree.natToHex);
        root = PoseidonTree.natToHex(z[PoseidonTree.DEPTH]);
        next_index = 0;
      };
      error = null;
    }
  };
}
