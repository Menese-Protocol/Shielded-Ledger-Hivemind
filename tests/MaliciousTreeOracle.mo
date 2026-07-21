/// TEST FIXTURE — a compromised tree oracle. Same candid interface as the real
/// `tree_oracle_bls` (`empty`, `append`), but every transition is first computed
/// CORRECTLY (via the ledger's own `PoseidonTree`, so `empty()`/configure succeed and
/// the corruption is surgical) and then a single field is corrupted per the armed mode.
/// This is the malicious-oracle battery adversary: with the ledger's frontier flag
/// ON, every corrupted transition must be caught by the in-canister cross-check and flip
/// the fail-closed guard. NEVER shipped; installed only by the battery driver.
/// Menese DeFi Team.

import Array "mo:core/Array";
import Nat64 "mo:core/Nat64";
import PoseidonTree "../src/PoseidonTree";

persistent actor MaliciousTreeOracle {
  public type TreeState = { filled : [Text]; root : Text; next_index : Nat64 };
  public type Transition = { state : ?TreeState; error : ?Text };

  // Corruption modes. #honest = behave correctly (baseline sanity of the fixture itself).
  public type Mode = {
    #honest;
    #wrong_root;      // fabricated root (the counterfeit-injection attack)
    #stale;           // echo the input state unchanged (no advance)
    #truncated;       // advance next_index but leave the root at the pre-append value
    #wrong_frontier;  // correct root, one filled lane corrupted
  };
  var mode : Mode = #honest;

  public func set_mode(m : Mode) : async () { mode := m };

  func zeros() : [Nat] { PoseidonTree.zeroHashes() };

  func honestAppend(state : TreeState, leaves : [Text]) : Transition {
    if (state.filled.size() != PoseidonTree.DEPTH) return { state = null; error = ?"REJECT:frontier-length" };
    if (leaves.size() == 0 or leaves.size() > 2) return { state = null; error = ?"REJECT:leaf-count" };
    let filled = Array.tabulate<Nat>(PoseidonTree.DEPTH, func(i) {
      switch (PoseidonTree.hexToNat(state.filled[i])) { case (?v) v; case null 0 };
    });
    let zs = zeros();
    var frontier : PoseidonTree.Frontier = { filled; nextIndex = state.next_index };
    var root : Nat = 0;
    for (leaf in leaves.vals()) {
      let parsed = switch (PoseidonTree.hexToNat(leaf)) { case (?v) v; case null 0 };
      let (next, r) = PoseidonTree.append(frontier, zs, parsed);
      frontier := next;
      root := r;
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

  public func empty() : async Transition {
    let zs = zeros();
    {
      state = ?{
        filled = Array.tabulate<Text>(PoseidonTree.DEPTH, func(i) { PoseidonTree.natToHex(zs[i]) });
        root = PoseidonTree.natToHex(zs[PoseidonTree.DEPTH]);
        next_index = 0;
      };
      error = null;
    }
  };

  // An attacker-chosen but canonically-valid fabricated root (a real field element the
  // attacker knows the tree opening for — the counterfeit-class threat).
  let FABRICATED_ROOT : Text = "0100000000000000000000000000000000000000000000000000000000000000";

  public func append(state : TreeState, leaves : [Text]) : async Transition {
    let honest = honestAppend(state, leaves);
    switch (mode) {
      case (#honest) honest;
      case (#stale) { { state = ?state; error = null } };
      case (_) {
        switch (honest.state) {
          case null honest;
          case (?good) {
            switch (mode) {
              case (#wrong_root) { { state = ?{ good with root = FABRICATED_ROOT }; error = null } };
              case (#truncated) { { state = ?{ good with root = state.root }; error = null } };
              case (#wrong_frontier) {
                let corrupted = Array.tabulate<Text>(PoseidonTree.DEPTH, func(i) {
                  if (i == 0) FABRICATED_ROOT else good.filled[i]
                });
                { state = ?{ good with filled = corrupted }; error = null }
              };
              case (_) honest;
            }
          };
        }
      };
    }
  };
}
