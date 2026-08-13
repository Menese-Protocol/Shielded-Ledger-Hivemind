/// A tree oracle that returns a root of its own choosing. Test-only.
///
/// Exists to witness the oracle-trust defect. With `tree_frontier_enabled` false — the shipped default — the
/// ledger computes no in-canister transition, `frontierCrossCheck` matches `case null null` and runs
/// no check, and `parseTransition` validates only the SHAPE of the reply: 32 lanes and a 32-byte
/// root hex. Nothing validates the value. So an oracle that returns a well-formed reply with a root
/// it invented has that root accepted, written into `historical_roots` and installed as `note_root`.
///
/// It is deliberately WELL-FORMED. An oracle returning malformed output would be caught by
/// parseTransition and would prove nothing; the finding is that a correctly-shaped lie is not
/// checked at all.
///
/// The vendored oracle at vendor/tree_oracle_bls is not modified. This is a separate canister the
/// battery points the ledger at.
import Array "mo:core/Array";
import Nat "mo:core/Nat";
import Nat64 "mo:core/Nat64";

persistent actor EvilTreeOracle {

  public type TreeState = { filled : [Text]; root : Text; next_index : Nat64 };
  public type TreeTransition = { state : ?TreeState; error : ?Text };

  /// The root this oracle will claim. A field element the ledger will accept as canonical hex.
  var forged_root : Text = "0000000000000000000000000000000000000000000000000000000000000abc";
  /// Off by default so the same canister can serve an honest-looking passthrough first.
  var forging : Bool = false;

  /// Intake-fix evidence. The root forgery above cannot exercise the LANE half of the
  /// intake fix: `filled` is passed through unforged, so a non-canonical lane was unreachable.
  var lane_forging : Bool = false;
  var forged_lane : Text = "";
  public func set_lane_forgery(enabled : Bool, lane : Text) : async () {
    lane_forging := enabled; forged_lane := lane;
  };

  public func set_forgery(enabled : Bool, root : Text) : async () {
    forging := enabled;
    if (root != "") forged_root := root;
  };

  public query func forged() : async (Bool, Text) { (forging, forged_root) };

  func zeroLane() : Text { "0000000000000000000000000000000000000000000000000000000000000000" };

  /// Honest-shaped transition: advance next_index by the leaf count and keep the lanes. It is not a
  /// real Poseidon frontier, which is the point — with the flag OFF the ledger never recomputes one,
  /// so it cannot tell.
  func transition(before : TreeState, leaves : [Text]) : TreeTransition {
    let lanes = if (before.filled.size() == 32) before.filled
      else Array.tabulate<Text>(32, func(_) { zeroLane() });
    {
      state = ?{
        filled = if (lane_forging) Array.tabulate<Text>(32, func(i) { if (i == 0) forged_lane else lanes[i] }) else lanes;
        root = if (forging) forged_root else before.root;
        next_index = before.next_index + Nat64.fromNat(leaves.size());
      };
      error = null;
    }
  };

  public func append(before : TreeState, leaves : [Text]) : async TreeTransition {
    transition(before, leaves)
  };

  public func empty() : async TreeTransition {
    {
      state = ?{
        filled = Array.tabulate<Text>(32, func(i) { if (lane_forging and i == 0) forged_lane else zeroLane() });
        root = forged_root;
        next_index = 0;
      };
      error = null;
    }
  };
}
