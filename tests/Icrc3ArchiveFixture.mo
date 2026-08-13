/// ICRC-3 block archive, test-only.
///
/// Exists so the reconcile path can be exercised against a ledger that ACTUALLY archives. The
/// ICRC-3 view on IcpLedgerFixture used to hard-code `archived_blocks = []`, which made every
/// archive-related assertion unfalsifiable: the scan could not encounter an archived range, so a
/// test of archive handling passed whether or not the handling existed.
///
/// The callback type is self-recursive — an archive reply is itself a GetBlocksResult and may
/// carry its own `archived_blocks` — so this fixture can chain to a further archive, which is
/// how the nesting bound in the reconcile walk gets exercised.
import Array "mo:core/Array";
import List "mo:core/List";
import Nat "mo:core/Nat";
import Principal "mo:core/Principal";
import Runtime "mo:core/Runtime";
import ICRC2 "../src/ICRC2";

persistent actor Icrc3ArchiveFixture {

  type Block = ICRC2.Block;
  type GetBlocksArgs = ICRC2.GetBlocksArgs;
  type ArchivedBlocks = { args : [GetBlocksArgs]; callback : GetBlocksCallback };
  type GetBlocksResult = { log_length : Nat; blocks : [Block]; archived_blocks : [ArchivedBlocks] };
  type GetBlocksCallback = shared query ([GetBlocksArgs]) -> async GetBlocksResult;
  type ArchiveActor = actor { icrc3_get_blocks : GetBlocksCallback };

  /// Blocks this archive holds, keyed by their ABSOLUTE index in the ledger's log.
  var base_index : Nat = 0;
  var held : [Block] = [];
  var total_log_length : Nat = 0;

  // ---- failure modes, each independently armable: the proven-absence invariant has to hold
  // under every one of them, and a happy-path assertion discharges none of them ----
  var mode_trap : Bool = false;        // callback traps
  var mode_empty : Bool = false;       // replies with nothing, claiming success
  var mode_short : Bool = false;       // replies with a strict prefix of the requested range
  var mode_wrong_ids : Bool = false;   // replies with blocks carrying ids outside the request
  var chain_to : ?Principal = null;    // reply defers again, to exercise the nesting bound
  var mode_wide_range : Bool = false;  // defers a range WIDER than it was asked for (malformed)

  public shared func load(base : Nat, blocks : [Block], log_length : Nat) : async () {
    base_index := base; held := blocks; total_log_length := log_length;
  };

  public shared func set_mode(
    trap : Bool, empty : Bool, short : Bool, wrong_ids : Bool, chain : ?Principal, wide_range : Bool
  ) : async () {
    mode_trap := trap; mode_empty := empty; mode_short := short;
    mode_wrong_ids := wrong_ids; chain_to := chain; mode_wide_range := wide_range;
  };

  public query func icrc3_get_blocks(ranges : [GetBlocksArgs]) : async GetBlocksResult {
    if (mode_trap) Runtime.trap("TEST_ONLY:archive-callback-trap");
    switch (chain_to) {
      case (?id) {
        // Defer instead of answering: the caller must follow, and must bound how far it will.
        // mode_wide_range makes the deferred range WIDER than the one it was asked about — a
        // malformed reply that, if trusted, would have the caller believe it observed indices
        // nobody ever served.
        let deferred = if (mode_wide_range) {
          Array.map<GetBlocksArgs, GetBlocksArgs>(ranges, func(r) { { start = r.start; length = r.length + 8 } })
        } else ranges;
        return {
          log_length = total_log_length;
          blocks = [];
          archived_blocks = [{ args = deferred; callback = (actor (Principal.toText(id)) : ArchiveActor).icrc3_get_blocks }];
        };
      };
      case null {};
    };
    if (mode_empty) return { log_length = total_log_length; blocks = []; archived_blocks = [] };

    let out = List.empty<Block>();
    for (range in ranges.vals()) {
      let requested_end = range.start + range.length;
      var index = range.start;
      while (index < requested_end) {
        if (index >= base_index and index < base_index + held.size()) {
          let b = held[index - base_index];
          // mode_wrong_ids answers with an id the caller never asked for; a caller that trusts
          // the reply blindly will mis-attribute the block.
          List.add(out, { id = if (mode_wrong_ids) index + 1_000_000 else b.id; block = b.block });
        };
        index += 1;
      };
    };
    let all = List.toArray(out);
    // mode_short returns a strict prefix, so `blocks.size()` under-reports what was covered —
    // the shape that makes a caller advancing by blocks.size() stall or skip.
    let served = if (mode_short and all.size() > 1) Array.tabulate<Block>(all.size() - 1, func(i) { all[i] }) else all;
    { log_length = total_log_length; blocks = served; archived_blocks = [] }
  };

  public query func held_range() : async { base : Nat; count : Nat } { { base = base_index; count = held.size() } };
}
