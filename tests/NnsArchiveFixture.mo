/// Local-only legacy ICP archive node used to falsify ledger/archive boundary handling.

import Array "mo:core/Array";
import Nat "mo:core/Nat";
import Nat64 "mo:core/Nat64";
import Principal "mo:core/Principal";
import NnsBlock "../src/NnsBlock";

persistent actor NnsArchiveFixture {
  type Ledger = actor {
    query_blocks : shared query NnsBlock.GetBlocksArgs -> async NnsBlock.QueryBlocksResponse;
    query_encoded_blocks : shared query NnsBlock.GetBlocksArgs -> async NnsBlock.QueryEncodedBlocksResponse;
  };

  var first_index : Nat = 0;
  var blocks : [NnsBlock.Block] = [];
  var encoded_blocks : [Blob] = [];

  func bounds(args : NnsBlock.GetBlocksArgs) : { #ok : (Nat, Nat); #err : NnsBlock.GetBlocksError } {
    let start = Nat64.toNat(args.start);
    let length = Nat64.toNat(args.length);
    if (start < first_index) {
      return #err(#BadFirstBlockIndex({
        requested_index = args.start;
        first_valid_index = Nat64.fromNat(first_index);
      }))
    };
    let offset = start - first_index;
    if (offset > blocks.size()) {
      return #err(#Other({ error_code = 1; error_message = "requested range starts past archive" }))
    };
    #ok((offset, Nat.min(blocks.size(), offset + length)))
  };

  public query func get_blocks(args : NnsBlock.GetBlocksArgs) : async NnsBlock.GetBlocksResult {
    switch (bounds(args)) {
      case (#err(error)) #Err(error);
      case (#ok((start, end))) #Ok({
        blocks = Array.tabulate<NnsBlock.Block>(end - start, func(i) { blocks[start + i] })
      });
    }
  };

  public query func get_encoded_blocks(
    args : NnsBlock.GetBlocksArgs
  ) : async NnsBlock.GetEncodedBlocksResult {
    switch (bounds(args)) {
      case (#err(error)) #Err(error);
      case (#ok((start, end))) #Ok(
        Array.tabulate<Blob>(end - start, func(i) { encoded_blocks[start + i] })
      );
    }
  };

  /// Pull an exact local range before the ledger fixture marks it archived. The archive never
  /// accepts caller-supplied blocks, preventing the positive boundary vector from diverging.
  public shared func test_sync(ledger_id : Principal, start : Nat64, length : Nat64) : async () {
    assert blocks.size() == 0;
    let ledger : Ledger = actor (Principal.toText(ledger_id));
    let candid = await ledger.query_blocks({ start; length });
    let encoded = await ledger.query_encoded_blocks({ start; length });
    assert candid.archived_blocks.size() == 0;
    assert encoded.archived_blocks.size() == 0;
    assert candid.first_block_index == start;
    assert encoded.first_block_index == start;
    assert candid.blocks.size() == Nat64.toNat(length);
    assert encoded.blocks.size() == candid.blocks.size();
    first_index := Nat64.toNat(start);
    blocks := candid.blocks;
    encoded_blocks := encoded.blocks;
  };

  public query func test_state() : async { first_index : Nat; length : Nat } {
    { first_index; length = blocks.size() }
  };
}
