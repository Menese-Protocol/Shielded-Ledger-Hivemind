/// Exact legacy NNS ICP `query_blocks` model and protobuf block encoder.
///
/// Pinned oracle: dfinity/ic c6a37193d91ddad3254fccce83fff18809fbbc1d
/// (`ledger.did`, `types.proto`, and `validate_endpoints.rs`). The Candid view always contains a
/// construction timestamp, but the protobuf source may omit it; `created_at_time_present` carries
/// that deliberately lossy presence bit for fixture/oracle vectors.

import Array "mo:core/Array";
import Blob "mo:core/Blob";
import List "mo:core/List";
import Nat64 "mo:core/Nat64";
import Nat8 "mo:core/Nat8";
import Principal "mo:core/Principal";
import Sha256 "mo:sha2/Sha256";

module {
  public type Tokens = { e8s : Nat64 };
  public type TimeStamp = { timestamp_nanos : Nat64 };
  public type Operation = {
    #Mint : { to : Blob; amount : Tokens };
    #Burn : { from : Blob; spender : ?Blob; amount : Tokens };
    #Transfer : { from : Blob; to : Blob; amount : Tokens; fee : Tokens; spender : ?Blob };
    #Approve : {
      from : Blob;
      spender : Blob;
      allowance_e8s : Int;
      allowance : Tokens;
      fee : Tokens;
      expires_at : ?TimeStamp;
      expected_allowance : ?Tokens;
    };
  };
  public type Transaction = {
    memo : Nat64;
    icrc1_memo : ?Blob;
    operation : ?Operation;
    created_at_time : TimeStamp;
  };
  public type Block = { parent_hash : ?Blob; transaction : Transaction; timestamp : TimeStamp };
  public type GetBlocksArgs = { start : Nat64; length : Nat64 };
  public type BlockRange = { blocks : [Block] };
  public type GetBlocksError = {
    #BadFirstBlockIndex : { requested_index : Nat64; first_valid_index : Nat64 };
    #Other : { error_code : Nat64; error_message : Text };
  };
  public type GetBlocksResult = { #Ok : BlockRange; #Err : GetBlocksError };
  public type QueryArchiveFn = shared query GetBlocksArgs -> async GetBlocksResult;
  public type ArchivedBlocksRange = {
    start : Nat64;
    length : Nat64;
    callback : QueryArchiveFn;
  };
  public type QueryBlocksResponse = {
    chain_length : Nat64;
    certificate : ?Blob;
    blocks : [Block];
    first_block_index : Nat64;
    archived_blocks : [ArchivedBlocksRange];
  };
  public type GetEncodedBlocksResult = { #Ok : [Blob]; #Err : GetBlocksError };
  public type QueryArchiveEncodedFn = shared query GetBlocksArgs -> async GetEncodedBlocksResult;
  public type ArchivedEncodedBlocksRange = {
    start : Nat64;
    length : Nat64;
    callback : QueryArchiveEncodedFn;
  };
  public type QueryEncodedBlocksResponse = {
    chain_length : Nat64;
    certificate : ?Blob;
    blocks : [Blob];
    first_block_index : Nat64;
    archived_blocks : [ArchivedEncodedBlocksRange];
  };

  public func accountIdentifier(owner : Principal, subaccount : ?Blob) : Blob {
    Principal.toLedgerAccount(owner, subaccount)
  };

  func append(output : List.List<Nat8>, bytes : [Nat8]) {
    for (byte in bytes.vals()) { List.add(output, byte) }
  };

  func varint(input : Nat64) : [Nat8] {
    let output = List.empty<Nat8>();
    var value = input;
    loop {
      var byte = value % 128;
      value /= 128;
      if (value != 0) byte += 128;
      List.add(output, Nat8.fromNat(Nat64.toNat(byte)));
      if (value == 0) return List.toArray(output);
    }
  };

  func key(field : Nat64, wire : Nat64) : [Nat8] { varint(field * 8 + wire) };

  func uintField(field : Nat64, value : Nat64) : [Nat8] {
    if (value == 0) return [];
    Array.concat(key(field, 0), varint(value))
  };

  func bytesField(field : Nat64, value : Blob) : [Nat8] {
    let bytes = Blob.toArray(value);
    Array.flatten([key(field, 2), varint(Nat64.fromNat(bytes.size())), bytes])
  };

  func messageField(field : Nat64, message : [Nat8]) : [Nat8] {
    Array.flatten([key(field, 2), varint(Nat64.fromNat(message.size())), message])
  };

  func tokens(value : Nat64) : [Nat8] { uintField(1, value) };
  func timestamp(value : Nat64) : [Nat8] { uintField(1, value) };
  func account(value : Blob) : [Nat8] { bytesField(1, value) };

  func encodeOperation(operation : Operation) : [Nat8] {
    switch (operation) {
      case (#Mint(value)) {
        let message = Array.flatten([
          messageField(2, account(value.to)),
          messageField(3, tokens(value.amount.e8s)),
        ]);
        messageField(2, message)
      };
      case (#Burn(value)) {
        let output = List.empty<Nat8>();
        append(output, messageField(1, account(value.from)));
        append(output, messageField(3, tokens(value.amount.e8s)));
        switch (value.spender) {
          case (?spender) append(output, messageField(4, account(spender)));
          case null {};
        };
        messageField(1, List.toArray(output))
      };
      case (#Transfer(value)) {
        let send = List.empty<Nat8>();
        append(send, messageField(1, account(value.from)));
        append(send, messageField(2, account(value.to)));
        append(send, messageField(3, tokens(value.amount.e8s)));
        append(send, messageField(4, tokens(value.fee.e8s)));
        switch (value.spender) {
          case (?spender) {
            let transferFrom = messageField(1, account(spender));
            append(send, messageField(6, transferFrom));
          };
          case null {};
        };
        messageField(3, List.toArray(send))
      };
      case (#Approve(value)) {
        let send = List.empty<Nat8>();
        append(send, messageField(1, account(value.from)));
        append(send, messageField(2, account(value.spender)));
        append(send, messageField(3, tokens(0)));
        append(send, messageField(4, tokens(value.fee.e8s)));
        let approve = List.empty<Nat8>();
        append(approve, messageField(1, tokens(value.allowance.e8s)));
        switch (value.expires_at) {
          case (?expiry) append(approve, messageField(2, timestamp(expiry.timestamp_nanos)));
          case null {};
        };
        switch (value.expected_allowance) {
          case (?expected) append(approve, messageField(3, tokens(expected.e8s)));
          case null {};
        };
        append(send, messageField(5, List.toArray(approve)));
        messageField(3, List.toArray(send))
      };
    }
  };

  /// Encode the exact legacy protobuf bytes hashed and certified by the NNS ICP ledger.
  public func encode(block : Block, created_at_time_present : Bool) : Blob {
    let transaction = List.empty<Nat8>();
    // prost emits protobuf fields in ascending tag order. Field order is hash-significant here:
    // transfer(1..3), memo(4), obsolete created_at(5, never emitted), created_at_time(6), memo(7).
    switch (block.transaction.operation) {
      case (?operation) append(transaction, encodeOperation(operation));
      case null {};
    };
    append(transaction, messageField(4, uintField(1, block.transaction.memo)));
    if (created_at_time_present) {
      append(
        transaction,
        messageField(6, timestamp(block.transaction.created_at_time.timestamp_nanos)),
      )
    };
    switch (block.transaction.icrc1_memo) {
      case (?memo) append(transaction, messageField(7, bytesField(1, memo)));
      case null {};
    };

    let output = List.empty<Nat8>();
    switch (block.parent_hash) {
      case (?parent) append(output, messageField(1, bytesField(1, parent)));
      case null {};
    };
    append(output, messageField(2, timestamp(block.timestamp.timestamp_nanos)));
    append(output, messageField(3, List.toArray(transaction)));
    Blob.fromArray(List.toArray(output))
  };

  public func hashEncoded(encoded : Blob) : Blob { Sha256.fromBlob(#sha256, encoded) };
}
