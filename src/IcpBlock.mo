/// The NNS ICP ledger's own history, read and matched directly (no adapter).
///
/// The ICP ledger does not serve ICRC-3 (`icrc3_get_blocks`); its history is the legacy
/// `query_blocks` log of `NnsBlock.Block`s, with archived ranges served by archive canisters. An
/// ICRC-2 `transfer_from` is recorded there as `Transfer { from; to; amount; fee; spender = ?_ }`
/// and an ICRC-1 `transfer` as the same operation with `spender = null`; accounts appear only as
/// 32-byte account identifiers, and the ICRC-1 memo as `icrc1_memo` (the legacy `memo` is 0).
///
/// The ledger knows every account it expects in a block it is checking (the user's, its own pool
/// account, its own principal as spender), so it computes their identifiers
/// (`Principal.toLedgerAccount`: CRC32 ‖ SHA-224("\x0Aaccount-id" ‖ principal ‖ subaccount)) and
/// compares bytes. No preimage registration, no translation, nothing to trust but the ICP ledger's
/// replicated reply.
///
/// Interface pinned to dfinity/ic 69b755062f5ef0a7d6efc9a127172b46121420c8
/// (`rs/ledger_suite/icp/ledger.did`), the revision the mainnet ICP ledger runs
/// (module hash 51f4be010f23064137defacd627ffbec024c5133210c68ca3b80ab8f257101d6).

import Blob "mo:core/Blob";
import Nat64 "mo:core/Nat64";
import Principal "mo:core/Principal";
import ICRC2 "ICRC2";
import NnsBlock "NnsBlock";

module {
  public type Block = NnsBlock.Block;
  public type GetBlocksArgs = NnsBlock.GetBlocksArgs;
  public type QueryBlocksResponse = NnsBlock.QueryBlocksResponse;
  public type ArchivedBlocksRange = NnsBlock.ArchivedBlocksRange;
  public type QueryArchiveFn = NnsBlock.QueryArchiveFn;

  public type IcpLedger = actor {
    query_blocks : shared query GetBlocksArgs -> async QueryBlocksResponse;
  };

  func accountId(account : ICRC2.Account) : Blob {
    Principal.toLedgerAccount(account.owner, account.subaccount)
  };

  func natIsE8s(value : Nat, e8s : Nat64) : Bool {
    value <= 0xFFFF_FFFF_FFFF_FFFF and Nat64.fromNat(value) == e8s
  };

  /// The `transfer_from` this ledger sent with `args`, spent by `spenderOwner`: every field the
  /// call fixed must be in the block exactly (fee and created_at_time are always set by the ledger,
  /// so their absence in `args` is itself a mismatch).
  public func matchesTransferFrom(block : Block, args : ICRC2.TransferFromArgs, spenderOwner : Principal) : Bool {
    let tx = block.transaction;
    let (from, to, amount, fee, spender) = switch (tx.operation) {
      case (?#Transfer(op)) (op.from, op.to, op.amount, op.fee, op.spender);
      case _ return false;
    };
    let expectedSpender = accountId({ owner = spenderOwner; subaccount = args.spender_subaccount });
    switch (spender) {
      case (?value) { if (not Blob.equal(value, expectedSpender)) return false };
      case null return false;
    };
    if (not Blob.equal(from, accountId(args.from))) return false;
    if (not Blob.equal(to, accountId(args.to))) return false;
    if (not natIsE8s(args.amount, amount.e8s)) return false;
    switch (args.fee) {
      case (?value) { if (not natIsE8s(value, fee.e8s)) return false };
      case null return false;
    };
    switch (args.created_at_time) {
      case (?value) { if (value != tx.created_at_time.timestamp_nanos) return false };
      case null return false;
    };
    switch (args.memo, tx.icrc1_memo) {
      case (?expected, ?actual) { if (not Blob.equal(expected, actual)) return false };
      case _ return false;
    };
    true
  };

  /// The ICRC-1 `transfer` this ledger sent with `args` from its own account (`fromOwner` with
  /// `args.from_subaccount`): an ICP `Transfer` with no spender and every fixed field equal.
  public func matchesTransfer(block : Block, args : ICRC2.TransferArg, fromOwner : Principal) : Bool {
    let tx = block.transaction;
    let (from, to, amount, fee, spender) = switch (tx.operation) {
      case (?#Transfer(op)) (op.from, op.to, op.amount, op.fee, op.spender);
      case _ return false;
    };
    if (spender != null) return false;
    if (not Blob.equal(from, accountId({ owner = fromOwner; subaccount = args.from_subaccount }))) return false;
    if (not Blob.equal(to, accountId(args.to))) return false;
    if (not natIsE8s(args.amount, amount.e8s)) return false;
    switch (args.fee) {
      case (?value) { if (not natIsE8s(value, fee.e8s)) return false };
      case null return false;
    };
    switch (args.created_at_time) {
      case (?value) { if (value != tx.created_at_time.timestamp_nanos) return false };
      case null return false;
    };
    switch (args.memo, tx.icrc1_memo) {
      case (?expected, ?actual) { if (not Blob.equal(expected, actual)) return false };
      case _ return false;
    };
    true
  };
}
