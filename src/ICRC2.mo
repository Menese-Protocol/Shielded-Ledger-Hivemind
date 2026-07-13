/// Minimal pinned ICRC-1/2/3 types used by the sandbox atomic-shield boundary.
///
/// This module intentionally contains no `#Int` block constructor. `ICRC3.Value` retains the
/// standard variant for decoding, but Gate 1 forbids emitting it while the external Rust crate's
/// positive-Int hashing bug remains open.

import Blob "mo:core/Blob";
import Principal "mo:core/Principal";
import ICRC3 "ICRC3";

module {
  public type Account = { owner : Principal; subaccount : ?Blob };

  public type TransferFromArgs = {
    spender_subaccount : ?Blob;
    from : Account;
    to : Account;
    amount : Nat;
    fee : ?Nat;
    memo : ?Blob;
    created_at_time : ?Nat64;
  };

  public type TransferFromError = {
    #BadFee : { expected_fee : Nat };
    #BadBurn : { min_burn_amount : Nat };
    #InsufficientFunds : { balance : Nat };
    #InsufficientAllowance : { allowance : Nat };
    #TooOld;
    #CreatedInFuture : { ledger_time : Nat64 };
    #Duplicate : { duplicate_of : Nat };
    #TemporarilyUnavailable;
    #GenericError : { error_code : Nat; message : Text };
  };
  public type TransferFromResult = { #Ok : Nat; #Err : TransferFromError };

  public type TransferArg = {
    from_subaccount : ?Blob;
    to : Account;
    amount : Nat;
    fee : ?Nat;
    memo : ?Blob;
    created_at_time : ?Nat64;
  };
  public type TransferError = {
    #BadFee : { expected_fee : Nat };
    #BadBurn : { min_burn_amount : Nat };
    #InsufficientFunds : { balance : Nat };
    #TooOld;
    #CreatedInFuture : { ledger_time : Nat64 };
    #Duplicate : { duplicate_of : Nat };
    #TemporarilyUnavailable;
    #GenericError : { error_code : Nat; message : Text };
  };
  public type TransferResult = { #Ok : Nat; #Err : TransferError };

  public type ApproveArgs = {
    from_subaccount : ?Blob;
    spender : Account;
    amount : Nat;
    expected_allowance : ?Nat;
    expires_at : ?Nat64;
    fee : ?Nat;
    memo : ?Blob;
    created_at_time : ?Nat64;
  };
  public type ApproveError = {
    #BadFee : { expected_fee : Nat };
    #InsufficientFunds : { balance : Nat };
    #AllowanceChanged : { current_allowance : Nat };
    #Expired : { ledger_time : Nat64 };
    #TooOld;
    #CreatedInFuture : { ledger_time : Nat64 };
    #Duplicate : { duplicate_of : Nat };
    #TemporarilyUnavailable;
    #GenericError : { error_code : Nat; message : Text };
  };
  public type ApproveResult = { #Ok : Nat; #Err : ApproveError };

  public type AllowanceArgs = { account : Account; spender : Account };
  public type Allowance = { allowance : Nat; expires_at : ?Nat64 };

  public type GetBlocksArgs = { start : Nat; length : Nat };
  public type Block = { id : Nat; block : ICRC3.Value };
  public type GetBlocksResult = {
    log_length : Nat;
    blocks : [Block];
  };

  public func accountsEqual(left : Account, right : Account) : Bool {
    if (not Principal.equal(left.owner, right.owner)) return false;
    switch (left.subaccount, right.subaccount) {
      case (null, null) true;
      case (?a, ?b) Blob.equal(a, b);
      case _ false;
    }
  };

  public func optionalBlobEqual(left : ?Blob, right : ?Blob) : Bool {
    switch (left, right) {
      case (null, null) true;
      case (?a, ?b) Blob.equal(a, b);
      case _ false;
    }
  };

  public func optionalNatEqual(left : ?Nat, right : ?Nat) : Bool { left == right };
  public func optionalNat64Equal(left : ?Nat64, right : ?Nat64) : Bool { left == right };

  public func transferArgsEqual(left : TransferFromArgs, right : TransferFromArgs) : Bool {
    optionalBlobEqual(left.spender_subaccount, right.spender_subaccount) and
    accountsEqual(left.from, right.from) and accountsEqual(left.to, right.to) and
    left.amount == right.amount and optionalNatEqual(left.fee, right.fee) and
    optionalBlobEqual(left.memo, right.memo) and
    optionalNat64Equal(left.created_at_time, right.created_at_time)
  };

  public func directTransferArgsEqual(left : TransferArg, right : TransferArg) : Bool {
    optionalBlobEqual(left.from_subaccount, right.from_subaccount) and
    accountsEqual(left.to, right.to) and left.amount == right.amount and
    optionalNatEqual(left.fee, right.fee) and optionalBlobEqual(left.memo, right.memo) and
    optionalNat64Equal(left.created_at_time, right.created_at_time)
  };
}
