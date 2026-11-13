/// Exact ICRC-3 `2xfer` matcher for recovery from ICRC-2 `Ok`/`Duplicate` results.

import Blob "mo:core/Blob";
import Nat64 "mo:core/Nat64";
import Principal "mo:core/Principal";
import ICRC2 "ICRC2";
import ICRC3 "ICRC3";

module {
  func mapField(entries : [(Text, ICRC3.Value)], name : Text) : ?ICRC3.Value {
    var found : ?ICRC3.Value = null;
    for ((key, value) in entries.vals()) {
      if (key == name) {
        if (found != null) return null;
        found := ?value;
      };
    };
    found
  };

  func hasField(entries : [(Text, ICRC3.Value)], name : Text) : Bool {
    for ((key, _) in entries.vals()) { if (key == name) return true };
    false
  };

  /// True when the block is in one of the two schemas ICRC-3 allows and names the wanted transfer.
  /// Typed form: `btype` names the operation (`typed` here) and the caller-set fee is `tx.fee`.
  /// Legacy ICRC-1/2 form, written by DFINITY's ICRC ledger (ckBTC included): no `btype`, `tx.op`
  /// names the operation, and the fee is `tx.fee` when the caller set it, else a block-level `fee`.
  /// The pool always sets the fee, so a legacy block of ours has `tx.fee` and no block-level `fee`.
  /// A duplicated `btype` or `op` reads as missing, so the block is refused.
  func schemaOk(outer : [(Text, ICRC3.Value)], tx : [(Text, ICRC3.Value)], typed : Text) : Bool {
    if (hasField(outer, "btype")) {
      textField(outer, "btype") == ?typed
    } else {
      textField(tx, "op") == ?"xfer" and not hasField(outer, "fee")
    }
  };

  func natField(entries : [(Text, ICRC3.Value)], name : Text) : ?Nat {
    switch (mapField(entries, name)) { case (?#Nat(value)) ?value; case _ null }
  };

  func blobField(entries : [(Text, ICRC3.Value)], name : Text) : ?Blob {
    switch (mapField(entries, name)) { case (?#Blob(value)) ?value; case _ null }
  };

  func textField(entries : [(Text, ICRC3.Value)], name : Text) : ?Text {
    switch (mapField(entries, name)) { case (?#Text(value)) ?value; case _ null }
  };

  func accountField(entries : [(Text, ICRC3.Value)], name : Text) : ?ICRC2.Account {
    let values = switch (mapField(entries, name)) {
      case (?#Array(value)) value;
      case _ return null;
    };
    if (values.size() != 1 and values.size() != 2) return null;
    let owner = switch (values[0]) {
      case (#Blob(value)) {
        if (value.size() > 29) return null;
        Principal.fromBlob(value)
      };
      case _ return null;
    };
    let subaccount : ?Blob = if (values.size() == 2) {
      switch (values[1]) {
        case (#Blob(value)) {
          if (value.size() != 32) return null;
          ?value
        };
        case _ return null;
      }
    } else { null };
    ?{ owner; subaccount }
  };

  /// Accepts the typed `2xfer` block or the legacy `op = "xfer"` block with a spender (DFINITY's ICRC
  /// ledger, ckBTC). Because the caller supplies `fee`, it must be in `tx.fee`; because
  /// `created_at_time` is non-null, it must be in `tx.ts`.
  public func matchesTransferFrom(
    block : ICRC3.Value,
    args : ICRC2.TransferFromArgs,
    spenderOwner : Principal,
  ) : Bool {
    let outer = switch (block) { case (#Map(value)) value; case _ return false };
    let tx = switch (mapField(outer, "tx")) { case (?#Map(value)) value; case _ return false };
    if (not schemaOk(outer, tx, "2xfer")) return false;

    if (natField(tx, "amt") != ?args.amount) return false;
    let expectedFee = switch (args.fee) { case (?value) value; case null return false };
    if (natField(tx, "fee") != ?expectedFee) return false;
    let expectedTime = switch (args.created_at_time) {
      case (?value) Nat64.toNat(value);
      case null return false;
    };
    if (natField(tx, "ts") != ?expectedTime) return false;
    let expectedMemo = switch (args.memo) { case (?value) value; case null return false };
    switch (blobField(tx, "memo")) {
      case (?value) { if (not Blob.equal(value, expectedMemo)) return false };
      case null return false;
    };
    let from = switch (accountField(tx, "from")) { case (?value) value; case null return false };
    let to = switch (accountField(tx, "to")) { case (?value) value; case null return false };
    let spender = switch (accountField(tx, "spender")) { case (?value) value; case null return false };
    ICRC2.accountsEqual(from, args.from) and ICRC2.accountsEqual(to, args.to) and
    ICRC2.accountsEqual(spender, { owner = spenderOwner; subaccount = args.spender_subaccount })
  };
}
