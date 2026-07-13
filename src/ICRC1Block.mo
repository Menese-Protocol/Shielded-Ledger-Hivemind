/// Exact ICRC-3 `1xfer` matcher for recovering an idempotent pool withdrawal.

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

  public func matchesTransfer(block : ICRC3.Value, args : ICRC2.TransferArg, fromOwner : Principal) : Bool {
    let outer = switch (block) { case (#Map(value)) value; case _ return false };
    if (textField(outer, "btype") != ?"1xfer") return false;
    let tx = switch (mapField(outer, "tx")) { case (?#Map(value)) value; case _ return false };
    if (natField(tx, "amt") != ?args.amount) return false;
    let fee = switch (args.fee) { case (?value) value; case null return false };
    if (natField(tx, "fee") != ?fee) return false;
    let timestamp = switch (args.created_at_time) {
      case (?value) Nat64.toNat(value);
      case null return false;
    };
    if (natField(tx, "ts") != ?timestamp) return false;
    let memo = switch (args.memo) { case (?value) value; case null return false };
    switch (blobField(tx, "memo")) {
      case (?value) { if (not Blob.equal(value, memo)) return false };
      case null return false;
    };
    let from = switch (accountField(tx, "from")) { case (?value) value; case null return false };
    let to = switch (accountField(tx, "to")) { case (?value) value; case null return false };
    ICRC2.accountsEqual(from, { owner = fromOwner; subaccount = args.from_subaccount }) and
    ICRC2.accountsEqual(to, args.to)
  };
}
