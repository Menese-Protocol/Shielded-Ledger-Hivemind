/// Public shielded-address directory for the pICP demo (Menese DeFi Team).
///
/// Maps an ICP principal to the PUBLIC halves of its shielded account. Private account material
/// is deterministically recovered after authentication with a vetKey encrypted to an ephemeral
/// browser transport key; no spend/decryption key is stored in localStorage or by this canister.
///
/// Security boundary: the management canister binds `input` to the authenticated caller below.
/// The browser verifies the encrypted vetKey against the derived public key before using it.
import Blob "mo:core/Blob";
import Map "mo:core/Map";
import Principal "mo:core/Principal";
import Result "mo:core/Result";
import Text "mo:core/Text";

persistent actor DemoDirectory {
  public type Entry = { shielded_pk : Text; enc_pk : Text };

  type VetKdKeyId = { curve : { #bls12_381_g2 }; name : Text };
  type VetKdSystemApi = actor {
    vetkd_public_key : ({ canister_id : ?Principal; context : Blob; key_id : VetKdKeyId }) ->
      async { public_key : Blob };
    vetkd_derive_key : ({
      context : Blob;
      input : Blob;
      key_id : VetKdKeyId;
      transport_public_key : Blob;
    }) -> async { encrypted_key : Blob };
  };

  let entries = Map.empty<Principal, Entry>();
  // Sealed wallet-birthday records, caller-keyed. Kept OUT of `entries` on purpose:
  // (a) `lookup` is a public query and must never expose another principal's birthday
  // ciphertext (presence/size metadata); (b) a new stable map is trivially upgrade-compatible,
  // whereas widening the Entry record inside the existing stable map is not. The canister
  // stores ONLY ciphertext (fixed 113 bytes) and can never build a principal→creation-height
  // table from its state.
  let birthdays = Map.empty<Principal, Blob>();
  let vetkd : VetKdSystemApi = actor ("aaaaa-aa");
  let key_id : VetKdKeyId = { curve = #bls12_381_g2; name = "test_key_1" };
  let key_context : Blob = Text.encodeUtf8("picp-shielded-account/v1");
  let VETKD_DERIVE_CYCLES : Nat = 26_153_846_153;

  /// Public verification key for this canister + application context. The client combines it
  /// with its principal input while verifying the encrypted key response.
  public shared func vetkey_public_key() : async Blob {
    let reply = await vetkd.vetkd_public_key({
      canister_id = ?Principal.fromActor(DemoDirectory);
      context = key_context;
      key_id;
    });
    reply.public_key
  };

  /// Deliver the caller's deterministic key encrypted to a one-use browser transport key.
  /// A caller cannot request another principal's key: the derivation input is not an argument.
  public shared ({ caller }) func derive_shielded_key(transport_public_key : Blob) : async Result.Result<Blob, Text> {
    if (Principal.isAnonymous(caller)) return #err("anonymous-caller");
    if (transport_public_key.size() != 48) return #err("bad-transport-public-key");
    let reply = await (with cycles = VETKD_DERIVE_CYCLES) vetkd.vetkd_derive_key({
      context = key_context;
      input = Principal.toBlob(caller);
      key_id;
      transport_public_key;
    });
    #ok(reply.encrypted_key)
  };

  /// Register (or rotate) the caller's shielded account keys. Caller-keyed: you can only ever
  /// write your own entry, so no one can redirect another principal's incoming notes.
  public shared ({ caller }) func register(shielded_pk : Text, enc_pk : Text) : async Result.Result<(), Text> {
    if (Principal.isAnonymous(caller)) return #err("anonymous-caller");
    if (shielded_pk.size() == 0 or shielded_pk.size() > 128) return #err("bad-shielded-pk");
    if (enc_pk.size() == 0 or enc_pk.size() > 128) return #err("bad-enc-pk");
    Map.add(entries, Principal.compare, caller, { shielded_pk; enc_pk });
    #ok
  };

  // The sealed birthday record is exactly nonce(24) ‖ secretbox(version(1) ‖ height(8 BE) ‖
  // ledger-binding-hash(32) ‖ chain-anchor(32)) = 113 bytes for EVERY account at EVERY height —
  // an exact-size guard, so ciphertext length can never leak the birthday's magnitude.
  let BIRTHDAY_CT_SIZE : Nat = 113;

  /// Store the caller's wallet birthday, sealed client-side under a vetKey-derived key the
  /// canister never sees. Caller-keyed like `register`: you can only ever write your own record,
  /// so no one can plant an inflated birthday on a victim. Registration is required first —
  /// only real accounts consume state.
  public shared ({ caller }) func set_birthday(ct : Blob) : async Result.Result<(), Text> {
    if (Principal.isAnonymous(caller)) return #err("anonymous-caller");
    switch (Map.get(entries, Principal.compare, caller)) {
      case null { return #err("not-registered") };
      case (?_) {};
    };
    if (ct.size() != BIRTHDAY_CT_SIZE) return #err("bad-birthday-ct-size");
    Map.add(birthdays, Principal.compare, caller, ct);
    #ok
  };

  /// Return the CALLER's own sealed birthday record only — deliberately not a query and not
  /// part of `lookup`: an update call returns consensus-certified state (a single malicious
  /// replica cannot serve a rolled-back ciphertext), and no other principal can even observe
  /// whether a record exists.
  public shared ({ caller }) func get_birthday() : async ?Blob {
    if (Principal.isAnonymous(caller)) return null;
    Map.get(birthdays, Principal.compare, caller)
  };

  public query func lookup(p : Principal) : async ?Entry {
    Map.get(entries, Principal.compare, p)
  };

  public query func count() : async Nat { Map.size(entries) };
}
