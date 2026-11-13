/// Shielded directory — Menese DeFi Team.
///
/// The private balance's key desk and address book (docs/CLAIMABLE-PAYMENTS-SPEC.md):
///
/// * KEYS. A user's shielded account is recovered at every sign-in from a vetKey derived for their
///   principal and delivered encrypted to a one-use browser transport key. The derivation input is
///   the CALLER, never an argument, so a caller can only ever obtain their own key. The same vetKey
///   opens claimable payments sent to that principal (IBE under this canister's derived public key).
/// * ADDRESSES. A user's public shielded address (`register`) so a sender can pay them directly;
///   `lookup_certified` answers through consensus so a single replica cannot substitute an address.
/// * BIRTHDAY. A sealed, fixed-size wallet birthday, readable only by its owner.
/// * POOLS. One vetKey per sign-in serves every pool (the browser derives separate account keys per
///   pool from it), but each pool has its own address and birthday per user. The ICP pool's live in
///   the original maps and the original calls keep meaning it; other pools (ckBTC) are registered by
///   the administrator and use the `*_for_pool` calls, which also answer for the ICP pool.
///
/// Each derivation costs the canister cycles, and anyone can mint principals, so derivations are
/// limited per caller per day and in total per hour, and refused (not trapped) when the balance
/// would fall below a reserve. The administrator (set at install) adjusts the limits.
///
/// Install: `(opt record { vetkd_key_name = "key_1"; administrator = principal "..." })`. Upgrades
/// may pass `null`: the key and administrator are kept from install (stable), because a different
/// key would derive every user's account anew and strand their notes.
import Blob "mo:core/Blob";
import Cycles "mo:core/Cycles";
import Int "mo:core/Int";
import Iter "mo:core/Iter";
import Map "mo:core/Map";
import Nat64 "mo:core/Nat64";
import Principal "mo:core/Principal";
import Result "mo:core/Result";
import Runtime "mo:core/Runtime";
import Text "mo:core/Text";
import Time "mo:core/Time";

persistent actor class ShieldedDirectory(init : ?{ vetkd_key_name : Text; administrator : Principal }) = self {
  public type Entry = { shielded_pk : Text; enc_pk : Text };
  public type Limits = {
    derivations_per_caller_per_day : Nat;
    derivations_per_hour : Nat;
    cycles_reserve : Nat;
  };
  public type Status = {
    vetkd_key_name : Text;
    administrator : Principal;
    limits : Limits;
    registered : Nat;
    derivations_this_hour : Nat;
    cycles : Nat;
  };

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

  // Fixed at install. A stable `let` is evaluated only on the first install; upgrades keep it.
  let installed = switch (init) {
    case (?value) value;
    case null Runtime.trap("install argument required: opt record { vetkd_key_name; administrator }");
  };
  let key_id : VetKdKeyId = { curve = #bls12_381_g2; name = installed.vetkd_key_name };
  var administrator : Principal = installed.administrator;

  // The application context of every shielded-account vetKey. Clients derive this canister's
  // public key for it from the IC's vetKD master key (they do not have to trust this canister for it).
  let key_context : Blob = Text.encodeUtf8("picp-shielded-account/v1");
  // Attached to each derivation: the price for key_1 on the IC; unused cycles are refunded.
  transient let VETKD_DERIVE_CYCLES : Nat = 26_153_846_153;

  let entries = Map.empty<Principal, Entry>();
  // Sealed birthdays, caller-keyed, kept apart from `entries` so no public read exposes them.
  let birthdays = Map.empty<Principal, Blob>();
  // Exactly nonce(24) ‖ secretbox(version(1) ‖ height(8) ‖ ledger hash(32) ‖ anchor(32)): one
  // size for every account, so the ciphertext length never reveals the birthday's magnitude.
  transient let BIRTHDAY_CT_SIZE : Nat = 113;

  // Addresses and birthdays of pools other than the ICP pool: pool -> user -> value. Only pools the
  // administrator registered are accepted, so callers cannot grow the key space with made-up pools.
  let pool_entries = Map.empty<Principal, Map.Map<Principal, Entry>>();
  let pool_birthdays = Map.empty<Principal, Map.Map<Principal, Blob>>();
  // The pool whose addresses and birthdays are `entries` / `birthdays` (the ICP pool). Set once.
  var legacy_pool : ?Principal = null;

  var limits : Limits = {
    derivations_per_caller_per_day = 20;
    derivations_per_hour = 5_000;
    cycles_reserve = 1_000_000_000_000;
  };
  // caller -> (day number, derivations that day); global (hour number, derivations that hour)
  let derivations = Map.empty<Principal, (Nat64, Nat)>();
  var hour_window : (Nat64, Nat) = (0, 0);

  transient let NS_PER_HOUR : Nat64 = 3_600_000_000_000;
  transient let NS_PER_DAY : Nat64 = 86_400_000_000_000;
  func now() : Nat64 { Nat64.fromNat(Int.abs(Time.now())) };

  /// Reserve one derivation for `caller` against both limits, or say why not. Reserved before the
  /// await, so concurrent calls cannot overshoot; a failed derivation keeps its slot (it may have
  /// spent cycles).
  func reserveDerivation(caller : Principal) : ?Text {
    if (Cycles.balance() < limits.cycles_reserve + VETKD_DERIVE_CYCLES) return ?"cycles-low";
    let t = now();
    let hour = t / NS_PER_HOUR;
    let hourCount = if (hour_window.0 == hour) hour_window.1 else 0;
    if (hourCount >= limits.derivations_per_hour) return ?"rate-limited:hour";
    let day = t / NS_PER_DAY;
    let callerCount = switch (Map.get(derivations, Principal.compare, caller)) {
      case (?(d, n)) if (d == day) n else 0;
      case null 0;
    };
    if (callerCount >= limits.derivations_per_caller_per_day) return ?"rate-limited:caller";
    hour_window := (hour, hourCount + 1);
    Map.add(derivations, Principal.compare, caller, (day, callerCount + 1));
    null
  };

  transient let vetkd : VetKdSystemApi = actor ("aaaaa-aa");

  /// This canister's derived public key for the shielded-account context. Clients also derive it
  /// themselves from the IC's master key and compare.
  public shared func vetkey_public_key() : async Blob {
    let reply = await vetkd.vetkd_public_key({
      canister_id = ?Principal.fromActor(self);
      context = key_context;
      key_id;
    });
    reply.public_key
  };

  /// The caller's vetKey, encrypted to a one-use transport key. The derivation input is the caller.
  public shared ({ caller }) func derive_shielded_key(transport_public_key : Blob) : async Result.Result<Blob, Text> {
    if (Principal.isAnonymous(caller)) return #err("anonymous-caller");
    if (transport_public_key.size() != 48) return #err("bad-transport-public-key");
    switch (reserveDerivation(caller)) { case (?e) return #err(e); case null {} };
    let reply = await (with cycles = VETKD_DERIVE_CYCLES) vetkd.vetkd_derive_key({
      context = key_context;
      input = Principal.toBlob(caller);
      key_id;
      transport_public_key;
    });
    #ok(reply.encrypted_key)
  };

  /// Register (or rotate) the caller's own shielded address. Nobody can write another's entry.
  public shared ({ caller }) func register(shielded_pk : Text, enc_pk : Text) : async Result.Result<(), Text> {
    if (Principal.isAnonymous(caller)) return #err("anonymous-caller");
    if (shielded_pk.size() == 0 or shielded_pk.size() > 128) return #err("bad-shielded-pk");
    if (enc_pk.size() == 0 or enc_pk.size() > 128) return #err("bad-enc-pk");
    Map.add(entries, Principal.compare, caller, { shielded_pk; enc_pk });
    #ok
  };

  /// Store the caller's sealed birthday; registration first, so only real accounts consume state.
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

  /// The caller's own sealed birthday. An update call: consensus-certified, and private to the caller.
  public shared ({ caller }) func get_birthday() : async ?Blob {
    if (Principal.isAnonymous(caller)) return null;
    Map.get(birthdays, Principal.compare, caller)
  };

  /// A principal's shielded address, answered by one replica (fast; for display).
  public query func lookup(p : Principal) : async ?Entry {
    Map.get(entries, Principal.compare, p)
  };

  /// The same, through consensus: what a sender uses before paying, so no single replica can
  /// substitute an address. Call it anonymously.
  public shared func lookup_certified(p : Principal) : async ?Entry {
    Map.get(entries, Principal.compare, p)
  };

  public query func count() : async Nat { Map.size(entries) };

  // ==================== per pool ====================

  public type Pools = { legacy_pool : ?Principal; pools : [Principal] };

  type PoolMaps = { entries : Map.Map<Principal, Entry>; birthdays : Map.Map<Principal, Blob> };

  /// The maps that hold `pool`'s addresses and birthdays, or null for a pool nobody registered.
  func mapsFor(pool : Principal) : ?PoolMaps {
    switch (legacy_pool) {
      case (?legacy) { if (Principal.equal(pool, legacy)) return ?{ entries; birthdays } };
      case null {};
    };
    switch (Map.get(pool_entries, Principal.compare, pool), Map.get(pool_birthdays, Principal.compare, pool)) {
      case (?e, ?b) ?{ entries = e; birthdays = b };
      case _ null;
    }
  };

  func validEntry(shielded_pk : Text, enc_pk : Text) : ?Text {
    if (shielded_pk.size() == 0 or shielded_pk.size() > 128) return ?"bad-shielded-pk";
    if (enc_pk.size() == 0 or enc_pk.size() > 128) return ?"bad-enc-pk";
    null
  };

  /// Register (or rotate) the caller's own shielded address in `pool`.
  public shared ({ caller }) func register_for_pool(pool : Principal, shielded_pk : Text, enc_pk : Text) : async Result.Result<(), Text> {
    if (Principal.isAnonymous(caller)) return #err("anonymous-caller");
    let maps = switch (mapsFor(pool)) { case (?m) m; case null return #err("unknown-pool") };
    switch (validEntry(shielded_pk, enc_pk)) { case (?e) return #err(e); case null {} };
    Map.add(maps.entries, Principal.compare, caller, { shielded_pk; enc_pk });
    #ok
  };

  /// Store the caller's sealed birthday for `pool`; registration in that pool first.
  public shared ({ caller }) func set_birthday_for_pool(pool : Principal, ct : Blob) : async Result.Result<(), Text> {
    if (Principal.isAnonymous(caller)) return #err("anonymous-caller");
    let maps = switch (mapsFor(pool)) { case (?m) m; case null return #err("unknown-pool") };
    if (Map.get(maps.entries, Principal.compare, caller) == null) return #err("not-registered");
    if (ct.size() != BIRTHDAY_CT_SIZE) return #err("bad-birthday-ct-size");
    Map.add(maps.birthdays, Principal.compare, caller, ct);
    #ok
  };

  /// The caller's own sealed birthday for `pool`. An update call: consensus-certified, private.
  public shared ({ caller }) func get_birthday_for_pool(pool : Principal) : async ?Blob {
    if (Principal.isAnonymous(caller)) return null;
    switch (mapsFor(pool)) { case (?maps) Map.get(maps.birthdays, Principal.compare, caller); case null null }
  };

  /// A principal's shielded address in `pool`, answered by one replica (for display).
  public query func lookup_for_pool(pool : Principal, p : Principal) : async ?Entry {
    switch (mapsFor(pool)) { case (?maps) Map.get(maps.entries, Principal.compare, p); case null null }
  };

  /// The same, through consensus: what a sender uses before paying in `pool`.
  public shared func lookup_certified_for_pool(pool : Principal, p : Principal) : async ?Entry {
    switch (mapsFor(pool)) { case (?maps) Map.get(maps.entries, Principal.compare, p); case null null }
  };

  public query func count_for_pool(pool : Principal) : async ?Nat {
    switch (mapsFor(pool)) { case (?maps) ?Map.size(maps.entries); case null null }
  };

  public query func pools() : async Pools {
    { legacy_pool; pools = Iter.toArray(Map.keys(pool_entries)) }
  };

  /// Administrator only, once: name the pool whose addresses and birthdays are the original maps.
  public shared ({ caller }) func set_legacy_pool(pool : Principal) : async Result.Result<(), Text> {
    if (caller != administrator) return #err("not-administrator");
    if (legacy_pool != null) return #err("legacy-pool-already-set");
    if (Principal.isAnonymous(pool)) return #err("anonymous-pool");
    if (Map.containsKey(pool_entries, Principal.compare, pool)) return #err("pool-already-registered");
    legacy_pool := ?pool;
    #ok
  };

  /// Administrator only: accept addresses and birthdays for another pool. Pools are never removed,
  /// so a user's address cannot disappear under a sender.
  public shared ({ caller }) func add_pool(pool : Principal) : async Result.Result<(), Text> {
    if (caller != administrator) return #err("not-administrator");
    if (Principal.isAnonymous(pool)) return #err("anonymous-pool");
    if (legacy_pool == ?pool) return #err("pool-is-legacy");
    if (Map.containsKey(pool_entries, Principal.compare, pool)) return #err("pool-already-registered");
    Map.add(pool_entries, Principal.compare, pool, Map.empty<Principal, Entry>());
    Map.add(pool_birthdays, Principal.compare, pool, Map.empty<Principal, Blob>());
    #ok
  };

  public query func status() : async Status {
    let hour = now() / NS_PER_HOUR;
    {
      vetkd_key_name = key_id.name;
      administrator;
      limits;
      registered = Map.size(entries);
      derivations_this_hour = if (hour_window.0 == hour) hour_window.1 else 0;
      cycles = Cycles.balance();
    }
  };

  /// Administrator only.
  public shared ({ caller }) func set_limits(next : Limits) : async Result.Result<Limits, Text> {
    if (caller != administrator) return #err("not-administrator");
    if (next.derivations_per_caller_per_day == 0 or next.derivations_per_hour == 0) return #err("limits-must-be-positive");
    limits := next;
    #ok(limits)
  };

  /// Administrator only: hand the role to another principal.
  public shared ({ caller }) func set_administrator(next : Principal) : async Result.Result<(), Text> {
    if (caller != administrator) return #err("not-administrator");
    if (Principal.isAnonymous(next)) return #err("anonymous-administrator");
    administrator := next;
    #ok
  };
};
