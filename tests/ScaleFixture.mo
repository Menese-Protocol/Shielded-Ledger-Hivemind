/// T1/T2 SYNTHETIC-STATE FIXTURE — test-only actor, never the shipped ledger wasm.
///
/// Declares the SAME persistent stable fields as src/Main.mo (a subset — fields absent
/// here are initialized by Main.mo's own initializers when this canister is UPGRADED to
/// the real zk_ledger wasm; moc's stable-compatibility allows added fields, probed in
/// Phase 2a) and populates them through the REAL NoteCodec + ICRC3 + StableLog +
/// StableBlobSet code: a genuine phash chain, per-block historical-root and nullifier
/// membership, and a tree_state consistent with note_root and noteCount(). Upgrading this
/// canister to zk_ledger.wasm therefore runs the REAL postupgrade against states of any
/// size (T1: 1k / 20k / 200k), and the fixture's corruption primitives + verbatim
/// old-walk transcription give T2 its differential oracle on the SAME corrupted state.
///
/// The old walk is exposed as `old_walk_reset` + `old_walk_range(count)` UPDATE calls
/// (the one-shot walk exceeds the 40B message budget past ~13k notes — measured
/// 3.0M instr/note): on a QUIESCENT fixture the chunked sweep is exactly the old walk's
/// order and error strings, phase by phase.

import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Char "mo:core/Char";
import List "mo:core/List";
import Nat "mo:core/Nat";
import Nat32 "mo:core/Nat32";
import Nat64 "mo:core/Nat64";
import Nat8 "mo:core/Nat8";
import Principal "mo:core/Principal";
import Region "mo:core/Region";
import Runtime "mo:core/Runtime";
import Text "mo:core/Text";
import Prim "mo:⛔";
import Sha256 "mo:sha2/Sha256";
import ICRC2 "../src/ICRC2";
import ICRC3 "../src/ICRC3";
import NoteAudit "../src/NoteAudit";
import NoteCodec "../src/NoteCodec";
import StableBlobSet "../src/StableBlobSet";
import StableLog "../src/StableLog";

persistent actor ScaleFixture {
  public type Result<T> = { #ok : T; #err : Text };
  public type TreeState = {
    filled : [Text];
    root : Text;
    next_index : Nat64;
  };
  public type OutputRecord = {
    commitment : Blob;
    ephemeral_key : Blob;
    note_ciphertext : Blob;
  };
  public type PendingShield = {
    intent_id : Blob;
    caller : Principal;
    output : OutputRecord;
    value : Nat64;
    transfer_args : ICRC2.TransferFromArgs;
    anchor_before : Blob;
    root_after : Blob;
    next_tree : TreeState;
    base_epoch : Nat;
    verifier_outcome : Text;
    attempts : Nat;
    ledger_tip_before : Nat;
  };
  public type PendingUnshield = {
    intent_id : Blob;
    caller : Principal;
    output_1 : OutputRecord;
    output_2 : OutputRecord;
    nullifier_1 : Blob;
    nullifier_2 : Blob;
    transfer_args : ICRC2.TransferArg;
    recipient_binding : Blob;
    public_value : Nat64;
    pool_debit : Nat;
    anchor_before : Blob;
    root_after : Blob;
    next_tree : TreeState;
    base_epoch : Nat;
    verifier_outcome : Text;
    attempts : Nat;
    ledger_tip_before : Nat;
  };

  let ENCODING_VERSION : Nat = 1;
  let STABLE_LAYOUT_VERSION : Nat = 1;

  // ==== stable fields shared with src/Main.mo (same names, same types) ====
  var configuring : Bool = false;
  var administrator : ?Principal = null;
  var verifier_id : ?Principal = null;
  var tree_oracle_id : ?Principal = null;
  var token_ledger_id : ?Principal = null;
  var history_adapter_id : ?Principal = null;
  var transparent_ledger_fee : Nat = 0;
  var transparent_ledger_decimals : Nat8 = 0;
  var pool_subaccount : ?Blob = null;
  var transfer_vk_hex : Text = "";
  var deposit_vk_hex : Text = "";
  var tree_state : ?TreeState = null;
  var note_root : Blob = "";
  let historical_roots = StableBlobSet.newState();
  let spent_nullifiers = StableBlobSet.newState();
  let completed_shield_intents = StableBlobSet.newState();
  let completed_unshield_intents = StableBlobSet.newState();
  let note_log = StableLog.newState();
  var last_block_hash : ?Blob = null;
  var pool_value : Nat = 0;
  var epoch : Nat = 0;
  var pending_shield : ?PendingShield = null;
  var pending_unshield : ?PendingUnshield = null;
  var transfer_statement_version : Nat = 1;
  var test_fail_after_token_once : Bool = false;
  let stable_layout_version : Nat = STABLE_LAYOUT_VERSION;

  StableBlobSet.ensureInit(historical_roots);
  StableBlobSet.ensureInit(spent_nullifiers);
  StableBlobSet.ensureInit(completed_shield_intents);
  StableBlobSet.ensureInit(completed_unshield_intents);
  StableLog.ensureInit(note_log);

  // ==== helpers transcribed verbatim from src/Main.mo (walk dependencies) ====
  func noteCount() : Nat { StableLog.size(note_log) };
  func rootCount() : Nat { StableBlobSet.size(historical_roots) };
  func nullifierCount() : Nat { StableBlobSet.size(spent_nullifiers) };
  func selfPrincipal() : Principal { Principal.fromActor(ScaleFixture) };
  func poolAccount() : ICRC2.Account { { owner = selfPrincipal(); subaccount = pool_subaccount } };
  func tokenConfigured() : Bool { token_ledger_id != null and history_adapter_id != null };
  func configured() : Bool {
    verifier_id != null and tree_oracle_id != null and tree_state != null
  };
  func currentTree() : TreeState {
    switch (tree_state) { case (?state) state; case null Runtime.trap("unconfigured") }
  };
  func fieldSized(value : Blob) : Bool { value.size() == 32 };

  func nibbleText(n : Nat) : Text {
    switch (n) {
      case 0 "0"; case 1 "1"; case 2 "2"; case 3 "3";
      case 4 "4"; case 5 "5"; case 6 "6"; case 7 "7";
      case 8 "8"; case 9 "9"; case 10 "a"; case 11 "b";
      case 12 "c"; case 13 "d"; case 14 "e"; case _ "f";
    }
  };
  func blobToHex(value : Blob) : Text {
    var result = "";
    for (byte in value.vals()) {
      let n = Nat8.toNat(byte);
      result #= nibbleText(n / 16) # nibbleText(n % 16);
    };
    result
  };
  func hexNibble(c : Char) : ?Nat8 {
    let n = Nat32.toNat(Char.toNat32(c));
    if (n >= 48 and n <= 57) return ?Nat8.fromNat(n - 48);
    if (n >= 97 and n <= 102) return ?Nat8.fromNat(n - 87);
    if (n >= 65 and n <= 70) return ?Nat8.fromNat(n - 55);
    null
  };
  func hexToBlob(value : Text) : ?Blob {
    let output = List.empty<Nat8>();
    var high : ?Nat8 = null;
    for (c in value.chars()) {
      let nibble = switch (hexNibble(c)) { case (?n) n; case null return null };
      switch (high) {
        case null { high := ?nibble };
        case (?h) {
          List.add(output, Nat8.fromNat(Nat8.toNat(h) * 16 + Nat8.toNat(nibble)));
          high := null;
        };
      };
    };
    if (high != null) return null;
    ?Blob.fromArray(List.toArray(output))
  };

  func blockValue(block : NoteCodec.ShieldedNoteBlock) : ICRC3.Value {
    let entries = List.empty<(Text, ICRC3.Value)>();
    List.add(entries, ("btype", #Text(block.btype)));
    switch (block.phash) { case (?hash) List.add(entries, ("phash", #Blob(hash))); case null {} };
    List.add(entries, ("encoding_version", #Nat(block.encoding_version)));
    List.add(entries, ("note_position", #Nat(block.note_position)));
    List.add(entries, ("commitment", #Blob(block.commitment)));
    List.add(entries, ("ephemeral_key", #Blob(block.ephemeral_key)));
    List.add(entries, ("note_ciphertext", #Blob(block.note_ciphertext)));
    List.add(entries, ("nullifiers", #Array(Array.map<Blob, ICRC3.Value>(block.nullifiers, func(value) {
      #Blob(value)
    }))));
    List.add(entries, ("anchor_before", #Blob(block.anchor_before)));
    List.add(entries, ("note_root_after", #Blob(block.note_root_after)));
    List.add(entries, ("timestamp", #Nat(Nat64.toNat(block.timestamp))));
    List.add(entries, ("origin", #Text(switch (block.origin) {
      case (#shield) "shield";
      case (#confidential_transfer) "confidential_transfer";
    })));
    #Map(List.toArray(entries))
  };

  func validateOutput(output : OutputRecord) : ?Text {
    if (not fieldSized(output.commitment)) return ?"REJECT:commitment-length";
    if (output.ephemeral_key.size() == 0) return ?"REJECT:ephemeral-key-empty";
    if (output.note_ciphertext.size() == 0) return ?"REJECT:ciphertext-empty";
    null
  };

  func recipientBindingValue(recipient : ICRC2.Account) : Result<Blob> {
    switch (recipient.subaccount) {
      case (?value) { if (value.size() != 32) return #err("REJECT:recipient-subaccount-length") };
      case null {};
    };
    let token = switch (token_ledger_id) {
      case (?value) value;
      case null return #err("REJECT:token-unconfigured");
    };
    let entries = List.empty<(Text, ICRC3.Value)>();
    List.add(entries, ("domain", #Text("picp-unshield-recipient/v1")));
    List.add(entries, ("pool", #Blob(Principal.toBlob(selfPrincipal()))));
    List.add(entries, ("token", #Blob(Principal.toBlob(token))));
    List.add(entries, ("owner", #Blob(Principal.toBlob(recipient.owner))));
    switch (recipient.subaccount) {
      case (?value) List.add(entries, ("subaccount", #Blob(value)));
      case null {};
    };
    let digest = Blob.toArray(ICRC3.hashValue(#Map(List.toArray(entries))));
    if (digest.size() != 32) return #err("REJECT:recipient-binding-hash");
    let field = Prim.Array_init<Nat8>(32, 0);
    var i : Nat = 0;
    while (i < 31) {
      field[i] := digest[i];
      i += 1;
    };
    #ok(Blob.fromArray(Array.fromVarArray(field)))
  };

  // ==== deterministic state generator (drives the REAL codec + chain code) ====
  func deterministicBlob(tag : Nat8, index : Nat, size : Nat) : Blob {
    let seed = Blob.fromArray(Array.tabulate<Nat8>(9, func(i) {
      if (i == 0) tag else Nat8.fromNat((index / (256 ** (i - 1))) % 256)
    }));
    let base = Sha256.fromBlob(#sha256, seed);
    if (size == 32) return base;
    let bytes = Blob.toArray(base);
    Blob.fromArray(Array.tabulate<Nat8>(size, func(i) { bytes[i % 32] }))
  };

  func rootFor(position : Nat) : Blob { deterministicBlob(2, position, 32) };

  /// Append `count` valid chained notes. Call repeatedly (paged; ~2k per call is well
  /// inside the 40B budget at the measured 1.5M instr/note append cost). Keeps
  /// note_root/tree_state/pool_value consistent so the state validates at every prefix.
  public func bulk_append(count : Nat) : async Nat {
    var i : Nat = 0;
    while (i < count) {
      let position = noteCount();
      let isTransfer = position % 3 != 0;
      let nullifiers : [Blob] = if (isTransfer) {
        [deterministicBlob(3, position * 2, 32), deterministicBlob(3, position * 2 + 1, 32)]
      } else { [] };
      let root = rootFor(position);
      let block : NoteCodec.ShieldedNoteBlock = {
        btype = "zknote1";
        phash = last_block_hash;
        encoding_version = ENCODING_VERSION;
        note_position = position;
        commitment = deterministicBlob(1, position, 32);
        ephemeral_key = deterministicBlob(4, position, 16);
        note_ciphertext = deterministicBlob(5, position, 112);
        nullifiers;
        anchor_before = note_root;
        note_root_after = root;
        timestamp = Nat64.fromNat(1_784_246_400_000_000_000 + position);
        origin = if (isTransfer) #confidential_transfer else #shield;
      };
      let encoded = switch (NoteCodec.encode(block)) {
        case (#ok(value)) value;
        case (#err(message)) Runtime.trap(message);
      };
      switch (StableLog.append(note_log, encoded)) {
        case (#ok(index)) { if (index != position) Runtime.trap("fixture: position") };
        case (#err(message)) Runtime.trap(message);
      };
      switch (StableBlobSet.put(historical_roots, root)) {
        case (#ok(_)) {};
        case (#err(message)) Runtime.trap(message);
      };
      for (n in nullifiers.vals()) {
        switch (StableBlobSet.put(spent_nullifiers, n)) {
          case (#ok(_)) {};
          case (#err(message)) Runtime.trap(message);
        };
      };
      last_block_hash := ?ICRC3.hashValue(blockValue(block));
      note_root := root;
      if (not isTransfer) { pool_value += 1_000_000 };
      epoch += 1;
      i += 1;
    };
    tree_state := ?{
      filled = Array.repeat<Text>("00", 32);
      root = blobToHex(note_root);
      next_index = Nat64.fromNat(noteCount());
    };
    noteCount()
  };

  /// Mark the fixture "configured" the way validateStableState expects (vk hexes are
  /// only size-checked by the walk; prepared vks stay null after the upgrade, which no
  /// postupgrade/audit/query path dereferences — pass-3 E1).
  public shared ({ caller }) func configure_fixture() : async () {
    verifier_id := ?selfPrincipal();
    tree_oracle_id := ?selfPrincipal();
    transfer_vk_hex := "aa";
    deposit_vk_hex := "aa";
    transfer_statement_version := 2;
    administrator := ?caller;
    if (tree_state == null) {
      let empty = rootFor(999_999_999);
      note_root := empty;
      ignore StableBlobSet.put(historical_roots, empty);
      tree_state := ?{
        filled = Array.repeat<Text>("00", 32);
        root = blobToHex(empty);
        next_index = 0;
      };
    };
  };

  public shared func configure_token_fixture(token : Principal, history : Principal) : async () {
    token_ledger_id := ?token;
    history_adapter_id := ?history;
    transparent_ledger_fee := 10_000;
    transparent_ledger_decimals := 8;
  };

  // ==== the OLD walk, verbatim order + strings, chunked for the 40B budget ====
  // On a quiescent fixture, reset + repeated range calls reproduce validateStableState
  // exactly: header phase, per-note walk, then the tail/configured/pending phases.
  // transient: the old-walk sweep runs and is read out BEFORE the fixture is upgraded
  // to the real wasm; these must not become stable vars Main.mo would have to migrate.
  transient var old_walk_cursor : Nat = 0;
  transient var old_walk_parent : ?Blob = null;
  transient var old_walk_result : ?Text = null; // null = in progress; ?"" = #ok; ?msg = #err(msg)

  func oldWalkHeader() : ?Text {
    if (stable_layout_version != STABLE_LAYOUT_VERSION) {
      return ?"stable-state:layout-version";
    };
    switch (StableLog.validate(note_log)) {
      case (#err(message)) return ?message;
      case (#ok(_)) {};
    };
    switch (StableBlobSet.validate(historical_roots)) {
      case (#err(message)) return ?("roots:" # message);
      case (#ok(_)) {};
    };
    switch (StableBlobSet.validate(spent_nullifiers)) {
      case (#err(message)) return ?("nullifiers:" # message);
      case (#ok(_)) {};
    };
    switch (StableBlobSet.validate(completed_shield_intents)) {
      case (#err(message)) return ?("completed-shields:" # message);
      case (#ok(_)) {};
    };
    switch (StableBlobSet.validate(completed_unshield_intents)) {
      case (#err(message)) return ?("completed-unshields:" # message);
      case (#ok(_)) {};
    };
    if (transfer_statement_version != 1 and transfer_statement_version != 2) {
      return ?"stable-state:transfer-statement-version";
    };
    null
  };

  func oldWalkNote(index : Nat) : ?Text {
    let encoded = switch (StableLog.get(note_log, index)) {
      case (?value) value;
      case null return ?"stable-state:missing-note";
    };
    let block = switch (NoteCodec.decode(encoded)) {
      case (#ok(value)) value;
      case (#err(message)) return ?message;
    };
    if (block.btype != "zknote1" or block.encoding_version != ENCODING_VERSION) {
      return ?"stable-state:block-domain";
    };
    if (block.note_position != index) return ?"stable-state:note-position";
    if (block.phash != old_walk_parent) return ?"stable-state:phash";
    if (not fieldSized(block.commitment) or not fieldSized(block.anchor_before) or
        not fieldSized(block.note_root_after)) {
      return ?"stable-state:block-field-length";
    };
    if (not StableBlobSet.contains(historical_roots, block.note_root_after)) {
      return ?"stable-state:missing-historical-root";
    };
    for (nullifier in block.nullifiers.vals()) {
      if (not StableBlobSet.contains(spent_nullifiers, nullifier)) {
        return ?"stable-state:missing-nullifier";
      };
    };
    let canonical = switch (NoteCodec.encode(block)) {
      case (#ok(value)) value;
      case (#err(message)) return ?message;
    };
    if (canonical != encoded) return ?"stable-state:noncanonical-note";
    old_walk_parent := ?ICRC3.hashValue(blockValue(block));
    null
  };

  func oldWalkTail() : ?Text {
    if (old_walk_parent != last_block_hash) return ?"stable-state:last-block-hash";

    if (configured()) {
      if (transfer_vk_hex.size() == 0 or deposit_vk_hex.size() == 0) {
        return ?"stable-state:empty-vk";
      };
      if (not fieldSized(note_root) or not StableBlobSet.contains(historical_roots, note_root)) {
        return ?"stable-state:current-root";
      };
      let state = currentTree();
      if (state.filled.size() != 32 or state.next_index != Nat64.fromNat(noteCount())) {
        return ?"stable-state:tree-position";
      };
      switch (hexToBlob(state.root)) {
        case (?root) { if (root != note_root) return ?"stable-state:tree-root" };
        case null return ?"stable-state:tree-root-hex";
      };
    } else {
      if (noteCount() != 0 or rootCount() != 0 or nullifierCount() != 0 or
          last_block_hash != null or pool_value != 0 or epoch != 0) {
        return ?"stable-state:unconfigured-nonempty";
      };
    };
    switch (pool_subaccount) {
      case (?value) { if (value.size() != 32) return ?"stable-state:pool-subaccount" };
      case null {};
    };
    if (tokenConfigured() and administrator == null) return ?"stable-state:token-admin";
    if (pending_shield != null and pending_unshield != null) {
      return ?"stable-state:multiple-pending-token-mutations";
    };
    switch (pending_shield) {
      case (?pending) {
        if (not tokenConfigured()) return ?"stable-state:pending-token-unconfigured";
        if (not fieldSized(pending.intent_id) or
            StableBlobSet.contains(completed_shield_intents, pending.intent_id)) {
          return ?"stable-state:pending-intent";
        };
        switch (validateOutput(pending.output)) {
          case (?_) return ?"stable-state:pending-output";
          case null {};
        };
        if (pending.base_epoch != epoch or pending.anchor_before != note_root) {
          return ?"stable-state:pending-epoch";
        };
        if (pending.next_tree.filled.size() != 32 or
            pending.next_tree.next_index != Nat64.fromNat(noteCount() + 1)) {
          return ?"stable-state:pending-tree-position";
        };
        switch (hexToBlob(pending.next_tree.root)) {
          case (?root) { if (root != pending.root_after) return ?"stable-state:pending-root" };
          case null return ?"stable-state:pending-root-hex";
        };
        let transfer = pending.transfer_args;
        if (not Principal.equal(transfer.from.owner, pending.caller) or
            transfer.spender_subaccount != null) {
          return ?"stable-state:pending-from";
        };
        if (not ICRC2.accountsEqual(transfer.to, poolAccount()) or
            transfer.amount != Nat64.toNat(pending.value) or transfer.fee != ?transparent_ledger_fee or
            transfer.created_at_time == null or transfer.memo != ?pending.intent_id) {
          return ?"stable-state:pending-transfer";
        };
      };
      case null {};
    };
    switch (pending_unshield) {
      case (?pending) {
        if (not tokenConfigured() or transfer_statement_version != 2) {
          return ?"stable-state:pending-unshield-configuration";
        };
        if (not fieldSized(pending.intent_id) or not fieldSized(pending.recipient_binding) or
            StableBlobSet.contains(completed_unshield_intents, pending.intent_id)) {
          return ?"stable-state:pending-unshield-intent";
        };
        switch (validateOutput(pending.output_1)) {
          case (?_) return ?"stable-state:pending-unshield-output-1";
          case null {};
        };
        switch (validateOutput(pending.output_2)) {
          case (?_) return ?"stable-state:pending-unshield-output-2";
          case null {};
        };
        if (pending.base_epoch != epoch or pending.anchor_before != note_root or
            not StableBlobSet.contains(historical_roots, pending.anchor_before)) {
          return ?"stable-state:pending-unshield-epoch";
        };
        if (pending.next_tree.filled.size() != 32 or
            pending.next_tree.next_index != Nat64.fromNat(noteCount() + 2)) {
          return ?"stable-state:pending-unshield-tree-position";
        };
        switch (hexToBlob(pending.next_tree.root)) {
          case (?root) { if (root != pending.root_after) return ?"stable-state:pending-unshield-root" };
          case null return ?"stable-state:pending-unshield-root-hex";
        };
        if (pending.nullifier_1 == pending.nullifier_2 or
            StableBlobSet.contains(spent_nullifiers, pending.nullifier_1) or
            StableBlobSet.contains(spent_nullifiers, pending.nullifier_2)) {
          return ?"stable-state:pending-unshield-nullifier";
        };
        let transfer = pending.transfer_args;
        if (transfer.from_subaccount != pool_subaccount or transfer.amount != Nat64.toNat(pending.public_value) or
            transfer.fee != ?transparent_ledger_fee or transfer.created_at_time == null or
            transfer.memo != ?pending.intent_id or not Principal.equal(transfer.to.owner, pending.caller)) {
          return ?"stable-state:pending-unshield-transfer";
        };
        if (pending.pool_debit != transfer.amount + transparent_ledger_fee or pending.pool_debit > pool_value) {
          return ?"stable-state:pending-unshield-pool-debit";
        };
        switch (recipientBindingValue(transfer.to)) {
          case (#ok(value)) { if (value != pending.recipient_binding) return ?"stable-state:pending-unshield-binding" };
          case (#err(_)) return ?"stable-state:pending-unshield-binding-invalid";
        };
      };
      case null {};
    };
    ?""
  };

  public func old_walk_reset() : async () {
    old_walk_cursor := 0;
    old_walk_parent := null;
    old_walk_result := oldWalkHeader(); // header phase runs first, exactly as the old walk
  };

  /// Advance the old walk by up to `count` notes; finishes with the tail phases when the
  /// per-note walk completes. Returns #ok(true) when the verdict is available.
  public func old_walk_range(count : Nat) : async Bool {
    if (old_walk_result != null) return true;
    var stepped : Nat = 0;
    while (stepped < count and old_walk_cursor < noteCount()) {
      switch (oldWalkNote(old_walk_cursor)) {
        case (?message) { old_walk_result := ?message; return true };
        case null {};
      };
      old_walk_cursor += 1;
      stepped += 1;
    };
    if (old_walk_cursor >= noteCount()) {
      old_walk_result := oldWalkTail();
      return true;
    };
    false
  };

  public query func old_walk_verdict() : async Result<()> {
    switch (old_walk_result) {
      case (?"") #ok(());
      case (?message) #err(message);
      case null #err("fixture:old-walk-incomplete");
    }
  };

  // ==== corruption primitives (T2/T3 states are built HERE, then upgraded) ====

  func noteOffset(index : Nat) : (Nat64, Nat) {
    let index_offset : Nat64 = 32 + Nat64.fromNat(index) * 16;
    let data_offset = Region.loadNat64(note_log.index_region, index_offset);
    let data_length = Nat32.toNat(Region.loadNat32(note_log.index_region, index_offset + 8));
    (data_offset, data_length)
  };

  /// Flip one byte of a stored note. With fix_checksum the frame checksum is recomputed
  /// so the blob still DECODES (corruption surfaces as a downstream semantic error);
  /// without it, decode fails with note-codec:checksum.
  public func corrupt_note_byte(index : Nat, offset : Nat, fix_checksum : Bool) : async () {
    let (base, length) = noteOffset(index);
    if (offset >= length) Runtime.trap("fixture: offset out of range");
    let byte = Region.loadNat8(note_log.data_region, base + Nat64.fromNat(offset));
    Region.storeNat8(note_log.data_region, base + Nat64.fromNat(offset), byte ^ 0x01);
    if (fix_checksum) {
      let payload_length : Nat = length - 48;
      let payload = Region.loadBlob(note_log.data_region, base + 48, payload_length);
      Region.storeBlob(note_log.data_region, base + 16, Sha256.fromBlob(#sha256, payload));
    };
  };

  func setState(which : Text) : StableBlobSet.State {
    if (which == "roots") historical_roots
    else if (which == "nullifiers") spent_nullifiers
    else if (which == "completed-shields") completed_shield_intents
    else Runtime.trap("fixture: unknown set")
  };

  func findSlot(state : StableBlobSet.State, key : Blob) : ?Nat64 {
    let digest = Blob.toArray(Sha256.fromBlob(#sha256, key));
    var value : Nat64 = 0;
    var i : Nat = 0;
    while (i < 8) {
      value := value * 256 + Nat64.fromNat(Nat8.toNat(digest[i]));
      i += 1;
    };
    var index = value % state.capacity;
    var probes : Nat64 = 0;
    while (probes < state.capacity) {
      let offset = state.table_offset + index * 33;
      switch (Region.loadNat8(state.region, offset)) {
        case 0 return null;
        case 1 {
          if (Region.loadBlob(state.region, offset + 1, 32) == key) return ?index;
        };
        case _ Runtime.trap("fixture: corrupt slot tag");
      };
      index := (index + 1) % state.capacity;
      probes += 1;
    };
    null
  };

  /// Overwrite the stored KEY bytes of `key`'s slot (tag stays 1, count unchanged):
  /// the set's own validate stays green while membership of `key` silently vanishes —
  /// the missing-historical-root / missing-nullifier corruption class.
  public func tamper_set_key(which : Text, key : Blob) : async () {
    let state = setState(which);
    switch (findSlot(state, key)) {
      case (?index) {
        let offset = state.table_offset + index * 33 + 1;
        let byte = Region.loadNat8(state.region, offset);
        Region.storeNat8(state.region, offset, byte ^ 0x01);
      };
      case null Runtime.trap("fixture: key not found");
    };
  };

  /// Zero a slot TAG (membership + observed-count corruption: stable-set:observed-count).
  public func zero_set_slot_tag(which : Text, key : Blob) : async () {
    let state = setState(which);
    switch (findSlot(state, key)) {
      case (?index) Region.storeNat8(state.region, state.table_offset + index * 33, 0);
      case null Runtime.trap("fixture: key not found");
    };
  };

  public func set_tree_root_hex(root : Text) : async () {
    let state = currentTree();
    tree_state := ?{ filled = state.filled; root; next_index = state.next_index };
  };

  public func set_last_block_hash(value : ?Blob) : async () { last_block_hash := value };

  public func nth_root(position : Nat) : async Blob { rootFor(position) };
  public func nth_nullifier(index : Nat) : async Blob { deterministicBlob(3, index, 32) };

  /// Populate a VALID pending_unshield (all :588–637 checks satisfiable), optionally
  /// with a corrupted recipient_binding (T2 case 7: stable-state:pending-unshield-binding).
  public shared ({ caller }) func populate_pending_unshield(corrupt_binding : Bool) : async () {
    if (not tokenConfigured()) Runtime.trap("fixture: configure token first");
    let recipient : ICRC2.Account = { owner = caller; subaccount = null };
    let binding = switch (recipientBindingValue(recipient)) {
      case (#ok(value)) value;
      case (#err(message)) Runtime.trap(message);
    };
    let stored_binding = if (corrupt_binding) {
      let bytes = Blob.toArray(binding);
      Blob.fromArray(Array.tabulate<Nat8>(32, func(i) { if (i == 5) bytes[i] ^ 0x01 else bytes[i] }))
    } else binding;
    let amount : Nat64 = 500_000;
    let debit = Nat64.toNat(amount) + transparent_ledger_fee;
    if (debit > pool_value) Runtime.trap("fixture: pool too small");
    let intent = deterministicBlob(7, 1, 32);
    let next_root = rootFor(1_000_000_007);
    pending_unshield := ?{
      intent_id = intent;
      caller;
      output_1 = {
        commitment = deterministicBlob(1, 1_000_000_001, 32);
        ephemeral_key = deterministicBlob(4, 1_000_000_001, 16);
        note_ciphertext = deterministicBlob(5, 1_000_000_001, 112);
      };
      output_2 = {
        commitment = deterministicBlob(1, 1_000_000_002, 32);
        ephemeral_key = deterministicBlob(4, 1_000_000_002, 16);
        note_ciphertext = deterministicBlob(5, 1_000_000_002, 112);
      };
      nullifier_1 = deterministicBlob(6, 1, 32);
      nullifier_2 = deterministicBlob(6, 2, 32);
      transfer_args = {
        from_subaccount = pool_subaccount;
        to = recipient;
        amount = Nat64.toNat(amount);
        fee = ?transparent_ledger_fee;
        memo = ?intent;
        created_at_time = ?Nat64.fromNat(1_784_246_400_000_000_000);
      };
      recipient_binding = stored_binding;
      public_value = amount;
      pool_debit = debit;
      anchor_before = note_root;
      root_after = next_root;
      next_tree = {
        filled = Array.repeat<Text>("00", 32);
        root = blobToHex(next_root);
        next_index = Nat64.fromNat(noteCount() + 2);
      };
      base_epoch = epoch;
      verifier_outcome = "ACCEPT";
      attempts = 1;
      ledger_tip_before = 0;
    };
  };

  public query func fixture_status() : async (Nat, Nat, Nat, Blob, ?Blob) {
    (noteCount(), rootCount(), nullifierCount(), note_root, last_block_hash)
  };

  // ==== NoteAudit parity gate (fast Checker vs verbatim referenceCheck) ====
  transient let parity_checker = NoteAudit.Checker();

  /// Walk notes [0, count) with BOTH per-note paths. Every note must produce the same
  /// outcome: (#ok h, #ok h') with h == h', or (#err m, #err m') with m == m'. Also
  /// measures both paths (instructions, allocation) for the §3.4 before/after record.
  /// Returns #ok((checked, fast_instr, fast_alloc, ref_instr, ref_alloc)).
  public func parity_check(count : Nat) : async Result<(Nat, Nat64, Nat, Nat64, Nat)> {
    var parent_fast : ?Blob = null;
    var parent_ref : ?Blob = null;
    var index : Nat = 0;
    var fast_instr : Nat64 = 0;
    var fast_alloc : Nat = 0;
    var ref_instr : Nat64 = 0;
    var ref_alloc : Nat = 0;
    let end = if (count > noteCount()) noteCount() else count;
    while (index < end) {
      let encoded = switch (StableLog.get(note_log, index)) {
        case (?value) value;
        case null return #err("parity: missing note");
      };
      let a0 = Prim.rts_total_allocation();
      let c0 = Prim.performanceCounter(0);
      let fast = parity_checker.checkNote(encoded, index, parent_fast, historical_roots, spent_nullifiers);
      let c1 = Prim.performanceCounter(0);
      let a1 = Prim.rts_total_allocation();
      let refr = NoteAudit.referenceCheck(encoded, index, parent_ref, historical_roots, spent_nullifiers);
      let c2 = Prim.performanceCounter(0);
      let a2 = Prim.rts_total_allocation();
      fast_instr += c1 - c0;
      fast_alloc += a1 - a0;
      ref_instr += c2 - c1;
      ref_alloc += a2 - a1;
      switch (fast, refr) {
        case (#ok(hf), #ok(hr)) {
          if (hf != hr) return #err("parity: hash mismatch at " # Nat.toText(index));
          parent_fast := ?hf;
          parent_ref := ?hr;
        };
        case (#err(mf), #err(mr)) {
          if (mf != mr) return #err("parity: error mismatch at " # Nat.toText(index) # ": fast=" # mf # " ref=" # mr);
          return #ok((index + 1, fast_instr, fast_alloc, ref_instr, ref_alloc));
        };
        case (#ok(_), #err(mr)) return #err("parity: fast ok / ref err(" # mr # ") at " # Nat.toText(index));
        case (#err(mf), #ok(_)) return #err("parity: fast err(" # mf # ") / ref ok at " # Nat.toText(index));
      };
      index += 1;
    };
    #ok((end, fast_instr, fast_alloc, ref_instr, ref_alloc))
  };
}
