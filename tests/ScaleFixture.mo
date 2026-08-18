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
import PoseidonTree "../src/PoseidonTree";
import StableBlobSet "../src/StableBlobSet";
import StableLog "../src/StableLog";
import Groth16Wire "../src/groth16/Groth16Wire";
import DetectChain "../src/DetectChain";

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

  /// DUAL MODE. The synthetic corpus below is cheap and fine for batteries that never
  /// reach finalize, but its `tree_state` is SELF-CONTRADICTORY: 32 all-zero lanes with
  /// `next_index = noteCount()` and the SHA-256 NOTE-CHAIN hash sitting in the POSEIDON-root field.
  /// No canonicality patch can make that consistent — it is why `finalize-frontier-mismatch` fires
  /// and why green was never reachable by patching values. Real-frontier mode maintains a genuine
  /// Poseidon frontier so lanes, root and next_index actually agree.
  /// TRANSIENT by necessity: these are DERIVED accumulator state, not ledger state. Declared
  /// stable they broke `total-commit` with M0169 — that battery SWAPS BUILDS under the fixture,
  /// so a build carrying them cannot round-trip with one that does not. `tree_state` itself is
  /// stable and is already written before any upgrade, so losing the accumulator across an
  /// upgrade costs nothing: the mode is re-enabled per run, and appends happen before the swap.
  transient var real_frontier : Bool = false;
  transient var frontier_acc : ?PoseidonTree.Frontier = null;
  transient var frontier_root : Nat = 0;
  public shared func set_real_frontier(enabled : Bool) : async () {
    real_frontier := enabled;
    frontier_acc := if (enabled) ?PoseidonTree.emptyFrontier(PoseidonTree.zeroHashes()) else null;
    frontier_root := 0;
  };
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

  /// A CANONICAL field element: the top byte is forced to zero, so the value is below 2^248 and
  /// therefore below the BLS12-381 scalar modulus. Without this the fixture's synthetic roots are
  /// uniformly random 32-byte values, roughly half of which are >= r, and set_tree_frontier
  /// correctly refuses to enable the cross-check over a frontier it cannot parse
  /// (REJECT:root-field / REJECT:frontier-field). That refusal is right; the fixture was wrong.
  /// ONE canonical-field-element generator, shared by every fixture value that reaches
  /// `PoseidonTree.hexToNat` — currently `rootFor` (tag 2) and all three tag-1 commitment sites.
  /// Routed through here rather than patched per-site so a fourth site cannot drift into this hole.
  ///
  /// THIS CODEBASE IS LITTLE-ENDIAN. `blobToHex` preserves byte order, and `hexToNat`/`natToHex`
  /// accumulate with `shift *= 256` from the first byte, so **byte 0 is the LEAST significant and
  /// byte 31 is the MOST significant**. Byte 31 is therefore the one that must be zeroed. The
  /// previous comment here said "top byte" while zeroing byte 0 — which bounded nothing and left
  /// roughly 55% of these values >= Fr.P, since Fr.P = 0x73eda753... and the MSB stayed a raw
  /// SHA-256 byte. That was the defect.
  ///
  /// CAVEAT, and it must not be read away: zeroing byte 31 yields values below 2^248, which is a
  /// strict SUBSET of canonical. This BOUNDS the fixture; it does NOT exercise the near-modulus
  /// boundary between 2^248 and Fr.P. Nobody may read "all fixture values are canonical" as
  /// "canonicality is tested" — no fixture value here ever approaches r.
  ///
  /// Why this is fidelity and not a weakened test: a real commitment is a Poseidon output and is
  /// canonical BY CONSTRUCTION, so a fixture emitting out-of-range commitments was modelling state
  /// the product cannot produce.
  func canonicalBlob(tag : Nat8, index : Nat) : Blob {
    let bytes = Blob.toArray(deterministicBlob(tag, index, 32));
    Blob.fromArray(Array.tabulate<Nat8>(32, func(i) { if (i == 31) 0 else bytes[i] }))
  };

  func rootFor(position : Nat) : Blob { canonicalBlob(2, position) };

  /// A zero lane, canonical by construction.
  func canonicalLane() : Text { "0000000000000000000000000000000000000000000000000000000000000000" };

  /// Append `count` valid chained notes. Call repeatedly (paged; ~2k per call is well
  /// inside the 40B budget at the measured 1.5M instr/note append cost). Keeps
  /// note_root/tree_state/pool_value consistent so the state validates at every prefix.
  /// Append `count` notes whose note_ciphertext is `ct_bytes` long, so a battery can build a
  /// log of abnormally large notes and measure how much work one audit chunk takes on. The
  /// ledger applies no upper bound to note_ciphertext on ingress, so this is representative of
  /// what a depositor can actually store, not a synthetic impossibility.
  public func bulk_append_sized(count : Nat, ct_bytes : Nat) : async Nat {
    await appendMany(count, ct_bytes)
  };

  public func bulk_append(count : Nat) : async Nat { await appendMany(count, 112) };

  // Instruction cost of hexToBytes over a caller-supplied Text, measured directly.
  // Wall-clock cannot resolve this -- a ~1.2s consensus round swamps the decode -- and arguing
  // instruction cost from a duration is the proxy substitution
  // docs/thresholds/THRESHOLDS-budget-guard.md F-3 forbids.
  // Calls the PRODUCTION function; adds no stable variable, so the upgrade gap does not bite.
  // Instruction cost of the PRODUCTION vk preparation: `configure` does TWO of these in one
  // message with no budget check. No stable variable.
  // boundaryProofAt -> merkleProof, unbounded in boundary count.
  // Transient state only -- built fresh per call, so NO stable variable is added.
  public func measure_boundary_proof(boundaries : Nat) : async (Nat64, Nat64, Bool) {
    let st = DetectChain.newState();
    let fr = DetectChain.emptyFrontier();
    var i = 0;
    let cBuild = Prim.performanceCounter(0);
    while (i < boundaries) {
      DetectChain.append(st, fr, i, [1, 2, 3]);
      i += 1;
    };
    let cBuilt = Prim.performanceCounter(0);
    let proof = DetectChain.boundaryProofAt(st, 0);
    let cProof = Prim.performanceCounter(0);
    (cBuilt - cBuild, cProof - cBuilt, proof != null)
  };

  public func measure_vk_prepare(vkHex : Text) : async (Nat64, Bool) {
    let c0 = Prim.performanceCounter(0);
    let prepared = Groth16Wire.parseAndPrepareVk(vkHex);
    let c1 = Prim.performanceCounter(0);
    (c1 - c0, prepared != null)
  };

  public func measure_hex_decode(hex : Text) : async (Nat64, Nat) {
    let c0 = Prim.performanceCounter(0);
    let decoded = Groth16Wire.hexToBytes(hex);
    let c1 = Prim.performanceCounter(0);
    (c1 - c0, switch (decoded) { case (?b) b.size(); case null 0 })
  };

  func appendMany(count : Nat, ct_bytes : Nat) : async Nat {
    // Computed once per call, not per note: zeroHashes() is itself 32 Poseidon compressions.
    let frontier_zeros : [Nat] = if (real_frontier) PoseidonTree.zeroHashes() else [];
    var i : Nat = 0;
    while (i < count) {
      let position = noteCount();
      let isTransfer = position % 3 != 0;
      let nullifiers : [Blob] = if (isTransfer) {
        [deterministicBlob(3, position * 2, 32), deterministicBlob(3, position * 2 + 1, 32)]
      } else { [] };
      // In real-frontier mode the note's root IS the frontier root after this
      // commitment is appended, so note_root, historical_roots, the block chain and the
      // derived tree_state describe ONE tree. The ledger's bounded postupgrade walk requires
      // exactly that: hexToBlob(tree_state.root) == note_root (stable-state:tree-root) and
      // lastBlock.note_root_after == note_root (stable-state:tail-root) — the synthetic
      // rootFor chain satisfies neither once tree_state is derived from the frontier.
      let root = if (real_frontier) {
        switch (frontier_acc, PoseidonTree.blobToNat(canonicalBlob(1, position))) {
          case (?f, ?leaf) {
            let (nf, r) = PoseidonTree.append(f, frontier_zeros, leaf);
            frontier_acc := ?nf;
            frontier_root := r;
            switch (hexToBlob(PoseidonTree.natToHex(r))) {
              case (?value) value;
              case null Runtime.trap("fixture: frontier root hex");
            };
          };
          case _ Runtime.trap("fixture: real frontier unavailable");
        };
      } else rootFor(position);
      let block : NoteCodec.ShieldedNoteBlock = {
        btype = "zknote1";
        phash = last_block_hash;
        encoding_version = ENCODING_VERSION;
        note_position = position;
        commitment = canonicalBlob(1, position);
        ephemeral_key = deterministicBlob(4, position, 16);
        note_ciphertext = deterministicBlob(5, position, ct_bytes);
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
    if (real_frontier) {
      // Derive lanes, root and next_index from the SAME frontier, so they agree by construction.
      switch (frontier_acc) {
        case (?f) {
          tree_state := ?{
            filled = Array.tabulate<Text>(32, func(i) { PoseidonTree.natToHex(f.filled[i]) });
            root = PoseidonTree.natToHex(frontier_root);
            next_index = f.nextIndex;
          };
        };
        case null {};
      };
    } else {
      tree_state := ?{
        filled = Array.repeat<Text>(canonicalLane(), 32);
        root = blobToHex(note_root);
        next_index = Nat64.fromNat(noteCount());
      };
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
        filled = Array.repeat<Text>(canonicalLane(), 32);
        root = blobToHex(empty);
        next_index = 0;
      };
    };
  };

  // The withdraw vector's fee (5298) is a PROOF PUBLIC INPUT and cannot be changed,
  // so the pool's transparent_ledger_fee must be brought to it or confidential_transfer refuses
  // REJECT:unshield-fee-below-token-fee (Main.mo:4069) before the verifier is ever called.
  // Deliberately NOT a new stable variable -- transparent_ledger_fee already exists. Adding stable
  // state here is what broke the layout-1 -> layout-2-unfixed upgrade in a33d751.
  public func set_transparent_fee(value : Nat) : async () { transparent_ledger_fee := value };

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
    else if (which == "completed-unshields") completed_unshield_intents
    else Runtime.trap("fixture: unknown set")
  };

  /// Stride of the ACTIVE table, read straight out of the region header rather than from the
  /// module. Layout 1 never wrote offset 48, so zero there means 33-byte slots. Reading the raw
  /// header is what lets this one fixture source compile against BOTH the layout-1 and the
  /// layout-2 module, which is the whole point: the migration battery builds two wasms from this
  /// same file and the only thing that differs between them is src/StableBlobSet.mo.
  func headerStride(state : StableBlobSet.State) : Nat64 {
    let stored = Region.loadNat64(state.region, 48);
    if (stored == 0) 33 else stored
  };

  func findSlot(state : StableBlobSet.State, key : Blob) : ?Nat64 {
    let stride = headerStride(state);
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
      let offset = state.table_offset + index * stride;
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
        let offset = state.table_offset + index * headerStride(state) + 1;
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
      case (?index) Region.storeNat8(state.region, state.table_offset + index * headerStride(state), 0);
      case null Runtime.trap("fixture: key not found");
    };
  };

  // ==== StableBlobSet layout / migration probes ================================================
  //
  // These drive a set DIRECTLY so that a layout change is observed rather than inferred from
  // ledger behaviour, and they deliberately call nothing the layout-1 module lacked.

  func migrationKey(index : Nat) : Blob { deterministicBlob(9, index, 32) };

  /// (version as WRITTEN in the header, stride, capacity, entry_count, table_offset, next_offset).
  /// The version is read from the region, not from the module's own LAYOUT_VERSION constant: what
  /// matters after an upgrade is what the bytes say, not what the new code would have written.
  public query func set_layout(which : Text) : async (Nat32, Nat64, Nat64, Nat64, Nat64, Nat64) {
    let state = setState(which);
    (
      Region.loadNat32(state.region, 8),
      headerStride(state),
      state.capacity,
      state.entry_count,
      state.table_offset,
      state.next_offset,
    )
  };

  /// Stride implied by the table's own geometry, derived independently of the header field.
  /// Disagreement with set_layout's stride means the header and the allocation have stopped
  /// describing the same table.
  public query func set_geometry_stride(which : Text) : async Nat64 {
    let state = setState(which);
    if (state.capacity == 0) 0 else (state.next_offset - state.table_offset) / state.capacity
  };

  public query func set_contains_key(which : Text, key : Blob) : async Bool {
    StableBlobSet.contains(setState(which), key)
  };

  /// How many of the deterministic migration keys [from, from+count) the set reports present.
  public query func set_contains_range(which : Text, from : Nat, count : Nat) : async Nat {
    let state = setState(which);
    var present = 0;
    var i = 0;
    while (i < count) {
      if (StableBlobSet.contains(state, migrationKey(from + i))) present += 1;
      i += 1;
    };
    present
  };

  public func set_put_range(which : Text, from : Nat, count : Nat) : async Result<Nat> {
    let state = setState(which);
    var added = 0;
    var i = 0;
    while (i < count) {
      switch (StableBlobSet.put(state, migrationKey(from + i))) {
        case (#ok(true)) added += 1;
        case (#ok(false)) {};
        case (#err(message)) return #err(message);
      };
      i += 1;
    };
    #ok(added)
  };

  /// Drive ONE chunk of the SAME `StableBlobSet.compactStep` the ledger's product entry
  /// `compact_set(#roots, budget)` (Main.mo:1608) runs — that method is a thin admin-gated wrapper
  /// over exactly this call. Exposed on the fixture so the reclamation can be measured on a set grown
  /// cheaply with `set_put_range`, without staging the thousands of real notes an in-ledger root
  /// population would need. Returns true when the relocation is complete.
  public func set_compact(which : Text, budget : Nat64) : async Bool {
    StableBlobSet.compactStep(setState(which), budget)
  };

  /// Put a range and then trap, so a message that performed a GROW — including the layout-1 to
  /// layout-2 conversion — fails after the conversion has already happened inside it.
  ///
  /// This is the lever for the interrupted-migration case, and it is used because the obvious ones
  /// do not bite: --wasm-memory-limit caps the Wasm heap, not the Region's stable memory, so a
  /// capped canister converts happily; and making the grow exceed the 40e9 instruction ceiling on
  /// its own needs a table around 2^20 entries, which is Track E's measurement, not a unit lever.
  /// What is actually under test is the IC's message atomicity: whatever the cause, a failed
  /// converting message must leave every committed key readable at the old layout.
  public func set_put_range_then_trap(which : Text, from : Nat, count : Nat) : async () {
    let state = setState(which);
    var i = 0;
    while (i < count) {
      switch (StableBlobSet.put(state, migrationKey(from + i))) {
        case (#err(message)) Runtime.trap("fixture: " # message);
        case (_) {};
      };
      i += 1;
    };
    Runtime.trap("TEST_ONLY:interrupted-migration");
  };

  /// Put keys [from, from+count) and report what the CALL cost, with the capacity either side so a
  /// grow can be attributed to it. Returns
  ///   (instructions, allocated bytes, capacity before, capacity after, entry_count, stride).
  /// Called with count = 1 immediately below a grow boundary, this is the cost of that grow.
  public func set_put_measured(which : Text, from : Nat, count : Nat)
    : async (Nat64, Nat, Nat64, Nat64, Nat64, Nat64) {
    let state = setState(which);
    let capacity_before = state.capacity;
    let alloc_before = Prim.rts_total_allocation();
    let counter_before = Prim.performanceCounter(0);
    var i = 0;
    while (i < count) {
      switch (StableBlobSet.put(state, migrationKey(from + i))) {
        case (#err(message)) Runtime.trap("fixture: " # message);
        case (_) {};
      };
      i += 1;
    };
    let counter_after = Prim.performanceCounter(0);
    let alloc_after = Prim.rts_total_allocation();
    (
      counter_after - counter_before,
      alloc_after - alloc_before,
      capacity_before,
      state.capacity,
      state.entry_count,
      headerStride(state),
    )
  };

  /// (window active, cursor, forced completions), read STRAIGHT OUT OF THE HEADER rather than
  /// through the module. That is what lets this file still compile against the frozen layout-1
  /// module, where all three read zero — which is the correct answer there, since a layout-1 set
  /// has no window.
  public query func set_window(which : Text) : async (Bool, Nat64, Nat64) {
    let state = setState(which);
    let word = Region.loadNat64(state.region, 56);
    let active = (word & 0x8000_0000_0000_0000) != 0;
    let forced = Nat64.fromNat(Nat32.toNat(Region.loadNat32(state.region, 12)));
    (active, word & 0x7fff_ffff_ffff_ffff, forced)
  };

  /// Put `count` keys measuring EVERY put separately, and report the maxima. Used by the rescue
  /// battery, where what matters is that no single message is expensive — not that the total is
  /// small, which it cannot be.
  /// Returns (max_instr, max_alloc, sum_instr, entries, window_active, cursor).
  public func set_put_walk(which : Text, from : Nat, count : Nat)
    : async (Nat64, Nat, Nat64, Nat64, Bool, Nat64) {
    let state = setState(which);
    var max_instr : Nat64 = 0;
    var max_alloc : Nat = 0;
    var sum_instr : Nat64 = 0;
    var i = 0;
    while (i < count) {
      let a0 = Prim.rts_total_allocation();
      let c0 = Prim.performanceCounter(0);
      switch (StableBlobSet.put(state, migrationKey(from + i))) {
        case (#err(message)) Runtime.trap("fixture: " # message);
        case (_) {};
      };
      let instr = Prim.performanceCounter(0) - c0;
      let alloc = Prim.rts_total_allocation() - a0;
      if (instr > max_instr) max_instr := instr;
      if (alloc > max_alloc) max_alloc := alloc;
      sum_instr += instr;
      i += 1;
    };
    let word = Region.loadNat64(state.region, 56);
    (max_instr, max_alloc, sum_instr, state.entry_count, (word & 0x8000_0000_0000_0000) != 0,
     word & 0x7fff_ffff_ffff_ffff)
  };

  // ==== PREPARE staging: the conditions PREPARE must reject BEFORE any money moves =============
  // Region-free and module-neutral, so this file still compiles against the frozen layout-1 module.

  /// Put an arbitrary key into a set, so a test can pre-spend a nullifier or pre-complete an intent.
  public func set_insert_key(which : Text, key : Blob) : async Result<Bool> {
    StableBlobSet.put(setState(which), key)
  };

  /// Force the pool balance, so a test can make pool_debit exceed it.
  public func set_pool_value(value : Nat) : async () { pool_value := value };

  /// (intent_id, nullifier_1, nullifier_2, pool_debit) of the pending unshield, so a test can stage
  /// each PREPARE rejection against the intent that is actually in flight.
  public query func pending_ids() : async ?(Blob, Blob, Blob, Nat) {
    switch (pending_unshield) {
      case (?p) ?(p.intent_id, p.nullifier_1, p.nullifier_2, p.pool_debit);
      case null null;
    }
  };

  /// (data-region capacity, data offset, bytes per note) — what a caller needs to fill the note log to
  /// one note-pair below its region boundary.
  public query func log_geometry() : async (Nat, Nat, Nat) {
    let (data, _index) = StableLog.regionBytes(note_log);
    let used = StableLog.dataSize(note_log);
    let n = noteCount();
    (data, used, if (n == 0) 1 else used / n)
  };

  /// Rewrite tree_state as a CANONICAL frontier: every lane and the root a valid field element.
  /// configure_fixture's synthetic state uses "00" lanes and a random 32-byte root, which
  /// set_tree_frontier correctly refuses with REJECT:frontier-field — it validates that the live
  /// wire frontier parses before it will turn the cross-check on. Test-only, and separate from
  /// configure_fixture so no existing battery's staging changes.
  public func configure_frontier_ready() : async () {
    let zero = "0000000000000000000000000000000000000000000000000000000000000000";
    let root = Blob.fromArray(Array.repeat<Nat8>(0, 32));
    note_root := root;
    ignore StableBlobSet.put(historical_roots, root);
    tree_state := ?{
      filled = Array.repeat<Text>(zero, 32);
      root = zero;
      next_index = Nat64.fromNat(noteCount());
    };
  };

  public query func set_validate(which : Text) : async Result<()> { StableBlobSet.validate(setState(which)) };
  public query func set_digest(which : Text) : async Blob { StableBlobSet.digest(setState(which)) };
  public query func set_size(which : Text) : async Nat { StableBlobSet.size(setState(which)) };

  /// Quarantine-exposure staging. `set_tree_root_hex` alone changes only `tree_state.root`, so the
  /// ledger's `validateStableStateBounded` trips `stable-state:tree-root` (the hex no longer
  /// matches `note_root`) and `postupgrade` TRAPS before the quarantine scan ever runs. Setting
  /// BOTH consistently is what reaches that scan: a root that is well-formed hex and matches
  /// `note_root`, but is NON-CANONICAL as a field element, passes validation and is then collected
  /// as an offender -- which is the state `quarantine_status` publishes.
  /// Separate method rather than a change to `set_tree_root_hex`, so no existing battery moves.
  public func set_note_root_hex(root : Text) : async Bool {
    switch (hexToBlob(root)) {
      case (?blob) {
        let state = currentTree();
        tree_state := ?{ filled = state.filled; root; next_index = state.next_index };
        note_root := blob;
        true
      };
      case null false;
    };
  };

  public func set_tree_root_hex(root : Text) : async () {
    let state = currentTree();
    tree_state := ?{ filled = state.filled; root; next_index = state.next_index };
  };

  public func set_last_block_hash(value : ?Blob) : async () { last_block_hash := value };

  public func nth_root(position : Nat) : async Blob { rootFor(position) };
  public func nth_nullifier(index : Nat) : async Blob { deterministicBlob(3, index, 32) };

  /// A created_at_time that is deliberately OUTSIDE the token ledger's 24h window.
  ///
  /// The #TooOld latch battery needs a pending transfer the token ledger will refuse as expired,
  /// and this constant supplies one. Every other test wants a transfer that can actually land, and
  /// stopped getting one the moment wall-clock time moved past the constant: the payout silently
  /// came back #TooOld, the crash-after-token staging never staged anything, and the failure looked
  /// like a test result. Use populate_pending_unshield_now for anything that needs the transfer to
  /// succeed.
  /// A function, not an actor-level `let`: in a persistent actor a top-level binding IS a stable
  /// variable, and adding one makes every wasm built before it un-upgradeable from (M0169).
  func expiredCreatedAt() : Nat64 { 1_784_246_400_000_000_000 };

  /// Populate a VALID pending_unshield (all :588–637 checks satisfiable), optionally
  /// with a corrupted recipient_binding (T2 case 7: stable-state:pending-unshield-binding),
  /// with a transfer whose created_at_time is already outside the token ledger's window.
  public shared ({ caller }) func populate_pending_unshield(corrupt_binding : Bool) : async () {
    populatePendingUnshield(caller, corrupt_binding, expiredCreatedAt());
  };

  /// The same, with a created_at_time of NOW, so the transfer is inside the window and can land.
  public shared ({ caller }) func populate_pending_unshield_now(corrupt_binding : Bool) : async () {
    populatePendingUnshield(caller, corrupt_binding, Prim.time());
  };

  func populatePendingUnshield(caller : Principal, corrupt_binding : Bool, created_at : Nat64) {
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
    let commitment_1 = canonicalBlob(1, 1_000_000_001);
    let commitment_2 = canonicalBlob(1, 1_000_000_002);
    // The ledger's finalize recomputes frontierAppend(currentTree(), [c1, c2]) and
    // compares its root to root_after (REJECT:finalize-frontier-mismatch on disagreement), so in
    // real-frontier mode root_after/next_tree must be the genuine post-append frontier — computed
    // here from a LOCAL copy; the live accumulator stays pre-transition, exactly like the pool's
    // tree_state. Synthetic mode keeps the placeholder chain values.
    let (next_root, next_tree_value) = if (real_frontier) {
      switch (frontier_acc, PoseidonTree.blobToNat(commitment_1), PoseidonTree.blobToNat(commitment_2)) {
        case (?f, ?leaf_1, ?leaf_2) {
          let zeros = PoseidonTree.zeroHashes();
          let (f1, _) = PoseidonTree.append(f, zeros, leaf_1);
          let (f2, r2) = PoseidonTree.append(f1, zeros, leaf_2);
          let root_blob = switch (hexToBlob(PoseidonTree.natToHex(r2))) {
            case (?value) value;
            case null Runtime.trap("fixture: frontier root hex");
          };
          (root_blob, {
            filled = Array.tabulate<Text>(32, func(i) { PoseidonTree.natToHex(f2.filled[i]) });
            root = PoseidonTree.natToHex(r2);
            next_index = f2.nextIndex;
          });
        };
        case _ Runtime.trap("fixture: real frontier unavailable");
      };
    } else {
      let synthetic = rootFor(1_000_000_007);
      (synthetic, {
        filled = Array.repeat<Text>(canonicalLane(), 32);
        root = blobToHex(synthetic);
        next_index = Nat64.fromNat(noteCount() + 2);
      });
    };
    pending_unshield := ?{
      intent_id = intent;
      caller;
      output_1 = {
        commitment = commitment_1;
        ephemeral_key = deterministicBlob(4, 1_000_000_001, 16);
        note_ciphertext = deterministicBlob(5, 1_000_000_001, 112);
      };
      output_2 = {
        commitment = commitment_2;
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
        created_at_time = ?created_at;
      };
      recipient_binding = stored_binding;
      public_value = amount;
      pool_debit = debit;
      anchor_before = note_root;
      root_after = next_root;
      next_tree = next_tree_value;
      base_epoch = epoch;
      verifier_outcome = "ACCEPT";
      attempts = 1;
      ledger_tip_before = 0;
    };
  };

  /// Finalize cross-check staging: corrupt the parked intent's root_after by one low-order byte,
  /// keeping the pending INTERNALLY coherent — next_tree.root must round-trip to root_after or
  /// the ledger's postupgrade walk refuses the upgrade with stable-state:pending-unshield-root.
  /// Byte 0 is the LEAST significant in this codebase, so the flip stays canonical whenever the
  /// root was; byte 31 is untouched. Returns the corrupted root so the battery can watch it
  /// enter (or be refused from) historical_roots across the upgrade. This is the staging A7
  /// showed no product fault injection can produce: the ledger settles every inferable token
  /// outcome, so the pending is STAGED in stable state rather than stranded through the API.
  public func test_corrupt_pending_root_after() : async Blob {
    switch (pending_unshield) {
      case (?p) {
        let bytes = Blob.toArray(p.root_after);
        let corrupt = Blob.fromArray(Array.tabulate<Nat8>(bytes.size(), func(i) {
          if (i == 0) bytes[i] ^ 0x01 else bytes[i]
        }));
        pending_unshield := ?{ p with root_after = corrupt;
                               next_tree = { filled = p.next_tree.filled;
                                             root = blobToHex(corrupt);
                                             next_index = p.next_tree.next_index } };
        corrupt
      };
      case null Runtime.trap("fixture: no pending unshield to corrupt");
    }
  };

  /// Arm the ledger's crash-after-token hook from the FIXTURE side, before the upgrade that
  /// installs the ledger wasm.
  ///
  /// The production arming entry, test_arm_fail_after_token_once, refuses while an intent is
  /// pending ("REJECT:pending-token-mutation"). A recovery path runs *because* an intent is
  /// pending, so through that entry arming the fault and reaching the code it targets are mutually
  /// exclusive — the paths that exist specifically to survive a crash were the only paths that
  /// could not be crash-tested. Setting the stable variable here, before the upgrade, lets the
  /// ledger wake already armed AND already holding a pending intent. The production guard is
  /// untouched: this is fixture code and never ships.
  public func test_preset_fail_after_token(value : Bool) : async () {
    test_fail_after_token_once := value;
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
