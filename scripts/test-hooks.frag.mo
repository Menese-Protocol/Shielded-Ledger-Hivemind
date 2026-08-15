  // Admin-gated corruption primitives for T3 (fail-closed drill on a RUNNING instance).
  // Injected by scripts/build-test-wasm.sh into zk_ledger_test.wasm ONLY — the shipped
  // zk_ledger.wasm never contains this block (additive-only diff proven at build time).
  // Deliberately NOT guard-checked: un-corrupting and re-auditing while guarded is the
  // recovery path under test.

  func __testNoteOffset(index : Nat) : (Nat64, Nat) {
    let index_offset : Nat64 = 32 + Nat64.fromNat(index) * 16;
    let data_offset = Prim.regionLoadNat64(note_log.index_region, index_offset);
    let data_length = Nat32.toNat(Prim.regionLoadNat32(note_log.index_region, index_offset + 8));
    (data_offset, data_length)
  };

  public shared ({ caller }) func test_corrupt_note_byte(index : Nat, offset : Nat, fix_checksum : Bool) : async () {
    if (not isAdministrator(caller)) Runtime.trap("test-hook:not-administrator");
    let (base, length) = __testNoteOffset(index);
    if (offset >= length) Runtime.trap("test-hook: offset out of range");
    let byte = Prim.regionLoadNat8(note_log.data_region, base + Nat64.fromNat(offset));
    Prim.regionStoreNat8(note_log.data_region, base + Nat64.fromNat(offset), byte ^ 0x01);
    if (fix_checksum) {
      let payload_length : Nat = length - 48;
      let payload = Prim.regionLoadBlob(note_log.data_region, base + 48, payload_length);
      Prim.regionStoreBlob(note_log.data_region, base + 16, Sha256.fromBlob(#sha256, payload));
    };
  };

  func __testSetOf(which : Text) : StableBlobSet.State {
    if (which == "roots") historical_roots
    else if (which == "nullifiers") spent_nullifiers
    else if (which == "completed-shields") completed_shield_intents
    else Runtime.trap("test-hook: unknown set")
  };

  func __testFindSlot(state : StableBlobSet.State, key : Blob) : ?Nat64 {
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
      switch (Prim.regionLoadNat8(state.region, offset)) {
        case 0 return null;
        case 1 {
          if (Prim.regionLoadBlob(state.region, offset + 1, 32) == key) return ?index;
        };
        case _ Runtime.trap("test-hook: corrupt slot tag");
      };
      index := (index + 1) % state.capacity;
      probes += 1;
    };
    null
  };

  public shared ({ caller }) func test_tamper_set_key(which : Text, key : Blob) : async () {
    if (not isAdministrator(caller)) Runtime.trap("test-hook:not-administrator");
    let state = __testSetOf(which);
    switch (__testFindSlot(state, key)) {
      case (?index) {
        let offset = state.table_offset + index * 33 + 1;
        let byte = Prim.regionLoadNat8(state.region, offset);
        Prim.regionStoreNat8(state.region, offset, byte ^ 0x01);
      };
      case null Runtime.trap("test-hook: key not found");
    };
  };

  public shared ({ caller }) func test_zero_set_slot_tag(which : Text, key : Blob) : async () {
    if (not isAdministrator(caller)) Runtime.trap("test-hook:not-administrator");
    let state = __testSetOf(which);
    switch (__testFindSlot(state, key)) {
      case (?index) Prim.regionStoreNat8(state.region, state.table_offset + index * 33, 0);
      case null Runtime.trap("test-hook: key not found");
    };
  };

  public shared ({ caller }) func test_set_tree_root_hex(root : Text) : async () {
    if (not isAdministrator(caller)) Runtime.trap("test-hook:not-administrator");
    let state = currentTree();
    tree_state := ?{ filled = state.filled; root; next_index = state.next_index };
  };

  public shared ({ caller }) func test_set_last_block_hash(value : ?Blob) : async () {
    if (not isAdministrator(caller)) Runtime.trap("test-hook:not-administrator");
    last_block_hash := value;
  };

  public query func test_nth_note_root(index : Nat) : async Blob {
    switch (decodeBlockAt(index)) {
      case (#ok(block)) block.note_root_after;
      case (#err(message)) Runtime.trap(message);
    }
  };

  public query func test_nth_note_nullifier(index : Nat) : async Blob {
    switch (decodeBlockAt(index)) {
      case (#ok(block)) {
        if (block.nullifiers.size() == 0) Runtime.trap("test-hook: no nullifiers");
        block.nullifiers[0]
      };
      case (#err(message)) Runtime.trap(message);
    }
  };

  // ===== §9 live-seam injections (hook-wasm ONLY; never in the shipped zk_ledger.wasm) =====

  // Seam "during certified-state update": perform the REAL certified-data update, then trap.
  // The IC rolls the message back atomically, so the certified data and all state must be
  // byte-identical afterward — the battery asserts exactly that (>=25 injections).
  public shared ({ caller }) func test_trap_during_cert_update() : async () {
    if (not isAdministrator(caller)) Runtime.trap("test-hook:not-administrator");
    refreshCertification();
    Runtime.trap("TEST_ONLY:fail-during-cert-update");
  };

  // Planted double-mint: inflate pool_value without any custody backing. The solvency
  // invariant (custody == pool_value) must break on the next sweep — the §9 teeth.
  public shared ({ caller }) func test_force_double_credit(amount : Nat) : async () {
    if (not isAdministrator(caller)) Runtime.trap("test-hook:not-administrator");
    pool_value += amount;
  };

  // Read-back of pool_value for the seam battery's solvency sweep.
  public query func test_pool_value() : async Nat { pool_value };

  // ===== detect-chain corruption primitives (AC-2 audit teeth; hook-wasm ONLY) =====
  // One primitive per audited field: chain tip, cached root, covered counter, note
  // counter, and one boundary leaf. Each must turn the background audit RED with its
  // exact `detect-chain:*` code; `detect_chain_rebuild` + `restart_audit` is the
  // recovery path under test.
  public shared ({ caller }) func test_detect_corrupt(field : Text) : async () {
    if (not isAdministrator(caller)) Runtime.trap("test-hook:not-administrator");
    func flip(b : Blob) : Blob {
      let bytes = Blob.toVarArray(b);
      bytes[0] := bytes[0] ^ 0x01;
      Blob.fromVarArray(bytes)
    };
    if (field == "chain") { detect_chain_state.chain := flip(detect_chain_state.chain) }
    else if (field == "root") { detect_chain_state.root := flip(detect_chain_state.root) }
    else if (field == "covered") { detect_chain_state.covered += 1 }
    else if (field == "count") { detect_chain_state.count += 1 }
    else if (field == "boundary") {
      switch (List.get(detect_chain_state.boundaries, 0)) {
        case (?leaf) List.put(detect_chain_state.boundaries, 0, flip(leaf));
        case null Runtime.trap("test-hook: no boundary to corrupt");
      };
    } else Runtime.trap("test-hook: unknown detect field");
  };

  // Wipe the in-memory anchor entirely (recovery-from-scratch drill: the rebuild must
  // reconstruct the identical anchor from the note log alone).
  public shared ({ caller }) func test_detect_wipe() : async () {
    if (not isAdministrator(caller)) Runtime.trap("test-hook:not-administrator");
    detect_chain_state.chain := Blob.fromArray(Array.repeat<Nat8>(0, 32));
    detect_chain_state.root := Blob.fromArray(Array.repeat<Nat8>(0, 32));
    detect_chain_state.covered := 0;
    detect_chain_state.count := 0;
    List.clear(detect_chain_state.boundaries);
    List.clear(detect_chain_frontier.stack);
  };

  // Anchor read-back for the battery's byte-compare (query; hook wasm only).
  public query func test_detect_anchor() : async { root : Blob; c_tip : Blob; note_count : Nat; covered : Nat; boundary_count : Nat } {
    {
      root = detect_chain_state.root;
      c_tip = detect_chain_state.chain;
      note_count = detect_chain_state.count;
      covered = detect_chain_state.covered;
      boundary_count = List.size(detect_chain_state.boundaries);
    }
  };

  // Decode-cost measurement (hook-wasm ONLY): call the PRODUCT hexToBlob and report instructions, so a
  // battery can show the unbounded decode (RED) vs the bounded reject (GREEN) on the real function.
  public func test_measure_hex_to_blob(hex : Text) : async (Nat64, Nat) {
    let c0 = Prim.performanceCounter(0);
    let r = hexToBlob(hex);
    let c1 = Prim.performanceCounter(0);
    (c1 - c0, switch (r) { case (?b) b.size(); case null 999_999 })
  };

  // ==== the three formerly-sealed arming entries (D-3, option (c)) ====
  //
  // These used to live in src/Main.mo behind a one-way runtime seal that DEFAULTED OPEN, so the
  // shipped binary carried them and an auditor checking README's "must not exist" found them
  // present and callable. They are now excluded at build time, exactly like the strictly more
  // dangerous primitives above, and the seal is gone with them: a module hash anyone can check
  // replaces a boolean the canister asserted about itself. CWE-489 places the mitigation at the
  // Build/Distribution phase for this reason.
  //
  // The administrator gate is RETAINED — build-time exclusion is the outer control, not a licence
  // to drop the inner one. The seal check is deliberately NOT carried over: in this build there is
  // no seal to consult, and a hook that consults a flag no binary sets is theatre.
  //
  // The state they arm is declared in src/Main.mo, because its consumption sites are inside
  // product function bodies that an additive-only fragment cannot reach into. Nothing in the
  // shipped binary can write either flag.

  /// Arm `count` forced PIR-fold traps. Arming with 0 disarms. Touches ONLY test state, never
  /// ledger state, so it carries no guard check — a battery must be able to disarm while degraded.
  public shared ({ caller }) func test_arm_pir2_fold_trap(count : Nat) : async Result<()> {
    if (not isAdministrator(caller)) return #err("REJECT:not-administrator");
    test_pir2_fold_trap_remaining := count;
    #ok(())
  };

  /// Deliberately corrupt `len` bytes of shard `shard`'s hint region at byte `offset` (XOR 0xFF),
  /// bounded to the shard's span — the repairability injection; the repair path must restore
  /// byte-identity from the authoritative log.
  public shared ({ caller }) func test_pir2_corrupt_hint(shard : Nat, offset : Nat, len : Nat) : async Result<()> {
    if (not isAdministrator(caller)) return #err("REJECT:not-administrator");
    if (not pir2_state.enabled) return #err("REJECT:pir2-not-enabled");
    let g = Pir2.geometry(pir2_state.shard_size);
    let total = Nat64.toNat(Pir2.hintBytesPerShard(g));
    if (offset >= total or len == 0 or offset + len > total) return #err("REJECT:corrupt-range");
    let base = Pir2.hRowOffset(g, shard, 0) + Nat64.fromNat(offset);
    let bytes = Blob.toArray(Region.loadBlob(pir2_state.h_region, base, len));
    let flipped = Array.tabulate<Nat8>(len, func(i) { bytes[i] ^ 0xFF });
    Region.storeBlob(pir2_state.h_region, base, Blob.fromArray(flipped));
    #ok(())
  };

  /// Force the next payout to fail AFTER the token transfer and before the finalize commit.
  /// Refused while an intent is in flight, which is why the batteries stage the flag from the
  /// fixture side instead of calling this.
  public shared ({ caller }) func test_arm_fail_after_token_once() : async Result<()> {
    switch (guardRejection()) { case (?message) return #err(message); case null {} };
    if (not isAdministrator(caller)) return #err("REJECT:not-administrator");
    if (pending_shield != null or pending_unshield != null) return #err("REJECT:pending-token-mutation");
    test_fail_after_token_once := true;
    #ok(())
  };
