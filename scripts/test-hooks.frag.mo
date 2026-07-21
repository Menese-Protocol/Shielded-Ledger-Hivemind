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
