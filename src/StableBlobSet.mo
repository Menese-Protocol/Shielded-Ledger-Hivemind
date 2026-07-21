/// Growable Region-backed set for fixed-width 32-byte keys.
///
/// The active open-addressed table is append-migrated inside one Region. Old tables are retained,
/// so a committed key is never deleted during growth and an interrupted update rolls back with the
/// canister message. Header fields are cross-checked after upgrade.

import Blob "mo:core/Blob";
import Nat "mo:core/Nat";
import Nat32 "mo:core/Nat32";
import Nat64 "mo:core/Nat64";
import Nat8 "mo:core/Nat8";
import Region "mo:core/Region";
import Runtime "mo:core/Runtime";
import Sha256 "mo:sha2/Sha256";

module {
  public type Result<T> = { #ok : T; #err : Text };

  public type State = {
    region : Region.Region;
    var table_offset : Nat64;
    var capacity : Nat64;
    var entry_count : Nat64;
    var next_offset : Nat64;
    var initialized : Bool;
  };

  public let LAYOUT_VERSION : Nat32 = 1;

  let PAGE_SIZE : Nat64 = 65_536;
  let HEADER_SIZE : Nat64 = 64;
  let INITIAL_CAPACITY : Nat64 = 16;
  let SLOT_SIZE : Nat64 = 33;
  let KEY_SIZE : Nat = 32;
  let MAGIC : Blob = "\5a\4b\53\45\54\30\30\31"; // ZKSET001
  let OUT_OF_MEMORY : Nat64 = 0xffff_ffff_ffff_ffff;

  public func newState() : State {
    {
      region = Region.new();
      var table_offset = HEADER_SIZE;
      var capacity = INITIAL_CAPACITY;
      var entry_count = 0;
      var next_offset = HEADER_SIZE + INITIAL_CAPACITY * SLOT_SIZE;
      var initialized = false;
    }
  };

  func regionCapacity(state : State) : Nat64 { Region.size(state.region) * PAGE_SIZE };

  func ensureCapacity(state : State, needed : Nat64) {
    let current = regionCapacity(state);
    if (needed <= current) return;
    let pages = (needed - current + PAGE_SIZE - 1) / PAGE_SIZE;
    if (Region.grow(state.region, pages) == OUT_OF_MEMORY) {
      Runtime.trap("StableBlobSet: out of stable memory");
    };
  };

  func writeHeader(state : State) {
    Region.storeBlob(state.region, 0, MAGIC);
    Region.storeNat32(state.region, 8, LAYOUT_VERSION);
    Region.storeNat64(state.region, 16, state.table_offset);
    Region.storeNat64(state.region, 24, state.capacity);
    Region.storeNat64(state.region, 32, state.entry_count);
    Region.storeNat64(state.region, 40, state.next_offset);
  };

  public func ensureInit(state : State) {
    if (state.initialized) return;
    ensureCapacity(state, state.next_offset);
    writeHeader(state);
    state.initialized := true;
  };

  func slotOffset(table_offset : Nat64, index : Nat64) : Nat64 {
    table_offset + index * SLOT_SIZE
  };

  func hashIndex(key : Blob, capacity : Nat64) : Nat64 {
    let digest = Blob.toArray(Sha256.fromBlob(#sha256, key));
    var value : Nat64 = 0;
    var i : Nat = 0;
    while (i < 8) {
      value := value * 256 + Nat64.fromNat(Nat8.toNat(digest[i]));
      i += 1;
    };
    value % capacity
  };

  func findIn(
    state : State,
    table_offset : Nat64,
    table_capacity : Nat64,
    key : Blob,
  ) : (Nat64, Bool) {
    var index = hashIndex(key, table_capacity);
    var probes : Nat64 = 0;
    while (probes < table_capacity) {
      let offset = slotOffset(table_offset, index);
      switch (Region.loadNat8(state.region, offset)) {
        case 0 return (index, false);
        case 1 {
          if (Region.loadBlob(state.region, offset + 1, KEY_SIZE) == key) return (index, true);
        };
        case _ Runtime.trap("StableBlobSet: corrupt slot tag");
      };
      index := (index + 1) % table_capacity;
      probes += 1;
    };
    Runtime.trap("StableBlobSet: table has no empty slot")
  };

  func insertInto(
    state : State,
    table_offset : Nat64,
    table_capacity : Nat64,
    key : Blob,
  ) {
    let (index, found) = findIn(state, table_offset, table_capacity, key);
    if (found) return;
    let offset = slotOffset(table_offset, index);
    Region.storeBlob(state.region, offset + 1, key);
    Region.storeNat8(state.region, offset, 1);
  };

  func grow(state : State) {
    let old_offset = state.table_offset;
    let old_capacity = state.capacity;
    let new_capacity = old_capacity * 2;
    let new_offset = state.next_offset;
    let new_next = new_offset + new_capacity * SLOT_SIZE;
    ensureCapacity(state, new_next);

    var index : Nat64 = 0;
    while (index < old_capacity) {
      let offset = slotOffset(old_offset, index);
      if (Region.loadNat8(state.region, offset) == 1) {
        insertInto(state, new_offset, new_capacity, Region.loadBlob(state.region, offset + 1, KEY_SIZE));
      };
      index += 1;
    };

    state.table_offset := new_offset;
    state.capacity := new_capacity;
    state.next_offset := new_next;
    writeHeader(state);
  };

  public func contains(state : State, key : Blob) : Bool {
    if (key.size() != KEY_SIZE or not state.initialized) return false;
    findIn(state, state.table_offset, state.capacity, key).1
  };

  /// Returns #ok(true) for a new key and #ok(false) for an existing key.
  public func put(state : State, key : Blob) : Result<Bool> {
    if (key.size() != KEY_SIZE) return #err("stable-set:key-length");
    ensureInit(state);
    let (_, found) = findIn(state, state.table_offset, state.capacity, key);
    if (found) return #ok(false);
    if ((state.entry_count + 1) * 10 > state.capacity * 7) grow(state);
    insertInto(state, state.table_offset, state.capacity, key);
    state.entry_count += 1;
    Region.storeNat64(state.region, 32, state.entry_count);
    #ok(true)
  };

  public func size(state : State) : Nat { Nat64.toNat(state.entry_count) };

  public func bytesAllocated(state : State) : Nat { Nat64.toNat(regionCapacity(state)) };

  public func digest(state : State) : Blob {
    let hash = Sha256.Digest(#sha256);
    var index : Nat64 = 0;
    while (index < state.capacity) {
      let offset = slotOffset(state.table_offset, index);
      let tag = Region.loadNat8(state.region, offset);
      hash.writeBlob(Blob.fromArray([tag]));
      if (tag == 1) hash.writeBlob(Region.loadBlob(state.region, offset + 1, KEY_SIZE));
      index += 1;
    };
    hash.sum()
  };

  func powerOfTwo(value : Nat64) : Bool {
    if (value < INITIAL_CAPACITY) return false;
    var current = value;
    while (current % 2 == 0) { current /= 2 };
    current == 1
  };

  /// The O(1) header subset of validate(): magic, version, header/state cross-checks,
  /// capacity/table bounds, load factor. Exactly validate()'s checks BEFORE its slot
  /// walk, same error strings — safe to run in postupgrade at any capacity.
  public func validateHeader(state : State) : Result<()> {
    if (not state.initialized) return #err("stable-set:not-initialized");
    if (regionCapacity(state) < HEADER_SIZE) return #err("stable-set:region-too-small");
    if (Region.loadBlob(state.region, 0, 8) != MAGIC) return #err("stable-set:magic");
    if (Region.loadNat32(state.region, 8) != LAYOUT_VERSION) {
      return #err("stable-set:layout-version");
    };
    if (Region.loadNat64(state.region, 16) != state.table_offset or
        Region.loadNat64(state.region, 24) != state.capacity or
        Region.loadNat64(state.region, 32) != state.entry_count or
        Region.loadNat64(state.region, 40) != state.next_offset) {
      return #err("stable-set:header-state-mismatch");
    };
    if (not powerOfTwo(state.capacity)) return #err("stable-set:capacity");
    if (state.table_offset < HEADER_SIZE or
        state.table_offset + state.capacity * SLOT_SIZE > state.next_offset or
        state.next_offset > regionCapacity(state)) {
      return #err("stable-set:table-bounds");
    };
    if (state.entry_count * 10 > state.capacity * 7) return #err("stable-set:load-factor");
    #ok(())
  };

  /// Slot-tag walk over slots [from, min(from+count, capacity_captured)) of a CAPTURED
  /// table (offset + capacity captured at phase start, so a concurrent grow cannot move
  /// the walk mid-phase; the caller detects the move and restarts). Returns the number
  /// of occupied slots seen in the range; same error string as validate()'s walk.
  public func countTagsRange(
    state : State,
    table_offset_captured : Nat64,
    capacity_captured : Nat64,
    from : Nat64,
    count : Nat64,
  ) : Result<Nat64> {
    var observed : Nat64 = 0;
    var index = from;
    let end = if (from + count > capacity_captured) capacity_captured else from + count;
    while (index < end) {
      let tag = Region.loadNat8(state.region, slotOffset(table_offset_captured, index));
      if (tag == 1) observed += 1 else if (tag != 0) return #err("stable-set:slot-tag");
      index += 1;
    };
    #ok(observed)
  };

  public func validate(state : State) : Result<()> {
    switch (validateHeader(state)) {
      case (#err(message)) return #err(message);
      case (#ok(_)) {};
    };
    let observed = switch (countTagsRange(state, state.table_offset, state.capacity, 0, state.capacity)) {
      case (#err(message)) return #err(message);
      case (#ok(value)) value;
    };
    if (observed != state.entry_count) return #err("stable-set:observed-count");
    #ok(())
  };
};
