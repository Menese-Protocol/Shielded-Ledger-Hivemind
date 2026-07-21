/// Versioned append-only Blob log backed by two stable Regions.
///
/// Derived from the ICRC-ME StableLog shape (separate index/data regions), with explicit magic,
/// version, cross-checked headers, and contiguous-index validation for upgrade safety.

import Blob "mo:core/Blob";
import Nat "mo:core/Nat";
import Nat32 "mo:core/Nat32";
import Nat64 "mo:core/Nat64";
import Region "mo:core/Region";
import Runtime "mo:core/Runtime";
import Sha256 "mo:sha2/Sha256";

module {
  public type Result<T> = { #ok : T; #err : Text };

  public type State = {
    index_region : Region.Region;
    data_region : Region.Region;
    var entry_count : Nat64;
    var data_offset : Nat64;
    var initialized : Bool;
  };

  public let LAYOUT_VERSION : Nat32 = 1;

  let PAGE_SIZE : Nat64 = 65_536;
  let HEADER_SIZE : Nat64 = 32;
  let DATA_HEADER_SIZE : Nat64 = 16;
  let INDEX_ENTRY_SIZE : Nat64 = 16;
  let INDEX_MAGIC : Blob = "\5a\4b\4c\4f\47\30\30\31"; // ZKLOG001
  let DATA_MAGIC : Blob = "\5a\4b\44\41\54\41\30\31"; // ZKDATA01
  let OUT_OF_MEMORY : Nat64 = 0xffff_ffff_ffff_ffff;
  let MAX_NAT32 : Nat = 0xffff_ffff;

  public func newState() : State {
    {
      index_region = Region.new();
      data_region = Region.new();
      var entry_count = 0;
      var data_offset = DATA_HEADER_SIZE;
      var initialized = false;
    }
  };

  func capacity(region : Region.Region) : Nat64 { Region.size(region) * PAGE_SIZE };

  func ensureCapacity(region : Region.Region, needed : Nat64) {
    let current = capacity(region);
    if (needed <= current) return;
    let pages = (needed - current + PAGE_SIZE - 1) / PAGE_SIZE;
    if (Region.grow(region, pages) == OUT_OF_MEMORY) Runtime.trap("StableLog: out of stable memory");
  };

  public func ensureInit(state : State) {
    if (state.initialized) return;
    ensureCapacity(state.index_region, HEADER_SIZE);
    ensureCapacity(state.data_region, DATA_HEADER_SIZE);
    Region.storeBlob(state.index_region, 0, INDEX_MAGIC);
    Region.storeNat32(state.index_region, 8, LAYOUT_VERSION);
    Region.storeNat64(state.index_region, 16, 0);
    Region.storeNat64(state.index_region, 24, DATA_HEADER_SIZE);
    Region.storeBlob(state.data_region, 0, DATA_MAGIC);
    Region.storeNat32(state.data_region, 8, LAYOUT_VERSION);
    state.entry_count := 0;
    state.data_offset := DATA_HEADER_SIZE;
    state.initialized := true;
  };

  public func append(state : State, data : Blob) : Result<Nat> {
    ensureInit(state);
    if (data.size() > MAX_NAT32) return #err("stable-log:entry-too-large");

    let index = state.entry_count;
    let data_length = Nat64.fromNat(data.size());
    let index_offset = HEADER_SIZE + index * INDEX_ENTRY_SIZE;
    ensureCapacity(state.data_region, state.data_offset + data_length);
    ensureCapacity(state.index_region, index_offset + INDEX_ENTRY_SIZE);

    Region.storeBlob(state.data_region, state.data_offset, data);
    Region.storeNat64(state.index_region, index_offset, state.data_offset);
    Region.storeNat32(state.index_region, index_offset + 8, Nat32.fromNat(data.size()));

    state.data_offset += data_length;
    state.entry_count += 1;
    Region.storeNat64(state.index_region, 24, state.data_offset);
    Region.storeNat64(state.index_region, 16, state.entry_count);
    #ok(Nat64.toNat(index))
  };

  public func get(state : State, index : Nat) : ?Blob {
    if (not state.initialized) return null;
    let i = Nat64.fromNat(index);
    if (i >= state.entry_count) return null;
    let index_offset = HEADER_SIZE + i * INDEX_ENTRY_SIZE;
    let data_offset = Region.loadNat64(state.index_region, index_offset);
    let data_length = Nat32.toNat(Region.loadNat32(state.index_region, index_offset + 8));
    ?Region.loadBlob(state.data_region, data_offset, data_length)
  };

  public func size(state : State) : Nat { Nat64.toNat(state.entry_count) };

  public func dataSize(state : State) : Nat {
    if (state.data_offset < DATA_HEADER_SIZE) 0 else Nat64.toNat(state.data_offset - DATA_HEADER_SIZE)
  };

  public func digest(state : State) : Blob {
    let hash = Sha256.Digest(#sha256);
    var index : Nat = 0;
    while (index < size(state)) {
      switch (get(state, index)) {
        case (?entry) hash.writeBlob(entry);
        case null Runtime.trap("StableLog: missing indexed entry");
      };
      index += 1;
    };
    hash.sum()
  };

  /// The O(1) header subset of validate(): magic, versions, header/state cross-checks,
  /// bounds. Exactly validate()'s checks BEFORE its index walk, same error strings —
  /// safe to run in postupgrade at any entry count.
  public func validateHeader(state : State) : Result<()> {
    if (not state.initialized) return #err("stable-log:not-initialized");
    if (capacity(state.index_region) < HEADER_SIZE or capacity(state.data_region) < DATA_HEADER_SIZE) {
      return #err("stable-log:region-too-small");
    };
    if (Region.loadBlob(state.index_region, 0, 8) != INDEX_MAGIC) {
      return #err("stable-log:index-magic");
    };
    if (Region.loadBlob(state.data_region, 0, 8) != DATA_MAGIC) {
      return #err("stable-log:data-magic");
    };
    if (Region.loadNat32(state.index_region, 8) != LAYOUT_VERSION or
        Region.loadNat32(state.data_region, 8) != LAYOUT_VERSION) {
      return #err("stable-log:layout-version");
    };
    if (Region.loadNat64(state.index_region, 16) != state.entry_count) {
      return #err("stable-log:entry-count");
    };
    if (Region.loadNat64(state.index_region, 24) != state.data_offset) {
      return #err("stable-log:data-offset");
    };
    if (HEADER_SIZE + state.entry_count * INDEX_ENTRY_SIZE > capacity(state.index_region)) {
      return #err("stable-log:index-bounds");
    };
    if (state.data_offset < DATA_HEADER_SIZE or state.data_offset > capacity(state.data_region)) {
      return #err("stable-log:data-bounds");
    };
    #ok(())
  };

  /// The contiguity walk over index entries [from, min(from+count, entry_count)),
  /// chunk-safe: the caller carries the running expected_offset between chunks (start it
  /// at dataStartOffset()). Same error strings as validate()'s walk; the caller performs
  /// the final tail comparison against a data_offset captured at its phase start.
  public func validateIndexRange(
    state : State,
    from : Nat64,
    count : Nat64,
    expected_offset_in : Nat64,
  ) : Result<Nat64> {
    var expected_offset = expected_offset_in;
    var index = from;
    let end = if (from + count > state.entry_count) state.entry_count else from + count;
    while (index < end) {
      let index_offset = HEADER_SIZE + index * INDEX_ENTRY_SIZE;
      let data_offset = Region.loadNat64(state.index_region, index_offset);
      let data_length = Nat64.fromNat(
        Nat32.toNat(Region.loadNat32(state.index_region, index_offset + 8))
      );
      if (data_offset != expected_offset) return #err("stable-log:noncontiguous-index");
      if (data_offset + data_length > state.data_offset) return #err("stable-log:entry-bounds");
      expected_offset += data_length;
      index += 1;
    };
    #ok(expected_offset)
  };

  /// First data offset (the walk's expected_offset seed) — the fixed data header size.
  public func dataStartOffset() : Nat64 { DATA_HEADER_SIZE };

  public func validate(state : State) : Result<()> {
    switch (validateHeader(state)) {
      case (#err(message)) return #err(message);
      case (#ok(_)) {};
    };
    let expected_offset = switch (validateIndexRange(state, 0, state.entry_count, DATA_HEADER_SIZE)) {
      case (#err(message)) return #err(message);
      case (#ok(value)) value;
    };
    if (expected_offset != state.data_offset) return #err("stable-log:tail-offset");
    #ok(())
  };
};
