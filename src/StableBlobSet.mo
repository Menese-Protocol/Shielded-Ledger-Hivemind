/// Growable Region-backed set for fixed-width 32-byte keys.
///
/// The active open-addressed table is append-migrated inside one Region. Old tables are retained,
/// so a committed key is never deleted during growth and an interrupted update rolls back with the
/// canister message. Header fields are cross-checked after upgrade.

import Blob "mo:core/Blob";
import List "mo:core/List";
import Nat "mo:core/Nat";
import Nat32 "mo:core/Nat32";
import Nat64 "mo:core/Nat64";
import Nat8 "mo:core/Nat8";
import Prim "mo:⛔";
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
  // NOTE: this record is a stable variable in every deployed canister. Adding a field to it is an
  // M0170 incompatible change and would make existing pools UNUPGRADEABLE, so the active table's
  // stride is carried in the region header (offset 48) and read on demand instead.

  public let LAYOUT_VERSION : Nat32 = 2;

  let PAGE_SIZE : Nat64 = 65_536;
  let HEADER_SIZE : Nat64 = 64;
  let INITIAL_CAPACITY : Nat64 = 16;
  // Layout 1: tag(1) ‖ key(32). Every rehash recomputed a full SHA-256 per surviving entry.
  // Layout 2: tag(1) ‖ key(32) ‖ hash prefix(8). grow() reads the stored prefix instead, so a
  // rehash moves bytes and does no hashing at all.
  let SLOT_SIZE_V1 : Nat64 = 33;
  let SLOT_SIZE_V2 : Nat64 = 41;
  let HASH_OFFSET : Nat64 = 33;
  let KEY_SIZE : Nat = 32;
  let MAGIC : Blob = "\5a\4b\53\45\54\30\30\31"; // ZKSET001
  let OUT_OF_MEMORY : Nat64 = 0xffff_ffff_ffff_ffff;

  // ==================== the migration window (option (b)) ====================
  //
  // A grow used to rehash the whole table in ONE message: O(N) instructions and O(N) allocation in a
  // single call, which is the wedge. Caching the slot hash (layout 2) cut the constant 16x and left
  // the shape untouched — the per-rung cost still doubled with the table.
  //
  // A window splits that work across the operations that follow it. On the grow the new table is
  // ALLOCATED but nothing is moved; each later `put` carries MIGRATION_CHUNK old slots across; the
  // window closes when the cursor reaches the end of the old table. Max work per message becomes a
  // constant instead of a function of N.
  //
  // WHY IT NEEDS NO LAYOUT_VERSION BUMP. Layout 1 wrote header bytes 0-47, layout 2 also 48-55, and
  // HEADER_SIZE has been 64 in both. Bytes 56-63 were written by neither and read back zero, so
  // every set that exists today reports "no window" without being touched — the same property that
  // let the stride move into the header at offset 48. The stable State record is unchanged, so
  // there is no M0170 and existing pools stay upgradeable.
  //
  // WHAT THE HEADER CARRIES DURING A WINDOW. table_offset, capacity and next_offset keep describing
  // the OLD table, unchanged; the new table is at next_offset with capacity 2 x capacity, and
  // next_offset advances only when the window closes. Six values fit in five words because the
  // capacity always doubles and tables are always allocated consecutively.
  let MIGRATION_OFFSET : Nat64 = 56;
  let MIGRATION_ACTIVE : Nat64 = 0x8000_0000_0000_0000;
  /// Bit 62 is claimed by COMPACT_ACTIVE, so the cursor mask NARROWS from bits 0-62 to
  /// bits 0-61. Both reads of it (`migrationCursor`, `setMigration`) move together — narrowing the
  /// mask alone, or setting the flag alone, corrupts every cursor read during a window. The cursor
  /// is a slot index bounded by 2^32, so 2^62 of headroom is untouched by this.
  let MIGRATION_CURSOR : Nat64 = 0x3fff_ffff_ffff_ffff;
  let COMPACT_ACTIVE : Nat64 = 0x4000_0000_0000_0000;
  /// Old slots carried across per `put`. Committed as an acceptance threshold before measuring.
  /// Any value >= 2 closes a window before the next grow can be demanded (see stepBound); 8 leaves
  /// a 5.6x margin on that bound.
  let MIGRATION_CHUNK : Nat64 = 8;
  // Reclaim work drained per put (compactStep): one unit is one relocated slot or one zeroed 8-byte
  // word. A bounded reclaim is at most COMPACT_MAX_BYTES (8 MiB): ~204,600 slots to copy + ~1.05M
  // words to zero. A grow to capacity C leaves ~0.35*C puts before the next grow; at 64 units/put the
  // whole reclaim drains in far fewer than that (the openWindow force-drain must never
  // fire), while each put's added cost stays a small flat constant.
  let COMPACT_BUDGET : Nat64 = 64;
  /// Ceiling on one explicit advanceMigration call, so the operator-driven convergence cannot be
  /// asked to exceed the per-message instruction limit.
  let MIGRATION_MAX_BUDGET : Nat64 = 65_536;
  /// Counter of forced completions, at the four header bytes between the version and table_offset
  /// that no layout has ever written. Not a diagnostic nicety: it is the evidence that the
  /// force-complete branch in put() is cold.
  let FORCED_OFFSET : Nat64 = 12;

  // Slot tags. A migrated slot is TOMBSTONED rather than cleared: clearing it would truncate every
  // open-addressed probe chain that runs through it, and a key later in such a chain would read as
  // ABSENT while still being present. On spent_nullifiers that is a double spend. A tombstone keeps
  // the chain intact and is never repaired, because the old table is discarded when the window
  // closes.
  let TAG_EMPTY : Nat8 = 0;
  let TAG_LIVE : Nat8 = 1;
  let TAG_MIGRATED : Nat8 = 2;

  public func newState() : State {
    {
      region = Region.new();
      var table_offset = HEADER_SIZE;
      var capacity = INITIAL_CAPACITY;
      var entry_count = 0;
      var next_offset = HEADER_SIZE + INITIAL_CAPACITY * SLOT_SIZE_V2;
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

  /// The stride is a PARAMETER. This used to store SLOT_SIZE_V2
  /// unconditionally, which was safe only because the two original callers -- ensureInit and
  /// closeWindow -- both run when the live table genuinely is layout 2. That was an unstated
  /// invariant, and compactStep became a third caller that breaks it: on a rescued layout-1 pool it
  /// relocates correctly at stride 33 and then the header labelled the table 41, so every probe
  /// address afterwards is wrong and a spent nullifier reads unspent. Layout-1/33 pools are a
  /// live tested state, so this is reachable, not theoretical.
  func writeHeader(state : State, stride : Nat64) {
    Region.storeBlob(state.region, 0, MAGIC);
    // The VERSION travels with the stride. Parameterising only the stride was half a fix --
    // openWindow's own comment says writeHeader "would stamp version 2 AND stride 41", and
    // compactStep relocating a rescued layout-1 table then labelled it version 2 while its slots are
    // still 33 bytes. A set-migration test caught it: the table is still layout 1.
    Region.storeNat32(state.region, 8, if (stride == SLOT_SIZE_V2) LAYOUT_VERSION else 1 : Nat32);
    Region.storeNat64(state.region, 16, state.table_offset);
    Region.storeNat64(state.region, 24, state.capacity);
    Region.storeNat64(state.region, 32, state.entry_count);
    Region.storeNat64(state.region, 40, state.next_offset);
    Region.storeNat64(state.region, 48, stride);
  };

  /// Stride of the ACTIVE table, read from the header rather than held in the stable record.
  /// A set written by the layout-1 module has zero here, because that module never wrote offset
  /// 48 — so zero means "33-byte slots, no cached hash". This is what lets an existing pool keep
  /// reading its own table correctly after the module is upgraded, with no stable-layout change
  /// and therefore no migration step: the table converts on its next grow.
  public func activeStride(state : State) : Nat64 { strideOf(state) };

  func strideOf(state : State) : Nat64 {
    let stored = Region.loadNat64(state.region, 48);
    if (stored == 0) SLOT_SIZE_V1 else stored
  };

  // ---- window accessors -----------------------------------------------------------------------
  // All of these read the region, so every caller must already have established that the set is
  // initialized; an uninitialized set has no header to read.

  func migrationWord(state : State) : Nat64 { Region.loadNat64(state.region, MIGRATION_OFFSET) };

  public func migrationActive(state : State) : Bool {
    state.initialized and (migrationWord(state) & MIGRATION_ACTIVE) != 0
  };

  /// How far the window has carried. Meaningless when no window is open, and zero there.
  public func migrationCursor(state : State) : Nat64 {
    if (not state.initialized) return 0;
    migrationWord(state) & MIGRATION_CURSOR
  };

  func setMigration(state : State, active : Bool, cursor : Nat64) {
    let flag : Nat64 = if (active) MIGRATION_ACTIVE else 0;
    let word = flag | (cursor & MIGRATION_CURSOR);
    Region.storeNat64(state.region, MIGRATION_OFFSET, word);
  };

  /// Offset and capacity of the table that inserts land in. During a window that is the NEW table,
  /// which is why an insert never touches the old one and the old one's probe chains stay frozen.
  /// PUBLIC, mirroring migrationActive at :158. The compaction window had no observability
  /// surface while its migration sibling did; that asymmetry, not unreachability, is why the
  /// routes to witnessing Cheney invariant 4 failed.
  public func compactionActive(state : State) : Bool {
    state.initialized and (migrationWord(state) & COMPACT_ACTIVE) != 0
  };

  /// PUBLIC, mirroring migrationCursor at :163.
  public func compactCursor(state : State) : Nat64 {
    migrationWord(state) & MIGRATION_CURSOR
  };

  func setCompaction(state : State, active : Bool, cursor : Nat64) {
    let flag : Nat64 = if (active) COMPACT_ACTIVE else 0;
    let word : Nat64 = flag | (cursor & MIGRATION_CURSOR);
    Region.storeNat64(state.region, MIGRATION_OFFSET, word);
  };

  /// Where slot `index` of the LIVE table actually is. During a chunked compaction the slots
  /// below the cursor have already been copied down to HEADER_SIZE and their source bytes have been
  /// overwritten, so a reader between chunks MUST dispatch on the cursor or it reads clobbered
  /// bytes. Compaction never runs during a migration window, so this only ever applies to the live
  /// table. Off a compaction this is exactly slotOffsetAt.
  func slotOffsetLive(state : State, table_offset : Nat64, index : Nat64, stride : Nat64) : Nat64 {
    if (compactionActive(state) and index < compactCursor(state)) {
      HEADER_SIZE + index * stride
    } else { table_offset + index * stride }
  };

  func targetOffset(state : State) : Nat64 {
    if (migrationActive(state)) state.next_offset else state.table_offset
  };

  public func activeCapacity(state : State) : Nat64 {
    if (migrationActive(state)) state.capacity * 2 else state.capacity
  };

  func targetStride(state : State) : Nat64 {
    if (migrationActive(state)) SLOT_SIZE_V2 else strideOf(state)
  };

  /// How many put() calls a window needs to close, and how many are available before the next grow
  /// would be demanded. The first must stay below the second or a grow can be demanded mid-window.
  /// Exposed so the property is measured rather than argued.
  public func stepBound(state : State) : (Nat64, Nat64) {
    let old_capacity = state.capacity;
    let remaining = if (migrationActive(state)) old_capacity - migrationCursor(state) else old_capacity;
    let steps = (remaining + MIGRATION_CHUNK - 1) / MIGRATION_CHUNK;
    let ceiling = (activeCapacity(state) * 7) / 10;
    let available : Nat64 = if (ceiling > state.entry_count) ceiling - state.entry_count else 0;
    (steps, available)
  };

  public func forcedCompletions(state : State) : Nat32 {
    if (not state.initialized) return 0;
    Region.loadNat32(state.region, FORCED_OFFSET)
  };

  public func ensureInit(state : State) {
    if (state.initialized) return;
    ensureCapacity(state, state.next_offset);
    writeHeader(state, SLOT_SIZE_V2);
    state.initialized := true;
  };

  func slotOffsetAt(table_offset : Nat64, index : Nat64, stride : Nat64) : Nat64 {
    table_offset + index * stride
  };

  /// The full 8-byte hash prefix, BEFORE the modulus. Layout 2 stores exactly this, so a rehash
  /// into a table of a different capacity only has to take the modulus again.
  ///
  /// OUTPUT IDENTITY IS LOAD-BEARING, not a nicety. Since layout 2 this value is PERSISTED in every
  /// slot. A different Nat64 for any key would leave every cached hash in every existing table
  /// silently wrong, and lookups would miss keys that are present — on spent_nullifiers that is a
  /// double spend, on completed_*_intents a replay. So this must stay byte-for-byte the same
  /// function as the version it replaced:
  ///
  ///   let digest = Blob.toArray(Sha256.fromBlob(#sha256, key));
  ///   var value : Nat64 = 0; var i : Nat = 0;
  ///   while (i < 8) { value := value * 256 + Nat64.fromNat(Nat8.toNat(digest[i])); i += 1 };
  ///
  /// Two things changed and neither can change the result. Blob.toArray built a 32-byte [Nat8] per
  /// call to read eight bytes from it; iterating the blob reads the same eight bytes in the same
  /// order. And Nat64.fromNat(Nat8.toNat(b)) routed every byte through arbitrary-precision Nat to
  /// widen 8 bits to 64; the two machine widenings do that exactly, since a Nat8 always fits.
  /// `value * 256 + b` on a Nat64 is `(value << 8) | b` for b < 256 by construction. Verified over
  /// a corpus, and against hashes already cached by the old code, in scripts/hash-parity-battery.sh.
  func hashOf(key : Blob) : Nat64 {
    let digest = Sha256.fromBlob(#sha256, key);
    var value : Nat64 = 0;
    var taken : Nat = 0;
    label scan for (byte in digest.vals()) {
      if (taken == 8) break scan;
      value := (value << 8) | Prim.nat32ToNat64(Prim.nat16ToNat32(Prim.nat8ToNat16(byte)));
      taken += 1;
    };
    value
  };

  /// The same value the set stores in a slot, exposed so a differential test can compare it against
  /// the previous implementation and against hashes already persisted by it.
  public func hashFor(key : Blob) : Nat64 { hashOf(key) };

  /// The hash CACHED in `key`'s slot, or null when the key is absent or the table predates layout 2.
  /// Lets a test read what the old module persisted and check the new hashOf still agrees with it.
  public func cachedHashOf(state : State, key : Blob) : ?Nat64 {
    if (key.size() != KEY_SIZE or not state.initialized) return null;
    let hash = hashOf(key);
    // The new table first, for the same reason contains does: during a window a key is in exactly
    // one of the two, and everything inserted or carried across since the window opened is in the
    // new one. Reading only the old table here reported a key that is present as having no cached
    // hash at all.
    if (migrationActive(state)) {
      let (index, found) = findInWith(state, state.next_offset, state.capacity * 2, key, hash, SLOT_SIZE_V2);
      if (found) {
        return ?Region.loadNat64(state.region, slotOffsetAt(state.next_offset, index, SLOT_SIZE_V2) + HASH_OFFSET);
      };
    };
    let stride = strideOf(state);
    if (stride != SLOT_SIZE_V2) return null;
    let (index, found) = findInWith(state, state.table_offset, state.capacity, key, hash, stride);
    if (not found) return null;
    ?Region.loadNat64(state.region, slotOffsetLive(state, state.table_offset, index, stride) + HASH_OFFSET)
  };

  func findInWith(
    state : State,
    table_offset : Nat64,
    table_capacity : Nat64,
    key : Blob,
    hash : Nat64,
    stride : Nat64,
  ) : (Nat64, Bool) {
    var index = hash % table_capacity;
    var probes : Nat64 = 0;
    while (probes < table_capacity) {
      let offset = slotOffsetLive(state, table_offset, index, stride);
      switch (Region.loadNat8(state.region, offset)) {
        case 0 return (index, false);
        case 1 {
          if (Region.loadBlob(state.region, offset + 1, KEY_SIZE) == key) return (index, true);
        };
        // A tombstone is a slot whose key has been carried into the new table. The probe must walk
        // THROUGH it, never stop at it: stopping would truncate the chain and report a key that is
        // still in this table as absent. It is never returned as an insertion point either, because
        // nothing is ever inserted into a table that has tombstones — the old table is frozen for
        // the life of the window and discarded at the end of it.
        case 2 {};
        case _ Runtime.trap("StableBlobSet: corrupt slot tag");
      };
      index := (index + 1) % table_capacity;
      probes += 1;
    };
    Runtime.trap("StableBlobSet: table has no empty slot")
  };

  /// Insert into a table OF THE GIVEN STRIDE using an already-known hash. A layout-2 slot also
  /// caches the hash, which is why a later rehash performs no SHA-256; a layout-1 slot has no room
  /// for one and keeps its narrow shape until the next grow converts it.
  ///
  /// The stride is a parameter rather than the SLOT_SIZE_V2 constant because both layouts are live
  /// at the same time. An upgraded pool keeps writing to its existing layout-1 table for every
  /// insert until the load factor forces a grow, and writing that table at the wide stride puts the
  /// slot at table_offset + index*41 in a table laid out at table_offset + index*33 — past the end
  /// of the table for a high index, over a neighbouring key for a low one.
  func insertInto(
    state : State,
    table_offset : Nat64,
    table_capacity : Nat64,
    key : Blob,
    hash : Nat64,
    stride : Nat64,
  ) {
    let (index, found) = findInWith(state, table_offset, table_capacity, key, hash, stride);
    if (found) return;
    let offset = slotOffsetLive(state, table_offset, index, stride);
    Region.storeBlob(state.region, offset + 1, key);
    if (stride == SLOT_SIZE_V2) Region.storeNat64(state.region, offset + HASH_OFFSET, hash);
    Region.storeNat8(state.region, offset, 1);
  };

  /// Allocate the doubled table and open the window. NOTHING is moved here — that is the whole
  /// point. The header keeps describing the old table, so a set that is upgraded, audited or
  /// validated mid-window reads exactly as it did before, plus the migration word.
  ///
  /// writeHeader is deliberately NOT called: it would stamp version 2 and stride 41, and during a
  /// window those four fields still describe the OLD table, which on a rescued pool is layout 1 at
  /// stride 33. The header becomes layout 2 when the window closes and the new table takes over.
  func openWindow(state : State) {
    let new_capacity = state.capacity * 2;
    // The new table always occupies fresh address space beyond every table before it, because
    // next_offset is monotone and each table is allocated at the end of the last. Region.grow
    // zero-fills, and no byte in this range has ever been written, so the new table starts empty.
    // Ordering matters: compactStep RESETS table_offset and next_offset when it finishes, so the
    // relocation must complete BEFORE ensureCapacity sizes the region -- otherwise the doubled
    // table is sized against a next_offset the loop then moves, and correctness rests on an
    // inequality rather than on the sizing being computed from the offsets actually in force.
    // Finish any in-flight compaction before sizing the region: compactStep resets table_offset and
    // next_offset when it completes, so the doubled table must be sized against the offsets actually
    // in force. In steady operation the per-put drain has already completed the compaction, so this
    // is a no-op — and it MUST be, because a compaction finished wholesale here would be the very
    // O(capacity) spike this rewrite removes (the flat-max assertion catches it if it ever fires).
    while (compactionActive(state)) { ignore compactStep(state, 0xffff_ffff) };
    // NO explicit zero-fill. The old code zeroed the new table's range on every grow — the O(capacity)
    // term the grow-cost measurement caught — because compaction reused reclaimed (dirty) space. That is gone:
    // compactStep now ZEROES the freed tail as part of the chunked reclaim, and Region.grow zero-fills
    // virgin pages, so the INVARIANT holds — [next_offset, extent) is always zero when no window is
    // open. The doubled table lands entirely in that already-zero range, so it starts clean with no
    // work here. The membership property (never wrong mid-window, zero false positives) is the standing proof
    // that the to-space is clean; if the invariant were ever violated a stale tag would surface there.
    ensureCapacity(state, state.next_offset + new_capacity * SLOT_SIZE_V2);
    // A compaction window and a migration window SHARE one 64-bit word, and setMigration below
    // writes `flag | cursor` over the whole of it -- so opening a migration while a compaction is in
    // flight silently erases COMPACT_ACTIVE and the compaction cursor. Slots below that cursor have
    // already been copied down to HEADER_SIZE, and once the cursor passes
    // (table_offset - HEADER_SIZE)/stride their source bytes have been overwritten, so with the
    // window erased slotOffsetLive would route those reads back to clobbered source bytes and a
    // SPENT NULLIFIER WOULD READ UNSPENT. The two windows are mutually exclusive by design --
    // compactStep already refuses while a migration is active -- and this is the missing other half
    // of that exclusion. Finish the relocation before opening the window; the cost is one table copy,
    // the same order as the doubled-table zero-fill ensureCapacity performs just below.
    setMigration(state, true, 0);
  };

  /// Reclaim the superseded tables. Every table before the live one is dead the moment a
  /// window closes, and next_offset is monotone, so after k grows the region carries (2^k - 1)*S0 of
  /// tables nothing references — measured at 49.9% of the set region.
  ///
  /// The live table moves DOWN to HEADER_SIZE. dest < src, so a copy in INCREASING address order is
  /// safe on the overlap: writing dest[i] can only touch src[i - delta] for delta > 0, already read.
  /// The committed design's phase-1 scratch copy of the S0 overlap is therefore unnecessary. There
  /// is no rehash either — compaction leaves `capacity` unchanged, so slot indices do not move and
  /// no open-addressed re-insertion happens. That re-insertion was the double-spend hazard; a pure
  /// relocation does not perform it.
  ///
  /// Bounded so this stays one message with no cursor and no test on the lookup path: above the
  /// budget the region is simply left as it is. AUDIT_BYTES_PER_CHUNK uses the same 8 MiB figure as
  /// the ledger's per-message byte budget.
  let COMPACT_MAX_BYTES : Nat64 = 8_388_608;

  /// Move the live table down to HEADER_SIZE a bounded number of slots at a time,
  /// so a table larger than COMPACT_MAX_BYTES can still be reclaimed. Returns true when finished.
  ///
  /// Correctness rests on two facts. dest < src, so copying in INCREASING index order never
  /// overwrites a source slot that has not been read yet. And capacity is unchanged, so slot
  /// indices do not move and there is no rehash — the double-spend hazard in the original design
  /// came from open-addressed re-insertion, which a relocation does not perform.
  ///
  /// Readers between chunks are served by slotOffsetLive, which dispatches on this cursor.
  /// (capacity, entry_count, table_offset, next_offset) — enough to see a relocation land.
  public func layoutOf(state : State) : (Nat64, Nat64, Nat64, Nat64) {
    (state.capacity, state.entry_count, state.table_offset, state.next_offset)
  };

  public func compactStep(state : State, budget : Nat64) : Bool {
    if (not state.initialized) return true;
    if (migrationActive(state)) return false;
    let stride = strideOf(state);
    if (not compactionActive(state)) {
      if (state.table_offset <= HEADER_SIZE) return true;
      setCompaction(state, true, 0);
    };
    // Where the relocated table ends: everything at or beyond this is freed tail, to be zeroed so the
    // NEXT grow reuses clean space (maintaining [next_offset, extent) == 0). Region.grow keeps the
    // virgin pages past the old table zero; this keeps the reclaimed pages zero.
    let newEnd = HEADER_SIZE + state.capacity * stride;
    var cursor = compactCursor(state);
    var work : Nat64 = 0;
    // Relocate the live table down, one slot per unit, cursor in [0, capacity) — so validateHeader's
    // compaction-cursor bound (cursor < capacity) is UNTOUCHED, no upgrade-path change. As each slot
    // is copied down, the part of its SOURCE that lies in the freed tail (src at/after newEnd) is
    // zeroed in place via storeNat64 (no allocation). Those freed sources are exactly the slots whose
    // destination (HEADER_SIZE + (cursor+delta)*stride, delta = (table_offset-HEADER_SIZE)/stride)
    // would be beyond capacity, so zeroing them can never clobber a relocated slot. This is what makes
    // reclaim FLAT: the O(capacity) relocate-and-zero never lands in one message — a bounded slice per
    // put, the stepMigration discipline.
    while (cursor < state.capacity and work < budget) {
      let src = state.table_offset + cursor * stride;
      let block = Region.loadBlob(state.region, src, Nat64.toNat(stride));
      Region.storeBlob(state.region, HEADER_SIZE + cursor * stride, block);
      if (src + stride > newEnd) {
        var z = if (src > newEnd) src else newEnd;
        let ze = src + stride;
        while (z + 8 <= ze) { Region.storeNat64(state.region, z, 0); z += 8 };
        while (z < ze) { Region.storeNat8(state.region, z, 0); z += 1 };
      };
      cursor += 1;
      work += 1;
    };
    if (cursor >= state.capacity) {
      state.table_offset := HEADER_SIZE;
      state.next_offset := newEnd;
      setCompaction(state, false, 0);
      writeHeader(state, stride);
      return true;
    };
    setCompaction(state, true, cursor);
    false
  };

  /// Two fixes here.
  /// STRIDE IS A PARAMETER, not `SLOT_SIZE_V2`: on a layout-1 table the constant over-sizes the copy
  /// by `capacity * 8` bytes, reading past `next_offset` -- a trap if that crosses the region end,
  /// and an over-reserved `next_offset` if it does not. It cannot be read from the header here
  /// either, because `closeWindow` calls this BEFORE rewriting the header, so `strideOf` would
  /// return the OLD table's stride while the table being compacted is the new layout-2 one.
  /// AND IT WRITES THE HEADER ITSELF. It mutates `table_offset` and `next_offset`; `closeWindow`
  /// happened to follow it with `writeHeader`, but the retroactive `put` path did not, so the first
  /// put on a pool already carrying superseded tables left header bytes 16 and 40 disagreeing with
  /// the State record. `validateHeader` cross-checks exactly those, so `postupgrade` trapped on
  /// `stable-set:header-state-mismatch` -- and it does not self-heal, because the retroactive path
  /// exists precisely for a pool that never doubles again and only `closeWindow` rewrote the header.
  // compactIfBounded (fde5b04) is REMOVED: it relocated the whole bounded table WHOLESALE in one
  // message on the value path — the one-message reclaim 4f4f28b had already ruled out for migration,
  // and the O(capacity) grow-message spike the cost measurement caught. All reclaim now goes through the
  // chunked compactStep cursor (driven a bounded slice per put), for every table size, not only the
  // > 8 MiB exception b079700 chunked.

  func closeWindow(state : State) {
    let new_offset = state.next_offset;
    let new_capacity = state.capacity * 2;
    state.table_offset := new_offset;
    state.capacity := new_capacity;
    state.next_offset := new_offset + new_capacity * SLOT_SIZE_V2;
    setMigration(state, false, 0);
    // Reclaim is NO LONGER done inline here. fde5b04 relocated the live table in ONE message at
    // closeWindow (up to COMPACT_MAX_BYTES = 8 MiB on a user's shield/unshield) — the exact
    // one-message anti-pattern 4f4f28b removed from migration. Reclaim now drains a bounded slice per
    // put through compactStep (see the put path), so this message only rewrites the header. The
    // header is layout 2 at stride 41: it describes the new table where it now lives, and the next
    // put's compactStep reads that stride when it starts relocating.
    writeHeader(state, SLOT_SIZE_V2);
  };

  /// Carry up to `budget` OLD SLOTS across. The budget counts slots scanned, not keys moved, because
  /// scanning is what the cost is proportional to — an empty slot is a load and a compare.
  ///
  /// Idempotent by construction, which is what makes a rolled-back message safe to retry: insertInto
  /// returns early when the key is already in the new table, and a slot is tombstoned only after its
  /// key has landed there, in the same message.
  func stepMigration(state : State, budget : Nat64) : Bool {
    if (not migrationActive(state)) return false;
    let old_offset = state.table_offset;
    let old_capacity = state.capacity;
    let old_stride = strideOf(state);
    let old_has_hash = old_stride == SLOT_SIZE_V2;
    let new_offset = state.next_offset;
    let new_capacity = old_capacity * 2;
    var cursor = migrationCursor(state);
    var scanned : Nat64 = 0;
    while (scanned < budget and cursor < old_capacity) {
      let offset = slotOffsetAt(old_offset, cursor, old_stride);
      if (Region.loadNat8(state.region, offset) == TAG_LIVE) {
        let key = Region.loadBlob(state.region, offset + 1, KEY_SIZE);
        // Layout 2 hands the hash over; only a layout-1 table still has to compute one, which is
        // why a rescued pool's window costs a SHA-256 per live slot and a converged one costs none.
        let hash = if (old_has_hash) Region.loadNat64(state.region, offset + HASH_OFFSET) else hashOf(key);
        insertInto(state, new_offset, new_capacity, key, hash, SLOT_SIZE_V2);
        Region.storeNat8(state.region, offset, TAG_MIGRATED);
      };
      cursor += 1;
      scanned += 1;
    };
    if (cursor >= old_capacity) { closeWindow(state); return true };
    setMigration(state, true, cursor);
    false
  };

  /// Carry the window forward explicitly, for a caller that wants it closed sooner than its own
  /// traffic would close it. Returns true when the window is closed on return.
  ///
  /// This is the answer to a pool with no write traffic: reads deliberately do not move the cursor
  /// (see contains), so without this a window on an idle pool would stay open indefinitely. The
  /// budget is capped so no single call can be asked to exceed the message limit.
  public func advanceMigration(state : State, budget : Nat64) : Bool {
    if (not state.initialized) return true;
    if (not migrationActive(state)) return true;
    let capped = if (budget > MIGRATION_MAX_BUDGET) MIGRATION_MAX_BUDGET else budget;
    ignore stepMigration(state, capped);
    not migrationActive(state)
  };

  /// Guarantee that the next `k` inserts will not allocate: no grow, no window opened, no
  /// Region.grow, and therefore no `out of stable memory` trap. Performs whatever is needed to make
  /// that true, and reports failure rather than trapping.
  ///
  /// A PREDICATE, NOT A RESERVATION. It asserts a state and makes it hold; it does not consume a
  /// budget. That distinction is load-bearing: resume_unshield requires a pending intent rather than
  /// the absence of one, so any number of callers can be in flight at once, and a cumulative
  /// reservation would leak one per caller and demand unbounded capacity. As a predicate, calling it
  /// twice is a no-op the second time — which is also why PREPARE-then-abort cannot grow anything
  /// more than once.
  public func ensureHeadroom(state : State, k : Nat64) : Result<()> {
    ensureInit(state);
    if ((state.entry_count + k) * 10 <= activeCapacity(state) * 7) return #ok(());
    // A window already open with insufficient headroom is the force-complete case, which the
    // forced-completion counter shows is cold. Finish it here, in PREPARE, where the cost is paid
    // before any money moves.
    if (migrationActive(state)) ignore stepMigration(state, state.capacity);
    if (not migrationActive(state) and (state.entry_count + k) * 10 > state.capacity * 7) {
      openWindow(state);
    };
    if ((state.entry_count + k) * 10 > activeCapacity(state) * 7) return #err("stable-set:headroom");
    #ok(())
  };

  /// Membership, with the hash already in hand. During a window a key is in EXACTLY ONE table: the
  /// new one if it has been carried across or was inserted during the window, the old one if it has
  /// not. It is never in both, because a slot is tombstoned in the same message its key lands in
  /// the new table, and never in neither, because the tombstone is written after the insert.
  func containsWith(state : State, key : Blob, hash : Nat64) : Bool {
    if (migrationActive(state)) {
      if (findInWith(state, state.next_offset, state.capacity * 2, key, hash, SLOT_SIZE_V2).1) return true;
    };
    findInWith(state, state.table_offset, state.capacity, key, hash, strideOf(state)).1
  };

  /// Membership does NOT advance the cursor, unlike Redis's rehash-on-find, and the reason is
  /// specific to this platform rather than a preference. A query's state changes are discarded on
  /// the IC, so stepping here could not converge a query-only pool anyway; and stepping on every
  /// membership check would move the cursor under the ledger's chunked audit walk, whose exactness
  /// depends on the set being quiescent for the length of the walk. advanceMigration is the
  /// supported way to converge a pool that is not being written to.
  public func contains(state : State, key : Blob) : Bool {
    if (key.size() != KEY_SIZE or not state.initialized) return false;
    containsWith(state, key, hashOf(key))
  };

  /// Returns #ok(true) for a new key and #ok(false) for an existing key.
  public func put(state : State, key : Blob) : Result<Bool> {
    if (key.size() != KEY_SIZE) return #err("stable-set:key-length");
    ensureInit(state);
    // Reclamation, CHUNKED — a bounded slice per put, never one message. This is the default path
    // now (fde5b04 had made the common case inline up to 8 MiB; b079700 chunked only the > 8 MiB
    // exception). compactStep relocates COMPACT_BUDGET slots (or zeroes that many freed 8-byte words)
    // and returns; over the puts before the next grow it drains the whole bounded reclaim, so no user
    // message pays the O(capacity) copy-and-zero. It is also retroactive: a pool that never doubles
    // again still drains its superseded tables one slice per put. In the steady state (table already
    // at HEADER_SIZE, nothing pending) compactStep returns on its first guard — one comparison.
    if (not migrationActive(state)
        and (compactionActive(state)
             or (state.table_offset > HEADER_SIZE
                 and state.capacity * strideOf(state) <= COMPACT_MAX_BYTES))) {
      ignore compactStep(state, COMPACT_BUDGET);
    };
    // Hashed once for this call and reused by every probe, the migration step and the insert.
    let hash = hashOf(key);
    if (containsWith(state, key, hash)) return #ok(false);

    // A grow demanded while a window is open. Unreachable while the stepBound property holds — a
    // window closes in ceil(capacity/CHUNK) puts and that is far fewer than the puts available
    // before this can fire — so the branch is counted rather than trusted, and the battery asserts
    // the counter stays zero. It finishes the window rather than refusing: a refusal here would fail
    // addNullifier, and a failing addNullifier is a wedge of exactly the kind this work removes.
    if (migrationActive(state) and (state.entry_count + 1) * 10 > activeCapacity(state) * 7) {
      Region.storeNat32(state.region, FORCED_OFFSET, Region.loadNat32(state.region, FORCED_OFFSET) + 1);
      ignore stepMigration(state, state.capacity);
    };

    // Open a window when the table inserts land in is full enough. Allocation only; no entry moves
    // in this message, which is what makes the cost of this message independent of N.
    if (not migrationActive(state) and (state.entry_count + 1) * 10 > state.capacity * 7) {
      openWindow(state);
    };

    insertInto(state, targetOffset(state), activeCapacity(state), key, hash, targetStride(state));
    state.entry_count += 1;
    Region.storeNat64(state.region, 32, state.entry_count);

    // Pay a bounded slice of the outstanding migration. This is the line that makes the per-message
    // cost flat in N instead of doubling with it.
    ignore stepMigration(state, MIGRATION_CHUNK);
    #ok(true)
  };

  public func size(state : State) : Nat { Nat64.toNat(state.entry_count) };

  public func bytesAllocated(state : State) : Nat { Nat64.toNat(regionCapacity(state)) };

  func digestTable(
    hash : Sha256.Digest,
    state : State,
    table_offset : Nat64,
    table_capacity : Nat64,
    stride : Nat64,
  ) {
    var index : Nat64 = 0;
    while (index < table_capacity) {
      let offset = slotOffsetLive(state, table_offset, index, stride);
      let tag = Region.loadNat8(state.region, offset);
      hash.writeBlob(Blob.fromArray([tag]));
      if (tag == TAG_LIVE) hash.writeBlob(Region.loadBlob(state.region, offset + 1, KEY_SIZE));
      index += 1;
    };
  };

  /// A digest of the set's LAYOUT, not of its contents — it always has been, which is why it changes
  /// across a grow. During a window both tables are covered, old then new, so the value stays a
  /// function of the bytes on disk and a corrupted slot still moves it.
  public func digest(state : State) : Blob {
    let hash = Sha256.Digest(#sha256);
    digestTable(hash, state, state.table_offset, state.capacity, strideOf(state));
    if (migrationActive(state)) {
      digestTable(hash, state, state.next_offset, state.capacity * 2, SLOT_SIZE_V2);
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
    // Both layouts are accepted: an upgraded set legitimately still carries version 1 until its
    // next grow converts it. Anything else is a genuine mismatch.
    let stored_version = Region.loadNat32(state.region, 8);
    if (stored_version != LAYOUT_VERSION and stored_version != 1) {
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
        state.table_offset + state.capacity * strideOf(state) > state.next_offset or
        state.next_offset > regionCapacity(state)) {
      return #err("stable-set:table-bounds");
    };
    // ---- the window. Every check below is ADDED, none replaced: the four cross-checks and the
    // bounds above still hold verbatim during a window, because table_offset, capacity and
    // next_offset keep describing the old table and next_offset does not move until the window
    // closes. What a window adds is a second table and a cursor, and neither was bounded before.
    let word = Region.loadNat64(state.region, MIGRATION_OFFSET);
    let active = (word & MIGRATION_ACTIVE) != 0;
    let cursor = word & MIGRATION_CURSOR;
    // A COMPACTION window stores its cursor in this same word, flagged by COMPACT_ACTIVE
    // (bit 62), while this check only knew MIGRATION_ACTIVE (bit 63). Mid-compaction it therefore
    // read active=false with a non-zero cursor and declared the word corrupt, so postupgrade
    // trapped with `postupgrade:nullifiers:stable-set:migration-word` and the upgrade was rolled
    // back -- a ledger could not be upgraded at all while a compaction was in flight. The window
    // is legitimate state that compactStep itself writes; recognise it rather than reject it.
    let compacting = (word & COMPACT_ACTIVE) != 0;
    if (active and compacting) return #err("stable-set:migration-compact-both");
    if (not active and not compacting and cursor != 0) return #err("stable-set:migration-word");
    // compactStep finalises and clears the window in the same message the cursor reaches capacity,
    // so a stored compaction cursor at or past the end is corrupt -- the same rule the migration
    // cursor is held to below, not a weaker one.
    if (compacting and cursor >= state.capacity) return #err("stable-set:compact-cursor");
    if (active) {
      // A committed window always has room left to carry: stepMigration closes the window in the
      // same message the cursor reaches the end, so a stored cursor at or past the end is corrupt.
      if (cursor >= state.capacity) return #err("stable-set:migration-cursor");
      if (state.next_offset + state.capacity * 2 * SLOT_SIZE_V2 > regionCapacity(state)) {
        return #err("stable-set:migration-bounds");
      };
    };
    // Measured against the table inserts actually land in, which during a window is the new one.
    // Against the old capacity this would reject a perfectly healthy mid-window set.
    if (state.entry_count * 10 > activeCapacity(state) * 7) return #err("stable-set:load-factor");
    #ok(())
  };

  /// Slot-tag walk over slots [from, min(from+count, capacity_captured)) of a CAPTURED
  /// table (offset + capacity captured at phase start, so a concurrent grow cannot move
  /// the walk mid-phase; the caller detects the move and restarts). Returns the number
  /// of occupied slots seen in the range; same error string as validate()'s walk.
  /// Number of slots a full walk of this set has to visit. Without a window that is the table's
  /// capacity, as it always was. With one it is BOTH tables, because the entries are spread across
  /// them — a walk of the old table alone would count `entry_count` minus everything carried across
  /// so far and report a healthy set as corrupt.
  public func walkWidth(state : State) : Nat64 {
    if (migrationActive(state)) state.capacity * 3 else state.capacity
  };

  /// Byte offset of virtual walk index `index`: the old table first, then the new one.
  func walkOffset(state : State, table_offset_captured : Nat64, index : Nat64) : Nat64 {
    if (migrationActive(state) and index >= state.capacity) {
      slotOffsetAt(state.next_offset, index - state.capacity, SLOT_SIZE_V2)
    } else {
      // MUST dispatch on the compaction cursor, like every other live read. This computed the
      // raw table_offset address, so a walk running while a compaction window was open read slots
      // below the cursor from source bytes already copied down to HEADER_SIZE and, past the overlap
      // point, overwritten. Reachable through the same one-directional guard as the other two:
      // compact_nullifier_set refuses while an audit runs, but restart_audit (Main.mo:1436) has no
      // compaction guard. Fixing the READER covers every caller; a guard on restart_audit would
      // cover only that one. NOTE: this is not the cause of the observed-count audit failure logged
      // on the ledger row -- that reproduces identically with this hunk reverted.
      slotOffsetLive(state, table_offset_captured, index, strideOf(state))
    }
  };

  /// The live keys of one window, for a caller that must INSPECT stored keys rather than count
  /// them. `countTagsRange` loads a slot's tag and counts it; nothing in this module returned key
  /// bytes, which is why a canonicality census over a set could not be written at all.
  ///
  /// Deliberately the same shape as its sibling above: bounded by the caller's `count`, clamped
  /// to the CAPTURED capacity so a walk that starts under one capacity cannot finish under
  /// another, and addressed through `walkOffset` so a walk during an open compaction window reads
  /// the relocated slots. A reader that computed the raw `table_offset` address instead would
  /// read clobbered bytes below the cursor — the defect already recorded against `slotAddress`,
  /// and a new reader is exactly where it would come back.
  ///
  /// Tombstones are skipped. A migrated slot's key lives in the new table and is returned there,
  /// so every live key is yielded exactly once across a full walk and a census cannot double
  /// count. Reads only: no stable variable, no mutation.
  ///
  /// Cost is `count * KEY_SIZE` bytes and nothing else, so a caller can size a window to a
  /// message budget without measuring.
  public func keysRange(
    state : State,
    table_offset_captured : Nat64,
    capacity_captured : Nat64,
    from : Nat64,
    count : Nat64,
  ) : Result<[Blob]> {
    let out = List.empty<Blob>();
    var index = from;
    let end = if (from + count > capacity_captured) capacity_captured else from + count;
    while (index < end) {
      let offset = walkOffset(state, table_offset_captured, index);
      let tag = Region.loadNat8(state.region, offset);
      if (tag == TAG_LIVE) {
        List.add(out, Region.loadBlob(state.region, offset + 1, KEY_SIZE));
      } else if (tag != TAG_EMPTY and tag != TAG_MIGRATED) {
        return #err("stable-set:slot-tag");
      };
      index += 1;
    };
    #ok(List.toArray(out))
  };

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
      let tag = Region.loadNat8(state.region, walkOffset(state, table_offset_captured, index));
      // A tombstone is a valid tag and is NOT counted: its key now lives in the new table and is
      // counted there, exactly once. That is what keeps live_old + live_new == entry_count true at
      // every cursor position rather than only at the ends.
      if (tag == TAG_LIVE) observed += 1
      else if (tag != TAG_EMPTY and tag != TAG_MIGRATED) return #err("stable-set:slot-tag");
      index += 1;
    };
    #ok(observed)
  };

  public func validate(state : State) : Result<()> {
    switch (validateHeader(state)) {
      case (#err(message)) return #err(message);
      case (#ok(_)) {};
    };
    let width = walkWidth(state);
    let observed = switch (countTagsRange(state, state.table_offset, width, 0, width)) {
      case (#err(message)) return #err(message);
      case (#ok(value)) value;
    };
    if (observed != state.entry_count) return #err("stable-set:observed-count");
    #ok(())
  };
};
