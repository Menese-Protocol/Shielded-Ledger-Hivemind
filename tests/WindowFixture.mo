/// Migration-window fixture, test-only.
///
/// Separate from ScaleFixture because ScaleFixture must compile against BOTH the current module and
/// the frozen layout-1 one at tests/layout1 — that is what makes the migration battery a genuine
/// cross-version test — so it may not reference anything the layout-1 module lacks. Everything here
/// calls window functions that exist only in the current module.
///
/// The measurement functions loop INSIDE one call and report per-iteration maxima. A `put` is what a
/// message contains, so the maximum over puts is the maximum over messages; doing it this way is
/// what makes it possible to walk a 2^20 window without one round-trip per key. The only thing it
/// leaves out is the constant per-message overhead, which is the same for every message and so
/// cannot change a ratio.
import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Nat "mo:core/Nat";
import Nat8 "mo:core/Nat8";
import Nat32 "mo:core/Nat32";
import Nat64 "mo:core/Nat64";
import Region "mo:core/Region";
import Runtime "mo:core/Runtime";
import Prim "mo:⛔";
import Sha256 "mo:sha2/Sha256";
import StableBlobSet "../src/StableBlobSet";
import StableLog "../src/StableLog";

persistent actor WindowFixture {
  public type Result<T> = { #ok : T; #err : Text };

  let keys = StableBlobSet.newState();
  StableBlobSet.ensureInit(keys);

  /// A note log, so the waste property can be measured on BOTH structures a PREPARE touches.
  /// The log is the half of the PREPARE hoist list the original design missed, and its
  /// headroom is denominated in bytes rather than slots.
  let log = StableLog.newState();
  StableLog.ensureInit(log);

  /// Tag byte of the key derivation. 9 by default, which is the derivation the other fixtures use,
  /// so every number already measured is reproduced unchanged at the default.
  ///
  /// It is settable so the confound below can be varied. Every rung in the base measurement is a single draw from the
  /// longest-probe-chain distribution for ONE key set, and no amount of re-running that key set
  /// reveals the spread of that draw. Changing the tag changes which keys, which is the confound
  /// that fixing the number of samples does not remove.
  var key_seed : Nat8 = 9;

  public func set_key_seed(value : Nat8) : async () { key_seed := value };
  public query func key_seed_now() : async Nat8 { key_seed };

  func corpusKey(index : Nat) : Blob {
    let seed = Blob.fromArray(Array.tabulate<Nat8>(9, func(i) {
      if (i == 0) key_seed else Nat8.fromNat((index / (256 ** (i - 1))) % 256)
    }));
    Sha256.fromBlob(#sha256, seed)
  };

  public type Window = {
    active : Bool;
    cursor : Nat64;
    capacity : Nat64;
    active_capacity : Nat64;
    entries : Nat64;
    walk_width : Nat64;
    stride : Nat64;
    forced : Nat32;
    steps_needed : Nat64;
    puts_available : Nat64;
  };

  func windowNow() : Window {
    let (steps, available) = StableBlobSet.stepBound(keys);
    {
      active = StableBlobSet.migrationActive(keys);
      cursor = StableBlobSet.migrationCursor(keys);
      capacity = keys.capacity;
      active_capacity = StableBlobSet.activeCapacity(keys);
      entries = keys.entry_count;
      walk_width = StableBlobSet.walkWidth(keys);
      stride = StableBlobSet.activeStride(keys);
      forced = StableBlobSet.forcedCompletions(keys);
      steps_needed = steps;
      puts_available = available;
    }
  };

  public query func window() : async Window { windowNow() };

  public type Walk = {
    puts : Nat;
    max_instr : Nat64;
    max_alloc : Nat;
    /// Which put was the most expensive, and the maximum over only the FIRST `sample` puts.
    ///
    /// Both exist because a raw maximum over a whole window is not comparable between rungs: a
    /// bigger window is a bigger sample, and the maximum of more samples is larger even when the
    /// distribution is identical. `max_first` fixes the sample size so the comparison is
    /// apples-to-apples, and `sum_instr` gives the mean, which is the deterministic per-put cost
    /// with no maximum-of-samples effect in it at all.
    max_index : Nat;
    max_first : Nat64;
    /// The 99th-percentile per-put cost across the whole window. This is the SHAPE metric: max is
    /// legitimately spiky under any amortised scheme (one put lands the migration or reclaim slice),
    /// so the max jumps on noise; p99 is stable and is what must not scale with N.
    p99_instr : Nat64;
    sum_instr : Nat64;
    open_instr : Nat64;
    open_alloc : Nat;
    close_instr : Nat64;
    close_alloc : Nat;
    opened : Bool;
    closed : Bool;
    after : Window;
  };

  /// Measure the two atomic region ops the reclaim ceiling is derived from: one storeNat64 (zero a
  /// word) and one loadBlob(41)+storeBlob(41) (relocate a slot). Returns mean instr/op over `n`. These
  /// are implementation constants, so multiplying them by the op COUNTS a COMPACT_MAX_BYTES reclaim
  /// implies gives a first-principles ceiling — not a measured max plus a fudge factor.
  public func measure_region_ops(n : Nat) : async (Nat64, Nat64) {
    let r = Region.new();
    ignore Region.grow(r, 4); // 256 KiB scratch
    let m = Nat64.fromNat(n);
    let c0 = Prim.performanceCounter(0);
    var i : Nat64 = 0;
    while (i < m) { Region.storeNat64(r, (i % 8192) * 8, 0); i += 1 };
    let c1 = Prim.performanceCounter(0);
    var j : Nat64 = 0;
    while (j < m) { let b = Region.loadBlob(r, 0, 41); Region.storeBlob(r, 65536 + (j % 1024) * 41, b); j += 1 };
    let c2 = Prim.performanceCounter(0);
    (if (m == 0) 0 else (c1 - c0) / m, if (m == 0) 0 else (c2 - c1) / m)
  };

  /// Put `count` keys, measuring EVERY put separately, and report the maxima plus the two messages
  /// that matter on their own: the one that opens a window (which allocates the whole new table) and
  /// the one that closes it.
  public func window_walk(from : Nat, count : Nat, sample : Nat) : async Walk {
    var max_instr : Nat64 = 0;
    var max_index : Nat = 0;
    var max_first : Nat64 = 0;
    var sum_instr : Nat64 = 0;
    var max_alloc : Nat = 0;
    var open_instr : Nat64 = 0;
    var open_alloc : Nat = 0;
    var close_instr : Nat64 = 0;
    var close_alloc : Nat = 0;
    var opened = false;
    var closed = false;
    // Every per-put cost, so a true percentile can be taken rather than just the maximum.
    let costs = Prim.Array_init<Nat64>(count, 0 : Nat64);
    var i = 0;
    while (i < count) {
      let was_active = StableBlobSet.migrationActive(keys);
      let a0 = Prim.rts_total_allocation();
      let c0 = Prim.performanceCounter(0);
      switch (StableBlobSet.put(keys, corpusKey(from + i))) {
        case (#err(message)) Runtime.trap("fixture: " # message);
        case (_) {};
      };
      let c1 = Prim.performanceCounter(0);
      let a1 = Prim.rts_total_allocation();
      let instr = c1 - c0;
      let alloc = a1 - a0;
      let is_active = StableBlobSet.migrationActive(keys);
      costs[i] := instr;
      if (instr > max_instr) { max_instr := instr; max_index := i };
      if (i < sample and instr > max_first) max_first := instr;
      sum_instr += instr;
      if (alloc > max_alloc) max_alloc := alloc;
      if (not was_active and is_active) { opened := true; open_instr := instr; open_alloc := alloc };
      if (was_active and not is_active) { closed := true; close_instr := instr; close_alloc := alloc };
      i += 1;
    };
    // p99 = the per-put cost the 99th percentile falls at, sorted ascending.
    let sorted = Array.sort<Nat64>(Array.fromVarArray<Nat64>(costs), Nat64.compare);
    let p99_instr : Nat64 = if (count == 0) 0 else sorted[Nat.min((count * 99) / 100, count - 1 : Nat)];
    {
      puts = count;
      max_instr; max_alloc; max_index; max_first; p99_instr; sum_instr;
      open_instr; open_alloc; close_instr; close_alloc;
      opened; closed;
      after = windowNow();
    }
  };

  /// Membership over the corpus [0, corpus) and over `controls` keys that were never inserted.
  /// Returns (false_negatives, false_positives). Both must be zero at every cursor position.
  public query func membership(corpus : Nat, controls : Nat) : async (Nat, Nat) {
    var missing = 0;
    var ghosts = 0;
    var i = 0;
    while (i < corpus) {
      if (not StableBlobSet.contains(keys, corpusKey(i))) missing += 1;
      i += 1;
    };
    i := 0;
    while (i < controls) {
      if (StableBlobSet.contains(keys, corpusKey(5_000_000 + i))) ghosts += 1;
      i += 1;
    };
    (missing, ghosts)
  };

  /// Paged halves of `membership`, because a query is capped at 5e9 instructions and a corpus of
  /// 100,000 keys is roughly 3e9 on its own — a whole-corpus call fails, and a battery that reads
  /// numbers out of the failure reply gets nonsense that looks like a result.
  public query func missing_in(from : Nat, count : Nat) : async Nat {
    var missing = 0;
    var i = 0;
    while (i < count) {
      if (not StableBlobSet.contains(keys, corpusKey(from + i))) missing += 1;
      i += 1;
    };
    missing
  };

  public query func ghosts_in(from : Nat, count : Nat) : async Nat {
    var ghosts = 0;
    var i = 0;
    while (i < count) {
      if (StableBlobSet.contains(keys, corpusKey(5_000_000 + from + i))) ghosts += 1;
      i += 1;
    };
    ghosts
  };

  /// Cost of `count` membership probes, for the open-window overhead measurement.
  public query func membership_cost(from : Nat, count : Nat) : async (Nat64, Nat) {
    var present = 0;
    let c0 = Prim.performanceCounter(0);
    var i = 0;
    while (i < count) {
      if (StableBlobSet.contains(keys, corpusKey(from + i))) present += 1;
      i += 1;
    };
    (Prim.performanceCounter(0) - c0, present)
  };

  /// One explicit advance. Returns (closed, instructions, allocated).
  public func advance(budget : Nat64) : async (Bool, Nat64, Nat) {
    let a0 = Prim.rts_total_allocation();
    let c0 = Prim.performanceCounter(0);
    let closed = StableBlobSet.advanceMigration(keys, budget);
    let c1 = Prim.performanceCounter(0);
    (closed, c1 - c0, Prim.rts_total_allocation() - a0)
  };

  /// Put a range and then trap, so a message that carried slots across fails after the fact. The
  /// lever for rollback durability: what must survive is not a simulated rollback but a real one.
  public func put_then_trap(from : Nat, count : Nat) : async () {
    var i = 0;
    while (i < count) {
      switch (StableBlobSet.put(keys, corpusKey(from + i))) {
        case (#err(message)) Runtime.trap("fixture: " # message);
        case (_) {};
      };
      i += 1;
    };
    Runtime.trap("TEST_ONLY:interrupted-window");
  };

  /// Advance and then trap, for the same reason on the explicit path.
  public func advance_then_trap(budget : Nat64) : async () {
    ignore StableBlobSet.advanceMigration(keys, budget);
    Runtime.trap("TEST_ONLY:interrupted-advance");
  };

  public func put_range(from : Nat, count : Nat) : async Result<Nat> {
    var added = 0;
    var i = 0;
    while (i < count) {
      switch (StableBlobSet.put(keys, corpusKey(from + i))) {
        case (#ok(true)) added += 1;
        case (#ok(false)) {};
        case (#err(message)) return #err(message);
      };
      i += 1;
    };
    #ok(added)
  };

  // Updates, not queries: both walk BOTH tables during a window, which at capacity 2^18 is about
  // 786,000 slots — past a query's 5e9 ceiling, where they fail rather than answer.
  public func validate() : async Result<()> { StableBlobSet.validate(keys) };

  /// Cheney invariant 4 witness surface. The compaction window is the sibling of the migration
  /// window and had no way to be driven or observed from a fixture, which is why the interleaving
  /// looked unreachable. These mirror the migration-side accessors exactly and add nothing else.
  public func compact_step(budget : Nat64) : async Bool {
    StableBlobSet.compactStep(keys, budget)
  };

  public query func compaction() : async (Bool, Nat64, Nat64, Nat64) {
    let (cap, entries, table_offset, next_offset) = StableBlobSet.layoutOf(keys);
    ignore cap; ignore entries;
    (StableBlobSet.compactionActive(keys), StableBlobSet.compactCursor(keys), table_offset, next_offset)
  };
  public func digest() : async Blob { StableBlobSet.digest(keys) };
  public query func header_ok() : async Result<()> { StableBlobSet.validateHeader(keys) };

  // ==== header perturbation =====================================================================
  // validateHeader is judged by whether it REJECTS a corrupted header, so the battery has to be able
  // to corrupt one. These write the region directly, which is exactly what a corruption is.

  public query func read_header(offset : Nat64) : async Nat64 { Region.loadNat64(keys.region, offset) };

  public func poke_header(offset : Nat64, value : Nat64) : async () {
    Region.storeNat64(keys.region, offset, value);
  };

  /// Corrupt a header word, ask validateHeader for a verdict, and put the word back — all inside one
  /// message, so a perturbation can never survive into a later leg of the battery.
  public func probe_header(offset : Nat64, value : Nat64) : async Result<()> {
    let saved = Region.loadNat64(keys.region, offset);
    Region.storeNat64(keys.region, offset, value);
    let verdict = StableBlobSet.validateHeader(keys);
    Region.storeNat64(keys.region, offset, saved);
    verdict
  };

  /// Same, for a slot tag: the walk must reject a tag that is neither empty, live nor tombstoned.
  public func probe_slot_tag(index : Nat64, tag : Nat8) : async Result<()> {
    let offset = keys.table_offset + index * StableBlobSet.activeStride(keys);
    let saved = Region.loadNat8(keys.region, offset);
    Region.storeNat8(keys.region, offset, tag);
    let verdict = StableBlobSet.validate(keys);
    Region.storeNat8(keys.region, offset, saved);
    verdict
  };

  public query func size() : async Nat { StableBlobSet.size(keys) };

  // ==== headroom is a predicate, so a repeated PREPARE grows nothing ==========================

  public func ensure_set_headroom(k : Nat64) : async Result<()> { StableBlobSet.ensureHeadroom(keys, k) };

  public func ensure_log_headroom(bytes : Nat64, entries : Nat64) : async Result<()> {
    StableLog.ensureHeadroom(log, bytes, entries)
  };

  /// (set region bytes, log data-region bytes, log index-region bytes) — the three quantities a
  /// leaking reservation would move on every attempt.
  public query func footprint() : async (Nat, Nat, Nat) {
    let (d, i) = StableLog.regionBytes(log);
    (StableBlobSet.bytesAllocated(keys), d, i)
  };

  /// A PREPARE-shaped cycle that then ABORTS: reserve for two nullifiers, one root, one completed
  /// entry and two note appends, and return without committing anything.
  public func prepare_then_abort(bytes : Nat64) : async Result<()> {
    switch (StableBlobSet.ensureHeadroom(keys, 4)) { case (#err(m)) return #err(m); case (_) {} };
    StableLog.ensureHeadroom(log, bytes, 2)
  };
}
