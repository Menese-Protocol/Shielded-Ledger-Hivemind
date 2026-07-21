/// PIR v2 — SimplePIR-shaped private retrieval over the note log, preprocessed BY the ledger.
///
/// The note log is projected into fixed 288-byte records (commitment(32) ‖
/// note_ciphertext[0..256) zero-padded), arranged per shard as an m_rows × m_cols byte matrix
/// in column-major record fill. The LWE hint H = D·A is maintained incrementally: each append
/// folds one column segment into H (a bounded region, independent of database size), so there
/// is no offline preprocessing step — the append path IS the preprocessor. Queries are plain
/// integer matrix-vector products over public column-range stripes whose bounds are functions
/// of (fill, stripe) only; the scan touches every cell in bounds and never branches on
/// ciphertext content.
///
/// Scheme constants (docs/PIR-SPEC.md v2): n = 1024, q = 2^32 (wrapping u32), p = 2^8,
/// Δ = 2^24, noise σ = 6.4 (client-side), uniform Z_q secret, fresh per query. The public
/// matrix A is expanded from a fixed domain-separated SHA-256 counter construction — never
/// chosen by anyone, never shipped: block k of column c in shard s is
/// SHA-256("zk-ledger/pir2/v1/A" ‖ s_le64 ‖ c_le64 ‖ k_le64), consumed as 8 little-endian
/// u32 words; n/8 = 128 blocks exactly.
///
/// Storage: three stable Regions (packed cells D, hints H, stream-chain boundary digests),
/// each with magic + layout-version headers in the StableLog discipline. Every u32 vector on
/// the wire is a little-endian byte Blob.

import Array "mo:core/Array";
import Blob "mo:core/Blob";
import List "mo:core/List";
import Nat "mo:core/Nat";
import Nat8 "mo:core/Nat8";
import Nat64 "mo:core/Nat64";
import Region "mo:core/Region";
import Runtime "mo:core/Runtime";
import VarArray "mo:core/VarArray";
import Prim "mo:⛔";
import Sha256 "mo:sha2/Sha256";

module {
  public let LWE_N : Nat = 1024;
  public let DELTA : Nat64 = 16_777_216; // 2^24
  public let RECORD_BYTES : Nat = 288;
  public let COMMITMENT_BYTES : Nat = 32;
  public let ENVELOPE_BYTES : Nat = 256;
  public let DPAGE : Nat = 4096; // records per certified chain boundary
  public let A_DOMAIN : Blob = "zk-ledger/pir2/v1/A";

  let PAGE_SIZE : Nat64 = 65_536;
  let HDR : Nat64 = 16; // 8-byte magic + 4-byte layout version + 4 reserved
  let LAYOUT_VERSION : Nat32 = 1;
  let D_MAGIC : Blob = "\5a\4b\50\44\41\54\30\31"; // ZKPDAT01
  let H_MAGIC : Blob = "\5a\4b\50\48\4e\54\30\31"; // ZKPHNT01
  let C_MAGIC : Blob = "\5a\4b\50\43\48\4e\30\31"; // ZKPCHN01
  let OUT_OF_MEMORY : Nat64 = 0xffff_ffff_ffff_ffff;

  public type State = {
    d_region : Region.Region;
    h_region : Region.Region;
    c_region : Region.Region;
    var enabled : Bool;
    var shard_size : Nat;
    var record_count : Nat;
    var chain : Blob;
    var boundary_count : Nat;
    var initialized : Bool;
  };

  public type Geometry = {
    shard_size : Nat;
    records_per_column : Nat;
    m_rows : Nat;
    m_cols : Nat;
  };

  public type StripeTrace = {
    cells_scanned : Nat;
    columns_scanned : Nat;
    selector_decryptions : Nat;
    target_index_parameters : Nat;
    target_dependent_branches : Nat;
    instructions : Nat64;
  };

  public func newState() : State {
    {
      d_region = Region.new();
      h_region = Region.new();
      c_region = Region.new();
      var enabled = false;
      var shard_size = 0;
      var record_count = 0;
      var chain = Blob.fromArray(Array.repeat<Nat8>(0, 32));
      var boundary_count = 0;
      var initialized = false;
    }
  };

  func ensureCapacity(region : Region.Region, needed : Nat64) {
    let current = Region.size(region) * PAGE_SIZE;
    if (needed <= current) return;
    let pages = (needed - current + PAGE_SIZE - 1) / PAGE_SIZE;
    if (Region.grow(region, pages) == OUT_OF_MEMORY) Runtime.trap("pir2: out of stable memory");
  };

  func initRegion(region : Region.Region, magic : Blob) {
    ensureCapacity(region, HDR);
    Region.storeBlob(region, 0, magic);
    Region.storeNat32(region, 8, LAYOUT_VERSION);
    Region.storeNat32(region, 12, 0);
  };

  func checkRegion(region : Region.Region, magic : Blob) : Bool {
    Region.size(region) > 0 and Region.loadBlob(region, 0, 8) == magic and
      Region.loadNat32(region, 8) == LAYOUT_VERSION
  };

  /// One-shot arming. A repeat call traps: the shard size (and with it every derived
  /// geometry constant and stored layout) is immutable for the lifetime of the deployment.
  public func enable(state : State, shardSize : Nat) {
    if (state.enabled) Runtime.trap("pir2: already enabled");
    if (shardSize == 0) Runtime.trap("pir2: shard size must be positive");
    state.shard_size := shardSize;
    initRegion(state.d_region, D_MAGIC);
    initRegion(state.h_region, H_MAGIC);
    initRegion(state.c_region, C_MAGIC);
    state.initialized := true;
    state.enabled := true;
  };

  /// Post-upgrade O(1) structural check, StableLog-style: headers must match when enabled.
  public func headersValid(state : State) : Bool {
    if (not state.enabled) return true;
    checkRegion(state.d_region, D_MAGIC) and checkRegion(state.h_region, H_MAGIC) and
      checkRegion(state.c_region, C_MAGIC)
  };

  // ==== geometry (normative integer definition; no floats anywhere) ====

  /// Exact floor integer square root (Newton).
  public func isqrt(v : Nat) : Nat {
    if (v < 2) return v;
    var x = v;
    var y = (x + 1) / 2;
    while (y < x) { x := y; y := (x + v / x) / 2 };
    x
  };

  /// rpc = max(1, (isqrt(S·R) + R/2) div R); m_rows = R·rpc; m_cols = ceil(S/rpc).
  public func geometry(shardSize : Nat) : Geometry {
    let rpc0 = (isqrt(shardSize * RECORD_BYTES) + RECORD_BYTES / 2) / RECORD_BYTES;
    let rpc = if (rpc0 == 0) 1 else rpc0;
    {
      shard_size = shardSize;
      records_per_column = rpc;
      m_rows = RECORD_BYTES * rpc;
      m_cols = (shardSize + rpc - 1) / rpc;
    }
  };

  /// In-shard record index -> (column, first row of its 288-row segment).
  public func place(g : Geometry, indexInShard : Nat) : (Nat, Nat) {
    (indexInShard / g.records_per_column, RECORD_BYTES * (indexInShard % g.records_per_column))
  };

  public func pinnedColumns(g : Geometry, fill : Nat) : Nat {
    (fill + g.records_per_column - 1) / g.records_per_column
  };

  /// Row bound for column c under pin `fill` — a public function of (fill, c), never of a
  /// query's target.
  public func pinnedRows(g : Geometry, fill : Nat, c : Nat) : Nat {
    let fullCols = fill / g.records_per_column;
    if (c < fullCols) g.m_rows
    else if (c == fullCols) RECORD_BYTES * (fill % g.records_per_column)
    else 0
  };

  /// Records currently in shard s (derived, no extra state).
  public func shardFill(state : State, shard : Nat) : Nat {
    if (state.record_count <= shard * state.shard_size) return 0;
    Nat.min(state.record_count - shard * state.shard_size, state.shard_size)
  };

  public func shardCount(state : State) : Nat {
    if (state.record_count == 0) 0
    else (state.record_count + state.shard_size - 1) / state.shard_size
  };

  /// A shard is frozen (immutable forever, hint downloadable) once completely filled.
  public func isFrozen(state : State, shard : Nat) : Bool {
    shardFill(state, shard) == state.shard_size
  };

  // ==== region addressing ====

  public func hintBytesPerShard(g : Geometry) : Nat64 {
    Nat64.fromNat(g.m_rows * LWE_N * 4)
  };

  public func dShardBase(g : Geometry, shard : Nat) : Nat64 {
    HDR + Nat64.fromNat(shard * g.m_rows * g.m_cols)
  };

  public func dCellOffset(g : Geometry, shard : Nat, c : Nat, r : Nat) : Nat64 {
    dShardBase(g, shard) + Nat64.fromNat(c * g.m_rows + r)
  };

  public func hRowOffset(g : Geometry, shard : Nat, r : Nat) : Nat64 {
    HDR + Nat64.fromNat(shard) * hintBytesPerShard(g) + Nat64.fromNat(r * LWE_N * 4)
  };

  // ==== A expansion ====

  func le64(v : Nat) : [Nat8] {
    Array.tabulate<Nat8>(8, func(i) { Nat8.fromNat((v / (256 ** i)) % 256) })
  };

  /// A[c, 8k .. 8k+8) — one SHA-256 block of the fixed public matrix.
  func aBlock(shard : Nat, c : Nat, k : Nat) : Blob {
    let seed = List.empty<Nat8>();
    for (byte in A_DOMAIN.values()) List.add(seed, byte);
    for (byte in le64(shard).values()) List.add(seed, byte);
    for (byte in le64(c).values()) List.add(seed, byte);
    for (byte in le64(k).values()) List.add(seed, byte);
    Sha256.fromBlob(#sha256, Blob.fromArray(List.toArray(seed)))
  };

  /// Expand A[c, :] into a caller-owned arena (LWE_N Nat32 slots at `offset`).
  public func aRowInto(shard : Nat, c : Nat, out : [var Nat32], offset : Nat) {
    var k = 0;
    var w = 0;
    while (k < LWE_N / 8) {
      let block = Blob.toArray(aBlock(shard, c, k));
      var i = 0;
      while (i < 8) {
        let b0 = Nat8.toNat(block[4 * i]);
        let b1 = Nat8.toNat(block[4 * i + 1]);
        let b2 = Nat8.toNat(block[4 * i + 2]);
        let b3 = Nat8.toNat(block[4 * i + 3]);
        out[offset + w] := Prim.natToNat32(b0 + 256 * (b1 + 256 * (b2 + 256 * b3)));
        w += 1;
        i += 1;
      };
      k += 1;
    };
  };

  // ==== record packing + append-path maintenance ====

  /// commitment(32) ‖ envelope[0..256) zero-padded; an oversized envelope truncates in its
  /// own record only (a public function of public sizes — the owner detects the truncated
  /// Poly1305 and falls back to the camouflaged page fetch).
  public func packRecord(commitment : Blob, envelope : Blob) : [Nat8] {
    if (commitment.size() != COMMITMENT_BYTES) Runtime.trap("pir2: bad commitment size");
    let record = Prim.Array_init<Nat8>(RECORD_BYTES, 0);
    let cm = Blob.toArray(commitment);
    var i = 0;
    while (i < COMMITMENT_BYTES) { record[i] := cm[i]; i += 1 };
    let env = Blob.toArray(envelope);
    let take = Nat.min(env.size(), ENVELOPE_BYTES);
    var j = 0;
    while (j < take) { record[COMMITMENT_BYTES + j] := env[j]; j += 1 };
    Array.fromVarArray(record)
  };

  /// Append one record at the next position: write its cells once, fold its column segment
  /// into H, and advance the certified stream chain. The touched hint region is one column
  /// segment (288 rows × n words) regardless of database size.
  public func append(state : State, commitment : Blob, envelope : Blob) {
    if (not state.enabled) Runtime.trap("pir2: not enabled");
    let g = geometry(state.shard_size);
    let idx = state.record_count;
    let shard = idx / state.shard_size;
    let (c, r0) = place(g, idx % state.shard_size);
    let record = packRecord(commitment, envelope);
    let recordBlob = Blob.fromArray(record);

    // cells: one contiguous 288-byte store
    let cellOffset = dCellOffset(g, shard, c, r0);
    ensureCapacity(state.d_region, cellOffset + Nat64.fromNat(RECORD_BYTES));
    Region.storeBlob(state.d_region, cellOffset, recordBlob);

    // hint fold: H[r, :] += cell(r) · A[c, :] for the segment's rows, as word-wise region
    // read-modify-write in pure Nat32 (the madd IS mod 2^32 — no widening). Measured against
    // a span-load/heap-fold/span-store variant: word-wise costs more raw instructions but
    // allocates ~15x less (2.25 MB vs 35 MB per append), and per-append allocation is the
    // scarcer budget on this ledger (EOP churn); the bound is committed from the probe.
    ensureCapacity(state.h_region, hRowOffset(g, shard, g.m_rows));
    let a = VarArray.repeat<Nat32>(0, LWE_N);
    aRowInto(shard, c, a, 0);
    var i = 0;
    while (i < RECORD_BYTES) {
      let cell : Nat32 = Prim.nat16ToNat32(Prim.nat8ToNat16(record[i]));
      if (cell != 0) {
        let rowOff = hRowOffset(g, shard, r0 + i);
        var j = 0;
        while (j < LWE_N) {
          let byteOff = rowOff + Nat64.fromNat(4 * j);
          Region.storeNat32(state.h_region, byteOff,
            Region.loadNat32(state.h_region, byteOff) +% cell *% a[j]);
          j += 1;
        };
      };
      i += 1;
    };

    // certified stream chain: chain := SHA-256(chain ‖ cells); boundary every DPAGE records
    let chainInput = List.empty<Nat8>();
    for (byte in state.chain.values()) List.add(chainInput, byte);
    for (byte in record.values()) List.add(chainInput, byte);
    state.chain := Sha256.fromBlob(#sha256, Blob.fromArray(List.toArray(chainInput)));
    state.record_count += 1;
    if (state.record_count % DPAGE == 0) {
      let off = HDR + Nat64.fromNat(state.boundary_count * 32);
      ensureCapacity(state.c_region, off + 32);
      Region.storeBlob(state.c_region, off, state.chain);
      state.boundary_count += 1;
    };
  };

  // ==== query path ====

  func wireToU32(blob : Blob) : [Nat32] {
    let bytes = Blob.toArray(blob);
    if (bytes.size() % 4 != 0) Runtime.trap("pir2: wire length must be a multiple of 4");
    Array.tabulate<Nat32>(bytes.size() / 4, func(i) {
      let b0 = Nat8.toNat(bytes[4 * i]);
      let b1 = Nat8.toNat(bytes[4 * i + 1]);
      let b2 = Nat8.toNat(bytes[4 * i + 2]);
      let b3 = Nat8.toNat(bytes[4 * i + 3]);
      Prim.natToNat32(b0 + 256 * (b1 + 256 * (b2 + 256 * b3)))
    })
  };

  func u32ToWire(words : [var Nat32]) : Blob {
    let out = Prim.Array_init<Nat8>(words.size() * 4, 0);
    var i = 0;
    while (i < words.size()) {
      let w = Prim.nat32ToNat64(words[i]);
      out[4 * i] := Nat8.fromNat(Nat64.toNat(w & 0xFF));
      out[4 * i + 1] := Nat8.fromNat(Nat64.toNat((w >> 8) & 0xFF));
      out[4 * i + 2] := Nat8.fromNat(Nat64.toNat((w >> 16) & 0xFF));
      out[4 * i + 3] := Nat8.fromNat(Nat64.toNat((w >> 24) & 0xFF));
      i += 1;
    };
    Blob.fromArray(Array.fromVarArray(out))
  };

  /// One stripe of the matvec: ans[r] += D[r, c] · qu[c] over the stripe's pinned columns.
  /// Bounds are public functions of (fill, stripe, kCols); every in-bounds cell is touched
  /// exactly once; nothing branches on ciphertext content. Returns the dense partial vector
  /// (the client accumulates stripes) plus the per-stripe trace the privacy battery asserts.
  public func answerStripe(
    state : State,
    shard : Nat,
    fill : Nat,
    stripe : Nat,
    kCols : Nat,
    quWire : Blob,
  ) : (Blob, StripeTrace) {
    let c0 = Prim.performanceCounter(0);
    if (not state.enabled) Runtime.trap("pir2: not enabled");
    if (kCols == 0) Runtime.trap("pir2: stripe width must be positive");
    if (fill == 0 or fill > shardFill(state, shard)) Runtime.trap("pir2: pin beyond fill");
    let g = geometry(state.shard_size);
    let cols = pinnedColumns(g, fill);
    let qu = wireToU32(quWire);
    if (qu.size() != cols) Runtime.trap("pir2: query length must equal pinned columns");
    let start = stripe * kCols;
    if (start >= cols) Runtime.trap("pir2: stripe beyond pinned columns");
    let end = Nat.min(start + kCols, cols);

    // Pure-Nat32 inner loop — the measured winner (283 instr/madd) of the seven-variant
    // on-replica micro-bench (tests/Pir2MicroBench.mo): [var Nat32] accumulator, direct
    // nat8→nat16→nat32 cell widening, native wrapping madd, no Nat64 anywhere.
    let ans = VarArray.repeat<Nat32>(0, g.m_rows);
    var cellsScanned = 0;
    var c = start;
    while (c < end) {
      let rows = pinnedRows(g, fill, c);
      if (rows > 0) {
        let colBytes = Blob.toArray(Region.loadBlob(state.d_region, dCellOffset(g, shard, c, 0), rows));
        let quC = qu[c];
        var r = 0;
        while (r < rows) {
          ans[r] := ans[r] +% Prim.nat16ToNat32(Prim.nat8ToNat16(colBytes[r])) *% quC;
          r += 1;
        };
        cellsScanned += rows;
      };
      c += 1;
    };
    let c1 = Prim.performanceCounter(0);
    (
      u32ToWire(ans),
      {
        cells_scanned = cellsScanned;
        columns_scanned = end - start;
        selector_decryptions = 0;
        target_index_parameters = 0;
        target_dependent_branches = 0;
        instructions = c1 - c0;
      },
    )
  };

  /// Densely packed record stream: (position 8B BE ‖ 288 cells) per record — 296 B/note,
  /// sliced from packed cells with no decode. The caller applies the icrc3-style total cap.
  public func recordStream(state : State, start : Nat, count : Nat) : Blob {
    if (not state.enabled) Runtime.trap("pir2: not enabled");
    let g = geometry(state.shard_size);
    let out = List.empty<Nat8>();
    let end = Nat.min(start + count, state.record_count);
    var i = start;
    while (i < end) {
      var k : Nat = 8;
      while (k > 0) { k -= 1; List.add(out, Nat8.fromNat((i / (256 ** k)) % 256)) };
      let shard = i / state.shard_size;
      let (c, r0) = place(g, i % state.shard_size);
      let cells = Blob.toArray(Region.loadBlob(state.d_region, dCellOffset(g, shard, c, r0), RECORD_BYTES));
      for (byte in cells.values()) List.add(out, byte);
      i += 1;
    };
    Blob.fromArray(List.toArray(out))
  };

  /// Hint bytes for a FROZEN shard only (the tail hint is never served: clients compute it
  /// from the certified record stream, so downloadable hints never mutate).
  public func hintChunk(state : State, shard : Nat, offset : Nat, len : Nat) : Blob {
    if (not state.enabled) Runtime.trap("pir2: not enabled");
    if (not isFrozen(state, shard)) Runtime.trap("pir2: hint served for frozen shards only");
    let g = geometry(state.shard_size);
    let total = Nat64.toNat(hintBytesPerShard(g));
    if (offset >= total) Runtime.trap("pir2: hint offset beyond shard");
    let take = Nat.min(len, total - offset);
    Region.loadBlob(state.h_region, hRowOffset(g, shard, 0) + Nat64.fromNat(offset), take)
  };

  /// Latest certified chain boundary (digest, records covered) — the anchor a streaming
  /// client verifies its recomputed chain against.
  public func latestBoundary(state : State) : ?(Blob, Nat) {
    if (state.boundary_count == 0) return null;
    let off = HDR + Nat64.fromNat((state.boundary_count - 1) * 32);
    ?(Region.loadBlob(state.c_region, off, 32), state.boundary_count * DPAGE)
  };
}
