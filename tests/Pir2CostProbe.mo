/// MEASUREMENT + DIFFERENTIAL HARNESS for the PIR v2 module — TEST/HARNESS INFRASTRUCTURE
/// ONLY, never installed as the ledger; no production canister imports it. Same discipline as
/// AuditCostProbe.mo / ReadPathProbe.mo: expose the EXACT production module (src/Pir2.mo) on
/// a bare actor so the Rust driver can (a) measure real on-replica costs — append-path hint
/// maintenance, stripe matvec instructions, wire sizes — and (b) byte-compare every server
/// answer against the independent Rust reference (soak/src/pir2.rs) over seeded corpora.
///
/// The driver supplies record bytes explicitly (commitment ‖ envelope), so the corpus is
/// built once in Rust and fed to both implementations — no cross-language synthesis to drift.

import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Nat "mo:core/Nat";
import Nat8 "mo:core/Nat8";
import Nat64 "mo:core/Nat64";
import Region "mo:core/Region";
import VarArray "mo:core/VarArray";
import Prim "mo:⛔";
import Pir2 "../src/Pir2";

persistent actor Pir2CostProbe {
  let state = Pir2.newState();
  var heap_sink : Nat64 = 0;

  public func enable(shardSize : Nat) : async () {
    Pir2.enable(state, shardSize);
  };

  public query func geometry_info() : async (Nat, Nat, Nat) {
    let g = Pir2.geometry(state.shard_size);
    (g.records_per_column, g.m_rows, g.m_cols)
  };

  public func bulk_append(records : [(Blob, Blob)]) : async Nat {
    for ((commitment, envelope) in records.values()) {
      Pir2.append(state, commitment, envelope);
    };
    state.record_count
  };

  /// Append with cost telemetry: (instructions, allocated bytes, heap delta) for the whole
  /// batch — the append-maintenance bound comes from this, measured on-replica.
  public func append_measured(records : [(Blob, Blob)]) : async (Nat64, Nat, Int) {
    let a0 = Prim.rts_total_allocation();
    let h0 = Prim.rts_heap_size();
    let c0 = Prim.performanceCounter(0);
    for ((commitment, envelope) in records.values()) {
      Pir2.append(state, commitment, envelope);
    };
    let c1 = Prim.performanceCounter(0);
    let a1 = Prim.rts_total_allocation();
    let h1 = Prim.rts_heap_size();
    (c1 - c0, a1 - a0, h1 - h0)
  };

  public query func answer_stripe(shard : Nat, fill : Nat, stripe : Nat, kCols : Nat, qu : Blob)
    : async (Blob, Pir2.StripeTrace) {
    Pir2.answerStripe(state, shard, fill, stripe, kCols, qu)
  };

  /// The same stripe as an update call — measures the matvec in DTS context (the metered
  /// deployment dial the spec documents).
  public func answer_stripe_update(shard : Nat, fill : Nat, stripe : Nat, kCols : Nat, qu : Blob)
    : async (Blob, Pir2.StripeTrace) {
    Pir2.answerStripe(state, shard, fill, stripe, kCols, qu)
  };

  /// TEETH for the S-1 instruction-equality privacy gate — the FORBIDDEN shape: a branch on
  /// query content (skip columns whose qu word has a zero low bit), which makes the executed
  /// instruction count a function of the ciphertext the client sent. The differential's gate
  /// must DETECT this variant (unequal `instructions` across queries) while the production
  /// `answerStripe` stays exactly equal. Answers from this endpoint are garbage by design;
  /// only the trace matters. Implemented HERE, in harness code — the production module never
  /// contains a leaky path.
  public query func answer_stripe_leaky(shard : Nat, fill : Nat, stripe : Nat, kCols : Nat, qu : Blob)
    : async (Blob, Pir2.StripeTrace) {
    let c0 = Prim.performanceCounter(0);
    let g = Pir2.geometry(state.shard_size);
    let cols = Pir2.pinnedColumns(g, fill);
    let bytes = Blob.toArray(qu);
    let quWords = Array.tabulate<Nat32>(bytes.size() / 4, func(i) {
      let b0 = Nat8.toNat(bytes[4 * i]);
      let b1 = Nat8.toNat(bytes[4 * i + 1]);
      let b2 = Nat8.toNat(bytes[4 * i + 2]);
      let b3 = Nat8.toNat(bytes[4 * i + 3]);
      Prim.natToNat32(b0 + 256 * (b1 + 256 * (b2 + 256 * b3)))
    });
    let start = stripe * kCols;
    let end = Nat.min(start + kCols, cols);
    let ans = VarArray.repeat<Nat32>(0, g.m_rows);
    var cellsScanned = 0;
    var c = start;
    while (c < end) {
      let quC = quWords[c];
      // FORBIDDEN: control flow depends on query-ciphertext content
      if (quC & 1 == 1) {
        let rows = Pir2.pinnedRows(g, fill, c);
        if (rows > 0) {
          let colBytes = Blob.toArray(Region.loadBlob(state.d_region, Pir2.dCellOffset(g, shard, c, 0), rows));
          var r = 0;
          while (r < rows) {
            ans[r] := ans[r] +% Prim.nat16ToNat32(Prim.nat8ToNat16(colBytes[r])) *% quC;
            r += 1;
          };
          cellsScanned += rows;
        };
      };
      c += 1;
    };
    let out = Prim.Array_init<Nat8>(ans.size() * 4, 0);
    var i = 0;
    while (i < ans.size()) {
      let w = Prim.nat32ToNat64(ans[i]);
      out[4 * i] := Nat8.fromNat(Nat64.toNat(w & 0xFF));
      out[4 * i + 1] := Nat8.fromNat(Nat64.toNat((w >> 8) & 0xFF));
      out[4 * i + 2] := Nat8.fromNat(Nat64.toNat((w >> 16) & 0xFF));
      out[4 * i + 3] := Nat8.fromNat(Nat64.toNat((w >> 24) & 0xFF));
      i += 1;
    };
    let c1 = Prim.performanceCounter(0);
    (
      Blob.fromArray(Array.fromVarArray(out)),
      {
        cells_scanned = cellsScanned;
        columns_scanned = end - start;
        selector_decryptions = 0;
        target_index_parameters = 0;
        target_dependent_branches = 1; // honest self-report: this variant branches on content
        instructions = c1 - c0;
        indexed_upto = state.record_count;
      },
    )
  };

  public query func record_stream(start : Nat, count : Nat) : async Blob {
    Pir2.recordStream(state, start, count)
  };

  /// Record-stream slice with instruction telemetry (per-note serve cost).
  public func record_stream_measured(start : Nat, count : Nat) : async (Nat64, Nat) {
    let c0 = Prim.performanceCounter(0);
    let out = Pir2.recordStream(state, start, count);
    let c1 = Prim.performanceCounter(0);
    (c1 - c0, out.size())
  };

  public query func hint_chunk(shard : Nat, offset : Nat, len : Nat) : async Blob {
    Pir2.hintChunk(state, shard, offset, len)
  };

  public query func chain_info() : async (Blob, Nat, ?(Blob, Nat)) {
    (state.chain, state.record_count, Pir2.latestBoundary(state))
  };

  /// Backfill strategy B (heap accumulation): absorb `count` synthetic-position records into
  /// a TRANSIENT heap hint arena instead of per-record region read-modify-write, then flush
  /// row-chunks to a scratch region once. Returns (absorb instr, flush instr, alloc bytes) so
  /// the driver can compare against strategy A (append_measured's per-record RMW) at the same
  /// size. Uses the module's own aRowInto/geometry so the arithmetic is the production one.
  public func measure_heap_backfill(records : [(Blob, Blob)]) : async (Nat64, Nat64, Nat) {
    let g = Pir2.geometry(state.shard_size);
    let a0 = Prim.rts_total_allocation();
    let c0 = Prim.performanceCounter(0);
    let hint = VarArray.repeat<Nat32>(0, g.m_rows * Pir2.LWE_N);
    let aRow = VarArray.repeat<Nat32>(0, Pir2.LWE_N);
    var idx = 0;
    for ((commitment, envelope) in records.values()) {
      let record = Pir2.packRecord(commitment, envelope);
      let (c, r0) = Pir2.place(g, idx);
      Pir2.aRowInto(0, c, aRow, 0);
      var i = 0;
      while (i < Pir2.RECORD_BYTES) {
        let cell : Nat64 = Nat64.fromNat(Nat8.toNat(record[i]));
        if (cell != 0) {
          let base = (r0 + i) * Pir2.LWE_N;
          var j = 0;
          while (j < Pir2.LWE_N) {
            let prev = Prim.nat32ToNat64(hint[base + j]);
            hint[base + j] := Prim.nat64ToNat32((prev +% cell *% Prim.nat32ToNat64(aRow[j])) & 0xFFFF_FFFF);
            j += 1;
          };
        };
        i += 1;
      };
      idx += 1;
    };
    let c1 = Prim.performanceCounter(0);
    // flush: serialize row-major u32 LE and keep the bytes alive via a running checksum
    // (a scratch region write would measure region I/O too; the dominant question is the
    // absorb-vs-RMW arithmetic, and the driver adds the measured storeBlob rate separately)
    var checksum : Nat64 = 0;
    var w = 0;
    while (w < g.m_rows * Pir2.LWE_N) {
      checksum := checksum +% Prim.nat32ToNat64(hint[w]);
      w += 1;
    };
    heap_sink := heap_sink +% checksum;
    let c2 = Prim.performanceCounter(0);
    let a1 = Prim.rts_total_allocation();
    (c1 - c0, c2 - c1, a1 - a0)
  };

  public query func drain_sink() : async Nat64 { heap_sink };

  // ==== scale-tier corpus synthesis (ScaleFixture discipline) ====
  // Directly fills packed cells / hint bytes so the 10^6 / 10^7 tiers exist in minutes; the
  // MEASURED operations above all go through the production module unchanged. The matvec's
  // instruction cost is cell-content-independent (no branch on cell values), so deterministic
  // LCG bytes measure exactly what real cells would.

  transient var lcg : Nat64 = 0x9E3779B97F4A7C15;

  func lcgByte() : Nat8 {
    lcg := lcg *% 6364136223846793005 +% 1442695040888963407;
    Nat8.fromNat(Nat64.toNat((lcg >> 33) & 0xFF))
  };

  /// Advance record_count to `target`. Fresh region pages are zero-initialized and the
  /// stripe matvec is cell-content-INDEPENDENT (no data-dependent branch), so a zero-cell
  /// corpus measures exactly what real cells would — no writes needed, only capacity.
  public func synth_fill(target : Nat) : async Nat {
    if (target <= state.record_count) return state.record_count;
    let g = Pir2.geometry(state.shard_size);
    let lastShard = (target - 1) / state.shard_size;
    let lastInShard = Nat.min(target - lastShard * state.shard_size, state.shard_size);
    let lastCol = (lastInShard + g.records_per_column - 1) / g.records_per_column;
    ensureRegion(state.d_region, Pir2.dCellOffset(g, lastShard, lastCol, 0));
    state.record_count := target;
    state.record_count
  };

  /// Fill shard `shard`'s hint bytes with LCG content (hint SERVE cost is content-blind).
  public func synth_hint(shard : Nat) : async () {
    let g = Pir2.geometry(state.shard_size);
    let total = Nat64.toNat(Pir2.hintBytesPerShard(g));
    let base = Pir2.hRowOffset(g, shard, 0);
    ensureRegion(state.h_region, base + Pir2.hintBytesPerShard(g));
    var off = 0;
    let chunk = 65_536;
    while (off < total) {
      let take = Nat.min(chunk, total - off);
      let bytes = Prim.Array_init<Nat8>(take, 0);
      var i = 0;
      while (i < take) { bytes[i] := lcgByte(); i += 1 };
      Region.storeBlob(state.h_region, base + Nat64.fromNat(off), Blob.fromArray(Array.fromVarArray(bytes)));
      off += take;
    };
  };

  func ensureRegion(region : Region.Region, needed : Nat64) {
    let pageSize : Nat64 = 65_536;
    let current = Region.size(region) * pageSize;
    if (needed <= current) return;
    let pages = (needed - current + pageSize - 1) / pageSize;
    ignore Region.grow(region, pages);
  };

  // ==== reference-populated fast fill (differential phase 2 ONLY) ====
  // The append fold's byte-identity is proven separately on a real-append corpus (differential
  // phase 1). Given THAT, the query byte-comparison at 144k scale only needs D and H to match
  // the reference — so the reference writes them directly here, at region-write speed, instead
  // of paying 176M instr/record through the fold. These setters address the SAME production
  // regions the query path reads; nothing else uses them.

  /// Store reference-computed packed cells for record at global `index` (288 bytes).
  public func store_cells(index : Nat, cells : Blob) : async () {
    let g = Pir2.geometry(state.shard_size);
    let shard = index / state.shard_size;
    let (c, r0) = Pir2.place(g, index % state.shard_size);
    let offset = Pir2.dCellOffset(g, shard, c, r0);
    ensureRegion(state.d_region, offset + Nat64.fromNat(cells.size()));
    Region.storeBlob(state.d_region, offset, cells);
  };

  /// Bulk store: reference-computed packed cells for consecutive records [start, start+n).
  public func store_cells_bulk(start : Nat, records : [Blob]) : async () {
    let g = Pir2.geometry(state.shard_size);
    var i = 0;
    while (i < records.size()) {
      let index = start + i;
      let shard = index / state.shard_size;
      let (c, r0) = Pir2.place(g, index % state.shard_size);
      let offset = Pir2.dCellOffset(g, shard, c, r0);
      ensureRegion(state.d_region, offset + Nat64.fromNat(records[i].size()));
      Region.storeBlob(state.d_region, offset, records[i]);
      i += 1;
    };
  };

  /// Store a raw hint-region span for `shard` at byte `offset` (reference-computed LE u32).
  public func store_hint(shard : Nat, offset : Nat, bytes : Blob) : async () {
    let g = Pir2.geometry(state.shard_size);
    let base = Pir2.hRowOffset(g, shard, 0) + Nat64.fromNat(offset);
    ensureRegion(state.h_region, base + Nat64.fromNat(bytes.size()));
    Region.storeBlob(state.h_region, base, bytes);
  };

  /// Set the logical record count after a reference population (no fold, no chain).
  public func set_record_count(n : Nat) : async () {
    state.record_count := n;
  };
}
