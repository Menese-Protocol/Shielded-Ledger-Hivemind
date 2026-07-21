/// MEASUREMENT HARNESS — per-note audit-path cost, for choosing the audit chunk size K
/// (K is chosen by measurement with ≥4× headroom) and for the
/// allocation-discipline before/after numbers.
///
/// TEST/HARNESS INFRASTRUCTURE ONLY (ChurnProfile.mo pattern): never installed as the
/// ledger, no production canister imports it. It builds a phash-chained note population
/// through the REAL NoteCodec + ICRC3 code, then times the EXACT old per-note walk body
/// (StableLog.get → decode → semantic checks → canonical re-encode → hashValue) with
/// Prim.performanceCounter(0) and Prim.rts_total_allocation() deltas.

import Array "mo:core/Array";
import Blob "mo:core/Blob";
import List "mo:core/List";
import Nat "mo:core/Nat";
import Nat64 "mo:core/Nat64";
import Nat8 "mo:core/Nat8";
import Runtime "mo:core/Runtime";
import Prim "mo:⛔";
import Sha256 "mo:sha2/Sha256";
import ICRC3 "../src/ICRC3";
import NoteCodec "../src/NoteCodec";
import StableBlobSet "../src/StableBlobSet";
import StableLog "../src/StableLog";

persistent actor AuditCostProbe {
  let note_log = StableLog.newState();
  let historical_roots = StableBlobSet.newState();
  let spent_nullifiers = StableBlobSet.newState();
  var last_block_hash : ?Blob = null;
  var sink : Nat64 = 0;

  StableLog.ensureInit(note_log);
  StableBlobSet.ensureInit(historical_roots);
  StableBlobSet.ensureInit(spent_nullifiers);

  func fieldSized(value : Blob) : Bool { value.size() == 32 };

  func deterministicBlob(tag : Nat8, index : Nat, size : Nat) : Blob {
    let seed = Blob.fromArray(Array.tabulate<Nat8>(9, func(i) {
      if (i == 0) tag else Nat8.fromNat((index / (256 ** (i - 1))) % 256)
    }));
    let base = Sha256.fromBlob(#sha256, seed);
    if (size == 32) return base;
    let bytes = Blob.toArray(base);
    Blob.fromArray(Array.tabulate<Nat8>(size, func(i) { bytes[i % 32] }))
  };

  // verbatim from src/Main.mo blockValue (the hash preimage builder)
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

  /// Append `count` phash-chained notes through the REAL codec (realistic soak shapes:
  /// 2 nullifiers on transfers, 16B ephemeral key, 112B ciphertext).
  public func bulk_append(count : Nat) : async Nat {
    var i : Nat = 0;
    while (i < count) {
      let position = StableLog.size(note_log);
      let isTransfer = position % 3 != 0;
      let nullifiers : [Blob] = if (isTransfer) {
        [deterministicBlob(3, position * 2, 32), deterministicBlob(3, position * 2 + 1, 32)]
      } else { [] };
      let root = deterministicBlob(2, position, 32);
      let block : NoteCodec.ShieldedNoteBlock = {
        btype = "zknote1";
        phash = last_block_hash;
        encoding_version = 1;
        note_position = position;
        commitment = deterministicBlob(1, position, 32);
        ephemeral_key = deterministicBlob(4, position, 16);
        note_ciphertext = deterministicBlob(5, position, 112);
        nullifiers;
        anchor_before = if (position == 0) deterministicBlob(2, 999_999_999, 32) else deterministicBlob(2, position - 1, 32);
        note_root_after = root;
        timestamp = Nat64.fromNat(1_784_246_400_000_000_000 + position);
        origin = if (isTransfer) #confidential_transfer else #shield;
      };
      let encoded = switch (NoteCodec.encode(block)) {
        case (#ok(value)) value;
        case (#err(message)) Runtime.trap(message);
      };
      switch (StableLog.append(note_log, encoded)) {
        case (#ok(_)) {};
        case (#err(message)) Runtime.trap(message);
      };
      ignore StableBlobSet.put(historical_roots, root);
      for (n in nullifiers.vals()) { ignore StableBlobSet.put(spent_nullifiers, n) };
      last_block_hash := ?ICRC3.hashValue(blockValue(block));
      i += 1;
    };
    StableLog.size(note_log)
  };

  /// The EXACT old per-note walk body over notes [from, from+count), reference path.
  /// Returns (instructions, allocation bytes, heap delta bytes) for the span.
  public func measure_reference_walk(from : Nat, count : Nat) : async (Nat64, Nat, Int) {
    var expected_parent : ?Blob = if (from == 0) null else {
      // seed the chain from the stored previous note
      switch (StableLog.get(note_log, from - 1)) {
        case (?encoded) {
          switch (NoteCodec.decode(encoded)) {
            case (#ok(block)) ?ICRC3.hashValue(blockValue(block));
            case (#err(m)) Runtime.trap(m);
          }
        };
        case null Runtime.trap("bad from");
      }
    };
    let a0 = Prim.rts_total_allocation();
    let h0 = Prim.rts_heap_size();
    let c0 = Prim.performanceCounter(0);
    var index = from;
    let end = from + count;
    while (index < end) {
      let encoded = switch (StableLog.get(note_log, index)) {
        case (?value) value;
        case null Runtime.trap("stable-state:missing-note");
      };
      let block = switch (NoteCodec.decode(encoded)) {
        case (#ok(value)) value;
        case (#err(message)) Runtime.trap(message);
      };
      if (block.btype != "zknote1" or block.encoding_version != 1) {
        Runtime.trap("stable-state:block-domain");
      };
      if (block.note_position != index) Runtime.trap("stable-state:note-position");
      if (block.phash != expected_parent) Runtime.trap("stable-state:phash");
      if (not fieldSized(block.commitment) or not fieldSized(block.anchor_before) or
          not fieldSized(block.note_root_after)) {
        Runtime.trap("stable-state:block-field-length");
      };
      if (not StableBlobSet.contains(historical_roots, block.note_root_after)) {
        Runtime.trap("stable-state:missing-historical-root");
      };
      for (nullifier in block.nullifiers.vals()) {
        if (not StableBlobSet.contains(spent_nullifiers, nullifier)) {
          Runtime.trap("stable-state:missing-nullifier");
        };
      };
      let canonical = switch (NoteCodec.encode(block)) {
        case (#ok(value)) value;
        case (#err(message)) Runtime.trap(message);
      };
      if (canonical != encoded) Runtime.trap("stable-state:noncanonical-note");
      expected_parent := ?ICRC3.hashValue(blockValue(block));
      index += 1;
    };
    let c1 = Prim.performanceCounter(0);
    let a1 = Prim.rts_total_allocation();
    let h1 = Prim.rts_heap_size();
    switch (expected_parent) { case (?h) { sink +%= Nat64.fromNat(Nat8.toNat(Blob.toArray(h)[0])) }; case null {} };
    (c1 - c0, a1 - a0, h1 - h0)
  };

  /// sha256 over a 32-byte input, iterated — the per-key cost of StableBlobSet grow/probe.
  public func measure_sha256_32(iters : Nat) : async (Nat64, Nat) {
    let key = deterministicBlob(9, 1, 32);
    let a0 = Prim.rts_total_allocation();
    let c0 = Prim.performanceCounter(0);
    var i : Nat = 0;
    while (i < iters) {
      let digest = Sha256.fromBlob(#sha256, key);
      sink +%= Nat64.fromNat(Nat8.toNat(Blob.toArray(digest)[0]));
      i += 1;
    };
    let c1 = Prim.performanceCounter(0);
    let a1 = Prim.rts_total_allocation();
    (c1 - c0, a1 - a0)
  };

  /// StableBlobSet slot-walk cost over the roots table (per-slot cost for chunk sizing S).
  public func measure_slot_walk() : async (Nat64, Nat, Nat64) {
    let cap = historical_roots.capacity;
    let a0 = Prim.rts_total_allocation();
    let c0 = Prim.performanceCounter(0);
    var observed : Nat64 = 0;
    var index : Nat64 = 0;
    while (index < cap) {
      let offset = historical_roots.table_offset + index * 33;
      let tag = Prim.regionLoadNat8(historical_roots.region, offset);
      if (tag == 1) observed += 1;
      index += 1;
    };
    let c1 = Prim.performanceCounter(0);
    let a1 = Prim.rts_total_allocation();
    sink +%= observed;
    (c1 - c0, a1 - a0, cap)
  };

  /// StableLog index-contiguity walk cost (per-entry cost for chunk sizing L).
  public func measure_index_walk() : async (Nat64, Nat, Nat) {
    let entries = StableLog.size(note_log);
    let a0 = Prim.rts_total_allocation();
    let c0 = Prim.performanceCounter(0);
    var expected_offset : Nat64 = 16;
    var index : Nat64 = 0;
    while (index < Nat64.fromNat(entries)) {
      let index_offset = 32 + index * 16;
      let data_offset = Prim.regionLoadNat64(note_log.index_region, index_offset);
      let data_length = Nat64.fromNat(Prim.nat32ToNat(Prim.regionLoadNat32(note_log.index_region, index_offset + 8)));
      if (data_offset != expected_offset) Runtime.trap("stable-log:noncontiguous-index");
      expected_offset += data_length;
      index += 1;
    };
    let c1 = Prim.performanceCounter(0);
    let a1 = Prim.rts_total_allocation();
    sink +%= expected_offset;
    (c1 - c0, a1 - a0, entries)
  };

  public query func drain_sink() : async Nat64 { sink };
}
