/// MEASUREMENT HARNESS — read-path A0 (bytes-per-note on the wire) and the
/// `detection_stream` per-note instruction cost. Same discipline as AuditCostProbe.mo:
/// TEST/HARNESS INFRASTRUCTURE ONLY — never installed as the ledger, no production
/// canister imports it. It builds a phash-chained note population through the REAL
/// NoteCodec + ICRC3 code with realistic FRONTEND envelope shapes, then:
///   - exposes `note_blocks_range` so the Rust driver can measure the exact candid wire
///     size of an `icrc3_get_blocks`-shaped response (A0: bytes/note, shield vs transfer);
///   - times the EXACT `detection_stream` core (blockAt → NoteCodec.decode → slice
///     note_ciphertext[0..40]) with Prim.performanceCounter(0) + allocation deltas — the
///     honest cost (getting note_ciphertext requires a full decode + per-note
///     SHA-256 checksum, it is not a free slice);
///   - returns the packed `detection_stream` blob so the driver can confirm ≤48 B/note.
///
/// Frontend envelope shapes (demo-frontend/src/wallet.js): the on-chain `ephemeral_key`
/// field is 32 random bytes (wallet.js:154) and is NOT the ECDH key; the real ephemeral
/// pubkey is note_ciphertext[0..32]. note_ciphertext = ephPk(32)||[tag(8)]||nonce(24)||box,
/// box = nacl.box over JSON {"v","rho","rcm"} (payload ~163 B + 16 B Poly1305).

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
import StableLog "../src/StableLog";

persistent actor ReadPathProbe {
  public type Block = { id : Nat; block : ICRC3.Value };

  let note_log = StableLog.newState();
  var last_block_hash : ?Blob = null;
  var sink : Nat64 = 0;

  StableLog.ensureInit(note_log);

  func deterministicBlob(tag : Nat8, index : Nat, size : Nat) : Blob {
    let seed = Blob.fromArray(Array.tabulate<Nat8>(9, func(i) {
      if (i == 0) tag else Nat8.fromNat((index / (256 ** (i - 1))) % 256)
    }));
    let base = Sha256.fromBlob(#sha256, seed);
    if (size == 32) return base;
    let bytes = Blob.toArray(base);
    Blob.fromArray(Array.tabulate<Nat8>(size, func(i) { bytes[i % 32] }))
  };

  // verbatim from src/Main.mo NoteAudit.blockValue (the ICRC3 hash preimage / wire Value)
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

  /// Append `count` notes. `isTransfer`: false = shield shape (0 nullifiers, 235 B ciphertext),
  /// true = confidential_transfer OUTPUT shape (2 nullifiers, 243 B new-format ciphertext).
  /// ephemeral_key is 32 B (frontend randomBytes(32)); ciphertext sizes match wallet.js envelopes.
  func appendShaped(count : Nat, isTransfer : Bool) : Nat {
    var i : Nat = 0;
    while (i < count) {
      let position = StableLog.size(note_log);
      let nullifiers : [Blob] = if (isTransfer) {
        [deterministicBlob(3, position * 2, 32), deterministicBlob(3, position * 2 + 1, 32)]
      } else { [] };
      let ctSize = if (isTransfer) 243 else 235; // new-format transfer / old-format shield illustrative
      let root = deterministicBlob(2, position, 32);
      let block : NoteCodec.ShieldedNoteBlock = {
        btype = "zknote1";
        phash = last_block_hash;
        encoding_version = 1;
        note_position = position;
        commitment = deterministicBlob(1, position, 32);
        ephemeral_key = deterministicBlob(4, position, 32);
        note_ciphertext = deterministicBlob(5, position, ctSize);
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
      last_block_hash := ?ICRC3.hashValue(blockValue(block));
      i += 1;
    };
    StableLog.size(note_log)
  };

  public func bulk_append(shieldCount : Nat, transferCount : Nat) : async Nat {
    ignore appendShaped(shieldCount, false);
    appendShaped(transferCount, true)
  };

  func blockAt(index : Nat) : NoteCodec.ShieldedNoteBlock {
    let encoded = switch (StableLog.get(note_log, index)) {
      case (?value) value;
      case null Runtime.trap("read-path-probe:missing-note");
    };
    switch (NoteCodec.decode(encoded)) {
      case (#ok(block)) block;
      case (#err(message)) Runtime.trap(message);
    }
  };

  /// A0: exactly the `icrc3_get_blocks` per-block wire shape. The Rust driver measures the
  /// candid-encoded length of this response / count to get bytes-per-note.
  public query func note_blocks_range(from : Nat, count : Nat) : async [Block] {
    let result = List.empty<Block>();
    let end = Nat.min(from + count, StableLog.size(note_log));
    var i = from;
    while (i < end) {
      List.add(result, { id = i; block = blockValue(blockAt(i)) });
      i += 1;
    };
    List.toArray(result)
  };

  /// The `detection_stream` core cost: decode each block and slice note_ciphertext[0..40].
  /// Returns (instructions, alloc bytes, heap delta) over [from, from+count).
  public func measure_detection_slice(from : Nat, count : Nat) : async (Nat64, Nat, Int) {
    let a0 = Prim.rts_total_allocation();
    let h0 = Prim.rts_heap_size();
    let c0 = Prim.performanceCounter(0);
    var index = from;
    let end = from + count;
    var acc : Nat8 = 0;
    while (index < end) {
      let ct = Blob.toArray(blockAt(index).note_ciphertext);
      // slice first 40 bytes (ephPk(32)||tag(8)); touch them so the work is not optimized away
      var j = 0;
      while (j < 40) { acc ^= ct[j]; j += 1 };
      index += 1;
    };
    let c1 = Prim.performanceCounter(0);
    let a1 = Prim.rts_total_allocation();
    let h1 = Prim.rts_heap_size();
    sink +%= Nat64.fromNat(Nat8.toNat(acc));
    (c1 - c0, a1 - a0, h1 - h0)
  };

  /// The packed `detection_stream` wire payload: (position 8B BE || ephPk 32 || tag 8) per note.
  /// The Rust driver measures candid length / count to confirm ≤ 48 B/note.
  public query func detection_stream_bytes(from : Nat, count : Nat) : async Blob {
    let out = List.empty<Nat8>();
    let end = Nat.min(from + count, StableLog.size(note_log));
    var index = from;
    while (index < end) {
      // position as 8-byte big-endian
      var k : Nat = 8;
      while (k > 0) {
        k -= 1;
        List.add(out, Nat8.fromNat((index / (256 ** k)) % 256));
      };
      let ct = Blob.toArray(blockAt(index).note_ciphertext);
      var j = 0;
      while (j < 40) { List.add(out, ct[j]); j += 1 };
      index += 1;
    };
    Blob.fromArray(List.toArray(out))
  };

  public query func size() : async Nat { StableLog.size(note_log) };
  public query func drain_sink() : async Nat64 { sink };
}
