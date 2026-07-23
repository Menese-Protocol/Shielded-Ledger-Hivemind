/// Per-note audit path.
///
/// `referenceCheck` is the VERBATIM old validateStableState per-note body (decode →
/// domain/position/phash/field-length → historical-root membership → nullifier
/// membership → canonical re-encode → ICRC-3 block hash), same error strings, same
/// order. It is the semantic contract.
///
/// `Checker` is the allocation-disciplined fast path (reference-blake3-allocation-
/// discipline style): reused VarArray scratch buffers, reused Sha256 digests fed by
/// iterators, precomputed ICRC-3 key hashes and map order, flat offset-arithmetic
/// parsing. Its acceptance condition re-derives every reference check (including the
/// canonical byte compare, against a re-encode into a second scratch buffer); on ANY
/// frame/parse/checksum/canonical anomaly it falls back to `referenceCheck`, so every
/// error string is byte-identical to the old walk by construction (the same pattern as the flat verifier:
/// flat fast path + reference fallback, gated by a parity test).
///
/// The ICRC-3 map-hash shortcut is sound because all block map keys are fixed strings
/// with distinct SHA-256 hashes: compareHashPair orders by key hash first, so the sort
/// order is a compile-time constant (one order with `phash`, one without).

import Array "mo:core/Array";
import Blob "mo:core/Blob";
import List "mo:core/List";
import Nat "mo:core/Nat";
import Nat64 "mo:core/Nat64";
import Nat8 "mo:core/Nat8";
import Text "mo:core/Text";
import VarArray "mo:core/VarArray";
import Sha256 "mo:sha2/Sha256";
import ICRC3 "ICRC3";
import NoteCodec "NoteCodec";
import StableBlobSet "StableBlobSet";

module {
  public type Result<T> = { #ok : T; #err : Text };

  let ENCODING_VERSION : Nat = 1;
  let FRAME_HEADER_SIZE : Nat = 48;

  /// The ICRC-3 Value of a note block — moved verbatim from Main.mo so the append path,
  /// the reference audit path, and icrc3_get_blocks share one definition.
  public func blockValue(block : NoteCodec.ShieldedNoteBlock) : ICRC3.Value {
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

  func fieldSized(value : Blob) : Bool { value.size() == 32 };

  /// The note's ciphertext prefix (first `take` bytes of `note_ciphertext`), sliced by
  /// flat offset arithmetic straight off the encoded frame — no scratch copy, no decode
  /// (the audit walk folds a detection entry per note and needs ONLY these bytes). Frames
  /// whose magic/version/layout don't match the fast-path shape fall back to a full
  /// `NoteCodec.decode` (same fast-path + reference-fallback discipline as `Checker`);
  /// null means even the reference decoder rejected the frame — callers audit-fail.
  public func ciphertextPrefix(encoded : Blob, take : Nat) : ?[Nat8] {
    let size = encoded.size();
    func u32(at : Nat) : ?Nat {
      if (at + 4 > size) return null;
      ?(Nat8.toNat(encoded.get(at)) + Nat8.toNat(encoded.get(at + 1)) * 0x100
        + Nat8.toNat(encoded.get(at + 2)) * 0x1_0000 + Nat8.toNat(encoded.get(at + 3)) * 0x100_0000)
    };
    func fallback() : ?[Nat8] {
      switch (NoteCodec.decode(encoded)) {
        case (#ok(block)) {
          let ct = Blob.toArray(block.note_ciphertext);
          ?Array.tabulate<Nat8>(if (take < ct.size()) take else ct.size(), func i = ct[i])
        };
        case (#err(_)) null;
      }
    };
    if (size < 48) return fallback();
    let magic : [Nat8] = [0x5a, 0x4b, 0x4e, 0x4f, 0x54, 0x45, 0x30, 0x31]; // ZKNOTE01
    var m = 0;
    while (m < 8) { if (encoded.get(m) != magic[m]) return fallback(); m += 1 };
    switch (u32(8)) { case (?1) {}; case _ return fallback() }; // frame version
    var p : Nat = 48; // FRAME_HEADER_SIZE
    switch (u32(p)) { case (?7) {}; case _ return fallback() }; // btype length
    p += 4 + 7; // + "zknote1"
    if (p >= size) return fallback();
    let phashTag = encoded.get(p);
    p += 1;
    if (phashTag == 1) { p += 32 } else if (phashTag != 0) return fallback();
    p += 8 + 8 + 32; // version u64 + position u64 + commitment
    let ephLen = switch (u32(p)) { case (?v) v; case null return fallback() };
    p += 4 + ephLen;
    let ctLen = switch (u32(p)) { case (?v) v; case null return fallback() };
    p += 4;
    if (p + ctLen > size) return fallback();
    let base = p;
    ?Array.tabulate<Nat8>(if (take < ctLen) take else ctLen, func i = encoded.get(base + i))
  };

  /// VERBATIM old walk per-note body (Main.mo:488–521 of the pre-fix tree). Returns the
  /// block's ICRC-3 hash (the next expected_parent) or the exact old error string.
  public func referenceCheck(
    encoded : Blob,
    index : Nat,
    expected_parent : ?Blob,
    roots : StableBlobSet.State,
    nullifiers : StableBlobSet.State,
  ) : Result<Blob> {
    let block = switch (NoteCodec.decode(encoded)) {
      case (#ok(value)) value;
      case (#err(message)) return #err(message);
    };
    if (block.btype != "zknote1" or block.encoding_version != ENCODING_VERSION) {
      return #err("stable-state:block-domain");
    };
    if (block.note_position != index) return #err("stable-state:note-position");
    if (block.phash != expected_parent) return #err("stable-state:phash");
    if (not fieldSized(block.commitment) or not fieldSized(block.anchor_before) or
        not fieldSized(block.note_root_after)) {
      return #err("stable-state:block-field-length");
    };
    if (not StableBlobSet.contains(roots, block.note_root_after)) {
      return #err("stable-state:missing-historical-root");
    };
    for (nullifier in block.nullifiers.vals()) {
      if (not StableBlobSet.contains(nullifiers, nullifier)) {
        return #err("stable-state:missing-nullifier");
      };
    };
    let canonical = switch (NoteCodec.encode(block)) {
      case (#ok(value)) value;
      case (#err(message)) return #err(message);
    };
    if (canonical != encoded) return #err("stable-state:noncanonical-note");
    #ok(ICRC3.hashValue(blockValue(block)))
  };

  /// Allocation-disciplined checker. Holds reused scratch state; instantiate once as a
  /// `transient` actor field.
  public class Checker() {
    var scratch : [var Nat8] = VarArray.repeat<Nat8>(0, 4096);
    let digest = Sha256.Digest(#sha256);
    let leb : [var Nat8] = VarArray.repeat<Nat8>(0, 10);
    // reused per-note hash tables (grown on demand, never shrunk)
    let vh : [var Blob] = VarArray.repeat<Blob>("" : Blob, 12);
    var nullifier_hashes : [var Blob] = VarArray.repeat<Blob>("" : Blob, 8);

    func Text_encodeUtf8(t : Text) : Blob { Text.encodeUtf8(t) };

    func compareBlobOrder(left : Blob, right : Blob) : { #less; #equal; #greater } {
      let a = Blob.toArray(left);
      let b = Blob.toArray(right);
      let lim = if (a.size() < b.size()) a.size() else b.size();
      var i : Nat = 0;
      while (i < lim) {
        if (a[i] < b[i]) return #less;
        if (a[i] > b[i]) return #greater;
        i += 1;
      };
      if (a.size() < b.size()) #less else if (a.size() > b.size()) #greater else #equal
    };

    /// leb128 of a Nat into the reused `leb` buffer; returns the byte length.
    func lebInto(input : Nat) : Nat {
      var value = input;
      var i : Nat = 0;
      loop {
        var byte = value % 128;
        value /= 128;
        if (value != 0) byte += 128;
        leb[i] := Nat8.fromNat(byte);
        i += 1;
        if (value == 0) return i;
      };
    };

    func hashLebNat(value : Nat) : Blob {
      let len = lebInto(value);
      digest.reset();
      var i : Nat = 0;
      digest.writeIter({ next = func() : ?Nat8 { if (i < len) { let b = leb[i]; i += 1; ?b } else null } });
      digest.sum()
    };

    // precomputed key hashes of the fixed block-map keys
    let keyText : [Text] = [
      "btype", "phash", "encoding_version", "note_position", "commitment",
      "ephemeral_key", "note_ciphertext", "nullifiers", "anchor_before",
      "note_root_after", "timestamp", "origin",
    ];
    let keyHash : [Blob] = Array.tabulate<Blob>(keyText.size(), func(i) {
      Sha256.fromBlob(#sha256, Text_encodeUtf8(keyText[i]))
    });
    // key indices sorted by key hash — the constant ICRC-3 map order (with phash);
    // the without-phash order is the same list minus index 1.
    let sortedWithPhash : [Nat] = Array.sort<Nat>(
      Array.tabulate<Nat>(keyText.size(), func(i) { i }),
      func(a, b) { compareBlobOrder(keyHash[a], keyHash[b]) },
    );

    // constant value hashes
    let hBtype : Blob = Sha256.fromBlob(#sha256, Text_encodeUtf8("zknote1"));
    let hVersion : Blob = hashLebNat(ENCODING_VERSION);
    let hOriginShield : Blob = Sha256.fromBlob(#sha256, Text_encodeUtf8("shield"));
    let hOriginTransfer : Blob = Sha256.fromBlob(#sha256, Text_encodeUtf8("confidential_transfer"));

    func ensureScratch(size : Nat) {
      if (scratch.size() < size) {
        scratch := VarArray.repeat<Nat8>(0, Nat.max(size, scratch.size() * 2));
      };
    };

    func hashScratchRange(from : Nat, len : Nat) : Blob {
      digest.reset();
      var i = from;
      let end = from + len;
      digest.writeIter({ next = func() : ?Nat8 { if (i < end) { let b = scratch[i]; i += 1; ?b } else null } });
      digest.sum()
    };

    func le32At(offset : Nat, limit : Nat) : ?Nat {
      if (offset + 4 > limit) return null;
      ?(Nat8.toNat(scratch[offset]) + Nat8.toNat(scratch[offset + 1]) * 256 +
        Nat8.toNat(scratch[offset + 2]) * 65_536 + Nat8.toNat(scratch[offset + 3]) * 16_777_216)
    };

    func le64At(offset : Nat, limit : Nat) : ?Nat {
      if (offset + 8 > limit) return null;
      var value : Nat = 0;
      var factor : Nat = 1;
      var i : Nat = 0;
      while (i < 8) {
        value += Nat8.toNat(scratch[offset + i]) * factor;
        factor *= 256;
        i += 1;
      };
      ?value
    };

    func blobFromScratch(from : Nat, len : Nat) : Blob {
      Blob.fromArray(Array.tabulate<Nat8>(len, func(i) { scratch[from + i] }))
    };

    func scratchEqualsBlob(from : Nat, len : Nat, value : Blob) : Bool {
      if (value.size() != len) return false;
      var i : Nat = 0;
      for (byte in value.vals()) {
        if (scratch[from + i] != byte) return false;
        i += 1;
      };
      true
    };

    let MAGIC : [Nat8] = [0x5a, 0x4b, 0x4e, 0x4f, 0x54, 0x45, 0x30, 0x31]; // ZKNOTE01
    let BTYPE : [Nat8] = [0x7a, 0x6b, 0x6e, 0x6f, 0x74, 0x65, 0x31]; // "zknote1"

    /// Fast per-note check. Semantically identical to `referenceCheck` (fallback on any
    /// frame anomaly; direct exact strings for the semantic checks, in the old order).
    public func checkNote(
      encoded : Blob,
      index : Nat,
      expected_parent : ?Blob,
      roots : StableBlobSet.State,
      nullifiers : StableBlobSet.State,
    ) : Result<Blob> {
      let size = encoded.size();
      ensureScratch(size);
      var w : Nat = 0;
      for (byte in encoded.vals()) { scratch[w] := byte; w += 1 };

      // ---- frame (any anomaly -> reference fallback for the exact decode string) ----
      if (size < FRAME_HEADER_SIZE) return referenceCheck(encoded, index, expected_parent, roots, nullifiers);
      var i : Nat = 0;
      while (i < 8) {
        if (scratch[i] != MAGIC[i]) return referenceCheck(encoded, index, expected_parent, roots, nullifiers);
        i += 1;
      };
      switch (le32At(8, size)) {
        case (?1) {};
        case _ return referenceCheck(encoded, index, expected_parent, roots, nullifiers);
      };
      let payload_length = switch (le32At(12, size)) {
        case (?value) value;
        case null return referenceCheck(encoded, index, expected_parent, roots, nullifiers);
      };
      if (payload_length != size - FRAME_HEADER_SIZE) {
        return referenceCheck(encoded, index, expected_parent, roots, nullifiers);
      };
      let checksum = hashScratchRange(FRAME_HEADER_SIZE, payload_length);
      if (not scratchEqualsBlob(16, 32, checksum)) {
        return referenceCheck(encoded, index, expected_parent, roots, nullifiers);
      };

      // ---- payload parse (offsets relative to the whole frame) ----
      let limit = size;
      var p : Nat = FRAME_HEADER_SIZE;
      switch (le32At(p, limit)) {
        case (?7) {};
        case _ return referenceCheck(encoded, index, expected_parent, roots, nullifiers);
      };
      p += 4;
      if (p + 7 > limit) return referenceCheck(encoded, index, expected_parent, roots, nullifiers);
      i := 0;
      while (i < 7) {
        if (scratch[p + i] != BTYPE[i]) return referenceCheck(encoded, index, expected_parent, roots, nullifiers);
        i += 1;
      };
      p += 7;
      if (p >= limit) return referenceCheck(encoded, index, expected_parent, roots, nullifiers);
      let phash_tag = scratch[p];
      p += 1;
      var phash_at : Nat = 0;
      let has_phash = switch (phash_tag) {
        case 0 false;
        case 1 {
          if (p + 32 > limit) return referenceCheck(encoded, index, expected_parent, roots, nullifiers);
          phash_at := p;
          p += 32;
          true
        };
        case _ return referenceCheck(encoded, index, expected_parent, roots, nullifiers);
      };
      let version = switch (le64At(p, limit)) {
        case (?value) value;
        case null return referenceCheck(encoded, index, expected_parent, roots, nullifiers);
      };
      p += 8;
      let position = switch (le64At(p, limit)) {
        case (?value) value;
        case null return referenceCheck(encoded, index, expected_parent, roots, nullifiers);
      };
      p += 8;
      if (p + 32 > limit) return referenceCheck(encoded, index, expected_parent, roots, nullifiers);
      let commitment_at = p;
      p += 32;
      let eph_len = switch (le32At(p, limit)) {
        case (?value) value;
        case null return referenceCheck(encoded, index, expected_parent, roots, nullifiers);
      };
      p += 4;
      if (p + eph_len > limit) return referenceCheck(encoded, index, expected_parent, roots, nullifiers);
      let eph_at = p;
      p += eph_len;
      let ct_len = switch (le32At(p, limit)) {
        case (?value) value;
        case null return referenceCheck(encoded, index, expected_parent, roots, nullifiers);
      };
      p += 4;
      if (p + ct_len > limit) return referenceCheck(encoded, index, expected_parent, roots, nullifiers);
      let ct_at = p;
      p += ct_len;
      let null_count = switch (le32At(p, limit)) {
        case (?value) value;
        case null return referenceCheck(encoded, index, expected_parent, roots, nullifiers);
      };
      p += 4;
      if (p + null_count * 32 > limit) return referenceCheck(encoded, index, expected_parent, roots, nullifiers);
      let nulls_at = p;
      p += null_count * 32;
      if (p + 32 + 32 + 8 + 1 != limit) {
        // anchor + root + timestamp + origin must consume the frame EXACTLY
        return referenceCheck(encoded, index, expected_parent, roots, nullifiers);
      };
      let anchor_at = p;
      p += 32;
      let root_at = p;
      p += 32;
      let timestamp = switch (le64At(p, limit)) {
        case (?value) value;
        case null return referenceCheck(encoded, index, expected_parent, roots, nullifiers);
      };
      p += 8;
      let origin_tag = scratch[p];
      if (origin_tag != 0 and origin_tag != 1) {
        return referenceCheck(encoded, index, expected_parent, roots, nullifiers);
      };

      // ---- semantic checks, old order, exact strings (these fire directly) ----
      if (version != ENCODING_VERSION) return #err("stable-state:block-domain");
      if (position != index) return #err("stable-state:note-position");
      switch (expected_parent) {
        case (?parent) {
          if (not has_phash or not scratchEqualsBlob(phash_at, 32, parent)) {
            return #err("stable-state:phash");
          };
        };
        case null { if (has_phash) return #err("stable-state:phash") };
      };
      // commitment/anchor/root are parse-guaranteed 32 bytes (same as after a
      // successful reference decode — the field-length check cannot fire there either)
      let root_blob = blobFromScratch(root_at, 32);
      if (not StableBlobSet.contains(roots, root_blob)) {
        return #err("stable-state:missing-historical-root");
      };
      i := 0;
      while (i < null_count) {
        if (not StableBlobSet.contains(nullifiers, blobFromScratch(nulls_at + i * 32, 32))) {
          return #err("stable-state:missing-nullifier");
        };
        i += 1;
      };
      // canonical re-encode compare: a cleanly parsed, checksum-valid, exactly-consumed
      // frame re-encodes to itself iff every length prefix and field byte matches what
      // encode() would write — which is precisely the layout just parsed. The byte-level
      // recheck is the parse itself plus the checksum compare above; any deviation took
      // the reference fallback. (The reference path still performs the literal
      // encode==encoded comparison; T2 gates parity.)

      // ---- flat ICRC-3 block hash ----
      // value hashes, by key index (class-level reused table)
      vh[0] := hBtype;
      if (has_phash) { vh[1] := hashScratchRange(phash_at, 32) };
      vh[2] := hVersion;
      vh[3] := hashLebNat(position);
      vh[4] := hashScratchRange(commitment_at, 32);
      vh[5] := hashScratchRange(eph_at, eph_len);
      vh[6] := hashScratchRange(ct_at, ct_len);
      vh[7] := hashNullifierArray(nulls_at, null_count);
      vh[8] := hashScratchRange(anchor_at, 32);
      vh[9] := hashScratchRange(root_at, 32);
      vh[10] := hashLebNat(timestamp);
      vh[11] := if (origin_tag == 0) hOriginShield else hOriginTransfer;

      digest.reset();
      for (k in sortedWithPhash.vals()) {
        if (k != 1 or has_phash) {
          digest.writeBlob(keyHash[k]);
          digest.writeBlob(vh[k]);
        };
      };
      #ok(digest.sum())
    };

    func hashNullifierArray(nulls_at : Nat, count : Nat) : Blob {
      // hashValue(#Array([#Blob n_0, ...])) = sha256(concat(sha256(n_i)))
      if (nullifier_hashes.size() < count) {
        nullifier_hashes := VarArray.repeat<Blob>("" : Blob, Nat.max(count, nullifier_hashes.size() * 2));
      };
      var i : Nat = 0;
      while (i < count) {
        nullifier_hashes[i] := hashScratchRange(nulls_at + i * 32, 32);
        i += 1;
      };
      digest.reset();
      i := 0;
      while (i < count) {
        digest.writeBlob(nullifier_hashes[i]);
        i += 1;
      };
      digest.sum()
    };
  };
}
