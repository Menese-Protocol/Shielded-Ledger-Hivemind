/// Deterministic, checksummed stable encoding for the `zknote1` typed record.
/// This is an internal stable-memory layout, not the public ICRC-3 Value encoding.

import Array "mo:core/Array";
import Blob "mo:core/Blob";
import List "mo:core/List";
import Nat "mo:core/Nat";
import Nat64 "mo:core/Nat64";
import Nat8 "mo:core/Nat8";
import Text "mo:core/Text";
import Sha256 "mo:sha2/Sha256";

module {
  public type Result<T> = { #ok : T; #err : Text };
  public type NoteOrigin = { #shield; #confidential_transfer };
  public type ShieldedNoteBlock = {
    btype : Text;
    phash : ?Blob;
    encoding_version : Nat;
    note_position : Nat;
    commitment : Blob;
    ephemeral_key : Blob;
    note_ciphertext : Blob;
    nullifiers : [Blob];
    anchor_before : Blob;
    note_root_after : Blob;
    timestamp : Nat64;
    origin : NoteOrigin;
  };

  public let LAYOUT_VERSION : Nat = 1;

  let MAGIC : Blob = "\5a\4b\4e\4f\54\45\30\31"; // ZKNOTE01
  let FRAME_HEADER_SIZE : Nat = 48;
  let MAX_NAT32 : Nat = 0xffff_ffff;

  func addBlob(output : List.List<Nat8>, value : Blob) {
    for (byte in value.vals()) List.add(output, byte);
  };

  func addNat32(output : List.List<Nat8>, value_input : Nat) {
    var value = value_input;
    var i : Nat = 0;
    while (i < 4) {
      List.add(output, Nat8.fromNat(value % 256));
      value /= 256;
      i += 1;
    };
  };

  func addNat64(output : List.List<Nat8>, value_input : Nat64) {
    var value = value_input;
    var i : Nat = 0;
    while (i < 8) {
      List.add(output, Nat8.fromNat(Nat64.toNat(value % 256)));
      value /= 256;
      i += 1;
    };
  };

  func validField(value : Blob) : Bool { value.size() == 32 };

  public func encode(block : ShieldedNoteBlock) : Result<Blob> {
    if (block.btype != "zknote1") return #err("note-codec:btype");
    if (block.encoding_version > Nat64.toNat(0xffff_ffff_ffff_ffff) or
        block.note_position > Nat64.toNat(0xffff_ffff_ffff_ffff)) {
      return #err("note-codec:nat64-overflow");
    };
    if (not validField(block.commitment) or not validField(block.anchor_before) or
        not validField(block.note_root_after)) {
      return #err("note-codec:field-length");
    };
    switch (block.phash) {
      case (?hash) { if (not validField(hash)) return #err("note-codec:phash-length") };
      case null {};
    };
    for (nullifier in block.nullifiers.vals()) {
      if (not validField(nullifier)) return #err("note-codec:nullifier-length");
    };

    let btype = Text.encodeUtf8(block.btype);
    if (btype.size() > MAX_NAT32 or block.ephemeral_key.size() > MAX_NAT32 or
        block.note_ciphertext.size() > MAX_NAT32 or block.nullifiers.size() > MAX_NAT32) {
      return #err("note-codec:length-overflow");
    };

    let payload = List.empty<Nat8>();
    addNat32(payload, btype.size());
    addBlob(payload, btype);
    switch (block.phash) {
      case null List.add(payload, Nat8.fromNat(0));
      case (?hash) { List.add(payload, Nat8.fromNat(1)); addBlob(payload, hash) };
    };
    addNat64(payload, Nat64.fromNat(block.encoding_version));
    addNat64(payload, Nat64.fromNat(block.note_position));
    addBlob(payload, block.commitment);
    addNat32(payload, block.ephemeral_key.size());
    addBlob(payload, block.ephemeral_key);
    addNat32(payload, block.note_ciphertext.size());
    addBlob(payload, block.note_ciphertext);
    addNat32(payload, block.nullifiers.size());
    for (nullifier in block.nullifiers.vals()) addBlob(payload, nullifier);
    addBlob(payload, block.anchor_before);
    addBlob(payload, block.note_root_after);
    addNat64(payload, block.timestamp);
    List.add(payload, switch (block.origin) {
      case (#shield) Nat8.fromNat(0);
      case (#confidential_transfer) Nat8.fromNat(1);
    });

    let payload_blob = Blob.fromArray(List.toArray(payload));
    if (payload_blob.size() > MAX_NAT32) return #err("note-codec:payload-too-large");
    let output = List.empty<Nat8>();
    addBlob(output, MAGIC);
    addNat32(output, LAYOUT_VERSION);
    addNat32(output, payload_blob.size());
    addBlob(output, Sha256.fromBlob(#sha256, payload_blob));
    addBlob(output, payload_blob);
    #ok(Blob.fromArray(List.toArray(output)))
  };

  func nat32At(bytes : [Nat8], offset : Nat) : ?Nat {
    if (offset + 4 > bytes.size()) return null;
    var value : Nat = 0;
    var factor : Nat = 1;
    var i : Nat = 0;
    while (i < 4) {
      value += Nat8.toNat(bytes[offset + i]) * factor;
      factor *= 256;
      i += 1;
    };
    ?value
  };

  func blobAt(bytes : [Nat8], offset : Nat, length : Nat) : ?Blob {
    if (offset > bytes.size()) return null;
    if (length > Nat.sub(bytes.size(), offset)) return null;
    ?Blob.fromArray(Array.tabulate<Nat8>(length, func(i) { bytes[offset + i] }))
  };

  class Reader(bytes : [Nat8]) {
    var offset : Nat = 0;

    public func byte() : ?Nat8 {
      if (offset >= bytes.size()) return null;
      let value = bytes[offset];
      offset += 1;
      ?value
    };

    public func nat32() : ?Nat {
      let value = nat32At(bytes, offset);
      switch (value) { case (?_) offset += 4; case null {} };
      value
    };

    public func nat64() : ?Nat64 {
      if (offset + 8 > bytes.size()) return null;
      var value : Nat64 = 0;
      var factor : Nat64 = 1;
      var i : Nat = 0;
      while (i < 8) {
        value += Nat64.fromNat(Nat8.toNat(bytes[offset + i])) * factor;
        if (i < 7) factor *= 256;
        i += 1;
      };
      offset += 8;
      ?value
    };

    public func blob(length : Nat) : ?Blob {
      let value = blobAt(bytes, offset, length);
      switch (value) { case (?_) offset += length; case null {} };
      value
    };

    public func done() : Bool { offset == bytes.size() };
  };

  func decodePayload(payload_blob : Blob) : Result<ShieldedNoteBlock> {
    let payload = Blob.toArray(payload_blob);
    let reader = Reader(payload);
    let btype_length = switch (reader.nat32()) {
      case (?value) value;
      case null return #err("note-codec:payload-truncated");
    };
    let btype_blob = switch (reader.blob(btype_length)) {
      case (?value) value;
      case null return #err("note-codec:payload-truncated");
    };
    let btype = switch (Text.decodeUtf8(btype_blob)) {
      case (?value) value;
      case null return #err("note-codec:btype-utf8");
    };
    if (btype != "zknote1") return #err("note-codec:btype");

    let phash = switch (reader.byte()) {
      case (?0) null;
      case (?1) switch (reader.blob(32)) {
        case (?value) ?value;
        case null return #err("note-codec:payload-truncated");
      };
      case (?_) return #err("note-codec:phash-tag");
      case null return #err("note-codec:payload-truncated");
    };
    let encoding_version = switch (reader.nat64()) {
      case (?value) Nat64.toNat(value);
      case null return #err("note-codec:payload-truncated");
    };
    let note_position = switch (reader.nat64()) {
      case (?value) Nat64.toNat(value);
      case null return #err("note-codec:payload-truncated");
    };
    let commitment = switch (reader.blob(32)) {
      case (?value) value;
      case null return #err("note-codec:payload-truncated");
    };
    let ephemeral_length = switch (reader.nat32()) {
      case (?value) value;
      case null return #err("note-codec:payload-truncated");
    };
    let ephemeral_key = switch (reader.blob(ephemeral_length)) {
      case (?value) value;
      case null return #err("note-codec:payload-truncated");
    };
    let ciphertext_length = switch (reader.nat32()) {
      case (?value) value;
      case null return #err("note-codec:payload-truncated");
    };
    let note_ciphertext = switch (reader.blob(ciphertext_length)) {
      case (?value) value;
      case null return #err("note-codec:payload-truncated");
    };
    let nullifier_count = switch (reader.nat32()) {
      case (?value) value;
      case null return #err("note-codec:payload-truncated");
    };
    let nullifiers = List.empty<Blob>();
    var i : Nat = 0;
    while (i < nullifier_count) {
      switch (reader.blob(32)) {
        case (?value) List.add(nullifiers, value);
        case null return #err("note-codec:payload-truncated");
      };
      i += 1;
    };
    let anchor_before = switch (reader.blob(32)) {
      case (?value) value;
      case null return #err("note-codec:payload-truncated");
    };
    let note_root_after = switch (reader.blob(32)) {
      case (?value) value;
      case null return #err("note-codec:payload-truncated");
    };
    let timestamp = switch (reader.nat64()) {
      case (?value) value;
      case null return #err("note-codec:payload-truncated");
    };
    let origin = switch (reader.byte()) {
      case (?0) #shield;
      case (?1) #confidential_transfer;
      case (?_) return #err("note-codec:origin");
      case null return #err("note-codec:payload-truncated");
    };
    if (not reader.done()) return #err("note-codec:payload-trailing");
    #ok({
      btype;
      phash;
      encoding_version;
      note_position;
      commitment;
      ephemeral_key;
      note_ciphertext;
      nullifiers = List.toArray(nullifiers);
      anchor_before;
      note_root_after;
      timestamp;
      origin;
    })
  };

  public func decode(encoded : Blob) : Result<ShieldedNoteBlock> {
    let bytes = Blob.toArray(encoded);
    if (bytes.size() < FRAME_HEADER_SIZE) return #err("note-codec:frame-truncated");
    switch (blobAt(bytes, 0, 8)) {
      case (?magic) { if (magic != MAGIC) return #err("note-codec:magic") };
      case null return #err("note-codec:frame-truncated");
    };
    let version = switch (nat32At(bytes, 8)) {
      case (?value) value;
      case null return #err("note-codec:frame-truncated");
    };
    if (version != LAYOUT_VERSION) return #err("note-codec:layout-version");
    let payload_length = switch (nat32At(bytes, 12)) {
      case (?value) value;
      case null return #err("note-codec:frame-truncated");
    };
    if (payload_length != Nat.sub(bytes.size(), FRAME_HEADER_SIZE)) {
      return #err("note-codec:frame-length");
    };
    let checksum = switch (blobAt(bytes, 16, 32)) {
      case (?value) value;
      case null return #err("note-codec:frame-truncated");
    };
    let payload = switch (blobAt(bytes, FRAME_HEADER_SIZE, payload_length)) {
      case (?value) value;
      case null return #err("note-codec:frame-truncated");
    };
    if (Sha256.fromBlob(#sha256, payload) != checksum) return #err("note-codec:checksum");
    decodePayload(payload)
  };
};
