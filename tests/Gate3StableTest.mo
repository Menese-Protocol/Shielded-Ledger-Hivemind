import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Debug "mo:core/Debug";
import Nat8 "mo:core/Nat8";
import Region "mo:core/Region";
import Runtime "mo:core/Runtime";
import Prim "mo:⛔";
import NoteCodec "../src/NoteCodec";
import StableBlobSet "../src/StableBlobSet";
import StableLog "../src/StableLog";

persistent actor {

func bytes(length : Nat, seed : Nat) : Blob {
  Blob.fromArray(Array.tabulate<Nat8>(length, func(i) { Nat8.fromNat((seed + i * 17) % 256) }))
};

func replaceByte(value : Blob, index : Nat, replacement : Nat8) : Blob {
  let source = Blob.toArray(value);
  let output = Prim.Array_init<Nat8>(source.size(), 0);
  var i : Nat = 0;
  while (i < source.size()) {
    output[i] := if (i == index) replacement else source[i];
    i += 1;
  };
  Blob.fromArray(Array.fromVarArray(output))
};

func truncate(value : Blob) : Blob {
  let source = Blob.toArray(value);
  Blob.fromArray(Array.tabulate<Nat8>(source.size() - 1, func(i) { source[i] }))
};

func codecError(result : NoteCodec.Result<NoteCodec.ShieldedNoteBlock>, expected : Text) : Bool {
  switch (result) { case (#err(message)) message == expected; case (#ok(_)) false }
};

func unitError(result : { #ok : (); #err : Text }, expected : Text) : Bool {
  switch (result) { case (#err(message)) message == expected; case (#ok(_)) false }
};

let record : NoteCodec.ShieldedNoteBlock = {
  btype = "zknote1";
  phash = ?bytes(32, 1);
  encoding_version = 1;
  note_position = 7;
  commitment = bytes(32, 2);
  ephemeral_key = bytes(33, 3);
  note_ciphertext = bytes(71, 4);
  nullifiers = [bytes(32, 5), bytes(32, 6)];
  anchor_before = bytes(32, 7);
  note_root_after = bytes(32, 8);
  timestamp = 123_456_789;
  origin = #confidential_transfer;
};

let encoded = switch (NoteCodec.encode(record)) {
  case (#ok(value)) value;
  case (#err(message)) Runtime.trap(message);
};
let decoded = switch (NoteCodec.decode(encoded)) {
  case (#ok(value)) value;
  case (#err(message)) Runtime.trap(message);
};
assert decoded.btype == record.btype;
assert decoded.phash == record.phash;
assert decoded.encoding_version == record.encoding_version;
assert decoded.note_position == record.note_position;
assert decoded.commitment == record.commitment;
assert decoded.ephemeral_key == record.ephemeral_key;
assert decoded.note_ciphertext == record.note_ciphertext;
assert decoded.nullifiers == record.nullifiers;
assert decoded.anchor_before == record.anchor_before;
assert decoded.note_root_after == record.note_root_after;
assert decoded.timestamp == record.timestamp;
assert decoded.origin == record.origin;

let encoded_bytes = Blob.toArray(encoded);
let changed_payload = replaceByte(
  encoded,
  48,
  if (encoded_bytes[48] == 0) 1 else 0,
);
assert codecError(NoteCodec.decode(changed_payload), "note-codec:checksum");
assert codecError(NoteCodec.decode(truncate(encoded)), "note-codec:frame-length");
assert codecError(NoteCodec.decode(replaceByte(encoded, 8, 2)), "note-codec:layout-version");
Debug.print("G3-CODEC PASS");

let log = StableLog.newState();
StableLog.ensureInit(log);
switch (StableLog.append(log, encoded)) {
  case (#ok(index)) assert index == 0;
  case (#err(message)) Runtime.trap(message);
};
assert StableLog.get(log, 0) == ?encoded;
assert StableLog.size(log) == 1;
assert switch (StableLog.validate(log)) { case (#ok(_)) true; case (#err(_)) false };
Region.storeNat32(log.index_region, 8, 2);
assert unitError(StableLog.validate(log), "stable-log:layout-version");
Region.storeNat32(log.index_region, 8, StableLog.LAYOUT_VERSION);
assert switch (StableLog.validate(log)) { case (#ok(_)) true; case (#err(_)) false };

let set = StableBlobSet.newState();
StableBlobSet.ensureInit(set);
let key = bytes(32, 9);
let missing = bytes(32, 10);
assert switch (StableBlobSet.put(set, key)) { case (#ok(true)) true; case _ false };
assert switch (StableBlobSet.put(set, key)) { case (#ok(false)) true; case _ false };
assert StableBlobSet.size(set) == 1;
assert StableBlobSet.contains(set, key);
assert not StableBlobSet.contains(set, missing);
assert switch (StableBlobSet.validate(set)) { case (#ok(_)) true; case (#err(_)) false };

Region.storeNat8(set.region, 0, 0);
assert unitError(StableBlobSet.validate(set), "stable-set:magic");
Region.storeNat8(set.region, 0, 0x5a);
Region.storeNat32(set.region, 8, 2);
assert unitError(StableBlobSet.validate(set), "stable-set:layout-version");
Region.storeNat32(set.region, 8, StableBlobSet.LAYOUT_VERSION);
assert switch (StableBlobSet.validate(set)) { case (#ok(_)) true; case (#err(_)) false };

var i : Nat = 11;
while (i < 40) {
  switch (StableBlobSet.put(set, bytes(32, i))) {
    case (#ok(true)) {};
    case (#ok(false)) Runtime.trap("unexpected duplicate");
    case (#err(message)) Runtime.trap(message);
  };
  i += 1;
};
assert StableBlobSet.size(set) == 30;
assert set.capacity >= 64;
assert switch (StableBlobSet.validate(set)) { case (#ok(_)) true; case (#err(_)) false };
Debug.print("G3-STORAGE PASS");

public query func result() : async { codec : Bool; storage : Bool; set_entries : Nat } {
  { codec = true; storage = true; set_entries = StableBlobSet.size(set) }
};

}
