/// Canonical IC hash tree for the ICRC-3 tip plus shielded-ledger state.
/// The source ICRC-ME module is read-only; this PoC-local module corrects its leaf domain separator
/// and decimal-text tip encoding against the pinned IC/ICRC-3 specifications.

import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Nat8 "mo:core/Nat8";
import Text "mo:core/Text";
import Sha256 "mo:sha2/Sha256";

module {
  public type Tuple = {
    last_block_index : ?Nat;
    last_block_hash : ?Blob;
    note_count : Nat;
    note_root : Blob;
    encoding_version : Nat;
    archive_manifest : Blob;
  };

  public type HashTree = {
    #empty;
    #fork : (HashTree, HashTree);
    #labeled : (Blob, HashTree);
    #leaf : Blob;
    #pruned : Blob;
  };

  func labeledLeaf(name : Text, value : Blob) : HashTree {
    #labeled(Text.encodeUtf8(name), #leaf(value))
  };

  func zkTree(tuple : Tuple) : HashTree {
    #labeled(
      Text.encodeUtf8("zk"),
      #fork(
        labeledLeaf("archive_manifest", tuple.archive_manifest),
        #fork(
          labeledLeaf("encoding_version", Blob.fromArray(leb128Nat(tuple.encoding_version))),
          #fork(
            labeledLeaf("note_count", Blob.fromArray(leb128Nat(tuple.note_count))),
            labeledLeaf("note_root", tuple.note_root),
          ),
        ),
      ),
    )
  };

  public func build(tuple : Tuple) : HashTree {
    switch (tuple.last_block_index, tuple.last_block_hash) {
      case (?index, ?hash) {
        #fork(
          #labeled(
            Text.encodeUtf8("tip"),
            #fork(
              labeledLeaf("last_block_hash", hash),
              labeledLeaf("last_block_index", Blob.fromArray(leb128Nat(index))),
            ),
          ),
          zkTree(tuple),
        )
      };
      case (null, null) zkTree(tuple);
      case _ { assert false; #empty };
    }
  };

  public func leb128Nat(input : Nat) : [Nat8] {
    var value = input;
    var output : [Nat8] = [];
    loop {
      var byte = value % 128;
      value /= 128;
      if (value != 0) byte += 128;
      output := Array.concat(output, [Nat8.fromNat(byte)]);
      if (value == 0) return output;
    };
  };

  func hashConcat(domain : Text, parts : [Blob]) : Blob {
    let digest = Sha256.Digest(#sha256);
    let encoded = Text.encodeUtf8(domain);
    digest.writeArray([Nat8.fromNat(encoded.size())]);
    digest.writeBlob(encoded);
    for (part in parts.vals()) { digest.writeBlob(part) };
    digest.sum()
  };

  public func digest(tree : HashTree) : Blob {
    switch (tree) {
      case (#empty) hashConcat("ic-hashtree-empty", []);
      case (#fork(left, right)) hashConcat("ic-hashtree-fork", [digest(left), digest(right)]);
      case (#labeled(name, subtree)) hashConcat("ic-hashtree-labeled", [name, digest(subtree)]);
      case (#leaf(value)) hashConcat("ic-hashtree-leaf", [value]);
      case (#pruned(hash)) hash;
    }
  };

  public func encodeCBOR(tree : HashTree) : Blob {
    Blob.fromArray(encodeTree(tree))
  };

  func encodeTree(tree : HashTree) : [Nat8] {
    switch (tree) {
      case (#empty) [0x81, 0x00] : [Nat8];
      case (#fork(left, right)) {
        Array.concat(([0x83, 0x01] : [Nat8]), Array.concat(encodeTree(left), encodeTree(right)))
      };
      case (#labeled(name, subtree)) {
        Array.concat(([0x83, 0x02] : [Nat8]), Array.concat(encodeBlob(name), encodeTree(subtree)))
      };
      case (#leaf(value)) Array.concat(([0x82, 0x03] : [Nat8]), encodeBlob(value));
      case (#pruned(hash)) Array.concat(([0x82, 0x04] : [Nat8]), encodeBlob(hash));
    }
  };

  func encodeBlob(value : Blob) : [Nat8] {
    let bytes = Blob.toArray(value);
    let size = bytes.size();
    if (size < 24) {
      Array.concat([Nat8.fromNat(0x40 + size)], bytes)
    } else if (size < 256) {
      Array.concat(([0x58, Nat8.fromNat(size)] : [Nat8]), bytes)
    } else if (size < 65_536) {
      Array.concat(([0x59, Nat8.fromNat(size / 256), Nat8.fromNat(size % 256)] : [Nat8]), bytes)
    } else {
      assert false;
      []
    }
  };
}
