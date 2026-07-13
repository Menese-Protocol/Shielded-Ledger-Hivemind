/// ICRC-3 Value and representation-independent hashing.
/// Normative oracle: dfinity/ICRC-1 standards/ICRC-3 at commit 5d670e54d9a58fbf472bf0a25f33743d60cfd0e6.

import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Int "mo:core/Int";
import List "mo:core/List";
import Nat8 "mo:core/Nat8";
import Text "mo:core/Text";
import Sha256 "mo:sha2/Sha256";

module {
  public type Value = {
    #Blob : Blob;
    #Text : Text;
    #Nat : Nat;
    #Int : Int;
    #Array : [Value];
    #Map : [(Text, Value)];
  };

  public func leb128Nat(input : Nat) : [Nat8] {
    let output = List.empty<Nat8>();
    var value = input;
    loop {
      var byte = value % 128;
      value /= 128;
      if (value != 0) byte += 128;
      List.add(output, Nat8.fromNat(byte));
      if (value == 0) return List.toArray(output);
    };
  };

  public func sleb128Int(input : Int) : [Nat8] {
    let output = List.empty<Nat8>();
    var value = input;
    loop {
      // Euclidean low seven bits, including for negative arbitrary-precision Int values.
      let low : Int = ((value % 128) + 128) % 128;
      let byte = Int.abs(low);
      let next = (value - low) / 128;
      let signSet = byte >= 64;
      let done = (next == 0 and not signSet) or (next == -1 and signSet);
      List.add(output, Nat8.fromNat(if (done) byte else byte + 128));
      if (done) return List.toArray(output);
      value := next;
    };
  };

  func compareBlob(left : Blob, right : Blob) : { #less; #equal; #greater } {
    let a = Blob.toArray(left);
    let b = Blob.toArray(right);
    let limit = if (a.size() < b.size()) a.size() else b.size();
    var i : Nat = 0;
    while (i < limit) {
      if (a[i] < b[i]) return #less;
      if (a[i] > b[i]) return #greater;
      i += 1;
    };
    if (a.size() < b.size()) #less else if (a.size() > b.size()) #greater else #equal
  };

  func compareHashPair(
    left : (Blob, Blob),
    right : (Blob, Blob),
  ) : { #less; #equal; #greater } {
    switch (compareBlob(left.0, right.0)) {
      case (#equal) compareBlob(left.1, right.1);
      case (#less) #less;
      case (#greater) #greater;
    }
  };

  func sha256(value : Blob) : Blob { Sha256.fromBlob(#sha256, value) };

  public func hashValue(value : Value) : Blob {
    switch (value) {
      case (#Blob(bytes)) sha256(bytes);
      case (#Text(text)) sha256(Text.encodeUtf8(text));
      case (#Nat(number)) sha256(Blob.fromArray(leb128Nat(number)));
      case (#Int(number)) sha256(Blob.fromArray(sleb128Int(number)));
      case (#Array(values)) {
        let digest = Sha256.Digest(#sha256);
        for (element in values.vals()) { digest.writeBlob(hashValue(element)) };
        digest.sum()
      };
      case (#Map(entries)) {
        let pairs = Array.map<(Text, Value), (Blob, Blob)>(entries, func((key, entry)) {
          (sha256(Text.encodeUtf8(key)), hashValue(entry))
        });
        let sorted = Array.sort<(Blob, Blob)>(pairs, compareHashPair);
        let digest = Sha256.Digest(#sha256);
        for ((keyHash, valueHash) in sorted.vals()) {
          digest.writeBlob(keyHash);
          digest.writeBlob(valueHash);
        };
        digest.sum()
      };
    }
  };
}
