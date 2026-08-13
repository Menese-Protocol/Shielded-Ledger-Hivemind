/// hashOf output-identity fixture, test-only.
///
/// Separate from ScaleFixture on purpose. ScaleFixture has to compile against BOTH the current
/// module and the frozen layout-1 one at tests/layout1 — that is what makes the migration battery a
/// genuine cross-version test — so it may not reference anything the layout-1 module lacks. These
/// probes call StableBlobSet.hashFor and cachedHashOf, which exist only in the current module, so
/// they live here.
///
/// What this exists to catch: since layout 2 the 8-byte hash prefix is PERSISTED in every slot. A
/// hashOf that returns a different Nat64 for any key leaves every cached hash in every existing
/// table silently wrong, and lookups miss keys that are present — a double spend on
/// spent_nullifiers, a replay on completed_*_intents. Equivalence is therefore measured, not argued.
import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Nat "mo:core/Nat";
import Nat8 "mo:core/Nat8";
import Nat64 "mo:core/Nat64";
import Runtime "mo:core/Runtime";
import Sha256 "mo:sha2/Sha256";
import StableBlobSet "../src/StableBlobSet";

persistent actor HashParityFixture {
  public type Result<T> = { #ok : T; #err : Text };

  let keys = StableBlobSet.newState();
  StableBlobSet.ensureInit(keys);

  /// Same derivation ScaleFixture uses for its migration corpus, so the two agree on what key N is.
  func corpusKey(index : Nat) : Blob {
    let seed = Blob.fromArray(Array.tabulate<Nat8>(9, func(i) {
      if (i == 0) 9 else Nat8.fromNat((index / (256 ** (i - 1))) % 256)
    }));
    Sha256.fromBlob(#sha256, seed)
  };

  /// The PREVIOUS hashOf, transcribed verbatim from src/StableBlobSet.mo as it stood before the
  /// allocation change. Kept here rather than in the module so the module has exactly one.
  func legacyHashOf(key : Blob) : Nat64 {
    let digest = Blob.toArray(Sha256.fromBlob(#sha256, key));
    var value : Nat64 = 0;
    var i : Nat = 0;
    while (i < 8) {
      value := value * 256 + Nat64.fromNat(Nat8.toNat(digest[i]));
      i += 1;
    };
    value
  };

  /// Edge inputs the deterministic corpus cannot reach: empty, all-zero, all-ones, single bytes, a
  /// counting pattern longer than the digest, and an all-ones-bit key. A leading zero byte is where
  /// a shift-and-or would diverge from a multiply-and-add if either were wrong about width.
  func edgeKey(index : Nat) : Blob {
    switch (index) {
      case 0 "";
      case 1 Blob.fromArray(Array.repeat<Nat8>(0, 32));
      case 2 Blob.fromArray(Array.repeat<Nat8>(255, 32));
      case 3 Blob.fromArray([0]);
      case 4 Blob.fromArray([255]);
      case 5 Blob.fromArray(Array.tabulate<Nat8>(64, func(i) { Nat8.fromNat(i % 256) }));
      case _ Blob.fromArray(Array.repeat<Nat8>(1, 32));
    }
  };

  let EDGE_COUNT : Nat = 7;

  /// (checked, mismatches) comparing the module's hashOf against the previous implementation over
  /// the corpus [from, from+count) plus the edge inputs.
  public query func hash_parity(from : Nat, count : Nat) : async (Nat, Nat) {
    var checked = 0;
    var mismatches = 0;
    var i = 0;
    while (i < EDGE_COUNT) {
      let key = edgeKey(i);
      if (StableBlobSet.hashFor(key) != legacyHashOf(key)) mismatches += 1;
      checked += 1;
      i += 1;
    };
    i := 0;
    while (i < count) {
      let key = corpusKey(from + i);
      if (StableBlobSet.hashFor(key) != legacyHashOf(key)) mismatches += 1;
      checked += 1;
      i += 1;
    };
    (checked, mismatches)
  };

  /// (checked, missing, mismatches) comparing the module's hashOf against the hash PERSISTED in each
  /// key's slot. This is the half hash_parity cannot do: on a table seeded before an upgrade those
  /// bytes were written by the OLD module, so this compares the new implementation against the old
  /// one's actual output rather than against a transcription of it.
  public query func cached_hash_parity(from : Nat, count : Nat) : async (Nat, Nat, Nat) {
    var checked = 0;
    var missing = 0;
    var mismatches = 0;
    var i = 0;
    while (i < count) {
      let key = corpusKey(from + i);
      switch (StableBlobSet.cachedHashOf(keys, key)) {
        case null missing += 1;
        case (?stored) { if (stored != StableBlobSet.hashFor(key)) mismatches += 1 };
      };
      checked += 1;
      i += 1;
    };
    (checked, missing, mismatches)
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

  public query func contains_range(from : Nat, count : Nat) : async Nat {
    var present = 0;
    var i = 0;
    while (i < count) {
      if (StableBlobSet.contains(keys, corpusKey(from + i))) present += 1;
      i += 1;
    };
    present
  };

  public query func layout() : async (Nat64, Nat64, Nat64) {
    (StableBlobSet.activeStride(keys), keys.capacity, keys.entry_count)
  };
  public query func digest() : async Blob { StableBlobSet.digest(keys) };
  public query func validate() : async Result<()> { StableBlobSet.validate(keys) };

  public query func edge_count() : async Nat { EDGE_COUNT };

  public func trap_if(condition : Bool) : async () {
    if (condition) Runtime.trap("TEST_ONLY:hash-parity");
  };
}
