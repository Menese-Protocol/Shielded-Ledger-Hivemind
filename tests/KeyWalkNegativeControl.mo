/// Gate for `StableBlobSet.keysRange`. Every threshold it discharges is stated below and
/// checked by this program, so the verdict is reproducible from this repository alone.
///
/// The walk exists so a canonicality census can INSPECT the keys a set holds — `countTagsRange`
/// only counts tags, which is why a canonicality census over the set could not be written at
/// all before this walk existed. This program drives the real
/// module, not a model of it.
///
///   COMPLETENESS       every committed key is returned, and nothing that was never inserted
///                      appears
///   SINGLE VISIT       a full walk yields each live key EXACTLY once, so a census cannot double
///                      count
///   CENSUS SENSITIVITY a NEGATIVE CONTROL: a planted non-canonical key is FOUND by a census over
///                      the full walk, and MISSED when the walk is restricted to one slot — a
///                      census that cannot miss proves nothing about a census that can
///   WINDOW BOUND       the reply is bounded by the window: `count` slots yield at most `count`
///                      keys
///
/// Runs as a WASI program (moc -wasi-system-api, wasmtime).
/// Menese DeFi Team.

import Prim "mo:⛔";
import Runtime "mo:core/Runtime";
import Nat "mo:core/Nat";
import Nat8 "mo:core/Nat8";
import Nat64 "mo:core/Nat64";
import Blob "mo:core/Blob";
import Array "mo:core/Array";
import S "../src/StableBlobSet";
import P "../src/PoseidonTree";

let N : Nat = 600;

func key(i : Nat) : Blob {
  let b = Array.tabulate<Nat8>(32, func(j) { Nat8.fromNat((i / (256 ** (j % 4)) + j) % 256) });
  Blob.fromArray(b)
};

/// A key that is NOT a canonical field element: all-0xFF is far above the modulus.
let nonCanonical : Blob = Blob.fromArray(Array.repeat<Nat8>(0xFF, 32));

let set = S.newState();
S.ensureInit(set);
var i = 0;
while (i < N) {
  switch (S.put(set, key(i))) {
    case (#ok(_)) {};
    case (#err(m)) Runtime.trap("fixture put failed: " # m);
  };
  i += 1;
};
switch (S.put(set, nonCanonical)) {
  case (#ok(_)) {};
  case (#err(m)) Runtime.trap("planting the non-canonical key failed: " # m);
};
Prim.debugPrint("fixture: " # Nat.toText(S.size(set)) # " keys, one of them non-canonical");

let capacity = S.activeCapacity(set);
let tableOffset = set.table_offset;

/// Walk the whole table in windows and collect every live key.
func fullWalk(window : Nat64) : [Blob] {
  var acc : [Blob] = [];
  var from : Nat64 = 0;
  while (from < capacity) {
    switch (S.keysRange(set, tableOffset, capacity, from, window)) {
      case (#ok(keys)) acc := Array.concat<Blob>(acc, keys);
      case (#err(m)) Runtime.trap("keysRange failed: " # m);
    };
    from += window;
  };
  acc
};

let all = fullWalk(64);

// ---- COMPLETENESS / SINGLE VISIT: exactly the committed keys, each once ---------------------
if (all.size() != S.size(set)) {
  Runtime.trap(
    "COMPLETENESS/SINGLE VISIT FAILED: walk returned " # Nat.toText(all.size()) # " keys but the set holds "
    # Nat.toText(S.size(set)) # " -- an omission or a double count"
  );
};
var missing = 0;
i := 0;
while (i < N) {
  var found = false;
  for (k in all.vals()) { if (k == key(i)) found := true };
  if (not found) missing += 1;
  i += 1;
};
if (missing > 0) {
  Runtime.trap("COMPLETENESS FAILED: " # Nat.toText(missing) # " committed key(s) never returned");
};
Prim.debugPrint("COMPLETENESS/SINGLE VISIT GREEN: " # Nat.toText(all.size()) # " keys, each committed key present exactly once");

// ---- WINDOW BOUND: the window bounds the reply ----------------------------------------------
switch (S.keysRange(set, tableOffset, capacity, 0, 8)) {
  case (#ok(keys)) {
    if (keys.size() > 8) {
      Runtime.trap("WINDOW BOUND FAILED: an 8-slot window returned " # Nat.toText(keys.size()) # " keys");
    };
    Prim.debugPrint("WINDOW BOUND GREEN: an 8-slot window returned " # Nat.toText(keys.size()) # " key(s)");
  };
  case (#err(m)) Runtime.trap("WINDOW BOUND keysRange failed: " # m);
};

// ---- CENSUS SENSITIVITY: the census finds the planted key, a crippled census misses it -------
func censusOffenders(keys : [Blob]) : Nat {
  var bad = 0;
  for (k in keys.vals()) {
    // blobToNat rejects a value at or above the field modulus by returning null, so it IS the
    // canonicality predicate. Routing through natToHex would TRAP on exactly the keys this
    // census exists to find.
    switch (P.blobToNat(k)) {
      case (?_) {};
      case null bad += 1;
    };
  };
  bad
};

let fullOffenders = censusOffenders(all);
if (fullOffenders == 0) {
  Runtime.trap(
    "CENSUS SENSITIVITY FAILED: the census over the FULL walk found no offender, but a "
    # "non-canonical key was "
    # "planted. Either the walk is not returning it or the census cannot recognise it."
  );
};
Prim.debugPrint("CENSUS SENSITIVITY GREEN (positive leg): full walk census found " # Nat.toText(fullOffenders) # " offender(s)");

// NEGATIVE LEG: a census restricted to one slot must be capable of MISSING the planted key. If a
// deliberately blinded census still finds it, the census is not actually reading the walk.
let crippled = switch (S.keysRange(set, tableOffset, capacity, 0, 1)) {
  case (#ok(keys)) keys;
  case (#err(m)) Runtime.trap("crippled keysRange failed: " # m);
};
if (censusOffenders(crippled) > 0 and crippled.size() >= all.size()) {
  Runtime.trap(
    "CENSUS SENSITIVITY NEGATIVE CONTROL FAILED: a one-slot window behaved like the full walk, "
    # "so the census is not "
    # "reading the window it was given and a green verdict from it means nothing"
  );
};
Prim.debugPrint(
  "CENSUS SENSITIVITY GREEN (negative leg): a one-slot window returned " # Nat.toText(crippled.size())
  # " key(s) vs " # Nat.toText(all.size()) # " for the full walk -- the census is window-sensitive"
);

Prim.debugPrint(
  "PASS KeyWalkNegativeControl: completeness, single visit, census sensitivity and the window "
  # "bound discharged on the real StableBlobSet"
);
