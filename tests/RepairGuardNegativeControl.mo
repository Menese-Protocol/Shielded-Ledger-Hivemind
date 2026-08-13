/// NEGATIVE CONTROL for `repair_tree_state`'s lane validation: the modulus check, not the hex
/// shape, is what stops a corrupt lane being installed.
///
/// The repair is the most dangerous function in this ledger: it writes the tree state every
/// anchor derives from. Its safety rests on refusing any supplied lane that is not a canonical
/// field element, and on DERIVING the root rather than accepting one. This program shows both
/// guards are load-bearing by removing them.
///
///   POSITIVE  the real guard rejects a non-canonical lane, so no state would be written
///   NEGATIVE  a shape-only guard (32 bytes of hex, no modulus check) ACCEPTS it, and the
///             repair would install exactly the value it exists to remove
///
///   ROOT   the derived root of a repaired frontier differs from a root a caller might name,
///          so accepting a caller-supplied root is not equivalent to deriving one
///
/// Runs as a WASI program (moc -wasi-system-api, wasmtime).
/// Menese DeFi Team.

import Prim "mo:⛔";
import Runtime "mo:core/Runtime";
import _Nat "mo:core/Nat";
import _Array "mo:core/Array";
import P "../src/PoseidonTree";

/// The repair's real lane check, verbatim: `hexToNat` returns null at or above the modulus.
func realGuard(lane : Text) : Bool {
  switch (P.hexToNat(lane)) { case (?_) true; case null false }
};

/// The guard as it would be if the modulus check were dropped: 64 hex characters and nothing else.
func shapeOnlyGuard(lane : Text) : Bool {
  if (lane.size() != 64) return false;
  for (c in lane.chars()) {
    let ok = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f');
    if (not ok) return false;
  };
  true
};

// A canonical lane, and a lane that is 64 well-formed hex characters but far above the modulus.
let canonicalLane = P.natToHex(P.hashN([11, 22]));
let nonCanonicalLane = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

// ---- GREEN: the real guard separates them ---------------------------------------------------
if (not realGuard(canonicalLane)) {
  Runtime.trap("GREEN FAILED: the real guard rejected a CANONICAL lane -- the repair would refuse valid input");
};
if (realGuard(nonCanonicalLane)) {
  Runtime.trap("GREEN FAILED: the real guard ACCEPTED a non-canonical lane -- the repair could install one");
};
Prim.debugPrint("GREEN: real guard accepts the canonical lane and rejects the non-canonical one");

// ---- NEGATIVE: the shape-only guard cannot tell them apart -----------------------------------
if (not shapeOnlyGuard(nonCanonicalLane)) {
  Runtime.trap(
    "LANE GUARD NEGATIVE CONTROL FAILED: the shape-only guard also rejected the non-canonical "
    # "lane, so this "
    # "fixture does not separate the two guards and proves nothing about the modulus check"
  );
};
Prim.debugPrint(
  "NEGATIVE: shape-only guard ACCEPTS the non-canonical lane -- so the modulus check is what "
  # "stops "
  # "the repair installing the value it exists to remove"
);

// ---- The root is derived, not named ----------------------------------------------------------
// A caller supplying lanes cannot also name a root: the canister derives it. Show the derived
// root of a non-trivial frontier is not something a caller could have guessed by, say, reusing
// the empty-tree root.
let zeros = P.zeroHashes();
var frontier = P.emptyFrontier(zeros);
let emptyRoot = P.frontierRootOf(frontier, zeros);
var i = 0;
while (i < 5) {
  let (nextF, _) = P.append(frontier, zeros, P.hashN([i + 90]));
  frontier := nextF;
  i += 1;
};
let derivedRoot = P.frontierRootOf(frontier, zeros);
if (derivedRoot == emptyRoot) {
  Runtime.trap(
    "ROOT CHECK FAILED: the derived root of a 5-leaf frontier equals the empty-tree root, so the "
    # "derivation is not reading the lanes and a caller-supplied root would be indistinguishable"
  );
};
Prim.debugPrint(
  "ROOT: a 5-leaf frontier derives " # P.natToHex(derivedRoot)
  # ", distinct from the empty-tree root -- the derivation reads the lanes it is given"
);

Prim.debugPrint(
  "PASS RepairGuardNegativeControl: the lane modulus check and the root derivation are both "
  # "shown load-bearing"
);
