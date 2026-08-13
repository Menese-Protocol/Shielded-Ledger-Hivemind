/// Property gate for `PoseidonTree.frontierRootOf`.
///
/// The repair path derives a root from lanes rather than accepting one from its caller, so the
/// derivation has to be right or the repair installs a root nobody checked. This pins it against
/// code that already exists, with no oracle needed:
///
///     for any frontier f and leaf L, if append(f, zeros, L) = (f', root)
///     then frontierRootOf(f', zeros) == root
///
/// If the derivation ever stops agreeing with the append walk, this fails at the first leaf.
///
/// The RED leg matters as much: a derivation that returned a constant would satisfy the property
/// vacuously on an empty tree, so the run also asserts the roots actually MOVE as leaves land.
///
/// Runs as a WASI program (moc -wasi-system-api, wasmtime).
/// Menese DeFi Team.

import Prim "mo:⛔";
import Runtime "mo:core/Runtime";
import Nat "mo:core/Nat";
import P "../src/PoseidonTree";

let zeros = P.zeroHashes();
var frontier = P.emptyFrontier(zeros);

// The empty tree's root must equal the derivation on the empty frontier.
let emptyDerived = P.frontierRootOf(frontier, zeros);
Prim.debugPrint("empty-tree root derived = " # P.natToHex(emptyDerived));

var checked = 0;
var distinct : [Nat] = [emptyDerived];
var i : Nat = 0;
while (i < 24) {
  // A leaf that varies per position, so a derivation ignoring its input cannot pass.
  let leaf = P.hashN([i + 7, i * 31 + 1]);
  let (nextFrontier, appendRoot) = P.append(frontier, zeros, leaf);
  let derived = P.frontierRootOf(nextFrontier, zeros);
  if (derived != appendRoot) {
    Runtime.trap(
      "FRONTIER-ROOT DIVERGENCE at leaf " # Nat.toText(i)
      # "  append=" # P.natToHex(appendRoot)
      # "  derived=" # P.natToHex(derived)
    );
  };
  frontier := nextFrontier;
  checked += 1;
  var seen = false;
  for (d in distinct.vals()) { if (d == appendRoot) seen := true };
  if (not seen) { distinct := Prim.Array_tabulate<Nat>(distinct.size() + 1, func(k) { if (k < distinct.size()) distinct[k] else appendRoot }) };
  i += 1;
};

// RED leg: the roots must actually move. A derivation returning a constant would agree with a
// broken append on every leaf and this property would be vacuous.
if (distinct.size() < checked) {
  Runtime.trap(
    "VACUOUS: only " # Nat.toText(distinct.size()) # " distinct roots across "
    # Nat.toText(checked) # " appends -- the roots are not moving, so agreement proves nothing"
  );
};

Prim.debugPrint(
  "PASS FrontierRootProperty: " # Nat.toText(checked)
  # " appends, derived root equals the append root every time, "
  # Nat.toText(distinct.size()) # " distinct roots so the check is not vacuous"
);
