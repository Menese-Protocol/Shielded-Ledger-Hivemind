/// AC-1 differential: the incremental boundary frontier (DetectChain.frontierAppend/
/// frontierRoot) must produce a root BYTE-IDENTICAL to the original full recompute
/// (DetectChain.merkleRoot) over the same leaves, at every size. Four families:
///   1. exhaustive sizes 0..300 (every leaf-count shape incl. all odd-promotion cases)
///   2. 1,000 seeded random checkpoint sizes <= 30,000 (xorshift64 seed printed)
///   3. scale: 24,414 boundaries (the 10^8-note count) — full compare at the end plus
///      periodic checkpoints
///   4. rebuild: frontierFromBoundaries over the scale leaf list must equal the live
///      frontier's root (the upgrade path)
/// TEETH (RED first): a planted off-by-one in the frontier fold (merge condition tests
/// the bit AFTER shifting — one level early) MUST diverge from merkleRoot on the same
/// sweep; the run traps if the mutant survives 0..300.
/// Structural: at 24,414 leaves the frontier holds <= 15 nodes (ceil(log2 B) + 1).
/// Run: moc $(mops sources) -wasi-system-api tests/DetectFrontierDifferential.mo -o det.wasm
///      && wasmtime det.wasm
import DetectChain "../src/DetectChain";
import Blob "mo:core/Blob";
import Nat8 "mo:core/Nat8";
import Nat64 "mo:core/Nat64";
import Nat "mo:core/Nat";
import Array "mo:core/Array";
import List "mo:core/List";
import Char "mo:core/Char";
import Debug "mo:core/Debug";
import Runtime "mo:core/Runtime";

let HEXC = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'];
func hex(b : Blob) : Text {
  var t = "";
  for (x in Blob.toArray(b).vals()) t #= Char.toText(HEXC[Nat8.toNat(x) / 16]) # Char.toText(HEXC[Nat8.toNat(x) % 16]);
  t
};

// xorshift64* PRNG — the whole battery is a deterministic function of SEED.
let SEED : Nat64 = 0x9e3779b97f4a7c15;
var rngState : Nat64 = SEED;
func rnd() : Nat64 {
  var x = rngState;
  x := x ^ (x >> 12);
  x := x ^ (x << 25);
  x := x ^ (x >> 27);
  rngState := x;
  x *% 0x2545f4914f6cdd1d
};

// deterministic 32-byte leaf for index i (seeded, byte-diverse)
func leafAt(i : Nat) : Blob {
  Blob.fromArray(Array.tabulate<Nat8>(32, func b {
    let v = Nat64.toNat((Nat64.fromNat(i) *% 0x9e3779b97f4a7c15 +% Nat64.fromNat(b) *% 0xbf58476d1ce4e5b9) >> 33);
    Nat8.fromNat(v % 256)
  }))
};

// MUTANT (teeth): off-by-one fold — merges based on the bit AFTER the shift, so it
// merges one level early/late relative to the binary counter. Must diverge.
func mutantAppend(f : DetectChain.Frontier, countBefore : Nat, leafValue : Blob) {
  var cur = DetectChain.leafHash(leafValue);
  var t = countBefore;
  while (t / 2 % 2 == 1) { // planted bug: inspects bit 1, not bit 0
    switch (List.removeLast(f.stack)) {
      case (?left) cur := DetectChain.nodeHash(left, cur);
      case null Runtime.trap("mutant underflow");
    };
    t /= 2;
  };
  List.add(f.stack, cur);
};

Debug.print("DETECT-FRONTIER-DIFFERENTIAL seed=" # Nat64.toText(SEED));

// ---- family 1: exhaustive 0..300 (and teeth on the same sweep) ----
let MAXE = 300;
let leaves1 = List.empty<Blob>();
let live = DetectChain.emptyFrontier();
let mutant = DetectChain.emptyFrontier();
var mutantDiverged = 0;
var n = 0;
// size 0 first: empty root must match
if (DetectChain.frontierRoot(live) != DetectChain.merkleRoot([])) Runtime.trap("size 0 diverged");
while (n < MAXE) {
  let leaf = leafAt(n);
  List.add(leaves1, leaf);
  DetectChain.frontierAppend(live, n, leaf);
  mutantAppend(mutant, n, leaf);
  n += 1;
  let expect = DetectChain.merkleRoot(List.toArray(leaves1));
  if (DetectChain.frontierRoot(live) != expect) Runtime.trap("family1 diverged at size " # Nat.toText(n));
  if (DetectChain.frontierRoot(mutant) != expect) mutantDiverged += 1;
};
if (mutantDiverged == 0) Runtime.trap("TEETH-FAILED: planted off-by-one mutant never diverged over 0..300");
Debug.print("family1 exhaustive 0..300: 301/301 byte-identical; TEETH mutant diverged at " # Nat.toText(mutantDiverged) # "/300 sizes (RED proven)");

// ---- family 2: 1,000 random checkpoint sizes <= 30,000 ----
// Sizes are drawn log-uniformly (uniform bit-length 1..15, then uniform within the
// bit-length, capped at MAX2): every tree HEIGHT gets equal probe mass — better shape
// coverage than uniform draws (which concentrate on 14-15-bit sizes) and a bounded
// total merkleRoot recompute cost (the reference side is O(size) per checkpoint).
let CHECKS = 1000;
let MAX2 = 30000;
func drawSize() : Nat {
  let bits = 1 + Nat64.toNat(rnd() % 15); // 1..15
  if (bits == 1) return 1;
  let lo = 2 ** (bits - 1 : Nat);
  let hi = Nat.min(2 ** bits - 1, MAX2);
  lo + Nat64.toNat(rnd() % Nat64.fromNat(hi - lo + 1))
};
let sizesVar = Array.toVarArray<Nat>(Array.tabulate<Nat>(CHECKS, func _ = drawSize()));
// insertion sort (1,000 elements — cost irrelevant, no index-underflow pitfalls)
func sortVar(a : [var Nat]) {
  var i = 1;
  while (i < a.size()) {
    let v = a[i];
    var j = i;
    while (j > 0 and a[j - 1] > v) { a[j] := a[j - 1]; j -= 1 };
    a[j] := v;
    i += 1;
  };
};
sortVar(sizesVar);
let leaves2 = List.empty<Blob>();
let live2 = DetectChain.emptyFrontier();
var checked2 = 0;
var k = 0;
var cur = 0;
while (k < CHECKS) {
  let target = sizesVar[k];
  while (cur < target) {
    let leaf = leafAt(1_000_000 + cur);
    List.add(leaves2, leaf);
    DetectChain.frontierAppend(live2, cur, leaf);
    cur += 1;
  };
  if (DetectChain.frontierRoot(live2) != DetectChain.merkleRoot(List.toArray(leaves2))) {
    Runtime.trap("family2 diverged at size " # Nat.toText(target));
  };
  checked2 += 1;
  k += 1;
};
Debug.print("family2 randomized: " # Nat.toText(checked2) # "/" # Nat.toText(CHECKS) # " checkpoint sizes <= " # Nat.toText(MAX2) # " byte-identical");

// ---- family 3: scale 24,414 (the 10^8-note boundary count) ----
let SCALE = 24414;
let leaves3 = List.empty<Blob>();
let live3 = DetectChain.emptyFrontier();
var s = 0;
var scaleChecks = 0;
while (s < SCALE) {
  let leaf = leafAt(2_000_000 + s);
  List.add(leaves3, leaf);
  DetectChain.frontierAppend(live3, s, leaf);
  s += 1;
  if (s % 4096 == 0 or s == SCALE) {
    if (DetectChain.frontierRoot(live3) != DetectChain.merkleRoot(List.toArray(leaves3))) {
      Runtime.trap("family3 diverged at size " # Nat.toText(s));
    };
    scaleChecks += 1;
  };
};
// structural bound: ceil(log2 24414) = 15
let stackSize = List.size(live3.stack);
if (stackSize > 15) Runtime.trap("frontier stores " # Nat.toText(stackSize) # " nodes at 24,414 — exceeds ceil(log2 B) + 1");
Debug.print("family3 scale " # Nat.toText(SCALE) # ": " # Nat.toText(scaleChecks) # " checkpoints byte-identical; frontier holds " # Nat.toText(stackSize) # " nodes (bound 15)");
Debug.print("scaleRoot=" # hex(DetectChain.frontierRoot(live3)));

// ---- family 4: rebuild-from-boundaries (upgrade path) equals the live frontier ----
let rebuilt = DetectChain.frontierFromBoundaries(leaves3);
if (DetectChain.frontierRoot(rebuilt) != DetectChain.frontierRoot(live3)) Runtime.trap("family4 rebuild diverged");
if (List.size(rebuilt.stack) != stackSize) Runtime.trap("family4 rebuild stack shape diverged");
Debug.print("family4 rebuild-from-boundaries: root + stack shape identical");

Debug.print("DETECT-FRONTIER-DIFFERENTIAL: ALL FAMILIES GREEN (teeth RED-proven)");
