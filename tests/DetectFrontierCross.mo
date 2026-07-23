/// AC-1 cross-language consumer: recomputes the gen-frontier-vectors.mjs families with the
/// Motoko INCREMENTAL FRONTIER (and the full append path through DetectChain.append) and
/// prints one `key=hex` line per vector; scripts/detect-battery.sh diffs every line against
/// tests/detect-frontier-vectors.json. Formulas mirror the generator exactly:
///   leaf[i][b]  = (i*2654435761 + b*40503) mod 256
///   entry[i][b] = (i*7 + b*3) mod 256
/// Run: moc $(mops sources) -wasi-system-api --incremental-gc tests/DetectFrontierCross.mo \
///        -o cross.wasm && wasmtime cross.wasm
import DetectChain "../src/DetectChain";
import Blob "mo:core/Blob";
import Nat8 "mo:core/Nat8";
import Nat "mo:core/Nat";
import Array "mo:core/Array";
import Char "mo:core/Char";
import Debug "mo:core/Debug";

let HEXC = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'];
func hex(b : Blob) : Text {
  var t = "";
  for (x in Blob.toArray(b).vals()) t #= Char.toText(HEXC[Nat8.toNat(x) / 16]) # Char.toText(HEXC[Nat8.toNat(x) % 16]);
  t
};

func leafAt(i : Nat) : Blob {
  Blob.fromArray(Array.tabulate<Nat8>(32, func b = Nat8.fromNat((i * 2654435761 + b * 40503) % 256)))
};

let MERKLE_SIZES : [Nat] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17, 255, 256, 257, 1023, 1024, 1025, 4095, 4096, 4097, 12207, 24413, 24414];
var maxSize = 0;
for (s in MERKLE_SIZES.vals()) if (s > maxSize) maxSize := s;

// one incremental frontier pass; print the FRONTIER root at each vector size
let f = DetectChain.emptyFrontier();
var i = 0;
var next = 0;
while (i < maxSize) {
  DetectChain.frontierAppend(f, i, leafAt(i));
  i += 1;
  if (next < MERKLE_SIZES.size() and MERKLE_SIZES[next] == i) {
    Debug.print("merkle[" # Nat.toText(i) # "]=" # hex(DetectChain.frontierRoot(f)));
    next += 1;
  };
};

// full append path through the PRODUCTION DetectChain.append (State + frontier):
// generator entries are posBE8(i) ‖ ct_i[0..40) with ct_i[j] = (i*7 + j*3) mod 256, so
// feeding just the ciphertext through append() reproduces them via entryBytes().
let APPEND_N = 25 * DetectChain.DPAGE + 517;
func ctAt(i : Nat) : [Nat8] {
  Array.tabulate<Nat8>(40, func j = Nat8.fromNat((i * 7 + j * 3) % 256))
};
let s = DetectChain.newState();
let sf = DetectChain.emptyFrontier();
var p = 0;
while (p < APPEND_N) {
  DetectChain.append(s, sf, p, ctAt(p));
  p += 1;
};
Debug.print("appendBoundaries=" # Nat.toText(s.covered));
Debug.print("appendRoot=" # hex(s.root));
Debug.print("appendCTip=" # hex(s.chain));
Debug.print("appendLeaf=" # hex(DetectChain.detectLeaf(s.root, s.chain, s.count)));
