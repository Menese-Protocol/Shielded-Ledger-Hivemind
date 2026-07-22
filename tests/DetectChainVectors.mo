/// Differential: DetectChain.mo (Motoko) must reproduce the JS reference construction
/// (demo-frontend/scripts/restore/detect-chain.mjs) byte-for-byte. Vectors:
/// for-team/detect-chain-vectors.json. Run: moc -r $(mops sources) tests/DetectChainVectors.mo
import DetectChain "../src/DetectChain";
import Blob "mo:core/Blob";
import Nat8 "mo:core/Nat8";
import Array "mo:core/Array";
import Char "mo:core/Char";
import Debug "mo:core/Debug";

let HEXC = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'];
func hex(b : Blob) : Text {
  var t = "";
  for (x in Blob.toArray(b).vals()) t #= Char.toText(HEXC[Nat8.toNat(x) / 16]) # Char.toText(HEXC[Nat8.toNat(x) % 16]);
  t
};

// chain over 10 deterministic entries E_i[b] = (i*7 + b*3) & 0xff
var chain = Blob.fromArray(Array.repeat<Nat8>(0, 32));
var i = 0;
while (i < 10) {
  let e = Blob.fromArray(Array.tabulate<Nat8>(48, func b = Nat8.fromNat((i * 7 + b * 3) % 256)));
  chain := DetectChain.fold(chain, e);
  i += 1;
};
Debug.print("cTip=" # hex(chain));
let root0 = DetectChain.merkleRoot([]);
Debug.print("detectLeaf=" # hex(DetectChain.detectLeaf(root0, chain, 10)));
// merkle over 5 leaves L_j[b] = (j*11 + b) & 0xff
let leaves = Array.tabulate<Blob>(5, func j = Blob.fromArray(Array.tabulate<Nat8>(32, func b = Nat8.fromNat((j * 11 + b) % 256))));
Debug.print("merkleRoot=" # hex(DetectChain.merkleRoot(leaves)));
Debug.print("leafHash0=" # hex(DetectChain.leafHash(leaves[0])));
