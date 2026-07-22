/// Certified detection-stream anchor (Menese DeFi Team). Additive, flag-gated
/// (`detect_chain_enabled`, default false); flag-off changes NOTHING (no state, no certified-tuple
/// label). Mirrors demo-frontend/scripts/restore/detect-chain.mjs BYTE-FOR-BYTE so a light client
/// verifies mirror-served detection pages against what consensus certified:
///
///   entry E_i     = (pos_i BE8) || note_ciphertext_i[0..40]                     (48 B)
///   chain c_{i+1} = SHA256(c_i || E_i),   c_0 = 0^32
///   boundary L_j  = c_{DPAGE*(j+1)}       (chain after complete segment j)
///   root R        = RFC-6962 Merkle over [L_0 .. L_{covered-1}]  (leaf 0x00||v, node 0x01||a||b)
///   detect leaf   = SHA256(R || c_tip || note_count LE8)  -> folded into certifiedTuple (flag on)
///
/// Differential-checked against the JS reference by tests/DetectChainVectors.mo
/// (vectors: for-team/detect-chain-vectors.json).
import Sha256 "mo:sha2/Sha256";
import Blob "mo:core/Blob";
import Nat8 "mo:core/Nat8";
import Nat "mo:core/Nat";
import Array "mo:core/Array";
import List "mo:core/List";
import Region "mo:core/Region";
import Nat64 "mo:core/Nat64";

module {
  public let DPAGE : Nat = 4096;
  func zero32() : Blob { Blob.fromArray(Array.repeat<Nat8>(0, 32)) };

  func sha(parts : [Blob]) : Blob {
    let d = Sha256.Digest(#sha256);
    for (p in parts.vals()) d.writeBlob(p);
    d.sum()
  };

  public func fold(chain : Blob, entry : Blob) : Blob { sha([chain, entry]) };
  public func leafHash(v : Blob) : Blob { sha([Blob.fromArray([0x00]), v]) };
  public func nodeHash(a : Blob, b : Blob) : Blob { sha([Blob.fromArray([0x01]), a, b]) };

  /// The 48-B detection entry for note `position` given its stored ciphertext bytes
  /// (big-endian position || note_ciphertext[0..40], zero-padded).
  public func entryBytes(position : Nat, ciphertext : [Nat8]) : Blob {
    Blob.fromArray(Array.tabulate<Nat8>(48, func i {
      if (i < 8) Nat8.fromNat((position / (256 ** (7 - i : Nat))) % 256)
      else { let j : Nat = i - 8; if (j < ciphertext.size()) ciphertext[j] else (0 : Nat8) }
    }))
  };

  func u64LE(n : Nat) : Blob {
    Blob.fromArray(Array.tabulate<Nat8>(8, func i = Nat8.fromNat((n / (256 ** i)) % 256)))
  };

  /// RFC-6962 Merkle root over boundary leaf VALUES (odd node promoted unchanged).
  public func merkleRoot(leaves : [Blob]) : Blob {
    if (leaves.size() == 0) return zero32();
    var level = Array.map<Blob, Blob>(leaves, leafHash);
    while (level.size() > 1) {
      let next = List.empty<Blob>();
      var i = 0;
      while (i < level.size()) {
        if (i + 1 < level.size()) List.add(next, nodeHash(level[i], level[i + 1])) else List.add(next, level[i]);
        i += 2;
      };
      level := List.toArray(next);
    };
    level[0]
  };

  /// Merkle inclusion proof for leaf index j: array of (siblingHash, siblingIsRight).
  public func merkleProof(leaves : [Blob], j : Nat) : [(Blob, Bool)] {
    let path = List.empty<(Blob, Bool)>();
    var level = Array.map<Blob, Blob>(leaves, leafHash);
    var idx = j;
    while (level.size() > 1) {
      if (idx % 2 == 0) { if (idx + 1 < level.size()) List.add(path, (level[idx + 1], true)) }
      else List.add(path, (level[idx - 1], false));
      let next = List.empty<Blob>();
      var i = 0;
      while (i < level.size()) {
        if (i + 1 < level.size()) List.add(next, nodeHash(level[i], level[i + 1])) else List.add(next, level[i]);
        i += 2;
      };
      idx /= 2;
      level := List.toArray(next);
    };
    List.toArray(path)
  };

  public func detectLeaf(root : Blob, cTip : Blob, noteCount : Nat) : Blob {
    sha([root, cTip, u64LE(noteCount)])
  };

  // ---- stateful anchor maintained on the append path (flag-gated in Main.mo) ----
  public type State = {
    var chain : Blob;              // c_{note_count}
    var root : Blob;               // cached Merkle root over complete-segment boundaries
    boundaries : List.List<Blob>;  // L_0 .. L_{covered-1}
    var covered : Nat;             // number of complete segments folded
    var count : Nat;               // notes folded
  };

  public func newState() : State {
    { var chain = zero32(); var root = zero32(); boundaries = List.empty<Blob>(); var covered = 0; var count = 0 }
  };

  /// Fold one note's detection entry; on a DPAGE boundary append a leaf and recompute the root
  /// (root only changes once per DPAGE appends — cheap amortized).
  public func append(s : State, position : Nat, ciphertext : [Nat8]) {
    s.chain := fold(s.chain, entryBytes(position, ciphertext));
    s.count += 1;
    if (s.count % DPAGE == 0) {
      List.add(s.boundaries, s.chain);
      s.covered += 1;
      s.root := merkleRoot(List.toArray(s.boundaries));
    };
  };

  /// The certified-tuple leaf value (flag on). Pure function of (root, chain, count).
  public func streamLeaf(s : State) : Blob { detectLeaf(s.root, s.chain, s.count) };

  public func boundaryProofAt(s : State, j : Nat) : ?{ leaf : Blob; path : [(Blob, Bool)] } {
    let arr = List.toArray(s.boundaries);
    if (j >= arr.size()) return null;
    ?{ leaf = arr[j]; path = merkleProof(arr, j) }
  };
}
