/// AC-REG-0 (hard-rule 6): with DETECT_CHAIN off, the certifiedTuple `detect_stream` label is
/// ABSENT and the hash-tree digest is byte-identical to the pre-feature five-leaf tree. This proves
/// it structurally: the NEW build(tuple with detect_stream=null) digest == the OLD (pre-feature)
/// tree digest, hand-built inline from the exact 44692fc structure. A Some(detect_stream) tuple
/// digests differently (the label is present). Run: moc -r $(mops sources) tests/DetectStreamByteIdentity.mo
import CT "../src/CertifiedTuple";
import Blob "mo:core/Blob";
import Nat8 "mo:core/Nat8";
import Text "mo:core/Text";
import Array "mo:core/Array";
import Debug "mo:core/Debug";

func b(n : Nat) : Blob { Blob.fromArray(Array.tabulate<Nat8>(32, func i = Nat8.fromNat((n + i) % 256))) };
func ll(name : Text, v : Blob) : CT.HashTree { #labeled(Text.encodeUtf8(name), #leaf(v)) };

let archive = b(1);
let audit = b(2);
let noteRoot = b(3);
let tipHash = b(4);
let ev = 7;
let nc = 123;
let idx = 122;

// OLD (pre-feature) tree, hand-built to the EXACT 44692fc structure (tip fork + 5-leaf zk fork).
let oldZk : CT.HashTree = #labeled(Text.encodeUtf8("zk"),
  #fork(ll("archive_manifest", archive),
    #fork(ll("audit", audit),
      #fork(ll("encoding_version", Blob.fromArray(CT.leb128Nat(ev))),
        #fork(ll("note_count", Blob.fromArray(CT.leb128Nat(nc))),
          ll("note_root", noteRoot))))));
let oldTree : CT.HashTree = #fork(
  #labeled(Text.encodeUtf8("tip"), #fork(ll("last_block_hash", tipHash), ll("last_block_index", Blob.fromArray(CT.leb128Nat(idx))))),
  oldZk);
let oldDigest = CT.digest(oldTree);

// NEW build with detect_stream = null (flag OFF; pir2_boundary null too — the all-None
// tuple is the 44692fc-identical baseline)
let tOff : CT.Tuple = { last_block_index = ?idx; last_block_hash = ?tipHash; note_count = nc; note_root = noteRoot; encoding_version = ev; archive_manifest = archive; audit_digest = audit; pir2_boundary = null; detect_stream = null };
let offDigest = CT.digest(CT.build(tOff));

// NEW build with detect_stream = Some (flag ON)
let tOn : CT.Tuple = { tOff with detect_stream = ?b(9) };
let onDigest = CT.digest(CT.build(tOn));

Debug.print("flag-off == baseline (byte-identical): " # (if (offDigest == oldDigest) "PASS" else "FAIL"));
Debug.print("flag-on  != baseline (label present)  : " # (if (onDigest != oldDigest) "PASS" else "FAIL"));
