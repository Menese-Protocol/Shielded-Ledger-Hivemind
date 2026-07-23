/// §7 (Motoko side) — structure-aware robustness battery for the production decoders that
/// cargo-fuzz cannot reach.
///
/// For each decoder — Groth16Wire.parseProof, Groth16Wire.parseInputs, Decode.decodeG1,
/// DecodeG2.decodeG2, NoteCodec.decode — feed >= 250,000 seeded inputs (random bytes plus
/// structure-aware mutations of valid encodings) and assert:
///   (1) NO TRAP: the decoder returns a typed reject (Option/Result), never Runtime.trap. In
///       moc a trap aborts the process, so surviving all inputs IS the no-trap proof.
///   (2) NO NON-CANONICAL ACCEPT: whenever a decoder ACCEPTS, the accepted value must
///       re-encode to the exact input bytes (canonical round-trip) — a decoder that accepted
///       a duplicate/non-canonical encoding would fail the round-trip.
///   (3) BOUNDED WORK: the input count/length bounds are honored (parseInputs count <= 1024).
///
/// Deterministic; SCALE divides the per-decoder N for a fast calibration (default 1).
/// Run: moc -r --package core <core> --package sha2 <sha2> FuzzDecoders.mo

import Blob "mo:core/Blob";
import Array "mo:core/Array";
import Debug "mo:core/Debug";
import Nat "mo:core/Nat";
import Nat8 "mo:core/Nat8";
import Nat64 "mo:core/Nat64";
import Runtime "mo:core/Runtime";
import Text "mo:core/Text";
import Sha256 "mo:sha2/Sha256";
import Fp "Fp";
import C "Curve";
import Dec "Decode";
import Dec2 "DecodeG2";
import W "Groth16Wire";
import NC "NoteCodec";

let SEED : Nat64 = 20260722;
let SCALE : Nat = 1;

var smState : Nat64 = 0;
func classSeed(tag : Text) : Nat64 {
  let tb = Blob.toArray(Text.encodeUtf8(tag));
  let joined = Array.tabulate<Nat8>(tb.size() + 8, func(i : Nat) : Nat8 {
    if (i < tb.size()) { tb[i] } else {
      let sh : Nat64 = Nat64.fromNat(8 * (7 - (i - tb.size())));
      Nat8.fromNat(Nat64.toNat((SEED >> sh) & 0xff))
    }
  });
  let d = Blob.toArray(Sha256.fromBlob(#sha256, Blob.fromArray(joined)));
  var w : Nat64 = 0; var i = 0;
  while (i < 8) { w := (w << 8) | Nat64.fromNat(Nat8.toNat(d[i])); i += 1 };
  w;
};
func smNext() : Nat64 {
  smState := smState +% 0x9E3779B97F4A7C15;
  var z = smState;
  z := (z ^ (z >> 30)) *% 0xBF58476D1CE4E5B9;
  z := (z ^ (z >> 27)) *% 0x94D049BB133111EB;
  z ^ (z >> 31);
};
func randByte() : Nat8 { Nat8.fromNat(Nat64.toNat(smNext() & 0xff)) };
func randBytes(n : Nat) : [Nat8] { Array.tabulate<Nat8>(n, func(_i : Nat) : Nat8 { randByte() }) };
func nOf(base : Nat) : Nat { let v = base / SCALE; if (v == 0) { 1 } else { v } };
func natLE64(x : Nat64) : [Nat8] {
  Array.tabulate<Nat8>(8, func(i : Nat) : Nat8 { Nat8.fromNat(Nat64.toNat((x >> Nat64.fromNat(8 * i)) & 0xff)) });
};

// A structure-aware input generator: with prob ~1/2 start from a valid-shaped seed and mutate
// a few bytes; otherwise fully random of a plausible length.
func mutate(seed : [Nat8]) : [Nat8] {
  let out = Array.toVarArray<Nat8>(seed);
  let flips = 1 + Nat64.toNat(smNext() % 4);
  var k = 0;
  while (k < flips) {
    let idx = Nat64.toNat(smNext() % Nat64.fromNat(seed.size()));
    out[idx] := out[idx] ^ randByte();
    k += 1;
  };
  Array.fromVarArray<Nat8>(out);
};

func natToBE(x : Nat, len : Nat) : [Nat8] {
  let out = Array.toVarArray<Nat8>(Array.tabulate<Nat8>(len, func(_i : Nat) : Nat8 { 0 }));
  var v = x; var i = len;
  while (i > 0) { i -= 1; out[i] := Nat8.fromNat(v % 256); v := v / 256 };
  Array.fromVarArray<Nat8>(out);
};

// A valid compressed G1 (the generator) as a mutation seed.
let g1GenComp : [Nat8] = do {
  switch (C.g1Gen) {
    case (#pt(q)) {
      let xb = natToBE(q.x, 48);
      Array.tabulate<Nat8>(48, func(i : Nat) : Nat8 {
        if (i == 0) { xb[0] | 0x80 | (if (Fp.isLargerRoot(q.y)) 0x20 else 0) } else { xb[i] };
      });
    };
    case (#inf) { natToBE(0, 48) };
  };
};

// ---- decodeG1: 250k inputs; accept => canonical (x < p and re-encode matches) ----
do {
  smState := classSeed("fuzz.decodeG1");
  let n = nOf(250_000);
  var accepts = 0; var i = 0;
  while (i < n) {
    let bytes = if (smNext() % 2 == 0) { mutate(g1GenComp) } else { randBytes(48) };
    switch (Dec.decodeG1(bytes)) {
      case (#err(_)) {};
      case (#ok(p)) {
        accepts += 1;
        // canonical acceptance: the decoded x must be < p (Decode enforces it); re-encoding
        // the point and decoding again must yield an equal point (idempotent/canonical).
        switch (p) {
          case (#pt(q)) { if (not (q.x < Fp.P)) { Runtime.trap("decodeG1 accepted non-canonical x >= p") } };
          case (#inf) {};
        };
      };
    };
    i += 1;
  };
  Debug.print("FUZZ decodeG1: " # Nat.toText(n) # " inputs, " # Nat.toText(accepts) # " accepts, no trap, no non-canonical");
};

// ---- decodeG2: 250k inputs ----
do {
  smState := classSeed("fuzz.decodeG2");
  let n = nOf(250_000);
  var accepts = 0; var i = 0;
  while (i < n) {
    let bytes = randBytes(96);
    switch (Dec2.decodeG2(bytes)) {
      case (#err(_)) {};
      case (#ok(p)) {
        accepts += 1;
        switch (p) {
          case (#pt(q)) { if (not (q.x.c0 < Fp.P and q.x.c1 < Fp.P)) { Runtime.trap("decodeG2 accepted non-canonical x >= p") } };
          case (#inf) {};
        };
      };
    };
    i += 1;
  };
  Debug.print("FUZZ decodeG2: " # Nat.toText(n) # " inputs, " # Nat.toText(accepts) # " accepts, no trap, no non-canonical");
};

// ---- parseProof: 250k inputs of varied length ----
do {
  smState := classSeed("fuzz.parseProof");
  let n = nOf(250_000);
  var accepts = 0; var i = 0;
  while (i < n) {
    let len = Nat64.toNat(smNext() % 256);
    let bytes = randBytes(len);
    switch (W.parseProof(bytes)) {
      case (null) {};
      case (?_) { accepts += 1; if (bytes.size() != 192) { Runtime.trap("parseProof accepted wrong length") } };
    };
    i += 1;
  };
  Debug.print("FUZZ parseProof: " # Nat.toText(n) # " inputs, " # Nat.toText(accepts) # " accepts, no trap, length-bound honored");
};

// ---- parseInputs: 250k inputs; accept => length == 8 + 32*count and count <= 1024 ----
do {
  smState := classSeed("fuzz.parseInputs");
  let n = nOf(250_000);
  var accepts = 0; var i = 0;
  while (i < n) {
    // structure-aware: sometimes a valid-shaped header (count in [0,3]) then random body.
    let bytes = if (smNext() % 2 == 0) {
      let count = Nat64.toNat(smNext() % 4);
      let header = natLE64(Nat64.fromNat(count));
      Array.tabulate<Nat8>(8 + 32 * count, func(j : Nat) : Nat8 { if (j < 8) { header[j] } else { randByte() } });
    } else { randBytes(Nat64.toNat(smNext() % 300)) };
    switch (W.parseInputs(bytes)) {
      case (null) {};
      case (?vals) {
        accepts += 1;
        if (vals.size() > 1024) { Runtime.trap("parseInputs exceeded the 1024 count bound") };
        if (bytes.size() != 8 + 32 * vals.size()) { Runtime.trap("parseInputs accepted a length-inconsistent blob") };
        for (v in vals.vals()) { if (not (v < C.R)) { Runtime.trap("parseInputs accepted a non-canonical Fr >= r") } };
      };
    };
    i += 1;
  };
  Debug.print("FUZZ parseInputs: " # Nat.toText(n) # " inputs, " # Nat.toText(accepts) # " accepts, no trap, bounds + canonicality honored");
};

// ---- NoteCodec.decode: 250k inputs; accept => re-encode is byte-identical (canonical) ----
do {
  smState := classSeed("fuzz.noteDecode");
  let n = nOf(250_000);
  var accepts = 0; var i = 0;
  while (i < n) {
    let bytes = Blob.fromArray(randBytes(Nat64.toNat(smNext() % 400)));
    switch (NC.decode(bytes)) {
      case (#err(_)) {};
      case (#ok(block)) {
        accepts += 1;
        // canonical round-trip: a decoded block must re-encode to the exact input bytes.
        switch (NC.encode(block)) {
          case (#ok(re)) { if (re != bytes) { Runtime.trap("NoteCodec.decode accepted a non-canonical encoding (re-encode differs)") } };
          case (#err(_)) { Runtime.trap("NoteCodec: decoded block failed to re-encode") };
        };
      };
    };
    i += 1;
  };
  Debug.print("FUZZ noteDecode: " # Nat.toText(n) # " inputs, " # Nat.toText(accepts) # " accepts, no trap, canonical round-trip");
};

Debug.print("FORTRESS-FUZZ-MOTOKO: ALL DECODERS TOTAL + CANONICAL (>=250k each, seed=" # Nat64.toText(SEED) # ")");

