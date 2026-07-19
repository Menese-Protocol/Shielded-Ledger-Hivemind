/// Wire boundary — the hex boundary of the Motoko Groth16 verifier.
///
/// Menese DeFi Team. This is the exact interface the shielded ledger already speaks to its
/// verifier: `(vk_hex, proof_hex, inputs_hex) -> Text`, arkworks compressed serialization:
///   proof  = A:G1(48) ‖ B:G2(96) ‖ C:G1(48)                                  (192 bytes)
///   vk     = alpha:G1 ‖ beta:G2 ‖ gamma:G2 ‖ delta:G2 ‖ u64-LE len ‖ len×G1  (344 + 48·len)
///   inputs = u64-LE count ‖ count × Fr (32 bytes LITTLE-endian, canonical < r)
/// Points are ZCash-compressed (Decode.decodeG1 / DecodeG2.decodeG2, both oracle-gated).
///
/// Verdict strings MIRROR the Rust boundary (`try_verify_bn254` in verify-bench/verifier), so the
/// ledger's callers and tests see identical strings:
///   ACCEPT · REJECT:hex · REJECT:vk-deserialize · REJECT:proof-deserialize ·
///   REJECT:inputs-deserialize · REJECT:pairing-check · REJECT:error:...
/// arkworks' deserialize_compressed validates subgroup membership INSIDE deserialization, so
/// wrong-subgroup points map to the -deserialize verdicts here too (decode = format+curve;
/// subgroup via CurveJac, same literal [r]P == O definition as L1).
///
/// The ledger parses its vk ONCE (`parseAndPrepareVk`, at configure) and per proof runs
/// `verifyPrepared` — decode B once, no vk re-validation per message.

import Nat8 "mo:core/Nat8";
import Nat64 "mo:core/Nat64";
import Array "mo:core/Array";
import Char "mo:core/Char";
import Text "mo:core/Text";
import List "mo:core/List";
import C "Curve";
import Fr "Fr";
import Dec "Decode";
import Dec2 "DecodeG2";
import GM "Groth16Multi";

module {
  // ---------------- hex ----------------
  public func hexToBytes(t : Text) : ?[Nat8] {
    let n = t.size();
    if (n % 2 != 0) { return null };
    let out = List.empty<Nat8>();
    var hi : ?Nat = null;
    for (ch in t.chars()) {
      let v = hexDigit(ch);
      switch (v) {
        case (null) { return null };
        case (?d) {
          switch (hi) {
            case (null) { hi := ?d };
            case (?h) { List.add(out, Nat8.fromNat(h * 16 + d)); hi := null };
          };
        };
      };
    };
    ?List.toArray(out);
  };
  func hexDigit(c : Char) : ?Nat {
    let n = Char.toNat32(c);
    if (n >= 48 and n <= 57) { return ?(Nat32ToNat(n) - 48) };
    if (n >= 97 and n <= 102) { return ?(Nat32ToNat(n) - 87) };
    if (n >= 65 and n <= 70) { return ?(Nat32ToNat(n) - 55) };
    null;
  };
  func Nat32ToNat(n : Nat32) : Nat { Nat64.toNat(Nat64.fromNat32(n)) };

  func slice(b : [Nat8], from : Nat, len : Nat) : [Nat8] {
    Array.tabulate<Nat8>(len, func(i) { b[from + i] });
  };

  // ---------------- scalar field (LE, canonical) ----------------
  func frFromLe(b : [Nat8], from : Nat) : ?Nat {
    var x : Nat = 0;
    var i : Nat = 32;
    while (i > 0) { i -= 1; x := x * 256 + Nat8.toNat(b[from + i]) };
    if (not Fr.isCanonical(x)) { return null };
    ?x;
  };
  func u64FromLe(b : [Nat8], from : Nat) : Nat {
    var x : Nat = 0;
    var i : Nat = 8;
    while (i > 0) { i -= 1; x := x * 256 + Nat8.toNat(b[from + i]) };
    x;
  };

  /// ark-serialize Vec<Fr>: u64 LE count, then count × 32-byte LE canonical Fr.
  public func parseInputs(bytes : [Nat8]) : ?[Nat] {
    if (bytes.size() < 8) { return null };
    let count = u64FromLe(bytes, 0);
    if (count > 1024) { return null }; // interface sanity bound, far above any pool statement
    if (bytes.size() != 8 + 32 * count) { return null };
    let out = List.empty<Nat>();
    var i : Nat = 0;
    while (i < count) {
      switch (frFromLe(bytes, 8 + 32 * i)) {
        case (null) { return null };
        case (?x) { List.add(out, x) };
      };
      i += 1;
    };
    ?List.toArray(out);
  };

  // ---------------- points (decode = format + on-curve ONLY) ----------------
  // Subgroup membership is enforced EXACTLY ONCE, inside the verifier (`Groth16Multi.verify`
  // validates A/B/C; `prepareVk` validates every vk point). Doing it here too would double the
  // most expensive per-proof component (~3.1B of duplicated [r]P checks, measured). arkworks
  // folds both halves into "deserialize", so a subgroup failure surfaced by the verifier is
  // mapped back to the -deserialize verdict string for parity (see verifyPrepared).
  func g1At(b : [Nat8], from : Nat) : ?C.G1 {
    switch (Dec.decodeG1(slice(b, from, 48))) {
      case (#err(_)) { null };
      case (#ok(p)) { ?p };
    };
  };
  func g2At(b : [Nat8], from : Nat) : ?C.G2 {
    switch (Dec2.decodeG2(slice(b, from, 96))) {
      case (#err(_)) { null };
      case (#ok(p)) { ?p };
    };
  };

  public type WireProof = { a : C.G1; b : C.G2; c : C.G1 };

  /// A:G1 ‖ B:G2 ‖ C:G1 — format + on-curve. NOT subgroup-validated here: the verifier does
  /// that once per point; callers other than `verifyPrepared` must validate before pairing.
  public func parseProof(bytes : [Nat8]) : ?WireProof {
    if (bytes.size() != 192) { return null };
    switch (g1At(bytes, 0), g2At(bytes, 48), g1At(bytes, 144)) {
      case (?a, ?b, ?c) { ?{ a; b; c } };
      case (_, _, _) { null };
    };
  };

  /// Parse AND prepare the verifying key (validation + fixed-pair preparation) — run once at
  /// vk registration, never per proof.
  public func parseAndPrepareVk(vkHex : Text) : ?GM.PreparedVk {
    switch (hexToBytes(vkHex)) {
      case (null) { null };
      case (?bytes) {
        if (bytes.size() < 344) { return null };
        let alpha = g1At(bytes, 0);
        let beta = g2At(bytes, 48);
        let gamma = g2At(bytes, 144);
        let delta = g2At(bytes, 240);
        let len = u64FromLe(bytes, 336);
        if (len < 1 or len > 1024) { return null };
        if (bytes.size() != 344 + 48 * len) { return null };
        switch (alpha, beta, gamma, delta) {
          case (?al, ?be, ?ga, ?de) {
            let ic = List.empty<C.G1>();
            var i : Nat = 0;
            while (i < len) {
              switch (g1At(bytes, 344 + 48 * i)) {
                case (null) { return null };
                case (?p) { List.add(ic, p) };
              };
              i += 1;
            };
            switch (GM.prepareVk(al, be, ga, de, List.toArray(ic))) {
              case (#ok(vk)) { ?vk };
              case (#err(_)) { null };
            };
          };
          case (_, _, _, _) { null };
        };
      };
    };
  };

  /// Per-proof verify against an already-prepared vk. Same verdict strings as the Rust
  /// boundary. Converts the vk's fixed pairs to flat limbs on the fly — callers that verify
  /// repeatedly (the ledger) use `verifyPreparedCached` with a converted-once FlatVk.
  public func verifyPrepared(vk : GM.PreparedVk, proofHex : Text, inputsHex : Text) : Text {
    verifyPreparedCached(vk, GM.prepareFlatVk(vk), proofHex, inputsHex)
  };

  /// Same wire semantics, fixed vk pairs already flat (the ledger's per-proof path).
  public func verifyPreparedCached(vk : GM.PreparedVk, flat : GM.FlatVk, proofHex : Text, inputsHex : Text) : Text {
    let proofBytes = switch (hexToBytes(proofHex)) {
      case (null) { return "REJECT:hex" };
      case (?b) { b };
    };
    let inputBytes = switch (hexToBytes(inputsHex)) {
      case (null) { return "REJECT:hex" };
      case (?b) { b };
    };
    let proof = switch (parseProof(proofBytes)) {
      case (null) { return "REJECT:proof-deserialize" };
      case (?p) { p };
    };
    let inputs = switch (parseInputs(inputBytes)) {
      case (null) { return "REJECT:inputs-deserialize" };
      case (?xs) { xs };
    };
    switch (GM.verifyWithFlat(vk, flat, proof.a, proof.b, proof.c, inputs)) {
      case (#ok) { "ACCEPT" };
      case (#err("E_PAIRING_FAIL")) { "REJECT:pairing-check" };
      // A:/B:/C: prefixed codes are the verifier's point-validation rejects (subgroup etc.) —
      // arkworks surfaces the same class at deserialization, so the verdict string matches it.
      case (#err(e)) {
        if (Text.startsWith(e, #text "A:") or Text.startsWith(e, #text "B:") or Text.startsWith(e, #text "C:")) {
          "REJECT:proof-deserialize";
        } else {
          "REJECT:error:" # e;
        };
      };
    };
  };

  /// One-shot boundary, drop-in for the Rust `try_verify_*`: parse + prepare the vk per call.
  /// The ledger should prefer `parseAndPrepareVk` once + `verifyPrepared` per proof.
  public func tryVerify(vkHex : Text, proofHex : Text, inputsHex : Text) : Text {
    switch (hexToBytes(vkHex)) {
      case (null) { return "REJECT:hex" };
      case (?_) {};
    };
    switch (parseAndPrepareVk(vkHex)) {
      case (null) { "REJECT:vk-deserialize" };
      case (?vk) { verifyPrepared(vk, proofHex, inputsHex) };
    };
  };
}
