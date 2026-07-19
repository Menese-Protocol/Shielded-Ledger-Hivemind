/// PROFILING HARNESS — allocation-churn breakdown of the in-process Groth16 verify path.
///
/// This actor is TEST/HARNESS INFRASTRUCTURE ONLY. It is never installed as the ledger and no
/// production canister imports it. It exists so the allocation work is aimed
/// by measurement, not guesswork: every probe wraps ONE verify component in
/// `Prim.rts_total_allocation()` + `performanceCounter(0)` deltas, on the frozen fixture vectors,
/// so the ~340 MB/op churn decomposes into an exact component table. The sum of component probes
/// must reconcile against the full `verifyPrepared` probe (checked by the Rust driver,
/// soak/src/bin/profile.rs).
///
/// Probes are UPDATE calls (a transfer verify is ~12.6B instructions — far over the query limit).
/// `sink` accumulates a value derived from every computation so no measured region is dead code.

import Array "mo:core/Array";
import Blob "mo:core/Blob";
import List "mo:core/List";
import Nat8 "mo:core/Nat8";
import Nat64 "mo:core/Nat64";
import Runtime "mo:core/Runtime";
import Prim "mo:⛔";
import FpM "../src/groth16/FpMont";
import TM "../src/groth16/TowerMont";
import C "../src/groth16/Curve";
import CJ "../src/groth16/CurveJac";
import PP "../src/groth16/PairingProjective";
import PF "../src/groth16/PairingFinalExp";
import GM "../src/groth16/Groth16Multi";
import GW "../src/groth16/Groth16Wire";
import ICRC3 "../src/ICRC3";
import NoteCodec "../src/NoteCodec";

persistent actor ChurnProfile {
  public type Probe = { alloc : Nat; instructions : Nat64; iters : Nat };

  transient var vk : ?GM.PreparedVk = null;
  transient var sink : Nat = 0;

  func requireVk() : GM.PreparedVk {
    switch (vk) { case (?v) v; case null Runtime.trap("set_vk first") }
  };

  func run(iters : Nat, f : () -> ()) : Probe {
    let a0 = Prim.rts_total_allocation();
    let c0 = Prim.performanceCounter(0);
    var i = 0;
    while (i < iters) { f(); i += 1 };
    let c1 = Prim.performanceCounter(0);
    let a1 = Prim.rts_total_allocation();
    { alloc = a1 - a0 : Nat; instructions = c1 - c0; iters }
  };

  // ---- prerequisites computed OUTSIDE measured regions ----

  func bytesOf(hex : Text) : [Nat8] {
    switch (GW.hexToBytes(hex)) { case (?b) b; case null Runtime.trap("bad hex") }
  };
  func proofOf(hex : Text) : GW.WireProof {
    switch (GW.parseProof(bytesOf(hex))) { case (?p) p; case null Runtime.trap("bad proof") }
  };
  func inputsOf(hex : Text) : [Nat] {
    switch (GW.parseInputs(bytesOf(hex))) { case (?xs) xs; case null Runtime.trap("bad inputs") }
  };
  func fp12Sink(x : TM.Fp12M) { sink += x.c0.c0.c0 % 1024 };
  func g1Sink(p : C.G1) { switch (p) { case (#inf) sink += 1; case (#pt(q)) sink += q.x % 1024 } };

  public func set_vk(vkHex : Text) : async Bool {
    vk := GW.parseAndPrepareVk(vkHex);
    vk != null
  };

  public query func sink_value() : async Nat { sink };

  // ---- component probes (transfer or deposit vectors, chosen by the driver's arguments) ----

  public func probe_hex(proofHex : Text, inputsHex : Text, iters : Nat) : async Probe {
    run(iters, func() {
      switch (GW.hexToBytes(proofHex)) { case (?b) sink += b.size(); case null {} };
      switch (GW.hexToBytes(inputsHex)) { case (?b) sink += b.size(); case null {} };
    })
  };

  public func probe_parse_proof(proofHex : Text, iters : Nat) : async Probe {
    let bytes = bytesOf(proofHex);
    run(iters, func() {
      switch (GW.parseProof(bytes)) { case (?p) g1Sink(p.a); case null {} };
    })
  };

  public func probe_parse_inputs(inputsHex : Text, iters : Nat) : async Probe {
    let bytes = bytesOf(inputsHex);
    run(iters, func() {
      switch (GW.parseInputs(bytes)) { case (?xs) sink += xs.size(); case null {} };
    })
  };

  public func probe_g1_validate_a(proofHex : Text, iters : Nat) : async Probe {
    let p = proofOf(proofHex);
    run(iters, func() {
      switch (CJ.g1Validate(p.a)) { case (#ok) sink += 1; case (#err(_)) {} };
    })
  };

  public func probe_g1_validate_c(proofHex : Text, iters : Nat) : async Probe {
    let p = proofOf(proofHex);
    run(iters, func() {
      switch (CJ.g1Validate(p.c)) { case (#ok) sink += 1; case (#err(_)) {} };
    })
  };

  public func probe_g2_validate_b(proofHex : Text, iters : Nat) : async Probe {
    let p = proofOf(proofHex);
    run(iters, func() {
      switch (CJ.g2Validate(p.b)) { case (#ok) sink += 1; case (#err(_)) {} };
    })
  };

  public func probe_vkx(inputsHex : Text, iters : Nat) : async Probe {
    let v = requireVk();
    let inputs = inputsOf(inputsHex);
    run(iters, func() { g1Sink(CJ.vkX(v.gammaAbc, inputs)) })
  };

  public func probe_prepare_b(proofHex : Text, iters : Nat) : async Probe {
    let p = proofOf(proofHex);
    run(iters, func() { sink += PP.prepareG2(p.b).ellCoeffs.size() })
  };

  public func probe_multi_miller(proofHex : Text, inputsHex : Text, iters : Nat) : async Probe {
    let v = requireVk();
    let p = proofOf(proofHex);
    let vkx = CJ.vkX(v.gammaAbc, inputsOf(inputsHex));
    let bPrep = PP.prepareG2(p.b);
    run(iters, func() { fp12Sink(GM.multiMillerRaw(v, p.a, bPrep, p.c, vkx)) })
  };

  public func probe_final_exp(proofHex : Text, inputsHex : Text, iters : Nat) : async Probe {
    let v = requireVk();
    let p = proofOf(proofHex);
    let raw = GM.multiMillerRaw(v, p.a, PP.prepareG2(p.b), p.c, CJ.vkX(v.gammaAbc, inputsOf(inputsHex)));
    run(iters, func() { fp12Sink(PF.finalExponentiate(raw)) })
  };

  public func probe_full_verify(proofHex : Text, inputsHex : Text, iters : Nat) : async Probe {
    let v = requireVk();
    run(iters, func() { sink += GW.verifyPrepared(v, proofHex, inputsHex).size() })
  };

  // ---- micro probes: bytes per primitive op ----

  // Pinned nonzero field elements (normal form < P), converted once outside the region.
  let A_N : Nat = 0x123456789abcdef0fedcba9876543210aa55aa55aa55aa55deadbeefcafebabe1122334455667788;
  let B_N : Nat = 0x0fedcba987654321f0e1d2c3b4a5968710fedcba98765432aabbccddeeff00112233445566778899;

  public func probe_mont_mul(iters : Nat) : async Probe {
    let a = FpM.toMont(A_N);
    let b = FpM.toMont(B_N);
    var acc = a;
    let p = run(iters, func() { acc := FpM.montMul(acc, b) });
    sink += acc % 1024;
    p
  };

  public func probe_fp_mul_normal(iters : Nat) : async Probe {
    var acc = A_N;
    let p = run(iters, func() { acc := FpM.mul(acc, B_N) });
    sink += acc % 1024;
    p
  };

  public func probe_fp_add(iters : Nat) : async Probe {
    var acc = A_N;
    let p = run(iters, func() { acc := FpM.add(acc, B_N) });
    sink += acc % 1024;
    p
  };

  public func probe_fp2_mul(iters : Nat) : async Probe {
    let a : TM.Fp2M = { c0 = FpM.toMont(A_N); c1 = FpM.toMont(B_N) };
    var acc = a;
    let p = run(iters, func() { acc := TM.fp2Mul(acc, a) });
    sink += acc.c0 % 1024;
    p
  };

  public func probe_fp6_mul(iters : Nat) : async Probe {
    let x : TM.Fp2M = { c0 = FpM.toMont(A_N); c1 = FpM.toMont(B_N) };
    let a : TM.Fp6M = { c0 = x; c1 = x; c2 = x };
    var acc = a;
    let p = run(iters, func() { acc := TM.fp6Mul(acc, a) });
    sink += acc.c0.c0 % 1024;
    p
  };

  public func probe_fp12_sqr_fast(iters : Nat) : async Probe {
    let x : TM.Fp2M = { c0 = FpM.toMont(A_N); c1 = FpM.toMont(B_N) };
    let s : TM.Fp6M = { c0 = x; c1 = x; c2 = x };
    var acc : TM.Fp12M = { c0 = s; c1 = s };
    let p = run(iters, func() { acc := TM.fp12SqrFast(acc) });
    fp12Sink(acc);
    p
  };

  public func probe_cyclotomic_sqr(iters : Nat) : async Probe {
    let x : TM.Fp2M = { c0 = FpM.toMont(A_N); c1 = FpM.toMont(B_N) };
    let s : TM.Fp6M = { c0 = x; c1 = x; c2 = x };
    var acc : TM.Fp12M = { c0 = s; c1 = s };
    let p = run(iters, func() { acc := PF.cyclotomicSquare(acc) });
    fp12Sink(acc);
    p
  };

  public func probe_g1_jac_add(iters : Nat) : async Probe {
    let g = CJ.g1FromAffine(C.g1Gen);
    let h = CJ.g1Dbl(g);
    var acc = g;
    let p = run(iters, func() { acc := CJ.g1Add(acc, h) });
    sink += acc.x % 1024;
    p
  };

  public func probe_g1_jac_dbl(iters : Nat) : async Probe {
    var acc = CJ.g1FromAffine(C.g1Gen);
    let p = run(iters, func() { acc := CJ.g1Dbl(acc) });
    sink += acc.x % 1024;
    p
  };

  // ---- ledger-side (non-verify) probes ----

  func repeatBlob(byte : Nat8, size : Nat) : Blob {
    Blob.fromArray(Array.repeat<Nat8>(byte, size))
  };

  func sampleBlock() : NoteCodec.ShieldedNoteBlock {
    {
      btype = "zknote1";
      phash = ?repeatBlob(7, 32);
      encoding_version = 1;
      note_position = 51987;
      commitment = repeatBlob(1, 32);
      ephemeral_key = repeatBlob(2, 16);
      note_ciphertext = repeatBlob(3, 112);
      nullifiers = [repeatBlob(4, 32), repeatBlob(5, 32)];
      anchor_before = repeatBlob(6, 32);
      note_root_after = repeatBlob(8, 32);
      timestamp = 1_784_246_400_000_000_000;
      origin = #confidential_transfer;
    }
  };

  // Main.mo `blockValue` replicated shape-for-shape (private there), so the ICRC-3 hashing cost
  // of one appended block is measured on the exact Value tree the ledger hashes.
  func sampleBlockValue() : ICRC3.Value {
    let block = sampleBlock();
    let entries = List.empty<(Text, ICRC3.Value)>();
    List.add(entries, ("btype", #Text(block.btype) : ICRC3.Value));
    switch (block.phash) { case (?hash) List.add(entries, ("phash", #Blob(hash) : ICRC3.Value)); case null {} };
    List.add(entries, ("encoding_version", #Nat(block.encoding_version) : ICRC3.Value));
    List.add(entries, ("note_position", #Nat(block.note_position) : ICRC3.Value));
    List.add(entries, ("commitment", #Blob(block.commitment) : ICRC3.Value));
    List.add(entries, ("ephemeral_key", #Blob(block.ephemeral_key) : ICRC3.Value));
    List.add(entries, ("note_ciphertext", #Blob(block.note_ciphertext) : ICRC3.Value));
    List.add(entries, ("nullifiers", #Array(Array.map<Blob, ICRC3.Value>(block.nullifiers, func(v) { #Blob(v) }))));
    List.add(entries, ("anchor_before", #Blob(block.anchor_before) : ICRC3.Value));
    List.add(entries, ("note_root_after", #Blob(block.note_root_after) : ICRC3.Value));
    List.add(entries, ("timestamp", #Nat(Nat64.toNat(block.timestamp)) : ICRC3.Value));
    List.add(entries, ("origin", #Text("confidential_transfer") : ICRC3.Value));
    #Map(List.toArray(entries))
  };

  public func probe_icrc3_block_hash(iters : Nat) : async Probe {
    let value = sampleBlockValue();
    run(iters, func() { sink += ICRC3.hashValue(value).size() })
  };

  public func probe_icrc3_build_and_hash(iters : Nat) : async Probe {
    run(iters, func() { sink += ICRC3.hashValue(sampleBlockValue()).size() })
  };

  public func probe_notecodec_encode(iters : Nat) : async Probe {
    let block = sampleBlock();
    run(iters, func() {
      switch (NoteCodec.encode(block)) { case (#ok(b)) sink += b.size(); case (#err(_)) {} };
    })
  };

  public func probe_notecodec_decode(iters : Nat) : async Probe {
    let encoded = switch (NoteCodec.encode(sampleBlock())) {
      case (#ok(b)) b;
      case (#err(e)) Runtime.trap(e);
    };
    run(iters, func() {
      switch (NoteCodec.decode(encoded)) { case (#ok(b)) sink += b.note_position; case (#err(_)) {} };
    })
  };

  // Main.mo `blobToHex` replicated verbatim (private there): per-32-byte-blob Text churn.
  func nibbleText(n : Nat) : Text {
    switch (n) {
      case 0 "0"; case 1 "1"; case 2 "2"; case 3 "3";
      case 4 "4"; case 5 "5"; case 6 "6"; case 7 "7";
      case 8 "8"; case 9 "9"; case 10 "a"; case 11 "b";
      case 12 "c"; case 13 "d"; case 14 "e"; case _ "f";
    }
  };
  public func probe_blob_to_hex(iters : Nat) : async Probe {
    let value = repeatBlob(0xab, 32);
    run(iters, func() {
      var result = "";
      for (byte in value.vals()) {
        let n = Nat8.toNat(byte);
        result #= nibbleText(n / 16) # nibbleText(n % 16);
      };
      sink += result.size();
    })
  };
}
