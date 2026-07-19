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
import Nat32 "mo:core/Nat32";
import Nat64 "mo:core/Nat64";
import Runtime "mo:core/Runtime";
import VarArray "mo:core/VarArray";
import Prim "mo:⛔";
import FpM "../src/groth16/FpMont";
import FpFlat "../src/groth16/FpFlat";
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

  // ---- L3 differential gates (flat backend vs its L2 anchor), oracle-methodology §3 ----

  public type Gate = { pass : Bool; checked : Nat; detail : Text };

  transient var rngState : Nat64 = 0x243F6A8885A308D3; // pi digits; deterministic across runs

  func rnd() : Nat64 {
    var x = rngState;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    rngState := x;
    x *% 0x2545F4914F6CDD1D
  };

  /// Uniform-enough Nat < P for differential vectors (build 12 random limbs, reduce mod P).
  func randFp() : Nat {
    var v : Nat = 0;
    var i = 0;
    while (i < 12) { v := v * 0x100000000 + Nat64.toNat(rnd() & 0xFFFFFFFF); i += 1 };
    v % FpM.P
  };

  func gateFail(what : Text, i : Nat) : Gate {
    { pass = false; checked = i; detail = what }
  };

  /// Differential test (Fp): FpFlat vs FpMont — montMul/add/sub/neg on the edge grid + `iters` random pairs,
  /// inv every 64th vector. Byte-identity: FpFlat limb results converted back must equal the
  /// FpMont Nat results EXACTLY, per vector (stronger than a digest — first divergence returned).
  public func gate_fp_flat(iters : Nat) : async Gate {
    let z = FpFlat.newBuf(8); // A=0 B=12 R=24 W=36 R2=48 (spare 60) T=72 (needs 14 of the 24 left)
    let edges : [Nat] = [0, 1, FpM.P - 1, FpM.P - 2, FpM.toMont(1)];
    var checked = 0;
    let total = iters + edges.size() * edges.size();
    var k = 0;
    while (k < total) {
      let (a, b) = if (k < edges.size() * edges.size()) {
        (edges[k / edges.size()], edges[k % edges.size()])
      } else { (randFp(), randFp()) };
      FpFlat.fromNat(a, z, 0);
      FpFlat.fromNat(b, z, 12);
      FpFlat.montMulInto(z, 24, z, 0, z, 12, z, 72);
      if (FpFlat.toNat(z, 24) != FpM.montMul(a, b)) return gateFail("montMul", k);
      FpFlat.addInto(z, 24, z, 0, z, 12);
      if (FpFlat.toNat(z, 24) != FpM.add(a, b)) return gateFail("add", k);
      FpFlat.subInto(z, 24, z, 0, z, 12);
      if (FpFlat.toNat(z, 24) != FpM.sub(a, b)) return gateFail("sub", k);
      FpFlat.negInto(z, 24, z, 0);
      if (FpFlat.toNat(z, 24) != FpM.sub(0, a)) return gateFail("neg", k);
      // aliasing forms: z := z * b and z := z + z must match the non-aliased results
      FpFlat.copy(z, 48, z, 0);
      FpFlat.montMulInto(z, 48, z, 48, z, 12, z, 72);
      if (FpFlat.toNat(z, 48) != FpM.montMul(a, b)) return gateFail("montMul-alias", k);
      FpFlat.copy(z, 48, z, 0);
      FpFlat.addInto(z, 48, z, 48, z, 48);
      if (FpFlat.toNat(z, 48) != FpM.add(a, a)) return gateFail("add-alias", k);
      // Fermat inv is ~770 muls on BOTH sides (the L2 side in slow normal-form pow), so it is
      // strided to keep the gate inside one message's instruction budget.
      if (k % 512 == 0 and a != 0) {
        // montInv(â) must equal toMont(inv(fromMont(â))) — the exact L2 inversion semantics.
        FpFlat.montInvInto(z, 24, z, 0, z, 36, z, 72);
        if (FpFlat.toNat(z, 24) != FpM.toMont(FpM.inv(FpM.montMul(a, 1)))) {
          return gateFail("inv", k);
        };
      };
      checked += 1;
      k += 1;
    };
    if (not FpFlat.isOneMont(z, 24)) {
      FpFlat.oneMontInto(z, 24);
      if (FpFlat.toNat(z, 24) != FpM.toMont(1)) return gateFail("one-mont", checked);
    };
    { pass = true; checked; detail = "FpFlat == FpMont on edge grid + random vectors" }
  };

  /// Flat montMul perf/alloc — the number that must be ~0 bytes/op.
  public func probe_flat_mont_mul(iters : Nat) : async Probe {
    let z = FpFlat.newBuf(8);
    FpFlat.fromNat(FpM.toMont(A_N), z, 0);
    FpFlat.fromNat(FpM.toMont(B_N), z, 12);
    let a0 = Prim.rts_total_allocation();
    let c0 = Prim.performanceCounter(0);
    var i = 0;
    while (i < iters) {
      FpFlat.montMulInto(z, 0, z, 0, z, 12, z, 72);
      i += 1;
    };
    let c1 = Prim.performanceCounter(0);
    let a1 = Prim.rts_total_allocation();
    sink += Nat32.toNat(z[0]) % 1024;
    { alloc = a1 - a0 : Nat; instructions = c1 - c0; iters }
  };

  // ---- representation probes: which storage forms are zero-alloc on wasm64/EOP ----
  // These decide the Phase-2 limb representation (measured, not assumed). Loops are written
  // INLINE (no closure) so capture-cell boxing cannot pollute the local-arithmetic numbers.

  public func probe_nat32_array_store(iters : Nat) : async Probe {
    let arr : [var Nat32] = VarArray.repeat<Nat32>(0, 16);
    let a0 = Prim.rts_total_allocation();
    let c0 = Prim.performanceCounter(0);
    var x : Nat32 = 0x9e3779b9;
    var i = 0;
    while (i < iters) {
      x := x *% 0x85ebca6b +% 1;
      arr[Nat32.toNat(x % 16)] := x;
      i += 1;
    };
    let c1 = Prim.performanceCounter(0);
    let a1 = Prim.rts_total_allocation();
    sink += Nat32.toNat(arr[0]) % 1024;
    { alloc = a1 - a0 : Nat; instructions = c1 - c0; iters }
  };

  public func probe_nat64_array_store(iters : Nat) : async Probe {
    let arr : [var Nat64] = VarArray.repeat<Nat64>(0, 16);
    let a0 = Prim.rts_total_allocation();
    let c0 = Prim.performanceCounter(0);
    var x : Nat64 = 0x9e3779b97f4a7c15; // full-width 64-bit values
    var i = 0;
    while (i < iters) {
      x := x *% 0xbf58476d1ce4e5b9 +% 1;
      arr[Nat64.toNat(x % 16)] := x;
      i += 1;
    };
    let c1 = Prim.performanceCounter(0);
    let a1 = Prim.rts_total_allocation();
    sink += Nat64.toNat(arr[0] % 1024);
    { alloc = a1 - a0 : Nat; instructions = c1 - c0; iters }
  };

  /// One simulated CIOS inner step (32x32->64 split mul + carry adds) purely in Nat64 locals.
  public func probe_nat64_local_arith(iters : Nat) : async Probe {
    let a0 = Prim.rts_total_allocation();
    let c0 = Prim.performanceCounter(0);
    var a : Nat64 = 0x123456789abcdef0;
    var b : Nat64 = 0x9abcdef012345678;
    var carry : Nat64 = 0;
    var i = 0;
    while (i < iters) {
      let lo = (a & 0xFFFFFFFF) *% (b & 0xFFFFFFFF);
      let hi = (a >> 32) *% (b & 0xFFFFFFFF);
      carry := (lo >> 32) +% (hi & 0xFFFFFFFF);
      a := (lo & 0xFFFFFFFF) +% (carry << 32) +% 1;
      b := b +% a;
      i += 1;
    };
    let c1 = Prim.performanceCounter(0);
    let a1 = Prim.rts_total_allocation();
    sink += Nat64.toNat((a +% carry) % 1024);
    { alloc = a1 - a0 : Nat; instructions = c1 - c0; iters }
  };

  /// Same arithmetic but through a closure-captured `var` (does capture-cell update box?).
  public func probe_nat64_capture_store(iters : Nat) : async Probe {
    var x : Nat64 = 0x9e3779b97f4a7c15;
    let p = run(iters, func() { x := x *% 0xbf58476d1ce4e5b9 +% 1 });
    sink += Nat64.toNat(x % 1024);
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
