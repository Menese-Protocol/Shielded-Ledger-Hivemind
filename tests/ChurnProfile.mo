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
import TF "../src/groth16/TowerFlat";
import TM "../src/groth16/TowerMont";
import C "../src/groth16/Curve";
import CF "../src/groth16/CurveFlat";
import CJ "../src/groth16/CurveJac";
import Dec "../src/groth16/Decode";
import Dec2 "../src/groth16/DecodeG2";
import PP "../src/groth16/PairingProjective";
import PF "../src/groth16/PairingFinalExp";
import GM "../src/groth16/Groth16Multi";
import PFlat "../src/groth16/PairingFlat";
import GW "../src/groth16/Groth16Wire";
import ICRC3 "../src/ICRC3";
import NoteCodec "../src/NoteCodec";

persistent actor ChurnProfile {
  public type Probe = { alloc : Nat; instructions : Nat64; iters : Nat };

  transient var vk : ?GM.PreparedVk = null;
  transient var vkFlat : ?GM.FlatVk = null;
  transient var sink : Nat = 0;

  func requireVk() : GM.PreparedVk {
    switch (vk) { case (?v) v; case null Runtime.trap("set_vk first") }
  };
  func requireFlat() : GM.FlatVk {
    switch (vkFlat) { case (?f) f; case null Runtime.trap("set_vk first") }
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
    vkFlat := switch (vk) { case (?v) ?GM.prepareFlatVk(v); case null null };
    vk != null
  };

  /// The LEDGER's exact per-proof path: cached FlatVk + verifyPreparedCached.
  public func probe_full_verify_cached(proofHex : Text, inputsHex : Text, iters : Nat) : async Probe {
    let v = requireVk();
    let f = requireFlat();
    run(iters, func() { sink += GW.verifyPreparedCached(v, f, proofHex, inputsHex).size() })
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

  // ---- tower gates: arena layout A@0(144) B@144(144) aux fp2s@300..372 D@372(144), scratch S@528 ----
  transient let TW_S : Nat = 528; // element region 0..516 (gate_fp12 D@372+144), scratch above

  func twArena() : [var Nat32] { FpFlat.newBuf((TW_S + TF.SCRATCH_LIMBS + 11) / 12 + 1) };

  func putFp(z : [var Nat32], off : Nat, x : Nat) { FpFlat.fromNat(x, z, off) };
  func putFp2(z : [var Nat32], off : Nat, e : TM.Fp2M) {
    putFp(z, off, e.c0);
    putFp(z, off + 12, e.c1);
  };
  func putFp6(z : [var Nat32], off : Nat, e : TM.Fp6M) {
    putFp2(z, off, e.c0);
    putFp2(z, off + 24, e.c1);
    putFp2(z, off + 48, e.c2);
  };
  func putFp12(z : [var Nat32], off : Nat, e : TM.Fp12M) {
    putFp6(z, off, e.c0);
    putFp6(z, off + 72, e.c1);
  };
  func getFp2(z : [var Nat32], off : Nat) : TM.Fp2M {
    { c0 = FpFlat.toNat(z, off); c1 = FpFlat.toNat(z, off + 12) }
  };
  func getFp6(z : [var Nat32], off : Nat) : TM.Fp6M {
    { c0 = getFp2(z, off); c1 = getFp2(z, off + 24); c2 = getFp2(z, off + 48) }
  };
  func getFp12(z : [var Nat32], off : Nat) : TM.Fp12M {
    { c0 = getFp6(z, off); c1 = getFp6(z, off + 72) }
  };
  func eqFp2(a : TM.Fp2M, b : TM.Fp2M) : Bool { a.c0 == b.c0 and a.c1 == b.c1 };
  func eqFp6(a : TM.Fp6M, b : TM.Fp6M) : Bool {
    eqFp2(a.c0, b.c0) and eqFp2(a.c1, b.c1) and eqFp2(a.c2, b.c2)
  };
  func eqFp12(a : TM.Fp12M, b : TM.Fp12M) : Bool { eqFp6(a.c0, b.c0) and eqFp6(a.c1, b.c1) };

  func randFp2(k : Nat) : TM.Fp2M {
    // first vectors exercise the degenerate shapes (zero / one / single-component)
    switch (k) {
      case 0 { { c0 = 0; c1 = 0 } };
      case 1 { { c0 = FpM.toMont(1); c1 = 0 } };
      case 2 { { c0 = 0; c1 = randFp() } };
      case 3 { { c0 = randFp(); c1 = 0 } };
      case _ { { c0 = randFp(); c1 = randFp() } };
    }
  };
  func randFp6(k : Nat) : TM.Fp6M {
    switch (k) {
      case 0 { { c0 = randFp2(0); c1 = randFp2(0); c2 = randFp2(0) } };
      case 1 { { c0 = randFp2(1); c1 = randFp2(0); c2 = randFp2(0) } };
      case _ { { c0 = randFp2(4); c1 = randFp2(4); c2 = randFp2(4) } };
    }
  };
  func randFp12(k : Nat) : TM.Fp12M {
    switch (k) {
      case 0 { { c0 = randFp6(0); c1 = randFp6(0) } };
      case 1 { { c0 = randFp6(1); c1 = randFp6(0) } };
      case _ { { c0 = randFp6(2); c1 = randFp6(2) } };
    }
  };

  /// Differential test (Fp2): flat Fp2 vs TowerMont — mul/sqrFast/add/sub/neg/nonresidue/mulByFp, inv strided.
  public func gate_fp2_flat(iters : Nat) : async Gate {
    let z = twArena();
    var k = 0;
    while (k < iters) {
      let a = randFp2(k);
      let b = randFp2(if (k < 5) (k + 1) % 5 else 4);
      let fp = randFp();
      putFp2(z, 0, a);
      putFp2(z, 24, b);
      putFp(z, 48, fp);
      TF.fp2MulInto(z, 288, 0, 24, TW_S);
      if (not eqFp2(getFp2(z, 288), TM.fp2Mul(a, b))) return gateFail("fp2Mul", k);
      TF.fp2SqrFastInto(z, 288, 0, TW_S);
      if (not eqFp2(getFp2(z, 288), TM.fp2SqrFast(a))) return gateFail("fp2SqrFast", k);
      TF.fp2AddInto(z, 288, 0, 24);
      if (not eqFp2(getFp2(z, 288), TM.fp2Add(a, b))) return gateFail("fp2Add", k);
      TF.fp2SubInto(z, 288, 0, 24);
      if (not eqFp2(getFp2(z, 288), TM.fp2Sub(a, b))) return gateFail("fp2Sub", k);
      TF.fp2NegInto(z, 288, 0);
      if (not eqFp2(getFp2(z, 288), TM.fp2Neg(a))) return gateFail("fp2Neg", k);
      TF.fp2MulByNonresidueInto(z, 288, 0, TW_S);
      if (not eqFp2(getFp2(z, 288), TM.fp2MulByNonresidue(a))) return gateFail("fp2Nonres", k);
      TF.fp2MulByFpInto(z, 288, 0, 48, TW_S);
      if (not eqFp2(getFp2(z, 288), TM.fp2MulByFp(a, fp))) return gateFail("fp2MulByFp", k);
      // aliased mul: a := a*b in place
      TF.fp2Copy(z, 288, 0);
      TF.fp2MulInto(z, 288, 288, 24, TW_S);
      if (not eqFp2(getFp2(z, 288), TM.fp2Mul(a, b))) return gateFail("fp2Mul-alias", k);
      if (k % 128 == 0 and not (a.c0 == 0 and a.c1 == 0)) {
        TF.fp2InvInto(z, 288, 0, TW_S);
        if (not eqFp2(getFp2(z, 288), TM.fp2Inv(a))) return gateFail("fp2Inv", k);
      };
      k += 1;
    };
    { pass = true; checked = iters; detail = "TowerFlat fp2 == TowerMont" }
  };

  /// Differential test (Fp6): flat Fp6 vs TowerMont — mul/add/sub/neg/mulByV/mulBy1/mulBy01, inv strided.
  public func gate_fp6_flat(iters : Nat) : async Gate {
    let z = twArena();
    var k = 0;
    while (k < iters) {
      let a = randFp6(k);
      let b = randFp6(if (k < 2) k + 1 else 2);
      let c0 = randFp2(4);
      let c1 = randFp2(4);
      putFp6(z, 0, a);
      putFp6(z, 144, b);
      putFp2(z, 96, c0);
      putFp2(z, 120, c1);
      TF.fp6MulInto(z, 288, 0, 144, TW_S);
      if (not eqFp6(getFp6(z, 288), TM.fp6Mul(a, b))) return gateFail("fp6Mul", k);
      TF.fp6AddInto(z, 288, 0, 144);
      if (not eqFp6(getFp6(z, 288), TM.fp6Add(a, b))) return gateFail("fp6Add", k);
      TF.fp6SubInto(z, 288, 0, 144);
      if (not eqFp6(getFp6(z, 288), TM.fp6Sub(a, b))) return gateFail("fp6Sub", k);
      TF.fp6MulByVInto(z, 288, 0, TW_S);
      if (not eqFp6(getFp6(z, 288), TM.fp6MulByV(a))) return gateFail("fp6MulByV", k);
      TF.fp6MulBy1Into(z, 288, 0, 120, TW_S);
      if (not eqFp6(getFp6(z, 288), TM.fp6MulBy1(a, c1))) return gateFail("fp6MulBy1", k);
      TF.fp6MulBy01Into(z, 288, 0, 96, 120, TW_S);
      if (not eqFp6(getFp6(z, 288), TM.fp6MulBy01(a, c0, c1))) return gateFail("fp6MulBy01", k);
      // aliased in-place mul
      TF.fp6Copy(z, 288, 0);
      TF.fp6MulInto(z, 288, 288, 288, TW_S);
      if (not eqFp6(getFp6(z, 288), TM.fp6Mul(a, a))) return gateFail("fp6Sqr-alias", k);
      if (k % 64 == 0 and k > 0) {
        TF.fp6InvInto(z, 288, 0, TW_S);
        if (not eqFp6(getFp6(z, 288), TM.fp6Inv(a))) return gateFail("fp6Inv", k);
      };
      k += 1;
    };
    { pass = true; checked = iters; detail = "TowerFlat fp6 == TowerMont" }
  };

  /// Differential test (Fp12): flat Fp12 vs TowerMont — mul/sqrFast/mulBy014/conj, inv strided, one-checks.
  public func gate_fp12_flat(iters : Nat) : async Gate {
    let z = twArena();
    var k = 0;
    while (k < iters) {
      let a = randFp12(k);
      let b = randFp12(if (k < 2) k + 1 else 2);
      let c0 = randFp2(4);
      let c1 = randFp2(4);
      let c4 = randFp2(4);
      putFp12(z, 0, a);
      putFp12(z, 144, b);
      putFp2(z, 300, c0);
      putFp2(z, 324, c1);
      putFp2(z, 348, c4);
      TF.fp12MulInto(z, 372, 0, 144, TW_S);
      if (not eqFp12(getFp12(z, 372), TM.fp12Mul(a, b))) return gateFail("fp12Mul", k);
      TF.fp12SqrFastInto(z, 372, 0, TW_S);
      if (not eqFp12(getFp12(z, 372), TM.fp12SqrFast(a))) return gateFail("fp12SqrFast", k);
      TF.fp12MulBy014Into(z, 372, 0, 300, 324, 348, TW_S);
      if (not eqFp12(getFp12(z, 372), TM.fp12MulBy014(a, c0, c1, c4))) {
        return gateFail("fp12MulBy014", k);
      };
      TF.fp12ConjInto(z, 372, 0);
      if (not eqFp12(getFp12(z, 372), TM.fp12Conj(a))) return gateFail("fp12Conj", k);
      TF.fp12Copy(z, 372, 0);
      TF.fp12MulInto(z, 372, 372, 372, TW_S);
      if (not eqFp12(getFp12(z, 372), TM.fp12Mul(a, a))) return gateFail("fp12Mul-alias", k);
      if (k % 32 == 0 and k > 0) {
        TF.fp12InvInto(z, 372, 0, TW_S);
        if (not eqFp12(getFp12(z, 372), TM.fp12Inv(a))) return gateFail("fp12Inv", k);
      };
      // one-detection parity with the verifier's target check
      TF.fp12SetOneMont(z, 372);
      if (not TF.fp12IsOneMont(z, 372)) return gateFail("fp12IsOneMont-true", k);
      if (not eqFp12(getFp12(z, 372), TM.fp12OneM())) return gateFail("fp12One", k);
      putFp12(z, 372, a);
      if (TF.fp12IsOneMont(z, 372) != TM.fp12Eq(a, TM.fp12OneM())) {
        return gateFail("fp12IsOneMont-false", k);
      };
      k += 1;
    };
    { pass = true; checked = iters; detail = "TowerFlat fp12 == TowerMont" }
  };

  // ---- curve gates: separate arena, elements 0..216, curve scratch base 240 ----
  transient let CV_S : Nat = 240; // element region 0..216 (G2 gate uses three 72-limb points)

  func cvArena() : [var Nat32] { FpFlat.newBuf((CV_S + CF.SCRATCH_LIMBS + 11) / 12 + 1) };

  /// Read a flat Jacobian G1 point back as the L2 record for exact coordinate comparison.
  func getG1J(z : [var Nat32], off : Nat) : CJ.G1J {
    { x = FpFlat.toNat(z, off); y = FpFlat.toNat(z, off + 12); z = FpFlat.toNat(z, off + 24) }
  };
  func eqG1J(a : CJ.G1J, b : CJ.G1J) : Bool { a.x == b.x and a.y == b.y and a.z == b.z };
  func getG2J(z : [var Nat32], off : Nat) : CJ.G2J {
    { x = getFp2(z, off); y = getFp2(z, off + 24); z = getFp2(z, off + 48) }
  };
  func eqG2J(a : CJ.G2J, b : CJ.G2J) : Bool {
    eqFp2(a.x, b.x) and eqFp2(a.y, b.y) and eqFp2(a.z, b.z)
  };
  func decodeG1Hex(hex : Text) : C.G1 {
    switch (Dec.decodeG1(bytesOf(hex))) {
      case (#ok(p)) p;
      case (#err(e)) Runtime.trap("decodeG1: " # e);
    }
  };
  func decodeG2Hex(hex : Text) : C.G2 {
    switch (Dec2.decodeG2(bytesOf(hex))) {
      case (#ok(p)) p;
      case (#err(e)) Runtime.trap("decodeG2: " # e);
    }
  };
  func randScalar() : Nat {
    var v : Nat = 0;
    var i = 0;
    while (i < 8) { v := v * 0x100000000 + Nat64.toNat(rnd() & 0xFFFFFFFF); i += 1 };
    v % C.R
  };

  /// Differential test (G1): flat G1 vs CurveJac — add/dbl/mul EXACT Jacobian coordinates, edge scalars,
  /// toAffine, and subgroup verdict parity on generator multiples, the fixture proof's A point,
  /// and an ark-generated on-curve-but-OFF-subgroup point (must be false on BOTH sides).
  public func gate_g1_flat(proofHex : Text, offSubG1Hex : Text, iters : Nat) : async Gate {
    let z = cvArena();
    let proof = proofOf(proofHex);
    let offSub = decodeG1Hex(offSubG1Hex);
    var k = 0;
    while (k < iters) {
      let k1 = randScalar();
      let k2 = randScalar();
      let p1 = CJ.g1ToAffine(CJ.g1Mul(CJ.g1FromAffine(C.g1Gen), k1));
      let p2 = CJ.g1ToAffine(CJ.g1Mul(CJ.g1FromAffine(C.g1Gen), k2));
      CF.g1FromAffineInto(z, 0, p1, CV_S);
      CF.g1FromAffineInto(z, 36, p2, CV_S);
      let j1 = CJ.g1FromAffine(p1);
      let j2 = CJ.g1FromAffine(p2);
      CF.g1AddInto(z, 72, 0, 36, CV_S);
      if (not eqG1J(getG1J(z, 72), CJ.g1Add(j1, j2))) return gateFail("g1Add", k);
      CF.g1DblInto(z, 72, 0, CV_S);
      if (not eqG1J(getG1J(z, 72), CJ.g1Dbl(j1))) return gateFail("g1Dbl", k);
      // aliased in-place add/dbl
      CF.g1Copy(z, 72, 0);
      CF.g1AddInto(z, 72, 72, 36, CV_S);
      if (not eqG1J(getG1J(z, 72), CJ.g1Add(j1, j2))) return gateFail("g1Add-alias", k);
      // add degeneracies: P + P (branch to dbl), P + (−P)? via mul edges below; inf handling
      CF.g1AddInto(z, 72, 0, 0, CV_S);
      if (not eqG1J(getG1J(z, 72), CJ.g1Add(j1, j1))) return gateFail("g1Add-self", k);
      let e = randScalar();
      CF.g1MulInto(z, 72, 0, CF.scalarLimbs(e), CV_S);
      if (not eqG1J(getG1J(z, 72), CJ.g1Mul(j1, e))) return gateFail("g1Mul", k);
      k += 1;
    };
    // edge scalars on the generator (0,1,2,r−1,r,r+1) — exact Jacobian coords each
    let gj = CJ.g1FromAffine(C.g1Gen);
    CF.g1FromAffineInto(z, 0, C.g1Gen, CV_S);
    for (e in [0, 1, 2, C.R - 1, C.R, C.R + 1].vals()) {
      CF.g1MulInto(z, 72, 0, CF.scalarLimbs(e), CV_S);
      if (not eqG1J(getG1J(z, 72), CJ.g1Mul(gj, e))) return gateFail("g1Mul-edge", e % 7);
    };
    // toAffine parity (normal-form comparison against L2, which converts out of Montgomery)
    CF.g1MulInto(z, 72, 0, CF.scalarLimbs(12345), CV_S);
    switch (CJ.g1ToAffine(CJ.g1Mul(gj, 12345))) {
      case (#pt(exp)) {
        CF.g1ToAffineInto(z, 108, 120, 72, CV_S);
        if (FpM.montMul(FpFlat.toNat(z, 108), 1) != exp.x) return gateFail("g1ToAffine-x", 0);
        if (FpM.montMul(FpFlat.toNat(z, 120), 1) != exp.y) return gateFail("g1ToAffine-y", 0);
      };
      case (#inf) return gateFail("g1ToAffine-inf", 0);
    };
    // subgroup verdict parity: generator TRUE, proof A TRUE, off-subgroup FALSE (both sides)
    var idx = 0;
    for ((p, expect) in [(C.g1Gen, true), (proof.a, true), (proof.c, true), (offSub, false)].vals()) {
      let cj = CJ.g1IsInSubgroup(p);
      if (cj != expect) return gateFail("g1Subgroup-CJ-expect", idx);
      CF.g1FromAffineInto(z, 0, p, CV_S);
      if (CF.g1InSubgroup(z, 0, 72, CV_S) != cj) return gateFail("g1Subgroup-flat", idx);
      idx += 1;
    };
    { pass = true; checked = iters; detail = "CurveFlat G1 == CurveJac (+edges, subgroup, off-subgroup ctrl)" }
  };

  /// Differential test (G2): flat G2 vs CurveJac — same battery on the twist, incl. the fixture proof's B
  /// and an ark-generated off-subgroup G2 point.
  public func gate_g2_flat(proofHex : Text, offSubG2Hex : Text, iters : Nat) : async Gate {
    let z = cvArena();
    let proof = proofOf(proofHex);
    let offSub = decodeG2Hex(offSubG2Hex);
    let g2gen : C.G2 = switch (proof.b) { case (#pt(_)) proof.b; case (#inf) return gateFail("B-inf", 0) };
    var k = 0;
    while (k < iters) {
      let k1 = randScalar();
      let p1 = CJ.g2ToAffine(CJ.g2Mul(CJ.g2FromAffine(g2gen), k1));
      let p2 = CJ.g2ToAffine(CJ.g2Mul(CJ.g2FromAffine(g2gen), randScalar()));
      CF.g2FromAffineInto(z, 0, p1, CV_S);
      CF.g2FromAffineInto(z, 72, p2, CV_S);
      let j1 = CJ.g2FromAffine(p1);
      let j2 = CJ.g2FromAffine(p2);
      CF.g2AddInto(z, 144, 0, 72, CV_S);
      if (not eqG2J(getG2J(z, 144), CJ.g2Add(j1, j2))) return gateFail("g2Add", k);
      CF.g2DblInto(z, 144, 0, CV_S);
      if (not eqG2J(getG2J(z, 144), CJ.g2Dbl(j1))) return gateFail("g2Dbl", k);
      let e = randScalar();
      CF.g2MulInto(z, 144, 0, CF.scalarLimbs(e), CV_S);
      if (not eqG2J(getG2J(z, 144), CJ.g2Mul(j1, e))) return gateFail("g2Mul", k);
      k += 1;
    };
    // subgroup verdicts: fixture B TRUE, off-subgroup FALSE, both sides agree
    var idx = 0;
    for ((p, expect) in [(proof.b, true), (offSub, false)].vals()) {
      let cj = CJ.g2IsInSubgroup(p);
      if (cj != expect) return gateFail("g2Subgroup-CJ-expect", idx);
      CF.g2FromAffineInto(z, 0, p, CV_S);
      if (CF.g2InSubgroup(z, 0, 144, CV_S) != cj) return gateFail("g2Subgroup-flat", idx);
      idx += 1;
    };
    { pass = true; checked = iters; detail = "CurveFlat G2 == CurveJac (+subgroup, off-subgroup ctrl)" }
  };

  // ---- pairing / final-exp / full-verify gates ----

  /// Differential test (prepare): flat prepareG2 vs PP.prepareG2 — all 68 coefficients (3 Fp2 each) must be
  /// limb-identical on the fixture proof's B point.
  public func gate_prepare_flat(proofHex : Text) : async Gate {
    let proof = proofOf(proofHex);
    let q = switch (proof.b) { case (#pt(v)) v; case (#inf) return gateFail("B-inf", 0) };
    // arena: B affine mont @0(48), coeffs @48(4896), spare @4944(24) → scratch S=4980
    let s = 4980;
    let z = FpFlat.newBuf((s + PFlat.SCRATCH_LIMBS + 11) / 12 + 1);
    FpFlat.fromNat(q.x.c0, z, 4944);
    FpFlat.toMontInto(z, 0, z, 4944, z, 4956, z, s);
    FpFlat.fromNat(q.x.c1, z, 4944);
    FpFlat.toMontInto(z, 12, z, 4944, z, 4956, z, s);
    FpFlat.fromNat(q.y.c0, z, 4944);
    FpFlat.toMontInto(z, 24, z, 4944, z, 4956, z, s);
    FpFlat.fromNat(q.y.c1, z, 4944);
    FpFlat.toMontInto(z, 36, z, 4944, z, 4956, z, s);
    PFlat.prepareG2Into(z, 48, 0, s);
    let ref = PP.prepareG2(proof.b);
    if (ref.ellCoeffs.size() != PFlat.COEFF_COUNT) return gateFail("ref-count", 0);
    var k = 0;
    while (k < PFlat.COEFF_COUNT) {
      let o = 48 + 72 * k;
      let rc = ref.ellCoeffs[k];
      if (not eqFp2(getFp2(z, o), rc.c0)) return gateFail("prep-c0", k);
      if (not eqFp2(getFp2(z, o + 24), rc.c1)) return gateFail("prep-c1", k);
      if (not eqFp2(getFp2(z, o + 48), rc.c2)) return gateFail("prep-c2", k);
      k += 1;
    };
    { pass = true; checked = PFlat.COEFF_COUNT; detail = "PairingFlat prepareG2 == PP.prepareG2" }
  };

  /// Differential test: flat Frobenius(1,2), cyclotomicSquare, expByX, and the assembled final
  /// exponentiation vs PairingFinalExp, on the REAL raw multi-Miller output of the fixture
  /// proof AND a forged (A/C-swapped) variant.
  public func gate_finalexp_flat(proofHex : Text, inputsHex : Text) : async Gate {
    let v = requireVk();
    let proof = proofOf(proofHex);
    let vkx = CJ.vkX(v.gammaAbc, inputsOf(inputsHex));
    let bPrep = PP.prepareG2(proof.b);
    let s = 432; // arena: in@0(144), out@144(144), tmp@288(144)
    let z = FpFlat.newBuf((s + PFlat.SCRATCH_LIMBS + 11) / 12 + 1);
    var round = 0;
    while (round < 2) {
      let raw = if (round == 0) {
        GM.multiMillerRaw(v, proof.a, bPrep, proof.c, vkx)
      } else {
        GM.multiMillerRaw(v, proof.c, bPrep, proof.a, vkx) // forged: A/C swapped
      };
      putFp12(z, 0, raw);
      PFlat.loadFrobConstants(z, s);
      PFlat.fp12FrobeniusInto(z, 288, 0, 1, s);
      if (not eqFp12(getFp12(z, 288), PF.fp12Frobenius(raw, 1))) return gateFail("frob1", round);
      PFlat.fp12FrobeniusInto(z, 288, 0, 2, s);
      if (not eqFp12(getFp12(z, 288), PF.fp12Frobenius(raw, 2))) return gateFail("frob2", round);
      let easy = PF.easyPart(raw);
      putFp12(z, 144, easy);
      PFlat.cyclotomicSquareInto(z, 288, 144, s);
      if (not eqFp12(getFp12(z, 288), PF.cyclotomicSquare(easy))) return gateFail("cyclo", round);
      // in-place cyclo (the expByX usage shape)
      PFlat.cyclotomicSquareInto(z, 144, 144, s);
      if (not eqFp12(getFp12(z, 144), PF.cyclotomicSquare(easy))) return gateFail("cyclo-alias", round);
      putFp12(z, 144, easy);
      PFlat.expByXInto(z, 288, 144, s);
      if (not eqFp12(getFp12(z, 288), PF.expByX(easy))) return gateFail("expByX", round);
      PFlat.finalExponentiateInto(z, 144, 0, s);
      if (not eqFp12(getFp12(z, 144), PF.finalExponentiate(raw))) return gateFail("finalexp", round);
      round += 1;
    };
    { pass = true; checked = 2; detail = "PairingFlat finalexp chain == PairingFinalExp (valid + forged)" }
  };

  /// Differential test (full verify): flat verify vs the verbatim reference assembly — verdicts must be
  /// IDENTICAL (both #ok or both the same #err code). One vector class per call.
  public func gate_verify_flat(proofHex : Text, inputsHex : Text) : async Gate {
    let v = requireVk();
    let proof = proofOf(proofHex);
    let inputs = inputsOf(inputsHex);
    let flat = GM.verify(v, proof.a, proof.b, proof.c, inputs);
    let ref = GM.verifyReference(v, proof.a, proof.b, proof.c, inputs);
    let cached = GM.verifyWithFlat(v, requireFlat(), proof.a, proof.b, proof.c, inputs);
    let same = switch (flat, ref, cached) {
      case (#ok, #ok, #ok) true;
      case (#err(x), #err(y), #err(w)) x == y and y == w;
      case (_, _, _) false;
    };
    let text = switch (flat) { case (#ok) "ok"; case (#err(e)) e };
    let refText = switch (ref) { case (#ok) "ok"; case (#err(e)) e };
    {
      pass = same;
      checked = 1;
      detail = "flat=" # text # " ref=" # refText;
    }
  };

  /// Full flat verify perf/alloc through the REAL wire path (same call the ledger makes).
  public func probe_flat_full_verify(proofHex : Text, inputsHex : Text, iters : Nat) : async Probe {
    let v = requireVk();
    run(iters, func() { sink += GW.verifyPrepared(v, proofHex, inputsHex).size() })
  };

  /// Stage-by-stage allocation decomposition of the FLAT verify (mirrors the engine's arena
  /// layout) — so every remaining megabyte in the new path is accounted for, not guessed at.
  public func probe_flat_stages(proofHex : Text, inputsHex : Text) : async [(Text, Probe)] {
    let v = requireVk();
    let proof = proofOf(proofHex);
    let inputs = inputsOf(inputsHex);
    let out = List.empty<(Text, Probe)>();
    let s = 20232;
    let a0 = Prim.rts_total_allocation();
    let c0 = Prim.performanceCounter(0);
    let z = VarArray.repeat<Nat32>(0, 23328);
    List.add(out, ("arena-alloc", { alloc = Prim.rts_total_allocation() - a0 : Nat; instructions = Prim.performanceCounter(0) - c0; iters = 1 }));
    let stage = func(name : Text, f : () -> ()) {
      let x0 = Prim.rts_total_allocation();
      let i0 = Prim.performanceCounter(0);
      f();
      List.add(out, (name, { alloc = Prim.rts_total_allocation() - x0 : Nat; instructions = Prim.performanceCounter(0) - i0; iters = 1 }));
    };
    stage("A+C-subgroup-flat", func() {
      CF.g1FromAffineInto(z, 576, proof.a, s);
      sink += if (CF.g1InSubgroup(z, 576, 0, s)) 1 else 0;
      CF.g1FromAffineInto(z, 576, proof.c, s);
      sink += if (CF.g1InSubgroup(z, 576, 0, s)) 1 else 0;
    });
    stage("B-subgroup-flat", func() {
      CF.g2FromAffineInto(z, 240, proof.b, s);
      sink += if (CF.g2InSubgroup(z, 240, 36, s)) 1 else 0;
    });
    stage("vkx-msm-flat", func() {
      CF.g1FromAffineInto(z, 156, v.gammaAbc[0], s);
      var i = 0;
      while (i < inputs.size()) {
        CF.g1FromAffineInto(z, 612, v.gammaAbc[i + 1], s);
        CF.g1MulInto(z, 612, 612, CF.scalarLimbs(inputs[i] % C.R), s);
        CF.g1AddInto(z, 156, 156, 612, s);
        i += 1;
      };
    });
    stage("load-vk-preps", func() {
      for (base in [5544, 10440, 15336].vals()) {
        let prep = if (base == 5544) v.betaPrep else if (base == 10440) v.gammaPrep else v.deltaPrep;
        var k = 0;
        for (coeff in prep.ellCoeffs.vals()) {
          let o = base + 72 * k;
          FpFlat.fromNat(coeff.c0.c0, z, o);
          FpFlat.fromNat(coeff.c0.c1, z, o + 12);
          FpFlat.fromNat(coeff.c1.c0, z, o + 24);
          FpFlat.fromNat(coeff.c1.c1, z, o + 36);
          FpFlat.fromNat(coeff.c2.c0, z, o + 48);
          FpFlat.fromNat(coeff.c2.c1, z, o + 60);
          k += 1;
        };
      };
    });
    stage("prepare-B-flat", func() {
      switch (proof.b) {
        case (#inf) {};
        case (#pt(q)) {
          FpFlat.fromNat(q.x.c0, z, 612);
          FpFlat.toMontInto(z, 240, z, 612, z, 624, z, s);
          FpFlat.fromNat(q.x.c1, z, 612);
          FpFlat.toMontInto(z, 252, z, 612, z, 624, z, s);
          FpFlat.fromNat(q.y.c0, z, 612);
          FpFlat.toMontInto(z, 264, z, 612, z, 624, z, s);
          FpFlat.fromNat(q.y.c1, z, 612);
          FpFlat.toMontInto(z, 276, z, 612, z, 624, z, s);
          PFlat.prepareG2Into(z, 648, 240, s);
        };
      };
    });
    stage("pair-G1-loads", func() {
      switch (proof.a) { case (#pt(p)) {
        FpFlat.fromNat(p.x, z, 612); FpFlat.toMontInto(z, 108, z, 612, z, 624, z, s);
        FpFlat.fromNat(p.y, z, 612); FpFlat.toMontInto(z, 120, z, 612, z, 624, z, s);
      }; case (#inf) {} };
      switch (proof.c) { case (#pt(p)) {
        FpFlat.fromNat(p.x, z, 612); FpFlat.toMontInto(z, 132, z, 612, z, 624, z, s);
        FpFlat.fromNat(p.y, z, 612); FpFlat.toMontInto(z, 144, z, 612, z, 624, z, s);
        FpFlat.negInto(z, 144, z, 144);
      }; case (#inf) {} };
      if (not CF.g1IsInf(z, 156)) {
        CF.g1ToAffineInto(z, 192, 204, 156, s);
        FpFlat.negInto(z, 204, z, 204);
      };
      switch (v.alphaNeg) { case (#pt(p)) {
        FpFlat.fromNat(p.x, z, 612); FpFlat.toMontInto(z, 216, z, 612, z, 624, z, s);
        FpFlat.fromNat(p.y, z, 612); FpFlat.toMontInto(z, 228, z, 612, z, 624, z, s);
      }; case (#inf) {} };
    });
    stage("miller-flat", func() {
      PFlat.multiMillerInto(z, 288, [true, true, true, true], [108, 192, 132, 216], [120, 204, 144, 228], [z, z, z, z], [648, 10440, 15336, 5544], s);
    });
    stage("finalexp-flat", func() {
      PFlat.finalExponentiateInto(z, 432, 288, s);
      sink += if (TF.fp12IsOneMont(z, 432)) 1 else 0;
    });
    List.toArray(out)
  };

  /// Flat G1 subgroup-check perf ([r]P, the validate workhorse) — must be ~0 bytes/op.
  public func probe_flat_g1_subgroup(iters : Nat) : async Probe {
    let z = cvArena();
    CF.g1FromAffineInto(z, 0, C.g1Gen, CV_S);
    let a0 = Prim.rts_total_allocation();
    let c0 = Prim.performanceCounter(0);
    var i = 0;
    var all = true;
    while (i < iters) {
      all := all and CF.g1InSubgroup(z, 0, 72, CV_S);
      i += 1;
    };
    let c1 = Prim.performanceCounter(0);
    let a1 = Prim.rts_total_allocation();
    sink += if (all) 1 else 0;
    { alloc = a1 - a0 : Nat; instructions = c1 - c0; iters }
  };

  /// Flat fp12SqrFast perf/alloc (the Miller loop workhorse — must be ~0 bytes/op).
  public func probe_flat_fp12_sqr(iters : Nat) : async Probe {
    let z = twArena();
    putFp12(z, 0, randFp12(2));
    let a0 = Prim.rts_total_allocation();
    let c0 = Prim.performanceCounter(0);
    var i = 0;
    while (i < iters) {
      TF.fp12SqrFastInto(z, 0, 0, TW_S);
      i += 1;
    };
    let c1 = Prim.performanceCounter(0);
    let a1 = Prim.rts_total_allocation();
    sink += Nat32.toNat(z[0]) % 1024;
    { alloc = a1 - a0 : Nat; instructions = c1 - c0; iters }
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
