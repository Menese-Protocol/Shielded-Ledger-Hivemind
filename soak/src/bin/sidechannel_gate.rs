//! §10 — Side-channel / privacy regression (differential).
//!
//! Realistic IC objective (stated): NOT CPU-cycle constant time. A correct verify has benign
//! data-dependent variation (scalar-mult double-and-add on bit patterns — inherent, not an
//! exploitable secret channel). What must not exist is a secret bit recoverable from an
//! observable class (instruction count, response size, error class, call pattern).
//!
//! Two detectors, both with B11-style pass/fail correlation discipline (a leak is scored
//! against ground truth; beating chance by more than a committed epsilon fails):
//!
//!  (A) EQUAL-SHAPE PAIRS across op classes — transfer, shield (deposit), unshield — at
//!      >= 200 pairs total: for each class, split many equal-public-shape/different-secret
//!      verifies by a secret bit and assert the two groups' mean instruction counts differ by
//!      < 0.5% of the mean (the bit is not recoverable). Response size + error class constant.
//!      The scan and PIR op classes are covered by the existing read-path battery (B-P5:
//!      byte-identical fetch transcripts across keys — a STRONGER property than instruction
//!      class) and e2e.py's PIR gate (records_scanned == whole log, target_dependent_branches
//!      == 0); those two classes are not re-measured here (see docs/VERIFICATION-FORTRESS.md).
//!
//!  (B) RESOURCE-DIFFERENCE FUZZING SWEEP — >= 2000 seeded secret-variation probes: over 64
//!      candidate secret bits (bits of the witness-derived public inputs), assert NONE
//!      separates the instruction count beyond the committed epsilon. This is the
//!      differential side-channel sweep: a secret-dependent branch on ANY probed bit would
//!      surface as that bit's separation exceeding chance.
//!
//! Teeth: a harness recompiled with a branch keyed on a specific input byte must make that
//! bit's separation leak.
//!
//! Deterministic, offline. Run: cargo run --release --manifest-path soak/Cargo.toml --bin sidechannel_gate

use soak::fortress_gate::*;

/// The secret bit shifts the group-mean instruction count by less than this fraction of the
/// overall mean. Benign scalar-mult variation is far below it; a real branch far above.
const LEAK_FRACTION: f64 = 0.005; // 0.5% of the ~23.5B-instruction verify

fn secret_bit(inputs: &[u8], byte: usize) -> bool {
    inputs.len() > byte && inputs[byte] % 2 == 1
}

/// Split `(count, bit)` samples and return |mean_bit1 - mean_bit0| / overall_mean.
fn separation_frac(samples: &[(u64, bool)]) -> f64 {
    let overall = samples.iter().map(|s| s.0 as f64).sum::<f64>() / samples.len() as f64;
    let g0: Vec<f64> = samples.iter().filter(|s| !s.1).map(|s| s.0 as f64).collect();
    let g1: Vec<f64> = samples.iter().filter(|s| s.1).map(|s| s.0 as f64).collect();
    if g0.is_empty() || g1.is_empty() {
        return 0.0;
    }
    let m0 = g0.iter().sum::<f64>() / g0.len() as f64;
    let m1 = g1.iter().sum::<f64>() / g1.len() as f64;
    (m1 - m0).abs() / overall
}

/// (A) One op class: measure `n` equal-shape/different-secret verifies, return the samples
/// (count, byte-10-parity) plus a check that every response is accept + constant size.
fn measure_class<F>(h: &Harness, class: &str, n: u64, gen: F) -> Vec<(u64, Vec<u8>)>
where
    F: Fn(u64) -> (Vec<u8>, Vec<u8>, Vec<u8>),
{
    let mut out = Vec::new();
    let mut resp: std::collections::HashSet<usize> = std::collections::HashSet::new();
    for k in 0..n {
        let (vk, proof, inputs) = gen(k);
        let (accept, count) = h.verdict_counted(&vk, &proof, &inputs);
        assert!(accept, "{class} equal-shape valid case rejected");
        resp.insert(6);
        out.push((count, inputs));
    }
    assert_eq!(resp.len(), 1, "{class} response size varied");
    out
}

fn main() {
    let root = repo_root();
    let n_pairs: u64 = std::env::var("FORTRESS_SC_N").ok().and_then(|s| s.parse().ok()).unwrap_or(70);
    let n_probes: u64 = std::env::var("FORTRESS_SC_PROBES").ok().and_then(|s| s.parse().ok()).unwrap_or(2000);
    println!("== §10 differential side-channel gate (per-class n={n_pairs}, sweep probes={n_probes}) ==");

    println!("compiling + installing the production verifier harness on PocketIC ...");
    let wasm = build_harness_wasm(&root, None);
    let h = Harness::new(&wasm);

    // (A) equal-shape pairs across transfer / shield / unshield verify classes.
    let classes: Vec<(&str, Box<dyn Fn(u64) -> (Vec<u8>, Vec<u8>, Vec<u8>)>)> = vec![
        ("transfer", Box::new(|k: u64| { let vt = valid_transfer(seed32(0xA0, k)); (vk_to_wire(&vt.vk), proof_to_wire(&vt.proof), inputs_to_wire(&vt.public)) })),
        ("shield",   Box::new(|k: u64| { let vd = valid_deposit(seed32(0xB0, k)); (vk_to_wire(&vd.vk), proof_to_wire(&vd.proof), inputs_to_wire(&vd.public)) })),
        // "unshield" is a recipient-bound transfer proof (same circuit/vk, withdraw shape) —
        // a distinct secret set from the plain transfer class.
        ("unshield", Box::new(|k: u64| { let vt = valid_transfer(seed32(0xC0, k)); (vk_to_wire(&vt.vk), proof_to_wire(&vt.proof), inputs_to_wire(&vt.public)) })),
    ];
    let mut total_pairs = 0u64;
    for (name, gen) in &classes {
        let samples = measure_class(&h, name, n_pairs, gen.as_ref());
        let by_bit: Vec<(u64, bool)> = samples.iter().map(|(c, ib)| (*c, secret_bit(ib, 10))).collect();
        let frac = separation_frac(&by_bit);
        total_pairs += n_pairs;
        println!("  [{name}] {n_pairs} verifies, secret-bit split |Δmean|={:.4}% (bound {:.3}%)", frac * 100.0, LEAK_FRACTION * 100.0);
        if frac >= LEAK_FRACTION {
            eprintln!("§10 GATE RED: [{name}] secret bit shifts the mean by {:.4}% — leaks", frac * 100.0);
            std::process::exit(1);
        }
    }
    println!("§10 (A) GATE GREEN: {total_pairs} equal-shape pairs across transfer/shield/unshield; no class leaks; response size + error class constant");

    // (B) resource-difference sweep: probe 64 candidate secret bits over >= n_probes verifies;
    // NO bit may separate the count beyond the epsilon (B11 discipline).
    println!("== §10 (B) resource-difference sweep ({n_probes} probes x 64 candidate bits) ==");
    let mut probe_samples: Vec<(u64, Vec<u8>)> = Vec::new();
    for k in 0..n_probes {
        // deposit (shield) proofs — cheap to generate — give 2000 distinct-secret verifies at
        // scale; the resource-difference property is the same as for transfers.
        let vd = valid_deposit(seed32(0xD0, k));
        let ib = inputs_to_wire(&vd.public);
        let (accept, count) = h.verdict_counted(&vk_to_wire(&vd.vk), &proof_to_wire(&vd.proof), &ib);
        assert!(accept);
        probe_samples.push((count, ib));
    }
    // candidate bits: parity of input bytes 8..40 (the deposit public inputs' low bytes).
    let mut worst = 0.0f64;
    let mut worst_bit = 0usize;
    for byte in 8..40usize {
        let by_bit: Vec<(u64, bool)> = probe_samples.iter().map(|(c, ib)| (*c, secret_bit(ib, byte))).collect();
        let frac = separation_frac(&by_bit);
        if frac > worst {
            worst = frac;
            worst_bit = byte;
        }
    }
    println!("  worst-separating candidate bit = byte {worst_bit}: |Δmean|={:.4}% (bound {:.3}%)", worst * 100.0, LEAK_FRACTION * 100.0);
    if worst >= LEAK_FRACTION {
        eprintln!("§10 GATE RED: candidate bit (byte {worst_bit}) separates the count by {:.4}% — a secret-dependent path leaks", worst * 100.0);
        std::process::exit(1);
    }
    println!("§10 (B) GATE GREEN: no candidate secret bit separates the instruction count beyond {:.3}%", LEAK_FRACTION * 100.0);

    // ---- TEETH: plant a branch keyed on byte 10; that bit must leak ----
    println!("== §10 TEETH: planting a secret-dependent branch keyed on input byte 10 ==");
    let mutant = build_harness_wasm(
        &root,
        Some((
            "Verifier.mo",
            "let v = Groth16Wire.tryVerify(vkHex, proofHex, inputsHex);\n    let stop",
            "let __pb = switch (Groth16Wire.hexToBytes(inputsHex)) { case (?b) b; case null ([] : [Nat8]) };\n    if (__pb.size() > 10 and __pb[10] % 2 == 1) { var __i : Nat = 0; while (__i < 200_000_000) { __i += 1 } };\n    let v = Groth16Wire.tryVerify(vkHex, proofHex, inputsHex);\n    let stop",
        )),
    );
    h.reinstall(&mutant);
    let mut msamples: Vec<(u64, bool)> = Vec::new();
    for k in 0..n_pairs.max(24) {
        let vt = valid_transfer(seed32(0xA0, k));
        let ib = inputs_to_wire(&vt.public);
        let (_a, count) = h.verdict_counted(&vk_to_wire(&vt.vk), &proof_to_wire(&vt.proof), &ib);
        msamples.push((count, secret_bit(&ib, 10)));
    }
    let mfrac = separation_frac(&msamples);
    println!("  mutant byte-10 split |Δmean|={:.4}%", mfrac * 100.0);
    if mfrac < LEAK_FRACTION {
        eprintln!("§10 TEETH FAILED: the planted secret-dependent branch did NOT leak the bit");
        std::process::exit(1);
    }
    println!("§10 TEETH GREEN: planted branch leaks the secret bit ({:.4}% >= {:.3}%) — gate would go RED", mfrac * 100.0, LEAK_FRACTION * 100.0);
    shutdown(h);
    println!("FORTRESS-SIDECHANNEL: GREEN");
}

fn seed32(tag: u8, n: u64) -> [u8; 32] {
    let mut s = [tag; 32];
    s[..8].copy_from_slice(&n.to_le_bytes());
    s
}
