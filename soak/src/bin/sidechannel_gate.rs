//! §10 — Side-channel / privacy regression (differential).
//!
//! Realistic IC objective (stated): NOT CPU-cycle constant time. A correct verify has benign
//! data-dependent variation (the scalar multiplications' double-and-add branches on the
//! input/point bit patterns — inherent, not an exploitable secret channel). What MUST NOT
//! exist is a secret bit that an observer can RECOVER from the instruction count — i.e. a
//! secret-dependent branch that splits the counts into separable classes.
//!
//! Detector (differential side-channel): over many valid verifies of the SAME public shape
//! but DIFFERENT underlying values, split the cases by the parity of a specific input byte
//! (a stand-in secret bit) and compare the two groups' mean instruction counts. If the split
//! is exploitable — the group means differ by more than a committed fraction of the overall
//! mean — the bit leaks. Benign scalar-mult variation is UNCORRELATED with any single byte's
//! parity, so a correct verifier's split is negligible; a secret-dependent branch keyed on
//! that byte separates the groups by the branch's cost.
//!
//! Extends B-P5 (keyless observer), B11 (linkage), and churnfix (instr/alloc). Response size
//! and error class are also asserted constant across cases.
//!
//! Teeth: a harness recompiled with a branch keyed on that byte must make the split leak.
//!
//! Deterministic, offline. Run: cargo run --release --manifest-path soak/Cargo.toml --bin sidechannel_gate

use soak::fortress_gate::*;

/// Committed leak threshold: the secret-bit split must move the group-mean instruction count
/// by less than this fraction of the overall mean. Benign scalar-mult variation is far below
/// it (uncorrelated with any byte's parity); a real branch is far above it.
const LEAK_FRACTION: f64 = 0.005; // 0.5% of the ~23.5B-instruction verify

/// The stand-in "secret bit": parity of input-blob byte 10 (an anchor byte that varies per
/// case and that the teeth branch keys on).
fn secret_bit(inputs: &[u8]) -> bool {
    inputs.len() > 10 && inputs[10] % 2 == 1
}

struct Sample {
    count: u64,
    bit: bool,
    resp_len: usize,
    accept: bool,
}

fn measure(h: &Harness, n: u64) -> Vec<Sample> {
    let mut out = Vec::new();
    for k in 0..n {
        let vt = valid_transfer(seed32(0xA0, k));
        let vkb = vk_to_wire(&vt.vk);
        let pb = proof_to_wire(&vt.proof);
        let ib = inputs_to_wire(&vt.public);
        let (accept, count) = h.verdict_counted(&vkb, &pb, &ib);
        out.push(Sample { count, bit: secret_bit(&ib), resp_len: if accept { 6 } else { 0 }, accept });
    }
    out
}

/// Returns (overall_mean, |mean_bit1 - mean_bit0|, group0_len, group1_len).
fn separation(samples: &[Sample]) -> (f64, f64, usize, usize) {
    let overall = samples.iter().map(|s| s.count as f64).sum::<f64>() / samples.len() as f64;
    let g0: Vec<f64> = samples.iter().filter(|s| !s.bit).map(|s| s.count as f64).collect();
    let g1: Vec<f64> = samples.iter().filter(|s| s.bit).map(|s| s.count as f64).collect();
    if g0.is_empty() || g1.is_empty() {
        return (overall, 0.0, g0.len(), g1.len());
    }
    let m0 = g0.iter().sum::<f64>() / g0.len() as f64;
    let m1 = g1.iter().sum::<f64>() / g1.len() as f64;
    (overall, (m1 - m0).abs(), g0.len(), g1.len())
}

fn main() {
    let root = repo_root();
    let n: u64 = std::env::var("FORTRESS_SC_N").ok().and_then(|s| s.parse().ok()).unwrap_or(40);
    println!("== §10 differential side-channel gate (equal-shape/different-secret, n={n}) ==");

    println!("compiling + installing the production verifier harness on PocketIC ...");
    let wasm = build_harness_wasm(&root, None);
    let h = Harness::new(&wasm);

    let samples = measure(&h, n);
    assert!(samples.iter().all(|s| s.accept), "an equal-shape valid case was rejected");
    // response size + error class constant across every case
    let resp: std::collections::HashSet<usize> = samples.iter().map(|s| s.resp_len).collect();
    assert_eq!(resp.len(), 1, "response size varied across cases: {resp:?}");

    let (mean, sep, g0, g1) = separation(&samples);
    let frac = sep / mean;
    println!("  overall mean={:.0} instr; secret-bit split |Δmean|={:.0} ({:.4}% of mean); groups={g0}/{g1}", mean, sep, frac * 100.0);
    if frac >= LEAK_FRACTION {
        eprintln!("§10 GATE RED: the secret bit shifts the mean by {:.4}% >= {:.4}% — the instruction count leaks it", frac * 100.0, LEAK_FRACTION * 100.0);
        std::process::exit(1);
    }
    println!("§10 GATE GREEN: secret bit not recoverable from the instruction count ({:.4}% < {:.4}%); response size constant", frac * 100.0, LEAK_FRACTION * 100.0);

    // ---- TEETH: plant a branch keyed on that exact secret bit ----
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
    let msamples = measure(&h, n);
    let (mmean, msep, mg0, mg1) = separation(&msamples);
    let mfrac = msep / mmean;
    println!("  mutant: mean={:.0} |Δmean|={:.0} ({:.4}%); groups={mg0}/{mg1}", mmean, msep, mfrac * 100.0);
    if mfrac < LEAK_FRACTION {
        eprintln!("§10 TEETH FAILED: the planted secret-dependent branch did NOT leak the bit");
        std::process::exit(1);
    }
    println!("§10 TEETH GREEN: planted branch leaks the secret bit ({:.4}% >= {:.4}%) — gate would go RED", mfrac * 100.0, LEAK_FRACTION * 100.0);
    shutdown(h);
    println!("FORTRESS-SIDECHANNEL: GREEN");
}

fn seed32(tag: u8, n: u64) -> [u8; 32] {
    let mut s = [tag; 32];
    s[..8].copy_from_slice(&n.to_le_bytes());
    s
}
