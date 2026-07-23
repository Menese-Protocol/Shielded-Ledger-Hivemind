//! §6 — Metamorphic testing.
//!
//! Validity-PRESERVING transforms of a valid proof must stay accepted by all three
//! verifiers; validity-DESTROYING transforms must be rejected by all three. The load-bearing
//! metamorphic invariant is that a Groth16 proof is NOT uniquely bound: any fresh proof of
//! the SAME statement (re-randomized prover randomness) verifies — while any change to the
//! statement's public inputs or verifying key is rejected.
//!
//! Reuses the production-verifier PocketIC harness in `soak::fortress_gate`.
//! Teeth: a destroying transform deliberately MISLABELED preserving must turn the suite RED
//! (its expected-accept is contradicted by the actual reject).
//!
//! Deterministic, offline. Run: cargo run --release --manifest-path soak/Cargo.toml --bin metamorphic_gate
//! Tiers: FORTRESS_META_N base transfers (default 40; committed full tier 200).

use ark_bls12_381::Bls12_381;
use ark_groth16::Groth16;
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use soak::fortress_gate::*;

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Preserve, // must stay ACCEPT
    Destroy,  // must be REJECT
}

struct Transform {
    label: &'static str,
    kind: Kind,
    vk: Vec<u8>,
    proof: Vec<u8>,
    inputs: Vec<u8>,
}

/// Build the transform set for one base valid transfer. `mislabel` (teeth) tags one
/// destroying transform as Preserve to prove the suite catches the contradiction.
fn transforms(
    vt: &ValidTransfer,
    base_seed: u64,
    wrong: &[u8],
    mislabel: bool,
) -> Vec<Transform> {
    let vkb = vk_to_wire(&vt.vk);
    let pb = proof_to_wire(&vt.proof);
    let ib = inputs_to_wire(&vt.public);
    let count = u64_le(&ib, 0) as usize;
    let mut out = Vec::new();

    // ---- PRESERVING: re-randomized proofs of the SAME statement ----
    for r in 0..2u64 {
        // fresh prover randomness => different proof bytes, identical public inputs.
        let mut rng = StdRng::seed_from_u64(base_seed.wrapping_mul(7).wrapping_add(r + 1));
        let proof = Groth16::<Bls12_381>::prove(&vt.pk, vt.circuit.clone(), &mut rng).unwrap();
        // sanity: it really is a different proof but a valid one.
        assert!(Groth16::<Bls12_381>::verify(&vt.vk, &vt.public, &proof).unwrap());
        let rp = proof_to_wire(&proof);
        assert_ne!(rp, pb, "re-proof produced identical bytes (randomness not exercised)");
        out.push(Transform { label: "reproof-rerandomized", kind: Kind::Preserve, vk: vkb.clone(), proof: rp, inputs: ib.clone() });
    }

    // ---- DESTROYING: statement / key mutations ----
    // change one output value (cm_out_1 is public input index 3).
    {
        let mut i = ib.clone();
        i[8 + 32 * 3] ^= 0x01;
        out.push(Transform { label: "change-output-commitment", kind: Kind::Destroy, vk: vkb.clone(), proof: pb.clone(), inputs: i });
    }
    // change transparent withdrawal destination (recipient_binding = index 7).
    {
        let mut i = ib.clone();
        i[8 + 32 * 7] ^= 0x01;
        out.push(Transform { label: "change-withdraw-recipient", kind: Kind::Destroy, vk: vkb.clone(), proof: pb.clone(), inputs: i });
    }
    // replace the root (anchor = index 0) with a different value.
    {
        let mut i = ib.clone();
        i[8] ^= 0x01;
        // the teeth: MISLABEL this destroying transform as preserving.
        let kind = if mislabel { Kind::Preserve } else { Kind::Destroy };
        out.push(Transform { label: "replace-root", kind, vk: vkb.clone(), proof: pb.clone(), inputs: i });
    }
    // replay a different nullifier (nf_1 = index 1).
    {
        let mut i = ib.clone();
        i[8 + 32] ^= 0x01;
        out.push(Transform { label: "swap-nullifier", kind: Kind::Destroy, vk: vkb.clone(), proof: pb.clone(), inputs: i });
    }
    // swap the two output commitments (indices 3 and 4) without a matching proof.
    if count >= 5 {
        let mut i = ib.clone();
        let (a, b) = (8 + 32 * 3, 8 + 32 * 4);
        for k in 0..32 {
            i.swap(a + k, b + k);
        }
        out.push(Transform { label: "swap-output-commitments", kind: Kind::Destroy, vk: vkb.clone(), proof: pb.clone(), inputs: i });
    }
    // verify against another circuit's key.
    out.push(Transform { label: "cross-circuit-vk", kind: Kind::Destroy, vk: wrong.to_vec(), proof: pb.clone(), inputs: ib.clone() });

    out
}

fn check(h: &Harness, t: &Transform) -> Result<(), String> {
    let a = ark_verdict(&t.vk, &t.proof, &t.inputs);
    let b = blst_verdict(&t.vk, &t.proof, &t.inputs);
    let m = h.verdict(&t.vk, &t.proof, &t.inputs);
    if !(a == b && b == m) {
        return Err(format!("3-way DISAGREE on {}: ark={a} blst={b} motoko={m}", t.label));
    }
    let expect_accept = t.kind == Kind::Preserve;
    if a != expect_accept {
        return Err(format!(
            "{} expected {} but all three {}",
            t.label,
            if expect_accept { "ACCEPT" } else { "REJECT" },
            if a { "ACCEPTED" } else { "REJECTED" }
        ));
    }
    Ok(())
}

fn main() {
    let root = repo_root();
    let n: u64 = std::env::var("FORTRESS_META_N").ok().and_then(|s| s.parse().ok()).unwrap_or(40);
    println!("== §6 metamorphic gate (base transfers = {n}) ==");

    let wrong = vk_to_wire(&wrong_vk());
    println!("compiling + installing the production verifier harness on PocketIC ...");
    let wasm = build_harness_wasm(&root, None);
    let h = Harness::new(&wasm);

    let mut preserve = 0u32;
    let mut destroy = 0u32;
    let mut failures = Vec::new();
    for base in 0..n {
        let vt = valid_transfer(seed32(0x60, base));
        for t in transforms(&vt, base, &wrong, false) {
            match t.kind {
                Kind::Preserve => preserve += 1,
                Kind::Destroy => destroy += 1,
            }
            if let Err(e) = check(&h, &t) {
                failures.push(format!("  base {base}: {e}"));
            }
        }
        if base % 10 == 0 {
            println!("  .. base {base}/{n}");
        }
    }
    if !failures.is_empty() {
        eprintln!("§6 GATE RED — {} failure(s):", failures.len());
        for f in failures.iter().take(20) {
            eprintln!("{f}");
        }
        std::process::exit(1);
    }
    println!("§6 GATE GREEN: {preserve} preserving transforms accepted, {destroy} destroying transforms rejected — all 3-way consistent");

    // ---- TEETH: mislabel a destroying transform as preserving; the suite must flag it ----
    println!("== §6 TEETH: mislabeling 'replace-root' (destroying) as preserving ==");
    let vt = valid_transfer(seed32(0x60, 0));
    let mislabeled = transforms(&vt, 0, &wrong, true);
    let mut caught = false;
    for t in &mislabeled {
        if t.label == "replace-root" {
            match check(&h, t) {
                Err(_) => caught = true, // the expected-accept contradicts the actual reject
                Ok(()) => {}
            }
        }
    }
    if !caught {
        eprintln!("§6 TEETH FAILED: a mislabeled destroying transform did NOT trip the suite");
        std::process::exit(1);
    }
    println!("§6 TEETH GREEN: mislabeled destroying transform tripped the suite (would go RED)");
    shutdown(h);
    println!("FORTRESS-METAMORPHIC: GREEN");
}

fn seed32(tag: u8, n: u64) -> [u8; 32] {
    let mut s = [tag; 32];
    s[..8].copy_from_slice(&n.to_le_bytes());
    s
}
