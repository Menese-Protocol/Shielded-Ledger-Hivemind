//! §1 — Three independent Groth16 verifiers, one gate.
//!
//! Every taxonomy case is checked by the PRODUCTION Motoko verifier (installed in PocketIC,
//! the exact shipped `Groth16Wire.tryVerify` -> L3 flat path), arkworks, AND blst. The gate
//! fails if any two disagree on accept/reject polarity on any case. The Motoko verdict runs
//! at wasm speed on PocketIC (the L3-flat path is interpreter-hostile — proven in Phase 0 —
//! so the interpreter is NOT used here). arkworks and blst run natively in this driver.
//!
//! Taxonomy (all on the shared ZCash wire encoding all three verifiers consume): the valid
//! base; every one of the 192 proof bytes mutated; every one of the 8 public inputs mutated;
//! truncation at each field boundary; oversize; point at infinity substituted at A/B/C and
//! each vk slot; off-curve and off-subgroup points; non-canonical coordinates (x >= p);
//! wrong (deposit) vk; wrong number of public inputs; each input set to r / r+1 / 2^256-1;
//! every vk byte mutated. Teeth: recompiling the harness with ONE wrong verifier limb turns
//! the 3-way gate RED on the valid base.
//!
//! Deterministic, offline. Run: cargo run --release --manifest-path soak/Cargo.toml --bin taxonomy_gate

use ark_bls12_381::{Bls12_381, Fq, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;
use pocket_ic::PocketIcBuilder;
use soak::pic_env;
use std::path::{Path, PathBuf};
use std::process::Command;

// ---------------- wire <-> ark ----------------

fn u64_le(bytes: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap())
}

/// Decode a compressed ZCash G1 (48 bytes) into an ark affine, subgroup-checked. None on any
/// format/canonical/subgroup failure (Validate::Yes is the deserialize_compressed default).
fn ark_g1(bytes: &[u8]) -> Option<G1Affine> {
    if bytes.len() != 48 {
        return None;
    }
    G1Affine::deserialize_compressed(bytes).ok()
}
fn ark_g2(bytes: &[u8]) -> Option<G2Affine> {
    if bytes.len() != 96 {
        return None;
    }
    G2Affine::deserialize_compressed(bytes).ok()
}

/// arkworks verdict on the wire triple: true = ACCEPT, false = REJECT (any decode/subgroup/
/// shape/pairing failure). Mirrors what blst and the Motoko verifier compute.
fn ark_verdict(vk_bytes: &[u8], proof_bytes: &[u8], input_bytes: &[u8]) -> bool {
    // vk
    if vk_bytes.len() < 344 {
        return false;
    }
    let alpha = match ark_g1(&vk_bytes[0..48]) {
        Some(p) => p,
        None => return false,
    };
    let beta = match ark_g2(&vk_bytes[48..144]) {
        Some(p) => p,
        None => return false,
    };
    let gamma = match ark_g2(&vk_bytes[144..240]) {
        Some(p) => p,
        None => return false,
    };
    let delta = match ark_g2(&vk_bytes[240..336]) {
        Some(p) => p,
        None => return false,
    };
    let len = u64_le(vk_bytes, 336) as usize;
    if len < 1 || len > 1024 || vk_bytes.len() != 344 + 48 * len {
        return false;
    }
    let mut ic = Vec::with_capacity(len);
    for i in 0..len {
        match ark_g1(&vk_bytes[344 + 48 * i..344 + 48 * (i + 1)]) {
            Some(p) => ic.push(p),
            None => return false,
        }
    }
    let vk = VerifyingKey::<Bls12_381> {
        alpha_g1: alpha,
        beta_g2: beta,
        gamma_g2: gamma,
        delta_g2: delta,
        gamma_abc_g1: ic,
    };
    // proof
    if proof_bytes.len() != 192 {
        return false;
    }
    let a = match ark_g1(&proof_bytes[0..48]) {
        Some(p) => p,
        None => return false,
    };
    let b = match ark_g2(&proof_bytes[48..144]) {
        Some(p) => p,
        None => return false,
    };
    let c = match ark_g1(&proof_bytes[144..192]) {
        Some(p) => p,
        None => return false,
    };
    let proof = Proof::<Bls12_381> { a, b, c };
    // inputs: u64-LE count, then count * 32-byte-LE canonical Fr
    if input_bytes.len() < 8 {
        return false;
    }
    let count = u64_le(input_bytes, 0) as usize;
    if input_bytes.len() != 8 + 32 * count {
        return false;
    }
    let mut inputs = Vec::with_capacity(count);
    for i in 0..count {
        let s = &input_bytes[8 + 32 * i..8 + 32 * (i + 1)];
        match Fr::deserialize_compressed(s) {
            Ok(f) => inputs.push(f),
            Err(_) => return false,
        }
    }
    // Groth16 verify (returns Err on shape mismatch count+1 != ic.len()).
    match Groth16::<Bls12_381>::verify(&vk, &inputs, &proof) {
        Ok(v) => v,
        Err(_) => false,
    }
}

/// blst verdict on the wire triple: true = ACCEPT.
fn blst_verdict(vk_bytes: &[u8], proof_bytes: &[u8], input_bytes: &[u8]) -> bool {
    let vk = match cross_oracle::parse_vk(vk_bytes) {
        Ok(v) => v,
        Err(_) => return false,
    };
    // split the input blob into 32-byte LE elements per the wire count.
    if input_bytes.len() < 8 {
        return false;
    }
    let count = u64_le(input_bytes, 0) as usize;
    if input_bytes.len() != 8 + 32 * count {
        return false;
    }
    let refs: Vec<&[u8]> = (0..count)
        .map(|i| &input_bytes[8 + 32 * i..8 + 32 * (i + 1)])
        .collect();
    cross_oracle::verify(&vk, proof_bytes, &refs) == cross_oracle::Verdict::Accept
}

// ---------------- ark -> wire serialization (for the base valid case) ----------------

fn compress_g1(p: &G1Affine) -> [u8; 48] {
    let mut out = [0u8; 48];
    if p.is_zero() {
        out[0] = 0xc0;
        return out;
    }
    let x: num_bigint::BigUint = p.x().unwrap().into_bigint().into();
    let xb = x.to_bytes_be();
    out[48 - xb.len()..].copy_from_slice(&xb);
    out[0] |= 0x80;
    let y: num_bigint::BigUint = p.y().unwrap().into_bigint().into();
    let pm: num_bigint::BigUint = Fq::MODULUS.into();
    if y > (&pm - 1u8) / 2u8 {
        out[0] |= 0x20;
    }
    out
}

fn compress_g2(p: &G2Affine) -> [u8; 96] {
    let mut out = [0u8; 96];
    if p.is_zero() {
        out[0] = 0xc0;
        return out;
    }
    let x = p.x().unwrap();
    let c1: num_bigint::BigUint = x.c1.into_bigint().into();
    let c0: num_bigint::BigUint = x.c0.into_bigint().into();
    let c1b = c1.to_bytes_be();
    let c0b = c0.to_bytes_be();
    out[48 - c1b.len()..48].copy_from_slice(&c1b);
    out[96 - c0b.len()..].copy_from_slice(&c0b);
    out[0] |= 0x80;
    // larger root: lexicographic (c1, then c0)
    let y = p.y().unwrap();
    let neg = -y;
    let larger = {
        let (a1, b1): (num_bigint::BigUint, num_bigint::BigUint) =
            (y.c1.into_bigint().into(), neg.c1.into_bigint().into());
        if a1 != b1 {
            a1 > b1
        } else {
            let (a0, b0): (num_bigint::BigUint, num_bigint::BigUint) =
                (y.c0.into_bigint().into(), neg.c0.into_bigint().into());
            a0 > b0
        }
    };
    if larger {
        out[0] |= 0x20;
    }
    out
}

fn fr_le(f: &Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    let b = f.into_bigint().to_bytes_le();
    out[..b.len().min(32)].copy_from_slice(&b[..b.len().min(32)]);
    out
}

/// Serialize an ark Vk/Proof/inputs to the ZCash wire triple.
fn to_wire(vk: &VerifyingKey<Bls12_381>, proof: &Proof<Bls12_381>, inputs: &[Fr]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut vkb = Vec::new();
    vkb.extend_from_slice(&compress_g1(&vk.alpha_g1));
    vkb.extend_from_slice(&compress_g2(&vk.beta_g2));
    vkb.extend_from_slice(&compress_g2(&vk.gamma_g2));
    vkb.extend_from_slice(&compress_g2(&vk.delta_g2));
    vkb.extend_from_slice(&(vk.gamma_abc_g1.len() as u64).to_le_bytes());
    for p in &vk.gamma_abc_g1 {
        vkb.extend_from_slice(&compress_g1(p));
    }
    let mut pb = Vec::new();
    pb.extend_from_slice(&compress_g1(&proof.a));
    pb.extend_from_slice(&compress_g2(&proof.b));
    pb.extend_from_slice(&compress_g1(&proof.c));
    let mut ib = Vec::new();
    ib.extend_from_slice(&(inputs.len() as u64).to_le_bytes());
    for f in inputs {
        ib.extend_from_slice(&fr_le(f));
    }
    (vkb, pb, ib)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

include!("taxonomy_gate_body.rs");
