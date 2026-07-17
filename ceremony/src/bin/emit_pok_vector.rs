//! Emit a cross-language test vector for the on-chain PoK verifier: a real Rust-produced Phase-2
//! contribution's delta points + proof of knowledge, so the Motoko `PokVerify.verifyPok` can be
//! checked to ACCEPT it (and reject a tampered copy). This is the oracle cross-check that the
//! canister's independent Motoko implementation agrees byte-for-byte with the Rust reference.
//!
//! Output: lines `name=hex` on stdout. Points are uncompressed big-endian (the ceremony wire form).

use ark_bls12_381::{Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ceremony::contribute::contribute;
use ceremony::transcript::{g1_be, g2_be, DeltaParams};
use rand::SeedableRng;

fn main() {
    let mut r = rand_chacha::ChaCha20Rng::seed_from_u64(0xC0FFEE);

    // A minimal delta-params object: delta at the generators, empty query vectors (verifyPok only
    // touches the delta and PoK points; the query vectors are the off-chain verifier's concern).
    let old = DeltaParams {
        delta_g1: G1Affine::generator(),
        delta_g2: G2Affine::generator(),
        h_query: vec![],
        l_query: vec![],
    };
    // An arbitrary but fixed prev-challenge.
    let prev: [u8; 32] = *b"phase2-pokvector-prev-challenge!";
    let d = Fr::from(0x9E3779B97F4A7C15u64); // a fixed nonzero secret for reproducibility
    let (new, pok) = contribute(&prev, &old, d, &mut r).unwrap();

    let hx = |b: &[u8]| b.iter().map(|c| format!("{c:02x}")).collect::<String>();
    println!("prev={}", hx(&prev));
    println!("old_delta_g1={}", hx(&g1_be(&old.delta_g1)));
    println!("new_delta_g1={}", hx(&g1_be(&new.delta_g1)));
    println!("new_delta_g2={}", hx(&g2_be(&new.delta_g2)));
    println!("s_g1={}", hx(&g1_be(&pok.s_g1)));
    println!("s_delta_g1={}", hx(&g1_be(&pok.s_delta_g1)));
    println!("r_delta_g2={}", hx(&g2_be(&pok.r_delta_g2)));
}
