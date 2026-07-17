//! One apply-and-destroy Phase-2 contribution (Bowe-Gabizon-Miers 2017 / sequential MMORPG).
//!
//! The secret delta increment `d` is sampled, USED to re-randomize the delta-dependent parameters,
//! and then dropped when this function returns. Nothing here is stored beyond the returned public
//! parameters and the public proof of knowledge. In the browser client this same code runs in the
//! wasm sandbox and the secret never crosses the wasm boundary, let alone a network call.

use crate::transcript::{pok_challenge, DeltaParams, Pok};
use ark_bls12_381::{Fr, G1Projective, G2Projective};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{Field, UniformRand, Zero};
use rand::RngCore;

/// Apply a fresh secret `d` to the current delta params and produce the PoK tying the new delta to
/// the old one. `d` MUST be a uniformly random nonzero scalar sampled from strong entropy; it is
/// consumed here. `rng` supplies the independent PoK nonce `s`.
///
/// `prev_challenge` is the running transcript challenge before this contribution (binds ordering).
pub fn contribute<R: RngCore>(
    prev_challenge: &[u8; 32],
    current: &DeltaParams,
    d: Fr,
    rng: &mut R,
) -> Result<(DeltaParams, Pok), String> {
    if d.is_zero() {
        return Err("delta increment must be nonzero".into());
    }
    let d_inv = d.inverse().ok_or("delta not invertible")?;

    // Re-randomize: delta scales by d, the queries divide by d.
    let new_delta_g1 = (G1Projective::from(current.delta_g1) * d).into_affine();
    let new_delta_g2 = (G2Projective::from(current.delta_g2) * d).into_affine();
    let new_h: Vec<_> = current
        .h_query
        .iter()
        .map(|p| (G1Projective::from(*p) * d_inv).into_affine())
        .collect();
    let new_l: Vec<_> = current
        .l_query
        .iter()
        .map(|p| (G1Projective::from(*p) * d_inv).into_affine())
        .collect();
    let new_delta = DeltaParams {
        delta_g1: new_delta_g1,
        delta_g2: new_delta_g2,
        h_query: new_h,
        l_query: new_l,
    };

    // Proof of knowledge of d. Independent nonce s; the challenge point r_g2 = c*G2 is derived by
    // Fiat-Shamir from the running challenge and the committed s-pair and new delta, so both the
    // canister and the standalone verifier recompute it with SHA-256 alone.
    let mut s;
    loop {
        s = Fr::rand(rng);
        if !s.is_zero() {
            break;
        }
    }
    let g1 = G1Projective::generator();
    let g2 = G2Projective::generator();
    let s_g1 = (g1 * s).into_affine();
    let s_delta_g1 = (g1 * (s * d)).into_affine();
    let c = pok_challenge(prev_challenge, &s_g1, &s_delta_g1, &new_delta_g1);
    let r_delta_g2 = (g2 * (c * d)).into_affine(); // = d * r_g2, r_g2 = c*G2

    Ok((new_delta, Pok { s_g1, s_delta_g1, r_delta_g2 }))
}

/// Sample a uniformly random nonzero delta increment from the given entropy source. Kept separate
/// so the caller decides the entropy: the browser client feeds WebCrypto bytes.
pub fn sample_secret<R: RngCore>(rng: &mut R) -> Fr {
    loop {
        let d = Fr::rand(rng);
        if !d.is_zero() {
            return d;
        }
    }
}
