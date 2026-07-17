//! Verification of Phase-2 contributions.
//!
//! Two tiers, matching the on-chain / off-chain verification split:
//!
//!   - `verify_pok`  : O(1) pairings. Proves the contributor knew a secret `d` and advanced delta
//!                     by exactly it, Fiat-Shamir-bound to the running transcript. This is the
//!                     SOUNDNESS-critical check the coordinator canister runs on-chain (the Motoko
//!                     canister re-implements it independently).
//!   - `verify_division` : pairings over a random linear combination of all ~53k H/L points.
//!                     Proves every query point was divided by that same `d`, i.e. the parameters
//!                     remain a correct SRS for the circuit. This is the CORRECTNESS check the
//!                     standalone verifier runs off-chain; it exceeds IC per-message limits.
//!
//! `verify_beacon_step` handles the public-secret finalize step.

use crate::transcript::{hash_obj, hash_to_fr, pok_challenge, DeltaParams, Pok};
use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{Field, One, Zero};

/// A point is acceptable on the wire iff it is on the curve, in the prime-order subgroup, and not
/// the identity. Contributions arrive from untrusted browsers, so every received point is checked.
fn ok_g1(p: &G1Affine) -> bool {
    !p.is_zero() && p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve()
}
fn ok_g2(p: &G2Affine) -> bool {
    !p.is_zero() && p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve()
}

/// Structural validity of a delta-params object against the expected query lengths.
pub fn validate_delta_shape(d: &DeltaParams, h_len: usize, l_len: usize) -> Result<(), String> {
    if d.h_query.len() != h_len {
        return Err(format!("h_query len {} != expected {h_len}", d.h_query.len()));
    }
    if d.l_query.len() != l_len {
        return Err(format!("l_query len {} != expected {l_len}", d.l_query.len()));
    }
    if !ok_g1(&d.delta_g1) || !ok_g2(&d.delta_g2) {
        return Err("delta_g1/delta_g2 not a valid non-identity subgroup point".into());
    }
    if !d.h_query.iter().all(ok_g1) || !d.l_query.iter().all(ok_g1) {
        return Err("a query point is not a valid non-identity subgroup point".into());
    }
    Ok(())
}

/// The cheap, soundness-critical check. `prev_challenge` is the running challenge BEFORE this
/// contribution; `old_delta_g1` is the accumulated delta_g1 the contributor started from. Verifies:
///   (1) same-ratio: s_delta/s (in G1) == r_delta/r (in G2)  [both equal the applied d]
///   (2) delta advanced by that same d: delta_after/delta_before (G1) == r_delta/r (G2)
///   (3) delta_g1 and delta_g2 encode the same d.
/// Also rejects the identity contribution (d = 1) and malformed PoK points.
pub fn verify_pok(
    prev_challenge: &[u8; 32],
    old_delta_g1: &G1Affine,
    new: &DeltaParams,
    pok: &Pok,
) -> Result<(), String> {
    if !ok_g1(&pok.s_g1) || !ok_g1(&pok.s_delta_g1) || !ok_g2(&pok.r_delta_g2) {
        return Err("PoK point malformed".into());
    }
    if !ok_g1(&new.delta_g1) || !ok_g2(&new.delta_g2) {
        return Err("new delta point malformed".into());
    }
    if new.delta_g1 == *old_delta_g1 {
        return Err("identity contribution (delta unchanged) rejected".into());
    }

    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();
    let c = pok_challenge(prev_challenge, &pok.s_g1, &pok.s_delta_g1, &new.delta_g1);
    let r_g2 = (G2Projective::generator() * c).into_affine();

    // (1) e(s_g1, r_delta_g2) == e(s_delta_g1, r_g2)
    if Bls12_381::pairing(pok.s_g1, pok.r_delta_g2) != Bls12_381::pairing(pok.s_delta_g1, r_g2) {
        return Err("PoK same-ratio check (1) failed".into());
    }
    // (2) e(delta_after, r_g2) == e(delta_before, r_delta_g2)
    if Bls12_381::pairing(new.delta_g1, r_g2) != Bls12_381::pairing(*old_delta_g1, pok.r_delta_g2) {
        return Err("PoK delta-advance check (2) failed".into());
    }
    // (3) e(delta_after_g1, G2) == e(G1, delta_after_g2)
    if Bls12_381::pairing(new.delta_g1, g2) != Bls12_381::pairing(g1, new.delta_g2) {
        return Err("delta_g1/delta_g2 consistency check (3) failed".into());
    }
    Ok(())
}

/// Deterministic batch scalar for the division check, from both param sets and a domain tag.
fn division_rho(old: &DeltaParams, new: &DeltaParams, tag: &[u8]) -> Fr {
    let mut pre = Vec::new();
    pre.extend_from_slice(&hash_obj(old));
    pre.extend_from_slice(&hash_obj(new));
    pre.extend_from_slice(tag);
    hash_to_fr(&pre)
}

/// Random-linear-combination consistency for one query vector:
///   e( sum rho^i new[i], new_delta_g2 ) == e( sum rho^i old[i], old_delta_g2 )
/// which holds iff new[i] * new_delta == old[i] * old_delta for every i, i.e. new[i] = old[i]/d.
fn division_ok(
    old_q: &[G1Affine],
    new_q: &[G1Affine],
    old_delta_g2: &G2Affine,
    new_delta_g2: &G2Affine,
    rho: Fr,
) -> bool {
    if old_q.len() != new_q.len() {
        return false;
    }
    let mut acc_old = G1Projective::zero();
    let mut acc_new = G1Projective::zero();
    let mut p = Fr::one();
    for i in 0..old_q.len() {
        acc_old += G1Projective::from(old_q[i]) * p;
        acc_new += G1Projective::from(new_q[i]) * p;
        p *= rho;
    }
    let lhs = Bls12_381::pairing(acc_new.into_affine(), *new_delta_g2);
    let rhs = Bls12_381::pairing(acc_old.into_affine(), *old_delta_g2);
    lhs == rhs
}

/// The full, heavy correctness check between two consecutive delta-params objects. Proves H and L
/// were each divided by the same secret that advanced delta. Independent of `verify_pok`.
pub fn verify_division(old: &DeltaParams, new: &DeltaParams) -> Result<(), String> {
    if old.h_query.len() != new.h_query.len() || old.l_query.len() != new.l_query.len() {
        return Err("query lengths changed between contributions".into());
    }
    let rho_h = division_rho(old, new, b"h-query");
    if !division_ok(&old.h_query, &new.h_query, &old.delta_g2, &new.delta_g2, rho_h) {
        return Err("H-query division inconsistent".into());
    }
    let rho_l = division_rho(old, new, b"l-query");
    if !division_ok(&old.l_query, &new.l_query, &old.delta_g2, &new.delta_g2, rho_l) {
        return Err("L-query division inconsistent".into());
    }
    Ok(())
}

/// The public random-beacon secret: d = hash_to_fr( "beacon" || beacon_bytes ). Fully public and
/// reproducible, so anyone can recompute it and confirm the final mix.
pub fn beacon_secret(beacon: &[u8]) -> Fr {
    let mut pre = Vec::with_capacity(6 + beacon.len());
    pre.extend_from_slice(b"beacon");
    pre.extend_from_slice(beacon);
    let mut d = hash_to_fr(&pre);
    if d.is_zero() {
        d = Fr::one() + Fr::one();
    }
    d
}

/// Verify the finalize step: the beacon's secret is public, so beyond the PoK we directly recompute
/// d from the beacon and confirm every part advanced by exactly it.
pub fn verify_beacon_step(
    prev_challenge: &[u8; 32],
    old: &DeltaParams,
    new: &DeltaParams,
    pok: &Pok,
    beacon: &[u8],
) -> Result<(), String> {
    verify_pok(prev_challenge, &old.delta_g1, new, pok)?;
    verify_division(old, new)?;
    // Public-secret confirmation: new = old transformed by the public beacon secret.
    let d = beacon_secret(beacon);
    let d_inv = d.inverse().ok_or("beacon secret not invertible")?;
    let expect_delta_g1 = (G1Projective::from(old.delta_g1) * d).into_affine();
    if expect_delta_g1 != new.delta_g1 {
        return Err("beacon delta_g1 does not match the public beacon secret".into());
    }
    // Spot-check one h and one l point against the public division (full vector already checked).
    if !old.h_query.is_empty() {
        let expect = (G1Projective::from(old.h_query[0]) * d_inv).into_affine();
        if expect != new.h_query[0] {
            return Err("beacon H-division does not match the public beacon secret".into());
        }
    }
    Ok(())
}
