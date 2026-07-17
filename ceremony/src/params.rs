//! Deriving the initial Phase-2 parameters from the Phase-1 SRS and a circuit, entirely in the
//! exponent (the accumulated Phase-1 secret tau/alpha/beta is never known in production).
//!
//! The Phase-2 parameter object IS an `ark_groth16::ProvingKey<Bls12_381>`: the initial one has
//! delta = 1 and gamma = 1, exactly as the standard Phase-2 MPC (bellman `MPCParameters::new`,
//! snarkjs) constructs it. A contribution scales delta_g1 / delta_g2 by its secret and divides
//! h_query / l_query by it; everything else (alpha, beta, gamma_abc, the A/B queries) is fixed by
//! Phase-1. The final ProvingKey is directly consumable by the existing browser prover, and its
//! embedded VerifyingKey is directly the ledger's verifying key.
//!
//! CORRECTNESS ORACLE. `initial_params_field_oracle` recomputes the same object from arkworks'
//! authoritative `LibsnarkReduction::instance_map_with_evaluation` at a KNOWN tau; the unit test
//! asserts the two agree element for element. That is the oracle-methodology cross-check: arkworks
//! QAP reduction is the source of truth, the FFT-in-exponent derivation is the port.

use crate::srs::Phase1Srs;
use crate::transcript::{DeltaParams, FixedParams};
use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Projective};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::Zero;
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_relations::r1cs::{
    ConstraintMatrices, ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisMode,
};

/// Synthesize a circuit into the finalized constraint system arkworks' generator would build, and
/// return its matrices plus the shape numbers. Kept identical to `generator.rs` (Constraints goal,
/// Setup mode, finalize) so the QAP domain and wire layout match the oracle exactly.
pub fn synthesize<C: ConstraintSynthesizer<Fr>>(
    circuit: C,
) -> (ConstraintMatrices<Fr>, usize, usize, usize) {
    let cs = ConstraintSystem::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Setup);
    circuit.generate_constraints(cs.clone()).expect("synthesis");
    cs.finalize();
    let num_instance = cs.num_instance_variables();
    let num_witness = cs.num_witness_variables();
    let num_constraints = cs.num_constraints();
    let matrices = cs.to_matrices().expect("matrices");
    (matrices, num_instance, num_witness, num_constraints)
}

/// The QAP domain size arkworks uses for this circuit (a power of two).
pub fn qap_domain_size(num_instance: usize, num_constraints: usize) -> usize {
    GeneralEvaluationDomain::<Fr>::new(num_constraints + num_instance)
        .expect("domain")
        .size()
}

/// Derive the initial Phase-2 ProvingKey (delta = 1, gamma = 1) from the SRS and circuit, in the
/// exponent. Fails if the SRS power does not cover the circuit's QAP domain.
pub fn derive_initial_params<C: ConstraintSynthesizer<Fr>>(
    srs: &Phase1Srs,
    circuit: C,
) -> Result<ProvingKey<Bls12_381>, String> {
    let (matrices, num_instance, num_witness, num_constraints) = synthesize(circuit);
    let total_wires = num_instance + num_witness; // = qap_num_variables + 1
    let domain = GeneralEvaluationDomain::<Fr>::new(num_constraints + num_instance)
        .ok_or("domain too large")?;
    let d = domain.size();
    if d > srs.n() {
        return Err(format!("circuit QAP domain {d} exceeds SRS capacity n={}", srs.n()));
    }
    if 2 * d - 1 > srs.tau_g1.len() {
        return Err("SRS tau_g1 too short for the H-query".into());
    }

    // --- Lagrange bases in the exponent: ifft of the first d powers. L_k(tau) = (1/d) sum_j w^{-kj} tau^j.
    let to_proj_g1 = |aff: &[G1Affine]| -> Vec<G1Projective> {
        aff.iter().map(|p| (*p).into()).collect()
    };
    let mut lag_g1: Vec<G1Projective> = to_proj_g1(&srs.tau_g1[..d]);
    domain.ifft_in_place(&mut lag_g1);
    let mut lag_g2: Vec<G2Projective> =
        srs.tau_g2[..d].iter().map(|p| (*p).into()).collect();
    domain.ifft_in_place(&mut lag_g2);
    let mut lag_alpha_g1: Vec<G1Projective> = to_proj_g1(&srs.alpha_tau_g1[..d]);
    domain.ifft_in_place(&mut lag_alpha_g1);
    let mut lag_beta_g1: Vec<G1Projective> = to_proj_g1(&srs.beta_tau_g1[..d]);
    domain.ifft_in_place(&mut lag_beta_g1);

    // --- Per-wire accumulators.
    // a_g1[j] = [A_j(tau)]_1, b_g1[j] = [B_j(tau)]_1, b_g2[j] = [B_j(tau)]_2,
    // lc_g1[j] = [ (beta*A_j + alpha*B_j + C_j)(tau) ]_1.
    let mut a_g1 = vec![G1Projective::zero(); total_wires];
    let mut b_g1 = vec![G1Projective::zero(); total_wires];
    let mut b_g2 = vec![G2Projective::zero(); total_wires];
    let mut lc_g1 = vec![G1Projective::zero(); total_wires];

    // Input-consistency rows (libsnark reduction): for instance wire j, A_j gets L_{num_constraints+j}.
    // Only the A matrix has these extra rows; they feed a_g1 and the beta*A part of lc.
    for j in 0..num_instance {
        let l = lag_g1[num_constraints + j];
        a_g1[j] += l;
        lc_g1[j] += lag_beta_g1[num_constraints + j];
    }

    // Constraint rows.
    for i in 0..num_constraints {
        let lg1 = lag_g1[i];
        let lg2 = lag_g2[i];
        let la = lag_alpha_g1[i];
        let lb = lag_beta_g1[i];
        for &(coeff, index) in &matrices.a[i] {
            a_g1[index] += lg1 * coeff;
            lc_g1[index] += lb * coeff; // beta * A
        }
        for &(coeff, index) in &matrices.b[i] {
            b_g1[index] += lg1 * coeff;
            b_g2[index] += lg2 * coeff;
            lc_g1[index] += la * coeff; // alpha * B
        }
        for &(coeff, index) in &matrices.c[i] {
            lc_g1[index] += lg1 * coeff; // C
        }
    }

    // --- gamma_abc (public wires, gamma = 1) and l_query (witness wires, delta = 1).
    let gamma_abc_proj: Vec<G1Projective> = lc_g1[..num_instance].to_vec();
    let l_query_proj: Vec<G1Projective> = lc_g1[num_instance..].to_vec();

    // --- H-query: h[i] = [ t(tau) * tau^i ]_1 = [tau^{d+i}]_1 - [tau^i]_1, delta = 1, i in 0..d-1.
    let mut h_query_proj = Vec::with_capacity(d - 1);
    for i in 0..(d - 1) {
        let hi: G1Projective = G1Projective::from(srs.tau_g1[d + i]) - G1Projective::from(srs.tau_g1[i]);
        h_query_proj.push(hi);
    }

    // --- Fixed scalars-in-exponent from Phase-1.
    let alpha_g1 = srs.alpha_tau_g1[0]; // [alpha]_1
    let beta_g1 = srs.beta_tau_g1[0]; // [beta]_1
    let beta_g2 = srs.beta_g2; // [beta]_2
    let g1 = G1Projective::generator();
    let g2 = G2Projective::generator();

    let vk = VerifyingKey::<Bls12_381> {
        alpha_g1,
        beta_g2,
        gamma_g2: g2.into_affine(), // gamma = 1
        delta_g2: g2.into_affine(), // delta = 1 (initial)
        gamma_abc_g1: G1Projective::normalize_batch(&gamma_abc_proj),
    };

    Ok(ProvingKey::<Bls12_381> {
        vk,
        beta_g1,
        delta_g1: g1.into_affine(), // delta = 1 (initial)
        a_query: G1Projective::normalize_batch(&a_g1),
        b_g1_query: G1Projective::normalize_batch(&b_g1),
        b_g2_query: G2Projective::normalize_batch(&b_g2),
        h_query: G1Projective::normalize_batch(&h_query_proj),
        l_query: G1Projective::normalize_batch(&l_query_proj),
    })
}

/// Split an arkworks ProvingKey into the Phase-1-fixed part and the delta-dependent part.
pub fn split_pk(pk: &ProvingKey<Bls12_381>) -> (FixedParams, DeltaParams) {
    let fixed = FixedParams {
        alpha_g1: pk.vk.alpha_g1,
        beta_g1: pk.beta_g1,
        beta_g2: pk.vk.beta_g2,
        gamma_g2: pk.vk.gamma_g2,
        gamma_abc_g1: pk.vk.gamma_abc_g1.clone(),
        a_query: pk.a_query.clone(),
        b_g1_query: pk.b_g1_query.clone(),
        b_g2_query: pk.b_g2_query.clone(),
        num_instance: pk.vk.gamma_abc_g1.len() as u32,
    };
    let delta = DeltaParams {
        delta_g1: pk.delta_g1,
        delta_g2: pk.vk.delta_g2,
        h_query: pk.h_query.clone(),
        l_query: pk.l_query.clone(),
    };
    (fixed, delta)
}

/// Reassemble an arkworks ProvingKey from the fixed and delta parts (used to prove/verify with the
/// ceremony's current or final keys).
pub fn join_pk(fixed: &FixedParams, delta: &DeltaParams) -> ProvingKey<Bls12_381> {
    let vk = VerifyingKey::<Bls12_381> {
        alpha_g1: fixed.alpha_g1,
        beta_g2: fixed.beta_g2,
        gamma_g2: fixed.gamma_g2,
        delta_g2: delta.delta_g2,
        gamma_abc_g1: fixed.gamma_abc_g1.clone(),
    };
    ProvingKey::<Bls12_381> {
        vk,
        beta_g1: fixed.beta_g1,
        delta_g1: delta.delta_g1,
        a_query: fixed.a_query.clone(),
        b_g1_query: fixed.b_g1_query.clone(),
        b_g2_query: fixed.b_g2_query.clone(),
        h_query: delta.h_query.clone(),
        l_query: delta.l_query.clone(),
    }
}

/// ORACLE: recompute the initial ProvingKey directly from arkworks' authoritative QAP evaluation at
/// a KNOWN tau, with the SAME alpha/beta the SRS was built from, gamma = delta = 1, canonical
/// generators. Used only by tests to prove `derive_initial_params` is correct.
#[cfg(test)]
pub fn initial_params_field_oracle<C: ConstraintSynthesizer<Fr>>(
    circuit: C,
    tau: Fr,
    alpha: Fr,
    beta: Fr,
) -> ProvingKey<Bls12_381> {
    use ark_ff::{Field, One};
    use ark_groth16::r1cs_to_qap::{LibsnarkReduction, R1CSToQAP};

    let cs = ConstraintSystem::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Setup);
    circuit.generate_constraints(cs.clone()).unwrap();
    cs.finalize();
    let num_instance = cs.num_instance_variables();

    let (a, b, c, zt, _qap_nv, m_raw) =
        LibsnarkReduction::instance_map_with_evaluation::<Fr, GeneralEvaluationDomain<Fr>>(cs, &tau)
            .unwrap();

    let g1 = G1Projective::generator();
    let g2 = G2Projective::generator();
    let gamma_inv = Fr::one();
    let delta_inv = Fr::one();

    let lc = |i: usize| beta * a[i] + alpha * b[i] + c[i];
    let gamma_abc: Vec<G1Affine> = (0..num_instance)
        .map(|i| (g1 * (lc(i) * gamma_inv)).into_affine())
        .collect();
    let l_query: Vec<G1Affine> = (num_instance..a.len())
        .map(|i| (g1 * (lc(i) * delta_inv)).into_affine())
        .collect();
    let a_query: Vec<G1Affine> = a.iter().map(|x| (g1 * x).into_affine()).collect();
    let b_g1_query: Vec<G1Affine> = b.iter().map(|x| (g1 * x).into_affine()).collect();
    let b_g2_query = b.iter().map(|x| (g2 * x).into_affine()).collect();
    let h_query: Vec<G1Affine> = (0..(m_raw - 1))
        .map(|i| (g1 * (zt * delta_inv * tau.pow([i as u64]))).into_affine())
        .collect();

    let vk = VerifyingKey::<Bls12_381> {
        alpha_g1: (g1 * alpha).into_affine(),
        beta_g2: (g2 * beta).into_affine(),
        gamma_g2: g2.into_affine(),
        delta_g2: g2.into_affine(),
        gamma_abc_g1: gamma_abc,
    };
    ProvingKey::<Bls12_381> {
        vk,
        beta_g1: (g1 * beta).into_affine(),
        delta_g1: g1.into_affine(),
        a_query,
        b_g1_query,
        b_g2_query,
        h_query,
        l_query,
    }
}
