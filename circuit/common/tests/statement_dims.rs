//! Statement-dimension pins: the legacy and hardened transfer statements have distinct R1CS
//! shapes, and a proving key's vector lengths identify which statement it was set up for.
//! These pins are what the wallet prover's statement inference relies on — if a dependency
//! bump ever changes the generator's key layout, this test fails loudly before the wallet
//! could mis-infer.
#![cfg(feature = "bls12-381")]

use ark_bls12_381::Bls12_381;
use ark_groth16::Groth16;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisMode};
use ark_snark::SNARK;
use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;
use common::{poseidon_config, ScalarField as F, TransferCircuit};

fn dims(legacy: bool) -> (usize, usize, usize) {
    let cfg = poseidon_config();
    let circuit =
        if legacy { TransferCircuit::blank_legacy(&cfg) } else { TransferCircuit::blank(&cfg) };
    let cs = ConstraintSystem::<F>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Setup);
    circuit.generate_constraints(cs.clone()).unwrap();
    cs.finalize();
    (cs.num_constraints(), cs.num_instance_variables(), cs.num_witness_variables())
}

#[test]
fn statement_dimensions_and_pk_lengths() {
    let cfg = poseidon_config();
    let (lc, li, lw) = dims(true);
    let (hc, hi, hw) = dims(false);
    println!("legacy  : constraints={lc} instance={li} witness={lw}");
    println!("hardened: constraints={hc} instance={hi} witness={hw}");

    let mut rng = StdRng::seed_from_u64(1);
    let (lpk, _lvk) =
        Groth16::<Bls12_381>::circuit_specific_setup(TransferCircuit::blank_legacy(&cfg), &mut rng)
            .unwrap();
    let (hpk, _hvk) =
        Groth16::<Bls12_381>::circuit_specific_setup(TransferCircuit::blank(&cfg), &mut rng)
            .unwrap();
    println!(
        "legacy  pk: a={} b_g1={} b_g2={} h={} l={}",
        lpk.a_query.len(),
        lpk.b_g1_query.len(),
        lpk.b_g2_query.len(),
        lpk.h_query.len(),
        lpk.l_query.len()
    );
    println!(
        "hardened pk: a={} b_g1={} b_g2={} h={} l={}",
        hpk.a_query.len(),
        hpk.b_g1_query.len(),
        hpk.b_g2_query.len(),
        hpk.h_query.len(),
        hpk.l_query.len()
    );
    assert_ne!(lw, hw, "statements must differ in witness count for pk inference");

    // The load-bearing pins. The wallet prover infers a proving key's statement from
    // `l_query.len() == <that statement's finalized witness count>`; both sides of that
    // equation are pinned here, for both statements, against the exact generator behavior.
    assert_eq!(lpk.l_query.len(), lw, "legacy pk l_query must equal the witness count");
    assert_eq!(hpk.l_query.len(), hw, "hardened pk l_query must equal the witness count");
    // The frozen legacy fixture oracle (`circuit/vectors-bls/ORACLE.txt`) pins this shape.
    assert_eq!((lc, li, lw), (20146, 9, 20213), "legacy statement shape drifted");
    assert_eq!(
        (hc, hi, hw),
        (20277, 9, 20342),
        "hardened statement shape drifted: 131 constraints (2x65 range + 1 distinctness) and \
         129 witnesses (128 bits + 1 inverse) over legacy"
    );
}
