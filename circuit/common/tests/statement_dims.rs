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
    // The frozen fixture oracles pin these shapes (TRANSFER-CIRCUIT lines: legacy in
    // `circuit/vectors-bls/ORACLE.txt`, hardened in
    // `fixtures/pool-vectors-bls12-381-hardened/ORACLE.txt`).
    //
    // Two relocations moved these numbers, in order.
    //
    // FIRST, the pre-tag numbers were restored. The TAG_MERGE hard fork grew them to 35506/35637
    // by absorbing the tag as a leading RATE element, which cost a second Poseidon permutation on
    // every one of 2 paths x 32 levels. Carrying the tag in the sponge CAPACITY instead separates
    // the domain identically — the capacity enters every round — but occupies no rate slot, so the
    // extra permutation disappears and the statement returns to exactly the size it had before the
    // tag existed. The tag is not weakened and not dropped: it now costs zero. That the numbers
    // land back on the historical pre-tag pins to the unit is the check that this was a relocation
    // and not a removal; `security_properties::merkle_node_domain_is_tag_separated` is the check
    // that the separation itself still holds.
    //
    // SECOND, the tree went 4-ary: 16 levels of arity 4 instead of 32 of arity 2, each level one
    // width-5 permutation instead of one width-3 permutation. That is what takes the hardened
    // statement from 20,277 to 14,261, and — because 14,335 wires fit a 2^14 domain where 20,351
    // needed 2^15 — halves the proving key a second time. The arity change ADDS constraints per
    // level (one-hot booleanity, the sum, and the selection inner product) and still wins, because
    // it removes 16 levels.
    //
    // Arity 4 and not 5: arity 5 reaches 13,797 constraints, 464 fewer, but BOTH land in the same
    // 2^14 domain, so the proving key — the whole point — is byte-for-byte identical either way,
    // and the extra 3.4% of circuit win is bought with ~21% more NATIVE work per append. In-circuit
    // the MDS is free (a linear combination); natively it is t^2 multiplications and dominates.
    // `frontier-oracle bench` measures it: at arity 4 an append is 0.99x the 2-ary cost, at arity 5
    // it is 1.15x. The ledger pays the native cost on every append, so arity 4 takes the same
    // download win for free. See `TREE_ARITY` in common/src/lib.rs for the full derivation.
    assert_eq!((lc, li, lw), (14130, 9, 14197), "legacy statement shape drifted");
    assert_eq!(
        (hc, hi, hw),
        (14261, 9, 14326),
        "hardened statement shape drifted: 131 constraints (2x65 range + 1 distinctness) and \
         129 witnesses (128 bits + 1 inverse) over legacy"
    );
    // The QAP domain is what the proving key's size is really made of, and it is why these two
    // changes halve the download twice over: 35,711 wires needed 2^16, 20,351 fit 2^15, and 14,335
    // fit 2^14. Pinned so a future circuit growth that silently crosses back over a boundary shows
    // up here as a failed test rather than as a doubled keyset in production. The headroom is now
    // 16,384 - 14,335 = 2,049 wires; that is the budget a future statement change has before the
    // keyset doubles.
    assert_eq!(hpk.h_query.len() + 1, 16384, "hardened QAP domain must be 2^14");
    assert_eq!(lpk.h_query.len() + 1, 16384, "legacy QAP domain must be 2^14");
}
