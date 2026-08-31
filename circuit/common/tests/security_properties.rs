#![cfg(feature = "bls12-381")]

use ark_bls12_381::Bls12_381;
use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, CryptographicSponge};
use ark_ff::{One, UniformRand};
use ark_groth16::{Groth16, Proof};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, RngCore, SeedableRng};
use common::{
    poseidon_config_tree, TREE_ARITY,
    derive_nf, derive_pk, hash_n, merkle_compress, note_commitment, poseidon_config, DenseTree,
    DepositCircuit, IncrementalTree, Note, PoseidonCfg, ScalarField as F, TransferCircuit, TAG_CM,
    TAG_MERGE,
};

const TEST_SEED: [u8; 32] = [0x53; 32];

fn assert_satisfied(circuit: TransferCircuit) {
    let cs = ConstraintSystem::<F>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    assert!(
        cs.is_satisfied().unwrap(),
        "honest transfer unexpectedly violated constraint {:?}",
        cs.which_is_unsatisfied().unwrap()
    );
}

fn assert_unsatisfied(circuit: TransferCircuit) {
    let cs = ConstraintSystem::<F>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    assert!(
        !cs.is_satisfied().unwrap(),
        "mutant unexpectedly satisfied the circuit"
    );
}

fn transfer_case(
    rng: &mut StdRng,
    cfg: &PoseidonCfg<F>,
    in_values: [u64; 2],
    fee: u64,
    public_out: u64,
    first_output: u64,
) -> TransferCircuit {
    let total = u128::from(in_values[0]) + u128::from(in_values[1]);
    let consumed = u128::from(fee) + u128::from(public_out) + u128::from(first_output);
    assert!(consumed <= total);
    let second_output = u64::try_from(total - consumed).unwrap();

    let owner_nk = F::rand(rng);
    let recipient_nk = F::rand(rng);
    let inputs = [
        Note {
            v: in_values[0],
            nk: owner_nk,
            rho: F::rand(rng),
            rcm: F::rand(rng),
        },
        Note {
            v: in_values[1],
            nk: owner_nk,
            rho: F::rand(rng),
            rcm: F::rand(rng),
        },
    ];

    // Put the real notes at non-trivial positions among unrelated commitments so both left and
    // right Merkle-path branches are exercised.
    let mut filler = || Note {
        v: 1,
        nk: F::rand(rng),
        rho: F::rand(rng),
        rcm: F::rand(rng),
    };
    let leaves = vec![
        filler().cm(cfg),
        inputs[0].cm(cfg),
        filler().cm(cfg),
        filler().cm(cfg),
        inputs[1].cm(cfg),
        filler().cm(cfg),
    ];
    let tree = DenseTree { leaves };
    let cfg_tree = poseidon_config_tree();
    let anchor = tree.root(&cfg_tree);
    let (rows_1, pos_1) = tree.path(&cfg_tree, 1);
    let (rows_2, pos_2) = tree.path(&cfg_tree, 4);
    let nullifiers = [inputs[0].nf(cfg), inputs[1].nf(cfg)];
    let output_pk = [derive_pk(cfg, recipient_nk), derive_pk(cfg, owner_nk)];
    let output_rcm = [F::rand(rng), F::rand(rng)];
    let output_values = [first_output, second_output];
    let output_commitments = [
        note_commitment(
            cfg,
            output_values[0],
            output_pk[0],
            nullifiers[0],
            output_rcm[0],
        ),
        note_commitment(
            cfg,
            output_values[1],
            output_pk[1],
            nullifiers[1],
            output_rcm[1],
        ),
    ];

    TransferCircuit {
        cfg: cfg.clone(),
        enforce_range: true,
        legacy_statement: false,
        anchor: Some(anchor),
        nf: [Some(nullifiers[0]), Some(nullifiers[1])],
        cm_out: [Some(output_commitments[0]), Some(output_commitments[1])],
        fee: Some(fee),
        v_pub_out: Some(public_out),
        recipient_binding: Some(F::rand(rng)),
        in_v: [Some(inputs[0].v), Some(inputs[1].v)],
        in_nk: [Some(inputs[0].nk), Some(inputs[1].nk)],
        in_rho: [Some(inputs[0].rho), Some(inputs[1].rho)],
        in_rcm: [Some(inputs[0].rcm), Some(inputs[1].rcm)],
        in_rows: [rows_1, rows_2],
        in_pos: [pos_1, pos_2],
        out_v: [
            Some(F::from(output_values[0])),
            Some(F::from(output_values[1])),
        ],
        out_pk: [Some(output_pk[0]), Some(output_pk[1])],
        out_rcm: [Some(output_rcm[0]), Some(output_rcm[1])],
    }
}

#[test]
fn randomized_transfers_enforce_conservation_membership_nullifiers_and_commitments() {
    let cfg = poseidon_config();
    let mut rng = StdRng::from_seed(TEST_SEED);

    for case in 0..12 {
        let first = 10_000 + rng.next_u64() % 1_000_000;
        let second = 10_000 + rng.next_u64() % 1_000_000;
        let total = first + second;
        let fee = rng.next_u64() % (total / 8 + 1);
        let public_out = rng.next_u64() % ((total - fee) / 3 + 1);
        let remaining = total - fee - public_out;
        let first_output = rng.next_u64() % (remaining + 1);
        let honest = transfer_case(
            &mut rng,
            &cfg,
            [first, second],
            fee,
            public_out,
            first_output,
        );
        assert_satisfied(honest.clone());

        let mut imbalance = honest.clone();
        let bumped = imbalance.out_v[0].unwrap() + F::one();
        imbalance.out_v[0] = Some(bumped);
        imbalance.cm_out[0] = Some(hash_n(
            &cfg,
            &[
                F::from(TAG_CM),
                bumped,
                imbalance.out_pk[0].unwrap(),
                imbalance.nf[0].unwrap(),
                imbalance.out_rcm[0].unwrap(),
            ],
        ));
        assert_unsatisfied(imbalance);

        let mut wrong_path = honest.clone();
        let input = case % 2;
        let level = (case * 7) % wrong_path.in_pos[input].len();
        // 5-ary: move the claimed slot within the row (was: flip the left/right bit). The one-hot
        // selector then picks a sibling instead of the node carried up, so membership must fail.
        wrong_path.in_pos[input][level] = (wrong_path.in_pos[input][level] + 1) % TREE_ARITY;
        assert_unsatisfied(wrong_path);

        let mut wrong_nullifier = honest.clone();
        wrong_nullifier.nf[case % 2] = Some(wrong_nullifier.nf[case % 2].unwrap() + F::one());
        assert_unsatisfied(wrong_nullifier);

        let mut wrong_commitment = honest;
        wrong_commitment.cm_out[case % 2] =
            Some(wrong_commitment.cm_out[case % 2].unwrap() + F::one());
        assert_unsatisfied(wrong_commitment);
    }
}

#[test]
fn u64_range_checks_block_the_field_wrap_mint() {
    let cfg = poseidon_config();
    let mut rng = StdRng::from_seed([0xa2; 32]);
    let honest = transfer_case(&mut rng, &cfg, [70, 30], 5, 0, 55);

    // In the scalar field, -1 + 96 + 5 == 100. Without integer range constraints this mints a
    // spendable 96-unit note while hiding p-1 in the other output.
    let negative = -F::one();
    let mut mutant = honest;
    mutant.out_v = [Some(negative), Some(F::from(96u64))];
    mutant.cm_out = [
        Some(hash_n(
            &cfg,
            &[
                F::from(TAG_CM),
                negative,
                mutant.out_pk[0].unwrap(),
                mutant.nf[0].unwrap(),
                mutant.out_rcm[0].unwrap(),
            ],
        )),
        Some(hash_n(
            &cfg,
            &[
                F::from(TAG_CM),
                F::from(96u64),
                mutant.out_pk[1].unwrap(),
                mutant.nf[1].unwrap(),
                mutant.out_rcm[1].unwrap(),
            ],
        )),
    ];

    let mut vulnerable_variant = mutant.clone();
    vulnerable_variant.enforce_range = false;
    assert_satisfied(vulnerable_variant);
    assert_unsatisfied(mutant);
}

#[test]
fn proof_is_bound_to_every_public_input_and_rejects_each_single_byte_mutation() {
    let cfg = poseidon_config();
    let mut rng = StdRng::from_seed([0x16; 32]);
    let circuit = transfer_case(&mut rng, &cfg, [70_000, 31_000], 10, 1_234, 50_000);
    let public_inputs = circuit.public_inputs();

    // This deterministic seed is test-only. It never generates deployment keys.
    let mut setup_rng = StdRng::from_seed([0xc3; 32]);
    let (pk, vk) =
        Groth16::<Bls12_381>::circuit_specific_setup(TransferCircuit::blank(&cfg), &mut setup_rng)
            .unwrap();
    let proof = Groth16::<Bls12_381>::prove(&pk, circuit, &mut rng).unwrap();
    assert!(Groth16::<Bls12_381>::verify(&vk, &public_inputs, &proof).unwrap());

    assert_eq!(
        public_inputs.len(),
        8,
        "public-input ordering changed without updating the gate"
    );
    for position in 0..public_inputs.len() {
        let mut mutant = public_inputs.clone();
        mutant[position] += F::one();
        assert!(
            !Groth16::<Bls12_381>::verify(&vk, &mutant, &proof).unwrap(),
            "proof accepted public-input mutation at position {position}"
        );
    }

    let mut encoded = Vec::new();
    proof.serialize_compressed(&mut encoded).unwrap();
    for byte in 0..encoded.len() {
        let mut mutant = encoded.clone();
        mutant[byte] ^= 1;
        if let Ok(decoded) = Proof::<Bls12_381>::deserialize_compressed(mutant.as_slice()) {
            assert!(
                !Groth16::<Bls12_381>::verify(&vk, &public_inputs, &decoded).unwrap(),
                "proof accepted a one-bit mutation in byte {byte}"
            );
        }
    }
}

#[test]
fn deposit_commitment_binds_amount_and_opening_across_edges() {
    let cfg = poseidon_config();
    let mut rng = StdRng::from_seed([0xd6; 32]);
    for value in [0, 1, 10_000, 100_000_000, u32::MAX as u64, u64::MAX] {
        let pk = derive_pk(&cfg, F::rand(&mut rng));
        let rho = F::rand(&mut rng);
        let rcm = F::rand(&mut rng);
        let cm = note_commitment(&cfg, value, pk, rho, rcm);
        let honest = DepositCircuit {
            cfg: cfg.clone(),
            cm: Some(cm),
            v_pub: Some(value),
            pk: Some(pk),
            rho: Some(rho),
            rcm: Some(rcm),
        };
        let cs = ConstraintSystem::<F>::new_ref();
        honest.clone().generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());

        let mut wrong_amount = honest.clone();
        wrong_amount.v_pub = Some(value.wrapping_add(1));
        let cs = ConstraintSystem::<F>::new_ref();
        wrong_amount.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());

        let mut wrong_opening = honest;
        wrong_opening.rcm = Some(rcm + F::one());
        let cs = ConstraintSystem::<F>::new_ref();
        wrong_opening.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }
}

#[test]
fn incremental_and_dense_tree_roots_match_after_every_append() {
    let cfg = poseidon_config();
    let mut rng = StdRng::from_seed([0x71; 32]);
    let cfg_tree = poseidon_config_tree();
    let mut incremental = IncrementalTree::new(&cfg_tree);
    let mut leaves = Vec::new();
    for _ in 0..40 {
        leaves.push(F::rand(&mut rng));
        let incremental_root = incremental.append(&cfg_tree, *leaves.last().unwrap());
        let dense_root = DenseTree {
            leaves: leaves.clone(),
        }
        .root(&cfg_tree);
        assert_eq!(incremental_root, dense_root);
    }
}

#[test]
fn note_hash_domains_are_distinct() {
    let cfg = poseidon_config();
    let mut rng = StdRng::from_seed([0x44; 32]);
    for _ in 0..32 {
        let nk = F::rand(&mut rng);
        let rho = F::rand(&mut rng);
        let rcm = F::rand(&mut rng);
        let pk = derive_pk(&cfg, nk);
        let nf = derive_nf(&cfg, nk, rho);
        let cm = note_commitment(&cfg, rng.next_u64(), pk, rho, rcm);
        // The merge (inner-node) domain joins pk/nf/cm as a fourth distinct image domain.
        // Built with `from_fn` over TREE_ARITY rather than a literal row: a literal pins the
        // test to one arity, and the arity has now changed twice. Alternating two DIFFERENT
        // note images keeps the row non-uniform, so the check cannot pass by accident on a
        // row whose slots are all equal.
        let row: [F; TREE_ARITY] = core::array::from_fn(|i| if i % 2 == 0 { pk } else { cm });
        let node = merkle_compress(&poseidon_config_tree(), &row);
        assert_ne!(pk, nf);
        assert_ne!(pk, cm);
        assert_ne!(nf, cm);
        assert_ne!(node, pk);
        assert_ne!(node, nf);
        assert_ne!(node, cm);
    }
}

/// The Merkle inner-node hash is domain-separated by TAG_MERGE=4 carried in the sponge CAPACITY,
/// so a node image lives in a domain distinct from a bare row hash and from a leaf commitment.
/// This is the structural separation the tag buys: an attacker cannot reinterpret an inner-node
/// value as a leaf commitment (or vice versa) without a Poseidon preimage, and the tag makes that
/// true by construction rather than as a consequence of arity alone.
///
/// TWO relocations are pinned here. The tag moved from a leading RATE element into the capacity so
/// a level stopped paying a second permutation; and the tree moved to arity 5 on its own width-6
/// Poseidon instance. Neither weakens the separation — the capacity enters every round, and the
/// two instances now have different round constants and a different MDS as well — so this test
/// asserts what it always did, plus a regression pin on each relocation.
#[test]
fn merkle_node_domain_is_tag_separated() {
    let cfg = poseidon_config();
    let cfg_tree = poseidon_config_tree();
    let mut rng = StdRng::from_seed([0x4e; 32]);
    for _ in 0..32 {
        let row: [F; TREE_ARITY] = core::array::from_fn(|_| F::rand(&mut rng));

        // The tagged node hash differs from the untagged hash of the same children on the same
        // instance: proof the tag actually moved the domain (not a no-op).
        let mut untagged = PoseidonSponge::<F>::new(&cfg_tree.0);
        for c in &row {
            untagged.absorb(c);
        }
        assert_ne!(
            merkle_compress(&cfg_tree, &row),
            untagged.squeeze_field_elements(1)[0],
            "merge tag did not change the node hash — domain separation is not in effect"
        );

        // And it equals a sponge whose CAPACITY carries the tag while the rate absorbs exactly the
        // ARITY children — pinning the exact preimage shape the circuit gadget and the Motoko
        // verifier must reproduce byte-for-byte. Spelled out from the schedule rather than by
        // calling merkle_compress, so this pins the construction instead of restating it.
        let mut sponge = PoseidonSponge::<F>::new(&cfg_tree.0);
        sponge.state[0] = F::from(TAG_MERGE);
        for c in &row {
            sponge.absorb(c);
        }
        assert_eq!(
            merkle_compress(&cfg_tree, &row),
            sponge.squeeze_field_elements(1)[0],
            "merkle_compress must be the capacity-tagged sponge over [TAG_MERGE, row..]"
        );

        // The tag must live in the CAPACITY, never back in a rate slot. Absorbed as a leading rate
        // element it separates the domain just as well but overflows the rate and costs a second
        // permutation on every Merkle level. Such a regression is silent everywhere else — proofs
        // still verify, they are simply twice the work — so this assertion is the only notice.
        let mut rate_absorbed = PoseidonSponge::<F>::new(&cfg_tree.0);
        rate_absorbed.absorb(&F::from(TAG_MERGE));
        for c in &row {
            rate_absorbed.absorb(c);
        }
        assert_ne!(
            merkle_compress(&cfg_tree, &row),
            rate_absorbed.squeeze_field_elements(1)[0],
            "the merge tag is being absorbed as a rate element again — the wasted permutation is back"
        );

        // A node image is distinct from a leaf commitment built to mimic it (arity/tag confusion
        // attempt): H_tree(TAG_MERGE, row..) != H_note(TAG_CM, v, pk, rho, rcm).
        let cm = note_commitment(&cfg, rng.next_u64(), row[0], row[1], F::rand(&mut rng));
        assert_ne!(merkle_compress(&cfg_tree, &row), cm);
        // Cross-check: feeding a note-domain tag in as a child does not collide with a leaf.
        let mut confused = row;
        confused[0] = F::from(TAG_CM);
        assert_ne!(merkle_compress(&cfg_tree, &confused), cm);

        // The two instances are genuinely different hashes, not the same permutation at two
        // widths: the tree instance must not reproduce a note-instance image of the same inputs.
        assert_ne!(
            merkle_compress(&cfg_tree, &row),
            hash_n(&cfg, &[F::from(TAG_MERGE), row[0], row[1]]),
            "tree and note instances collide — the width-6 config is not actually in use"
        );
    }
}
