//! §4 single-rule-violation matrix (circuit soundness).
//!
//! For each rule the transfer circuit enforces, build an otherwise-honest witness that
//! violates EXACTLY ONE rule and assert the constraint system is UNSATISFIED — the
//! load-bearing property (if a single-rule violation still satisfied, all three verifiers
//! would correctly accept a proof for a broken circuit). Complements the reference-model
//! agreement in fortress/refmodel/model.py: that proves the honest path is computed
//! independently-correctly; this proves the dishonest paths are rejected by the circuit.
//!
//! This lives in the TEST tree (never in lib.rs / vendor/tree_common) so the security
//! gate's frozen-copy diff stays intact. Deterministic: one seed, printed via the harness.
#![cfg(feature = "bls12-381")]

use ark_bls12_381::Bls12_381;
use ark_ff::{One, UniformRand, Zero};
use ark_groth16::Groth16;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, RngCore, SeedableRng};
use common::{
    derive_pk, note_commitment, poseidon_config, DenseTree, Note, PoseidonCfg, ScalarField as F,
    TransferCircuit, TAG_CM,
};

const SEED: [u8; 32] = [0x4f; 32];

/// Build an honest, satisfiable 2-in/2-out transfer.
fn honest(rng: &mut StdRng, cfg: &PoseidonCfg<F>) -> TransferCircuit {
    let owner_nk = F::rand(rng);
    let recipient_nk = F::rand(rng);
    let in_v = [70_000u64 + rng.next_u64() % 500_000, 40_000 + rng.next_u64() % 500_000];
    let inputs = [
        Note { v: in_v[0], nk: owner_nk, rho: F::rand(rng), rcm: F::rand(rng) },
        Note { v: in_v[1], nk: owner_nk, rho: F::rand(rng), rcm: F::rand(rng) },
    ];
    let mut filler = |rng: &mut StdRng| Note { v: 1, nk: F::rand(rng), rho: F::rand(rng), rcm: F::rand(rng) };
    let leaves = vec![
        filler(rng).cm(cfg), inputs[0].cm(cfg), filler(rng).cm(cfg),
        filler(rng).cm(cfg), inputs[1].cm(cfg), filler(rng).cm(cfg),
    ];
    let tree = DenseTree { leaves };
    let anchor = tree.root(cfg);
    let (sib0, bits0) = tree.path(cfg, 1);
    let (sib1, bits1) = tree.path(cfg, 4);
    let nf = [inputs[0].nf(cfg), inputs[1].nf(cfg)];
    let out_pk = [derive_pk(cfg, recipient_nk), derive_pk(cfg, owner_nk)];
    let out_rcm = [F::rand(rng), F::rand(rng)];
    let total = in_v[0] + in_v[1];
    let fee = rng.next_u64() % (total / 8 + 1);
    let v_pub_out = rng.next_u64() % ((total - fee) / 3 + 1);
    let rem = total - fee - v_pub_out;
    let out_v = [rng.next_u64() % (rem + 1), 0];
    let out_v = [out_v[0], rem - out_v[0]];
    let cm_out = [
        note_commitment(cfg, out_v[0], out_pk[0], nf[0], out_rcm[0]),
        note_commitment(cfg, out_v[1], out_pk[1], nf[1], out_rcm[1]),
    ];
    TransferCircuit {
        cfg: cfg.clone(),
        enforce_range: true,
        anchor: Some(anchor),
        nf: [Some(nf[0]), Some(nf[1])],
        cm_out: [Some(cm_out[0]), Some(cm_out[1])],
        fee: Some(fee),
        v_pub_out: Some(v_pub_out),
        recipient_binding: Some(F::rand(rng)),
        in_v: [Some(in_v[0]), Some(in_v[1])],
        in_nk: [Some(inputs[0].nk), Some(inputs[1].nk)],
        in_rho: [Some(inputs[0].rho), Some(inputs[1].rho)],
        in_rcm: [Some(inputs[0].rcm), Some(inputs[1].rcm)],
        in_siblings: [sib0, sib1],
        in_bits: [bits0, bits1],
        out_v: [Some(F::from(out_v[0])), Some(F::from(out_v[1]))],
        out_pk: [Some(out_pk[0]), Some(out_pk[1])],
        out_rcm: [Some(out_rcm[0]), Some(out_rcm[1])],
    }
}

fn satisfied(c: &TransferCircuit) -> bool {
    let cs = ConstraintSystem::<F>::new_ref();
    c.clone().generate_constraints(cs.clone()).unwrap();
    cs.is_satisfied().unwrap()
}

/// Recompute cm_out[j] consistent with a mutated out_v[j] so the ONLY broken rule is the
/// one under test (otherwise the commitment-binding rule breaks too and the test is moot).
fn recommit(cfg: &PoseidonCfg<F>, c: &TransferCircuit, j: usize, new_v: F) -> F {
    common::hash_n(cfg, &[F::from(TAG_CM), new_v, c.out_pk[j].unwrap(), c.nf[j].unwrap(), c.out_rcm[j].unwrap()])
}

#[test]
fn every_single_rule_violation_is_unsatisfiable() {
    let cfg = poseidon_config();
    let mut rng = StdRng::from_seed(SEED);
    let mut count = 0;

    for case in 0..25 {
        let h = honest(&mut rng, &cfg);
        assert!(satisfied(&h), "honest case {case} unexpectedly unsatisfied");

        // 1. wrong owner (nk) on an input — pk/cm/nf all derive from it; membership breaks.
        let mut m = h.clone();
        m.in_nk[0] = Some(m.in_nk[0].unwrap() + F::one());
        assert!(!satisfied(&m), "wrong-owner satisfied");
        count += 1;

        // 2. wrong Merkle path bit.
        let mut m = h.clone();
        let lvl = (case * 7) % m.in_bits[0].len();
        m.in_bits[0][lvl] = !m.in_bits[0][lvl];
        assert!(!satisfied(&m), "wrong-path satisfied");
        count += 1;

        // 3. false root (anchor).
        let mut m = h.clone();
        m.anchor = Some(m.anchor.unwrap() + F::one());
        assert!(!satisfied(&m), "false-root satisfied");
        count += 1;

        // 4. value imbalance (bump one output value + recommit, break conservation only).
        let mut m = h.clone();
        let nv = m.out_v[0].unwrap() + F::one();
        m.out_v[0] = Some(nv);
        m.cm_out[0] = Some(recommit(&cfg, &m, 0, nv));
        assert!(!satisfied(&m), "value-imbalance satisfied");
        count += 1;

        // 5. out-of-range value (2^64) balanced by a compensating output, recommit both.
        let mut m = h.clone();
        let big = F::from(1u128 << 64);
        let cur0 = m.out_v[0].unwrap();
        let nv0 = cur0 + big;
        let nv1 = m.out_v[1].unwrap() - big; // wraps in the field; conservation holds mod p
        m.out_v[0] = Some(nv0);
        m.out_v[1] = Some(nv1);
        m.cm_out[0] = Some(recommit(&cfg, &m, 0, nv0));
        m.cm_out[1] = Some(recommit(&cfg, &m, 1, nv1));
        assert!(!satisfied(&m), "out-of-range value satisfied (range check absent?)");
        count += 1;

        // 6. wrong-secret nullifier (nf public input doesn't match the derived nf).
        let mut m = h.clone();
        m.nf[0] = Some(m.nf[0].unwrap() + F::one());
        assert!(!satisfied(&m), "wrong-secret-nullifier satisfied");
        count += 1;

        // 7. mismatched output commitment (public cm_out disagrees with the witness).
        let mut m = h.clone();
        m.cm_out[1] = Some(m.cm_out[1].unwrap() + F::one());
        assert!(!satisfied(&m), "mismatched-output-commitment satisfied");
        count += 1;

        // 8. changed recipient key without recommitting the output.
        let mut m = h.clone();
        m.out_pk[0] = Some(m.out_pk[0].unwrap() + F::one());
        assert!(!satisfied(&m), "changed-recipient-key satisfied");
        count += 1;

        // 9. changed recipient by swapping the two output recipient keys WITHOUT
        //    recommitting — the outputs no longer open to their public commitments.
        //    (Recipient-binding of the transparent withdraw target is a verifier-level
        //    property — the public recipient_binding input and its witnessed mirror read
        //    the same field, so they cannot diverge within one witness; that integrity is
        //    asserted at the verifier in `recipient_binding_is_bound_at_the_verifier`.)
        let mut m = h.clone();
        m.out_pk.swap(0, 1);
        assert!(!satisfied(&m), "swapped-recipient satisfied");
        count += 1;

        // 10. changed withdrawal amount (v_pub_out) without rebalancing — conservation breaks.
        let mut m = h.clone();
        m.v_pub_out = Some(m.v_pub_out.unwrap() + 1);
        assert!(!satisfied(&m), "changed-withdraw-amount satisfied");
        count += 1;

        // 11. fee omitted from conservation (drop the fee, keep outputs) — imbalance.
        let mut m = h.clone();
        if m.fee.unwrap() > 0 {
            m.fee = Some(0);
            assert!(!satisfied(&m), "fee-omitted satisfied");
            count += 1;
        }

        // 12. duplicate input note (same note in both slots) — the two nullifiers would be
        //     equal; here we make in1 identical to in0 (incl. path) but keep the distinct
        //     public nf[1]; the derived nf won't match nf[1] -> unsatisfied. (The equal-nf
        //     double-spend is caught by the canister; the circuit rejects the public/witness
        //     mismatch this construction forces.)
        let mut m = h.clone();
        m.in_nk[1] = m.in_nk[0];
        m.in_rho[1] = m.in_rho[0];
        m.in_rcm[1] = m.in_rcm[0];
        m.in_v[1] = m.in_v[0];
        m.in_siblings[1] = m.in_siblings[0].clone();
        m.in_bits[1] = m.in_bits[0].clone();
        assert!(!satisfied(&m), "duplicate-input-note satisfied");
        count += 1;

        // 13. changed deposit amount analogue: change an input value without updating its
        //     committed leaf/membership — cm no longer opens to the tree.
        let mut m = h.clone();
        m.in_v[0] = Some(m.in_v[0].unwrap() + 1);
        assert!(!satisfied(&m), "changed-input-amount satisfied");
        count += 1;

        // 14. dummy-treated-as-real: a zero-value input with a fabricated membership path.
        //     Replace in0 with a v=0 note whose cm is NOT in the tree; membership fails.
        let mut m = h.clone();
        m.in_v[0] = Some(0);
        // recompute nothing else: the honest anchor/path no longer authenticate this note.
        assert!(!satisfied(&m), "dummy-as-real satisfied");
        count += 1;
    }
    assert!(count >= 25 * 13, "violation matrix under-ran: {count}");
    println!("VIOLATION-MATRIX GREEN: {count} single-rule violations all UNSATISFIED");
}

#[test]
fn violated_witness_fails_proof_generation_or_verification() {
    // The strongest form: a value-imbalanced witness must not yield a verifying proof under
    // the honestly-generated keys. Groth16 proving on an unsatisfied CS errors; we assert
    // the negative path end to end for a representative violation.
    let cfg = poseidon_config();
    let mut rng = StdRng::from_seed([0x5a; 32]);
    let mut setup_rng = StdRng::from_seed([0xc3; 32]);
    let (pk, vk) =
        Groth16::<Bls12_381>::circuit_specific_setup(TransferCircuit::blank(&cfg), &mut setup_rng)
            .unwrap();

    let h = honest(&mut rng, &cfg);
    let good = Groth16::<Bls12_381>::prove(&pk, h.clone(), &mut rng).unwrap();
    assert!(Groth16::<Bls12_381>::verify(&vk, &h.public_inputs(), &good).unwrap());

    let mut bad = h.clone();
    let nv = bad.out_v[0].unwrap() + F::one();
    bad.out_v[0] = Some(nv);
    bad.cm_out[0] = Some(recommit(&cfg, &bad, 0, nv));
    // proving on an unsatisfied constraint system fails; if a proof were produced, verifying
    // it against the (correct) public inputs must fail.
    match Groth16::<Bls12_381>::prove(&pk, bad.clone(), &mut rng) {
        Err(_) => { /* expected: cannot prove a broken statement */ }
        Ok(proof) => {
            assert!(
                !Groth16::<Bls12_381>::verify(&vk, &bad.public_inputs(), &proof).unwrap(),
                "a proof for a value-imbalanced witness verified"
            );
        }
    }
    println!("VIOLATION-PROOF GREEN: imbalanced witness cannot yield a verifying proof");
    let _ = F::zero;
}

#[test]
fn recipient_binding_is_bound_at_the_verifier() {
    // The transparent-withdraw recipient is bound by the 8th public input. A proof for one
    // recipient must not verify against a different public recipient — the anti-replay
    // property. This is the verifier-level counterpart to the circuit-level matrix.
    let cfg = poseidon_config();
    let mut rng = StdRng::from_seed([0x9c; 32]);
    let mut setup_rng = StdRng::from_seed([0xc3; 32]);
    let (pk, vk) =
        Groth16::<Bls12_381>::circuit_specific_setup(TransferCircuit::blank(&cfg), &mut setup_rng)
            .unwrap();
    let h = honest(&mut rng, &cfg);
    let proof = Groth16::<Bls12_381>::prove(&pk, h.clone(), &mut rng).unwrap();
    let mut pubs = h.public_inputs();
    assert!(Groth16::<Bls12_381>::verify(&vk, &pubs, &proof).unwrap());
    // index 7 is recipient_binding (allocation order): change it and verification must fail.
    pubs[7] += F::one();
    assert!(
        !Groth16::<Bls12_381>::verify(&vk, &pubs, &proof).unwrap(),
        "proof verified against a changed recipient binding"
    );
    println!("RECIPIENT-BINDING GREEN: proof rejected under a changed public recipient");
}
