//! A2 / B5 "counterfeit-mint": the named Zcash-2018 counterfeiting regression guard.
//!
//! The bug class: a withdrawal whose claimed public value exceeds the true committed note value
//! (value inflation). The pool has two INDEPENDENT defenses, and this module proves both fire:
//!
//! Proof 1 (native, this module): the transfer circuit is UNSATISFIABLE for a counterfeit
//! witness — both the plain imbalance and the field-wrap variant (conservation holding only
//! modulo p) admit no proof, and the field-wrap variant is shown to SATISFY the range-check-free
//! circuit variant, demonstrating the range constraint is the load-bearing defense rather than
//! decoration.
//!
//! Proof 2 (live, in the runner): even if a counterfeit proof hypothetically existed, the
//! `poolDebit > pool_value` turnstile in `src/Main.mo` (confidential_transfer guard) rejects any
//! payout beyond what was ever shielded in, before verification is even consulted — asserted
//! against the running canister with verifier_outcome NOT_CALLED.
//!
//! Honesty boundary: this guards the known bug class; it does not prove circuit soundness
//! against a novel parameter flaw. That rests on the trusted-setup policy and circuit review.

use ark_bls12_381::Fr as F;
use ark_ff::UniformRand;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_std::rand::SeedableRng;
use common::{poseidon_config, DenseTree, Note, TransferCircuit};

pub struct MintGuardReport {
    pub imbalance_unsatisfiable: bool,
    pub wrap_unsatisfiable_with_range: bool,
    pub wrap_satisfiable_without_range: bool,
}

/// Build the honest 2-note tree and a counterfeit withdrawal witness, then check
/// satisfiability of the three variants.
pub fn native_counterfeit_check() -> MintGuardReport {
    let cfg = poseidon_config();
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(20260717);
    let nk = F::rand(&mut rng);
    let pk = common::derive_pk(&cfg, nk);

    let n1 = Note { v: 70, nk, rho: F::rand(&mut rng), rcm: F::rand(&mut rng) };
    let n2 = Note { v: 30, nk, rho: F::rand(&mut rng), rcm: F::rand(&mut rng) };
    let tree = DenseTree { leaves: vec![n1.cm(&cfg), n2.cm(&cfg)] };
    let anchor = tree.root(&cfg);
    let (sib1, bits1) = tree.path(&cfg, 0);
    let (sib2, bits2) = tree.path(&cfg, 1);
    let nf1 = n1.nf(&cfg);
    let nf2 = n2.nf(&cfg);

    let base = |out_v: [F; 2], v_pub_out: u64, cm_out: [F; 2]| TransferCircuit {
        cfg: cfg.clone(),
        enforce_range: true,
        anchor: Some(anchor),
        nf: [Some(nf1), Some(nf2)],
        cm_out: [Some(cm_out[0]), Some(cm_out[1])],
        fee: Some(0),
        v_pub_out: Some(v_pub_out),
        recipient_binding: Some(F::from(0u64)),
        in_v: [Some(n1.v), Some(n2.v)],
        in_nk: [Some(nk), Some(nk)],
        in_rho: [Some(n1.rho), Some(n2.rho)],
        in_rcm: [Some(n1.rcm), Some(n2.rcm)],
        in_siblings: [sib1.clone(), sib2.clone()],
        in_bits: [bits1.clone(), bits2.clone()],
        out_v: [Some(out_v[0]), Some(out_v[1])],
        out_pk: [Some(pk), Some(pk)],
        out_rcm: [Some(F::rand(&mut rng.clone())), Some(F::rand(&mut rng.clone()))],
    };

    // Variant 1: plain imbalance. Inputs are worth 100; claim v_pub_out = 1_000_000 with zero
    // outputs. Conservation over Z cannot hold; the witness must not satisfy the circuit.
    let imbalance_unsatisfiable = {
        let mut rng2 = ark_std::rand::rngs::StdRng::seed_from_u64(1);
        let rcm1 = F::rand(&mut rng2);
        let rcm2 = F::rand(&mut rng2);
        let cm1 = common::note_commitment(&cfg, 0, pk, nf1, rcm1);
        let cm2 = common::note_commitment(&cfg, 0, pk, nf2, rcm2);
        let mut c = base([F::from(0u64), F::from(0u64)], 1_000_000, [cm1, cm2]);
        c.out_rcm = [Some(rcm1), Some(rcm2)];
        let cs = ConstraintSystem::<F>::new_ref();
        c.generate_constraints(cs.clone()).unwrap();
        !cs.is_satisfied().unwrap()
    };

    // Variant 2: the field-wrap mint. Choose out1 = -1_000_000 (mod p) and v_pub_out =
    // 1_000_100 so conservation holds as a FIELD equation: 100 = (-1e6) + 0 + 0 + 1_000_100
    // (mod p). Without the range check this satisfies the constraint system (the Zcash-class
    // vulnerability shape); with the range check it must not.
    let neg_million = -F::from(1_000_000u64);
    let mut rng3 = ark_std::rand::rngs::StdRng::seed_from_u64(2);
    let rcm1 = F::rand(&mut rng3);
    let rcm2 = F::rand(&mut rng3);
    let cm1 = {
        // commitment over the raw field value (the attacker controls the opening)
        common::hash_n(&cfg, &[F::from(3u64), neg_million, pk, nf1, rcm1])
    };
    let cm2 = common::note_commitment(&cfg, 0, pk, nf2, rcm2);
    let make_wrap = |enforce_range: bool| {
        let mut c = base([neg_million, F::from(0u64)], 1_000_100, [cm1, cm2]);
        c.enforce_range = enforce_range;
        c.out_rcm = [Some(rcm1), Some(rcm2)];
        c
    };
    let wrap_unsatisfiable_with_range = {
        let cs = ConstraintSystem::<F>::new_ref();
        make_wrap(true).generate_constraints(cs.clone()).unwrap();
        !cs.is_satisfied().unwrap()
    };
    let wrap_satisfiable_without_range = {
        let cs = ConstraintSystem::<F>::new_ref();
        make_wrap(false).generate_constraints(cs.clone()).unwrap();
        cs.is_satisfied().unwrap()
    };

    MintGuardReport {
        imbalance_unsatisfiable,
        wrap_unsatisfiable_with_range,
        wrap_satisfiable_without_range,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counterfeit_mint_is_unprovable_and_range_check_is_load_bearing() {
        let r = native_counterfeit_check();
        assert!(r.imbalance_unsatisfiable, "imbalanced counterfeit satisfied the circuit");
        assert!(r.wrap_unsatisfiable_with_range, "field-wrap mint satisfied the real circuit");
        assert!(
            r.wrap_satisfiable_without_range,
            "field-wrap mint should satisfy the no-range variant (proves the range check is the defense)"
        );
    }
}
