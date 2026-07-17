//! Phase-2 trusted-setup MMORPG ceremony core (Bowe-Gabizon-Miers 2017) for the shielded-ledger
//! Groth16 circuits over BLS12-381.
//!
//! Modules:
//!   - `srs`        : the inherited/universal Phase-1 powers of tau (circuit-independent).
//!   - `params`     : deriving the initial Phase-2 parameters from the SRS + a circuit (FFT in
//!                    the exponent), and the parameter type each contribution transforms.
//!   - `contribute` : one apply-and-destroy contribution (sample secret, transform, prove, wipe).
//!   - `verify`     : single-contribution proof-of-knowledge check (the cheap on-chain check) plus
//!                    the full delta-division-consistency check (the heavy off-chain check),
//!                    transcript chaining, and beacon finalize.
//!   - `transcript` : the public transcript types and their canonical serialization.
//!
//! The coordinator canister (Motoko) re-implements ONLY the cheap on-chain check independently;
//! the standalone verifier binary uses `verify` for the full check. Nothing here ever holds a
//! participant secret beyond the single stack frame that samples, applies, and drops it.

pub mod contribute;
pub mod params;
pub mod phase1_import;
pub mod session;
pub mod srs;
pub mod transcript;
pub mod verify;

#[cfg(test)]
mod session_tests {
    //! Build a full two-circuit transcript with the local simulator, then verify it end to end with
    //! the standalone verifier core, and confirm a tampered transcript is rejected.
    use super::session::*;
    use super::srs::*;
    use rand::SeedableRng;

    #[test]
    fn simulated_transcript_verifies_end_to_end() {
        let mut r = rand_chacha::ChaCha20Rng::seed_from_u64(2026);
        // Power 15 covers BOTH circuits (transfer QAP 2^15; deposit 2^10 is a sub-domain).
        let srs = Phase1Srs::generate_test_tier(15, &mut r);
        let init = CeremonyInit::from_srs(&srs).unwrap();
        let mut t = init.empty_transcript();
        simulate_contribution(&init, &mut t, vec![0xa1], 1, &mut r).unwrap();
        simulate_contribution(&init, &mut t, vec![0xb2], 2, &mut r).unwrap();
        finalize_with_beacon(&init, &mut t, b"drand round 5000000".to_vec(), &mut r).unwrap();

        let (final_keys, report) = verify_full_transcript(&srs, &t).expect("transcript must verify");
        assert_eq!(report.honest_contributions, 2);
        assert!(report.finalized);
        selfcheck_keys_work(&final_keys).expect("final keys must prove+verify real proofs");

        // Tamper: flip the finalized flag off -> mismatch with beacon presence.
        let mut bad = t.clone();
        bad.finalized = false;
        assert!(verify_full_transcript(&srs, &bad).is_err());

        // Tamper: drop the beacon's last H point correctness by corrupting a transfer H point.
        let mut bad2 = t.clone();
        let last = bad2.contributions.len() - 1;
        let corrupted: ark_bls12_381::G1Affine =
            (ark_bls12_381::G1Projective::from(bad2.contributions[last].transfer.delta.h_query[0])
                + <ark_bls12_381::G1Projective as ark_ec::PrimeGroup>::generator())
            .into();
        bad2.contributions[last].transfer.delta.h_query[0] = corrupted;
        assert!(verify_full_transcript(&srs, &bad2).is_err());
    }
}

#[cfg(test)]
mod ceremony_tests {
    //! A full multi-contributor Phase-2 ceremony on the deposit circuit (fast, 2^10): three honest
    //! contributions plus a beacon finalize, then the resulting keys prove+verify a real deposit,
    //! and each step passes both verification tiers. Tampering is rejected.
    use super::contribute::*;
    use super::params::*;
    use super::srs::*;
    use super::transcript::*;
    use super::verify::*;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_ec::PrimeGroup;
    use ark_ff::UniformRand;
    use ark_groth16::Groth16;
    use ark_snark::SNARK;
    use common::*;
    use rand::SeedableRng;

    #[test]
    fn full_deposit_ceremony_verifies_and_keys_work() {
        let cfg = poseidon_config();
        let mut r = rand_chacha::ChaCha20Rng::seed_from_u64(100);
        let srs = Phase1Srs::generate_test_tier(10, &mut r);
        let pk0 = derive_initial_params(&srs, DepositCircuit::blank(&cfg)).unwrap();
        let (fixed, initial) = split_pk(&pk0);
        let h_len = initial.h_query.len();
        let l_len = initial.l_query.len();

        let genesis =
            genesis_challenge(10, srs.sha256_hex().as_bytes(), &fixed, &fixed, &initial, &initial);

        // Drive 3 honest contributions, replaying verification exactly as the verifier will.
        let mut challenge = genesis;
        let mut cur = initial.clone();
        for _ in 0..3 {
            let d = sample_secret(&mut r);
            let (next, pok) = contribute(&challenge, &cur, d, &mut r).unwrap();
            validate_delta_shape(&next, h_len, l_len).unwrap();
            verify_pok(&challenge, &cur.delta_g1, &next, &pok).expect("pok must verify");
            verify_division(&cur, &next).expect("division must verify");
            let contribution = Contribution {
                contributor: vec![1, 2, 3],
                timestamp: 0,
                transfer: CircuitContribution { delta: next.clone(), pok: pok.clone() },
                deposit: CircuitContribution { delta: next.clone(), pok: pok.clone() },
                is_beacon: false,
                beacon: vec![],
            };
            challenge = advance_challenge(&challenge, &contribution);
            cur = next;
        }

        // Beacon finalize.
        let beacon = b"bitcoin block 900000 hash deadbeef";
        let d = beacon_secret(beacon);
        let (final_params, pok) = contribute(&challenge, &cur, d, &mut r).unwrap();
        verify_beacon_step(&challenge, &cur, &final_params, &pok, beacon).expect("beacon verifies");

        // The final keys must prove+verify a real deposit.
        let pk_final = join_pk(&fixed, &final_params);
        let n = Note { v: 999, nk: Fr::rand(&mut r), rho: Fr::rand(&mut r), rcm: Fr::rand(&mut r) };
        let c = DepositCircuit {
            cfg: cfg.clone(),
            cm: Some(n.cm(&cfg)),
            v_pub: Some(n.v),
            pk: Some(n.pk(&cfg)),
            rho: Some(n.rho),
            rcm: Some(n.rcm),
        };
        let publics = c.public_inputs();
        let proof = Groth16::<Bls12_381>::prove(&pk_final, c, &mut r).unwrap();
        assert!(
            Groth16::<Bls12_381>::verify(&pk_final.vk, &publics, &proof).unwrap(),
            "final ceremony keys must verify a real proof"
        );
        // vk shape: gamma_abc length == num public inputs + 1 (deposit: cm, v_pub, +1 = 3).
        assert_eq!(pk_final.vk.gamma_abc_g1.len(), 3);
    }

    #[test]
    fn tampered_contribution_is_rejected() {
        let cfg = poseidon_config();
        let mut r = rand_chacha::ChaCha20Rng::seed_from_u64(200);
        let srs = Phase1Srs::generate_test_tier(10, &mut r);
        let pk0 = derive_initial_params(&srs, DepositCircuit::blank(&cfg)).unwrap();
        let (fixed, initial) = split_pk(&pk0);
        let genesis =
            genesis_challenge(10, srs.sha256_hex().as_bytes(), &fixed, &fixed, &initial, &initial);

        let d = sample_secret(&mut r);
        let (good, pok) = contribute(&genesis, &initial, d, &mut r).unwrap();

        // (a) forged PoK against a different challenge -> PoK check fails.
        let wrong_challenge = [9u8; 32];
        assert!(verify_pok(&wrong_challenge, &initial.delta_g1, &good, &pok).is_err());

        // (b) corrupt a single H-query point -> division check fails but PoK still passes
        //     (exactly the on-chain/off-chain split: soundness ok, correctness caught off-chain).
        let mut bad = good.clone();
        bad.h_query[5] = (ark_bls12_381::G1Projective::from(bad.h_query[5])
            + ark_bls12_381::G1Projective::generator())
        .into();
        verify_pok(&genesis, &initial.delta_g1, &bad, &pok).expect("PoK unaffected by H tamper");
        assert!(verify_division(&initial, &bad).is_err(), "division must catch H tamper");

        // (c) identity contribution (delta unchanged) is rejected.
        assert!(verify_pok(&genesis, &initial.delta_g1, &initial, &pok).is_err());
    }
}

#[cfg(test)]
mod params_tests {
    use super::params::*;
    use super::srs::*;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_ff::UniformRand;
    use ark_groth16::{Groth16, ProvingKey};
    use ark_snark::SNARK;
    use common::*;
    use rand::SeedableRng;

    fn assert_pk_eq(mine: &ProvingKey<Bls12_381>, oracle: &ProvingKey<Bls12_381>) {
        assert_eq!(mine.vk.alpha_g1, oracle.vk.alpha_g1, "alpha_g1");
        assert_eq!(mine.vk.beta_g2, oracle.vk.beta_g2, "beta_g2");
        assert_eq!(mine.vk.gamma_g2, oracle.vk.gamma_g2, "gamma_g2");
        assert_eq!(mine.vk.delta_g2, oracle.vk.delta_g2, "delta_g2");
        assert_eq!(mine.vk.gamma_abc_g1, oracle.vk.gamma_abc_g1, "gamma_abc_g1");
        assert_eq!(mine.beta_g1, oracle.beta_g1, "beta_g1");
        assert_eq!(mine.delta_g1, oracle.delta_g1, "delta_g1");
        assert_eq!(mine.a_query, oracle.a_query, "a_query");
        assert_eq!(mine.b_g1_query, oracle.b_g1_query, "b_g1_query");
        assert_eq!(mine.b_g2_query, oracle.b_g2_query, "b_g2_query");
        assert_eq!(mine.h_query, oracle.h_query, "h_query");
        assert_eq!(mine.l_query, oracle.l_query, "l_query");
    }

    // Deposit circuit (QAP domain 2^10): cross-check the FFT-in-exponent derivation against the
    // arkworks QAP oracle at a known tau, then prove+verify a real witness with the derived keys.
    #[test]
    fn deposit_initial_params_match_oracle_and_prove() {
        let cfg = poseidon_config();
        let mut r = rand_chacha::ChaCha20Rng::seed_from_u64(42);
        let tau = Fr::rand(&mut r);
        let alpha = Fr::rand(&mut r);
        let beta = Fr::rand(&mut r);
        let srs = Phase1Srs::from_secret(10, tau, alpha, beta, SrsProvenance::TestTierKnownSecret, 1024);
        srs.structure_check(&(0..srs.tau_g1.len()).collect::<Vec<_>>()).unwrap();

        let mine = derive_initial_params(&srs, DepositCircuit::blank(&cfg)).unwrap();
        let oracle = initial_params_field_oracle(DepositCircuit::blank(&cfg), tau, alpha, beta);
        assert_pk_eq(&mine, &oracle);

        // Functional: a real deposit proof verifies under the derived (delta=1) keys.
        let n = Note { v: 123, nk: Fr::rand(&mut r), rho: Fr::rand(&mut r), rcm: Fr::rand(&mut r) };
        let c = DepositCircuit {
            cfg: cfg.clone(),
            cm: Some(n.cm(&cfg)),
            v_pub: Some(n.v),
            pk: Some(n.pk(&cfg)),
            rho: Some(n.rho),
            rcm: Some(n.rcm),
        };
        let publics = c.public_inputs();
        let proof = Groth16::<Bls12_381>::prove(&mine, c, &mut r).unwrap();
        assert!(Groth16::<Bls12_381>::verify(&mine.vk, &publics, &proof).unwrap());
    }

    // Transfer circuit (QAP domain 2^15): the real, load-bearing circuit. Oracle cross-check + a
    // real 2-in/2-out transfer proof under the derived keys.
    #[test]
    fn transfer_initial_params_match_oracle_and_prove() {
        let cfg = poseidon_config();
        let mut r = rand_chacha::ChaCha20Rng::seed_from_u64(7);
        let tau = Fr::rand(&mut r);
        let alpha = Fr::rand(&mut r);
        let beta = Fr::rand(&mut r);
        let srs = Phase1Srs::from_secret(15, tau, alpha, beta, SrsProvenance::TestTierKnownSecret, 32768);

        let mine = derive_initial_params(&srs, TransferCircuit::blank(&cfg)).unwrap();
        let oracle = initial_params_field_oracle(TransferCircuit::blank(&cfg), tau, alpha, beta);
        assert_pk_eq(&mine, &oracle);

        // Real transfer witness (Alice 70+30 -> Bob 55, change 40, fee 5).
        let alice_nk = Fr::rand(&mut r);
        let bob_nk = Fr::rand(&mut r);
        let bob_pk = derive_pk(&cfg, bob_nk);
        let alice_pk = derive_pk(&cfg, alice_nk);
        let n1 = Note { v: 70, nk: alice_nk, rho: Fr::rand(&mut r), rcm: Fr::rand(&mut r) };
        let n2 = Note { v: 30, nk: alice_nk, rho: Fr::rand(&mut r), rcm: Fr::rand(&mut r) };
        let dense = DenseTree { leaves: vec![n1.cm(&cfg), n2.cm(&cfg)] };
        let anchor = dense.root(&cfg);
        let (sib1, bits1) = dense.path(&cfg, 0);
        let (sib2, bits2) = dense.path(&cfg, 1);
        let nf1 = n1.nf(&cfg);
        let nf2 = n2.nf(&cfg);
        let out1 = Note { v: 55, nk: bob_nk, rho: nf1, rcm: Fr::rand(&mut r) };
        let out2 = Note { v: 40, nk: alice_nk, rho: nf2, rcm: Fr::rand(&mut r) };
        let c = TransferCircuit {
            cfg: cfg.clone(),
            enforce_range: true,
            anchor: Some(anchor),
            nf: [Some(nf1), Some(nf2)],
            cm_out: [Some(out1.cm(&cfg)), Some(out2.cm(&cfg))],
            fee: Some(5),
            v_pub_out: Some(0),
            recipient_binding: Some(Fr::from(0u64)),
            in_v: [Some(n1.v), Some(n2.v)],
            in_nk: [Some(n1.nk), Some(n2.nk)],
            in_rho: [Some(n1.rho), Some(n2.rho)],
            in_rcm: [Some(n1.rcm), Some(n2.rcm)],
            in_siblings: [sib1, sib2],
            in_bits: [bits1, bits2],
            out_v: [Some(Fr::from(out1.v)), Some(Fr::from(out2.v))],
            out_pk: [Some(bob_pk), Some(alice_pk)],
            out_rcm: [Some(out1.rcm), Some(out2.rcm)],
        };
        let publics = c.public_inputs();
        let proof = Groth16::<Bls12_381>::prove(&mine, c, &mut r).unwrap();
        assert!(Groth16::<Bls12_381>::verify(&mine.vk, &publics, &proof).unwrap());
    }
}

#[cfg(test)]
mod srs_tests {
    use super::srs::*;
    use rand::SeedableRng;

    #[test]
    fn test_tier_srs_passes_structure_check() {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(1);
        let srs = Phase1Srs::generate_test_tier(8, &mut rng); // n = 256, fast
        // full check across every index
        let all: Vec<usize> = (0..srs.tau_g1.len()).collect();
        srs.structure_check(&all).expect("well-formed SRS must pass structure_check");
    }

    #[test]
    fn tampered_srs_is_rejected() {
        use ark_ec::PrimeGroup;
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(2);
        let mut srs = Phase1Srs::generate_test_tier(8, &mut rng);
        // Corrupt one interior power: the chain must break.
        srs.tau_g1[100] = (ark_bls12_381::G1Projective::generator()
            * ark_bls12_381::Fr::from(999u64))
        .into();
        let all: Vec<usize> = (0..srs.tau_g1.len()).collect();
        assert!(srs.structure_check(&all).is_err(), "tampered SRS must be rejected");
    }
}
