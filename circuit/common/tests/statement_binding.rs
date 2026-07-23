//! Statement ↔ verifying-key binding proofs for the two transfer statements.
//!
//! The hardening changed the transfer statement (in-circuit fee/v_pub_out ranges + input-note
//! distinctness), so it changed the verifying key. This battery proves the binding both ways at
//! the Groth16 level:
//!
//!   1. Each statement's frozen fixture proof ACCEPTS under its own fixture verifying key
//!      (`fixtures/pool-vectors-bls12-381` = legacy, `fixtures/pool-vectors-bls12-381-hardened`
//!      = hardened) and REJECTS under the other statement's verifying key.
//!   2. Matched-publics cross-rejection: ONE honest witness (satisfiable under both statements)
//!      is proven under a legacy proving key and under a hardened proving key; each proof
//!      ACCEPTS under its own verifying key and REJECTS under the other — with byte-identical
//!      public inputs, so the rejection is attributable to the statement change alone.
//!
//! Consequence for deployment: a ledger configured with the hardened verifying key accepts NO
//! proof produced for the legacy statement (and vice versa) — rotating the key IS the cutover.
#![cfg(feature = "bls12-381")]

use ark_bls12_381::{Bls12_381, Fr as F};
use ark_ff::UniformRand;
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;
use ark_std::rand::rngs::StdRng;
use ark_std::rand::{RngCore, SeedableRng};
use common::{
    derive_pk, note_commitment, poseidon_config, DenseTree, Note, PoseidonCfg, TransferCircuit,
};
use std::path::PathBuf;

fn fixture_dir(hardened: bool) -> PathBuf {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf();
    root.join(if hardened {
        "fixtures/pool-vectors-bls12-381-hardened"
    } else {
        "fixtures/pool-vectors-bls12-381"
    })
}

fn read(dir: &PathBuf, name: &str) -> String {
    std::fs::read_to_string(dir.join(name))
        .unwrap_or_else(|e| panic!("read {}/{name}: {e}", dir.display()))
        .trim()
        .to_string()
}

fn read_vk(dir: &PathBuf) -> VerifyingKey<Bls12_381> {
    let bytes = hex_decode(&read(dir, "transfer_vk.hex"));
    VerifyingKey::deserialize_compressed(&bytes[..]).expect("vk deserialize")
}

fn read_proof(dir: &PathBuf, name: &str) -> Proof<Bls12_381> {
    let bytes = hex_decode(&read(dir, name));
    Proof::deserialize_compressed(&bytes[..]).expect("proof deserialize")
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn read_field(dir: &PathBuf, name: &str) -> F {
    common::f_from_hex(&read(dir, name)).expect("field hex")
}

fn fixture_transfer_publics(dir: &PathBuf) -> Vec<F> {
    vec![
        read_field(dir, "anchor.hex"),
        read_field(dir, "nf1.hex"),
        read_field(dir, "nf2.hex"),
        read_field(dir, "cm_out1.hex"),
        read_field(dir, "cm_out2.hex"),
        F::from(read(dir, "fee.txt").parse::<u64>().unwrap()),
        F::from(read(dir, "v_pub_out.txt").parse::<u64>().unwrap()),
        read_field(dir, "recipient_binding.hex"),
    ]
}

#[test]
fn fixture_proofs_bind_to_their_own_statement_vk() {
    let legacy_dir = fixture_dir(false);
    let hardened_dir = fixture_dir(true);
    let legacy_vk = read_vk(&legacy_dir);
    let hardened_vk = read_vk(&hardened_dir);
    assert_ne!(
        read(&legacy_dir, "transfer_vk.hex"),
        read(&hardened_dir, "transfer_vk.hex"),
        "the two statements must have distinct verifying keys"
    );

    let legacy_proof = read_proof(&legacy_dir, "transfer_proof.hex");
    let legacy_publics = fixture_transfer_publics(&legacy_dir);
    let hardened_proof = read_proof(&hardened_dir, "transfer_proof.hex");
    let hardened_publics = fixture_transfer_publics(&hardened_dir);

    // Own-key acceptance.
    assert!(
        Groth16::<Bls12_381>::verify(&legacy_vk, &legacy_publics, &legacy_proof).unwrap(),
        "legacy fixture proof must verify under the legacy vk"
    );
    assert!(
        Groth16::<Bls12_381>::verify(&hardened_vk, &hardened_publics, &hardened_proof).unwrap(),
        "hardened fixture proof must verify under the hardened vk"
    );

    // Cross-key rejection.
    assert!(
        !Groth16::<Bls12_381>::verify(&hardened_vk, &legacy_publics, &legacy_proof).unwrap(),
        "legacy fixture proof must REJECT under the hardened vk"
    );
    assert!(
        !Groth16::<Bls12_381>::verify(&legacy_vk, &hardened_publics, &hardened_proof).unwrap(),
        "hardened fixture proof must REJECT under the legacy vk"
    );
}

fn honest_witness(rng: &mut StdRng, cfg: &PoseidonCfg<F>, legacy_statement: bool) -> TransferCircuit {
    let owner_nk = F::rand(rng);
    let recipient_nk = F::rand(rng);
    let in_v = [60_000u64 + rng.next_u64() % 100_000, 30_000 + rng.next_u64() % 100_000];
    let inputs = [
        Note { v: in_v[0], nk: owner_nk, rho: F::rand(rng), rcm: F::rand(rng) },
        Note { v: in_v[1], nk: owner_nk, rho: F::rand(rng), rcm: F::rand(rng) },
    ];
    let leaves = vec![inputs[0].cm(cfg), inputs[1].cm(cfg)];
    let tree = DenseTree { leaves };
    let anchor = tree.root(cfg);
    let (sib0, bits0) = tree.path(cfg, 0);
    let (sib1, bits1) = tree.path(cfg, 1);
    let nf = [inputs[0].nf(cfg), inputs[1].nf(cfg)];
    let out_pk = [derive_pk(cfg, recipient_nk), derive_pk(cfg, owner_nk)];
    let out_rcm = [F::rand(rng), F::rand(rng)];
    let fee = 7u64;
    let total = in_v[0] + in_v[1] - fee;
    let out_v = [total / 3, total - total / 3];
    let cm_out = [
        note_commitment(cfg, out_v[0], out_pk[0], nf[0], out_rcm[0]),
        note_commitment(cfg, out_v[1], out_pk[1], nf[1], out_rcm[1]),
    ];
    TransferCircuit {
        cfg: cfg.clone(),
        enforce_range: true,
        legacy_statement,
        anchor: Some(anchor),
        nf: [Some(nf[0]), Some(nf[1])],
        cm_out: [Some(cm_out[0]), Some(cm_out[1])],
        fee: Some(fee),
        v_pub_out: Some(0),
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

#[test]
fn matched_publics_cross_statement_rejection() {
    let cfg = poseidon_config();
    // Dev setups for both statements (test-only seed; never deployment keys).
    let mut setup_rng = StdRng::from_seed([0xA3; 32]);
    let (legacy_pk, legacy_vk) = Groth16::<Bls12_381>::circuit_specific_setup(
        TransferCircuit::blank_legacy(&cfg),
        &mut setup_rng,
    )
    .unwrap();
    let (hardened_pk, hardened_vk) =
        Groth16::<Bls12_381>::circuit_specific_setup(TransferCircuit::blank(&cfg), &mut setup_rng)
            .unwrap();

    for seed in [0x51u8, 0x52] {
        // ONE honest witness; the identical assignment expressed under each statement.
        let mut rng = StdRng::from_seed([seed; 32]);
        let legacy_circuit = honest_witness(&mut rng, &cfg, true);
        let hardened_circuit =
            TransferCircuit { legacy_statement: false, ..legacy_circuit.clone() };
        let publics = legacy_circuit.public_inputs();
        assert_eq!(
            publics,
            hardened_circuit.public_inputs(),
            "matched-publics precondition: identical statement instance"
        );

        let mut prove_rng = StdRng::from_seed([seed ^ 0xFF; 32]);
        let legacy_proof =
            Groth16::<Bls12_381>::prove(&legacy_pk, legacy_circuit, &mut prove_rng).unwrap();
        let hardened_proof =
            Groth16::<Bls12_381>::prove(&hardened_pk, hardened_circuit, &mut prove_rng).unwrap();

        // Own-key acceptance...
        assert!(
            Groth16::<Bls12_381>::verify(&legacy_vk, &publics, &legacy_proof).unwrap(),
            "legacy proof under legacy vk (seed {seed})"
        );
        assert!(
            Groth16::<Bls12_381>::verify(&hardened_vk, &publics, &hardened_proof).unwrap(),
            "hardened proof under hardened vk (seed {seed})"
        );
        // ...and cross-key rejection on BYTE-IDENTICAL public inputs: the statement change
        // alone separates the keys.
        assert!(
            !Groth16::<Bls12_381>::verify(&hardened_vk, &publics, &legacy_proof).unwrap(),
            "legacy-statement proof must REJECT under the hardened vk (seed {seed})"
        );
        assert!(
            !Groth16::<Bls12_381>::verify(&legacy_vk, &publics, &hardened_proof).unwrap(),
            "hardened-statement proof must REJECT under the legacy vk (seed {seed})"
        );
    }
}
