//! B1a: regenerate the transfer/deposit proving+verifying keys in-process from the deterministic
//! setup (seed 20260712) and assert their SHA-256 against `SETUP-MANIFEST.json` before anything
//! else runs. The harness proves against exactly these keys, so byte-identity with the pinned
//! verifying keys the canister is configured with is load-bearing, not decorative: if the
//! reproduction were wrong, every proof would be rejected. The SHA-256 gate makes a wrong
//! reproduction fail loudly here instead of silently downstream.
//!
//! The RNG-consumption prefix mirrors `circuit/gen/src/main.rs` exactly: 8 note-secret field
//! draws, the transfer setup, then the 13 field draws gen makes between the two setups (three
//! Groth16 proofs at 2 scalars each = 6, plus 7 note-`rcm`/`rho` draws), then the deposit setup.
//! Any drift is caught by the manifest SHA comparison.

use ark_bls12_381::{Bls12_381, Fr as F};
use ark_ff::UniformRand;
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;
use common::{poseidon_config, DepositCircuit, TransferCircuit};
use sha2::{Digest, Sha256};

const INSECURE_TEST_SEED: u64 = 20260712;
const NOTE_DRAWS_BEFORE_TRANSFER_SETUP: usize = 8;
const DRAWS_BETWEEN_SETUPS: usize = 13;

#[derive(Clone)]
pub struct Keyset {
    pub transfer_pk: ProvingKey<Bls12_381>,
    pub transfer_vk: VerifyingKey<Bls12_381>,
    pub deposit_pk: ProvingKey<Bls12_381>,
    pub deposit_vk: VerifyingKey<Bls12_381>,
    pub transfer_vk_hex: String,
    pub deposit_vk_hex: String,
    /// Which transfer statement these keys belong to (`true` = the pre-hardening statement of
    /// `fixtures/pool-vectors-bls12-381`; `false` = the hardened conservation statement). Every
    /// proof the harness builds must construct its circuit with the SAME statement or proving
    /// fails against these keys.
    pub legacy_statement: bool,
}

#[derive(serde::Deserialize)]
struct Manifest {
    setup_mode: String,
    transfer_pk_sha256: String,
    transfer_vk_sha256: String,
    deposit_pk_sha256: String,
    deposit_vk_sha256: String,
}

fn compressed_hex<T: CanonicalSerialize>(x: &T) -> String {
    let mut b = Vec::new();
    x.serialize_compressed(&mut b).unwrap();
    hex::encode(b)
}

fn uncompressed_sha256<T: CanonicalSerialize>(x: &T) -> String {
    let mut b = Vec::new();
    x.serialize_uncompressed(&mut b).unwrap();
    hex::encode(Sha256::digest(&b))
}

/// SHA-256 of the .hex FILE content gen writes for a vk (ASCII hex of the compressed vk, no
/// newline) — the exact bytes `SETUP-MANIFEST.json` hashed.
fn vk_hex_file_sha256(vk_hex: &str) -> String {
    hex::encode(Sha256::digest(vk_hex.as_bytes()))
}

/// Regenerate the keyset and gate it against the manifest. Returns the keyset on success; errors
/// (aborting the whole run) if the setup mode is not the deterministic test mode or any SHA
/// mismatches. `legacy_statement` selects which transfer statement to set up — it must match the
/// manifest the caller passes (each statement has its own fixture manifest).
pub fn regenerate_and_verify(manifest_json: &str, legacy_statement: bool) -> Result<Keyset, String> {
    let manifest: Manifest =
        serde_json::from_str(manifest_json).map_err(|e| format!("manifest parse: {e}"))?;
    if manifest.setup_mode != "insecure-deterministic-test" {
        return Err(format!("unexpected setup mode {}", manifest.setup_mode));
    }

    let cfg = poseidon_config();
    let mut rng = StdRng::seed_from_u64(INSECURE_TEST_SEED);

    for _ in 0..NOTE_DRAWS_BEFORE_TRANSFER_SETUP {
        let _ = F::rand(&mut rng);
    }
    let transfer_blank = if legacy_statement {
        TransferCircuit::blank_legacy(&cfg)
    } else {
        TransferCircuit::blank(&cfg)
    };
    let (transfer_pk, transfer_vk) =
        Groth16::<Bls12_381>::circuit_specific_setup(transfer_blank, &mut rng)
            .map_err(|e| format!("transfer setup: {e}"))?;

    for _ in 0..DRAWS_BETWEEN_SETUPS {
        let _ = F::rand(&mut rng);
    }
    let (deposit_pk, deposit_vk) =
        Groth16::<Bls12_381>::circuit_specific_setup(DepositCircuit::blank(&cfg), &mut rng)
            .map_err(|e| format!("deposit setup: {e}"))?;

    let transfer_vk_hex = compressed_hex(&transfer_vk);
    let deposit_vk_hex = compressed_hex(&deposit_vk);

    let checks = [
        ("transfer_pk", uncompressed_sha256(&transfer_pk), manifest.transfer_pk_sha256.clone()),
        ("transfer_vk", vk_hex_file_sha256(&transfer_vk_hex), manifest.transfer_vk_sha256.clone()),
        ("deposit_pk", uncompressed_sha256(&deposit_pk), manifest.deposit_pk_sha256.clone()),
        ("deposit_vk", vk_hex_file_sha256(&deposit_vk_hex), manifest.deposit_vk_sha256.clone()),
    ];
    for (name, got, want) in &checks {
        if got != want {
            return Err(format!(
                "B1a keyset SHA-256 mismatch for {name}: regenerated {got} != manifest {want}"
            ));
        }
    }

    Ok(Keyset {
        transfer_pk,
        transfer_vk,
        deposit_pk,
        deposit_vk,
        transfer_vk_hex,
        deposit_vk_hex,
        legacy_statement,
    })
}

/// B1 proof 2: the frozen fixture proofs from `fixtures/pool-vectors-bls12-381/` must verify
/// under the REGENERATED verifying keys (and the frozen bad proof must not), proving the
/// regenerated setup is the same setup the fixtures were produced from — not merely one with
/// matching hashes on disk.
pub fn verify_frozen_fixtures(fixture_dir: &std::path::Path, keys: &Keyset) -> Result<(), String> {
    use ark_groth16::Proof;
    use ark_serialize::CanonicalDeserialize;

    let read = |name: &str| -> Result<String, String> {
        std::fs::read_to_string(fixture_dir.join(name))
            .map(|s| s.trim().to_string())
            .map_err(|e| format!("read {name}: {e}"))
    };
    let field = |name: &str| -> Result<F, String> {
        common::f_from_hex(&read(name)?).ok_or_else(|| format!("{name}: bad field hex"))
    };
    let proof = |name: &str| -> Result<Proof<Bls12_381>, String> {
        let bytes = hex::decode(read(name)?).map_err(|e| format!("{name}: {e}"))?;
        Proof::deserialize_compressed(&bytes[..]).map_err(|e| format!("{name}: {e}"))
    };

    // frozen deposit proof 1
    let deposit_publics = vec![
        field("deposit1_cm.hex")?,
        F::from(read("deposit1_v.txt")?.parse::<u64>().map_err(|e| e.to_string())?),
    ];
    if !Groth16::<Bls12_381>::verify(&keys.deposit_vk, &deposit_publics, &proof("deposit1_proof.hex")?)
        .map_err(|e| e.to_string())?
    {
        return Err("frozen deposit1 proof rejected by regenerated deposit vk".into());
    }

    // frozen transfer proof with its full 8-input statement
    let transfer_publics = vec![
        field("anchor.hex")?,
        field("nf1.hex")?,
        field("nf2.hex")?,
        field("cm_out1.hex")?,
        field("cm_out2.hex")?,
        F::from(read("fee.txt")?.parse::<u64>().map_err(|e| e.to_string())?),
        F::from(read("v_pub_out.txt")?.parse::<u64>().map_err(|e| e.to_string())?),
        field("recipient_binding.hex")?,
    ];
    if !Groth16::<Bls12_381>::verify(&keys.transfer_vk, &transfer_publics, &proof("transfer_proof.hex")?)
        .map_err(|e| e.to_string())?
    {
        return Err("frozen transfer proof rejected by regenerated transfer vk".into());
    }

    // the frozen single-bit-flipped proof must NOT verify (the check has teeth)
    let bad = hex::decode(read("transfer_badproof.hex")?).map_err(|e| e.to_string())?;
    let bad_accepted = match Proof::<Bls12_381>::deserialize_compressed(&bad[..]) {
        Ok(p) => Groth16::<Bls12_381>::verify(&keys.transfer_vk, &transfer_publics, &p)
            .map_err(|e| e.to_string())?,
        Err(_) => false, // rejected at deserialization: also a rejection
    };
    if bad_accepted {
        return Err("frozen tampered proof unexpectedly ACCEPTED".into());
    }
    Ok(())
}
