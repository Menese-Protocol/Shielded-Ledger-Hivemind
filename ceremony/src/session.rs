//! Ceremony orchestration: initialize the two-circuit Phase-2 state from an SRS, drive a full run
//! (used by the local CLI simulator), and — the piece the standalone verifier is built on — replay
//! and verify a complete published transcript from scratch.
//!
//! The ceremony specializes exactly two circuits: the join-split transfer and the deposit. Their
//! definitions are compiled in from `common`, so a verifier re-derives the initial parameters
//! itself and never has to trust the transcript's claim of what circuits it specialized.

use crate::contribute::{contribute, sample_secret};
use crate::params::{derive_initial_params, join_pk, split_pk};
use crate::srs::Phase1Srs;
use crate::transcript::{
    advance_challenge, genesis_challenge, CircuitContribution, Contribution, DeltaParams,
    FixedParams, Transcript,
};
use crate::verify::{beacon_secret, validate_delta_shape, verify_beacon_step, verify_division, verify_pok};
use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::ProvingKey;
use common::{poseidon_config, DepositCircuit, TransferCircuit};
use rand::RngCore;

/// Everything derived once from the SRS: the fixed params of both circuits and the initial delta
/// params, plus the query lengths used to shape-check every incoming contribution.
pub struct CeremonyInit {
    pub power: u32,
    pub srs_sha256: Vec<u8>,
    pub transfer_fixed: FixedParams,
    pub deposit_fixed: FixedParams,
    pub transfer_initial: DeltaParams,
    pub deposit_initial: DeltaParams,
}

impl CeremonyInit {
    /// Derive the initial two-circuit Phase-2 state from an SRS.
    pub fn from_srs(srs: &Phase1Srs) -> Result<Self, String> {
        let cfg = poseidon_config();
        let t_pk = derive_initial_params(srs, TransferCircuit::blank(&cfg))?;
        let d_pk = derive_initial_params(srs, DepositCircuit::blank(&cfg))?;
        let (transfer_fixed, transfer_initial) = split_pk(&t_pk);
        let (deposit_fixed, deposit_initial) = split_pk(&d_pk);
        Ok(CeremonyInit {
            power: srs.power,
            srs_sha256: hex::decode(srs.sha256_hex()).unwrap(),
            transfer_fixed,
            deposit_fixed,
            transfer_initial,
            deposit_initial,
        })
    }

    pub fn genesis_challenge(&self) -> [u8; 32] {
        genesis_challenge(
            self.power,
            &self.srs_sha256,
            &self.transfer_fixed,
            &self.deposit_fixed,
            &self.transfer_initial,
            &self.deposit_initial,
        )
    }

    /// An empty (zero-contribution) transcript pinned to this initial state.
    pub fn empty_transcript(&self) -> Transcript {
        Transcript {
            power: self.power,
            srs_sha256: self.srs_sha256.clone(),
            transfer_fixed: self.transfer_fixed.clone(),
            deposit_fixed: self.deposit_fixed.clone(),
            transfer_initial: self.transfer_initial.clone(),
            deposit_initial: self.deposit_initial.clone(),
            contributions: vec![],
            finalized: false,
        }
    }
}

/// The current delta state of a transcript (the params the next contributor starts from).
pub fn current_deltas(t: &Transcript) -> (DeltaParams, DeltaParams) {
    match t.contributions.last() {
        None => (t.transfer_initial.clone(), t.deposit_initial.clone()),
        Some(c) => (c.transfer.delta.clone(), c.deposit.delta.clone()),
    }
}

/// The running challenge after replaying the transcript's contributions (no verification).
fn running_challenge(init_genesis: [u8; 32], contributions: &[Contribution]) -> [u8; 32] {
    let mut ch = init_genesis;
    for c in contributions {
        ch = advance_challenge(&ch, c);
    }
    ch
}

/// LOCAL SIMULATOR ONLY. Append one honest contribution (both circuits) sampling fresh secrets from
/// `rng`. In the real ceremony this happens in the contributor's browser, not here; this exists so
/// the CLI can produce a transcript for the battery without standing up the canister and 20 browsers.
pub fn simulate_contribution<R: RngCore>(
    init: &CeremonyInit,
    transcript: &mut Transcript,
    contributor: Vec<u8>,
    timestamp: u64,
    rng: &mut R,
) -> Result<(), String> {
    if transcript.finalized {
        return Err("ceremony already finalized".into());
    }
    let challenge = running_challenge(init.genesis_challenge(), &transcript.contributions);
    let (t_cur, d_cur) = current_deltas(transcript);
    let (t_next, t_pok) = contribute(&challenge, &t_cur, sample_secret(rng), rng)?;
    let (d_next, d_pok) = contribute(&challenge, &d_cur, sample_secret(rng), rng)?;
    transcript.contributions.push(Contribution {
        contributor,
        timestamp,
        transfer: CircuitContribution { delta: t_next, pok: t_pok },
        deposit: CircuitContribution { delta: d_next, pok: d_pok },
        is_beacon: false,
        beacon: vec![],
    });
    Ok(())
}

/// Apply the public beacon finalize step and freeze the transcript.
pub fn finalize_with_beacon<R: RngCore>(
    init: &CeremonyInit,
    transcript: &mut Transcript,
    beacon: Vec<u8>,
    rng: &mut R,
) -> Result<(), String> {
    if transcript.finalized {
        return Err("already finalized".into());
    }
    let challenge = running_challenge(init.genesis_challenge(), &transcript.contributions);
    let (t_cur, d_cur) = current_deltas(transcript);
    let d = beacon_secret(&beacon);
    let (t_next, t_pok) = contribute(&challenge, &t_cur, d, rng)?;
    let (d_next, d_pok) = contribute(&challenge, &d_cur, d, rng)?;
    transcript.contributions.push(Contribution {
        contributor: vec![],
        timestamp: 0,
        transfer: CircuitContribution { delta: t_next, pok: t_pok },
        deposit: CircuitContribution { delta: d_next, pok: d_pok },
        is_beacon: true,
        beacon,
    });
    transcript.finalized = true;
    Ok(())
}

/// The final proving keys reconstructed from a verified transcript.
pub struct FinalKeys {
    pub transfer_pk: ProvingKey<Bls12_381>,
    pub deposit_pk: ProvingKey<Bls12_381>,
}

/// A structured report of a full transcript verification.
pub struct VerifyReport {
    pub honest_contributions: usize,
    pub finalized: bool,
    pub transfer_vk_sha256: String,
    pub deposit_vk_sha256: String,
}

/// THE STANDALONE VERIFIER CORE (D4). Re-derive the initial params from the SRS and the compiled-in
/// circuits, confirm the transcript starts there, then replay every contribution through BOTH
/// verification tiers (PoK + division), the beacon finalize, and the fixed-params-never-change
/// invariant. Returns the reconstructed final keys and a report, or the first inconsistency.
///
/// Shares NO code with the coordinator canister's Motoko acceptance path: this is an independent
/// Rust implementation that additionally runs the full off-chain division check the canister omits.
pub fn verify_full_transcript(
    srs: &Phase1Srs,
    transcript: &Transcript,
) -> Result<(FinalKeys, VerifyReport), String> {
    // 1. The transcript must be pinned to THIS srs.
    let srs_hash = hex::decode(srs.sha256_hex()).unwrap();
    if srs_hash != transcript.srs_sha256 {
        return Err("transcript srs_sha256 does not match the provided SRS".into());
    }
    // 2. Re-derive the initial state and confirm the transcript starts exactly there.
    let init = CeremonyInit::from_srs(srs)?;
    if init.transfer_fixed != transcript.transfer_fixed
        || init.deposit_fixed != transcript.deposit_fixed
        || init.transfer_initial != transcript.transfer_initial
        || init.deposit_initial != transcript.deposit_initial
    {
        return Err("transcript initial parameters do not match the SRS-derived parameters".into());
    }

    let t_h = init.transfer_initial.h_query.len();
    let t_l = init.transfer_initial.l_query.len();
    let d_h = init.deposit_initial.h_query.len();
    let d_l = init.deposit_initial.l_query.len();

    // 3. Replay.
    let mut challenge = init.genesis_challenge();
    let mut t_cur = init.transfer_initial.clone();
    let mut d_cur = init.deposit_initial.clone();
    let mut beacon_seen = false;
    let mut honest = 0usize;

    for (i, c) in transcript.contributions.iter().enumerate() {
        if beacon_seen {
            return Err(format!("contribution {i} follows the beacon finalize step"));
        }
        validate_delta_shape(&c.transfer.delta, t_h, t_l)
            .map_err(|e| format!("contribution {i} transfer shape: {e}"))?;
        validate_delta_shape(&c.deposit.delta, d_h, d_l)
            .map_err(|e| format!("contribution {i} deposit shape: {e}"))?;

        if c.is_beacon {
            verify_beacon_step(&challenge, &t_cur, &c.transfer.delta, &c.transfer.pok, &c.beacon)
                .map_err(|e| format!("contribution {i} transfer beacon: {e}"))?;
            verify_beacon_step(&challenge, &d_cur, &c.deposit.delta, &c.deposit.pok, &c.beacon)
                .map_err(|e| format!("contribution {i} deposit beacon: {e}"))?;
            beacon_seen = true;
        } else {
            verify_pok(&challenge, &t_cur.delta_g1, &c.transfer.delta, &c.transfer.pok)
                .map_err(|e| format!("contribution {i} transfer PoK: {e}"))?;
            verify_division(&t_cur, &c.transfer.delta)
                .map_err(|e| format!("contribution {i} transfer division: {e}"))?;
            verify_pok(&challenge, &d_cur.delta_g1, &c.deposit.delta, &c.deposit.pok)
                .map_err(|e| format!("contribution {i} deposit PoK: {e}"))?;
            verify_division(&d_cur, &c.deposit.delta)
                .map_err(|e| format!("contribution {i} deposit division: {e}"))?;
            honest += 1;
        }
        challenge = advance_challenge(&challenge, c);
        t_cur = c.transfer.delta.clone();
        d_cur = c.deposit.delta.clone();
    }

    if transcript.finalized != beacon_seen {
        return Err("finalized flag disagrees with the presence of a beacon step".into());
    }

    let transfer_pk = join_pk(&init.transfer_fixed, &t_cur);
    let deposit_pk = join_pk(&init.deposit_fixed, &d_cur);

    // vk shape sanity: gamma_abc length = public inputs + 1.
    if transfer_pk.vk.gamma_abc_g1.len() != init.transfer_fixed.num_instance as usize
        || deposit_pk.vk.gamma_abc_g1.len() != init.deposit_fixed.num_instance as usize
    {
        return Err("final vk gamma_abc length mismatch".into());
    }

    let report = VerifyReport {
        honest_contributions: honest,
        finalized: transcript.finalized,
        transfer_vk_sha256: vk_sha256(&transfer_pk),
        deposit_vk_sha256: vk_sha256(&deposit_pk),
    };
    Ok((FinalKeys { transfer_pk, deposit_pk }, report))
}

/// SHA-256 of a verifying key's compressed serialization (the ledger's key identity).
pub fn vk_sha256(pk: &ProvingKey<Bls12_381>) -> String {
    use ark_serialize::CanonicalSerialize;
    use sha2::{Digest, Sha256};
    let mut b = Vec::new();
    pk.vk.serialize_compressed(&mut b).unwrap();
    hex::encode(Sha256::digest(&b))
}

/// Prove+verify a real witness against final keys, the ultimate "the keys work" check.
pub fn selfcheck_keys_work(final_keys: &FinalKeys) -> Result<(), String> {
    use ark_ff::UniformRand;
    use ark_snark::SNARK;
    use common::{derive_pk, DenseTree, Note};
    let cfg = poseidon_config();
    let mut r = rand::rngs::OsRng;

    // deposit
    let n = Note { v: 42, nk: Fr::rand(&mut r), rho: Fr::rand(&mut r), rcm: Fr::rand(&mut r) };
    let dc = DepositCircuit {
        cfg: cfg.clone(),
        cm: Some(n.cm(&cfg)),
        v_pub: Some(n.v),
        pk: Some(n.pk(&cfg)),
        rho: Some(n.rho),
        rcm: Some(n.rcm),
    };
    let dp = dc.public_inputs();
    let dproof = ark_groth16::Groth16::<Bls12_381>::prove(&final_keys.deposit_pk, dc, &mut r)
        .map_err(|_| "deposit prove failed")?;
    if !ark_groth16::Groth16::<Bls12_381>::verify(&final_keys.deposit_pk.vk, &dp, &dproof)
        .map_err(|_| "deposit verify errored")?
    {
        return Err("deposit proof did not verify under final keys".into());
    }

    // transfer
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
    let tc = TransferCircuit {
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
    let tp = tc.public_inputs();
    let tproof = ark_groth16::Groth16::<Bls12_381>::prove(&final_keys.transfer_pk, tc, &mut r)
        .map_err(|_| "transfer prove failed")?;
    if !ark_groth16::Groth16::<Bls12_381>::verify(&final_keys.transfer_pk.vk, &tp, &tproof)
        .map_err(|_| "transfer verify errored")?
    {
        return Err("transfer proof did not verify under final keys".into());
    }
    Ok(())
}
