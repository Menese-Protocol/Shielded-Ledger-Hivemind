//! Proof and argument construction for soak operations. Witnesses are assembled exactly as the
//! reference browser prover does (`demo-frontend/prover-wasm/src/lib.rs`): Merkle paths against a
//! snapshot anchor, output rho chained to the input nullifiers, recipient binding as the eighth
//! public input. Every proof is self-verified against the regenerated verifying key before it is
//! allowed near the canister, so a submission rejection can never be blamed on a malformed
//! harness proof.
//!
//! Note ciphertexts: the ledger stores `ephemeral_key`/`note_ciphertext` as opaque bytes and
//! never interprets them. The harness uses a deterministic recognition-tag + SHA-256 keystream
//! encoding so the wallet-style scan (B3 proof 1) performs a genuine trial-recognition pass over
//! the public log with only the recipient's scan key. This is a correctness artifact of the test
//! suite, not a proposed encryption scheme.

use crate::candid_types as ct;
use crate::crypto::f_bytes;
use crate::model::AccountKeys;
use ark_bls12_381::{Bls12_381, Fr as F};
use ark_groth16::Groth16;
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use common::{derive_nf, note_commitment, DepositCircuit, PoseidonCfg, TransferCircuit, TREE_ARITY};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};

pub const NOTE_PAYLOAD_LEN: usize = 104; // v(8) || rho(32) || rcm(32) || pk(32)
pub const NOTE_TAG_LEN: usize = 8;

/// The fixed output shape (ephemeral-key length, note-ciphertext length) this process seals
/// notes to, once set; unset = the compact form (16-byte key, tag + payload). The ledger's
/// set_note_shape refuses any output of another size, so a run under a note shape sets this
/// to the same pair before preparing anything.
static NOTE_SHAPE: std::sync::OnceLock<(usize, usize)> = std::sync::OnceLock::new();

pub fn set_note_shape(ephemeral_key_len: usize, note_ciphertext_len: usize) {
    assert!(ephemeral_key_len >= 16, "note shape: ephemeral key shorter than 16 bytes");
    assert!(note_ciphertext_len >= NOTE_TAG_LEN + NOTE_PAYLOAD_LEN, "note shape: ciphertext shorter than tag + payload");
    let want = (ephemeral_key_len, note_ciphertext_len);
    let got = *NOTE_SHAPE.get_or_init(|| want);
    assert_eq!(got, want, "note shape already set to a different size in this process");
}

pub fn note_shape() -> Option<(usize, usize)> {
    NOTE_SHAPE.get().copied()
}

/// The `recipient_binding` a private transfer carrying `envelope` proves (src/Main.mo
/// claimBinding): SHA-256("picp-claim-envelope/v1" ‖ pool principal ‖ envelope), byte 31 cleared.
pub fn claim_envelope_binding(pool: &candid::Principal, envelope: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"picp-claim-envelope/v1");
    h.update(pool.as_slice());
    h.update(envelope);
    let mut out: [u8; 32] = h.finalize().into();
    out[31] = 0;
    out
}

fn compressed_hex<T: CanonicalSerialize>(x: &T) -> String {
    let mut b = Vec::new();
    x.serialize_compressed(&mut b).unwrap();
    hex::encode(b)
}

/// Per-operation deterministic RNG: everything random about op `op_index` of run `seed` derives
/// from this, so a rerun with the same seed reproduces identical proofs and ciphertexts.
pub fn op_rng(seed: u64, op_index: u64, domain: &str) -> ChaCha20Rng {
    let mut h = Sha256::new();
    h.update(b"soak-op-rng-v1");
    h.update(seed.to_le_bytes());
    h.update(op_index.to_le_bytes());
    h.update(domain.as_bytes());
    ChaCha20Rng::from_seed(h.finalize().into())
}

fn keystream(scan_key: &[u8; 32], eph: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut counter = 0u32;
    while out.len() < len {
        let mut h = Sha256::new();
        h.update(b"soak-note-stream-v1");
        h.update(scan_key);
        h.update(eph);
        h.update(counter.to_le_bytes());
        out.extend_from_slice(&h.finalize());
        counter += 1;
    }
    out.truncate(len);
    out
}

fn recognition_tag(scan_key: &[u8; 32], eph: &[u8]) -> [u8; NOTE_TAG_LEN] {
    let mut h = Sha256::new();
    h.update(b"soak-note-tag-v1");
    h.update(scan_key);
    h.update(eph);
    let d: [u8; 32] = h.finalize().into();
    d[..NOTE_TAG_LEN].try_into().unwrap()
}

/// Encrypt a note opening to the recipient's scan key. Returns (ephemeral_key, ciphertext).
pub fn encrypt_note(
    recipient: &AccountKeys,
    v: u64,
    rho: &F,
    rcm: &F,
    rng: &mut ChaCha20Rng,
) -> (Vec<u8>, Vec<u8>) {
    use rand_chacha::rand_core::RngCore;
    let (eph_len, body_len) = match note_shape() {
        Some((eph_len, ct_len)) => (eph_len, ct_len - NOTE_TAG_LEN),
        None => (16, NOTE_PAYLOAD_LEN),
    };
    let mut eph = vec![0u8; eph_len];
    rng.fill_bytes(&mut eph);
    let mut payload = Vec::with_capacity(body_len);
    payload.extend_from_slice(&v.to_le_bytes());
    payload.extend_from_slice(&f_bytes(rho));
    payload.extend_from_slice(&f_bytes(rcm));
    payload.extend_from_slice(&f_bytes(&recipient.pk));
    // padding to the fixed shape is encrypted under the same keystream, so it is uniform on chain
    payload.resize(body_len, 0);
    let stream = keystream(&recipient.scan_key, &eph, body_len);
    let mut body: Vec<u8> = payload.iter().zip(stream.iter()).map(|(p, s)| p ^ s).collect();
    let mut ciphertext = recognition_tag(&recipient.scan_key, &eph).to_vec();
    ciphertext.append(&mut body);
    (eph, ciphertext)
}

/// Attempt trial recognition + decryption with `scan_key`. Returns (v, rho, rcm, pk) on tag match.
pub fn try_decrypt_note(
    scan_key: &[u8; 32],
    eph: &[u8],
    ciphertext: &[u8],
) -> Option<(u64, [u8; 32], [u8; 32], [u8; 32])> {
    // the compact form, or a fixed shape whose padding must decrypt to zeros
    if ciphertext.len() < NOTE_TAG_LEN + NOTE_PAYLOAD_LEN {
        return None;
    }
    if ciphertext[..NOTE_TAG_LEN] != recognition_tag(scan_key, eph) {
        return None;
    }
    let body_len = ciphertext.len() - NOTE_TAG_LEN;
    let stream = keystream(scan_key, eph, body_len);
    let plain: Vec<u8> = ciphertext[NOTE_TAG_LEN..]
        .iter()
        .zip(stream.iter())
        .map(|(c, s)| c ^ s)
        .collect();
    if plain[NOTE_PAYLOAD_LEN..].iter().any(|&b| b != 0) {
        return None;
    }
    let v = u64::from_le_bytes(plain[0..8].try_into().unwrap());
    Some((
        v,
        plain[8..40].try_into().unwrap(),
        plain[40..72].try_into().unwrap(),
        plain[72..104].try_into().unwrap(),
    ))
}

pub struct PreparedShield {
    pub args: ct::DepositArgs,
    pub v: u64,
    pub rho: F,
    pub rcm: F,
}

/// Build a canister-ready shield (deposit) for `acct`, proving knowledge of the commitment
/// opening. `rho`/`rcm` were drawn by the planner (which already appended the commitment to its
/// planning mirror); `created_at_time` is stamped by the submitter.
#[allow(clippy::too_many_arguments)]
pub fn prepare_shield(
    cfg: &PoseidonCfg<F>,
    deposit_pk: &ark_groth16::ProvingKey<Bls12_381>,
    acct: &AccountKeys,
    v: u64,
    rho: F,
    rcm: F,
    seed: u64,
    op_index: u64,
) -> PreparedShield {
    let mut rng = op_rng(seed, op_index, "shield");
    let cm = note_commitment(cfg, v, acct.pk, rho, rcm);
    let circuit = DepositCircuit {
        cfg: cfg.clone(),
        cm: Some(cm),
        v_pub: Some(v),
        pk: Some(acct.pk),
        rho: Some(rho),
        rcm: Some(rcm),
    };
    let publics = circuit.public_inputs();
    let proof = Groth16::<Bls12_381>::prove(deposit_pk, circuit, &mut rng).expect("deposit prove");
    assert!(
        Groth16::<Bls12_381>::verify(&deposit_pk.vk, &publics, &proof).unwrap(),
        "deposit self-verification failed"
    );
    let (eph, ciphertext) = encrypt_note(acct, v, &rho, &rcm, &mut rng);
    use rand_chacha::rand_core::RngCore;
    let mut nonce = [0u8; 32];
    rng.fill_bytes(&mut nonce);
    PreparedShield {
        args: ct::DepositArgs {
            value: v,
            from_subaccount: None,
            created_at_time: 0, // stamped at submission
            client_nonce: ct::blob(nonce.to_vec()),
            commitment: ct::blob(f_bytes(&cm).to_vec()),
            ephemeral_key: ct::blob(eph),
            note_ciphertext: ct::blob(ciphertext),
            proof_hex: compressed_hex(&proof),
        },
        v,
        rho,
        rcm,
    }
}

pub struct TransferPlanInput {
    /// model note index, plus everything needed for the witness
    pub note_index: usize,
    pub leaf_index: u64,
    pub v: u64,
    pub nk: F,
    pub rho: F,
    pub rcm: F,
}

/// Everything anchor-dependent, extracted by the planner from its evolving planning mirror so
/// the proof anchor equals the EXACT tree root at this op's submission position (unshield
/// finalization requires the current root, not merely a historical one).
pub struct TransferCrypto {
    pub anchor: F,
    /// (one full row per level, the walked node's slot in each row) — `DenseTree::path` shape
    pub path1: (Vec<[F; TREE_ARITY]>, Vec<usize>),
    pub path2: (Vec<[F; TREE_ARITY]>, Vec<usize>),
    pub out_rcm1: F,
    pub out_rcm2: F,
}

pub struct PreparedTransfer {
    pub args: ct::TransferArgs,
    pub in_notes: (usize, usize),
    /// (owner, v, rho, rcm) of each output, for the model
    pub outs: [(usize, u64, F, F); 2],
    pub recipient_acct: Option<usize>,
    pub anchor: [u8; 32],
}

/// Build a canister-ready confidential transfer (private when v_pub_out == 0, unshield
/// otherwise). Anchor and membership paths come from the planner's `crypto` (the predicted
/// submission-time tree state).
#[allow(clippy::too_many_arguments)]
pub fn prepare_transfer(
    cfg: &PoseidonCfg<F>,
    transfer_pk: &ark_groth16::ProvingKey<Bls12_381>,
    legacy_statement: bool,
    crypto: &TransferCrypto,
    inputs: (&TransferPlanInput, &TransferPlanInput),
    out_owners: (&AccountKeys, &AccountKeys),
    out_values: (u64, u64),
    fee: u64,
    v_pub_out: u64,
    recipient_binding: [u8; 32],
    recipient: Option<ct::Account>,
    recipient_acct: Option<usize>,
    seed: u64,
    op_index: u64,
) -> PreparedTransfer {
    let mut rng = op_rng(seed, op_index, "transfer");
    let (in1, in2) = inputs;
    let anchor_f = crypto.anchor;
    let (rows1, pos1) = crypto.path1.clone();
    let (rows2, pos2) = crypto.path2.clone();
    let nf1 = derive_nf(cfg, in1.nk, in1.rho);
    let nf2 = derive_nf(cfg, in2.nk, in2.rho);
    let out_rcm1 = crypto.out_rcm1;
    let out_rcm2 = crypto.out_rcm2;
    let cm_out1 = note_commitment(cfg, out_values.0, out_owners.0.pk, nf1, out_rcm1);
    let cm_out2 = note_commitment(cfg, out_values.1, out_owners.1.pk, nf2, out_rcm2);
    let binding_f = crate::crypto::f_from_bytes(&recipient_binding)
        .expect("recipient binding must be a canonical field element");

    let circuit = TransferCircuit {
        cfg: cfg.clone(),
        enforce_range: true,
        // must match the statement of `transfer_pk` or proving fails
        legacy_statement,
        anchor: Some(anchor_f),
        nf: [Some(nf1), Some(nf2)],
        cm_out: [Some(cm_out1), Some(cm_out2)],
        fee: Some(fee),
        v_pub_out: Some(v_pub_out),
        recipient_binding: Some(binding_f),
        in_v: [Some(in1.v), Some(in2.v)],
        in_nk: [Some(in1.nk), Some(in2.nk)],
        in_rho: [Some(in1.rho), Some(in2.rho)],
        in_rcm: [Some(in1.rcm), Some(in2.rcm)],
        in_rows: [rows1, rows2],
        in_pos: [pos1, pos2],
        out_v: [Some(F::from(out_values.0)), Some(F::from(out_values.1))],
        out_pk: [Some(out_owners.0.pk), Some(out_owners.1.pk)],
        out_rcm: [Some(out_rcm1), Some(out_rcm2)],
    };
    let publics = circuit.public_inputs();
    let proof = Groth16::<Bls12_381>::prove(transfer_pk, circuit, &mut rng).expect("transfer prove");
    assert!(
        Groth16::<Bls12_381>::verify(&transfer_pk.vk, &publics, &proof).unwrap(),
        "transfer self-verification failed"
    );

    let (eph1, ct1) = encrypt_note(out_owners.0, out_values.0, &nf1, &out_rcm1, &mut rng);
    let (eph2, ct2) = encrypt_note(out_owners.1, out_values.1, &nf2, &out_rcm2, &mut rng);

    PreparedTransfer {
        args: ct::TransferArgs {
            anchor: ct::blob(f_bytes(&anchor_f).to_vec()),
            nullifier_1: ct::blob(f_bytes(&nf1).to_vec()),
            nullifier_2: ct::blob(f_bytes(&nf2).to_vec()),
            output_1: ct::OutputRecord {
                commitment: ct::blob(f_bytes(&cm_out1).to_vec()),
                ephemeral_key: ct::blob(eph1),
                note_ciphertext: ct::blob(ct1),
            },
            output_2: ct::OutputRecord {
                commitment: ct::blob(f_bytes(&cm_out2).to_vec()),
                ephemeral_key: ct::blob(eph2),
                note_ciphertext: ct::blob(ct2),
            },
            fee,
            v_pub_out,
            recipient,
            created_at_time: None, // stamped at submission for unshields
            proof_hex: compressed_hex(&proof),
            claim_envelope: None,
        },
        in_notes: (in1.note_index, in2.note_index),
        outs: [
            (out_owners.0.index, out_values.0, nf1, out_rcm1),
            (out_owners.1.index, out_values.1, nf2, out_rcm2),
        ],
        recipient_acct,
        anchor: f_bytes(&anchor_f),
    }
}
