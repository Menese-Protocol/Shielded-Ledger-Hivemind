//! B10: keyless-observer leakage audit.
//!
//! A scanner holding NO account keys walks the complete `icrc3_get_blocks` stream and must
//! (proof 1) find zero plaintext amounts and zero sender/recipient principals in the opaque
//! fields of confidential-transfer blocks, and (proof 2) demonstrably fail to recognize a single
//! note ciphertext — so it cannot reconstruct any account balance — while the keyed replayer
//! succeeds on the very same stream.
//!
//! Scope and honesty: shield/unshield token legs are public by design (they live on the token
//! ledger) and are excluded. This audit is a LEAKAGE REGRESSION GUARD on the block encoding; it
//! does not prove cryptographic unlinkability, which rests on the circuit design and its review.
//! The needle values come from the harness's own knowledge of the run (the observer being tested
//! still holds no keys; the needles only define what a leak would look like).

use crate::model::AccountKeys;
use crate::prover::try_decrypt_note;
use crate::replayer::RawBlock;
use candid::Principal;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub struct LeakReport {
    pub blocks_scanned: u64,
    pub confidential_blocks_scanned: u64,
    pub amount_needles: u64,
    pub amount_hits: u64,
    pub principal_needles: u64,
    pub principal_hits: u64,
    pub keyless_recognized_notes: u64,
    pub adversary_keys_tried: u64,
}

/// The opaque byte surface of one block: every field a keyless observer sees except the plain
/// structural metadata (position, timestamp, origin/btype tags).
fn opaque_bytes(b: &RawBlock) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        32 + b.ephemeral_key.len() + b.note_ciphertext.len() + 32 * b.nullifiers.len() + 64,
    );
    out.extend_from_slice(&b.commitment);
    out.extend_from_slice(&b.ephemeral_key);
    out.extend_from_slice(&b.note_ciphertext);
    for nf in &b.nullifiers {
        out.extend_from_slice(nf);
    }
    out.extend_from_slice(&b.anchor_before);
    out.extend_from_slice(&b.note_root_after);
    out
}

fn count_window_hits(haystack: &[u8], window: usize, needles: &HashSet<Vec<u8>>) -> u64 {
    if haystack.len() < window || needles.is_empty() {
        return 0;
    }
    let mut hits = 0;
    for w in haystack.windows(window) {
        if needles.contains(w) {
            hits += 1;
        }
    }
    hits
}

/// Run the keyless audit. `amounts` are all note values that ever moved in a confidential
/// transfer; `principals` are all user principals of the run.
pub fn keyless_leakage_audit(
    blocks: &[RawBlock],
    amounts: &HashSet<u64>,
    principals: &[Principal],
) -> LeakReport {
    // proof 1a: amount needles, little- and big-endian 64-bit, zero excluded (degenerate).
    let mut amount_needles: HashSet<Vec<u8>> = HashSet::new();
    for &v in amounts {
        if v == 0 {
            continue;
        }
        amount_needles.insert(v.to_le_bytes().to_vec());
        amount_needles.insert(v.to_be_bytes().to_vec());
    }
    // proof 1b: principal needles (raw principal bytes), grouped by length.
    let mut principal_needles_by_len: std::collections::HashMap<usize, HashSet<Vec<u8>>> =
        std::collections::HashMap::new();
    for p in principals {
        let bytes = p.as_slice().to_vec();
        principal_needles_by_len.entry(bytes.len()).or_default().insert(bytes);
    }

    let mut amount_hits = 0u64;
    let mut principal_hits = 0u64;
    let mut confidential = 0u64;
    for b in blocks {
        let bytes = opaque_bytes(b);
        if b.origin == "confidential_transfer" {
            confidential += 1;
            amount_hits += count_window_hits(&bytes, 8, &amount_needles);
        }
        for (len, needles) in &principal_needles_by_len {
            principal_hits += count_window_hits(&bytes, *len, needles);
        }
    }

    // proof 2: the observer's best generic recognition attempt with keys it could plausibly
    // guess (all-zero, and a family of deterministic adversary keys) recognizes nothing.
    let mut adversary_keys: Vec<[u8; 32]> = vec![[0u8; 32], [0xffu8; 32]];
    for i in 0..14u64 {
        let mut h = Sha256::new();
        h.update(b"keyless-adversary-guess");
        h.update(i.to_le_bytes());
        adversary_keys.push(h.finalize().into());
    }
    let mut recognized = 0u64;
    for b in blocks {
        for key in &adversary_keys {
            if try_decrypt_note(key, &b.ephemeral_key, &b.note_ciphertext).is_some() {
                recognized += 1;
            }
        }
    }

    LeakReport {
        blocks_scanned: blocks.len() as u64,
        confidential_blocks_scanned: confidential,
        amount_needles: amount_needles.len() as u64,
        amount_hits,
        principal_needles: principals.len() as u64,
        principal_hits,
        keyless_recognized_notes: recognized,
        adversary_keys_tried: adversary_keys.len() as u64,
    }
}

/// Assert the audit verdicts (called from the battery). `keyed_recognized` is how many notes the
/// KEYED replayer recognized on the same stream — it must equal the block count (every block
/// carries exactly one note) to prove the stream is fully readable with keys.
pub fn assert_no_leakage(report: &LeakReport, keyed_recognized: u64) {
    assert_eq!(
        report.amount_hits, 0,
        "B10: plaintext amount bytes found in confidential-transfer blocks"
    );
    assert_eq!(report.principal_hits, 0, "B10: principal bytes found in block opaque fields");
    assert_eq!(
        report.keyless_recognized_notes, 0,
        "B10: a keyless observer recognized a note ciphertext"
    );
    assert_eq!(
        keyed_recognized, report.blocks_scanned,
        "B10: keyed replayer must recognize every note on the same stream"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_scan_finds_planted_needle() {
        // the scanner must be able to find a leak if one existed (the check has teeth)
        let mut needles = HashSet::new();
        needles.insert(1234567u64.to_le_bytes().to_vec());
        let mut hay = vec![0u8; 64];
        hay[13..21].copy_from_slice(&1234567u64.to_le_bytes());
        assert_eq!(count_window_hits(&hay, 8, &needles), 1);
    }
}

/// Convenience: collect confidential-transfer amounts from account keys + blocks (used by the
/// battery to build the needle set WITHOUT reaching into the model: decrypt with the keyed
/// scan, then hand only the values to the keyless audit).
pub fn confidential_amounts_from_keyed_scan(
    cfg: &common::PoseidonCfg<ark_bls12_381::Fr>,
    accounts: &[AccountKeys],
    blocks: &[RawBlock],
) -> HashSet<u64> {
    use ark_ff::PrimeField;
    use rayon::prelude::*;
    let sets: Vec<HashSet<u64>> = accounts
        .par_iter()
        .map(|acct| {
            let mut mine = HashSet::new();
            for b in blocks {
                if b.origin != "confidential_transfer" {
                    continue;
                }
                if let Some((v, rho, rcm, pk)) =
                    try_decrypt_note(&acct.scan_key, &b.ephemeral_key, &b.note_ciphertext)
                {
                    let cm = common::note_commitment(
                        cfg,
                        v,
                        ark_bls12_381::Fr::from_le_bytes_mod_order(&pk),
                        ark_bls12_381::Fr::from_le_bytes_mod_order(&rho),
                        ark_bls12_381::Fr::from_le_bytes_mod_order(&rcm),
                    );
                    if crate::crypto::f_bytes(&cm) == b.commitment {
                        mine.insert(v);
                    }
                }
            }
            mine
        })
        .collect();
    sets.into_iter().flatten().collect()
}
