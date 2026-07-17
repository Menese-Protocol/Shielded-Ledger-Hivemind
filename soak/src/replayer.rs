//! B3 proof 2 / B4 proof 2 / B7 proof 2: the independent block-stream replayer.
//!
//! This module reconstructs the entire ledger state purely from the `icrc3_get_blocks` stream,
//! written from the `zknote1` block schema (`docs/ICRC3-ZKNOTE1-SCHEMA.md`, `src/NoteCodec.mo`
//! field set). It shares NO state code with the reference model: blocks are parsed from the wire,
//! the phash link of every block is verified with the ICRC-3 representation-independent hash, the
//! commitment tree is rebuilt with `common::IncrementalTree` (a different implementation from the
//! model's `MerkleMirror`), and per-account balances come from ciphertext recognition alone.
//!
//! Any violation panics: a replayer panic is a soak finding, never something to soften.

use crate::candid_types::{self as ct, Value};
use crate::icrc3_hash::hash_value;
use crate::model::AccountKeys;
use crate::pic_env::Env;
use crate::prover::try_decrypt_note;
use ark_bls12_381::Fr as F;
use ark_ff::PrimeField;
use common::{derive_nf, note_commitment, poseidon_config, IncrementalTree};
use std::collections::{HashMap, HashSet};

pub struct RawBlock {
    pub position: u64,
    pub btype: String,
    pub encoding_version: u64,
    pub phash: Option<[u8; 32]>,
    pub commitment: [u8; 32],
    pub ephemeral_key: Vec<u8>,
    pub note_ciphertext: Vec<u8>,
    pub nullifiers: Vec<[u8; 32]>,
    pub anchor_before: [u8; 32],
    pub note_root_after: [u8; 32],
    pub timestamp: u64,
    pub origin: String,
    pub hash: [u8; 32],
}

fn map_get<'a>(entries: &'a [(String, Value)], key: &str) -> Option<&'a Value> {
    entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

fn as_blob32(v: &Value, what: &str) -> [u8; 32] {
    match v {
        Value::Blob(b) => b.as_slice().try_into().unwrap_or_else(|_| panic!("{what}: not 32 bytes")),
        _ => panic!("{what}: not a blob"),
    }
}

fn as_nat_u64(v: &Value, what: &str) -> u64 {
    match v {
        Value::Nat(n) => u64::try_from(n.0.clone()).unwrap_or_else(|_| panic!("{what}: too large")),
        _ => panic!("{what}: not a nat"),
    }
}

fn as_text(v: &Value, what: &str) -> String {
    match v {
        Value::Text(t) => t.clone(),
        _ => panic!("{what}: not text"),
    }
}

fn parse_block(id: u64, value: &Value) -> RawBlock {
    let Value::Map(entries) = value else { panic!("block {id}: not a map") };
    let nullifiers = match map_get(entries, "nullifiers") {
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| as_blob32(v, "nullifier"))
            .collect::<Vec<_>>(),
        _ => panic!("block {id}: missing nullifiers array"),
    };
    RawBlock {
        nullifiers,
        position: as_nat_u64(map_get(entries, "note_position").expect("note_position"), "note_position"),
        btype: as_text(map_get(entries, "btype").expect("btype"), "btype"),
        encoding_version: as_nat_u64(
            map_get(entries, "encoding_version").expect("encoding_version"),
            "encoding_version",
        ),
        phash: map_get(entries, "phash").map(|v| as_blob32(v, "phash")),
        commitment: as_blob32(map_get(entries, "commitment").expect("commitment"), "commitment"),
        ephemeral_key: match map_get(entries, "ephemeral_key").expect("ephemeral_key") {
            Value::Blob(b) => b.to_vec(),
            _ => panic!("ephemeral_key: not a blob"),
        },
        note_ciphertext: match map_get(entries, "note_ciphertext").expect("note_ciphertext") {
            Value::Blob(b) => b.to_vec(),
            _ => panic!("note_ciphertext: not a blob"),
        },
        anchor_before: as_blob32(map_get(entries, "anchor_before").expect("anchor_before"), "anchor_before"),
        note_root_after: as_blob32(
            map_get(entries, "note_root_after").expect("note_root_after"),
            "note_root_after",
        ),
        timestamp: as_nat_u64(map_get(entries, "timestamp").expect("timestamp"), "timestamp"),
        origin: as_text(map_get(entries, "origin").expect("origin"), "origin"),
        hash: hash_value(value),
    }
}

/// Fetch the complete block log, paginated.
pub fn fetch_all_blocks(env: &Env) -> Vec<RawBlock> {
    const PAGE: u64 = 256;
    let mut blocks = Vec::new();
    let mut start = 0u64;
    loop {
        let result: ct::GetBlocksResult = env
            .query(
                env.ledger,
                "icrc3_get_blocks",
                (vec![ct::GetBlocksArgs {
                    start: candid::Nat::from(start),
                    length: candid::Nat::from(PAGE),
                }],),
            )
            .expect("icrc3_get_blocks");
        let log_length = u64::try_from(result.log_length.0.clone()).unwrap();
        for entry in &result.blocks {
            let id = u64::try_from(entry.id.0.clone()).unwrap();
            assert_eq!(id, blocks.len() as u64, "block ids must be dense and ordered");
            blocks.push(parse_block(id, &entry.block));
        }
        start = blocks.len() as u64;
        if start >= log_length {
            assert_eq!(start, log_length, "fetched more blocks than log_length");
            return blocks;
        }
    }
}

pub struct ReplayResult {
    pub block_count: u64,
    pub last_block_hash: Option<[u8; 32]>,
    pub final_root: [u8; 32],
    pub balances: Vec<u128>,
    pub total_unspent: u128,
    pub spent_nullifiers: u64,
    pub transfer_ops: u64,
    pub shield_ops: u64,
    /// how many note ciphertexts the keyed scan recognized (B10 contrast: must be all of them)
    pub recognized_notes: u64,
}

/// Replay the chain: verify every phash link, block domain, position density, nullifier
/// uniqueness, anchor recognition, and the note-root chain (tree rebuilt independently); then
/// compute per-account balances from ciphertext recognition.
pub fn replay(blocks: &[RawBlock], accounts: &[AccountKeys]) -> ReplayResult {
    let cfg = poseidon_config();
    let mut tree = IncrementalTree::new(&cfg);
    let mut known_roots: HashSet<[u8; 32]> = HashSet::new();
    known_roots.insert(crate::crypto::f_bytes(&tree.root));
    let mut spent: HashSet<[u8; 32]> = HashSet::new();
    let mut prev_hash: Option<[u8; 32]> = None;
    let mut shield_ops = 0u64;
    let mut transfer_ops = 0u64;

    let mut i = 0usize;
    while i < blocks.len() {
        let b = &blocks[i];
        assert_eq!(b.position, i as u64, "position mismatch at {i}");
        assert_eq!(b.btype, "zknote1", "unexpected btype at {i}");
        assert_eq!(b.encoding_version, 1, "unexpected encoding_version at {i}");
        assert_eq!(b.phash, prev_hash, "phash link broken at block {i}");

        match b.origin.as_str() {
            "shield" => {
                assert!(b.nullifiers.is_empty(), "shield block {i} must carry no nullifiers");
                assert_eq!(
                    b.anchor_before,
                    crate::crypto::f_bytes(&tree.root),
                    "shield block {i}: anchor_before must be the pre-append root"
                );
                let leaf = F::from_le_bytes_mod_order(&b.commitment);
                // exact wire check: the commitment must BE a canonical field element
                assert_eq!(
                    crate::crypto::f_bytes(&leaf),
                    b.commitment,
                    "shield block {i}: non-canonical commitment"
                );
                tree.append(&cfg, leaf);
                assert_eq!(
                    b.note_root_after,
                    crate::crypto::f_bytes(&tree.root),
                    "shield block {i}: root_after mismatch (independent tree)"
                );
                known_roots.insert(b.note_root_after);
                prev_hash = Some(b.hash);
                shield_ops += 1;
                i += 1;
            }
            "confidential_transfer" => {
                // A transfer writes exactly two consecutive blocks sharing the nullifier pair,
                // the proof anchor, and the post-both-appends root.
                assert!(i + 1 < blocks.len(), "dangling transfer block at {i}");
                let b2 = &blocks[i + 1];
                assert_eq!(b2.origin, "confidential_transfer", "transfer pair broken at {i}");
                assert_eq!(b2.nullifiers, b.nullifiers, "transfer pair nullifiers differ at {i}");
                assert_eq!(b2.anchor_before, b.anchor_before, "transfer pair anchors differ at {i}");
                assert_eq!(b2.note_root_after, b.note_root_after, "transfer pair roots differ at {i}");
                assert_eq!(b.nullifiers.len(), 2, "transfer must spend exactly two notes at {i}");
                assert_ne!(b.nullifiers[0], b.nullifiers[1], "duplicate nullifier in tx at {i}");
                assert!(
                    known_roots.contains(&b.anchor_before),
                    "transfer at {i} references an anchor that never appeared in the chain"
                );
                for nf in &b.nullifiers {
                    assert!(spent.insert(*nf), "nullifier reused across chain at block {i}");
                }
                for blk in [b, b2] {
                    let leaf = F::from_le_bytes_mod_order(&blk.commitment);
                    assert_eq!(
                        crate::crypto::f_bytes(&leaf),
                        blk.commitment,
                        "transfer block: non-canonical commitment"
                    );
                    tree.append(&cfg, leaf);
                }
                let root_now = crate::crypto::f_bytes(&tree.root);
                assert_eq!(b.note_root_after, root_now, "transfer root_after mismatch at {i}");
                known_roots.insert(root_now);
                // phash chain covers BOTH blocks individually
                assert_eq!(b2.phash, Some(b.hash), "phash link broken inside transfer pair at {i}");
                prev_hash = Some(b2.hash);
                transfer_ops += 1;
                i += 2;
            }
            other => panic!("unknown origin {other:?} at block {i}"),
        }
    }

    // Per-account balances by recognition scan against the replayer's own spent set.
    let mut balances = vec![0u128; accounts.len()];
    let mut total_unspent: u128 = 0;
    let mut owned_notes: HashMap<[u8; 32], (usize, u64)> = HashMap::new(); // nf -> (acct, v)
    use rayon::prelude::*;
    let per_account: Vec<Vec<([u8; 32], u64)>> = accounts
        .par_iter()
        .map(|acct| {
            let mut mine = Vec::new();
            for b in blocks {
                let Some((v, rho, _rcm, pk)) =
                    try_decrypt_note(&acct.scan_key, &b.ephemeral_key, &b.note_ciphertext)
                else {
                    continue;
                };
                let rho_f = F::from_le_bytes_mod_order(&rho);
                let pk_f = F::from_le_bytes_mod_order(&pk);
                let rcm_f = F::from_le_bytes_mod_order(&_rcm);
                let cm = note_commitment(&cfg, v, pk_f, rho_f, rcm_f);
                assert_eq!(
                    crate::crypto::f_bytes(&cm),
                    b.commitment,
                    "replayer: decrypted opening does not recompute the block commitment"
                );
                let nf = derive_nf(&cfg, acct.nk, rho_f);
                mine.push((crate::crypto::f_bytes(&nf), v));
            }
            mine
        })
        .collect();
    let mut recognized_notes = 0u64;
    for (acct_idx, mine) in per_account.into_iter().enumerate() {
        for (nf, v) in mine {
            recognized_notes += 1;
            let dup = owned_notes.insert(nf, (acct_idx, v));
            assert!(dup.is_none(), "two accounts recognized the same note");
            if !spent.contains(&nf) {
                balances[acct_idx] += v as u128;
                total_unspent += v as u128;
            }
        }
    }

    ReplayResult {
        recognized_notes,
        block_count: blocks.len() as u64,
        last_block_hash: prev_hash,
        final_root: crate::crypto::f_bytes(&tree.root),
        balances,
        total_unspent,
        spent_nullifiers: spent.len() as u64,
        transfer_ops,
        shield_ops,
    }
}
