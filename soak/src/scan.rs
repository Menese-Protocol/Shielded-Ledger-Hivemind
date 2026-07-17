//! B3 proof 1: the wallet-style full-population balance scan. For every account, walk the PUBLIC
//! block log (as fetched from `icrc3_get_blocks`), trial-recognize each note ciphertext with the
//! account's scan key, verify the decrypted opening recomputes the block's commitment, derive the
//! nullifier, and subtract spent notes using only the public nullifier lists. No model state is
//! consulted: the scan sees exactly what a real wallet holding the account keys would see.

use crate::model::AccountKeys;
use crate::prover::try_decrypt_note;
use crate::replayer::RawBlock;
use ark_bls12_381::Fr as F;
use ark_ff::PrimeField;
use common::{derive_nf, note_commitment, PoseidonCfg};
use rayon::prelude::*;
use std::collections::HashSet;

fn f_from_le(bytes: &[u8; 32]) -> F {
    F::from_le_bytes_mod_order(bytes)
}

/// Balance of every account by ownership scan. Returns per-account spendable balances.
pub fn wallet_scan_balances(
    cfg: &PoseidonCfg<F>,
    accounts: &[AccountKeys],
    blocks: &[RawBlock],
) -> Vec<u128> {
    // The global spent-nullifier set is public: the union of every block's nullifier list.
    let spent: HashSet<[u8; 32]> = blocks
        .iter()
        .flat_map(|b| b.nullifiers.iter().copied())
        .collect();

    accounts
        .par_iter()
        .map(|acct| {
            let mut balance: u128 = 0;
            for block in blocks {
                let Some((v, rho, rcm, pk)) =
                    try_decrypt_note(&acct.scan_key, &block.ephemeral_key, &block.note_ciphertext)
                else {
                    continue;
                };
                // Ownership is proven by recomputing the public commitment from the opening.
                let rho_f = f_from_le(&rho);
                let rcm_f = f_from_le(&rcm);
                let pk_f = f_from_le(&pk);
                let cm = note_commitment(cfg, v, pk_f, rho_f, rcm_f);
                if crate::crypto::f_bytes(&cm) != block.commitment {
                    panic!(
                        "scan: ciphertext for block {} decrypts to an opening that does not match \
                         the public commitment",
                        block.position
                    );
                }
                let nf = derive_nf(cfg, acct.nk, rho_f);
                if !spent.contains(&crate::crypto::f_bytes(&nf)) {
                    balance += v as u128;
                }
            }
            balance
        })
        .collect()
}
