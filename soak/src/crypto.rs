//! Cryptographic foundation for the soak harness.
//!
//! The circuit, Poseidon parameters, note/nullifier derivations, and reference trees are reused
//! verbatim from `circuit/common` (the exact code the deployed verifying keys were generated
//! against). This module adds only: wire encoding helpers and an O(depth) incremental Merkle
//! mirror whose root must equal the canister tree oracle's root after every append. If the mirror
//! and the canister ever disagree, that is a reported finding, not something the harness papers
//! over.

use ark_bls12_381::Fr as F;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use common::{merkle_compress, zero_hashes, PoseidonCfg, TREE_DEPTH};
use std::collections::HashMap;

/// 32-byte little-endian canonical compressed Fr — the exact wire form the ledger and prover use.
pub fn f_bytes(x: &F) -> [u8; 32] {
    let mut b = Vec::with_capacity(32);
    x.serialize_compressed(&mut b).unwrap();
    let mut out = [0u8; 32];
    out.copy_from_slice(&b);
    out
}

pub fn f_from_bytes(b: &[u8]) -> Option<F> {
    F::deserialize_compressed(b).ok()
}

pub fn hex_of(x: &F) -> String {
    hex::encode(f_bytes(x))
}

/// A u64 value as the ledger encodes fee / v_pub_out: 32-byte little-endian, low 8 bytes set.
/// This equals the compressed serialization of `F::from(value)`.
pub fn nat64_field_bytes(value: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..8].copy_from_slice(&value.to_le_bytes());
    out
}

/// Append-only incremental Merkle tree, depth 32, Poseidon 2-to-1 compression — the same shape
/// as `common::IncrementalTree` and the tree-oracle canister, but with a stored-node map so a
/// membership path is O(depth) instead of O(n). Node values at internal levels are updated in
/// place as right children arrive, exactly matching the canister's `filled`/append semantics.
#[derive(Clone)]
pub struct MerkleMirror {
    zeros: Vec<F>,
    // nodes[level] : populated node index -> current hash at that level
    nodes: Vec<HashMap<u64, F>>,
    next_index: u64,
    root: F,
}

impl MerkleMirror {
    pub fn new(cfg: &PoseidonCfg<F>) -> Self {
        let zeros = zero_hashes(cfg);
        let nodes = (0..=TREE_DEPTH).map(|_| HashMap::new()).collect();
        let root = zeros[TREE_DEPTH];
        MerkleMirror { zeros, nodes, next_index: 0, root }
    }

    pub fn leaf_count(&self) -> u64 {
        self.next_index
    }

    pub fn root(&self) -> F {
        self.root
    }

    /// Append one leaf; returns its leaf index. Updates every touched internal node so subsequent
    /// path queries reflect the current tree.
    pub fn append(&mut self, cfg: &PoseidonCfg<F>, leaf: F) -> u64 {
        assert!(self.next_index < (1u64 << TREE_DEPTH), "tree full");
        let leaf_index = self.next_index;
        let mut idx = leaf_index;
        let mut cur = leaf;
        self.nodes[0].insert(idx, cur);
        for lvl in 0..TREE_DEPTH {
            if idx % 2 == 0 {
                cur = merkle_compress(cfg, cur, self.zeros[lvl]);
            } else {
                let left = *self.nodes[lvl].get(&(idx - 1)).expect("left sibling must exist");
                cur = merkle_compress(cfg, left, cur);
            }
            idx /= 2;
            self.nodes[lvl + 1].insert(idx, cur);
        }
        self.next_index += 1;
        self.root = cur;
        leaf_index
    }

    /// (siblings, position bits little-endian) for `index`, against the CURRENT tree.
    pub fn path(&self, index: u64) -> (Vec<F>, Vec<bool>) {
        let mut siblings = Vec::with_capacity(TREE_DEPTH);
        let mut bits = Vec::with_capacity(TREE_DEPTH);
        let mut idx = index;
        for lvl in 0..TREE_DEPTH {
            let sib_idx = idx ^ 1;
            let sib = self.nodes[lvl].get(&sib_idx).copied().unwrap_or(self.zeros[lvl]);
            siblings.push(sib);
            bits.push(idx % 2 == 1);
            idx /= 2;
        }
        (siblings, bits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::{poseidon_config, DenseTree, IncrementalTree, Note};
    use ark_ff::UniformRand;
    use ark_std::rand::SeedableRng;

    #[test]
    fn mirror_matches_reference_trees() {
        let cfg = poseidon_config();
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(1);
        let mut mirror = MerkleMirror::new(&cfg);
        let mut inc = IncrementalTree::new(&cfg);
        let mut leaves: Vec<F> = Vec::new();
        for i in 0..200u64 {
            let note = Note { v: i, nk: F::rand(&mut rng), rho: F::rand(&mut rng), rcm: F::rand(&mut rng) };
            let cm = note.cm(&cfg);
            leaves.push(cm);
            let inc_root = inc.append(&cfg, cm);
            let mir_root = {
                mirror.append(&cfg, cm);
                mirror.root()
            };
            assert_eq!(inc_root, mir_root, "mirror vs IncrementalTree diverged at leaf {i}");
            let dense_root = DenseTree { leaves: leaves.clone() }.root(&cfg);
            assert_eq!(dense_root, mir_root, "mirror vs DenseTree diverged at leaf {i}");
        }
        // membership paths must fold back to the current root under the same gadget rule.
        for &idx in &[0u64, 1, 2, 7, 42, 199] {
            let (sibs, bits) = mirror.path(idx);
            let mut cur = leaves[idx as usize];
            for (sib, bit) in sibs.iter().zip(bits.iter()) {
                cur = if *bit { merkle_compress(&cfg, *sib, cur) } else { merkle_compress(&cfg, cur, *sib) };
            }
            assert_eq!(cur, mirror.root(), "path fold mismatch at {idx}");
        }
    }
}
