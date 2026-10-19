//! Cryptographic foundation for the soak harness.
//!
//! The circuit, Poseidon parameters, note/nullifier derivations, and reference trees are reused
//! verbatim from `circuit/common` (the exact code the deployed verifying keys were generated
//! against). This module adds only: wire encoding helpers and an O(levels) incremental Merkle
//! mirror whose root must equal the canister tree oracle's root after every append. If the mirror
//! and the canister ever disagree, that is a reported finding, not something the harness papers
//! over.

use ark_bls12_381::Fr as F;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use common::{
    merkle_compress, poseidon_config_tree, zero_hashes, TreeCfg, TREE_ARITY, TREE_CAPACITY, TREE_LEVELS,
};
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

/// Append-only incremental Merkle tree — 4-ary, 16 levels, Poseidon ARITY-to-1 compression under
/// the TREE instance (`common::poseidon_config_tree`) — the same shape as `common::IncrementalTree`
/// and the ledger's in-canister frontier, but with a stored-node map so a membership path is
/// O(levels) instead of O(n). Node values at internal levels are updated in place as later
/// children of their row arrive, exactly matching the canister's `filled`/append semantics.
///
/// The mirror owns its tree config: the note instance and the tree instance are different
/// Poseidon widths, and handing the wrong one to a tree is a silent fork (see `common::TreeCfg`).
#[derive(Clone)]
pub struct MerkleMirror {
    cfg_tree: TreeCfg,
    zeros: Vec<F>,
    // nodes[level] : populated node index -> current hash at that level
    nodes: Vec<HashMap<u64, F>>,
    next_index: u64,
    root: F,
}

impl Default for MerkleMirror {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleMirror {
    pub fn new() -> Self {
        let cfg_tree = poseidon_config_tree();
        let zeros = zero_hashes(&cfg_tree);
        let nodes = (0..=TREE_LEVELS).map(|_| HashMap::new()).collect();
        let root = zeros[TREE_LEVELS];
        MerkleMirror { cfg_tree, zeros, nodes, next_index: 0, root }
    }

    pub fn leaf_count(&self) -> u64 {
        self.next_index
    }

    pub fn root(&self) -> F {
        self.root
    }

    /// The row of `ARITY` nodes at `lvl` containing node `idx`, empty slots filled with the
    /// level's zero hash.
    fn row(&self, lvl: usize, idx: u64) -> [F; TREE_ARITY] {
        let base = idx - idx % TREE_ARITY as u64;
        let mut row = [self.zeros[lvl]; TREE_ARITY];
        for (j, slot) in row.iter_mut().enumerate() {
            if let Some(v) = self.nodes[lvl].get(&(base + j as u64)) {
                *slot = *v;
            }
        }
        row
    }

    /// Append one leaf; returns its leaf index. Updates every touched internal node so subsequent
    /// path queries reflect the current tree.
    pub fn append(&mut self, leaf: F) -> u64 {
        assert!(self.next_index < TREE_CAPACITY, "tree full");
        let leaf_index = self.next_index;
        let mut idx = leaf_index;
        let mut cur = leaf;
        self.nodes[0].insert(idx, cur);
        for lvl in 0..TREE_LEVELS {
            cur = merkle_compress(&self.cfg_tree, &self.row(lvl, idx));
            idx /= TREE_ARITY as u64;
            self.nodes[lvl + 1].insert(idx, cur);
        }
        self.next_index += 1;
        self.root = cur;
        leaf_index
    }

    /// (one full row per level, the walked node's slot in each row) for `index`, against the
    /// CURRENT tree — the shape `common::DenseTree::path` returns and the circuit consumes.
    pub fn path(&self, index: u64) -> (Vec<[F; TREE_ARITY]>, Vec<usize>) {
        let mut rows = Vec::with_capacity(TREE_LEVELS);
        let mut positions = Vec::with_capacity(TREE_LEVELS);
        let mut idx = index;
        for lvl in 0..TREE_LEVELS {
            rows.push(self.row(lvl, idx));
            positions.push((idx % TREE_ARITY as u64) as usize);
            idx /= TREE_ARITY as u64;
        }
        (rows, positions)
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
        let cfg_tree = poseidon_config_tree();
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(1);
        let mut mirror = MerkleMirror::new();
        let mut inc = IncrementalTree::new(&cfg_tree);
        let mut leaves: Vec<F> = Vec::new();
        for i in 0..200u64 {
            let note = Note { v: i, nk: F::rand(&mut rng), rho: F::rand(&mut rng), rcm: F::rand(&mut rng) };
            let cm = note.cm(&cfg);
            leaves.push(cm);
            let inc_root = inc.append(&cfg_tree, cm);
            let mir_root = {
                mirror.append(cm);
                mirror.root()
            };
            assert_eq!(inc_root, mir_root, "mirror vs IncrementalTree diverged at leaf {i}");
            let dense = DenseTree { leaves: leaves.clone() };
            assert_eq!(dense.root(&cfg_tree), mir_root, "mirror vs DenseTree diverged at leaf {i}");
        }
        // membership paths must equal the reference path and fold back to the current root.
        let dense = DenseTree { leaves: leaves.clone() };
        for &idx in &[0u64, 1, 2, 3, 4, 7, 42, 199] {
            let (rows, positions) = mirror.path(idx);
            assert_eq!((rows.clone(), positions.clone()), dense.path(&cfg_tree, idx as usize), "path mismatch at {idx}");
            let mut cur = leaves[idx as usize];
            for (row, pos) in rows.iter().zip(positions.iter()) {
                assert_eq!(row[*pos], cur, "walked node not in its row at {idx}");
                cur = merkle_compress(&cfg_tree, row);
            }
            assert_eq!(cur, mirror.root(), "path fold mismatch at {idx}");
        }
    }
}
