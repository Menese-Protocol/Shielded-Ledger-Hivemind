//! Stateless adapter over the circuit crate's read-only native Poseidon tree.
//!
//! This contains no pairing or proof-verification implementation. It converts a Candid frontier
//! into `common::IncrementalTree`, executes the exact hash code used by the circuit and its oracle,
//! and returns the next frontier. The Motoko ledger remains the sole state committer.

#[cfg(feature = "bls12-381")]
use ark_bls12_381::Fr as F;
#[cfg(not(feature = "bls12-381"))]
use ark_bn254::Fr as F;
use candid::{CandidType, Deserialize};
use common::{
    f_from_hex, f_to_hex, poseidon_config_tree, zero_hashes, IncrementalTree, TreeCfg, TREE_ARITY,
    TREE_CAPACITY, TREE_LEVELS,
};
use std::cell::RefCell;

/// Flat frontier length on the wire: `filled[lvl * TREE_ARITY + j]`, level-major then slot.
/// This is `src/PoseidonTree.mo`'s `FILLED_LEN`, and the two must stay equal — the Motoko ledger
/// is the sole state committer and this oracle only has to agree with it.
const FILLED_LEN: usize = TREE_LEVELS * TREE_ARITY;

thread_local! {
    // The TREE Poseidon instance (width 6, rate = TREE_ARITY), NOT the note/commitment
    // `poseidon_config()`. Wrapping the wrong one in a `TreeCfg` typechecks and then silently
    // anchors under the wrong permutation, which is the whole reason this is spelled out here.
    static CFG: TreeCfg = poseidon_config_tree();
    static ZEROS: RefCell<Option<Vec<F>>> = const { RefCell::new(None) };
}

#[derive(Clone, CandidType, Deserialize)]
struct TreeState {
    filled: Vec<String>,
    root: String,
    next_index: u64,
}

#[derive(CandidType, Deserialize)]
struct Transition {
    state: Option<TreeState>,
    error: Option<String>,
}

fn error(message: impl Into<String>) -> Transition {
    Transition { state: None, error: Some(message.into()) }
}

fn zeros() -> Vec<F> {
    ZEROS.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_none() {
            *slot = Some(CFG.with(zero_hashes));
        }
        slot.as_ref().unwrap().clone()
    })
}

fn external(tree: &IncrementalTree) -> TreeState {
    TreeState {
        // Flatten the per-level rows back to the level-major wire order.
        filled: tree.filled.iter().flatten().map(f_to_hex).collect(),
        root: f_to_hex(&tree.root),
        next_index: tree.next_index,
    }
}

#[ic_cdk::update]
fn empty() -> Transition {
    let tree = CFG.with(IncrementalTree::new);
    Transition { state: Some(external(&tree)), error: None }
}

#[ic_cdk::update]
fn append(state: TreeState, leaves: Vec<String>) -> Transition {
    if state.filled.len() != FILLED_LEN {
        return error("REJECT:frontier-length");
    }
    if leaves.is_empty() || leaves.len() > 2 {
        return error("REJECT:leaf-count");
    }
    if state.next_index > TREE_CAPACITY - leaves.len() as u64 {
        return error("REJECT:tree-full");
    }

    let flat: Option<Vec<F>> = state.filled.iter().map(|value| f_from_hex(value)).collect();
    let Some(flat) = flat else {
        return error("REJECT:frontier-field");
    };
    // Re-group the flat wire frontier into the per-level rows `IncrementalTree` walks. The length
    // was checked above, so every chunk is exactly TREE_ARITY wide and the unwrap cannot fire.
    let filled: Vec<[F; TREE_ARITY]> = flat
        .chunks_exact(TREE_ARITY)
        .map(|row| <[F; TREE_ARITY]>::try_from(row).unwrap())
        .collect();
    let Some(root) = f_from_hex(&state.root) else {
        return error("REJECT:root-field");
    };
    let parsed_leaves: Option<Vec<F>> = leaves.iter().map(|value| f_from_hex(value)).collect();
    let Some(parsed_leaves) = parsed_leaves else {
        return error("REJECT:leaf-field");
    };

    let mut tree = IncrementalTree {
        filled,
        zeros: zeros(),
        next_index: state.next_index,
        root,
    };
    CFG.with(|cfg| {
        for leaf in parsed_leaves {
            tree.append(cfg, leaf);
        }
    });
    Transition { state: Some(external(&tree)), error: None }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The flat wire frontier must be exactly `src/PoseidonTree.mo`'s `FILLED_LEN`. If the arity
    /// or level count ever moves again, this fails here rather than as a length rejection against
    /// a live ledger.
    #[test]
    fn wire_frontier_length_matches_the_motoko_ledger() {
        assert_eq!(FILLED_LEN, 64, "FILLED_LEN must equal LEVELS * ARITY = 16 * 4");
    }

    /// The flatten/re-group marshalling is the only logic this adapter owns; everything else is
    /// `common`'s tree. Appending through the Candid surface must land on the same root as
    /// appending directly to `IncrementalTree`, or the oracle disagrees with the ledger it exists
    /// to cross-check.
    #[test]
    fn candid_round_trip_agrees_with_the_native_tree() {
        let cfg = poseidon_config_tree();
        let leaves = [F::from(7u64), F::from(11u64), F::from(13u64)];

        // Direct: three appends straight onto the native tree.
        let mut native = IncrementalTree::new(&cfg);
        for leaf in leaves {
            native.append(&cfg, leaf);
        }

        // Through the wire: empty(), then one `append` call per leaf, re-marshalling each time.
        let mut state = match empty() {
            Transition { state: Some(state), .. } => state,
            other => panic!("empty() must succeed, got error {:?}", other.error),
        };
        assert_eq!(state.filled.len(), FILLED_LEN);
        for leaf in leaves {
            state = match append(state, vec![f_to_hex(&leaf)]) {
                Transition { state: Some(next), .. } => next,
                other => panic!("append must succeed, got error {:?}", other.error),
            };
        }

        assert_eq!(state.root, f_to_hex(&native.root), "root diverged across the wire");
        assert_eq!(state.next_index, native.next_index);
        let flat: Vec<String> = native.filled.iter().flatten().map(f_to_hex).collect();
        assert_eq!(state.filled, flat, "frontier diverged across the wire");
    }

    /// A frontier of the OLD binary-tree length must be refused, not silently re-grouped. This is
    /// the exact shape the pre-4-ary oracle served, so it is the one wrong input most likely to
    /// arrive.
    #[test]
    fn a_binary_tree_frontier_is_refused() {
        let stale = TreeState {
            filled: vec![f_to_hex(&F::from(0u64)); 32],
            root: f_to_hex(&F::from(0u64)),
            next_index: 0,
        };
        let out = append(stale, vec![f_to_hex(&F::from(1u64))]);
        assert_eq!(out.error.as_deref(), Some("REJECT:frontier-length"));
        assert!(out.state.is_none());
    }
}

ic_cdk::export_candid!();

