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
use common::{f_from_hex, f_to_hex, poseidon_config, zero_hashes, IncrementalTree, TREE_DEPTH};
use std::cell::RefCell;

thread_local! {
    static CFG: common::PoseidonCfg<F> = poseidon_config();
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
        filled: tree.filled.iter().map(f_to_hex).collect(),
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
    if state.filled.len() != TREE_DEPTH {
        return error("REJECT:frontier-length");
    }
    if leaves.is_empty() || leaves.len() > 2 {
        return error("REJECT:leaf-count");
    }
    if state.next_index > (1u64 << TREE_DEPTH) - leaves.len() as u64 {
        return error("REJECT:tree-full");
    }

    let filled: Option<Vec<F>> = state.filled.iter().map(|value| f_from_hex(value)).collect();
    let Some(filled) = filled else {
        return error("REJECT:frontier-field");
    };
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

ic_cdk::export_candid!();

