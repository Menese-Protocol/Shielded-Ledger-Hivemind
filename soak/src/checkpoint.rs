//! Crash-resumability: every ~5k ops the run persists the PocketIC instance
//! state to a state directory and the full reference model + planner RNG + counters to a
//! checkpoint file. On restart the run reloads both and continues from the last checkpoint, so an
//! environmental interruption on this shared box costs seconds instead of hours. Correctness is
//! unchanged: every operation is still verified against the canister live, and the final battery
//! runs over the complete stream.
//!
//! Field elements serialize as their 32-byte little-endian canonical form; the Merkle mirror and
//! the commitment/nullifier index maps are rebuilt from the note list on load, so they are not
//! stored.

use crate::crypto::{f_bytes, f_from_bytes, MerkleMirror};
use crate::model::{ExpectedBlock, Model, NoteRecord, PublicAmountEvent};
use ark_bls12_381::Fr as F;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet};

fn origin_to_u8(o: &str) -> u8 {
    match o {
        "shield" => 0,
        "confidential_transfer" => 1,
        _ => panic!("unknown origin {o}"),
    }
}
fn u8_to_origin(o: u8) -> &'static str {
    match o {
        0 => "shield",
        1 => "confidential_transfer",
        _ => panic!("bad origin byte"),
    }
}

#[derive(Serialize, Deserialize)]
struct NoteCp {
    leaf_index: u64,
    cm: [u8; 32],
    owner: usize,
    v: u64,
    rho: [u8; 32],
    rcm: [u8; 32],
    nf: [u8; 32],
    spent: bool,
}

#[derive(Serialize, Deserialize)]
struct BlockCp {
    origin: u8,
    commitment: [u8; 32],
    nullifiers: Vec<[u8; 32]>,
    anchor_before: [u8; 32],
    root_after: [u8; 32],
    actor: usize,
    output_note: usize,
}

#[derive(Serialize, Deserialize)]
struct AmountEvCp {
    value: u64,
    block_index: usize,
}

/// The full resumable state: model + planner state.
#[derive(Serialize, Deserialize)]
pub struct Checkpoint {
    pub seed: u64,
    pub accounts: usize,
    pub token_fee: u64,
    // env principals so resume can rebuild the Env against the reloaded state
    pub ledger: candid::Principal,
    pub token: candid::Principal,
    pub tree_oracle: candid::Principal,
    pub admin: candid::Principal,
    pub executed: u64,
    pub op_index: u64,
    pub upgrade_points: Vec<u64>,
    pub next_upgrade: usize,
    pub upgrades_done: Vec<u64>,
    pub last_recycle: u64,
    pub last_checkpoint_ops: u64,
    pub pauper_used: bool,
    pub rng: ChaCha20Rng,
    pub injection_counts: Vec<(u8, u64)>,
    pub counters: [u64; 7],
    pub report_injections_json: String,
    /// candid-encoded ct::TransferArgs of the last accepted private transfer (for ProofReplay)
    pub last_accepted_private: Option<Vec<u8>>,

    // model
    notes: Vec<NoteCp>,
    blocks: Vec<BlockCp>,
    historical_roots: Vec<[u8; 32]>,
    token_balances: Vec<u128>,
    pool_custody: u128,
    pool_value: u128,
    epoch: u64,
    cumulative_shield_in: u128,
    cumulative_unshield_out: u128,
    shield_events: Vec<AmountEvCp>,
    unshield_events: Vec<AmountEvCp>,
}

impl Checkpoint {
    pub fn from_model(model: &Model) -> ModelPart {
        ModelPart {
            notes: model
                .notes
                .iter()
                .map(|n| NoteCp {
                    leaf_index: n.leaf_index,
                    cm: f_bytes(&n.cm),
                    owner: n.owner,
                    v: n.v,
                    rho: f_bytes(&n.rho),
                    rcm: f_bytes(&n.rcm),
                    nf: f_bytes(&n.nf),
                    spent: n.spent,
                })
                .collect(),
            blocks: model
                .blocks
                .iter()
                .map(|b| BlockCp {
                    origin: origin_to_u8(b.origin),
                    commitment: b.commitment,
                    nullifiers: b.nullifiers.clone(),
                    anchor_before: b.anchor_before,
                    root_after: b.root_after,
                    actor: b.actor,
                    output_note: b.output_note,
                })
                .collect(),
            historical_roots: model.historical_roots.iter().copied().collect(),
            token_balances: model.token_balances.clone(),
            pool_custody: model.pool_custody,
            pool_value: model.pool_value,
            epoch: model.epoch,
            cumulative_shield_in: model.cumulative_shield_in,
            cumulative_unshield_out: model.cumulative_unshield_out,
            shield_events: model
                .shield_events
                .iter()
                .map(|e| AmountEvCp { value: e.value, block_index: e.block_index })
                .collect(),
            unshield_events: model
                .unshield_events
                .iter()
                .map(|e| AmountEvCp { value: e.value, block_index: e.block_index })
                .collect(),
        }
    }

    /// Rebuild the Model from the checkpoint (mirror + index maps reconstructed from notes).
    pub fn into_model(self, cfg: &common::PoseidonCfg<F>) -> Model {
        let mut notes = Vec::with_capacity(self.notes.len());
        let mut cm_to_note = HashMap::new();
        let mut nf_to_note = HashMap::new();
        let mut unspent_by_account = vec![BTreeSet::new(); self.accounts];
        // rebuild the Merkle mirror by appending commitments in leaf-index order
        let mut ordered: Vec<(u64, [u8; 32])> = self.notes.iter().map(|n| (n.leaf_index, n.cm)).collect();
        ordered.sort_by_key(|(li, _)| *li);
        let mut mirror = MerkleMirror::new(cfg);
        for (li, cm) in &ordered {
            let appended = mirror.append(cfg, f_from_bytes(cm).expect("cm bytes"));
            assert_eq!(appended, *li, "checkpoint: leaf index mismatch on mirror rebuild");
        }
        for (idx, n) in self.notes.iter().enumerate() {
            let rec = NoteRecord {
                leaf_index: n.leaf_index,
                cm: f_from_bytes(&n.cm).expect("cm"),
                owner: n.owner,
                v: n.v,
                rho: f_from_bytes(&n.rho).expect("rho"),
                rcm: f_from_bytes(&n.rcm).expect("rcm"),
                nf: f_from_bytes(&n.nf).expect("nf"),
                spent: n.spent,
            };
            cm_to_note.insert(n.cm, idx);
            nf_to_note.insert(n.nf, idx);
            if !n.spent {
                unspent_by_account[n.owner].insert(idx);
            }
            notes.push(rec);
        }
        let blocks: Vec<ExpectedBlock> = self
            .blocks
            .iter()
            .map(|b| ExpectedBlock {
                origin: u8_to_origin(b.origin),
                commitment: b.commitment,
                nullifiers: b.nullifiers.clone(),
                anchor_before: b.anchor_before,
                root_after: b.root_after,
                actor: b.actor,
                output_note: b.output_note,
            })
            .collect();
        let historical_roots: HashSet<[u8; 32]> = self.historical_roots.iter().copied().collect();
        Model {
            cfg: cfg.clone(),
            mirror,
            notes,
            cm_to_note,
            nf_to_note,
            unspent_by_account,
            blocks,
            historical_roots,
            token_balances: self.token_balances.clone(),
            pool_custody: self.pool_custody,
            pool_value: self.pool_value,
            epoch: self.epoch,
            token_fee: self.token_fee,
            cumulative_shield_in: self.cumulative_shield_in,
            cumulative_unshield_out: self.cumulative_unshield_out,
            shield_events: self
                .shield_events
                .iter()
                .map(|e| PublicAmountEvent { value: e.value, block_index: e.block_index })
                .collect(),
            unshield_events: self
                .unshield_events
                .iter()
                .map(|e| PublicAmountEvent { value: e.value, block_index: e.block_index })
                .collect(),
        }
    }
}

/// The model-derived half of a checkpoint (the runner fills in the rest).
pub struct ModelPart {
    pub notes: Vec<NoteCp>,
    pub blocks: Vec<BlockCp>,
    pub historical_roots: Vec<[u8; 32]>,
    pub token_balances: Vec<u128>,
    pub pool_custody: u128,
    pub pool_value: u128,
    pub epoch: u64,
    pub cumulative_shield_in: u128,
    pub cumulative_unshield_out: u128,
    pub shield_events: Vec<AmountEvCp>,
    pub unshield_events: Vec<AmountEvCp>,
}

impl ModelPart {
    #[allow(clippy::too_many_arguments)]
    pub fn into_checkpoint(
        self,
        seed: u64,
        accounts: usize,
        token_fee: u64,
        env: (candid::Principal, candid::Principal, candid::Principal, candid::Principal),
        executed: u64,
        op_index: u64,
        upgrade_points: Vec<u64>,
        next_upgrade: usize,
        upgrades_done: Vec<u64>,
        last_recycle: u64,
        last_checkpoint_ops: u64,
        pauper_used: bool,
        rng: ChaCha20Rng,
        injection_counts: Vec<(u8, u64)>,
        counters: [u64; 7],
        report_injections_json: String,
        last_accepted_private: Option<Vec<u8>>,
    ) -> Checkpoint {
        Checkpoint {
            seed,
            accounts,
            token_fee,
            ledger: env.0,
            token: env.1,
            tree_oracle: env.2,
            admin: env.3,
            executed,
            op_index,
            upgrade_points,
            next_upgrade,
            upgrades_done,
            last_recycle,
            last_checkpoint_ops,
            pauper_used,
            rng,
            injection_counts,
            counters,
            report_injections_json,
            last_accepted_private,
            notes: self.notes,
            blocks: self.blocks,
            historical_roots: self.historical_roots,
            token_balances: self.token_balances,
            pool_custody: self.pool_custody,
            pool_value: self.pool_value,
            epoch: self.epoch,
            cumulative_shield_in: self.cumulative_shield_in,
            cumulative_unshield_out: self.cumulative_unshield_out,
            shield_events: self.shield_events,
            unshield_events: self.unshield_events,
        }
    }
}

pub fn save(checkpoint: &Checkpoint, path: &std::path::Path) {
    let tmp = path.with_extension("tmp");
    let bytes = bincode::serialize(checkpoint).expect("serialize checkpoint");
    std::fs::write(&tmp, &bytes).expect("write checkpoint tmp");
    std::fs::rename(&tmp, path).expect("atomic rename checkpoint"); // atomic swap
}

pub fn load(path: &std::path::Path) -> Option<Checkpoint> {
    let bytes = std::fs::read(path).ok()?;
    bincode::deserialize(&bytes).ok()
}
