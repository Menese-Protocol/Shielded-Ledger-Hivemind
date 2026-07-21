//! The soak orchestrator: plans seeded random operation batches, proves them in parallel,
//! submits them sequentially, applies every accepted mutation to the reference model, asserts
//! the canister's reported state against the model after every operation, injects adversarial
//! operations that MUST be rejected, performs mid-run upgrades, and runs the full-population
//! verification battery at the end.
//!
//! Anchor discipline: the planner walks an evolving PLANNING MIRROR of the commitment tree and
//! extracts, for every transfer, the exact tree root (and membership paths) the canister will
//! hold when that op is submitted. Unshield finalization demands the CURRENT root as the proof
//! anchor (not merely a historical one), so predicted-at-planning anchors are what make batched
//! parallel proving sound.

use crate::candid_types as ct;
use crate::cert;
use crate::crypto::{f_bytes, MerkleMirror};
use crate::keys::Keyset;
use crate::model::{derive_accounts, AccountKeys, Model};
use crate::observer;
use crate::pic_env::{self, Env};
use crate::prover::{self, PreparedShield, PreparedTransfer, TransferPlanInput};
use crate::replayer;
use crate::scan;
use ark_bls12_381::Fr as F;
use ark_ff::UniformRand;
use candid::Principal;
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;
use serde::Serialize;
use std::collections::HashSet;
use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;

#[derive(Clone, Debug)]
pub struct TierConfig {
    pub label: String,
    pub accounts: usize,
    pub ops: usize,
    pub seed: u64,
    pub upgrades: usize,
    pub batch: usize,
    pub check_interval: usize,
    pub recycle_ops: usize,
    /// durable checkpoint cadence (ops). Each checkpoint persists PocketIC state + the model so a
    /// crash resumes from here. Also serves as the memory-recycle. 0 disables checkpointing.
    pub checkpoint_ops: usize,
    /// durable PocketIC state directory and model checkpoint file (for crash-resume).
    pub state_dir: PathBuf,
    pub checkpoint_file: PathBuf,
}

impl TierConfig {
    pub fn from_env() -> Self {
        let get = |k: &str, d: u64| -> u64 {
            std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d)
        };
        TierConfig {
            label: std::env::var("SOAK_LABEL").unwrap_or_else(|_| "smoke".into()),
            accounts: get("SOAK_ACCOUNTS", 200) as usize,
            ops: get("SOAK_OPS", 1000) as usize,
            seed: get("SOAK_SEED", 20260717),
            upgrades: get("SOAK_UPGRADES", 3) as usize,
            batch: get("SOAK_BATCH", 46) as usize,
            check_interval: get("SOAK_CHECK_INTERVAL", 1000) as usize,
            // pure in-process memory recycle (no durable persist). 0 disables; the durable
            // checkpoint below also recycles, so this is usually left 0.
            recycle_ops: get("SOAK_RECYCLE_OPS", 0) as usize,
            checkpoint_ops: get("SOAK_CHECKPOINT_OPS", 2000) as usize,
            state_dir: std::env::var("SOAK_STATE_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|_| {
                    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("checkpoints/state")
                }),
            checkpoint_file: std::env::var("SOAK_CHECKPOINT_FILE")
                .map(PathBuf::from)
                .unwrap_or_else(|_| {
                    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("checkpoints/model.ckpt")
                }),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize)]
pub enum InjectionClass {
    DoubleSpend,
    ProofReplay,
    ProofMutation,
    UnknownAnchor,
    WrongRecipientBinding,
    InsufficientAllowance,
    /// Zcash-2018 counterfeiting shape: claimed v_pub_out beyond the pool's total value; the
    /// turnstile must reject it BEFORE the verifier is consulted (verifier_outcome NOT_CALLED).
    CounterfeitMint,
}

pub const ALL_INJECTIONS: [InjectionClass; 7] = [
    InjectionClass::DoubleSpend,
    InjectionClass::ProofReplay,
    InjectionClass::ProofMutation,
    InjectionClass::UnknownAnchor,
    InjectionClass::WrongRecipientBinding,
    InjectionClass::InsufficientAllowance,
    InjectionClass::CounterfeitMint,
];

impl InjectionClass {
    fn to_u8(self) -> u8 {
        ALL_INJECTIONS.iter().position(|c| *c == self).unwrap() as u8
    }
    fn from_u8(b: u8) -> Self {
        ALL_INJECTIONS[b as usize]
    }
}

impl Counters {
    fn to_array(&self) -> [u64; 7] {
        [
            self.shields,
            self.private_transfers,
            self.unshields,
            self.fault_shield,
            self.fault_unshield,
            self.injections,
            self.injections_rejected,
        ]
    }
    fn from_array(a: [u64; 7]) -> Self {
        Counters {
            shields: a[0],
            private_transfers: a[1],
            unshields: a[2],
            fault_shield: a[3],
            fault_unshield: a[4],
            injections: a[5],
            injections_rejected: a[6],
        }
    }
}

enum PlannedOp {
    Shield { acct: usize, prepared: Box<PreparedShield> },
    Transfer { caller: usize, prepared: Box<PreparedTransfer> },
    FaultUnshield { caller: usize, prepared: Box<PreparedTransfer> },
    FaultShield { acct: usize, prepared: Box<PreparedShield> },
    Inject {
        class: InjectionClass,
        caller: usize,
        transfer: Option<Box<PreparedTransfer>>,
        shield: Option<Box<PreparedShield>>,
    },
}

use crate::prover::TransferCrypto;

enum Blueprint {
    Shield { acct: usize, v: u64, rho: F, rcm: F, fault: bool },
    Transfer { caller: usize, in1: usize, in2: usize, out_v: (u64, u64), recipient: usize, unshield: Option<u64>, fault: bool, crypto: Box<TransferCrypto> },
    InjectDoubleSpend { caller: usize, spent: usize, fresh: usize, crypto: Box<TransferCrypto> },
    InjectReplay,
    InjectMutation { caller: usize, in1: usize, in2: usize, crypto: Box<TransferCrypto> },
    InjectUnknownAnchor { caller: usize },
    InjectWrongBinding { caller: usize, in1: usize, in2: usize, v_pub: u64, bound_to: usize, crypto: Box<TransferCrypto> },
    InjectInsufficientAllowance { v: u64, rho: F, rcm: F },
    InjectCounterfeitMint { caller: usize, v_pub: u64, anchor: [u8; 32] },
}

struct PlannedJob {
    index: u64,
    bp: Blueprint,
}

#[derive(Serialize, serde::Deserialize, Clone)]
pub struct InjectionTranscript {
    pub class: String,
    pub op_index: u64,
    pub outcome: String,
    pub verifier_outcome: String,
    pub detail: String,
}

#[derive(Serialize)]
pub struct BatteryLine {
    pub item: String,
    pub verdict: String,
}

#[derive(Serialize)]
pub struct RunReport {
    pub label: String,
    pub seed: u64,
    pub accounts: usize,
    pub ops_requested: usize,
    pub ops_executed: u64,
    pub accepted_shields: u64,
    pub accepted_private_transfers: u64,
    pub accepted_unshields: u64,
    pub fault_recoveries_shield: u64,
    pub fault_recoveries_unshield: u64,
    pub injections_total: u64,
    pub injections_rejected: u64,
    pub injection_counts: Vec<(String, u64)>,
    pub injection_transcripts: Vec<InjectionTranscript>,
    pub upgrades_performed: u64,
    pub upgrade_positions: Vec<u64>,
    pub blocks: u64,
    pub notes_created: u64,
    pub notes_spent: u64,
    pub final_pool_value: u128,
    pub final_custody: u128,
    pub total_unspent_value: u128,
    pub state_hash: String,
    pub wall_clock_seconds: f64,
    pub ledger_wasm_sha256: String,
    pub token_wasm_sha256: String,
    pub tree_oracle_wasm_sha256: String,
    pub moc_version: String,
    pub battery: Vec<BatteryLine>,
}

fn now_stamp() -> String {
    let d = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap();
    format!("t{}", d.as_secs())
}

fn gib(n: &candid::Nat) -> f64 {
    u128::try_from(n.0.clone()).expect("rts counter fits u128") as f64 / (1u64 << 30) as f64
}

/// Directory holding atomic checkpoint pairs, next to the legacy checkpoint file.
fn pairs_root(checkpoint_file: &std::path::Path) -> std::path::PathBuf {
    checkpoint_file.with_file_name(format!(
        "{}-pairs",
        checkpoint_file.file_name().expect("checkpoint file name").to_string_lossy()
    ))
}

/// Remove all committed `pair-<op>` dirs except the `keep` with the highest op.
fn prune_pairs(root: &std::path::Path, keep: usize) {
    let Ok(entries) = std::fs::read_dir(root) else { return };
    let mut ops: Vec<(u64, std::path::PathBuf)> = entries
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            let op = name.strip_prefix("pair-")?.parse::<u64>().ok()?;
            Some((op, e.path()))
        })
        .collect();
    ops.sort_by_key(|(op, _)| std::cmp::Reverse(*op));
    for (_, path) in ops.into_iter().skip(keep) {
        let _ = std::fs::remove_dir_all(path);
    }
}

/// Locate the newest atomic checkpoint pair, set the crashed live state dir aside for
/// forensics, and materialize the pair's state snapshot as the live state dir — so canister
/// state and model agree by construction. Falls back to the legacy single checkpoint file
/// (paired with the live state dir, the pre-pair layout) when no pair exists.
fn prepare_resume(tier: &TierConfig) -> Option<crate::checkpoint::Checkpoint> {
    let root = pairs_root(&tier.checkpoint_file);
    if let Ok(name) = std::fs::read_to_string(root.join("LATEST")) {
        let pair = root.join(name.trim());
        let model = pair.join("model.ckpt");
        let state = pair.join("state");
        if model.is_file() && state.is_dir() {
            if let Some(ckpt) = crate::checkpoint::load(&model) {
                let crashed = tier.state_dir.with_file_name(format!(
                    "{}-crashed",
                    tier.state_dir.file_name().expect("state dir name").to_string_lossy()
                ));
                let _ = std::fs::remove_dir_all(&crashed);
                if tier.state_dir.exists() {
                    std::fs::rename(&tier.state_dir, &crashed).expect("set aside crashed state dir");
                }
                pic_env::copy_dir_recursive(&state, &tier.state_dir);
                println!(
                    "[resume] materialized live state from atomic pair {} (crashed live dir set aside)",
                    pair.display()
                );
                return Some(ckpt);
            }
        }
        println!("[resume] LATEST pair incomplete or unreadable; trying legacy checkpoint file");
    }
    crate::checkpoint::load(&tier.checkpoint_file)
}

pub struct Runner {
    pub tier: TierConfig,
    pub keys: Keyset,
    pub env: Env,
    pub model: Model,
    pub accounts: Vec<AccountKeys>,
    pub cfg: common::PoseidonCfg<F>,
    rng: ChaCha20Rng,
    op_index: u64,
    last_accepted_private: Option<ct::TransferArgs>,
    pauper: AccountKeys,
    pauper_used: bool,
    pub report_injections: Vec<InjectionTranscript>,
    pub injection_counts: std::collections::HashMap<InjectionClass, u64>,
    pub counters: Counters,
    upgrade_points: Vec<u64>,
    pub upgrades_done: Vec<u64>,
    progress_path: Option<String>,
    fixture_proof_hex: String,
    pub resumed_from: u64,
    executed_start: u64,
    next_upgrade_start: usize,
    pub started: Instant,
}

#[derive(Default)]
pub struct Counters {
    pub shields: u64,
    pub private_transfers: u64,
    pub unshields: u64,
    pub fault_shield: u64,
    pub fault_unshield: u64,
    pub injections: u64,
    pub injections_rejected: u64,
}

const INITIAL_BALANCE: u128 = 1 << 45;
const ALLOWANCE: u128 = 1 << 60;

impl Runner {
    pub fn new(tier: TierConfig, keys: Keyset, wasms: &pic_env::BuiltWasms) -> Self {
        let cfg = common::poseidon_config();
        let accounts = derive_accounts(tier.seed, tier.accounts, &cfg);
        let pauper = derive_accounts(tier.seed.wrapping_add(0xdead), tier.accounts + 1, &cfg)
            .pop()
            .unwrap();
        let fixture_proof_hex = std::fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .join("fixtures/pool-vectors-bls12-381/transfer_proof.hex"),
        )
        .expect("read fixture transfer proof")
        .trim()
        .to_string();

        // RESUME PATH: a matching checkpoint (same seed) means a prior process was interrupted.
        if tier.checkpoint_ops > 0 {
            if let Some(ckpt) = prepare_resume(&tier) {
                if ckpt.seed == tier.seed && ckpt.accounts == tier.accounts {
                    println!(
                        "[resume] found checkpoint at op {} (seed {}); reloading PocketIC state + model...",
                        ckpt.executed, ckpt.seed
                    );
                    let env = pic_env::resume(
                        &tier.state_dir,
                        ckpt.ledger,
                        ckpt.token,
                        ckpt.tree_oracle,
                        ckpt.admin,
                        ckpt.token_fee,
                        wasms.ledger.clone(),
                    );
                    // reconstruct the runner state from the checkpoint
                    let rng = ckpt.rng.clone();
                    let op_index = ckpt.op_index;
                    let executed = ckpt.executed;
                    let upgrade_points = ckpt.upgrade_points.clone();
                    let next_upgrade = ckpt.next_upgrade;
                    let upgrades_done = ckpt.upgrades_done.clone();
                    let pauper_used = ckpt.pauper_used;
                    let counters = Counters::from_array(ckpt.counters);
                    let injection_counts: std::collections::HashMap<InjectionClass, u64> = ckpt
                        .injection_counts
                        .iter()
                        .map(|(b, c)| (InjectionClass::from_u8(*b), *c))
                        .collect();
                    let report_injections: Vec<InjectionTranscript> =
                        serde_json::from_str(&ckpt.report_injections_json).unwrap_or_default();
                    let last_accepted_private = ckpt
                        .last_accepted_private
                        .as_ref()
                        .map(|b| candid::decode_one::<ct::TransferArgs>(b).expect("decode replay args"));
                    let model = ckpt.into_model(&cfg);
                    let runner = Runner {
                        fixture_proof_hex,
                        progress_path: std::env::var("SOAK_PROGRESS_LOG").ok(),
                        resumed_from: executed,
                        tier,
                        keys,
                        env,
                        model,
                        accounts,
                        cfg,
                        rng,
                        op_index,
                        last_accepted_private,
                        pauper,
                        pauper_used,
                        report_injections,
                        injection_counts,
                        counters,
                        upgrade_points,
                        upgrades_done,
                        executed_start: executed,
                        next_upgrade_start: next_upgrade,
                        started: Instant::now(),
                    };
                    // consistency: the reloaded canister must agree with the reloaded model
                    let status = runner.env.ledger_status();
                    let cn = u64::try_from(status.note_count.0.clone()).unwrap();
                    assert_eq!(
                        cn,
                        runner.model.blocks.len() as u64,
                        "resume: canister note_count {cn} != model blocks {}. Checkpoint inconsistent.",
                        runner.model.blocks.len()
                    );
                    assert_eq!(
                        status.note_root.as_slice(),
                        f_bytes(&runner.model.mirror.root()).as_slice(),
                        "resume: canister note_root != model mirror root"
                    );
                    println!("[resume] consistent at op {executed}: note_count {cn}, root matches.");
                    return runner;
                }
            }
        }

        // FRESH PATH: clear any stale durable state, set up, and fund.
        let _ = std::fs::remove_file(&tier.checkpoint_file);
        let _ = std::fs::remove_dir_all(&tier.state_dir);
        let _ = std::fs::remove_dir_all(pairs_root(&tier.checkpoint_file));
        std::fs::create_dir_all(&tier.state_dir).expect("create state dir");
        std::fs::create_dir_all(tier.checkpoint_file.parent().unwrap()).ok();
        let env = pic_env::setup(wasms, &keys.transfer_vk_hex, &keys.deposit_vk_hex, &tier.state_dir);
        let principals: Vec<Principal> = accounts.iter().map(|a| a.principal).collect();
        println!("[setup] funding {} accounts on the token fixture...", principals.len());
        let t0 = Instant::now();
        pic_env::fund_accounts(&env, &principals, INITIAL_BALANCE, ALLOWANCE);
        pic_env::fund_accounts(&env, &[pauper.principal], INITIAL_BALANCE, 1);
        println!("[setup] funded in {:.1}s", t0.elapsed().as_secs_f64());

        let model = Model::new(tier.accounts, INITIAL_BALANCE, env.token_fee);
        let mut rng = prover::op_rng(tier.seed, u64::MAX, "runner");
        let lo = (tier.ops as u64 / 10).max(1);
        let hi = (tier.ops as u64).max(lo + 1);
        let mut upgrade_points: Vec<u64> = (0..tier.upgrades)
            .map(|_| rng.gen_range(lo..hi))
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        upgrade_points.sort();
        println!("[setup] upgrade points at ops {upgrade_points:?}");
        Runner {
            fixture_proof_hex,
            progress_path: std::env::var("SOAK_PROGRESS_LOG").ok(),
            resumed_from: 0,
            tier,
            keys,
            env,
            model,
            accounts,
            cfg,
            rng,
            op_index: 0,
            last_accepted_private: None,
            pauper,
            pauper_used: false,
            report_injections: Vec::new(),
            injection_counts: Default::default(),
            counters: Default::default(),
            upgrade_points,
            upgrades_done: Vec::new(),
            executed_start: 0,
            next_upgrade_start: 0,
            started: Instant::now(),
        }
    }

    /// Persist a durable checkpoint as an ATOMIC PAIR: while the instance is dropped mid-recycle
    /// (state dir flushed and quiescent), snapshot the state dir into `pair-<op>/state`, then
    /// write the model + planner state to `pair-<op>/model.ckpt` and flip the `LATEST` pointer.
    /// The live state dir keeps advancing after this returns; pairing IT with a model file is
    /// exactly the Jul-18 wedge (canister ahead of model, resume assert loops forever) — resume
    /// loads the pair instead. Returns the recycle+snapshot wall-time.
    fn checkpoint(&mut self, executed: u64, next_upgrade: usize, last_recycle: u64, last_checkpoint: u64) -> f64 {
        let t = Instant::now();
        let root = pairs_root(&self.tier.checkpoint_file);
        let pair_tmp = root.join(format!("pair-{executed}.tmp"));
        let pair_dir = root.join(format!("pair-{executed}"));
        let _ = std::fs::remove_dir_all(&pair_tmp);
        std::fs::create_dir_all(&pair_tmp).expect("create pair tmp dir");
        // recycle persists the PocketIC instance to the durable state dir and frees server
        // memory; the snapshot is taken inside the drop-rebuild window
        self.env
            .recycle_with_snapshot(Some((&self.tier.state_dir, &pair_tmp.join("state"))));
        let model_part = crate::checkpoint::Checkpoint::from_model(&self.model);
        let last_private = self
            .last_accepted_private
            .as_ref()
            .map(|a| candid::encode_one(a).expect("encode replay args"));
        let injection_counts: Vec<(u8, u64)> = self
            .injection_counts
            .iter()
            .map(|(k, v)| (k.to_u8(), *v))
            .collect();
        let ckpt = model_part.into_checkpoint(
            self.tier.seed,
            self.tier.accounts,
            self.env.token_fee,
            (self.env.ledger, self.env.token, self.env.tree_oracle, self.env.admin),
            executed,
            self.op_index,
            self.upgrade_points.clone(),
            next_upgrade,
            self.upgrades_done.clone(),
            last_recycle,
            last_checkpoint,
            self.pauper_used,
            self.rng.clone(),
            injection_counts,
            self.counters.to_array(),
            serde_json::to_string(&self.report_injections).unwrap(),
            last_private,
        );
        crate::checkpoint::save(&ckpt, &pair_tmp.join("model.ckpt"));
        // legacy single-file location too, for older tooling that inspects it
        crate::checkpoint::save(&ckpt, &self.tier.checkpoint_file);
        let _ = std::fs::remove_dir_all(&pair_dir);
        std::fs::rename(&pair_tmp, &pair_dir).expect("commit checkpoint pair");
        let latest_tmp = root.join("LATEST.tmp");
        std::fs::write(&latest_tmp, format!("pair-{executed}")).expect("write LATEST.tmp");
        std::fs::rename(&latest_tmp, root.join("LATEST")).expect("commit LATEST");
        prune_pairs(&root, 2);
        t.elapsed().as_secs_f64()
    }

    fn progress(&self, line: &str) {
        println!("[{}] {}", now_stamp(), line);
        if let Some(path) = &self.progress_path {
            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
                let _ = writeln!(f, "- {} soak[{}] {}", now_stamp(), self.tier.label, line);
            }
        }
    }

    /// Pick an account owning >= 2 unspent, unreserved notes visible in the snapshot, plus two
    /// such notes. Randomized with bounded retries; None when the population cannot support it.
    /// Pick an account owning >= 2 unspent, unreserved notes, plus two such notes.
    fn pick_two(&mut self, reserved: &HashSet<usize>) -> Option<(usize, usize, usize)> {
        let n = self.accounts.len();
        for _ in 0..32 {
            let a = self.rng.gen_range(0..n);
            let notes: Vec<usize> = self.model.unspent_by_account[a]
                .iter()
                .copied()
                .filter(|i| !reserved.contains(i))
                .collect();
            if notes.len() >= 2 {
                let i1 = notes[self.rng.gen_range(0..notes.len())];
                let mut i2 = i1;
                while i2 == i1 {
                    i2 = notes[self.rng.gen_range(0..notes.len())];
                }
                return Some((a, i1, i2));
            }
        }
        None
    }

    /// Anchor + membership paths + output rcm draws for a transfer proved at this batch
    /// position: extracted from the planning mirror BEFORE the op's own outputs are appended,
    /// so the anchor equals the exact tree root the canister will hold at submission.
    fn transfer_crypto(&self, planning: &MerkleMirror, in1: usize, in2: usize, index: u64) -> Box<TransferCrypto> {
        let mut prng = prover::op_rng(self.tier.seed, index, "transfer-plan");
        let out_rcm1 = F::rand(&mut prng);
        let out_rcm2 = F::rand(&mut prng);
        Box::new(TransferCrypto {
            anchor: planning.root(),
            path1: planning.path(self.model.notes[in1].leaf_index),
            path2: planning.path(self.model.notes[in2].leaf_index),
            out_rcm1,
            out_rcm2,
        })
    }

    /// Plan a shield and append its predicted commitment to the planning mirror.
    fn plan_shield(&mut self, index: u64, planning: &mut MerkleMirror) -> Blueprint {
        let acct = self.rng.gen_range(0..self.accounts.len());
        let v = self.rng.gen_range(100_000..10_000_000);
        let mut prng = prover::op_rng(self.tier.seed, index, "shield-plan");
        let rho = F::rand(&mut prng);
        let rcm = F::rand(&mut prng);
        let cm = common::note_commitment(&self.cfg, v, self.accounts[acct].pk, rho, rcm);
        planning.append(&self.cfg, cm);
        let fault = self.rng.gen_bool(0.005);
        Blueprint::Shield { acct, v, rho, rcm, fault }
    }

    /// Plan a full batch against an evolving planning mirror. Accepted ops append their
    /// predicted commitments; injections (always rejected) append nothing.
    fn plan_batch(&mut self, want: usize) -> Vec<PlannedJob> {
        let mut planning = self.model.mirror.clone();
        let mut reserved: HashSet<usize> = HashSet::new();
        let mut jobs = Vec::with_capacity(want);
        let fee = self.env.token_fee;
        let batch_pool_value = self.model.pool_value;
        for _ in 0..want {
            let index = self.op_index;
            self.op_index += 1;
            let roll: f64 = self.rng.gen();
            let bp = if roll < 0.10 {
                self.plan_injection(index, &mut planning, &mut reserved, batch_pool_value)
            } else if roll < 0.42 {
                self.plan_shield(index, &mut planning)
            } else if roll < 0.86 {
                match self.pick_two(&reserved) {
                    Some((a, i1, i2)) => {
                        let total = self.model.notes[i1].v + self.model.notes[i2].v;
                        let v1 = self.rng.gen_range(0..=total);
                        let recipient = self.rng.gen_range(0..self.accounts.len());
                        reserved.insert(i1);
                        reserved.insert(i2);
                        let crypto = self.transfer_crypto(&planning, i1, i2, index);
                        let out_v = (v1, total - v1);
                        let cm1 = common::note_commitment(
                            &self.cfg, out_v.0, self.accounts[recipient].pk,
                            self.model.notes[i1].nf, crypto.out_rcm1,
                        );
                        let cm2 = common::note_commitment(
                            &self.cfg, out_v.1, self.accounts[a].pk,
                            self.model.notes[i2].nf, crypto.out_rcm2,
                        );
                        planning.append(&self.cfg, cm1);
                        planning.append(&self.cfg, cm2);
                        Blueprint::Transfer {
                            caller: a, in1: i1, in2: i2, out_v, recipient,
                            unshield: None, fault: false, crypto,
                        }
                    }
                    None => self.plan_shield(index, &mut planning),
                }
            } else {
                match self.pick_two(&reserved) {
                    Some((a, i1, i2)) => {
                        let total = self.model.notes[i1].v + self.model.notes[i2].v;
                        if total <= fee + 1 {
                            self.plan_shield(index, &mut planning)
                        } else {
                            let v_pub = self.rng.gen_range(1..=(total - fee));
                            let change = total - fee - v_pub;
                            let v1 = self.rng.gen_range(0..=change);
                            reserved.insert(i1);
                            reserved.insert(i2);
                            let fault = self.rng.gen_bool(0.01);
                            let crypto = self.transfer_crypto(&planning, i1, i2, index);
                            let out_v = (v1, change - v1);
                            let cm1 = common::note_commitment(
                                &self.cfg, out_v.0, self.accounts[a].pk,
                                self.model.notes[i1].nf, crypto.out_rcm1,
                            );
                            let cm2 = common::note_commitment(
                                &self.cfg, out_v.1, self.accounts[a].pk,
                                self.model.notes[i2].nf, crypto.out_rcm2,
                            );
                            planning.append(&self.cfg, cm1);
                            planning.append(&self.cfg, cm2);
                            Blueprint::Transfer {
                                caller: a, in1: i1, in2: i2, out_v, recipient: a,
                                unshield: Some(v_pub), fault, crypto,
                            }
                        }
                    }
                    None => self.plan_shield(index, &mut planning),
                }
            };
            jobs.push(PlannedJob { index, bp });
        }
        jobs
    }

    fn plan_injection(
        &mut self,
        index: u64,
        planning: &mut MerkleMirror,
        reserved: &mut HashSet<usize>,
        batch_pool_value: u128,
    ) -> Blueprint {
        let n = self.accounts.len();
        let mut classes: Vec<InjectionClass> =
            vec![InjectionClass::UnknownAnchor, InjectionClass::CounterfeitMint];
        let spent_notes: Vec<usize> = self
            .model
            .notes
            .iter()
            .enumerate()
            .filter(|(_, note)| note.spent)
            .map(|(i, _)| i)
            .collect();
        let fresh_note = self
            .model
            .notes
            .iter()
            .enumerate()
            .find(|(i, note)| !note.spent && !reserved.contains(i))
            .map(|(i, _)| i);
        if !spent_notes.is_empty() && fresh_note.is_some() {
            classes.push(InjectionClass::DoubleSpend);
        }
        if self.last_accepted_private.is_some() {
            classes.push(InjectionClass::ProofReplay);
        }
        if !self.pauper_used {
            classes.push(InjectionClass::InsufficientAllowance);
        }
        let two = self.pick_two(reserved);
        if two.is_some() {
            classes.push(InjectionClass::ProofMutation);
            classes.push(InjectionClass::WrongRecipientBinding);
        }
        // bias toward the least-exercised class so every class accumulates evidence
        classes.sort_by_key(|c| self.injection_counts.get(c).copied().unwrap_or(0));
        match classes[0] {
            InjectionClass::DoubleSpend => {
                let spent = spent_notes[self.rng.gen_range(0..spent_notes.len())];
                let fresh = fresh_note.unwrap();
                let crypto = self.transfer_crypto(planning, spent, fresh, index);
                Blueprint::InjectDoubleSpend {
                    caller: self.model.notes[spent].owner,
                    spent,
                    fresh,
                    crypto,
                }
            }
            InjectionClass::ProofReplay => Blueprint::InjectReplay,
            InjectionClass::ProofMutation => {
                let (a, i1, i2) = two.unwrap();
                reserved.insert(i1);
                reserved.insert(i2);
                let crypto = self.transfer_crypto(planning, i1, i2, index);
                Blueprint::InjectMutation { caller: a, in1: i1, in2: i2, crypto }
            }
            InjectionClass::UnknownAnchor => {
                Blueprint::InjectUnknownAnchor { caller: self.rng.gen_range(0..n) }
            }
            InjectionClass::WrongRecipientBinding => {
                let (a, i1, i2) = two.unwrap();
                let fee = self.env.token_fee;
                let total = self.model.notes[i1].v + self.model.notes[i2].v;
                if total <= fee + 1 {
                    return Blueprint::InjectUnknownAnchor { caller: a };
                }
                reserved.insert(i1);
                reserved.insert(i2);
                let crypto = self.transfer_crypto(planning, i1, i2, index);
                Blueprint::InjectWrongBinding {
                    caller: a,
                    in1: i1,
                    in2: i2,
                    v_pub: self.rng.gen_range(1..=(total - fee)),
                    bound_to: (a + 1) % n,
                    crypto,
                }
            }
            InjectionClass::InsufficientAllowance => {
                self.pauper_used = true;
                let mut prng = prover::op_rng(self.tier.seed, index, "shield-plan");
                let rho = F::rand(&mut prng);
                let rcm = F::rand(&mut prng);
                Blueprint::InjectInsufficientAllowance {
                    v: self.rng.gen_range(100_000..10_000_000),
                    rho,
                    rcm,
                }
            }
            InjectionClass::CounterfeitMint => {
                // A payout claim beyond everything ever shielded in, padded past anything the
                // rest of this batch can add. The anchor is the predicted current root, so the
                // turnstile is provably the guard that fires (verifier_outcome NOT_CALLED).
                let v_pub = u64::try_from(batch_pool_value + 1_000_000_000)
                    .expect("pool value fits u64");
                Blueprint::InjectCounterfeitMint {
                    caller: self.rng.gen_range(0..n),
                    v_pub,
                    anchor: f_bytes(&planning.root()),
                }
            }
        }
    }

    fn prove_batch(&mut self, jobs: Vec<PlannedJob>) -> Vec<PlannedOp> {
        let seed = self.tier.seed;
        let cfg = &self.cfg;
        let keys = &self.keys;
        let accounts = &self.accounts;
        let pauper = &self.pauper;
        let model = &self.model;
        let env_token_fee = self.env.token_fee;
        let last_private = self.last_accepted_private.clone();
        let ledger = self.env.ledger;
        let token = self.env.token;
        let fixture_proof_hex = &self.fixture_proof_hex;

        let binding_for = move |owner: Principal| -> [u8; 32] {
            use crate::icrc3_hash::{blob_v, hash_value, text};
            let value = ct::Value::Map(vec![
                ("domain".into(), text("picp-unshield-recipient/v1")),
                ("pool".into(), blob_v(ledger.as_slice().to_vec())),
                ("token".into(), blob_v(token.as_slice().to_vec())),
                ("owner".into(), blob_v(owner.as_slice().to_vec())),
            ]);
            let mut digest = hash_value(&value);
            digest[31] = 0;
            digest
        };
        let plan_input = |idx: usize| -> TransferPlanInput {
            let note = &model.notes[idx];
            TransferPlanInput {
                note_index: idx,
                leaf_index: note.leaf_index,
                v: note.v,
                nk: accounts[note.owner].nk,
                rho: note.rho,
                rcm: note.rcm,
            }
        };

        jobs.into_par_iter()
            .map(|job| {
                let PlannedJob { index, bp } = job;
                match bp {
                    Blueprint::Shield { acct, v, rho, rcm, fault } => {
                        let prepared = Box::new(prover::prepare_shield(
                            cfg, &keys.deposit_pk, &accounts[acct], v, rho, rcm, seed, index,
                        ));
                        if fault {
                            PlannedOp::FaultShield { acct, prepared }
                        } else {
                            PlannedOp::Shield { acct, prepared }
                        }
                    }
                    Blueprint::Transfer { caller, in1, in2, out_v, recipient, unshield, fault, crypto } => {
                        let i1 = plan_input(in1);
                        let i2 = plan_input(in2);
                        let (fee, v_pub, binding, recipient_account, recipient_idx) = match unshield {
                            Some(v_pub) => (
                                env_token_fee,
                                v_pub,
                                binding_for(accounts[caller].principal),
                                Some(ct::Account { owner: accounts[caller].principal, subaccount: None }),
                                Some(caller),
                            ),
                            None => (0u64, 0u64, [0u8; 32], None, None),
                        };
                        let out1_owner = if unshield.is_some() { &accounts[caller] } else { &accounts[recipient] };
                        let prepared = prover::prepare_transfer(
                            cfg, &keys.transfer_pk, &crypto, (&i1, &i2),
                            (out1_owner, &accounts[caller]), out_v,
                            fee, v_pub, binding, recipient_account, recipient_idx,
                            seed, index,
                        );
                        if fault && unshield.is_some() {
                            PlannedOp::FaultUnshield { caller, prepared: Box::new(prepared) }
                        } else {
                            PlannedOp::Transfer { caller, prepared: Box::new(prepared) }
                        }
                    }
                    Blueprint::InjectDoubleSpend { caller, spent, fresh, crypto } => {
                        let i1 = plan_input(spent);
                        let i2 = plan_input(fresh);
                        let total = i1.v + i2.v;
                        let prepared = prover::prepare_transfer(
                            cfg, &keys.transfer_pk, &crypto, (&i1, &i2),
                            (&accounts[caller], &accounts[caller]), (total, 0),
                            0, 0, [0u8; 32], None, None, seed, index,
                        );
                        PlannedOp::Inject { class: InjectionClass::DoubleSpend, caller, transfer: Some(Box::new(prepared)), shield: None }
                    }
                    Blueprint::InjectReplay => {
                        let args = last_private.clone().expect("replay planned without prior transfer");
                        PlannedOp::Inject {
                            class: InjectionClass::ProofReplay,
                            caller: 0,
                            transfer: Some(Box::new(PreparedTransfer {
                                args,
                                in_notes: (usize::MAX, usize::MAX),
                                outs: [(0, 0, F::from(0u64), F::from(0u64)), (0, 0, F::from(0u64), F::from(0u64))],
                                recipient_acct: None,
                                anchor: [0u8; 32],
                            })),
                            shield: None,
                        }
                    }
                    Blueprint::InjectMutation { caller, in1, in2, crypto } => {
                        let i1 = plan_input(in1);
                        let i2 = plan_input(in2);
                        let total = i1.v + i2.v;
                        let mut prepared = prover::prepare_transfer(
                            cfg, &keys.transfer_pk, &crypto, (&i1, &i2),
                            (&accounts[caller], &accounts[caller]), (total, 0),
                            0, 0, [0u8; 32], None, None, seed, index,
                        );
                        let mut bytes = hex::decode(&prepared.args.proof_hex).unwrap();
                        let pos = (index as usize).wrapping_mul(37) % bytes.len();
                        bytes[pos] ^= 0x01;
                        prepared.args.proof_hex = hex::encode(bytes);
                        PlannedOp::Inject { class: InjectionClass::ProofMutation, caller, transfer: Some(Box::new(prepared)), shield: None }
                    }
                    Blueprint::InjectUnknownAnchor { caller } => {
                        let mut rng = prover::op_rng(seed, index, "fake-tree");
                        let mut fake = MerkleMirror::new(cfg);
                        let fn1 = common::Note { v: 1_000_000, nk: accounts[caller].nk, rho: F::rand(&mut rng), rcm: F::rand(&mut rng) };
                        let fn2 = common::Note { v: 500_000, nk: accounts[caller].nk, rho: F::rand(&mut rng), rcm: F::rand(&mut rng) };
                        let l1 = fake.append(cfg, fn1.cm(cfg));
                        let l2 = fake.append(cfg, fn2.cm(cfg));
                        let mut prng = prover::op_rng(seed, index, "fake-tree-plan");
                        let crypto = TransferCrypto {
                            anchor: fake.root(),
                            path1: fake.path(l1),
                            path2: fake.path(l2),
                            out_rcm1: F::rand(&mut prng),
                            out_rcm2: F::rand(&mut prng),
                        };
                        let i1 = TransferPlanInput { note_index: usize::MAX, leaf_index: l1, v: fn1.v, nk: fn1.nk, rho: fn1.rho, rcm: fn1.rcm };
                        let i2 = TransferPlanInput { note_index: usize::MAX, leaf_index: l2, v: fn2.v, nk: fn2.nk, rho: fn2.rho, rcm: fn2.rcm };
                        let prepared = prover::prepare_transfer(
                            cfg, &keys.transfer_pk, &crypto, (&i1, &i2),
                            (&accounts[caller], &accounts[caller]), (1_400_000, 100_000),
                            0, 0, [0u8; 32], None, None, seed, index,
                        );
                        PlannedOp::Inject { class: InjectionClass::UnknownAnchor, caller, transfer: Some(Box::new(prepared)), shield: None }
                    }
                    Blueprint::InjectWrongBinding { caller, in1, in2, v_pub, bound_to, crypto } => {
                        let i1 = plan_input(in1);
                        let i2 = plan_input(in2);
                        let total = i1.v + i2.v;
                        let change = total - env_token_fee - v_pub;
                        // proof bound to `bound_to`'s account; submitted with recipient = caller
                        let prepared = prover::prepare_transfer(
                            cfg, &keys.transfer_pk, &crypto, (&i1, &i2),
                            (&accounts[caller], &accounts[caller]), (change, 0),
                            env_token_fee, v_pub,
                            binding_for(accounts[bound_to].principal),
                            Some(ct::Account { owner: accounts[caller].principal, subaccount: None }),
                            Some(caller),
                            seed, index,
                        );
                        PlannedOp::Inject { class: InjectionClass::WrongRecipientBinding, caller, transfer: Some(Box::new(prepared)), shield: None }
                    }
                    Blueprint::InjectInsufficientAllowance { v, rho, rcm } => {
                        let prepared = prover::prepare_shield(cfg, &keys.deposit_pk, pauper, v, rho, rcm, seed, index);
                        PlannedOp::Inject { class: InjectionClass::InsufficientAllowance, caller: usize::MAX, transfer: None, shield: Some(Box::new(prepared)) }
                    }
                    Blueprint::InjectCounterfeitMint { caller, v_pub, anchor } => {
                        let mut rng = prover::op_rng(seed, index, "counterfeit");
                        let nf1 = F::rand(&mut rng);
                        let nf2 = F::rand(&mut rng);
                        let cm1 = F::rand(&mut rng);
                        let cm2 = F::rand(&mut rng);
                        let args = ct::TransferArgs {
                            anchor: ct::blob(anchor.to_vec()),
                            nullifier_1: ct::blob(f_bytes(&nf1).to_vec()),
                            nullifier_2: ct::blob(f_bytes(&nf2).to_vec()),
                            output_1: ct::OutputRecord {
                                commitment: ct::blob(f_bytes(&cm1).to_vec()),
                                ephemeral_key: ct::blob(vec![1u8; 16]),
                                note_ciphertext: ct::blob(vec![1u8; 112]),
                            },
                            output_2: ct::OutputRecord {
                                commitment: ct::blob(f_bytes(&cm2).to_vec()),
                                ephemeral_key: ct::blob(vec![1u8; 16]),
                                note_ciphertext: ct::blob(vec![1u8; 112]),
                            },
                            fee: env_token_fee,
                            v_pub_out: v_pub,
                            recipient: Some(ct::Account { owner: accounts[caller].principal, subaccount: None }),
                            created_at_time: None, // stamped at submission
                            proof_hex: fixture_proof_hex.clone(),
                        };
                        PlannedOp::Inject {
                            class: InjectionClass::CounterfeitMint,
                            caller,
                            transfer: Some(Box::new(PreparedTransfer {
                                args,
                                in_notes: (usize::MAX, usize::MAX),
                                outs: [(0, 0, F::from(0u64), F::from(0u64)), (0, 0, F::from(0u64), F::from(0u64))],
                                recipient_acct: None,
                                anchor,
                            })),
                            shield: None,
                        }
                    }
                }
            })
            .collect()
    }

    fn assert_state_matches(&self, m: &ct::MutationResult, context: &str) {
        let root = f_bytes(&self.model.mirror.root());
        assert_eq!(m.note_root.as_slice(), root.as_slice(), "{context}: note_root diverged from model");
        assert_eq!(
            u64::try_from(m.note_count.0.clone()).unwrap(),
            self.model.blocks.len() as u64,
            "{context}: note_count diverged"
        );
        assert_eq!(
            u64::try_from(m.nullifier_count.0.clone()).unwrap(),
            self.model.spent_count() as u64,
            "{context}: nullifier_count diverged"
        );
        assert_eq!(
            u128::try_from(m.pool_value.0.clone()).unwrap(),
            self.model.pool_value,
            "{context}: pool_value diverged"
        );
        assert_eq!(u64::try_from(m.epoch.0.clone()).unwrap(), self.model.epoch, "{context}: epoch diverged");
    }

    fn submit(&mut self, op: PlannedOp) {
        match op {
            PlannedOp::Shield { acct, prepared } => {
                let mut args = prepared.args.clone();
                args.created_at_time = self.env.time_ns();
                let m: ct::MutationResult = self
                    .env
                    .update(self.env.ledger, self.accounts[acct].principal, "shield", (args,))
                    .expect("shield call");
                assert_eq!(m.outcome, "ACCEPT", "shield rejected: {} / {}", m.outcome, m.verifier_outcome);
                let keys = self.accounts[acct].clone();
                self.model.apply_shield(&keys, prepared.v, prepared.rho, prepared.rcm);
                self.assert_state_matches(&m, "shield");
                self.counters.shields += 1;
            }
            PlannedOp::FaultShield { acct, prepared } => {
                let ok: ct::MotokoResult<()> = self
                    .env
                    .update(self.env.ledger, self.env.admin, "test_arm_fail_after_token_once", ())
                    .expect("arm fault");
                ok.into_result().expect("arm fault result");
                let mut args = prepared.args.clone();
                args.created_at_time = self.env.time_ns();
                let r: Result<ct::MutationResult, String> =
                    self.env.update(self.env.ledger, self.accounts[acct].principal, "shield", (args,));
                let err = r.err().expect("armed shield must trap after the token call");
                assert!(err.contains("TEST_ONLY:fail-after-token"), "unexpected trap: {err}");
                let m: ct::MutationResult = self
                    .env
                    .update(self.env.ledger, self.accounts[acct].principal, "resume_shield", ())
                    .expect("resume_shield");
                assert_eq!(m.outcome, "ACCEPT", "resume_shield: {}", m.outcome);
                let keys = self.accounts[acct].clone();
                self.model.apply_shield(&keys, prepared.v, prepared.rho, prepared.rcm);
                self.assert_state_matches(&m, "resume_shield");
                self.counters.fault_shield += 1;
            }
            PlannedOp::Transfer { caller, prepared } => {
                let mut args = prepared.args.clone();
                if args.v_pub_out > 0 {
                    args.created_at_time = Some(self.env.time_ns());
                }
                let is_private = args.v_pub_out == 0;
                let m: ct::MutationResult = self
                    .env
                    .update(self.env.ledger, self.accounts[caller].principal, "confidential_transfer", (args.clone(),))
                    .expect("confidential_transfer call");
                assert_eq!(m.outcome, "ACCEPT", "transfer rejected: {} / {}", m.outcome, m.verifier_outcome);
                let outs = [
                    (prepared.outs[0].0, prepared.outs[0].1, prepared.outs[0].3),
                    (prepared.outs[1].0, prepared.outs[1].1, prepared.outs[1].3),
                ];
                self.model.apply_transfer(
                    prepared.in_notes.0,
                    prepared.in_notes.1,
                    outs,
                    args.fee,
                    args.v_pub_out,
                    prepared.recipient_acct,
                    prepared.anchor,
                    &self.accounts,
                );
                self.assert_state_matches(&m, "transfer");
                if is_private {
                    self.last_accepted_private = Some(args);
                    self.counters.private_transfers += 1;
                } else {
                    self.counters.unshields += 1;
                }
            }
            PlannedOp::FaultUnshield { caller, prepared } => {
                let ok: ct::MotokoResult<()> = self
                    .env
                    .update(self.env.ledger, self.env.admin, "test_arm_fail_after_token_once", ())
                    .expect("arm fault");
                ok.into_result().expect("arm fault result");
                let mut args = prepared.args.clone();
                args.created_at_time = Some(self.env.time_ns());
                let r: Result<ct::MutationResult, String> = self.env.update(
                    self.env.ledger,
                    self.accounts[caller].principal,
                    "confidential_transfer",
                    (args.clone(),),
                );
                let err = r.err().expect("armed unshield must trap after the token call");
                assert!(err.contains("TEST_ONLY:fail-after-token"), "unexpected trap: {err}");
                let m: ct::MutationResult = self
                    .env
                    .update(self.env.ledger, self.accounts[caller].principal, "resume_unshield", ())
                    .expect("resume_unshield");
                assert_eq!(m.outcome, "ACCEPT", "resume_unshield: {}", m.outcome);
                let outs = [
                    (prepared.outs[0].0, prepared.outs[0].1, prepared.outs[0].3),
                    (prepared.outs[1].0, prepared.outs[1].1, prepared.outs[1].3),
                ];
                self.model.apply_transfer(
                    prepared.in_notes.0,
                    prepared.in_notes.1,
                    outs,
                    args.fee,
                    args.v_pub_out,
                    prepared.recipient_acct,
                    prepared.anchor,
                    &self.accounts,
                );
                self.assert_state_matches(&m, "resume_unshield");
                self.counters.fault_unshield += 1;
            }
            PlannedOp::Inject { class, caller, transfer, shield } => {
                self.counters.injections += 1;
                let (outcome, verifier_outcome) = if let Some(prepared) = transfer {
                    let mut args = prepared.args.clone();
                    if args.v_pub_out > 0 {
                        args.created_at_time = Some(self.env.time_ns());
                    }
                    let sender = if caller == usize::MAX { self.env.admin } else { self.accounts[caller].principal };
                    let m: ct::MutationResult = self
                        .env
                        .update(self.env.ledger, sender, "confidential_transfer", (args,))
                        .expect("injection call");
                    (m.outcome, m.verifier_outcome)
                } else {
                    let prepared = shield.expect("injection carries either transfer or shield");
                    let mut args = prepared.args.clone();
                    args.created_at_time = self.env.time_ns();
                    let m: ct::MutationResult = self
                        .env
                        .update(self.env.ledger, self.pauper.principal, "shield", (args,))
                        .expect("injection shield call");
                    (m.outcome, m.verifier_outcome)
                };
                let ok = match class {
                    InjectionClass::DoubleSpend | InjectionClass::ProofReplay => outcome == "REJECT:nullifier-spent",
                    InjectionClass::UnknownAnchor => outcome == "REJECT:unknown-anchor",
                    InjectionClass::InsufficientAllowance => outcome == "REJECT:token:InsufficientAllowance",
                    InjectionClass::CounterfeitMint => {
                        outcome == "REJECT:turnstile" && verifier_outcome == "NOT_CALLED"
                    }
                    InjectionClass::ProofMutation | InjectionClass::WrongRecipientBinding => {
                        outcome.starts_with("REJECT:")
                            && (outcome.contains("pairing") || outcome.contains("deserialize") || outcome.contains("hex"))
                    }
                };
                assert!(
                    ok,
                    "injection {class:?} was not rejected as expected: outcome={outcome} verifier={verifier_outcome}"
                );
                let status = self.env.ledger_status();
                assert_eq!(
                    u64::try_from(status.epoch.0.clone()).unwrap(),
                    self.model.epoch,
                    "injection {class:?} changed the epoch"
                );
                assert_eq!(
                    status.note_root.as_slice(),
                    f_bytes(&self.model.mirror.root()).as_slice(),
                    "injection {class:?} changed the note root"
                );
                self.counters.injections_rejected += 1;
                *self.injection_counts.entry(class).or_insert(0) += 1;
                if self.report_injections.iter().filter(|t| t.class == format!("{class:?}")).count() < 1 {
                    self.report_injections.push(InjectionTranscript {
                        class: format!("{class:?}"),
                        op_index: self.op_index,
                        outcome,
                        verifier_outcome,
                        detail: "state unchanged (epoch + note_root asserted)".into(),
                    });
                }
            }
        }
    }

    pub fn cheap_invariants(&self) {
        let status = self.env.ledger_status();
        assert_eq!(status.note_root.as_slice(), f_bytes(&self.model.mirror.root()).as_slice(), "interval: root");
        assert_eq!(u64::try_from(status.note_count.0.clone()).unwrap(), self.model.blocks.len() as u64, "interval: note_count");
        assert_eq!(u64::try_from(status.nullifier_count.0.clone()).unwrap(), self.model.spent_count() as u64, "interval: nullifiers");
        assert_eq!(u128::try_from(status.pool_value.0.clone()).unwrap(), self.model.pool_value, "interval: pool_value");
        assert_eq!(u64::try_from(status.epoch.0.clone()).unwrap(), self.model.epoch, "interval: epoch");
        let custody = self.env.token_balance(&self.env.pool_account());
        assert_eq!(custody, self.model.pool_custody, "interval: token custody");
        assert_eq!(self.model.pool_value, self.model.total_unspent(), "interval: pool_value == unspent notes");
        // A2 conservation: the pool can never pay out more than was shielded in.
        assert_eq!(
            self.model.pool_value,
            self.model.cumulative_shield_in - self.model.cumulative_unshield_out,
            "interval: pool_value == cumulative in - cumulative out"
        );
    }

    fn audit_status(&self) -> ct::AuditStatus {
        self.env
            .query(self.env.ledger, "audit_status", ())
            .expect("audit_status query")
    }

    /// audit_status, tolerating a module that predates the audit (a checkpoint resumed
    /// with the OLD wasm still installed — the state upgrade #1 starts from). Returns
    /// None exactly when the method does not exist; any other failure still panics.
    fn try_audit_status(&self) -> Option<ct::AuditStatus> {
        match self.env.query::<ct::AuditStatus>(self.env.ledger, "audit_status", ()) {
            Ok(s) => Some(s),
            Err(e) if e.contains("no query method") || e.contains("does not exist") => None,
            Err(e) => panic!("audit_status query: {e}"),
        }
    }

    /// Drive PocketIC rounds until the background audit reaches a terminal state, with a
    /// HARD BOUND committed up front (bounded-verification: a stalled tick chain must
    /// fail the run loudly, never hang the poll). Returns the terminal status.
    fn await_audit_terminal(&self, label: &str) -> ct::AuditStatus {
        let notes = u64::try_from(self.env.ledger_status().note_count.0.clone()).unwrap();
        // K=4096 notes/chunk + one chunk per set/log phase + margin; each chunk needs a
        // handful of rounds (timer tick + self-call + reply). 16 ticks/chunk is ~5x the
        // observed need; the bound exists to convert a dead tick chain into a loud panic.
        let max_ticks = (notes / 4_096 + 16) * 16 + 256;
        let mut ticks: u64 = 0;
        loop {
            let status = self.audit_status();
            match status.state {
                ct::AuditState::running => {}
                _ => return status,
            }
            if ticks >= max_ticks {
                panic!(
                    "audit poll bound exhausted ({label}): {max_ticks} ticks, still running at phase {:?} cursor {} of {} (epoch {}, retries {}) — tick chain presumed dead",
                    status.phase, status.cursor, status.total, status.audit_epoch, status.chunk_retries
                );
            }
            if ticks % 64 == 0 {
                self.progress(&format!(
                    "audit poll ({label}): phase {:?} cursor {}/{} epoch {}",
                    status.phase, status.cursor, status.total, status.audit_epoch
                ));
            }
            self.env.pic().advance_time(std::time::Duration::from_secs(1));
            self.env.pic().tick();
            ticks += 1;
        }
    }

    fn upgrade(&mut self, at_op: u64) {
        let rts = self.env.ledger_rts();
        self.progress(&format!(
            "upgrade #{} at op {} STARTING (mode upgrade, same wasm) | pre-upgrade rts: mem {:.2}GiB heap {:.2}GiB max-live {:.2}GiB",
            self.upgrades_done.len() + 1,
            at_op,
            gib(&rts.memory_size),
            gib(&rts.heap_size),
            gib(&rts.max_live_size)
        ));
        // DRAIN: an open audit-chunk self-call makes the moc EOP runtime reject the
        // upgrade ("canister_pre_upgrade attempted with outstanding message callbacks",
        // TX probe). The audit must be terminal before install_code. A pre-existing
        // FAIL is ledger-implicated: stop loudly. A module that PREDATES the audit
        // (old-wasm checkpoint, upgrade #1 of a resumed run) has no audit and no open
        // contexts — nothing to drain.
        match self.try_audit_status() {
            None => self.progress("pre-upgrade drain: installed module predates the audit (old wasm) — nothing to drain"),
            Some(_) => {
                let drained = self.await_audit_terminal("pre-upgrade drain");
                if let ct::AuditState::fail { code, index } = &drained.state {
                    panic!("audit FAILED before upgrade #{}: {code} at index {index}", self.upgrades_done.len() + 1);
                }
            }
        }
        let pre = self.env.ledger_status();
        // moc 1.4.1 compiles with enhanced orthogonal persistence: the upgrade must carry
        // wasm_memory_persistence = keep (the state-preserving option; `replace` would wipe).
        self.env
            .pic()
            .upgrade_eop_canister(self.env.ledger, self.env.ledger_wasm.clone(), candid::encode_args(()).unwrap(), Some(self.env.admin))
            .unwrap_or_else(|e| panic!("upgrade failed: {e:?}"));
        // free any WASM chunk storage the upgrade left resident
        let _ = self.env.pic().clear_chunk_store(self.env.ledger, Some(self.env.admin));
        // COMMITTED postupgrade cost bounds (the fix's contract): the old full walk cost
        // ~3.0M instr + 180KB alloc PER NOTE (154B instr / 9.3GB at 51,411 notes — the
        // measured OOM wall). The bounded postupgrade decodes ONE block: 2B instructions
        // and 256 MiB heap growth are ~75x/~36x under the old wall at this tier and
        // catch any O(n) regression loudly.
        let stats: ct::PostupgradeStats = self
            .env
            .query(self.env.ledger, "postupgrade_stats", ())
            .expect("postupgrade_stats");
        assert!(
            stats.instructions < 2_000_000_000,
            "postupgrade used {} instructions — O(n) regression (bound 2B)",
            stats.instructions
        );
        let heap_before = u128::try_from(stats.heap_before.0.clone()).unwrap();
        let heap_after = u128::try_from(stats.heap_after.0.clone()).unwrap();
        let heap_delta = heap_after.saturating_sub(heap_before);
        assert!(
            heap_delta < 256 * 1024 * 1024,
            "postupgrade heap delta {heap_delta}B — allocation regression (bound 256MiB)"
        );
        let post = self.env.ledger_status();
        assert_eq!(pre.note_root, post.note_root, "upgrade lost note_root");
        assert_eq!(pre.note_count, post.note_count, "upgrade lost note_count");
        assert_eq!(pre.nullifier_count, post.nullifier_count, "upgrade lost nullifiers");
        assert_eq!(pre.pool_value, post.pool_value, "upgrade lost pool_value");
        assert_eq!(pre.epoch, post.epoch, "upgrade lost epoch");
        // bounded O(k) validation answers immediately (the full walk is the audit's job)
        let validated: ct::MotokoResult<candid::Reserved> = self
            .env
            .query(self.env.ledger, "validate_stable_state", ())
            .expect("validate_stable_state");
        validated.into_result().expect("stable state invalid after upgrade");
        // SAME end-to-end assurance as the old blocking walk, amortized: poll the
        // background audit to completion and require PASS before declaring the upgrade
        // complete. Instructions/alloc stay bounded PER MESSAGE; the verdict is whole-state.
        let audited = self.await_audit_terminal("post-upgrade audit");
        match &audited.state {
            ct::AuditState::pass => {}
            other => panic!(
                "audit did not PASS after upgrade #{}: {other:?}",
                self.upgrades_done.len() + 1
            ),
        }
        self.cheap_invariants();
        self.progress(&format!(
            "upgrade #{} complete, audit PASS (epoch {}), invariants green | postupgrade {} instr, heap delta {}B",
            self.upgrades_done.len() + 1,
            audited.audit_epoch,
            stats.instructions,
            heap_delta
        ));
        self.upgrades_done.push(at_op);
    }

    pub fn run(&mut self) -> u64 {
        let mut executed: u64 = self.executed_start;
        let total = self.tier.ops as u64;
        let mut next_upgrade = self.next_upgrade_start;
        let mut last_checkpoint = executed;
        let mut last_recycle = executed;
        let mut last_durable_ckpt = executed;
        let mut upgrade_since_recycle = false;
        if self.resumed_from > 0 {
            self.progress(&format!("resumed at op {} of {total}", self.resumed_from));
        }
        while executed < total {
            let want = self.tier.batch.min((total - executed) as usize);
            let plan = self.plan_batch(want);
            let t0 = Instant::now();
            let ops = self.prove_batch(plan);
            let proving = t0.elapsed().as_secs_f64();
            let t1 = Instant::now();
            let count = ops.len() as u64;
            for op in ops {
                if std::env::var("SOAK_TRACE").is_ok() {
                    let kind = match &op {
                        PlannedOp::Shield { .. } => "shield".to_string(),
                        PlannedOp::FaultShield { .. } => "fault-shield".to_string(),
                        PlannedOp::Transfer { prepared, .. } => {
                            if prepared.args.v_pub_out > 0 { "unshield".to_string() } else { "private".to_string() }
                        }
                        PlannedOp::FaultUnshield { .. } => "fault-unshield".to_string(),
                        PlannedOp::Inject { class, .. } => format!("inject:{class:?}"),
                    };
                    println!("[trace] op {} = {kind}", executed + 1);
                }
                self.submit(op);
                executed += 1;
                if next_upgrade < self.upgrade_points.len() && executed >= self.upgrade_points[next_upgrade] {
                    self.upgrade(executed);
                    next_upgrade += 1;
                    upgrade_since_recycle = true;
                }
                if executed % self.tier.check_interval as u64 == 0 {
                    self.cheap_invariants();
                }
            }
            let submitting = t1.elapsed().as_secs_f64();
            // pure in-process recycle (memory only), if configured separately from checkpointing
            let interval_due = self.tier.recycle_ops > 0
                && executed / self.tier.recycle_ops as u64 > last_recycle / self.tier.recycle_ops as u64;
            if executed < total && (interval_due || upgrade_since_recycle) {
                let t = Instant::now();
                self.env.recycle();
                last_recycle = executed;
                upgrade_since_recycle = false;
                self.cheap_invariants();
                self.progress(&format!("recycled instance at op {executed} in {:.1}s (server memory freed, recycle #{})", t.elapsed().as_secs_f64(), self.env.recycles));
            }
            // DURABLE CHECKPOINT: persist PocketIC state + model so a crash resumes from here.
            let ckpt_due = self.tier.checkpoint_ops > 0
                && executed / self.tier.checkpoint_ops as u64 > last_durable_ckpt / self.tier.checkpoint_ops as u64;
            if executed < total && (ckpt_due || (upgrade_since_recycle && self.tier.checkpoint_ops > 0)) {
                let secs = self.checkpoint(executed, next_upgrade, last_recycle, last_checkpoint);
                last_durable_ckpt = executed;
                upgrade_since_recycle = false;
                self.cheap_invariants();
                let rts = self.env.ledger_rts();
                self.progress(&format!(
                    "durable checkpoint at op {executed} in {secs:.1}s (state persisted, resumable) | ledger rts: mem {:.2}GiB heap {:.2}GiB max-live {:.2}GiB alloc {:.1}GiB reclaimed {:.1}GiB",
                    gib(&rts.memory_size),
                    gib(&rts.heap_size),
                    gib(&rts.max_live_size),
                    gib(&rts.total_allocation),
                    gib(&rts.reclaimed)
                ));
            }
            if executed - last_checkpoint >= 5000 || executed >= total {
                let rate = executed as f64 / self.started.elapsed().as_secs_f64();
                self.progress(&format!(
                    "{executed}/{total} ops | last batch {count}: prove {proving:.1}s submit {submitting:.1}s | avg {rate:.2} ops/s | notes {} spent {} pool {}",
                    self.model.notes.len(),
                    self.model.spent_count(),
                    self.model.pool_value
                ));
                last_checkpoint = executed;
            }
        }
        while next_upgrade < self.upgrade_points.len() {
            self.upgrade(executed);
            next_upgrade += 1;
        }
        self.cheap_invariants();
        executed
    }

    /// Full-population final verification. Returns battery lines + the deterministic state hash
    /// + block count.
    pub fn verify_full(&self) -> (Vec<BatteryLine>, String, u64) {
        let mut battery: Vec<BatteryLine> = Vec::new();
        let push = |battery: &mut Vec<BatteryLine>, item: &str, verdict: String| {
            println!("[battery] {item}: {verdict}");
            battery.push(BatteryLine { item: item.into(), verdict });
        };
        let t0 = Instant::now();
        self.progress("final verification: fetching complete block log...");
        let blocks = replayer::fetch_all_blocks(&self.env);
        // Behavior-identity dump: every SEMANTIC block field on `SEM` lines,
        // the timing-derived fields (timestamp; phash/hash, which chain over timestamps) on
        // `TIME` lines. Two runs of DIFFERENT wasms on a DTS chain cannot see identical
        // `Time.now()` (round counts differ with instruction counts), so the identity contract
        // is: all SEM lines byte-identical; TIME lines may differ only in the timing channel.
        if let Ok(path) = std::env::var("SOAK_DUMP_BLOCKS") {
            use std::io::Write;
            let mut fh = std::fs::File::create(&path).expect("create block dump");
            for b in &blocks {
                writeln!(
                    fh,
                    "SEM {} {} v{} cm {} eph {} ct {} nfs {} anchor {} root {} origin {}",
                    b.position,
                    b.btype,
                    b.encoding_version,
                    hex::encode(b.commitment),
                    hex::encode(&b.ephemeral_key),
                    hex::encode(&b.note_ciphertext),
                    b.nullifiers.iter().map(hex::encode).collect::<Vec<_>>().join(","),
                    hex::encode(b.anchor_before),
                    hex::encode(b.note_root_after),
                    origin = b.origin,
                )
                .unwrap();
                writeln!(
                    fh,
                    "TIME {} ts {} phash {} hash {}",
                    b.position,
                    b.timestamp,
                    b.phash.map(hex::encode).unwrap_or_default(),
                    hex::encode(b.hash)
                )
                .unwrap();
            }
            writeln!(fh, "SEM semantic-state-hash {}", self.model.state_hash(b"")).unwrap();
            writeln!(fh, "SEM block-count {}", blocks.len()).unwrap();
            writeln!(fh, "SEM note-root {}", hex::encode(f_bytes(&self.model.mirror.root()))).unwrap();
            writeln!(fh, "SEM pool-value {} epoch {}", self.model.pool_value, self.model.epoch).unwrap();
        }
        self.progress(&format!("fetched {} blocks in {:.1}s", blocks.len(), t0.elapsed().as_secs_f64()));

        // model vs actual block log, field by field
        assert_eq!(blocks.len(), self.model.blocks.len(), "block count vs model");
        for (i, (actual, expected)) in blocks.iter().zip(self.model.blocks.iter()).enumerate() {
            assert_eq!(actual.commitment, expected.commitment, "block {i} commitment");
            assert_eq!(actual.origin, expected.origin, "block {i} origin");
            assert_eq!(actual.nullifiers, expected.nullifiers, "block {i} nullifiers");
            assert_eq!(actual.anchor_before, expected.anchor_before, "block {i} anchor_before");
            assert_eq!(actual.note_root_after, expected.root_after, "block {i} root_after");
        }
        push(&mut battery, "B2-block-log-vs-model", format!("PASS ({} blocks field-identical)", blocks.len()));

        // independent replayer: phash chain + tree + balances
        let t1 = Instant::now();
        let replay = replayer::replay(&blocks, &self.accounts);
        self.progress(&format!(
            "replayer: {} blocks ({} shields, {} transfers), full phash chain verified in {:.1}s",
            replay.block_count, replay.shield_ops, replay.transfer_ops, t1.elapsed().as_secs_f64()
        ));
        assert_eq!(replay.final_root, f_bytes(&self.model.mirror.root()), "replayer final root vs model");
        push(&mut battery, "B3/B7-replayer-phash-chain",
            format!("PASS ({} links verified across {} upgrades)", replay.block_count, self.upgrades_done.len()));

        // B3: full-population balances, two independent proofs, all N accounts
        let t2 = Instant::now();
        let model_balances: Vec<u128> = (0..self.accounts.len()).map(|a| self.model.balance_of(a)).collect();
        let scan_balances = scan::wallet_scan_balances(&self.cfg, &self.accounts, &blocks);
        for a in 0..model_balances.len() {
            assert_eq!(scan_balances[a], model_balances[a], "B3 wallet-scan balance mismatch account {a}");
            assert_eq!(replay.balances[a], model_balances[a], "B3 replayer balance mismatch account {a}");
        }
        self.progress(&format!(
            "B3 full population: wallet scan + replayer agree with model on all {} accounts ({:.1}s)",
            model_balances.len(), t2.elapsed().as_secs_f64()
        ));
        push(&mut battery, "B3-full-population-balances",
            format!("PASS (all {} accounts, wallet scan + independent replayer)", model_balances.len()));

        // B4 solvency, from model and from replayer
        let custody = self.env.token_balance(&self.env.pool_account());
        let status = self.env.ledger_status();
        let pool_value = u128::try_from(status.pool_value.0.clone()).unwrap();
        assert_eq!(custody, self.model.pool_custody, "B4: custody vs model");
        assert_eq!(pool_value, self.model.total_unspent(), "B4: pool_value vs model unspent");
        assert_eq!(custody, pool_value, "B4: custody vs pool_value");
        assert_eq!(replay.total_unspent, custody, "B4: replayer unspent vs custody");
        push(&mut battery, "B4-solvency",
            format!("PASS (custody == pool_value == unspent == {custody}, model + replayer)"));

        // A2 cumulative conservation at final state
        assert_eq!(
            pool_value,
            self.model.cumulative_shield_in - self.model.cumulative_unshield_out,
            "A2: pool_value != cumulative shields - cumulative unshields"
        );
        push(&mut battery, "A2-conservation",
            format!("PASS (pool_value == {} shielded in - {} paid out)",
                self.model.cumulative_shield_in, self.model.cumulative_unshield_out));

        // B6 certificate, bound to the replayer's independently computed tip hash
        let tip: Option<ct::DataCertificate> = self
            .env
            .query(self.env.ledger, "icrc3_get_tip_certificate", ())
            .expect("tip certificate");
        let tip = tip.expect("tip certificate present");
        let root_key = self.env.pic().root_key().expect("PocketIC root key");
        let archive_manifest = crate::icrc3_hash::hash_value(&ct::Value::Array(vec![])).to_vec();
        let replayer_tip_hash = replay.last_block_hash.expect("chain nonempty");
        // explicit B3<->B6 bind: the canister's certified snapshot must carry the same tip hash
        // the replayer computed from the raw stream
        let snapshot: ct::CertifiedSnapshot = self
            .env
            .query(self.env.ledger, "certified_snapshot", ())
            .expect("certified_snapshot");
        assert_eq!(
            snapshot.last_block_hash.as_ref().map(|b| b.as_slice()),
            Some(replayer_tip_hash.as_slice()),
            "B6: certified last_block_hash != replayer chain tip"
        );
        // the certified audit leaf: assert the audit is PASS, then expect its digest —
        // the ICRC-3 map hash of {state: "pass"} — computed INDEPENDENTLY here
        let audit = self.audit_status();
        assert!(
            matches!(audit.state, ct::AuditState::pass),
            "B6: audit not PASS at certification time: {:?}",
            audit.state
        );
        let audit_digest = crate::icrc3_hash::hash_value(&ct::Value::Map(vec![(
            "state".into(),
            crate::icrc3_hash::text("pass"),
        )]))
        .to_vec();
        let tuple = cert::ExpectedTuple {
            tip_index: blocks.len() as u64 - 1,
            tip_hash: replayer_tip_hash,
            note_count: blocks.len() as u64,
            note_root: f_bytes(&self.model.mirror.root()),
            encoding_version: 1,
            archive_manifest,
            audit_digest,
        };
        let report = cert::verify_tip_certificate(
            &tip.certificate,
            &tip.hash_tree,
            &self.env.ledger,
            &root_key,
            &tuple,
            self.env.time_ns() as u128,
        )
        .expect("B6 certificate verification");
        assert!(
            report.valid
                && report.signature_mutant_rejected
                && report.wrong_root_key_rejected
                && report.note_root_witness_mutant_rejected,
            "B6 negative controls failed"
        );
        push(&mut battery, "B6-certification",
            "PASS (root-key verified, tip bound to replayer chain hash, 3 tamper controls rejected)".into());

        // B5 injection summary
        for class in ALL_INJECTIONS {
            let count = self.injection_counts.get(&class).copied().unwrap_or(0);
            assert!(count > 0, "B5: injection class {class:?} never exercised");
        }
        assert_eq!(self.counters.injections, self.counters.injections_rejected, "B5: some injection was not rejected");
        push(&mut battery, "B5-adversarial-injections",
            format!("PASS ({} injected, 100% rejected, all {} classes exercised)",
                self.counters.injections, ALL_INJECTIONS.len()));

        // B7 count part: the tier's configured upgrade count must all have landed (the full
        // tier configures >= 3; smoke tiers may configure fewer — the requirement is the
        // tier's, not a hard-coded 3, so a 1-upgrade smoke doesn't fail its own battery)
        assert!(
            self.upgrades_done.len() >= self.tier.upgrades,
            "B7: {} upgrades performed, tier requires {}",
            self.upgrades_done.len(),
            self.tier.upgrades
        );
        push(&mut battery, "B7-upgrades-under-load",
            format!("PASS ({} upgrades at ops {:?})", self.upgrades_done.len(), self.upgrades_done));

        // B10: keyless-observer leakage audit
        let t3 = Instant::now();
        let amounts = observer::confidential_amounts_from_keyed_scan(&self.cfg, &self.accounts, &blocks);
        let mut principals: Vec<Principal> = self.accounts.iter().map(|a| a.principal).collect();
        principals.push(self.pauper.principal);
        let leak = observer::keyless_leakage_audit(&blocks, &amounts, &principals);
        observer::assert_no_leakage(&leak, replay.recognized_notes);
        self.progress(&format!(
            "B10 keyless observer: {} amount needles + {} principals over {} blocks, 0 hits; {} adversary keys recognized 0 notes ({:.1}s)",
            leak.amount_needles, leak.principal_needles, leak.blocks_scanned,
            leak.adversary_keys_tried, t3.elapsed().as_secs_f64()
        ));
        push(&mut battery, "B10-keyless-observer",
            format!(
                "PASS (0/{} amount hits, 0 principal hits, keyless recognized 0 vs keyed {})",
                leak.amount_needles, replay.recognized_notes
            ));

        // B11: statistical correlation / cryptanalysis audit
        let t4 = Instant::now();
        let link = crate::linkage::run_audit(&self.model);
        self.progress(&format!(
            "B11 linkage: (a) nf->cm {} samples mean-percentile {:.4} top1 {:.5} (chance {:.5}); (b) same-account balanced-acc {:.4} over {} pairs; (c) amount unique-match {:.3} CI[{:.3},{:.3}] over {} unshields; (d) timing-adjacency {:.4} vs chance {:.4} ({:.1}s)",
            link.nf_cm_samples, link.nf_cm_mean_percentile, link.nf_cm_top1_rate, link.nf_cm_chance_top1,
            link.same_acct_balanced_acc, link.same_acct_samples,
            link.amount_unique_match_rate, link.amount_unique_match_ci95.0, link.amount_unique_match_ci95.1, link.unshield_events,
            link.adjacency_same_actor_rate, link.adjacency_chance, t4.elapsed().as_secs_f64()
        ));
        // (a) and (b) are PASS/FAIL: a beat-chance result is a real leak finding, surfaced by a
        // panic here (that is a success of the harness, never softened).
        crate::linkage::verdict(&link).unwrap_or_else(|e| {
            panic!("B11 LINKAGE FINDING (a beat-chance score is a real leak — investigate, do NOT weaken): {e}")
        });
        push(&mut battery, "B11-linkage-cryptanalysis",
            format!(
                "PASS crypto (a) nf->cm percentile {:.4} within {:.3} of 0.5, top1 {:.5}<=chance {:.5}; (b) same-account {:.4} within {:.3} of 0.5. MEASURE (c) amount unique-match {:.3} CI[{:.3},{:.3}]; (d) timing-adjacency {:.4} vs chance {:.4}",
                link.nf_cm_mean_percentile, link.epsilon_a, link.nf_cm_top1_rate, link.nf_cm_chance_top1,
                link.same_acct_balanced_acc, link.epsilon_b,
                link.amount_unique_match_rate, link.amount_unique_match_ci95.0, link.amount_unique_match_ci95.1,
                link.adjacency_same_actor_rate, link.adjacency_chance
            ));

        let state_hash = self.model.state_hash(&replayer_tip_hash);
        (battery, state_hash, blocks.len() as u64)
    }
}
