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
            // recycle the PocketIC instance every this-many ops to bound server memory over a
            // long run (DFINITY drop_and_take_state pattern). 0 disables recycling.
            recycle_ops: get("SOAK_RECYCLE_OPS", 100) as usize,
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

#[derive(Serialize, Clone)]
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
        let env = pic_env::setup(wasms, &keys.transfer_vk_hex, &keys.deposit_vk_hex);
        let accounts = derive_accounts(tier.seed, tier.accounts, &cfg);
        let pauper = derive_accounts(tier.seed.wrapping_add(0xdead), tier.accounts + 1, &cfg)
            .pop()
            .unwrap();
        let principals: Vec<Principal> = accounts.iter().map(|a| a.principal).collect();
        println!("[setup] funding {} accounts on the token fixture...", principals.len());
        let t0 = Instant::now();
        pic_env::fund_accounts(&env, &principals, INITIAL_BALANCE, ALLOWANCE);
        // the pauper's allowance covers less than any shield value + fee: the
        // insufficient-allowance class must be rejected by the token leg.
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
        let fixture_proof_hex = std::fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .join("fixtures/pool-vectors-bls12-381/transfer_proof.hex"),
        )
        .expect("read fixture transfer proof")
        .trim()
        .to_string();
        Runner {
            fixture_proof_hex,
            progress_path: std::env::var("SOAK_PROGRESS_LOG").ok(),
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
            started: Instant::now(),
        }
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

    fn upgrade(&mut self, at_op: u64) {
        self.progress(&format!("upgrade #{} at op {} (mode upgrade, same wasm)", self.upgrades_done.len() + 1, at_op));
        let pre = self.env.ledger_status();
        // moc 1.4.1 compiles with enhanced orthogonal persistence: the upgrade must carry
        // wasm_memory_persistence = keep (the state-preserving option; `replace` would wipe).
        self.env
            .pic()
            .upgrade_eop_canister(self.env.ledger, self.env.ledger_wasm.clone(), candid::encode_args(()).unwrap(), Some(self.env.admin))
            .unwrap_or_else(|e| panic!("upgrade failed: {e:?}"));
        // free any WASM chunk storage the upgrade left resident
        let _ = self.env.pic().clear_chunk_store(self.env.ledger, Some(self.env.admin));
        let post = self.env.ledger_status();
        assert_eq!(pre.note_root, post.note_root, "upgrade lost note_root");
        assert_eq!(pre.note_count, post.note_count, "upgrade lost note_count");
        assert_eq!(pre.nullifier_count, post.nullifier_count, "upgrade lost nullifiers");
        assert_eq!(pre.pool_value, post.pool_value, "upgrade lost pool_value");
        assert_eq!(pre.epoch, post.epoch, "upgrade lost epoch");
        let validated: ct::MotokoResult<candid::Reserved> = self
            .env
            .query(self.env.ledger, "validate_stable_state", ())
            .expect("validate_stable_state");
        validated.into_result().expect("stable state invalid after upgrade");
        self.cheap_invariants();
        self.progress(&format!("upgrade #{} complete, invariants green", self.upgrades_done.len() + 1));
        self.upgrades_done.push(at_op);
    }

    pub fn run(&mut self) -> u64 {
        let mut executed: u64 = 0;
        let total = self.tier.ops as u64;
        let mut next_upgrade = 0usize;
        let mut last_checkpoint = 0u64;
        let mut last_recycle = 0u64;
        let mut upgrade_since_recycle = false;
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
            let interval_due = self.tier.recycle_ops > 0
                && executed / self.tier.recycle_ops as u64 > last_recycle / self.tier.recycle_ops as u64;
            if executed < total && (interval_due || upgrade_since_recycle) {
                let t = Instant::now();
                self.env.recycle();
                last_recycle = executed;
                upgrade_since_recycle = false;
                // the recycled instance must carry identical state
                self.cheap_invariants();
                self.progress(&format!("recycled instance at op {executed} in {:.1}s (server memory freed, recycle #{})", t.elapsed().as_secs_f64(), self.env.recycles));
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
        let tuple = cert::ExpectedTuple {
            tip_index: blocks.len() as u64 - 1,
            tip_hash: replayer_tip_hash,
            note_count: blocks.len() as u64,
            note_root: f_bytes(&self.model.mirror.root()),
            encoding_version: 1,
            archive_manifest,
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

        // B7 count part
        assert!(self.upgrades_done.len() >= 3, "B7: fewer than 3 upgrades performed");
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

        let state_hash = self.model.state_hash(&replayer_tip_hash);
        (battery, state_hash, blocks.len() as u64)
    }
}
