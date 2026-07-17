//! The reference model (D1e): the harness's own account of what the ledger state must be after
//! every accepted operation. It tracks notes, nullifiers, per-account spendable balances, the
//! expected block log, the expected pool value and token custody, and a Merkle mirror whose root
//! must equal the canister's `note_root` after every mutation. Any divergence between the model
//! and the canister is a reported finding.

use crate::crypto::{f_bytes, MerkleMirror};
use ark_bls12_381::Fr as F;
use ark_ff::PrimeField;
use common::{derive_nf, derive_pk, note_commitment, poseidon_config, PoseidonCfg};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap, HashSet};

/// One shielded account: a distinct caller principal with its own nullifier key. `nk` is the
/// spend secret; `pk = H(1, nk)` the shielded address; the scan key recognizes note ciphertexts.
#[derive(Clone)]
pub struct AccountKeys {
    pub index: usize,
    pub principal: candid::Principal,
    pub nk: F,
    pub pk: F,
    pub scan_key: [u8; 32],
}

pub fn derive_accounts(seed: u64, n: usize, cfg: &PoseidonCfg<F>) -> Vec<AccountKeys> {
    (0..n)
        .map(|i| {
            let mut h = Sha256::new();
            h.update(b"soak-account-nk-v1");
            h.update(seed.to_le_bytes());
            h.update((i as u64).to_le_bytes());
            let digest: [u8; 32] = h.finalize().into();
            let nk = F::from_le_bytes_mod_order(&digest);
            let pk = derive_pk(cfg, nk);
            let mut h = Sha256::new();
            h.update(b"soak-scan-key-v1");
            h.update(f_bytes(&nk));
            let scan_key: [u8; 32] = h.finalize().into();
            let mut p = Sha256::new();
            p.update(b"soak-principal-v1");
            p.update(seed.to_le_bytes());
            p.update((i as u64).to_le_bytes());
            let pdigest: [u8; 32] = p.finalize().into();
            AccountKeys {
                index: i,
                principal: candid::Principal::self_authenticating(pdigest),
                nk,
                pk,
                scan_key,
            }
        })
        .collect()
}

#[derive(Clone, Debug)]
pub struct NoteRecord {
    pub leaf_index: u64,
    pub cm: F,
    pub owner: usize,
    pub v: u64,
    pub rho: F,
    pub rcm: F,
    pub nf: F,
    pub spent: bool,
}

#[derive(Clone, Debug)]
pub struct ExpectedBlock {
    pub origin: &'static str, // "shield" | "confidential_transfer"
    pub commitment: [u8; 32],
    pub nullifiers: Vec<[u8; 32]>,
    pub anchor_before: [u8; 32],
    pub root_after: [u8; 32],
}

pub struct Model {
    pub cfg: PoseidonCfg<F>,
    pub mirror: MerkleMirror,
    pub notes: Vec<NoteRecord>,
    pub cm_to_note: HashMap<[u8; 32], usize>,
    pub nf_to_note: HashMap<[u8; 32], usize>,
    pub unspent_by_account: Vec<BTreeSet<usize>>,
    pub blocks: Vec<ExpectedBlock>,
    pub historical_roots: HashSet<[u8; 32]>,
    /// expected fixture-token balance per account (owner principal, no subaccount)
    pub token_balances: Vec<u128>,
    /// expected fixture-token balance of the pool account
    pub pool_custody: u128,
    /// expected `pool_value` reported by the ledger
    pub pool_value: u128,
    pub epoch: u64,
    pub token_fee: u64,
    /// cumulative value shielded in (A2 conservation invariant)
    pub cumulative_shield_in: u128,
    /// cumulative value paid out of the pool by unshields, including token fees
    pub cumulative_unshield_out: u128,
}

impl Model {
    pub fn new(n_accounts: usize, initial_balance: u128, token_fee: u64) -> Self {
        let cfg = poseidon_config();
        let mirror = MerkleMirror::new(&cfg);
        let mut historical_roots = HashSet::new();
        historical_roots.insert(f_bytes(&mirror.root()));
        Model {
            cfg,
            mirror,
            notes: Vec::new(),
            cm_to_note: HashMap::new(),
            nf_to_note: HashMap::new(),
            unspent_by_account: vec![BTreeSet::new(); n_accounts],
            blocks: Vec::new(),
            historical_roots,
            token_balances: vec![initial_balance; n_accounts],
            pool_custody: 0,
            pool_value: 0,
            epoch: 0,
            token_fee,
            cumulative_shield_in: 0,
            cumulative_unshield_out: 0,
        }
    }

    /// Record an accepted shield: one appended commitment, no nullifiers.
    pub fn apply_shield(
        &mut self,
        acct: &AccountKeys,
        v: u64,
        rho: F,
        rcm: F,
    ) {
        let anchor_before = f_bytes(&self.mirror.root());
        let cm = note_commitment(&self.cfg, v, acct.pk, rho, rcm);
        let leaf_index = self.mirror.append(&self.cfg, cm);
        let root_after = f_bytes(&self.mirror.root());
        let nf = derive_nf(&self.cfg, acct.nk, rho);
        let idx = self.notes.len();
        self.notes.push(NoteRecord { leaf_index, cm, owner: acct.index, v, rho, rcm, nf, spent: false });
        self.cm_to_note.insert(f_bytes(&cm), idx);
        self.nf_to_note.insert(f_bytes(&nf), idx);
        self.unspent_by_account[acct.index].insert(idx);
        self.blocks.push(ExpectedBlock {
            origin: "shield",
            commitment: f_bytes(&cm),
            nullifiers: vec![],
            anchor_before,
            root_after,
        });
        self.historical_roots.insert(root_after);
        self.token_balances[acct.index] = self.token_balances[acct.index]
            .checked_sub(v as u128 + self.token_fee as u128)
            .expect("model: shield overdraws account token balance");
        self.pool_custody += v as u128;
        self.pool_value += v as u128;
        self.cumulative_shield_in += v as u128;
        self.epoch += 1;
    }

    /// Record an accepted confidential transfer (private when v_pub_out == 0, unshield
    /// otherwise). `anchor` is the proof's anchor (recorded verbatim in both blocks).
    /// Output j's rho is input j's nullifier (circuit-enforced chaining).
    #[allow(clippy::too_many_arguments)]
    pub fn apply_transfer(
        &mut self,
        in1: usize,
        in2: usize,
        outs: [(usize, u64, F); 2], // (owner account, value, rcm); rho is chained
        fee: u64,
        v_pub_out: u64,
        recipient_acct: Option<usize>,
        anchor: [u8; 32],
        accounts: &[AccountKeys],
    ) {
        let nf1 = self.notes[in1].nf;
        let nf2 = self.notes[in2].nf;
        let nullifiers = vec![f_bytes(&nf1), f_bytes(&nf2)];
        for input in [in1, in2] {
            assert!(!self.notes[input].spent, "model: double spend of note {input}");
            self.notes[input].spent = true;
            let owner = self.notes[input].owner;
            self.unspent_by_account[owner].remove(&input);
        }
        let rhos = [nf1, nf2];
        let mut roots_after = [self.mirror.root(); 2];
        let mut new_note_indices = [0usize; 2];
        for (j, (owner, v, rcm)) in outs.iter().enumerate() {
            let pk = accounts[*owner].pk;
            let cm = note_commitment(&self.cfg, *v, pk, rhos[j], *rcm);
            let leaf_index = self.mirror.append(&self.cfg, cm);
            roots_after[j] = self.mirror.root();
            let nf = derive_nf(&self.cfg, accounts[*owner].nk, rhos[j]);
            let idx = self.notes.len();
            self.notes.push(NoteRecord {
                leaf_index,
                cm,
                owner: *owner,
                v: *v,
                rho: rhos[j],
                rcm: *rcm,
                nf,
                spent: false,
            });
            self.cm_to_note.insert(f_bytes(&cm), idx);
            self.nf_to_note.insert(f_bytes(&nf), idx);
            self.unspent_by_account[*owner].insert(idx);
            new_note_indices[j] = idx;
        }
        // The canister appends BOTH leaves in one tree-oracle call, then writes both blocks with
        // the SAME root_after (the root after both appends) and the proof's anchor as
        // anchor_before (src/Main.mo appendBlock calls at :1632-:1633 and :1397-:1398).
        let final_root = f_bytes(&roots_after[1]);
        for (j, (owner, v, _)) in outs.iter().enumerate() {
            let _ = (owner, v);
            self.blocks.push(ExpectedBlock {
                origin: "confidential_transfer",
                commitment: f_bytes(&self.notes[new_note_indices[j]].cm),
                nullifiers: nullifiers.clone(),
                anchor_before: anchor,
                root_after: final_root,
            });
        }
        self.historical_roots.insert(final_root);
        if v_pub_out > 0 {
            let recipient = recipient_acct.expect("unshield needs recipient");
            // pool pays v_pub_out to the recipient plus the transparent fee.
            let debit = v_pub_out as u128 + self.token_fee as u128;
            self.pool_custody = self
                .pool_custody
                .checked_sub(debit)
                .expect("model: unshield overdraws pool custody");
            self.pool_value = self
                .pool_value
                .checked_sub(debit)
                .expect("model: unshield overdraws pool value");
            self.cumulative_unshield_out += debit;
            self.token_balances[recipient] += v_pub_out as u128;
            // The harness sets the shielded public `fee` == transparent token fee, so shielded
            // value destroyed (fee + v_pub_out) equals the pool debit and the invariant
            // pool_value == Σ unspent notes is preserved exactly.
            assert_eq!(fee, self.token_fee, "harness policy: unshield fee == transparent fee");
        } else {
            assert_eq!(fee, 0, "harness policy: private transfers carry fee 0");
        }
        self.epoch += 1;
    }

    pub fn balance_of(&self, account: usize) -> u128 {
        self.unspent_by_account[account]
            .iter()
            .map(|&i| self.notes[i].v as u128)
            .sum()
    }

    pub fn total_unspent(&self) -> u128 {
        self.notes.iter().filter(|n| !n.spent).map(|n| n.v as u128).sum()
    }

    pub fn spent_count(&self) -> usize {
        self.notes.iter().filter(|n| n.spent).count()
    }

    /// Deterministic digest of the model's final state (B2 proof 2): includes every note,
    /// spent flag, balances, block structure, roots, pool numbers.
    pub fn state_hash(&self, last_block_hash: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(b"soak-state-hash-v1");
        h.update((self.notes.len() as u64).to_le_bytes());
        for n in &self.notes {
            h.update(f_bytes(&n.cm));
            h.update(f_bytes(&n.nf));
            h.update((n.owner as u64).to_le_bytes());
            h.update(n.v.to_le_bytes());
            h.update([n.spent as u8]);
        }
        for b in &self.blocks {
            h.update(b.origin.as_bytes());
            h.update(b.commitment);
            for nf in &b.nullifiers {
                h.update(nf);
            }
            h.update(b.anchor_before);
            h.update(b.root_after);
        }
        h.update(f_bytes(&self.mirror.root()));
        h.update(self.pool_value.to_le_bytes());
        h.update(self.pool_custody.to_le_bytes());
        h.update(self.epoch.to_le_bytes());
        h.update(last_block_hash);
        hex::encode(h.finalize())
    }
}
