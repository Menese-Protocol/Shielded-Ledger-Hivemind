//! Prepaid-fee-balance edge battery — teeth-first, on PocketIC.
//!
//! Proves the prepaid fee mechanism (deposit once publicly / debit internally per accepted
//! shielded transfer / withdraw the remainder) against the REAL ledger wasm with real Groth16
//! proofs, and proves every detector has teeth by first turning it RED against four
//! deliberately-broken ledger variants (planted defects, compiled from a patched source copy —
//! the shipped tree is never modified):
//!
//!   X  debit skipped (debitPrepaid no-op + pre-verify insufficient guard removed)
//!   Y  rate floor + flag ignored (activePrepaidRate returns >=1 regardless of the flag)
//!   W  balances made transient (upgrade wipes them)
//!   R  resume without reconcile (post-dedup-window recovery re-sends instead of scanning)
//!
//! Checks (committed thresholds; each asserts canister state AND prints a log marker):
//!   C1 zero-rate no-op                 C2 insufficient REJECT with zero state mutation
//!   C3 exact-balance boundary          C4 overflow/dust (over-withdraw, zero value, dust)
//!   C5 interleaving: no double debit   C6 upgrade persistence (balances/rate/flag/revenue)
//!   C7 withdraw-all then transfers reject; tokens land   C8 flag-off ignores balances
//!   C9 fee-custody solvency at rest    C10 deposit crash recovery past the dedup window
//!
//! RED expectations per variant: X ⇒ C2,C3,C4,C5,C7,C9 fail; Y ⇒ C1,C8 fail; W ⇒ C6 fails;
//! R ⇒ C10 fails. The battery PASSES only if every check is green on the shipped wasm AND
//! every listed check goes red on its variant.

use ark_ff::UniformRand;
use candid::Principal;
use sha2::Digest;
use soak::candid_types as ct;
use soak::crypto::f_bytes;
use soak::model::AccountKeys;
use soak::{keys, pic_env, prover};
use std::path::{Path, PathBuf};

type F = common::ScalarField;

const RATE: u64 = 25_000; // committed per-transfer rate for rate>0 scenarios (e8s)
const FUND: u128 = 1_000_000_000;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

fn fee_subaccount() -> Vec<u8> {
    sha2::Sha256::digest(b"zk-ledger/prepaid-fee-account/v1").to_vec()
}

// ---- candid mirrors for the new endpoints (decode-only where possible) ----

#[derive(candid::CandidType, serde::Deserialize, Clone)]
struct PrepaidDepositArgs {
    value: u64,
    from_subaccount: Option<ct::Blob>,
    created_at_time: u64,
    client_nonce: ct::Blob,
}

#[derive(candid::CandidType, serde::Deserialize)]
struct PrepaidFeeStatus {
    enabled: bool,
    rate: candid::Nat,
    total_prepaid: candid::Nat,
    revenue: candid::Nat,
    fee_account: ct::Account,
    holders: candid::Nat,
    pending: Option<candid::Reserved>,
    completed_intents: candid::Nat,
}

struct NoteRec {
    acct: usize,
    v: u64,
    rho: F,
    rcm: F,
    spent: bool,
}

struct Harness {
    env: pic_env::Env,
    keyset: keys::Keyset,
    cfg: common::PoseidonCfg<F>,
    accounts: Vec<AccountKeys>,
    leaves: Vec<F>,
    notes: Vec<NoteRec>,
    op: u64,
}

impl Harness {
    fn new(wasms: &pic_env::BuiltWasms, keyset: keys::Keyset, tag: &str) -> Self {
        let cfg = common::poseidon_config();
        let accounts = soak::model::derive_accounts(20260723, 4, &cfg);
        let state_dir =
            std::env::temp_dir().join(format!("prepaid_battery_{}_{}", std::process::id(), tag));
        let _ = std::fs::remove_dir_all(&state_dir);
        std::fs::create_dir_all(&state_dir).unwrap();
        let env = pic_env::setup(wasms, &keyset.transfer_vk_hex, &keyset.deposit_vk_hex, &state_dir);
        let principals: Vec<Principal> = accounts.iter().map(|a| a.principal).collect();
        pic_env::fund_accounts(&env, &principals, FUND, FUND);
        Harness { env, keyset, cfg, accounts, leaves: Vec::new(), notes: Vec::new(), op: 0 }
    }

    fn admin(&self) -> Principal {
        self.env.admin
    }

    fn set_prepaid(&self, enabled: bool) {
        let r: ct::MotokoResult<PrepaidFeeStatus> = self
            .env
            .update(self.env.ledger, self.admin(), "set_prepaid_fee", (enabled,))
            .expect("set_prepaid_fee");
        r.into_result().expect("set_prepaid_fee result");
    }

    fn set_rate(&self, rate: u64) {
        let r: ct::MotokoResult<PrepaidFeeStatus> = self
            .env
            .update(self.env.ledger, self.admin(), "set_prepaid_fee_rate", (rate,))
            .expect("set_prepaid_fee_rate");
        r.into_result().expect("set_prepaid_fee_rate result");
    }

    fn status(&self) -> PrepaidFeeStatus {
        self.env.query(self.env.ledger, "prepaid_fee_status", ()).expect("prepaid_fee_status")
    }

    /// prepaid_fee_balance is caller-scoped; query AS the account's principal.
    fn balance_of(&self, acct: usize) -> u64 {
        let raw = self
            .env
            .pic()
            .query_call(
                self.env.ledger,
                self.accounts[acct].principal,
                "prepaid_fee_balance",
                candid::encode_args(()).unwrap(),
            )
            .expect("prepaid_fee_balance");
        let n: candid::Nat = candid::decode_one(&raw).expect("decode balance");
        u64::try_from(n.0).unwrap()
    }

    fn deposit_args(&mut self, value: u64) -> PrepaidDepositArgs {
        self.op += 1;
        let mut prng = prover::op_rng(20260723, self.op, "prepaid-deposit");
        use rand_chacha::rand_core::RngCore;
        let mut nonce = [0u8; 32];
        prng.fill_bytes(&mut nonce);
        PrepaidDepositArgs {
            value,
            from_subaccount: None,
            created_at_time: self.env.time_ns(),
            client_nonce: ct::blob(nonce.to_vec()),
        }
    }

    fn deposit(&mut self, acct: usize, value: u64) -> Result<u64, String> {
        let args = self.deposit_args(value);
        let r: ct::MotokoResult<candid::Nat> = self
            .env
            .update(self.env.ledger, self.accounts[acct].principal, "prepaid_fee_deposit", (args,))
            .expect("prepaid_fee_deposit call");
        r.into_result().map(|n| u64::try_from(n.0).unwrap())
    }

    fn withdraw(&self, acct: usize, amount: u64) -> Result<u64, String> {
        let r: ct::MotokoResult<candid::Nat> = self
            .env
            .update(
                self.env.ledger,
                self.accounts[acct].principal,
                "prepaid_fee_withdraw",
                (amount, self.env.time_ns()),
            )
            .expect("prepaid_fee_withdraw call");
        r.into_result().map(|n| u64::try_from(n.0).unwrap())
    }

    fn resume(&self, acct: usize) -> Result<u64, String> {
        let r: ct::MotokoResult<candid::Nat> = self
            .env
            .update(self.env.ledger, self.accounts[acct].principal, "resume_prepaid", ())
            .expect("resume_prepaid call");
        r.into_result().map(|n| u64::try_from(n.0).unwrap())
    }

    fn shield(&mut self, acct: usize, v: u64) -> ct::MutationResult {
        self.op += 1;
        let mut prng = prover::op_rng(20260723, self.op, "prepaid-shield-plan");
        let rho = F::rand(&mut prng);
        let rcm = F::rand(&mut prng);
        let mut prepared = prover::prepare_shield(
            &self.cfg,
            &self.keyset.deposit_pk,
            &self.accounts[acct],
            v,
            rho,
            rcm,
            20260723,
            self.op,
        );
        prepared.args.created_at_time = self.env.time_ns();
        let m: ct::MutationResult = self
            .env
            .update(self.env.ledger, self.accounts[acct].principal, "shield", (prepared.args,))
            .expect("shield call");
        if m.outcome == "ACCEPT" {
            let cm = common::note_commitment(&self.cfg, v, self.accounts[acct].pk, rho, rcm);
            self.leaves.push(cm);
            self.notes.push(NoteRec { acct, v, rho, rcm, spent: false });
        }
        m
    }

    /// Build canister-ready args for a private transfer spending the caller's notes `i`,`j`
    /// (indices into self.notes), paying `first` to `to_acct` and the change back to `acct`.
    fn transfer_args(&mut self, acct: usize, i: usize, j: usize, to_acct: usize, first: u64) -> prover::PreparedTransfer {
        self.op += 1;
        let leaf_index = |note: usize| -> u64 {
            // notes are appended to `leaves` in creation order: note k's commitment is leaf k
            // for shields; transfer outputs are pushed as they are accepted.
            note as u64
        };
        let plan = |note: usize| -> prover::TransferPlanInput {
            let n = &self.notes[note];
            prover::TransferPlanInput {
                note_index: note,
                leaf_index: leaf_index(note),
                v: n.v,
                nk: self.accounts[n.acct].nk,
                rho: n.rho,
                rcm: n.rcm,
            }
        };
        let tree = common::DenseTree { leaves: self.leaves.clone() };
        let anchor = tree.root(&self.cfg);
        let mut prng = prover::op_rng(20260723, self.op, "prepaid-transfer-plan");
        let crypto = prover::TransferCrypto {
            anchor,
            path1: tree.path(&self.cfg, self.notes_leaf(i)),
            path2: tree.path(&self.cfg, self.notes_leaf(j)),
            out_rcm1: F::rand(&mut prng),
            out_rcm2: F::rand(&mut prng),
        };
        let total = self.notes[i].v + self.notes[j].v;
        let (in1, in2) = (plan(i), plan(j));
        prover::prepare_transfer(
            &self.cfg,
            &self.keyset.transfer_pk,
            self.keyset.legacy_statement,
            &crypto,
            (&in1, &in2),
            (&self.accounts[to_acct], &self.accounts[acct]),
            (first, total - first),
            0,
            0,
            [0u8; 32],
            None,
            None,
            20260723,
            self.op,
        )
    }

    fn notes_leaf(&self, note: usize) -> usize {
        note
    }

    fn submit_transfer(&mut self, acct: usize, prepared: &prover::PreparedTransfer) -> ct::MutationResult {
        let m: ct::MutationResult = self
            .env
            .update(
                self.env.ledger,
                self.accounts[acct].principal,
                "confidential_transfer",
                (prepared.args.clone(),),
            )
            .expect("confidential_transfer call");
        if m.outcome == "ACCEPT" {
            self.record_accepted(prepared);
        }
        m
    }

    fn record_accepted(&mut self, prepared: &prover::PreparedTransfer) {
        self.notes[prepared.in_notes.0].spent = true;
        self.notes[prepared.in_notes.1].spent = true;
        for (owner, v, rho, rcm) in prepared.outs.iter() {
            let cm = common::note_commitment(&self.cfg, *v, self.accounts[*owner].pk, *rho, *rcm);
            self.leaves.push(cm);
            self.notes.push(NoteRec { acct: *owner, v: *v, rho: *rho, rcm: *rcm, spent: false });
        }
        // sanity: our mirror root matches the canister's
        let tree = common::DenseTree { leaves: self.leaves.clone() };
        let root = f_bytes(&tree.root(&self.cfg)).to_vec();
        let status = self.env.ledger_status();
        assert_eq!(status.note_root.as_ref(), root.as_slice(), "battery mirror diverged from the ledger root");
    }

    fn fee_custody(&self) -> u128 {
        self.env.token_balance(&ct::Account {
            owner: self.env.ledger,
            subaccount: Some(ct::blob(fee_subaccount())),
        })
    }

    fn upgrade(&self) {
        self.env
            .pic()
            .upgrade_eop_canister(
                self.env.ledger,
                self.env.ledger_wasm.clone(),
                candid::encode_args(()).unwrap(),
                Some(self.admin()),
            )
            .unwrap_or_else(|e| panic!("upgrade failed: {e:?}"));
    }

    fn arm_fail_after_token(&self) {
        let r: ct::MotokoResult<()> = self
            .env
            .update(self.env.ledger, self.admin(), "test_arm_fail_after_token_once", ())
            .expect("test_arm_fail_after_token_once");
        r.into_result().expect("arm fault");
    }

    fn advance_past_dedup_window(&self) {
        let _: () = self
            .env
            .update(self.env.token, self.admin(), "test_advance_time", (candid::Nat::from(86_500_000_000_000u64),))
            .expect("test_advance_time");
    }
}

fn nat64(n: &candid::Nat) -> u64 {
    u64::try_from(n.0.clone()).unwrap()
}

// ---------------------------------------------------------------------------
// The ten checks. Each returns Err(reason) instead of panicking so the SAME code path can be
// asserted GREEN on the shipped wasm and RED on a planted-defect variant.
// ---------------------------------------------------------------------------

/// C1 zero-rate no-op: flag ON, rate 0 — an accepted transfer must not touch balances/revenue.
fn c1_zero_rate_noop(w: &pic_env::BuiltWasms, ks: keys::Keyset) -> Result<(), String> {
    let mut h = Harness::new(w, ks, "c1");
    h.set_prepaid(true);
    h.set_rate(0);
    assert_eq!(h.shield(0, 100_000).outcome, "ACCEPT", "c1 shield");
    assert_eq!(h.shield(0, 50_000).outcome, "ACCEPT", "c1 shield 2");
    h.deposit(0, 200_000).map_err(|e| format!("c1 deposit: {e}"))?;
    let before = h.balance_of(0);
    let p = h.transfer_args(0, 0, 1, 1, 60_000);
    let m = h.submit_transfer(0, &p);
    if m.outcome != "ACCEPT" {
        return Err(format!("c1 transfer outcome {}", m.outcome));
    }
    let after = h.balance_of(0);
    let st = h.status();
    if after != before {
        return Err(format!("c1 RED: zero-rate transfer changed balance {before} -> {after}"));
    }
    if nat64(&st.revenue) != 0 {
        return Err(format!("c1 RED: zero-rate produced revenue {}", nat64(&st.revenue)));
    }
    println!("[C1] PASS zero-rate no-op: balance {before} unchanged, revenue 0");
    Ok(())
}

/// C2 insufficient balance: REJECT with the committed error, verifier NOT_CALLED, and ZERO
/// state mutation (root/epoch/nullifiers/balance byte-compared before vs after).
fn c2_insufficient_reject(w: &pic_env::BuiltWasms, ks: keys::Keyset) -> Result<(), String> {
    let mut h = Harness::new(w, ks, "c2");
    h.set_prepaid(true);
    h.set_rate(RATE);
    assert_eq!(h.shield(0, 100_000).outcome, "ACCEPT", "c2 shield");
    assert_eq!(h.shield(0, 50_000).outcome, "ACCEPT", "c2 shield 2");
    // deposit LESS than the rate
    h.deposit(0, RATE - 1).map_err(|e| format!("c2 deposit: {e}"))?;
    let st0 = h.env.ledger_status();
    let bal0 = h.balance_of(0);
    let p = h.transfer_args(0, 0, 1, 1, 60_000);
    let m: ct::MutationResult = h
        .env
        .update(h.env.ledger, h.accounts[0].principal, "confidential_transfer", (p.args.clone(),))
        .expect("c2 transfer call");
    if m.outcome != "REJECT:prepaid-fee-insufficient" {
        return Err(format!("c2 RED: expected REJECT:prepaid-fee-insufficient, got {}", m.outcome));
    }
    if m.verifier_outcome != "NOT_CALLED" {
        return Err(format!("c2: verifier consulted: {}", m.verifier_outcome));
    }
    let st1 = h.env.ledger_status();
    let bal1 = h.balance_of(0);
    if st1.note_root != st0.note_root
        || st1.epoch != st0.epoch
        || st1.nullifier_count != st0.nullifier_count
        || st1.note_count != st0.note_count
        || bal1 != bal0
    {
        return Err("c2: rejected transfer mutated state".into());
    }
    println!("[C2] PASS insufficient balance: clean REJECT, verifier NOT_CALLED, zero mutation");
    Ok(())
}

/// C3 exact boundary: balance == rate accepts and lands on exactly 0; the next transfer rejects.
fn c3_exact_boundary(w: &pic_env::BuiltWasms, ks: keys::Keyset) -> Result<(), String> {
    let mut h = Harness::new(w, ks, "c3");
    h.set_prepaid(true);
    h.set_rate(RATE);
    for _ in 0..4 {
        assert_eq!(h.shield(0, 100_000).outcome, "ACCEPT", "c3 shield");
    }
    h.deposit(0, RATE).map_err(|e| format!("c3 deposit: {e}"))?;
    let p = h.transfer_args(0, 0, 1, 1, 60_000);
    let m = h.submit_transfer(0, &p);
    if m.outcome != "ACCEPT" {
        return Err(format!("c3 boundary transfer rejected: {}", m.outcome));
    }
    let bal = h.balance_of(0);
    if bal != 0 {
        return Err(format!("c3 RED: balance after exact-rate debit is {bal}, want 0"));
    }
    let st = h.status();
    if nat64(&st.revenue) != RATE {
        return Err(format!("c3 RED: revenue {} != rate {}", nat64(&st.revenue), RATE));
    }
    let p2 = h.transfer_args(0, 2, 3, 1, 10_000);
    let m2: ct::MutationResult = h
        .env
        .update(h.env.ledger, h.accounts[0].principal, "confidential_transfer", (p2.args.clone(),))
        .expect("c3 second transfer");
    if m2.outcome != "REJECT:prepaid-fee-insufficient" {
        return Err(format!("c3 RED: post-exhaustion transfer said {}", m2.outcome));
    }
    println!("[C3] PASS exact boundary: rate-sized balance spent to 0, next transfer rejected");
    Ok(())
}

/// C4 overflow/dust: over-withdraw rejects with no change; zero-value ops reject; a dust
/// remainder stays withdrawable.
fn c4_overflow_dust(w: &pic_env::BuiltWasms, ks: keys::Keyset) -> Result<(), String> {
    let mut h = Harness::new(w, ks, "c4");
    h.set_prepaid(true);
    h.set_rate(RATE);
    let fee = h.env.token_fee;
    h.deposit(0, 100_000).map_err(|e| format!("c4 deposit: {e}"))?;
    let bal0 = h.balance_of(0);
    if bal0 != 100_000 {
        return Err(format!("c4: deposit credited {bal0}, want 100000"));
    }
    // over-withdraw: amount + fee exceeds the balance
    match h.withdraw(0, 100_000 + 1) {
        Err(e) if e == "REJECT:prepaid-fee-insufficient" => {}
        other => return Err(format!("c4 RED: over-withdraw returned {other:?}")),
    }
    if h.balance_of(0) != bal0 {
        return Err(format!("c4 RED: failed over-withdraw changed balance {} -> {}", bal0, h.balance_of(0)));
    }
    // zero-value deposit and withdraw reject
    match h.deposit(0, 0) {
        Err(e) if e == "REJECT:prepaid-zero-value" => {}
        other => return Err(format!("c4: zero deposit returned {other:?}")),
    }
    match h.withdraw(0, 0) {
        Err(e) if e == "REJECT:prepaid-zero-value" => {}
        other => return Err(format!("c4: zero withdraw returned {other:?}")),
    }
    // withdraw down to dust, then withdraw the dust
    let dust = 17u64;
    let first = 100_000 - fee - (dust + fee);
    let after = h.withdraw(0, first).map_err(|e| format!("c4 withdraw: {e}"))?;
    if after != dust + fee {
        return Err(format!("c4: remainder {after}, want {}", dust + fee));
    }
    let end = h.withdraw(0, dust).map_err(|e| format!("c4 dust withdraw: {e}"))?;
    if end != 0 {
        return Err(format!("c4: dust withdraw left {end}"));
    }
    println!("[C4] PASS overflow/dust: over-withdraw clean-rejected, zero-values rejected, dust recovered");
    Ok(())
}

/// C5 adversarial interleaving: a transfer and a withdraw-all race for a balance that can fund
/// only one of them. Exactly one may win; the balance must end 0 with no double spend of it.
fn c5_interleaving(w: &pic_env::BuiltWasms, ks: keys::Keyset) -> Result<(), String> {
    let mut h = Harness::new(w, ks, "c5");
    h.set_prepaid(true);
    h.set_rate(RATE);
    let fee = h.env.token_fee;
    assert_eq!(h.shield(0, 100_000).outcome, "ACCEPT", "c5 shield");
    assert_eq!(h.shield(0, 50_000).outcome, "ACCEPT", "c5 shield 2");
    h.deposit(0, RATE).map_err(|e| format!("c5 deposit: {e}"))?;
    // The withdraw drains exactly the full balance (amount + token fee == RATE).
    let wd_amount = RATE - fee;
    let p = h.transfer_args(0, 0, 1, 1, 60_000);
    let caller = h.accounts[0].principal;
    let t_msg = h
        .env
        .pic()
        .submit_call(
            h.env.ledger,
            caller,
            "confidential_transfer",
            candid::encode_args((p.args.clone(),)).unwrap(),
        )
        .map_err(|e| format!("submit transfer: {e:?}"))?;
    let w_msg = h
        .env
        .pic()
        .submit_call(
            h.env.ledger,
            caller,
            "prepaid_fee_withdraw",
            candid::encode_args((wd_amount, h.env.time_ns())).unwrap(),
        )
        .map_err(|e| format!("submit withdraw: {e:?}"))?;
    let t_raw = h.env.pic().await_call(t_msg).map_err(|e| format!("transfer await: {e:?}"))?;
    let w_raw = h.env.pic().await_call(w_msg).map_err(|e| format!("withdraw await: {e:?}"))?;
    let t: ct::MutationResult = candid::decode_one(&t_raw).unwrap();
    let wr: ct::MotokoResult<candid::Nat> = candid::decode_one(&w_raw).unwrap();
    let t_accepted = t.outcome == "ACCEPT";
    if t_accepted {
        h.record_accepted(&p);
    }
    let w_res = wr.into_result();
    let w_ok = w_res.is_ok();
    println!("[C5] transfer={}, withdraw={:?}", t.outcome, w_res.as_ref().map(|n| nat64(n)));
    if t_accepted == w_ok {
        return Err(format!(
            "c5 RED: transfer_accepted={t_accepted} withdraw_ok={w_ok} — the {} won",
            if t_accepted { "BOTH" } else { "NEITHER" }
        ));
    }
    let bal = h.balance_of(0);
    if bal != 0 {
        return Err(format!("c5 RED: final balance {bal}, want 0"));
    }
    let st = h.status();
    let expected_revenue = if t_accepted { RATE } else { 0 };
    if nat64(&st.revenue) != expected_revenue {
        return Err(format!("c5: revenue {} want {expected_revenue}", nat64(&st.revenue)));
    }
    // solvency after the race
    let custody = h.fee_custody();
    let expect = u128::from(nat64(&st.total_prepaid)) + u128::from(nat64(&st.revenue));
    if custody != expect {
        return Err(format!("c5 RED: custody {custody} != total+revenue {expect}"));
    }
    println!("[C5] PASS interleaving: exactly one winner, balance 0, solvency holds");
    Ok(())
}

/// C6 upgrade persistence: balances, rate, flag, and revenue survive a canister upgrade.
fn c6_upgrade_persistence(w: &pic_env::BuiltWasms, ks: keys::Keyset) -> Result<(), String> {
    let mut h = Harness::new(w, ks, "c6");
    h.set_prepaid(true);
    h.set_rate(RATE);
    assert_eq!(h.shield(0, 100_000).outcome, "ACCEPT", "c6 shield");
    assert_eq!(h.shield(0, 50_000).outcome, "ACCEPT", "c6 shield 2");
    h.deposit(0, 10 * RATE).map_err(|e| format!("c6 deposit: {e}"))?;
    let p = h.transfer_args(0, 0, 1, 1, 60_000);
    let m = h.submit_transfer(0, &p);
    if m.outcome != "ACCEPT" {
        return Err(format!("c6 pre-upgrade transfer: {}", m.outcome));
    }
    let bal0 = h.balance_of(0);
    let st0 = h.status();
    h.upgrade();
    let bal1 = h.balance_of(0);
    let st1 = h.status();
    if bal1 != bal0 {
        return Err(format!("c6 RED: balance {bal0} -> {bal1} across upgrade"));
    }
    if !st1.enabled || nat64(&st1.rate) != RATE || nat64(&st1.revenue) != nat64(&st0.revenue)
        || nat64(&st1.total_prepaid) != nat64(&st0.total_prepaid)
    {
        return Err("c6 RED: flag/rate/revenue/total did not survive the upgrade".into());
    }
    println!("[C6] PASS upgrade persistence: balance {bal1}, rate {RATE}, revenue {} preserved", nat64(&st1.revenue));
    Ok(())
}

/// C7 withdraw-all: the remainder leaves, the tokens land in the caller's token account, and
/// further transfers reject.
fn c7_withdraw_all(w: &pic_env::BuiltWasms, ks: keys::Keyset) -> Result<(), String> {
    let mut h = Harness::new(w, ks, "c7");
    h.set_prepaid(true);
    h.set_rate(RATE);
    let fee = h.env.token_fee;
    assert_eq!(h.shield(0, 100_000).outcome, "ACCEPT", "c7 shield");
    assert_eq!(h.shield(0, 50_000).outcome, "ACCEPT", "c7 shield 2");
    h.deposit(0, 5 * RATE).map_err(|e| format!("c7 deposit: {e}"))?;
    let account = ct::Account { owner: h.accounts[0].principal, subaccount: None };
    let token_before = h.env.token_balance(&account);
    let bal = h.balance_of(0);
    let amount = bal - fee;
    let after = h.withdraw(0, amount).map_err(|e| format!("c7 withdraw-all: {e}"))?;
    if after != 0 || h.balance_of(0) != 0 {
        return Err(format!("c7 RED: withdraw-all left {after}"));
    }
    let token_after = h.env.token_balance(&account);
    if token_after != token_before + u128::from(amount) {
        return Err(format!(
            "c7 RED: token account grew by {} (want {amount})",
            token_after.saturating_sub(token_before)
        ));
    }
    let p = h.transfer_args(0, 0, 1, 1, 60_000);
    let m: ct::MutationResult = h
        .env
        .update(h.env.ledger, h.accounts[0].principal, "confidential_transfer", (p.args.clone(),))
        .expect("c7 transfer");
    if m.outcome != "REJECT:prepaid-fee-insufficient" {
        return Err(format!("c7 RED: transfer after withdraw-all said {}", m.outcome));
    }
    println!("[C7] PASS withdraw-all: balance 0, {amount} landed on the token account, transfers reject");
    Ok(())
}

/// C8 flag-off ignores balances entirely: with the mechanism disabled a funded balance is
/// never debited and never blocks; deposits reject while disabled.
fn c8_flag_off(w: &pic_env::BuiltWasms, ks: keys::Keyset) -> Result<(), String> {
    let mut h = Harness::new(w, ks, "c8");
    h.set_prepaid(true);
    h.set_rate(RATE);
    h.deposit(0, 3 * RATE).map_err(|e| format!("c8 deposit: {e}"))?;
    h.set_prepaid(false); // disable — balances remain but must be inert
    assert_eq!(h.shield(0, 100_000).outcome, "ACCEPT", "c8 shield");
    assert_eq!(h.shield(0, 50_000).outcome, "ACCEPT", "c8 shield 2");
    let bal0 = h.balance_of(0);
    let p = h.transfer_args(0, 0, 1, 1, 60_000);
    let m = h.submit_transfer(0, &p);
    if m.outcome != "ACCEPT" {
        return Err(format!("c8 flag-off transfer rejected: {}", m.outcome));
    }
    let bal1 = h.balance_of(0);
    if bal1 != bal0 {
        return Err(format!("c8 RED: flag-off transfer debited {bal0} -> {bal1}"));
    }
    match h.deposit(0, RATE) {
        Err(e) if e == "REJECT:prepaid-fee-disabled" => {}
        other => return Err(format!("c8 RED: flag-off deposit returned {other:?}")),
    }
    // fund-safety: withdrawals still work while disabled
    let fee = h.env.token_fee;
    let left = h.withdraw(0, bal0 - fee).map_err(|e| format!("c8 flag-off withdraw: {e}"))?;
    if left != 0 {
        return Err(format!("c8: flag-off withdraw left {left}"));
    }
    println!("[C8] PASS flag-off: balance ignored by transfers, deposits reject, withdrawal available");
    Ok(())
}

/// C9 solvency at rest: fee-account custody equals total_prepaid + revenue after a mixed
/// workload (deposits, debits, withdrawals).
fn c9_solvency(w: &pic_env::BuiltWasms, ks: keys::Keyset) -> Result<(), String> {
    let mut h = Harness::new(w, ks, "c9");
    h.set_prepaid(true);
    h.set_rate(RATE);
    let fee = h.env.token_fee;
    assert_eq!(h.shield(0, 100_000).outcome, "ACCEPT", "c9 shield");
    assert_eq!(h.shield(0, 50_000).outcome, "ACCEPT", "c9 shield 2");
    assert_eq!(h.shield(1, 80_000).outcome, "ACCEPT", "c9 shield 3");
    assert_eq!(h.shield(1, 70_000).outcome, "ACCEPT", "c9 shield 4");
    h.deposit(0, 4 * RATE).map_err(|e| format!("c9 deposit0: {e}"))?;
    h.deposit(1, 2 * RATE).map_err(|e| format!("c9 deposit1: {e}"))?;
    let p = h.transfer_args(0, 0, 1, 1, 60_000);
    if h.submit_transfer(0, &p).outcome != "ACCEPT" {
        return Err("c9 transfer 0".into());
    }
    let p2 = h.transfer_args(1, 2, 3, 0, 40_000);
    if h.submit_transfer(1, &p2).outcome != "ACCEPT" {
        return Err("c9 transfer 1".into());
    }
    h.withdraw(0, RATE).map_err(|e| format!("c9 withdraw: {e}"))?;
    let st = h.status();
    let custody = h.fee_custody();
    let expect = u128::from(nat64(&st.total_prepaid)) + u128::from(nat64(&st.revenue));
    if custody != expect {
        return Err(format!(
            "c9 RED: custody {custody} != total {} + revenue {} (token fee {fee})",
            nat64(&st.total_prepaid),
            nat64(&st.revenue)
        ));
    }
    if nat64(&st.revenue) != 2 * RATE {
        return Err(format!("c9: revenue {} want {}", nat64(&st.revenue), 2 * RATE));
    }
    println!("[C9] PASS solvency at rest: custody {custody} == total+revenue after mixed workload");
    Ok(())
}

/// C10 deposit crash recovery: the canister traps AFTER the token pull, the dedup window
/// expires, and resume_prepaid must credit EXACTLY once via the memo reconcile (never
/// re-charging, never losing the deposit).
fn c10_crash_recovery(w: &pic_env::BuiltWasms, ks: keys::Keyset) -> Result<(), String> {
    let mut h = Harness::new(w, ks, "c10");
    h.set_prepaid(true);
    h.set_rate(RATE);
    let value = 6 * RATE;
    let account = ct::Account { owner: h.accounts[0].principal, subaccount: None };
    let token_before = h.env.token_balance(&account);
    h.arm_fail_after_token();
    let args = h.deposit_args(value);
    let call: Result<ct::MotokoResult<candid::Nat>, String> =
        h.env.update(h.env.ledger, h.accounts[0].principal, "prepaid_fee_deposit", (args,));
    if call.is_ok() {
        return Err("c10: armed deposit unexpectedly completed".into());
    }
    // the pull happened (tokens moved), the credit did not
    let token_mid = h.env.token_balance(&account);
    if token_mid + u128::from(value) + u128::from(h.env.token_fee) != token_before {
        return Err(format!("c10: token leg did not land (balance {token_before} -> {token_mid})"));
    }
    if h.balance_of(0) != 0 {
        return Err("c10: balance credited despite the trap".into());
    }
    // past the dedup window, a naive re-send would be TooOld and lose the deposit
    h.advance_past_dedup_window();
    let after = h.resume(0).map_err(|e| format!("c10 RED: resume failed: {e}"))?;
    if after != value {
        return Err(format!("c10 RED: resume credited {after}, want {value}"));
    }
    let token_end = h.env.token_balance(&account);
    if token_end != token_mid {
        return Err(format!("c10 RED: resume moved tokens again ({token_mid} -> {token_end})"));
    }
    // idempotent replay: a second resume has nothing to do
    match h.resume(0) {
        Err(e) if e == "REJECT:no-pending-prepaid" => {}
        other => return Err(format!("c10: second resume returned {other:?}")),
    }
    println!("[C10] PASS crash recovery: post-window resume credited exactly once by memo reconcile");
    Ok(())
}

// ---------------------------------------------------------------------------
// Planted-defect variants
// ---------------------------------------------------------------------------

fn build_variant(root: &Path, wasms: &pic_env::BuiltWasms, tag: &str, patches: &[(&str, &str)]) -> pic_env::BuiltWasms {
    let stage = std::env::temp_dir().join(format!("prepaid_variant_{}_{}", std::process::id(), tag));
    let _ = std::fs::remove_dir_all(&stage);
    pic_env::copy_dir_recursive(&root.join("src"), &stage.join("src"));
    let main_path = stage.join("src/Main.mo");
    let mut source = std::fs::read_to_string(&main_path).expect("read Main.mo");
    for (from, to) in patches {
        assert!(
            source.contains(from),
            "variant {tag}: patch anchor not found:\n{from}"
        );
        source = source.replace(from, to);
    }
    std::fs::write(&main_path, source).expect("write patched Main.mo");
    let out = stage.join("zk_ledger_variant.wasm");
    let sources_raw = String::from_utf8(
        std::process::Command::new("/usr/bin/mops")
            .arg("sources")
            .current_dir(root)
            .output()
            .expect("mops")
            .stdout,
    )
    .unwrap();
    let source_args: Vec<String> = sources_raw.split_whitespace().map(String::from).collect();
    let status = std::process::Command::new("/opt/moc-1.4.1/moc")
        .args(&source_args)
        .arg("-c")
        .arg(main_path.to_str().unwrap())
        .arg("-o")
        .arg(&out)
        .current_dir(root)
        .status()
        .expect("moc spawn");
    assert!(status.success(), "variant {tag} compile failed");
    let ledger = std::fs::read(&out).expect("read variant wasm");
    pic_env::BuiltWasms { ledger, ..wasms.clone() }
}

fn main() {
    let root = repo_root();
    let keyset_for = || {
        let manifest = std::fs::read_to_string(
            root.join("fixtures/pool-vectors-bls12-381/SETUP-MANIFEST.json"),
        )
        .unwrap();
        keys::regenerate_and_verify(&manifest, true).expect("keyset")
    };
    println!("[battery] building wasms (ledger + token + tree oracle)...");
    let wasms = pic_env::build_wasms(&root, &root.join("soak/target/wasms"));
    println!("[battery] ledger sha256 {}", wasms.ledger_sha256);

    type Check = (&'static str, fn(&pic_env::BuiltWasms, keys::Keyset) -> Result<(), String>);
    let checks: Vec<Check> = vec![
        ("C1", c1_zero_rate_noop),
        ("C2", c2_insufficient_reject),
        ("C3", c3_exact_boundary),
        ("C4", c4_overflow_dust),
        ("C5", c5_interleaving),
        ("C6", c6_upgrade_persistence),
        ("C7", c7_withdraw_all),
        ("C8", c8_flag_off),
        ("C9", c9_solvency),
        ("C10", c10_crash_recovery),
    ];

    // ---- TEETH FIRST: every check RED on its planted-defect variant ----
    println!("\n==== TEETH: planted defects must turn the checks RED ====");
    let variant_x = build_variant(
        &root,
        &wasms,
        "X",
        &[
            (
                "let balance = prepaidFeeBalance(holder);\n    if (balance < amount) return false;\n    setPrepaidFeeBalance(holder, balance - amount);\n    prepaid_fee_total -= amount;\n    true",
                "true // PLANTED DEFECT X: debit skipped",
            ),
            (
                "    let prepaidRate = activePrepaidRate();\n    if (prepaidRate > 0 and prepaidFeeBalance(caller) < prepaidRate) {\n      return mutation(\"REJECT:prepaid-fee-insufficient\", \"NOT_CALLED\");\n    };",
                "    let prepaidRate = activePrepaidRate(); // PLANTED DEFECT X: pre-verify guard removed",
            ),
        ],
    );
    let variant_y = build_variant(
        &root,
        &wasms,
        "Y",
        &[(
            "func activePrepaidRate() : Nat { if (prepaid_fee_enabled) prepaid_fee_rate else 0 };",
            "func activePrepaidRate() : Nat { if (prepaid_fee_rate == 0) 1 else prepaid_fee_rate }; // PLANTED DEFECT Y: flag ignored, floor 1",
        )],
    );
    let variant_w = build_variant(
        &root,
        &wasms,
        "W",
        &[(
            "let prepaid_fee_balances = Map.empty<Principal, Nat>();",
            "transient let prepaid_fee_balances = Map.empty<Principal, Nat>(); // PLANTED DEFECT W: balances wiped by upgrades",
        )],
    );
    let variant_r = build_variant(
        &root,
        &wasms,
        "R",
        &[(
            "pending_prepaid := ?{ pending with attempts = pending.attempts + 1 };\n    await drivePendingPrepaid(pending.intent_id, false, true)",
            "pending_prepaid := ?{ pending with attempts = pending.attempts + 1 };\n    await drivePendingPrepaid(pending.intent_id, false, false) // PLANTED DEFECT R: resume without reconcile",
        )],
    );

    let red_expectations: Vec<(&str, &pic_env::BuiltWasms, Vec<&str>)> = vec![
        ("X:debit-skipped", &variant_x, vec!["C2", "C3", "C4", "C5", "C7", "C9"]),
        ("Y:flag-ignored", &variant_y, vec!["C1", "C8"]),
        ("W:transient-balances", &variant_w, vec!["C6"]),
        ("R:no-reconcile", &variant_r, vec!["C10"]),
    ];

    let mut teeth = 0u32;
    for (vname, vwasms, red_checks) in &red_expectations {
        for want_red in red_checks {
            let (_, f) = checks.iter().find(|(n, _)| n == want_red).unwrap();
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                f(vwasms, keyset_for())
            }));
            let red = match outcome {
                Ok(Err(reason)) => {
                    println!("[TEETH {vname}/{want_red}] RED as required: {reason}");
                    true
                }
                Ok(Ok(())) => false,
                Err(_) => {
                    println!("[TEETH {vname}/{want_red}] RED as required (hard panic)");
                    true
                }
            };
            assert!(red, "TEETH FAILED: {want_red} stayed GREEN on planted defect {vname}");
            teeth += 1;
        }
    }
    println!("==== TEETH: {teeth}/10 planted-defect reds confirmed ====");

    // ---- GREEN: every check must pass on the shipped wasm ----
    println!("\n==== SHIPPED WASM: all checks must be GREEN ====");
    let mut green = 0u32;
    for (name, f) in &checks {
        f(&wasms, keyset_for()).unwrap_or_else(|e| panic!("{name} FAILED on the shipped wasm: {e}"));
        green += 1;
    }
    println!("\nPREPAID-FEE BATTERY COMPLETE: {green}/10 green on shipped, {teeth}/10 planted reds");
    println!("PREPAID-FEE-BATTERY: PASS");
}
