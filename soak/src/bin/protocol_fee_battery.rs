//! Protocol-fee battery — teeth-first, on PocketIC.
//!
//! Proves the protocol fee (a FLAT fee on every private transfer and a basis-point share of every
//! unshield, both carried in the transfer proof's public `fee` and moved from pool_value into
//! protocol_fee_revenue at commit; revenue swept in batches from the pool account into the ledger's
//! own treasury subaccount, then withdrawn from the treasury to a configured recipient)
//! against the REAL ledger wasm with real Groth16 proofs. Every check is first turned RED against
//! a deliberately broken ledger variant compiled from a patched source copy (the shipped tree is
//! never modified):
//!
//!   A  send fee not earned        (private commit skips pool_value -= / revenue +=)
//!   B  private fee check removed  (any fee accepted on a private transfer)
//!   C  unshield share rounded DOWN instead of up
//!   D  unshield share not earned at finalize
//!   E  sweep pays from the prepaid-fee subaccount instead of the pool account
//!   H  sweep never credits the treasury
//!   F  send fee transient (an upgrade wipes the schedule)
//!   G  send-fee cap removed
//!   I  recipient-is-ledger guard removed (a payout could land in the ledger's own accounts)
//!
//! Checks (each asserts canister state, token balances, and BOTH custody identities at rest:
//! pool-account balance == pool_value + revenue; treasury-account balance == treasury):
//!   P1 zero schedule is inert           P2 flat send fee earned exactly once
//!   P3 wrong send fee: clean REJECT     P4 unshield share (rounded up) earned at finalize
//!   P5 wrong unshield fee: clean REJECT P6 sweep pool→treasury, then withdraw treasury→recipient
//!   P7 upgrade keeps schedule+revenue   P8 caps + admin gate on the schedule; no recipient owned
//!      by the ledger itself (default, pool or treasury account)
//!   P9 a private transfer submitted by the ANONYMOUS principal is accepted and charged
//!   P10 crash after the unshield payout: resume earns the share exactly once; crash after the
//!       sweep: resume credits the treasury exactly once; crash after the withdraw: resume pays
//!       the recipient exactly once
//!
//! RED expectations: A ⇒ P2,P9; B ⇒ P3; C ⇒ P4; D ⇒ P4,P10; E ⇒ P6; F ⇒ P7; G ⇒ P8;
//! H ⇒ P6,P10; I ⇒ P8. The battery
//! PASSES only if every check is green on the shipped wasm AND every listed check goes red on its
//! variant.

use ark_ff::UniformRand;
use candid::Principal;
use soak::candid_types as ct;
use soak::crypto::f_bytes;
use soak::model::AccountKeys;
use soak::{keys, pic_env, prover};
use std::path::{Path, PathBuf};

type F = common::ScalarField;

const SEND_FEE: u64 = 10_000_000; // 0.1 token at 8 decimals — the ruled launch fee
const UNSHIELD_BPS: u64 = 30; // 0.3% — the ruled launch share
const FUND: u128 = 1_000_000_000;
const NOTE: u64 = 200_000_000; // 2 tokens per shielded note
const SEED: u64 = 20261015;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

/// The share the ledger must charge: ceil(v * bps / 10_000), computed independently here.
fn expected_share(v: u64, bps: u64) -> u64 {
    let num = u128::from(v) * u128::from(bps);
    u64::try_from(num.div_ceil(10_000)).unwrap()
}

#[derive(candid::CandidType, serde::Deserialize, Clone)]
struct ProtocolFeeConfig {
    send_fee: u64,
    unshield_bps: candid::Nat,
    recipient: Option<ct::Account>,
}

#[derive(candid::CandidType, serde::Deserialize)]
struct ProtocolFeeStatus {
    send_fee: candid::Nat,
    unshield_bps: candid::Nat,
    recipient: Option<ct::Account>,
    revenue: candid::Nat,
    transparent_ledger_fee: candid::Nat,
    pool_custody_at_rest: candid::Nat,
    treasury: candid::Nat,
    treasury_account: ct::Account,
}

#[derive(candid::CandidType, serde::Deserialize)]
struct AtomicityPending {
    intent_id: ct::Blob,
}

#[derive(candid::CandidType, serde::Deserialize)]
struct AtomicityStatus {
    pool_account: ct::Account,
    pending_unshield: Option<AtomicityPending>,
}

fn nat(n: &candid::Nat) -> u128 {
    u128::try_from(n.0.clone()).unwrap()
}

struct NoteRec {
    acct: usize,
    v: u64,
    rho: F,
    rcm: F,
}

struct Harness {
    env: pic_env::Env,
    keyset: keys::Keyset,
    cfg: common::PoseidonCfg<F>,
    cfg_tree: common::TreeCfg,
    accounts: Vec<AccountKeys>,
    leaves: Vec<F>,
    notes: Vec<NoteRec>,
    op: u64,
}

impl Harness {
    fn new(wasms: &pic_env::BuiltWasms, keyset: keys::Keyset, tag: &str) -> Self {
        let cfg = common::poseidon_config();
        let accounts = soak::model::derive_accounts(SEED, 4, &cfg);
        let state_dir =
            std::env::temp_dir().join(format!("protocol_fee_battery_{}_{}", std::process::id(), tag));
        let _ = std::fs::remove_dir_all(&state_dir);
        std::fs::create_dir_all(&state_dir).unwrap();
        let env = pic_env::setup(wasms, &keyset.transfer_vk_hex, &keyset.deposit_vk_hex, &state_dir);
        let principals: Vec<Principal> = accounts.iter().map(|a| a.principal).collect();
        pic_env::fund_accounts(&env, &principals, FUND, FUND);
        Harness { env, keyset, cfg, cfg_tree: common::poseidon_config_tree(), accounts, leaves: Vec::new(), notes: Vec::new(), op: 0 }
    }

    fn admin(&self) -> Principal {
        self.env.admin
    }

    /// Account 2 stands in for the backend canister's main account (the ruled recipient).
    fn recipient(&self) -> ct::Account {
        ct::Account { owner: self.accounts[2].principal, subaccount: None }
    }

    fn set_fee_as(&self, who: Principal, send_fee: u64, bps: u64, recipient: Option<ct::Account>) -> Result<ProtocolFeeStatus, String> {
        let config = ProtocolFeeConfig { send_fee, unshield_bps: candid::Nat::from(bps), recipient };
        let r: ct::MotokoResult<ProtocolFeeStatus> = self
            .env
            .update(self.env.ledger, who, "set_protocol_fee", (config,))
            .map_err(|e| format!("set_protocol_fee call: {e}"))?;
        r.into_result()
    }

    fn set_fee(&self, send_fee: u64, bps: u64) {
        self.set_fee_as(self.admin(), send_fee, bps, Some(self.recipient()))
            .unwrap_or_else(|e| panic!("set_protocol_fee: {e}"));
    }

    fn status(&self) -> ProtocolFeeStatus {
        self.env.query(self.env.ledger, "protocol_fee_status", ()).expect("protocol_fee_status")
    }

    fn required_fee(&self, v_pub_out: u64) -> u64 {
        let n: candid::Nat =
            self.env.query(self.env.ledger, "required_transfer_fee", (v_pub_out,)).expect("required_transfer_fee");
        u64::try_from(n.0).unwrap()
    }

    fn atomicity(&self) -> AtomicityStatus {
        self.env.query(self.env.ledger, "atomicity_status", ()).expect("atomicity_status")
    }

    fn pool_custody(&self) -> u128 {
        let pool = self.atomicity().pool_account;
        self.env.token_balance(&pool)
    }

    fn pool_value(&self) -> u128 {
        nat(&self.env.ledger_status().pool_value)
    }

    /// The custody identity at rest: the pool account holds exactly pool_value + revenue, and the
    /// status field reports the same sum.
    fn custody_identity(&self, label: &str) -> Result<(), String> {
        let custody = self.pool_custody();
        let st = self.status();
        let expect = self.pool_value() + nat(&st.revenue);
        if custody != expect || nat(&st.pool_custody_at_rest) != expect {
            return Err(format!(
                "{label}: custody {custody} != pool_value {} + revenue {} (status says {})",
                self.pool_value(),
                nat(&st.revenue),
                nat(&st.pool_custody_at_rest)
            ));
        }
        let treasury_custody = self.env.token_balance(&st.treasury_account);
        if treasury_custody != nat(&st.treasury) {
            return Err(format!("{label}: treasury account holds {treasury_custody} != treasury {}", nat(&st.treasury)));
        }
        Ok(())
    }

    fn shield(&mut self, acct: usize, v: u64) -> ct::MutationResult {
        self.op += 1;
        let mut prng = prover::op_rng(SEED, self.op, "protocol-fee-shield-plan");
        let rho = F::rand(&mut prng);
        let rcm = F::rand(&mut prng);
        let mut prepared = prover::prepare_shield(
            &self.cfg,
            &self.keyset.deposit_pk,
            &self.accounts[acct],
            v,
            rho,
            rcm,
            SEED,
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
            self.notes.push(NoteRec { acct, v, rho, rcm });
        }
        m
    }

    fn binding_for(&self, account: &ct::Account) -> [u8; 32] {
        let r: ct::MotokoResult<ct::Blob> = self
            .env
            .query(self.env.ledger, "recipient_binding", (account.clone(),))
            .expect("recipient_binding");
        let b = r.into_result().expect("recipient_binding result");
        <[u8; 32]>::try_from(b.as_ref()).expect("32-byte binding")
    }

    /// Prove a transfer spending notes `i`,`j` of `acct`. Private when `v_pub == 0` (first output
    /// to `to_acct`, change back to `acct`); otherwise an unshield of `v_pub` to `acct`'s own
    /// account with both outputs back to `acct`. Outputs absorb `total - first - fee - v_pub`.
    fn prepare(&mut self, acct: usize, i: usize, j: usize, to_acct: usize, first: u64, fee: u64, v_pub: u64) -> prover::PreparedTransfer {
        self.op += 1;
        let plan = |note: usize| -> prover::TransferPlanInput {
            let n = &self.notes[note];
            prover::TransferPlanInput {
                note_index: note,
                leaf_index: note as u64,
                v: n.v,
                nk: self.accounts[n.acct].nk,
                rho: n.rho,
                rcm: n.rcm,
            }
        };
        let tree = common::DenseTree { leaves: self.leaves.clone() };
        let anchor = tree.root(&self.cfg_tree);
        let mut prng = prover::op_rng(SEED, self.op, "protocol-fee-transfer-plan");
        let crypto = prover::TransferCrypto {
            anchor,
            path1: tree.path(&self.cfg_tree, i),
            path2: tree.path(&self.cfg_tree, j),
            out_rcm1: F::rand(&mut prng),
            out_rcm2: F::rand(&mut prng),
        };
        let total = self.notes[i].v + self.notes[j].v;
        let change = total - first - fee - v_pub;
        let (in1, in2) = (plan(i), plan(j));
        let (binding, recipient, recipient_acct, first_owner) = if v_pub > 0 {
            let account = ct::Account { owner: self.accounts[acct].principal, subaccount: None };
            (self.binding_for(&account), Some(account), Some(acct), acct)
        } else {
            ([0u8; 32], None, None, to_acct)
        };
        prover::prepare_transfer(
            &self.cfg,
            &self.keyset.transfer_pk,
            self.keyset.legacy_statement,
            &crypto,
            (&in1, &in2),
            (&self.accounts[first_owner], &self.accounts[acct]),
            (first, change),
            fee,
            v_pub,
            binding,
            recipient,
            recipient_acct,
            SEED,
            self.op,
        )
    }

    fn submit_as(&mut self, who: Principal, prepared: &prover::PreparedTransfer) -> Result<ct::MutationResult, String> {
        let mut args = prepared.args.clone();
        if args.v_pub_out > 0 {
            args.created_at_time = Some(self.env.time_ns());
        }
        let m: ct::MutationResult = self.env.update(self.env.ledger, who, "confidential_transfer", (args,))?;
        if m.outcome == "ACCEPT" {
            self.record_accepted(prepared);
        }
        Ok(m)
    }

    fn submit(&mut self, acct: usize, prepared: &prover::PreparedTransfer) -> ct::MutationResult {
        let who = self.accounts[acct].principal;
        self.submit_as(who, prepared).expect("confidential_transfer call")
    }

    fn record_accepted(&mut self, prepared: &prover::PreparedTransfer) {
        for (owner, v, rho, rcm) in prepared.outs.iter() {
            let cm = common::note_commitment(&self.cfg, *v, self.accounts[*owner].pk, *rho, *rcm);
            self.leaves.push(cm);
            self.notes.push(NoteRec { acct: *owner, v: *v, rho: *rho, rcm: *rcm });
        }
        let tree = common::DenseTree { leaves: self.leaves.clone() };
        let root = f_bytes(&tree.root(&self.cfg_tree)).to_vec();
        let status = self.env.ledger_status();
        assert_eq!(status.note_root.as_ref(), root.as_slice(), "battery mirror diverged from the ledger root");
    }

    fn admin_payout(&self, who: Principal, method: &str, amount: u64) -> Result<u128, String> {
        let r: ct::MotokoResult<candid::Nat> = self
            .env
            .update(self.env.ledger, who, method, (amount, self.env.time_ns()))
            .map_err(|e| format!("{method} call: {e}"))?;
        r.into_result().map(|n| nat(&n))
    }

    fn sweep(&self, who: Principal, amount: u64) -> Result<u128, String> {
        self.admin_payout(who, "protocol_fee_sweep", amount)
    }

    fn withdraw(&self, who: Principal, amount: u64) -> Result<u128, String> {
        self.admin_payout(who, "protocol_treasury_withdraw", amount)
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
            .expect("test_arm_fail_after_token_once (needs the hook wasm)");
        r.into_result().expect("arm fault");
    }

    fn token_of(&self, acct: usize) -> u128 {
        self.env.token_balance(&ct::Account { owner: self.accounts[acct].principal, subaccount: None })
    }
}

/// Two shielded notes for `acct`; returns their note indices.
fn two_notes(h: &mut Harness, acct: usize) -> (usize, usize) {
    let a = h.notes.len();
    assert_eq!(h.shield(acct, NOTE).outcome, "ACCEPT", "shield 1");
    assert_eq!(h.shield(acct, NOTE).outcome, "ACCEPT", "shield 2");
    (a, a + 1)
}

/// The full mutable footprint a rejected transfer must not touch.
fn snapshot(h: &Harness) -> (Vec<u8>, u128, u128, u128, u128, u128) {
    let s = h.env.ledger_status();
    (
        s.note_root.to_vec(),
        nat(&s.epoch),
        nat(&s.nullifier_count),
        nat(&s.pool_value),
        nat(&h.status().revenue),
        h.pool_custody(),
    )
}

struct Wasms {
    plain: pic_env::BuiltWasms,
    hooks: pic_env::BuiltWasms,
}

// ---------------------------------------------------------------------------
// The checks. Each returns Err(reason) rather than panicking so the SAME code path is asserted
// GREEN on the shipped wasm and RED on a planted-defect variant.
// ---------------------------------------------------------------------------

/// P1: with the default (zero) schedule a fee-0 private transfer is accepted and nothing moves.
fn p1_zero_schedule(w: &Wasms, ks: keys::Keyset) -> Result<(), String> {
    let mut h = Harness::new(&w.plain, ks, "p1");
    let st = h.status();
    if nat(&st.send_fee) != 0 || nat(&st.unshield_bps) != 0 || nat(&st.revenue) != 0 {
        return Err("p1: fresh ledger has a non-zero schedule".into());
    }
    if h.required_fee(0) != 0 || h.required_fee(1_000_000) != h.env.token_fee {
        return Err("p1: zero schedule quotes a fee beyond the token fee".into());
    }
    let (i, j) = two_notes(&mut h, 0);
    let pv0 = h.pool_value();
    let p = h.prepare(0, i, j, 1, 50_000_000, 0, 0);
    let m = h.submit(0, &p);
    if m.outcome != "ACCEPT" {
        return Err(format!("p1: fee-0 transfer said {}", m.outcome));
    }
    if h.pool_value() != pv0 || nat(&h.status().revenue) != 0 {
        return Err("p1: zero schedule moved value".into());
    }
    h.custody_identity("p1")?;
    println!("[P1] PASS zero schedule: fee-0 transfer accepted, pool_value and revenue unchanged");
    Ok(())
}

/// P2: the flat send fee is charged on the proof, moved from pool_value to revenue exactly once.
fn p2_send_fee_earned(w: &Wasms, ks: keys::Keyset) -> Result<(), String> {
    let mut h = Harness::new(&w.plain, ks, "p2");
    h.set_fee(SEND_FEE, UNSHIELD_BPS);
    if h.required_fee(0) != SEND_FEE {
        return Err(format!("p2: quote {} != send fee {SEND_FEE}", h.required_fee(0)));
    }
    let (i, j) = two_notes(&mut h, 0);
    let pv0 = h.pool_value();
    let p = h.prepare(0, i, j, 1, 50_000_000, SEND_FEE, 0);
    let m = h.submit(0, &p);
    if m.outcome != "ACCEPT" {
        return Err(format!("p2: correct-fee transfer said {}", m.outcome));
    }
    let revenue = nat(&h.status().revenue);
    if revenue != u128::from(SEND_FEE) {
        return Err(format!("p2 RED: revenue {revenue}, want {SEND_FEE}"));
    }
    if h.pool_value() != pv0 - u128::from(SEND_FEE) {
        return Err(format!("p2 RED: pool_value {} want {}", h.pool_value(), pv0 - u128::from(SEND_FEE)));
    }
    h.custody_identity("p2 RED")?;
    println!("[P2] PASS send fee: {SEND_FEE} moved from pool_value to revenue, custody identity holds");
    Ok(())
}

/// P3: a private transfer proven with the wrong fee is rejected before the verifier, with zero
/// state mutation — both below and above the schedule.
fn p3_wrong_send_fee(w: &Wasms, ks: keys::Keyset) -> Result<(), String> {
    let mut h = Harness::new(&w.plain, ks, "p3");
    h.set_fee(SEND_FEE, UNSHIELD_BPS);
    let (i, j) = two_notes(&mut h, 0);
    for wrong in [0, SEND_FEE - 1, SEND_FEE + 1] {
        let before = snapshot(&h);
        let p = h.prepare(0, i, j, 1, 50_000_000, wrong, 0);
        let m = h.submit(0, &p);
        if m.outcome != "REJECT:transfer-fee-mismatch" {
            return Err(format!("p3 RED: fee {wrong} said {}", m.outcome));
        }
        if m.verifier_outcome != "NOT_CALLED" {
            return Err(format!("p3: verifier consulted for fee {wrong}"));
        }
        if snapshot(&h) != before {
            return Err(format!("p3: rejected fee {wrong} mutated state"));
        }
    }
    println!("[P3] PASS wrong send fee: 0, fee-1, fee+1 all REJECT:transfer-fee-mismatch, NOT_CALLED, zero mutation");
    Ok(())
}

/// P4: an unshield pays v to the caller; the share ceil(v·bps/10000) is earned at finalize;
/// pool_value drops by v + token fee + share.
fn p4_unshield_share(w: &Wasms, ks: keys::Keyset) -> Result<(), String> {
    let mut h = Harness::new(&w.plain, ks, "p4");
    h.set_fee(SEND_FEE, UNSHIELD_BPS);
    let (i, j) = two_notes(&mut h, 0);
    // 123_456_789 * 30 / 10_000 = 370_370.367 → the share must round UP to 370_371.
    let v = 123_456_789u64;
    let share = expected_share(v, UNSHIELD_BPS);
    if share != 370_371 {
        return Err(format!("p4: harness share {share}"));
    }
    let fee = h.env.token_fee + share;
    if h.required_fee(v) != fee {
        return Err(format!("p4 RED: ledger quotes {} want {fee}", h.required_fee(v)));
    }
    let pv0 = h.pool_value();
    let tok0 = h.token_of(0);
    let p = h.prepare(0, i, j, 0, 0, fee, v);
    let m = h.submit(0, &p);
    if m.outcome != "ACCEPT" {
        return Err(format!("p4 RED: correct unshield said {}", m.outcome));
    }
    if h.token_of(0) != tok0 + u128::from(v) {
        return Err(format!("p4: caller received {} want {v}", h.token_of(0) - tok0));
    }
    let revenue = nat(&h.status().revenue);
    if revenue != u128::from(share) {
        return Err(format!("p4 RED: revenue {revenue} want {share}"));
    }
    let want_pv = pv0 - u128::from(v) - u128::from(h.env.token_fee) - u128::from(share);
    if h.pool_value() != want_pv {
        return Err(format!("p4 RED: pool_value {} want {want_pv}", h.pool_value()));
    }
    h.custody_identity("p4 RED")?;
    println!("[P4] PASS unshield share: {v} paid, share {share} (rounded up) earned, custody identity holds");
    Ok(())
}

/// P5: an unshield carrying only the token fee (no share), or the share rounded down, is
/// rejected cleanly; a fee below the token fee keeps its original reason.
fn p5_wrong_unshield_fee(w: &Wasms, ks: keys::Keyset) -> Result<(), String> {
    let mut h = Harness::new(&w.plain, ks, "p5");
    h.set_fee(SEND_FEE, UNSHIELD_BPS);
    let (i, j) = two_notes(&mut h, 0);
    let v = 123_456_789u64;
    let token_fee = h.env.token_fee;
    let cases = [
        (token_fee, "REJECT:transfer-fee-mismatch"),
        (token_fee + 370_370, "REJECT:transfer-fee-mismatch"),
        (token_fee - 1, "REJECT:unshield-fee-below-token-fee"),
    ];
    for (fee, want) in cases {
        let before = snapshot(&h);
        let p = h.prepare(0, i, j, 0, 0, fee, v);
        let m = h.submit(0, &p);
        if m.outcome != want || m.verifier_outcome != "NOT_CALLED" {
            return Err(format!("p5 RED: fee {fee} said {} / {} want {want}", m.outcome, m.verifier_outcome));
        }
        if snapshot(&h) != before {
            return Err(format!("p5: rejected unshield fee {fee} mutated state"));
        }
    }
    println!("[P5] PASS wrong unshield fee: no-share, rounded-down, below-token-fee all rejected cleanly");
    Ok(())
}

/// P6: the sweep moves revenue from the pool account into the treasury subaccount (revenue down
/// by amount + token fee, treasury up by amount, pool_value untouched); the withdraw pays the
/// configured recipient out of the treasury. Non-admin, over-sweep, over-withdraw and
/// unset-recipient calls are refused with no change.
fn p6_sweep_and_withdraw(w: &Wasms, ks: keys::Keyset) -> Result<(), String> {
    let mut h = Harness::new(&w.plain, ks, "p6");
    let token_fee = h.env.token_fee;
    h.set_fee_as(h.admin(), SEND_FEE, UNSHIELD_BPS, None).map_err(|e| format!("p6 set: {e}"))?;
    let (i, j) = two_notes(&mut h, 0);
    let p = h.prepare(0, i, j, 1, 50_000_000, SEND_FEE, 0);
    if h.submit(0, &p).outcome != "ACCEPT" {
        return Err("p6: fee transfer".into());
    }
    let revenue = u64::try_from(nat(&h.status().revenue)).unwrap();
    match h.sweep(h.accounts[0].principal, 1) {
        Err(e) if e == "REJECT:not-administrator" => {}
        other => return Err(format!("p6: non-admin sweep returned {other:?}")),
    }
    match h.sweep(h.admin(), revenue) {
        Err(e) if e == "REJECT:protocol-fee-insufficient" => {}
        other => return Err(format!("p6: over-sweep returned {other:?}")),
    }
    if nat(&h.status().revenue) != u128::from(revenue) {
        return Err("p6: refused over-sweep changed revenue".into());
    }
    let pv0 = h.pool_value();
    let swept = revenue - token_fee;
    let treasury = h.sweep(h.admin(), swept).map_err(|e| format!("p6 RED: sweep failed: {e}"))?;
    let st = h.status();
    if treasury != u128::from(swept) || nat(&st.treasury) != u128::from(swept) || nat(&st.revenue) != 0 {
        return Err(format!("p6 RED: after sweep treasury {} revenue {} want {swept}/0", nat(&st.treasury), nat(&st.revenue)));
    }
    if h.pool_value() != pv0 {
        return Err("p6 RED: sweep touched pool_value".into());
    }
    h.custody_identity("p6 RED (sweep)")?;
    // withdraw: refused with no recipient, then paid to the recipient once it is set
    match h.withdraw(h.admin(), 1) {
        Err(e) if e == "REJECT:protocol-fee-recipient-unset" => {}
        other => return Err(format!("p6: unset-recipient withdraw returned {other:?}")),
    }
    h.set_fee(SEND_FEE, UNSHIELD_BPS);
    match h.withdraw(h.admin(), swept) {
        Err(e) if e == "REJECT:protocol-treasury-insufficient" => {}
        other => return Err(format!("p6: over-withdraw returned {other:?}")),
    }
    match h.withdraw(h.accounts[0].principal, 1) {
        Err(e) if e == "REJECT:not-administrator" => {}
        other => return Err(format!("p6: non-admin withdraw returned {other:?}")),
    }
    let rec0 = h.token_of(2);
    let paid = swept - token_fee;
    let left = h.withdraw(h.admin(), paid).map_err(|e| format!("p6 RED: withdraw failed: {e}"))?;
    if left != 0 || nat(&h.status().treasury) != 0 {
        return Err(format!("p6 RED: treasury after withdraw-all {left}"));
    }
    if h.token_of(2) != rec0 + u128::from(paid) {
        return Err(format!("p6 RED: recipient grew by {} want {paid}", h.token_of(2) - rec0));
    }
    h.custody_identity("p6 RED (withdraw)")?;
    println!("[P6] PASS sweep {swept} pool→treasury, withdraw {paid} treasury→recipient; refusals clean; both identities hold");
    Ok(())
}

/// P7: schedule, recipient, and revenue survive an upgrade, and the fee still applies after it.
fn p7_upgrade(w: &Wasms, ks: keys::Keyset) -> Result<(), String> {
    let mut h = Harness::new(&w.plain, ks, "p7");
    h.set_fee(SEND_FEE, UNSHIELD_BPS);
    let (i, j) = two_notes(&mut h, 0);
    let p = h.prepare(0, i, j, 1, 50_000_000, SEND_FEE, 0);
    if h.submit(0, &p).outcome != "ACCEPT" {
        return Err("p7: pre-upgrade transfer".into());
    }
    let half = SEND_FEE / 2;
    h.sweep(h.admin(), half).map_err(|e| format!("p7 sweep: {e}"))?;
    h.upgrade();
    let st = h.status();
    if nat(&st.send_fee) != u128::from(SEND_FEE)
        || nat(&st.unshield_bps) != u128::from(UNSHIELD_BPS)
        || nat(&st.revenue) != u128::from(SEND_FEE - half - h.env.token_fee)
        || nat(&st.treasury) != u128::from(half)
        || st.recipient.as_ref().map(|a| a.owner) != Some(h.accounts[2].principal)
    {
        return Err(format!(
            "p7 RED: after upgrade send_fee {} bps {} revenue {}",
            nat(&st.send_fee),
            nat(&st.unshield_bps),
            nat(&st.revenue)
        ));
    }
    h.custody_identity("p7")?;
    println!("[P7] PASS upgrade: schedule, recipient, revenue and treasury preserved");
    Ok(())
}

/// P8: the caps and the administrator gate on set_protocol_fee.
fn p8_caps(w: &Wasms, ks: keys::Keyset) -> Result<(), String> {
    let h = Harness::new(&w.plain, ks, "p8");
    let rec = Some(h.recipient());
    let checks: [(Principal, u64, u64, &str); 3] = [
        (h.admin(), 100_000_001, 0, "REJECT:protocol-send-fee-cap"),
        (h.admin(), 0, 101, "REJECT:protocol-unshield-bps-cap"),
        (h.accounts[0].principal, SEND_FEE, UNSHIELD_BPS, "REJECT:not-administrator"),
    ];
    for (who, fee, bps, want) in checks {
        match h.set_fee_as(who, fee, bps, rec.clone()) {
            Err(e) if e == want => {}
            other => return Err(format!("p8 RED: ({fee},{bps}) returned {:?} want {want}", other.map(|_| "ok"))),
        }
    }
    // no recipient the ledger itself owns: its default account, its pool account, its treasury
    let treasury = h.status().treasury_account;
    let own = [
        ct::Account { owner: h.env.ledger, subaccount: None },
        h.env.pool_account(),
        treasury,
    ];
    for (k, account) in own.into_iter().enumerate() {
        match h.set_fee_as(h.admin(), SEND_FEE, UNSHIELD_BPS, Some(account)) {
            Err(e) if e == "REJECT:recipient-is-ledger" => {}
            other => return Err(format!("p8 RED: ledger-owned recipient {k} returned {:?} want REJECT:recipient-is-ledger", other.map(|_| "ok"))),
        }
    }
    let st = h.status();
    if nat(&st.send_fee) != 0 || nat(&st.unshield_bps) != 0 || st.recipient.is_some() {
        return Err("p8 RED: a refused setting took effect".into());
    }
    // the caps themselves are accepted
    h.set_fee_as(h.admin(), 100_000_000, 100, rec).map_err(|e| format!("p8: cap values refused: {e}"))?;
    println!("[P8] PASS caps: over-cap fee/bps, non-admin and ledger-owned recipients refused; cap values accepted");
    Ok(())
}

/// P9: a private transfer needs no identity — submitted by the ANONYMOUS principal it is accepted
/// and charged exactly like any other.
fn p9_anonymous(w: &Wasms, ks: keys::Keyset) -> Result<(), String> {
    let mut h = Harness::new(&w.plain, ks, "p9");
    h.set_fee(SEND_FEE, UNSHIELD_BPS);
    let (i, j) = two_notes(&mut h, 0);
    let p = h.prepare(0, i, j, 1, 50_000_000, SEND_FEE, 0);
    let m = h.submit_as(Principal::anonymous(), &p)?;
    if m.outcome != "ACCEPT" {
        return Err(format!("p9: anonymous private transfer said {}", m.outcome));
    }
    if nat(&h.status().revenue) != u128::from(SEND_FEE) {
        return Err(format!("p9 RED: anonymous transfer earned {}", nat(&h.status().revenue)));
    }
    h.custody_identity("p9 RED")?;
    println!("[P9] PASS anonymous submission: accepted and charged {SEND_FEE}");
    Ok(())
}

/// P10: crash AFTER the token leg, three times. (a) unshield: the payout lands, the canister traps
/// before finalize; the share is not yet earned; resume_unshield earns it exactly once. (b) sweep:
/// the move lands; resume_prepaid credits the treasury exactly once. (c) withdraw: the payout lands;
/// resume_prepaid finalizes without paying again.
fn p10_crash_recovery(w: &Wasms, ks: keys::Keyset) -> Result<(), String> {
    let mut h = Harness::new(&w.hooks, ks, "p10");
    h.set_fee(SEND_FEE, UNSHIELD_BPS);
    let (i, j) = two_notes(&mut h, 0);
    let v = 123_456_789u64;
    let share = expected_share(v, UNSHIELD_BPS);
    let fee = h.env.token_fee + share;
    let tok0 = h.token_of(0);
    let pv0 = h.pool_value();
    let p = h.prepare(0, i, j, 0, 0, fee, v);
    h.arm_fail_after_token();
    if h.submit_as(h.accounts[0].principal, &p).is_ok() {
        return Err("p10: armed unshield completed instead of trapping".into());
    }
    if h.atomicity().pending_unshield.is_none() {
        return Err("p10: no pending unshield after the trap".into());
    }
    if h.token_of(0) != tok0 + u128::from(v) {
        return Err("p10: the payout did not land before the trap".into());
    }
    if nat(&h.status().revenue) != 0 {
        return Err("p10: share earned before finalize".into());
    }
    let r: ct::MutationResult = h
        .env
        .update(h.env.ledger, h.accounts[0].principal, "resume_unshield", ())
        .map_err(|e| format!("p10 resume call: {e}"))?;
    if r.outcome != "ACCEPT" {
        return Err(format!("p10: resume_unshield said {}", r.outcome));
    }
    h.record_accepted(&p);
    if h.token_of(0) != tok0 + u128::from(v) {
        return Err("p10 RED: resume paid the unshield again".into());
    }
    if nat(&h.status().revenue) != u128::from(share) {
        return Err(format!("p10 RED: revenue after resume {} want {share}", nat(&h.status().revenue)));
    }
    let want_pv = pv0 - u128::from(v) - u128::from(h.env.token_fee) - u128::from(share);
    if h.pool_value() != want_pv {
        return Err(format!("p10 RED: pool_value {} want {want_pv}", h.pool_value()));
    }
    h.custody_identity("p10 RED (unshield)")?;

    // (b) sweep crash: the move lands, the canister traps; resume credits the treasury once
    let swept = share - h.env.token_fee;
    let pool_tok0 = h.pool_custody();
    h.arm_fail_after_token();
    if h.sweep(h.admin(), swept).is_ok() {
        return Err("p10: armed sweep completed instead of trapping".into());
    }
    if h.pool_custody() + u128::from(swept) + u128::from(h.env.token_fee) != pool_tok0 {
        return Err("p10: the sweep did not land before the trap".into());
    }
    let r: ct::MotokoResult<candid::Nat> = h
        .env
        .update(h.env.ledger, h.admin(), "resume_prepaid", ())
        .map_err(|e| format!("p10 resume_prepaid call: {e}"))?;
    r.into_result().map_err(|e| format!("p10: resume_prepaid after sweep: {e}"))?;
    if nat(&h.status().treasury) != u128::from(swept) {
        return Err(format!("p10 RED: treasury after resumed sweep {} want {swept}", nat(&h.status().treasury)));
    }
    h.custody_identity("p10 RED (sweep)")?;

    // (c) withdraw crash: the payout lands, the canister traps; resume pays exactly once
    let rec0 = h.token_of(2);
    let paid = swept - h.env.token_fee;
    h.arm_fail_after_token();
    if h.withdraw(h.admin(), paid).is_ok() {
        return Err("p10: armed withdraw completed instead of trapping".into());
    }
    if h.token_of(2) != rec0 + u128::from(paid) {
        return Err("p10: the withdraw did not land before the trap".into());
    }
    let r: ct::MotokoResult<candid::Nat> = h
        .env
        .update(h.env.ledger, h.admin(), "resume_prepaid", ())
        .map_err(|e| format!("p10 resume_prepaid call: {e}"))?;
    r.into_result().map_err(|e| format!("p10: resume_prepaid after withdraw: {e}"))?;
    if h.token_of(2) != rec0 + u128::from(paid) {
        return Err("p10 RED: resume paid the withdraw again".into());
    }
    if nat(&h.status().treasury) != 0 {
        return Err(format!("p10: treasury after withdraw-all {}", nat(&h.status().treasury)));
    }
    h.custody_identity("p10 RED (withdraw)")?;
    println!("[P10] PASS crash recovery: unshield share earned once, sweep credited once, withdraw paid once");
    Ok(())
}

// ---------------------------------------------------------------------------
// Builds
// ---------------------------------------------------------------------------

/// Compile src/Main.mo with `patches` applied and, when `hooks`, the admin-gated test-hook
/// fragment injected before the actor's closing brace (the build-test-wasm.sh construction).
fn build_ledger(root: &Path, tag: &str, patches: &[(&str, &str)], hooks: bool) -> Vec<u8> {
    let stage = std::env::temp_dir().join(format!("protocol_fee_variant_{}_{}", std::process::id(), tag));
    let _ = std::fs::remove_dir_all(&stage);
    pic_env::copy_dir_recursive(&root.join("src"), &stage.join("src"));
    let main_path = stage.join("src/Main.mo");
    let mut source = std::fs::read_to_string(&main_path).expect("read Main.mo");
    for (from, to) in patches {
        assert!(source.contains(from), "variant {tag}: patch anchor not found:\n{from}");
        assert_eq!(source.matches(from).count(), 1, "variant {tag}: patch anchor not unique:\n{from}");
        source = source.replace(from, to);
    }
    if hooks {
        let fragment = std::fs::read_to_string(root.join("scripts/test-hooks.frag.mo")).expect("read hook fragment");
        let close = source.rfind('}').expect("actor closing brace");
        source = format!(
            "{}  // ================= TEST HOOKS (generated; NEVER in the shipped wasm) =================\n{}\n  // ================= END TEST HOOKS =================\n{}",
            &source[..close],
            fragment,
            &source[close..]
        );
    }
    std::fs::write(&main_path, source).expect("write patched Main.mo");
    let out = stage.join("zk_ledger_variant.wasm");
    let sources_raw = String::from_utf8(
        std::process::Command::new("/usr/bin/mops").arg("sources").current_dir(root).output().expect("mops").stdout,
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
    std::fs::read(&out).expect("read variant wasm")
}

fn wasms_for(root: &Path, base: &pic_env::BuiltWasms, tag: &str, patches: &[(&str, &str)]) -> Wasms {
    let plain = if patches.is_empty() { base.ledger.clone() } else { build_ledger(root, tag, patches, false) };
    let hooks = build_ledger(root, &format!("{tag}-hooks"), patches, true);
    Wasms {
        plain: pic_env::BuiltWasms { ledger: plain, ..base.clone() },
        hooks: pic_env::BuiltWasms { ledger: hooks, ..base.clone() },
    }
}

type Check = (&'static str, fn(&Wasms, keys::Keyset) -> Result<(), String>);

fn main() {
    let root = repo_root();
    // The SHIPPED transfer statement is the hardened one (in-circuit fee/v_pub_out ranges and
    // input-note distinctness), so the battery proves against the hardened deterministic keyset.
    let manifest =
        std::fs::read_to_string(root.join("fixtures/pool-vectors-bls12-381-hardened/SETUP-MANIFEST.json")).unwrap();
    println!("[battery] regenerating the hardened-statement test keyset...");
    let keyset = keys::regenerate_and_verify(&manifest, false).expect("keyset");
    println!("[battery] building wasms (ledger + token + tree oracle)...");
    let base = pic_env::build_wasms(&root, &root.join("soak/target/wasms"));
    println!("[battery] shipped ledger sha256 {}", base.ledger_sha256);
    let shipped = wasms_for(&root, &base, "shipped", &[]);

    let checks: Vec<Check> = vec![
        ("P1", p1_zero_schedule),
        ("P2", p2_send_fee_earned),
        ("P3", p3_wrong_send_fee),
        ("P4", p4_unshield_share),
        ("P5", p5_wrong_unshield_fee),
        ("P6", p6_sweep_and_withdraw),
        ("P7", p7_upgrade),
        ("P8", p8_caps),
        ("P9", p9_anonymous),
        ("P10", p10_crash_recovery),
    ];

    println!("\n==== TEETH: planted defects must turn the checks RED ====");
    let variants: Vec<(&str, Vec<(&str, &str)>, Vec<&str>)> = vec![
        (
            "A:send-fee-not-earned",
            vec![(
                "      pool_value -= protocolShare;\n      protocol_fee_revenue += protocolShare;\n      addNullifier(args.nullifier_1);",
                "      addNullifier(args.nullifier_1); // PLANTED DEFECT A: send fee not earned",
            )],
            vec!["P2", "P9"],
        ),
        (
            "B:private-fee-check-removed",
            vec![(
                "      if (Nat64.toNat(args.fee) != requiredFee) {\n        return mutation(\"REJECT:transfer-fee-mismatch\", \"NOT_CALLED\");\n      };\n      switch (args.claim_envelope) {",
                "      // PLANTED DEFECT B: private fee unchecked\n      switch (args.claim_envelope) {",
            )],
            vec!["P3"],
        ),
        (
            "C:share-rounded-down",
            vec![(
                "(vPubOut * bps + BPS_DENOMINATOR - 1) / BPS_DENOMINATOR",
                "(vPubOut * bps) / BPS_DENOMINATOR // PLANTED DEFECT C: rounded down",
            )],
            vec!["P4"],
        ),
        (
            "D:share-not-earned",
            vec![(
                "    pool_value -= pending.pool_debit + pending_unshield_protocol_fee;\n    protocol_fee_revenue += pending_unshield_protocol_fee;",
                "    pool_value -= pending.pool_debit; // PLANTED DEFECT D: share not earned",
            )],
            vec!["P4", "P10"],
        ),
        (
            "E:sweep-from-fee-subaccount",
            vec![(
                "        case (#sweep) pool_subaccount;\n",
                "        // PLANTED DEFECT E: sweep pays from the wrong account\n",
            )],
            vec!["P6"],
        ),
        (
            "H:sweep-not-credited",
            vec![(
                "          case (#sweep) protocol_treasury_balance += op.transfer_args.amount;",
                "          case (#sweep) {}; // PLANTED DEFECT H: treasury never credited",
            )],
            vec!["P6", "P10"],
        ),
        (
            "F:transient-schedule",
            vec![(
                "  var protocol_send_fee : Nat = 0;",
                "  transient var protocol_send_fee : Nat = 0; // PLANTED DEFECT F",
            )],
            vec!["P7"],
        ),
        (
            "G:cap-removed",
            vec![(
                "    if (sendFee > PROTOCOL_SEND_FEE_MAX) return #err(\"REJECT:protocol-send-fee-cap\");",
                "    // PLANTED DEFECT G: send-fee cap removed",
            )],
            vec!["P8"],
        ),
        (
            "I:recipient-is-ledger-guard-removed",
            vec![(
                "        if (account.owner == selfPrincipal()) return #err(\"REJECT:recipient-is-ledger\");",
                "        // PLANTED DEFECT I: recipient-is-ledger guard removed",
            )],
            vec!["P8"],
        ),
    ];

    let mut teeth = 0u32;
    let mut wanted = 0u32;
    for (vname, patches, red_checks) in &variants {
        let tag = vname.split(':').next().unwrap();
        let vw = wasms_for(&root, &base, tag, patches);
        for want_red in red_checks {
            wanted += 1;
            let (_, f) = checks.iter().find(|(n, _)| n == want_red).unwrap();
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(&vw, keyset.clone())));
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
    println!("==== TEETH: {teeth}/{wanted} planted-defect reds confirmed ====");

    println!("\n==== SHIPPED WASM: all checks must be GREEN ====");
    let mut green = 0u32;
    for (name, f) in &checks {
        f(&shipped, keyset.clone()).unwrap_or_else(|e| panic!("{name} FAILED on the shipped wasm: {e}"));
        green += 1;
    }
    println!("\nPROTOCOL-FEE BATTERY COMPLETE: {green}/{} green on shipped, {teeth}/{wanted} planted reds", checks.len());
    println!("PROTOCOL-FEE-BATTERY: PASS");
}
