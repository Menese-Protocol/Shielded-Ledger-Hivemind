//! Forged-proof cool-down battery — teeth-first, on PocketIC.
//!
//! The cool-down (set_forged_proof_guard) counts failed verifications from shield AND
//! confidential_transfer in one window; at the threshold it refuses every NEW proof, before the
//! verifier, until the cool-down ends. Proven against the REAL ledger wasm with real proofs. A
//! forgery here is a genuine proof submitted with altered public inputs (outputs swapped, or the
//! shield value changed), so every forged verdict is REJECT:pairing-check — the expensive path.
//!
//! Checks:
//!   G1 off by default: forgeries are counted but nothing cools down; honest transfers pass
//!   G2 configuration: administrator only; threshold, window and cool-down bounds
//!   G3 trip: forged shield + forged transfers reach the threshold; then a forged transfer, an
//!      honest transfer and an honest shield are all refused before the verifier (NOT_CALLED),
//!      with zero mutation, and the failure counters do not move
//!   G5 expiry: after the cool-down an honest transfer is accepted
//!   G6 window: failures from an expired window do not count toward the threshold
//!   G7 administrator: clear_forged_proof_cooldown (admin only) and threshold 0 both end a cool-down
//!   G8 upgrade: a running cool-down and its configuration survive an upgrade
//!   G9 cost: a refused-in-cool-down forgery is measured against a verified forgery (wall clock;
//!      PocketIC's system subnet does not charge cycles) and must cost under a quarter of it
//!
//! Finalize and resume paths never verify a proof and never consult the cool-down. A cool-down
//! cannot even overlap a pending intent: while one is pending, shield and confidential_transfer
//! refuse (pending-token-mutation) before the verifier, so nothing can be counted.
//!
//! RED expectations (each a patched copy of src/Main.mo; the shipped tree is never modified):
//!   A transfer failures not counted ⇒ G3   B shield failures not counted ⇒ G3
//!   C transfer ignores the cool-down ⇒ G3  D shield ignores the cool-down ⇒ G3
//!   E cool-down end transient ⇒ G8         F window never restarts ⇒ G6
//!   G configuration not admin-gated ⇒ G2   H cool-down never expires ⇒ G5

use ark_ff::UniformRand;
use candid::Principal;
use soak::candid_types as ct;
use soak::crypto::f_bytes;
use soak::model::AccountKeys;
use soak::{keys, pic_env, prover};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

type F = common::ScalarField;

const FUND: u128 = 2_000_000_000;
const NOTE: u64 = 100_000_000;
const SEED: u64 = 20261016;
const WINDOW: u64 = 600;
const COOLDOWN: u64 = 1800;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

#[derive(candid::CandidType, serde::Deserialize, Clone, Debug)]
struct GuardConfig {
    threshold: candid::Nat,
    window_seconds: candid::Nat,
    cooldown_seconds: candid::Nat,
}

#[derive(candid::CandidType, serde::Deserialize, Debug)]
struct GuardStatus {
    config: GuardConfig,
    cooling_down: bool,
    cooldown_until: candid::Int,
    failures_in_window: candid::Nat,
    window_started_at: candid::Int,
    trips: candid::Nat,
    failures_total: candid::Nat,
}

fn nat(n: &candid::Nat) -> u128 {
    u128::try_from(n.0.clone()).unwrap()
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
    cfg_tree: common::TreeCfg,
    accounts: Vec<AccountKeys>,
    leaves: Vec<F>,
    notes: Vec<NoteRec>,
    op: u64,
}

impl Harness {
    fn new(wasms: &pic_env::BuiltWasms, keyset: keys::Keyset, tag: &str) -> Self {
        let cfg = common::poseidon_config();
        let accounts = soak::model::derive_accounts(SEED, 3, &cfg);
        let state_dir = std::env::temp_dir().join(format!("forged_guard_battery_{}_{}", std::process::id(), tag));
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

    fn set_guard_as(&self, who: Principal, threshold: u64, window: u64, cooldown: u64) -> Result<GuardStatus, String> {
        let config = GuardConfig {
            threshold: candid::Nat::from(threshold),
            window_seconds: candid::Nat::from(window),
            cooldown_seconds: candid::Nat::from(cooldown),
        };
        let r: ct::MotokoResult<GuardStatus> = self
            .env
            .update(self.env.ledger, who, "set_forged_proof_guard", (config,))
            .map_err(|e| format!("set_forged_proof_guard call: {e}"))?;
        r.into_result()
    }

    fn set_guard(&self, threshold: u64) {
        self.set_guard_as(self.admin(), threshold, WINDOW, COOLDOWN).unwrap_or_else(|e| panic!("set guard: {e}"));
    }

    fn clear_as(&self, who: Principal) -> Result<GuardStatus, String> {
        let r: ct::MotokoResult<GuardStatus> = self
            .env
            .update(self.env.ledger, who, "clear_forged_proof_cooldown", ())
            .map_err(|e| format!("clear call: {e}"))?;
        r.into_result()
    }

    fn status(&self) -> GuardStatus {
        self.env.query(self.env.ledger, "forged_proof_guard_status", ()).expect("forged_proof_guard_status")
    }

    fn advance(&self, secs: u64) {
        self.env.pic().advance_time(Duration::from_secs(secs));
        self.env.pic().tick();
    }

    fn prepare_shield(&mut self, acct: usize, v: u64) -> (ct::DepositArgs, F, F) {
        self.op += 1;
        let mut prng = prover::op_rng(SEED, self.op, "forged-guard-shield-plan");
        let rho = F::rand(&mut prng);
        let rcm = F::rand(&mut prng);
        let mut prepared =
            prover::prepare_shield(&self.cfg, &self.keyset.deposit_pk, &self.accounts[acct], v, rho, rcm, SEED, self.op);
        prepared.args.created_at_time = self.env.time_ns();
        (prepared.args, rho, rcm)
    }

    fn send_shield(&mut self, acct: usize, args: ct::DepositArgs) -> ct::MutationResult {
        self.env.update(self.env.ledger, self.accounts[acct].principal, "shield", (args,)).expect("shield call")
    }

    fn shield(&mut self, acct: usize, v: u64) -> ct::MutationResult {
        let (args, rho, rcm) = self.prepare_shield(acct, v);
        let m = self.send_shield(acct, args);
        if m.outcome == "ACCEPT" {
            self.leaves.push(common::note_commitment(&self.cfg, v, self.accounts[acct].pk, rho, rcm));
            self.notes.push(NoteRec { acct, v, rho, rcm, spent: false });
        }
        m
    }

    /// A genuine deposit proof sent with the value changed: well-formed, verified, REJECT:pairing-check.
    fn forged_shield(&mut self, acct: usize) -> ct::MutationResult {
        let (mut args, _, _) = self.prepare_shield(acct, NOTE);
        args.value += 1;
        self.send_shield(acct, args)
    }

    /// Two unspent notes of `acct`, shielding fresh ones as needed.
    fn two_notes(&mut self, acct: usize) -> (usize, usize) {
        let mut free: Vec<usize> = (0..self.notes.len()).filter(|&k| self.notes[k].acct == acct && !self.notes[k].spent).collect();
        while free.len() < 2 {
            let m = self.shield(acct, NOTE);
            assert_eq!(m.outcome, "ACCEPT", "shield for notes said {}", m.outcome);
            free.push(self.notes.len() - 1);
        }
        (free[0], free[1])
    }

    /// Shield fresh notes until `acct` holds at least `n` unspent ones.
    fn ensure_notes(&mut self, acct: usize, n: usize) {
        while (0..self.notes.len()).filter(|&k| self.notes[k].acct == acct && !self.notes[k].spent).count() < n {
            let m = self.shield(acct, NOTE);
            assert_eq!(m.outcome, "ACCEPT", "shield for notes said {}", m.outcome);
        }
    }

    /// A private transfer from `acct` spending two of its notes, half to account 1, change back.
    fn prepare_transfer(&mut self, acct: usize) -> (prover::PreparedTransfer, usize, usize) {
        let (i, j) = self.two_notes(acct);
        self.op += 1;
        let plan = |note: usize| -> prover::TransferPlanInput {
            let n = &self.notes[note];
            prover::TransferPlanInput { note_index: note, leaf_index: note as u64, v: n.v, nk: self.accounts[n.acct].nk, rho: n.rho, rcm: n.rcm }
        };
        let tree = common::DenseTree { leaves: self.leaves.clone() };
        let anchor = tree.root(&self.cfg_tree);
        let mut prng = prover::op_rng(SEED, self.op, "forged-guard-transfer-plan");
        let crypto = prover::TransferCrypto {
            anchor,
            path1: tree.path(&self.cfg_tree, i),
            path2: tree.path(&self.cfg_tree, j),
            out_rcm1: F::rand(&mut prng),
            out_rcm2: F::rand(&mut prng),
        };
        let total = self.notes[i].v + self.notes[j].v;
        let first = total / 2;
        let (in1, in2) = (plan(i), plan(j));
        let p = prover::prepare_transfer(
            &self.cfg,
            &self.keyset.transfer_pk,
            self.keyset.legacy_statement,
            &crypto,
            (&in1, &in2),
            (&self.accounts[1], &self.accounts[acct]),
            (first, total - first),
            0,
            0,
            [0u8; 32],
            None,
            None,
            SEED,
            self.op,
        );
        (p, i, j)
    }

    fn send_transfer(&mut self, who: Principal, args: ct::TransferArgs) -> ct::MutationResult {
        self.env.update(self.env.ledger, who, "confidential_transfer", (args,)).expect("confidential_transfer call")
    }

    /// An honest private transfer; its notes are recorded only when accepted.
    fn honest_transfer(&mut self) -> ct::MutationResult {
        let (p, i, j) = self.prepare_transfer(0);
        let m = self.send_transfer(self.accounts[0].principal, p.args.clone());
        if m.outcome == "ACCEPT" {
            self.notes[i].spent = true;
            self.notes[j].spent = true;
            for (owner, v, rho, rcm) in p.outs.iter() {
                self.leaves.push(common::note_commitment(&self.cfg, *v, self.accounts[*owner].pk, *rho, *rcm));
                self.notes.push(NoteRec { acct: *owner, v: *v, rho: *rho, rcm: *rcm, spent: false });
            }
            let tree = common::DenseTree { leaves: self.leaves.clone() };
            let root = f_bytes(&tree.root(&self.cfg_tree)).to_vec();
            assert_eq!(self.env.ledger_status().note_root.as_ref(), root.as_slice(), "battery mirror diverged");
        }
        m
    }

    /// A genuine transfer proof sent with its two outputs swapped: every pre-verify check passes
    /// (known anchor, fresh nullifiers, fee), the public inputs no longer match the proof.
    fn forged_transfer(&mut self) -> ct::MutationResult {
        let (p, _, _) = self.prepare_transfer(0);
        let mut args = p.args.clone();
        std::mem::swap(&mut args.output_1, &mut args.output_2);
        self.send_transfer(Principal::anonymous(), args)
    }

    fn upgrade(&self) {
        self.env
            .pic()
            .upgrade_eop_canister(self.env.ledger, self.env.ledger_wasm.clone(), candid::encode_args(()).unwrap(), Some(self.admin()))
            .unwrap_or_else(|e| panic!("upgrade failed: {e:?}"));
    }
}

fn snapshot(h: &Harness) -> (Vec<u8>, u128, u128, u128) {
    let s = h.env.ledger_status();
    (s.note_root.to_vec(), nat(&s.epoch), nat(&s.nullifier_count), nat(&s.pool_value))
}

fn expect_forged(m: &ct::MutationResult, what: &str) -> Result<(), String> {
    if m.outcome != "REJECT:pairing-check" || m.verifier_outcome != "REJECT:pairing-check" {
        return Err(format!("{what}: forgery said {} / {} (want a verified REJECT:pairing-check)", m.outcome, m.verifier_outcome));
    }
    Ok(())
}

fn expect_cooldown(m: &ct::MutationResult, what: &str) -> Result<(), String> {
    if m.outcome != "REJECT:forged-proof-cooldown" || m.verifier_outcome != "NOT_CALLED" {
        return Err(format!("{what}: said {} / {} (want REJECT:forged-proof-cooldown, NOT_CALLED)", m.outcome, m.verifier_outcome));
    }
    Ok(())
}

/// Trip the guard (threshold 3) with one forged shield and two forged transfers.
fn trip(h: &mut Harness, tag: &str) -> Result<(), String> {
    h.set_guard(3);
    let m = h.forged_shield(0);
    expect_forged(&m, &format!("{tag} forged shield"))?;
    for k in 0..2 {
        let m = h.forged_transfer();
        expect_forged(&m, &format!("{tag} forged transfer {k}"))?;
    }
    let st = h.status();
    if !st.cooling_down || nat(&st.trips) != 1 {
        return Err(format!("{tag} RED: after 3 forgeries cooling_down={} trips={}", st.cooling_down, nat(&st.trips)));
    }
    Ok(())
}

// ---------------------------------------------------------------------------

fn g1_off_by_default(w: &pic_env::BuiltWasms, ks: keys::Keyset) -> Result<(), String> {
    let mut h = Harness::new(w, ks, "g1");
    let st = h.status();
    if nat(&st.config.threshold) != 0 || st.cooling_down {
        return Err("g1: a fresh ledger has the guard on".into());
    }
    for k in 0..6 {
        expect_forged(&h.forged_transfer(), &format!("g1 forgery {k}"))?;
    }
    let st = h.status();
    if nat(&st.failures_total) != 6 || nat(&st.trips) != 0 || st.cooling_down {
        return Err(format!("g1: off guard counted {} tripped {}", nat(&st.failures_total), nat(&st.trips)));
    }
    let m = h.honest_transfer();
    if m.outcome != "ACCEPT" {
        return Err(format!("g1: honest transfer after forgeries said {}", m.outcome));
    }
    println!("[G1] PASS off by default: 6 forgeries verified and counted, no cool-down, honest transfer accepted");
    Ok(())
}

fn g2_configuration(w: &pic_env::BuiltWasms, ks: keys::Keyset) -> Result<(), String> {
    let h = Harness::new(w, ks, "g2");
    let user = h.accounts[0].principal;
    let cases: [(Principal, u64, u64, u64, &str); 6] = [
        (user, 3, WINDOW, COOLDOWN, "REJECT:not-administrator"),
        (h.admin(), 100_001, WINDOW, COOLDOWN, "REJECT:forged-guard-threshold"),
        (h.admin(), 3, 59, COOLDOWN, "REJECT:forged-guard-window"),
        (h.admin(), 3, 86_401, COOLDOWN, "REJECT:forged-guard-window"),
        (h.admin(), 3, WINDOW, 59, "REJECT:forged-guard-cooldown"),
        (h.admin(), 3, WINDOW, 86_401, "REJECT:forged-guard-cooldown"),
    ];
    for (who, t, win, cd, want) in cases {
        match h.set_guard_as(who, t, win, cd) {
            Err(e) if e == want => {}
            other => return Err(format!("g2 RED: ({t},{win},{cd}) returned {:?} want {want}", other.map(|_| "ok"))),
        }
    }
    if nat(&h.status().config.threshold) != 0 {
        return Err("g2 RED: a refused configuration took effect".into());
    }
    if let Err(e) = h.clear_as(user) {
        if e != "REJECT:not-administrator" {
            return Err(format!("g2: non-admin clear said {e}"));
        }
    } else {
        return Err("g2 RED: non-admin clear accepted".into());
    }
    h.set_guard_as(h.admin(), 100_000, 86_400, 60).map_err(|e| format!("g2: bound values refused: {e}"))?;
    println!("[G2] PASS configuration: non-admin set/clear and out-of-bounds values refused; bound values accepted");
    Ok(())
}

fn g3_trip(w: &pic_env::BuiltWasms, ks: keys::Keyset) -> Result<(), String> {
    let mut h = Harness::new(w, ks, "g3");
    h.ensure_notes(0, 2); // notes for the honest attempts, shielded before the cool-down
    trip(&mut h, "g3")?;
    let total = nat(&h.status().failures_total);
    expect_cooldown(&h.forged_transfer(), "g3 RED forged transfer in cool-down")?;
    let before = snapshot(&h);
    expect_cooldown(&h.honest_transfer(), "g3 RED honest transfer in cool-down")?;
    if snapshot(&h) != before {
        return Err("g3: a refused transfer mutated state".into());
    }
    let (args, _, _) = h.prepare_shield(0, NOTE);
    expect_cooldown(&h.send_shield(0, args), "g3 RED honest shield in cool-down")?;
    if snapshot(&h) != before {
        return Err("g3: a refused shield mutated state".into());
    }
    if nat(&h.status().failures_total) != total {
        return Err("g3: refusals in cool-down were counted as verifications".into());
    }
    println!(
        "[G3] PASS trip: shield + transfer forgeries share the count; in cool-down forged/honest transfer and honest shield refused before the verifier, zero mutation"
    );
    Ok(())
}

fn g5_expiry(w: &pic_env::BuiltWasms, ks: keys::Keyset) -> Result<(), String> {
    let mut h = Harness::new(w, ks, "g5");
    h.ensure_notes(0, 2);
    trip(&mut h, "g5")?;
    h.advance(COOLDOWN - 60);
    expect_cooldown(&h.honest_transfer(), "g5 one minute before the end")?;
    h.advance(61);
    if h.status().cooling_down {
        return Err("g5 RED: still cooling down after the cool-down".into());
    }
    let m = h.honest_transfer();
    if m.outcome != "ACCEPT" {
        return Err(format!("g5 RED: honest transfer after the cool-down said {}", m.outcome));
    }
    println!("[G5] PASS expiry: refused 1 min before the end, accepted after it");
    Ok(())
}

fn g6_window(w: &pic_env::BuiltWasms, ks: keys::Keyset) -> Result<(), String> {
    let mut h = Harness::new(w, ks, "g6");
    h.ensure_notes(0, 2);
    h.set_guard(3);
    for k in 0..2 {
        expect_forged(&h.forged_transfer(), &format!("g6 forgery {k}"))?;
    }
    h.advance(WINDOW + 1);
    expect_forged(&h.forged_transfer(), "g6 forgery in the new window")?;
    let st = h.status();
    if st.cooling_down || nat(&st.trips) != 0 || nat(&st.failures_in_window) != 1 {
        return Err(format!(
            "g6 RED: expired failures counted: cooling_down={} trips={} in_window={}",
            st.cooling_down,
            nat(&st.trips),
            nat(&st.failures_in_window)
        ));
    }
    for k in 0..2 {
        expect_forged(&h.forged_transfer(), &format!("g6 forgery {k} (second window)"))?;
    }
    if !h.status().cooling_down {
        return Err("g6: three forgeries in one window did not trip".into());
    }
    println!("[G6] PASS window: 2 forgeries + window expiry + 1 = no trip; 3 in one window trip");
    Ok(())
}

fn g7_admin_end(w: &pic_env::BuiltWasms, ks: keys::Keyset) -> Result<(), String> {
    let mut h = Harness::new(w, ks, "g7");
    h.ensure_notes(0, 4);
    trip(&mut h, "g7")?;
    h.clear_as(h.admin()).map_err(|e| format!("g7: admin clear: {e}"))?;
    let m = h.honest_transfer();
    if m.outcome != "ACCEPT" {
        return Err(format!("g7: honest transfer after clear said {}", m.outcome));
    }
    // a second trip, ended by switching the guard off
    for k in 0..3 {
        expect_forged(&h.forged_transfer(), &format!("g7 second-trip forgery {k}"))?;
    }
    if !h.status().cooling_down {
        return Err("g7: second trip did not start".into());
    }
    h.set_guard(0);
    let m = h.honest_transfer();
    if m.outcome != "ACCEPT" {
        return Err(format!("g7: honest transfer after threshold 0 said {}", m.outcome));
    }
    println!("[G7] PASS administrator: clear ends a cool-down; threshold 0 ends one");
    Ok(())
}

fn g8_upgrade(w: &pic_env::BuiltWasms, ks: keys::Keyset) -> Result<(), String> {
    let mut h = Harness::new(w, ks, "g8");
    h.ensure_notes(0, 2);
    trip(&mut h, "g8")?;
    h.upgrade();
    let st = h.status();
    if !st.cooling_down || nat(&st.config.threshold) != 3 || nat(&st.trips) != 1 {
        return Err(format!("g8 RED: after upgrade cooling_down={} threshold={} trips={}", st.cooling_down, nat(&st.config.threshold), nat(&st.trips)));
    }
    expect_cooldown(&h.honest_transfer(), "g8 RED honest transfer after upgrade")?;
    h.advance(COOLDOWN + 1);
    let m = h.honest_transfer();
    if m.outcome != "ACCEPT" {
        return Err(format!("g8: honest transfer after the cool-down said {}", m.outcome));
    }
    println!("[G8] PASS upgrade: running cool-down and configuration kept; ends on time");
    Ok(())
}

fn g9_cost(w: &pic_env::BuiltWasms, ks: keys::Keyset) -> Result<(), String> {
    let mut h = Harness::new(w, ks, "g9");
    h.set_guard(6);
    // prepare first so only the ledger call is timed
    let mut forged = Vec::new();
    for _ in 0..10 {
        let (p, _, _) = h.prepare_transfer(0);
        let mut args = p.args.clone();
        std::mem::swap(&mut args.output_1, &mut args.output_2);
        forged.push(args);
    }
    let mut verified = Vec::new();
    let mut refused = Vec::new();
    for args in forged {
        let t = Instant::now();
        let m = h.send_transfer(Principal::anonymous(), args);
        let dt = t.elapsed();
        if m.outcome == "REJECT:pairing-check" {
            verified.push(dt);
        } else if m.outcome == "REJECT:forged-proof-cooldown" {
            refused.push(dt);
        } else {
            return Err(format!("g9: forgery said {}", m.outcome));
        }
    }
    if verified.len() != 6 || refused.len() != 4 {
        return Err(format!("g9: {} verified / {} refused, want 6 / 4", verified.len(), refused.len()));
    }
    let mean = |v: &[Duration]| v.iter().sum::<Duration>() / v.len() as u32;
    let (mv, mr) = (mean(&verified), mean(&refused));
    if mr * 4 >= mv {
        return Err(format!("g9: refused forgery {mr:?} is not under a quarter of a verified one {mv:?}"));
    }
    println!("[G9] PASS cost: verified forgery {mv:?} mean, refused in cool-down {mr:?} mean ({:.1}%)", 100.0 * mr.as_secs_f64() / mv.as_secs_f64());
    Ok(())
}

// ---------------------------------------------------------------------------

fn build_ledger(root: &Path, tag: &str, patches: &[(&str, &str)]) -> Vec<u8> {
    let stage = std::env::temp_dir().join(format!("forged_guard_variant_{}_{}", std::process::id(), tag));
    let _ = std::fs::remove_dir_all(&stage);
    pic_env::copy_dir_recursive(&root.join("src"), &stage.join("src"));
    let main_path = stage.join("src/Main.mo");
    let mut source = std::fs::read_to_string(&main_path).expect("read Main.mo");
    for (from, to) in patches {
        assert_eq!(source.matches(from).count(), 1, "variant {tag}: patch anchor must occur exactly once:\n{from}");
        source = source.replace(from, to);
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

type Check = (&'static str, fn(&pic_env::BuiltWasms, keys::Keyset) -> Result<(), String>);

fn main() {
    let root = repo_root();
    let manifest = std::fs::read_to_string(root.join("fixtures/pool-vectors-bls12-381-hardened/SETUP-MANIFEST.json")).unwrap();
    println!("[battery] regenerating the hardened-statement test keyset...");
    let keyset = keys::regenerate_and_verify(&manifest, false).expect("keyset");
    println!("[battery] building wasms (ledger + token + tree oracle)...");
    let base = pic_env::build_wasms(&root, &root.join("soak/target/wasms"));
    println!("[battery] shipped ledger sha256 {}", base.ledger_sha256);

    let checks: Vec<Check> = vec![
        ("G1", g1_off_by_default),
        ("G2", g2_configuration),
        ("G3", g3_trip),
        ("G5", g5_expiry),
        ("G6", g6_window),
        ("G7", g7_admin_end),
        ("G8", g8_upgrade),
        ("G9", g9_cost),
    ];

    println!("\n==== TEETH: planted defects must turn the checks RED ====");
    let variants: Vec<(&str, Vec<(&str, &str)>, Vec<&str>)> = vec![
        (
            "A:transfer-not-counted",
            vec![(
                "let verdict = verifyTransferProof(args.proof_hex, inputs);\n    if (verdict != \"ACCEPT\") {\n      recordFailedVerification(verdict);",
                "let verdict = verifyTransferProof(args.proof_hex, inputs);\n    if (verdict != \"ACCEPT\") { // PLANTED DEFECT A",
            )],
            vec!["G3"],
        ),
        (
            "B:shield-not-counted",
            vec![(
                "let verdict = verifyShieldProof(args.proof_hex, inputs);\n    if (verdict != \"ACCEPT\") {\n      recordFailedVerification(verdict);",
                "let verdict = verifyShieldProof(args.proof_hex, inputs);\n    if (verdict != \"ACCEPT\") { // PLANTED DEFECT B",
            )],
            vec!["G3"],
        ),
        (
            "C:transfer-ignores-cooldown",
            vec![(
                "    switch (forgedCooldownRejection()) { case (?e) return mutation(e, \"NOT_CALLED\"); case null {} };\n    let verdict = verifyTransferProof",
                "    // PLANTED DEFECT C\n    let verdict = verifyTransferProof",
            )],
            vec!["G3"],
        ),
        (
            "D:shield-ignores-cooldown",
            vec![(
                "    switch (forgedCooldownRejection()) { case (?e) return mutation(e, \"NOT_CALLED\"); case null {} };\n    let verdict = verifyShieldProof",
                "    // PLANTED DEFECT D\n    let verdict = verifyShieldProof",
            )],
            vec!["G3"],
        ),
        (
            "E:transient-cooldown-end",
            vec![("  var forged_cooldown_until : Int = 0;", "  transient var forged_cooldown_until : Int = 0; // PLANTED DEFECT E")],
            vec!["G8"],
        ),
        (
            "F:window-never-restarts",
            vec![(
                "    if (now - forged_window_start >= forged_guard.window_seconds * 1_000_000_000) {\n      forged_window_start := now;\n      forged_in_window := 0;\n    };\n",
                "    // PLANTED DEFECT F: the window never restarts\n",
            )],
            vec!["G6"],
        ),
        (
            "G:configuration-not-admin-gated",
            vec![(
                "    if (not isAdministrator(caller)) return #err(\"REJECT:not-administrator\");\n    if (config.threshold > FORGED_THRESHOLD_MAX)",
                "    // PLANTED DEFECT G\n    if (config.threshold > FORGED_THRESHOLD_MAX)",
            )],
            vec!["G2"],
        ),
        (
            "H:cooldown-never-expires",
            vec![(
                "forged_guard.threshold > 0 and Time.now() < forged_cooldown_until",
                "forged_guard.threshold > 0 and forged_cooldown_until > 0 // PLANTED DEFECT H",
            )],
            vec!["G5"],
        ),
    ];

    let mut teeth = 0u32;
    let mut wanted = 0u32;
    for (vname, patches, red_checks) in &variants {
        let tag = vname.split(':').next().unwrap();
        let vw = pic_env::BuiltWasms { ledger: build_ledger(&root, tag, patches), ..base.clone() };
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
        f(&base, keyset.clone()).unwrap_or_else(|e| panic!("{name} FAILED on the shipped wasm: {e}"));
        green += 1;
    }
    println!("\nFORGED-PROOF GUARD BATTERY COMPLETE: {green}/{} green on shipped, {teeth}/{wanted} planted reds", checks.len());
    println!("FORGED-PROOF-GUARD-BATTERY: PASS");
}
