//! Claimable-payment envelope battery (ledger side) — teeth-first, on
//! PocketIC, against the real ledger wasm with real Groth16 proofs.
//!
//! The ledger treats an envelope as opaque: it checks the length, binds it to the proof through the
//! public `recipient_binding` input, and logs it with the position of the note it describes. These
//! checks prove exactly that, so the envelopes here are random bytes of the right length; real IBE
//! envelopes are covered by the client's own end-to-end test.
//!
//! Planted defects (compiled from a patched source copy; the shipped tree is never modified):
//!   B  binding ignored (an enveloped transfer is still bound to zero)
//!   N  envelope not logged
//!   P  wrong note position logged (the position after the append)
//!   L  length check removed
//!   R  required switch ignored
//!   U  envelopes accepted on unshields
//!
//! Checks:
//!   Q1 an enveloped private transfer is accepted and logged once, at output_1's position
//!   Q2 a swapped or stripped envelope is rejected by the proof check, zero state mutation
//!   Q3 a wrong-length envelope is rejected before the verifier, zero state mutation
//!   Q4 the required switch forces envelopes on private transfers; admin-only
//!   Q5 an unshield carrying an envelope is rejected before the verifier
//!   Q6 the claim log and the switch survive an upgrade; paging is bounded
//!
//! RED expectations: B ⇒ Q1; N ⇒ Q1; P ⇒ Q1; L ⇒ Q3; R ⇒ Q4; U ⇒ Q5.

use ark_ff::UniformRand;
use candid::Principal;
use rand_chacha::rand_core::RngCore;
use sha2::Digest;
use soak::candid_types as ct;
use soak::crypto::f_bytes;
use soak::model::AccountKeys;
use soak::{keys, pic_env, prover};
use std::path::{Path, PathBuf};

type F = common::ScalarField;

const ENVELOPE_LEN: usize = 216;
const FUND: u128 = 1_000_000_000;
const NOTE: u64 = 200_000_000;
const SEED: u64 = 20261016;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

/// The binding the ledger must require, computed independently (src/Main.mo claimBinding).
fn claim_binding(pool: &Principal, envelope: &[u8]) -> [u8; 32] {
    let mut h = sha2::Sha256::new();
    h.update(b"picp-claim-envelope/v1");
    h.update(pool.as_slice());
    h.update(envelope);
    let mut out: [u8; 32] = h.finalize().into();
    out[31] = 0;
    out
}

#[derive(candid::CandidType, serde::Deserialize, Debug)]
struct ClaimRecord {
    index: candid::Nat,
    note_position: candid::Nat,
    time: candid::Int,
    envelope: ct::Blob,
}

#[derive(candid::CandidType, serde::Deserialize)]
struct ClaimLogPage {
    total: candid::Nat,
    records: Vec<ClaimRecord>,
}

#[derive(candid::CandidType, serde::Deserialize)]
struct ClaimStatus {
    required: bool,
    envelope_len: candid::Nat,
    total: candid::Nat,
}

fn n(x: &candid::Nat) -> u64 {
    u64::try_from(x.0.clone()).unwrap()
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
        let accounts = soak::model::derive_accounts(SEED, 3, &cfg);
        let state_dir = std::env::temp_dir().join(format!("claim_battery_{}_{}", std::process::id(), tag));
        let _ = std::fs::remove_dir_all(&state_dir);
        std::fs::create_dir_all(&state_dir).unwrap();
        let env = pic_env::setup(wasms, &keyset.transfer_vk_hex, &keyset.deposit_vk_hex, &state_dir);
        let principals: Vec<Principal> = accounts.iter().map(|a| a.principal).collect();
        pic_env::fund_accounts(&env, &principals, FUND, FUND);
        Harness {
            env,
            keyset,
            cfg,
            cfg_tree: common::poseidon_config_tree(),
            accounts,
            leaves: Vec::new(),
            notes: Vec::new(),
            op: 0,
        }
    }

    fn envelope(&mut self) -> Vec<u8> {
        self.op += 1;
        let mut prng = prover::op_rng(SEED, self.op, "claim-envelope");
        let mut e = vec![0u8; ENVELOPE_LEN];
        prng.fill_bytes(&mut e);
        e
    }

    fn shield(&mut self, acct: usize, v: u64) {
        self.op += 1;
        let mut prng = prover::op_rng(SEED, self.op, "claim-shield");
        let (rho, rcm) = (F::rand(&mut prng), F::rand(&mut prng));
        let mut prepared =
            prover::prepare_shield(&self.cfg, &self.keyset.deposit_pk, &self.accounts[acct], v, rho, rcm, SEED, self.op);
        prepared.args.created_at_time = self.env.time_ns();
        let m: ct::MutationResult =
            self.env.update(self.env.ledger, self.accounts[acct].principal, "shield", (prepared.args,)).expect("shield");
        assert_eq!(m.outcome, "ACCEPT", "shield");
        self.leaves.push(common::note_commitment(&self.cfg, v, self.accounts[acct].pk, rho, rcm));
        self.notes.push(NoteRec { acct, v, rho, rcm });
    }

    fn two_notes(&mut self, acct: usize) -> (usize, usize) {
        let a = self.notes.len();
        self.shield(acct, NOTE);
        self.shield(acct, NOTE);
        (a, a + 1)
    }

    /// Prove a transfer of notes i,j. Private when `v_pub == 0`; `binding` is the public
    /// recipient binding the proof commits to.
    fn prepare(&mut self, acct: usize, i: usize, j: usize, v_pub: u64, binding: [u8; 32]) -> prover::PreparedTransfer {
        self.op += 1;
        let plan = |note: usize| -> prover::TransferPlanInput {
            let r = &self.notes[note];
            prover::TransferPlanInput { note_index: note, leaf_index: note as u64, v: r.v, nk: self.accounts[r.acct].nk, rho: r.rho, rcm: r.rcm }
        };
        let tree = common::DenseTree { leaves: self.leaves.clone() };
        let mut prng = prover::op_rng(SEED, self.op, "claim-transfer");
        let crypto = prover::TransferCrypto {
            anchor: tree.root(&self.cfg_tree),
            path1: tree.path(&self.cfg_tree, i),
            path2: tree.path(&self.cfg_tree, j),
            out_rcm1: F::rand(&mut prng),
            out_rcm2: F::rand(&mut prng),
        };
        let total = self.notes[i].v + self.notes[j].v;
        let (fee, recipient, racct) = if v_pub > 0 {
            (self.env.token_fee, Some(ct::Account { owner: self.accounts[acct].principal, subaccount: None }), Some(acct))
        } else {
            (0, None, None)
        };
        let first = if v_pub > 0 { 0 } else { 50_000_000 };
        let (in1, in2) = (plan(i), plan(j));
        prover::prepare_transfer(
            &self.cfg, &self.keyset.transfer_pk, self.keyset.legacy_statement, &crypto, (&in1, &in2),
            (&self.accounts[if v_pub > 0 { acct } else { 1 }], &self.accounts[acct]),
            (first, total - first - fee - v_pub), fee, v_pub, binding, recipient, racct, SEED, self.op,
        )
    }

    fn submit(&mut self, acct: usize, p: &prover::PreparedTransfer, envelope: Option<Vec<u8>>) -> ct::MutationResult {
        let mut args = p.args.clone();
        args.claim_envelope = envelope.map(ct::blob);
        if args.v_pub_out > 0 {
            args.created_at_time = Some(self.env.time_ns());
        }
        let m: ct::MutationResult =
            self.env.update(self.env.ledger, self.accounts[acct].principal, "confidential_transfer", (args,)).expect("transfer call");
        if m.outcome == "ACCEPT" {
            for (owner, v, rho, rcm) in p.outs.iter() {
                self.leaves.push(common::note_commitment(&self.cfg, *v, self.accounts[*owner].pk, *rho, *rcm));
                self.notes.push(NoteRec { acct: *owner, v: *v, rho: *rho, rcm: *rcm });
            }
        }
        m
    }

    fn page(&self, start: u64, count: u64) -> ClaimLogPage {
        self.env.query(self.env.ledger, "claim_envelopes", (candid::Nat::from(start), candid::Nat::from(count))).expect("claim_envelopes")
    }

    fn status(&self) -> ClaimStatus {
        self.env.query(self.env.ledger, "claim_status", ()).expect("claim_status")
    }

    fn set_required(&self, who: Principal, on: bool) -> Result<ClaimStatus, String> {
        let r: ct::MotokoResult<ClaimStatus> =
            self.env.update(self.env.ledger, who, "set_claim_envelopes_required", (on,)).map_err(|e| e.to_string())?;
        r.into_result()
    }

    fn footprint(&self) -> (Vec<u8>, u64, u64, u64, u64) {
        let s = self.env.ledger_status();
        (s.note_root.to_vec(), n(&s.epoch), n(&s.nullifier_count), n(&s.note_count), n(&self.status().total))
    }
}

/// Q1: enveloped transfer accepted; one record, at output_1's position, bytes identical.
fn q1_logged(w: &pic_env::BuiltWasms, ks: keys::Keyset) -> Result<(), String> {
    let mut h = Harness::new(w, ks, "q1");
    let (i, j) = h.two_notes(0);
    let env = h.envelope();
    let position_before = n(&h.env.ledger_status().note_count);
    let p = h.prepare(0, i, j, 0, claim_binding(&h.env.ledger, &env));
    let m = h.submit(0, &p, Some(env.clone()));
    if m.outcome != "ACCEPT" {
        return Err(format!("q1 RED: enveloped transfer said {}", m.outcome));
    }
    let page = h.page(0, 10);
    if n(&page.total) != 1 || page.records.len() != 1 {
        return Err(format!("q1 RED: claim log holds {} records, want 1", n(&page.total)));
    }
    let r = &page.records[0];
    if n(&r.note_position) != position_before {
        return Err(format!("q1 RED: logged position {} want {}", n(&r.note_position), position_before));
    }
    if r.envelope.as_ref() != env.as_slice() {
        return Err("q1 RED: logged envelope differs from the submitted one".into());
    }
    let now = h.env.time_ns() as i128;
    let t: i128 = r.time.0.clone().try_into().unwrap();
    if (now - t).abs() > 600_000_000_000 {
        return Err(format!("q1: logged time {t} far from now {now}"));
    }
    println!("[Q1] PASS enveloped transfer accepted; logged once at position {position_before}, bytes identical");
    Ok(())
}

/// Q2: a proof bound to envelope A, submitted with envelope B or with none, fails the proof check.
fn q2_swap_strip(w: &pic_env::BuiltWasms, ks: keys::Keyset) -> Result<(), String> {
    let mut h = Harness::new(w, ks, "q2");
    let (i, j) = h.two_notes(0);
    let a = h.envelope();
    let b = h.envelope();
    let p = h.prepare(0, i, j, 0, claim_binding(&h.env.ledger, &a));
    for (label, env) in [("swapped", Some(b.clone())), ("stripped", None)] {
        let before = h.footprint();
        let m = h.submit(0, &p, env);
        if m.outcome == "ACCEPT" || !m.outcome.starts_with("REJECT:") {
            return Err(format!("q2 RED: {label} envelope said {}", m.outcome));
        }
        if h.footprint() != before {
            return Err(format!("q2: {label} envelope mutated state"));
        }
        println!("[Q2]   {label}: {}", m.outcome);
    }
    // the honest submission still goes through afterwards
    let m = h.submit(0, &p, Some(a));
    if m.outcome != "ACCEPT" {
        return Err(format!("q2: honest envelope after the attacks said {}", m.outcome));
    }
    println!("[Q2] PASS swapped and stripped envelopes rejected by the proof check, zero mutation");
    Ok(())
}

/// Q3: wrong lengths are refused before the verifier.
fn q3_length(w: &pic_env::BuiltWasms, ks: keys::Keyset) -> Result<(), String> {
    let mut h = Harness::new(w, ks, "q3");
    let (i, j) = h.two_notes(0);
    for len in [0usize, ENVELOPE_LEN - 1, ENVELOPE_LEN + 1, 4096] {
        let env = vec![7u8; len];
        let p = h.prepare(0, i, j, 0, claim_binding(&h.env.ledger, &env));
        let before = h.footprint();
        let m = h.submit(0, &p, Some(env));
        if m.outcome != "REJECT:claim-envelope-length" || m.verifier_outcome != "NOT_CALLED" {
            return Err(format!("q3 RED: length {len} said {} / {}", m.outcome, m.verifier_outcome));
        }
        if h.footprint() != before {
            return Err(format!("q3: length {len} mutated state"));
        }
    }
    println!("[Q3] PASS lengths 0, {}, {}, 4096 refused before the verifier", ENVELOPE_LEN - 1, ENVELOPE_LEN + 1);
    Ok(())
}

/// Q4: with the switch on, a private transfer without an envelope is refused; with one it passes.
fn q4_required(w: &pic_env::BuiltWasms, ks: keys::Keyset) -> Result<(), String> {
    let mut h = Harness::new(w, ks, "q4");
    match h.set_required(h.accounts[0].principal, true) {
        Err(e) if e == "REJECT:not-administrator" => {}
        other => return Err(format!("q4: non-admin switch returned {:?}", other.map(|s| s.required))),
    }
    h.set_required(h.env.admin, true).map_err(|e| format!("q4 set: {e}"))?;
    if !h.status().required {
        return Err("q4: switch did not stick".into());
    }
    let (i, j) = h.two_notes(0);
    let bare = h.prepare(0, i, j, 0, [0u8; 32]);
    let before = h.footprint();
    let m = h.submit(0, &bare, None);
    if m.outcome != "REJECT:claim-envelope-required" || m.verifier_outcome != "NOT_CALLED" {
        return Err(format!("q4 RED: envelope-less transfer under the switch said {}", m.outcome));
    }
    if h.footprint() != before {
        return Err("q4: refused transfer mutated state".into());
    }
    let env = h.envelope();
    let p = h.prepare(0, i, j, 0, claim_binding(&h.env.ledger, &env));
    let m = h.submit(0, &p, Some(env));
    if m.outcome != "ACCEPT" {
        return Err(format!("q4: enveloped transfer under the switch said {}", m.outcome));
    }
    println!("[Q4] PASS switch forces envelopes (admin-only); enveloped transfer accepted");
    Ok(())
}

/// Q5: unshields never carry envelopes.
fn q5_unshield(w: &pic_env::BuiltWasms, ks: keys::Keyset) -> Result<(), String> {
    let mut h = Harness::new(w, ks, "q5");
    let (i, j) = h.two_notes(0);
    let account = ct::Account { owner: h.accounts[0].principal, subaccount: None };
    let r: ct::MotokoResult<ct::Blob> = h.env.query(h.env.ledger, "recipient_binding", (account,)).expect("recipient_binding");
    let binding: [u8; 32] = r.into_result().map_err(|e| format!("binding: {e}"))?.as_ref().try_into().unwrap();
    let p = h.prepare(0, i, j, 100_000_000, binding);
    let env = h.envelope();
    let before = h.footprint();
    let m = h.submit(0, &p, Some(env));
    if m.outcome != "REJECT:unshield-claim-envelope" || m.verifier_outcome != "NOT_CALLED" {
        return Err(format!("q5 RED: enveloped unshield said {} / {}", m.outcome, m.verifier_outcome));
    }
    if h.footprint() != before {
        return Err("q5: refused unshield mutated state".into());
    }
    let m = h.submit(0, &p, None);
    if m.outcome != "ACCEPT" {
        return Err(format!("q5: plain unshield said {}", m.outcome));
    }
    println!("[Q5] PASS enveloped unshield refused before the verifier; plain unshield accepted");
    Ok(())
}

/// Q6: log + switch survive an upgrade; paging is bounded and indexes are stable.
fn q6_upgrade_paging(w: &pic_env::BuiltWasms, ks: keys::Keyset) -> Result<(), String> {
    let mut h = Harness::new(w, ks, "q6");
    let mut envs = Vec::new();
    for _ in 0..2 {
        let (i, j) = h.two_notes(0);
        let env = h.envelope();
        let p = h.prepare(0, i, j, 0, claim_binding(&h.env.ledger, &env));
        if h.submit(0, &p, Some(env.clone())).outcome != "ACCEPT" {
            return Err("q6: setup transfer".into());
        }
        envs.push(env);
    }
    h.set_required(h.env.admin, true).map_err(|e| format!("q6 set: {e}"))?;
    let before = h.page(0, 10);
    h.env
        .pic()
        .upgrade_eop_canister(h.env.ledger, h.env.ledger_wasm.clone(), candid::encode_args(()).unwrap(), Some(h.env.admin))
        .map_err(|e| format!("q6 upgrade: {e:?}"))?;
    let after = h.page(0, 10);
    if n(&after.total) != 2 || !h.status().required {
        return Err(format!("q6 RED: after upgrade total {} required {}", n(&after.total), h.status().required));
    }
    for (k, r) in after.records.iter().enumerate() {
        if r.envelope.as_ref() != envs[k].as_slice() || n(&r.index) != k as u64
            || n(&r.note_position) != n(&before.records[k].note_position)
        {
            return Err(format!("q6 RED: record {k} changed across the upgrade"));
        }
    }
    let tail = h.page(1, 10);
    let past = h.page(5, 10);
    let capped = h.page(0, 100_000);
    if tail.records.len() != 1 || n(&tail.records[0].index) != 1 || !past.records.is_empty() || capped.records.len() != 2 {
        return Err("q6: paging returned the wrong slices".into());
    }
    println!("[Q6] PASS claim log and switch survive the upgrade; paging bounded and stable");
    Ok(())
}

fn build_variant(root: &Path, wasms: &pic_env::BuiltWasms, tag: &str, patches: &[(&str, &str)]) -> pic_env::BuiltWasms {
    let stage = std::env::temp_dir().join(format!("claim_variant_{}_{}", std::process::id(), tag));
    let _ = std::fs::remove_dir_all(&stage);
    pic_env::copy_dir_recursive(&root.join("src"), &stage.join("src"));
    let main_path = stage.join("src/Main.mo");
    let mut source = std::fs::read_to_string(&main_path).expect("read Main.mo");
    for (from, to) in patches {
        assert_eq!(source.matches(from).count(), 1, "variant {tag}: anchor must occur exactly once:\n{from}");
        source = source.replace(from, to);
    }
    std::fs::write(&main_path, source).expect("write patched Main.mo");
    let out = stage.join("zk_ledger_variant.wasm");
    let sources_raw =
        String::from_utf8(std::process::Command::new("/usr/bin/mops").arg("sources").current_dir(root).output().expect("mops").stdout).unwrap();
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
    pic_env::BuiltWasms { ledger: std::fs::read(&out).expect("read variant"), ..wasms.clone() }
}

type Check = (&'static str, fn(&pic_env::BuiltWasms, keys::Keyset) -> Result<(), String>);

fn main() {
    let root = repo_root();
    let (legacy, dir) = keys::statement_from_env();
    let manifest = std::fs::read_to_string(root.join(dir).join("SETUP-MANIFEST.json")).unwrap();
    let keyset = keys::regenerate_and_verify(&manifest, legacy).expect("keyset");
    let wasms = pic_env::build_wasms(&root, &root.join("soak/target/wasms"));
    println!("[battery] shipped ledger sha256 {}", wasms.ledger_sha256);

    let checks: Vec<Check> = vec![
        ("Q1", q1_logged),
        ("Q2", q2_swap_strip),
        ("Q3", q3_length),
        ("Q4", q4_required),
        ("Q5", q5_unshield),
        ("Q6", q6_upgrade_paging),
    ];
    let variants: Vec<(&str, Vec<(&str, &str)>, Vec<&str>)> = vec![
        ("B:binding-ignored", vec![("          claimBinding(envelope)\n", "          zeroField() // PLANTED DEFECT B\n")], vec!["Q1"]),
        (
            "N:not-logged",
            vec![(
                "          switch (StableLog.append(claim_log, claimRecordBytes(claimPosition, Time.now(), envelope))) {\n            case (#ok(_)) {};",
                "          switch (#ok(0) : StableLog.Result<Nat>) { // PLANTED DEFECT N\n            case (#ok(_)) {};",
            )],
            vec!["Q1"],
        ),
        ("P:wrong-position", vec![("claimRecordBytes(claimPosition, Time.now(), envelope)", "claimRecordBytes(noteCount(), Time.now(), envelope) /* PLANTED DEFECT P */")], vec!["Q1"]),
        (
            "L:length-unchecked",
            vec![(
                "          if (envelope.size() != CLAIM_ENVELOPE_LEN) return mutation(\"REJECT:claim-envelope-length\", \"NOT_CALLED\");\n",
                "          // PLANTED DEFECT L: length unchecked\n",
            )],
            vec!["Q3"],
        ),
        (
            "R:switch-ignored",
            vec![(
                "          if (claim_envelopes_required) return mutation(\"REJECT:claim-envelope-required\", \"NOT_CALLED\");\n",
                "          // PLANTED DEFECT R: switch ignored\n",
            )],
            vec!["Q4"],
        ),
        (
            "U:unshield-envelope",
            vec![(
                "      if (args.claim_envelope != null) {\n        return mutation(\"REJECT:unshield-claim-envelope\", \"NOT_CALLED\");\n      };\n",
                "      // PLANTED DEFECT U: envelope allowed on unshields\n",
            )],
            vec!["Q5"],
        ),
    ];

    println!("\n==== TEETH: planted defects must turn the checks RED ====");
    let (mut teeth, mut wanted) = (0u32, 0u32);
    for (vname, patches, reds) in &variants {
        let vw = build_variant(&root, &wasms, vname.split(':').next().unwrap(), patches);
        for want in reds {
            wanted += 1;
            let (_, f) = checks.iter().find(|(name, _)| name == want).unwrap();
            let red = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(&vw, keyset.clone()))) {
                Ok(Err(reason)) => {
                    println!("[TEETH {vname}/{want}] RED as required: {reason}");
                    true
                }
                Ok(Ok(())) => false,
                Err(_) => {
                    println!("[TEETH {vname}/{want}] RED as required (hard panic)");
                    true
                }
            };
            assert!(red, "TEETH FAILED: {want} stayed GREEN on planted defect {vname}");
            teeth += 1;
        }
    }
    println!("==== TEETH: {teeth}/{wanted} planted-defect reds confirmed ====");

    println!("\n==== SHIPPED WASM: all checks must be GREEN ====");
    for (name, f) in &checks {
        f(&wasms, keyset.clone()).unwrap_or_else(|e| panic!("{name} FAILED on the shipped wasm: {e}"));
    }
    println!("\nCLAIM BATTERY COMPLETE: {}/{} green on shipped, {teeth}/{wanted} planted reds", checks.len(), checks.len());
    println!("CLAIM-BATTERY: PASS");
}
