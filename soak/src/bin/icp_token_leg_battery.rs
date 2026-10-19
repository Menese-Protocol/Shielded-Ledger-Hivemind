//! ICP token-leg battery — the pool on the REAL NNS ICP ledger, teeth-first, on PocketIC.
//!
//! The mainnet ICP ledger serves no ICRC-3 log; the pool reads its legacy `query_blocks` history
//! directly (src/IcpBlock.mo, `configure_icp_token_ledger`). This battery installs the ICP ledger
//! wasm of the revision mainnet runs (ICP_LEDGER_WASM; dfinity/ic 69b75506…, module hash
//! 51f4be01…) at its mainnet id on PocketIC's NNS subnet, ICRC-2 on, archiving after a few
//! blocks, and drives the ledger build with test hooks (fault injection only).
//!
//! Checks:
//!   I1 make private: settles from the ICP block; the user pays value + fee exactly once; the pool
//!      account holds the value
//!   I2 move out: the ICP payout block settles it; the user receives exactly the amount
//!   I3 crash after the ICP transfer, resumed inside the dedup window: the resend answers
//!      Duplicate, the intent settles, one charge
//!   I4 crash, the block archived, resumed after the window: the scan finds it through the archive,
//!      the intent settles, one charge
//!   I5 crash, the block archived, resumed inside the window: Duplicate names an archived block,
//!      read back through the archive, one charge
//!   I6 (ledger with a one-page scan budget) the shield's token call is rejected (test hook), 200
//!      more ICP blocks land, resumed after the window: proving the transfer never landed takes
//!      several resumes, each continuing where the last stopped; the resend then answers TooOld, the
//!      settling scan starts from the kept place, and the intent is released with nothing charged
//!
//! RED expectations (each a patched copy of src/; the shipped tree is never modified):
//!   A archived ranges skipped ⇒ I4, I5    B transfer_from matched against the wrong account ⇒ I1
//!   C scan place not kept (on the I6 budget) ⇒ I6
//!   D scan place dropped once absence is proven (on the I6 budget) ⇒ I6 (the second scan restarts
//!     at the low-water mark and never finishes)
//!
//! Usage: ICP_LEDGER_WASM=<ledger-canister_notify-method.wasm.gz> cargo run --release --bin icp_token_leg_battery

use ark_ff::UniformRand;
use candid::{CandidType, Nat, Principal};
use serde::Deserialize;
use soak::candid_types as ct;
use soak::crypto::f_bytes;
use soak::model::AccountKeys;
use soak::{keys, pic_env, prover};
use std::path::{Path, PathBuf};
use std::time::Duration;

type F = common::ScalarField;

const ICP: u64 = 100_000_000;
const FEE: u64 = 10_000;
const SEED: u64 = 20261017;
const ARCHIVE_TRIGGER: u64 = 12;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

#[derive(CandidType)]
struct ApproveArgs {
    from_subaccount: Option<ct::Blob>,
    spender: ct::Account,
    amount: Nat,
    expected_allowance: Option<Nat>,
    expires_at: Option<u64>,
    fee: Option<Nat>,
    memo: Option<ct::Blob>,
    created_at_time: Option<u64>,
}
#[derive(CandidType)]
struct TransferArg {
    from_subaccount: Option<ct::Blob>,
    to: ct::Account,
    amount: Nat,
    fee: Option<Nat>,
    memo: Option<ct::Blob>,
    created_at_time: Option<u64>,
}
#[derive(CandidType, Deserialize, Debug)]
enum IcrcResult {
    Ok(Nat),
    Err(candid::Reserved),
}
#[derive(CandidType, Deserialize, Debug)]
struct ChainLength {
    chain_length: u64,
    first_block_index: u64,
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
    fn new(w: &pic_env::BuiltWasms, icp_wasm: &[u8], ks: keys::Keyset, tag: &str) -> Self {
        let cfg = common::poseidon_config();
        let accounts = soak::model::derive_accounts(SEED, 3, &cfg);
        let dir = std::env::temp_dir().join(format!("icp_leg_battery_{}_{}", std::process::id(), tag));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let principals: Vec<Principal> = accounts.iter().map(|a| a.principal).collect();
        let env = pic_env::setup_icp(w, icp_wasm, &ks.transfer_vk_hex, &ks.deposit_vk_hex, &dir, &principals, 1_000 * ICP, ARCHIVE_TRIGGER);
        let h = Harness { env, keyset: ks, cfg, cfg_tree: common::poseidon_config_tree(), accounts, leaves: vec![], notes: vec![], op: 0 };
        for i in 0..h.accounts.len() {
            let r: IcrcResult = h
                .env
                .update(
                    h.env.token,
                    h.accounts[i].principal,
                    "icrc2_approve",
                    (ApproveArgs {
                        from_subaccount: None,
                        spender: ct::Account { owner: h.env.ledger, subaccount: None },
                        amount: Nat::from(500 * ICP),
                        expected_allowance: None,
                        expires_at: None,
                        fee: None,
                        memo: None,
                        created_at_time: None,
                    },),
                )
                .expect("icrc2_approve call");
            assert!(matches!(r, IcrcResult::Ok(_)), "approve: {r:?}");
        }
        h
    }

    fn icp_balance(&self, owner: Principal) -> u64 {
        let n: Nat = self.env.query(self.env.token, "icrc1_balance_of", (ct::Account { owner, subaccount: None },)).expect("balance");
        u64::try_from(n.0).unwrap()
    }
    fn pool_balance(&self) -> u64 {
        self.icp_balance(self.env.ledger)
    }
    fn chain(&self) -> ChainLength {
        self.env
            .query(self.env.token, "query_blocks", (QueryArgs { start: 0, length: 0 },))
            .expect("query_blocks")
    }
    fn advance(&self, secs: u64) {
        self.env.pic().advance_time(Duration::from_secs(secs));
        self.env.pic().tick();
    }
    /// `n` ordinary ICP transfers (1 e8s between two users): new blocks, and archiving.
    fn icp_traffic(&self, n: u64) {
        for k in 0..n {
            let r: IcrcResult = self
                .env
                .update(
                    self.env.token,
                    self.accounts[2].principal,
                    "icrc1_transfer",
                    (TransferArg {
                        from_subaccount: None,
                        to: ct::Account { owner: self.accounts[1].principal, subaccount: None },
                        amount: Nat::from(1u64 + k),
                        fee: None,
                        memo: None,
                        created_at_time: None,
                    },),
                )
                .expect("icrc1_transfer call");
            assert!(matches!(r, IcrcResult::Ok(_)), "traffic: {r:?}");
        }
        for _ in 0..5 {
            self.env.pic().tick(); // let the ledger spawn and fill its archive
        }
    }
    fn archived(&self) -> bool {
        self.chain().first_block_index > 0
    }

    fn prepare_shield(&mut self, acct: usize, v: u64) -> (ct::DepositArgs, F, F) {
        self.op += 1;
        let mut prng = prover::op_rng(SEED, self.op, "icp-leg-shield");
        let rho = F::rand(&mut prng);
        let rcm = F::rand(&mut prng);
        let mut prepared = prover::prepare_shield(&self.cfg, &self.keyset.deposit_pk, &self.accounts[acct], v, rho, rcm, SEED, self.op);
        prepared.args.created_at_time = self.env.time_ns();
        (prepared.args, rho, rcm)
    }
    fn record_shield(&mut self, acct: usize, v: u64, rho: F, rcm: F) {
        self.leaves.push(common::note_commitment(&self.cfg, v, self.accounts[acct].pk, rho, rcm));
        self.notes.push(NoteRec { acct, v, rho, rcm, spent: false });
    }
    fn shield(&mut self, acct: usize, v: u64) -> ct::MutationResult {
        let (args, rho, rcm) = self.prepare_shield(acct, v);
        let m: ct::MutationResult = self.env.update(self.env.ledger, self.accounts[acct].principal, "shield", (args,)).expect("shield call");
        if m.outcome.starts_with("ACCEPT") {
            self.record_shield(acct, v, rho, rcm);
        }
        m
    }
    /// A shield that traps right after the ICP transfer (test hook), leaving the intent pending.
    fn crashed_shield(&mut self, acct: usize, v: u64) -> (F, F) {
        let armed: ct::MotokoResult<()> = self.env.update(self.env.ledger, self.env.admin, "test_arm_fail_after_token_once", ()).expect("arm");
        armed.into_result().expect("arm result");
        let (args, rho, rcm) = self.prepare_shield(acct, v);
        let r: Result<ct::MutationResult, String> = self.env.update(self.env.ledger, self.accounts[acct].principal, "shield", (args,));
        let err = r.err().expect("armed shield must trap after the token call");
        assert!(err.contains("TEST_ONLY:fail-after-token"), "unexpected trap: {err}");
        (rho, rcm)
    }
    fn resume_shield(&self, acct: usize) -> ct::MutationResult {
        self.env.update(self.env.ledger, self.accounts[acct].principal, "resume_shield", ()).expect("resume_shield call")
    }

    /// Move `v_pub` out of `acct`'s two largest notes to `acct`'s own ICP account.
    fn unshield(&mut self, acct: usize, v_pub: u64) -> ct::MutationResult {
        let mut own: Vec<usize> = (0..self.notes.len()).filter(|&k| self.notes[k].acct == acct && !self.notes[k].spent).collect();
        own.sort_by_key(|&k| std::cmp::Reverse(self.notes[k].v));
        let (i, j) = (own[0], own[1]);
        self.op += 1;
        let plan = |k: usize| prover::TransferPlanInput {
            note_index: k,
            leaf_index: k as u64,
            v: self.notes[k].v,
            nk: self.accounts[self.notes[k].acct].nk,
            rho: self.notes[k].rho,
            rcm: self.notes[k].rcm,
        };
        let tree = common::DenseTree { leaves: self.leaves.clone() };
        let mut prng = prover::op_rng(SEED, self.op, "icp-leg-unshield");
        let crypto = prover::TransferCrypto {
            anchor: tree.root(&self.cfg_tree),
            path1: tree.path(&self.cfg_tree, i),
            path2: tree.path(&self.cfg_tree, j),
            out_rcm1: F::rand(&mut prng),
            out_rcm2: F::rand(&mut prng),
        };
        let total = self.notes[i].v + self.notes[j].v;
        let owner = self.accounts[acct].principal;
        let binding = {
            use soak::icrc3_hash::{blob_v, hash_value, text};
            let value = ct::Value::Map(vec![
                ("domain".into(), text("picp-unshield-recipient/v1")),
                ("pool".into(), blob_v(self.env.ledger.as_slice().to_vec())),
                ("token".into(), blob_v(self.env.token.as_slice().to_vec())),
                ("owner".into(), blob_v(owner.as_slice().to_vec())),
            ]);
            let mut d = hash_value(&value);
            d[31] = 0;
            d
        };
        let (in1, in2) = (plan(i), plan(j));
        let mut prepared = prover::prepare_transfer(
            &self.cfg,
            &self.keyset.transfer_pk,
            self.keyset.legacy_statement,
            &crypto,
            (&in1, &in2),
            (&self.accounts[acct], &self.accounts[acct]),
            (0, total - FEE - v_pub),
            FEE,
            v_pub,
            binding,
            Some(ct::Account { owner, subaccount: None }),
            Some(acct),
            SEED,
            self.op,
        );
        prepared.args.created_at_time = Some(self.env.time_ns());
        let m: ct::MutationResult = self.env.update(self.env.ledger, owner, "confidential_transfer", (prepared.args.clone(),)).expect("unshield call");
        if m.outcome.starts_with("ACCEPT") {
            self.notes[i].spent = true;
            self.notes[j].spent = true;
            for (o, v, rho, rcm) in prepared.outs.iter() {
                self.leaves.push(common::note_commitment(&self.cfg, *v, self.accounts[*o].pk, *rho, *rcm));
                self.notes.push(NoteRec { acct: *o, v: *v, rho: *rho, rcm: *rcm, spent: false });
            }
            let root = f_bytes(&common::DenseTree { leaves: self.leaves.clone() }.root(&self.cfg_tree)).to_vec();
            assert_eq!(self.env.ledger_status().note_root.as_ref(), root.as_slice(), "battery mirror diverged");
        }
        m
    }
}

#[derive(CandidType)]
struct QueryArgs {
    start: u64,
    length: u64,
}

fn accepted(m: &ct::MutationResult, what: &str) -> Result<(), String> {
    if m.outcome.starts_with("ACCEPT") { Ok(()) } else { Err(format!("{what}: {} / {}", m.outcome, m.verifier_outcome)) }
}

type Built = (pic_env::BuiltWasms, Vec<u8>, keys::Keyset);

fn i1_i2_settle(b: &Built) -> Result<(), String> {
    let (w, icp, ks) = b;
    let mut h = Harness::new(w, icp, ks.clone(), "i1");
    let user = h.accounts[0].principal;
    let (u0, p0) = (h.icp_balance(user), h.pool_balance());
    accepted(&h.shield(0, 3 * ICP), "I1 shield")?;
    accepted(&h.shield(0, ICP), "I1 second shield")?;
    let (u1, p1) = (h.icp_balance(user), h.pool_balance());
    if u0 - u1 != 4 * ICP + 2 * FEE || p1 - p0 != 4 * ICP {
        return Err(format!("I1 RED: user −{} (want {}), pool +{} (want {})", u0 - u1, 4 * ICP + 2 * FEE, p1 - p0, 4 * ICP));
    }
    println!("[I1] PASS make private settles from the ICP block: user −{} e8s, pool +{} e8s", u0 - u1, p1 - p0);
    accepted(&h.unshield(0, ICP / 2), "I2 unshield")?;
    let (u2, p2) = (h.icp_balance(user), h.pool_balance());
    if u2 - u1 != ICP / 2 || p1 - p2 != ICP / 2 + FEE {
        return Err(format!("I2 RED: user +{} (want {}), pool −{} (want {})", u2 - u1, ICP / 2, p1 - p2, ICP / 2 + FEE));
    }
    println!("[I2] PASS move out settles from the ICP payout block: user +{} e8s, pool −{} e8s", u2 - u1, p1 - p2);
    Ok(())
}

fn i3_resume_in_window(b: &Built) -> Result<(), String> {
    let (w, icp, ks) = b;
    let mut h = Harness::new(w, icp, ks.clone(), "i3");
    let user = h.accounts[0].principal;
    let u0 = h.icp_balance(user);
    let (rho, rcm) = h.crashed_shield(0, 2 * ICP);
    let charged = u0 - h.icp_balance(user);
    let m = h.resume_shield(0);
    accepted(&m, "I3 resume")?;
    h.record_shield(0, 2 * ICP, rho, rcm);
    let total = u0 - h.icp_balance(user);
    if charged != 2 * ICP + FEE || total != charged {
        return Err(format!("I3 RED: charged {charged} at the crash, {total} after resume (want {} once)", 2 * ICP + FEE));
    }
    println!("[I3] PASS crash then resume in the dedup window: settled ({}), charged once ({total} e8s)", m.outcome);
    Ok(())
}

fn i4_resume_after_window_archived(b: &Built) -> Result<(), String> {
    let (w, icp, ks) = b;
    let mut h = Harness::new(w, icp, ks.clone(), "i4");
    let user = h.accounts[0].principal;
    let u0 = h.icp_balance(user);
    let (rho, rcm) = h.crashed_shield(0, 2 * ICP);
    h.icp_traffic(3 * ARCHIVE_TRIGGER);
    if !h.archived() {
        return Err("I4 setup: the ICP ledger did not archive".into());
    }
    h.advance(25 * 3600);
    let m = h.resume_shield(0);
    accepted(&m, "I4 resume after the window")?;
    h.record_shield(0, 2 * ICP, rho, rcm);
    // the traffic is sent by account 2, so account 0's balance moves only by the shield
    let charged = u0 - h.icp_balance(user);
    if charged != 2 * ICP + FEE {
        return Err(format!("I4 RED: charged {charged} (want {})", 2 * ICP + FEE));
    }
    println!("[I4] PASS crash, block archived, resumed after 25 h: found through the archive ({}), charged once", m.outcome);
    Ok(())
}

fn i5_resume_in_window_archived(b: &Built) -> Result<(), String> {
    let (w, icp, ks) = b;
    let mut h = Harness::new(w, icp, ks.clone(), "i5");
    let user = h.accounts[0].principal;
    let u0 = h.icp_balance(user);
    let (rho, rcm) = h.crashed_shield(0, 2 * ICP);
    h.icp_traffic(3 * ARCHIVE_TRIGGER);
    if !h.archived() {
        return Err("I5 setup: the ICP ledger did not archive".into());
    }
    let m = h.resume_shield(0);
    accepted(&m, "I5 resume in window, archived")?;
    h.record_shield(0, 2 * ICP, rho, rcm);
    let charged = u0 - h.icp_balance(user);
    if charged != 2 * ICP + FEE {
        return Err(format!("I5 RED: charged {charged} (want {})", 2 * ICP + FEE));
    }
    println!("[I5] PASS crash, block archived, resumed in the window: Duplicate read through the archive ({}), charged once", m.outcome);
    Ok(())
}

fn i6_scan_keeps_place(b: &Built) -> Result<(), String> {
    let (w, icp, ks) = b;
    let mut h = Harness::new(w, icp, ks.clone(), "i6");
    let user = h.accounts[0].principal;
    let u0 = h.icp_balance(user);
    // the shield's token call is rejected (test hook): the intent stays pending, no ICP moves
    let armed: ct::MotokoResult<()> = h.env.update(h.env.ledger, h.env.admin, "test_arm_reject_token_call_once", ()).map_err(|e| format!("arm: {e}"))?;
    armed.into_result().map_err(|e| format!("arm: {e}"))?;
    let m = h.shield(0, 2 * ICP);
    if !m.outcome.starts_with("PENDING:token-call") {
        return Err(format!("I6 setup: the rejected shield said {}", m.outcome));
    }
    // 200 more ICP blocks, then past the dedup window: proving the transfer never landed means
    // reading to the end of the log, over three one-page scans
    h.icp_traffic(200);
    h.advance(25 * 3600);
    let mut resumes = 0;
    let outcome = loop {
        resumes += 1;
        let m = h.resume_shield(0);
        if !m.outcome.starts_with("PENDING") || resumes >= 12 {
            break m.outcome;
        }
    };
    let charged = u0 - h.icp_balance(user);
    if !outcome.starts_with("REJECT") || resumes < 3 || charged != 0 {
        return Err(format!("I6 RED: after {resumes} resumes the intent says {outcome}; charged {charged}"));
    }
    println!("[I6] PASS a 200-block tail on a one-page budget: absence proven over {resumes} resumes, intent released ({outcome}), nothing charged");
    Ok(())
}

/// The hook ledger built from a patched copy of src/Main.mo (each anchor must occur once). The
/// generated source sits next to src/Main.mo so its relative imports resolve, and is removed after.
fn build_hook_variant(root: &Path, tag: &str, patches: &[(&str, &str)]) -> Vec<u8> {
    let mut main = std::fs::read_to_string(root.join("src/Main.mo")).expect("read Main.mo");
    for (from, to) in patches {
        assert_eq!(main.matches(from).count(), 1, "variant {tag}: patch anchor must occur exactly once:\n{from}");
        main = main.replace(from, to);
    }
    let fragment = std::fs::read_to_string(root.join("scripts/test-hooks.frag.mo")).expect("hook fragment");
    let close = main.rfind('}').expect("actor closing brace");
    let generated = format!(
        "{}  // ================= TEST HOOKS (generated; NEVER in the shipped wasm) =================\n{fragment}\n  // ================= END TEST HOOKS =================\n{}",
        &main[..close],
        &main[close..]
    );
    let path = root.join(format!("src/MainIcpVariant_{tag}.generated.mo"));
    std::fs::write(&path, generated).expect("write variant source");
    let sources = String::from_utf8(std::process::Command::new(pic_env::resolve_mops()).arg("sources").current_dir(root).output().expect("mops").stdout).unwrap();
    let out = std::env::temp_dir().join(format!("icp_leg_variant_{}_{tag}.wasm", std::process::id()));
    let status = std::process::Command::new(pic_env::resolve_moc())
        .args(sources.split_whitespace())
        .arg("-c")
        .arg(&path)
        .arg("-o")
        .arg(&out)
        .current_dir(root)
        .status()
        .expect("moc");
    let _ = std::fs::remove_file(&path);
    assert!(status.success(), "variant {tag} compile failed");
    std::fs::read(&out).expect("read variant wasm")
}

type Check = (&'static str, fn(&Built) -> Result<(), String>);

fn main() {
    let root = repo_root();
    let icp_path = std::env::var("ICP_LEDGER_WASM").expect("ICP_LEDGER_WASM=<ledger-canister_notify-method.wasm.gz>");
    let icp = std::fs::read(&icp_path).expect("read ICP ledger wasm");
    println!("[battery] ICP ledger wasm (gz) sha256 {}", pic_env::sha_hex(&icp));
    let manifest = std::fs::read_to_string(root.join("fixtures/pool-vectors-bls12-381-hardened/SETUP-MANIFEST.json")).unwrap();
    let keyset = keys::regenerate_and_verify(&manifest, false).expect("keyset");
    let base = pic_env::build_wasms(&root, &root.join("soak/target/wasms"));
    let with = |ledger: Vec<u8>| -> Built { (pic_env::BuiltWasms { ledger, ..base.clone() }, icp.clone(), keyset.clone()) };
    let shipped = with(pic_env::build_hook_ledger(&root, &root.join("soak/target/wasms")));
    // the I6 budget: one 64-block page per scan call instead of 256
    let budget = ("  let SCAN_PAGE_LIMIT : Nat = 256;", "  let SCAN_PAGE_LIMIT : Nat = 1; // I6: one page per call");
    let budgeted = with(build_hook_variant(&root, "budget", &[budget]));

    let checks: Vec<Check> = vec![
        ("I1+I2", i1_i2_settle),
        ("I3", i3_resume_in_window),
        ("I4", i4_resume_after_window_archived),
        ("I5", i5_resume_in_window_archived),
    ];

    println!("\n==== TEETH: planted defects must turn the checks RED ====");
    let skip_archive = (
        "    for (range in first.archived_blocks.vals()) {\n      let rangeStart = Nat64.toNat(range.start);",
        "    for (range in ([] : [IcpBlock.ArchivedBlocksRange]).vals()) { // PLANTED DEFECT A\n      let rangeStart = Nat64.toNat(range.start);",
    );
    let wrong_account = (
        "      case (#icp(value)) IcpBlock.matchesTransferFrom(value, args, selfPrincipal());",
        "      case (#icp(value)) IcpBlock.matchesTransferFrom(value, { args with from = args.to }, selfPrincipal()); // PLANTED DEFECT B",
    );
    let forget_place = (
        "          index += covered;\n          Map.add(icp_scan_cursor, Blob.compare, intent, index);",
        "          index += covered; // PLANTED DEFECT C: the place is not kept",
    );
    let drop_on_absent = (
        "      if (index >= chainLength) return #absent;",
        "      if (index >= chainLength) { Map.remove(icp_scan_cursor, Blob.compare, intent); return #absent }; // PLANTED DEFECT D",
    );
    let variants: Vec<(&str, Built, Vec<&str>)> = vec![
        ("A:archived-ranges-skipped", with(build_hook_variant(&root, "a", &[skip_archive])), vec!["I4", "I5"]),
        ("B:wrong-account", with(build_hook_variant(&root, "b", &[wrong_account])), vec!["I1+I2"]),
        ("C:scan-place-not-kept", with(build_hook_variant(&root, "c", &[budget, forget_place])), vec!["I6"]),
        ("D:place-dropped-after-absence", with(build_hook_variant(&root, "d", &[budget, drop_on_absent])), vec!["I6"]),
    ];
    let all: Vec<Check> = checks.iter().cloned().chain(std::iter::once(("I6", i6_scan_keeps_place as fn(&Built) -> Result<(), String>))).collect();
    let (mut teeth, mut wanted) = (0u32, 0u32);
    for (vname, built, reds) in &variants {
        for want in reds {
            wanted += 1;
            let (_, f) = all.iter().find(|(n, _)| n == want).unwrap();
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(built)));
            let red = match outcome {
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

    println!("\n==== SHIPPED LEDGER (hooks build) against the real ICP ledger: all checks GREEN ====");
    let mut green = 0;
    for (name, f) in &checks {
        f(&shipped).unwrap_or_else(|e| panic!("{name} FAILED on the shipped ledger: {e}"));
        green += 1;
    }
    i6_scan_keeps_place(&budgeted).unwrap_or_else(|e| panic!("I6 FAILED on the budgeted ledger: {e}"));
    green += 1;
    println!("\nICP TOKEN-LEG BATTERY COMPLETE: {green}/5 green, {teeth}/{wanted} planted reds");
    println!("ICP-TOKEN-LEG-BATTERY: PASS");
}
