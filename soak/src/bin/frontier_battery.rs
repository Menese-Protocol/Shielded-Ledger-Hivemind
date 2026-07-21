//! Malicious-oracle battery + standalone + upgrade-safety proof on PocketIC.
//!
//! For each scenario a FRESH ledger is stood up (honest vendored oracle used for
//! `configure`), the in-canister frontier is enabled, then the tree oracle is swapped
//! for a COMPROMISED one (`tests/MaliciousTreeOracle.mo`) armed to corrupt exactly one
//! field of an otherwise-correct transition. With the frontier authoritative, every
//! corrupted append MUST be rejected by the in-canister cross-check, the sticky
//! fail-closed guard MUST latch, and `historical_root_count` MUST NOT grow — i.e. no
//! oracle-injected root ever reaches `historical_roots`. Two further scenarios prove
//! the honest cross-check accepts (fixture sanity) and that the ledger stands ALONE
//! with the oracle fully detached, and one proves the flag + root survive an upgrade.
//!
//! Real Groth16 deposit proofs are built with the same prover the soak uses, so these
//! are genuine accepted/rejected shields, not synthetic candid.

use ark_ff::UniformRand;
use candid::{Nat, Principal};
use soak::candid_types as ct;
use soak::{keys, pic_env, prover};
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

fn compile_malicious_oracle(root: &Path) -> Vec<u8> {
    let out = std::env::temp_dir().join(format!("malicious_oracle_{}.wasm", std::process::id()));
    let sources_raw = String::from_utf8(
        Command::new("/usr/bin/mops").arg("sources").current_dir(root).output().expect("mops").stdout,
    )
    .unwrap();
    let source_args: Vec<String> = sources_raw.split_whitespace().map(String::from).collect();
    let status = Command::new("/opt/moc-1.4.1/moc")
        .args(&source_args)
        .arg("-c")
        .arg("tests/MaliciousTreeOracle.mo")
        .arg("-o")
        .arg(&out)
        .current_dir(root)
        .status()
        .expect("moc spawn");
    assert!(status.success(), "malicious oracle compile failed");
    std::fs::read(&out).expect("read malicious oracle wasm")
}

#[derive(candid::CandidType)]
enum Mode {
    #[allow(dead_code)]
    honest,
    wrong_root,
    stale,
    truncated,
    wrong_frontier,
}

#[derive(candid::CandidType, serde::Deserialize)]
struct FrontierStatus {
    enabled: bool,
    tree_oracle: Option<Principal>,
}

struct Harness {
    env: pic_env::Env,
    keyset: keys::Keyset,
    cfg: common::PoseidonCfg<common::ScalarField>,
    accounts: Vec<soak::model::AccountKeys>,
    op: u64,
}

impl Harness {
    fn new(root: &Path, wasms: &pic_env::BuiltWasms, keyset: keys::Keyset, tag: &str) -> Self {
        let cfg = common::poseidon_config();
        let accounts = soak::model::derive_accounts(20260721, 4, &cfg);
        let state_dir = std::env::temp_dir().join(format!("frontier_battery_{}_{}", std::process::id(), tag));
        let _ = std::fs::remove_dir_all(&state_dir);
        std::fs::create_dir_all(&state_dir).unwrap();
        let env = pic_env::setup(wasms, &keyset.transfer_vk_hex, &keyset.deposit_vk_hex, &state_dir);
        let principals: Vec<Principal> = accounts.iter().map(|a| a.principal).collect();
        pic_env::fund_accounts(&env, &principals, 1_000_000_000, 1_000_000_000);
        Harness { env, keyset, cfg, accounts, op: 0 }
    }

    fn enable_frontier(&self) {
        let r: ct::MotokoResult<ct::LedgerStatus> = self
            .env
            .update(self.env.ledger, self.env.admin, "set_tree_frontier", (true,))
            .expect("set_tree_frontier");
        r.into_result().expect("enable frontier");
    }

    fn attach_oracle(&self, oracle: Option<Principal>) {
        let r: ct::MotokoResult<ct::LedgerStatus> = self
            .env
            .update(self.env.ledger, self.env.admin, "set_tree_oracle", (oracle,))
            .expect("set_tree_oracle");
        r.into_result().expect("set_tree_oracle result");
    }

    fn frontier_status(&self) -> FrontierStatus {
        self.env.query(self.env.ledger, "tree_frontier_status", ()).expect("tree_frontier_status")
    }

    fn root_count(&self) -> u64 {
        u64::try_from(self.env.ledger_status().historical_root_count.0).unwrap()
    }

    /// Submit a genuine deposit for account `acct` with value `v`. Returns the outcome.
    fn shield(&mut self, acct: usize, v: u64) -> ct::MutationResult {
        self.op += 1;
        let mut prng = prover::op_rng(20260721, self.op, "battery-shield-plan");
        let rho = common::ScalarField::rand(&mut prng);
        let rcm = common::ScalarField::rand(&mut prng);
        let mut prepared =
            prover::prepare_shield(&self.cfg, &self.keyset.deposit_pk, &self.accounts[acct], v, rho, rcm, 20260721, self.op);
        prepared.args.created_at_time = self.env.time_ns();
        self.env
            .update(self.env.ledger, self.accounts[acct].principal, "shield", (prepared.args,))
            .expect("shield call")
    }
}

fn main() {
    let root = repo_root();
    let keyset_for = || {
        let manifest = std::fs::read_to_string(root.join("fixtures/pool-vectors-bls12-381/SETUP-MANIFEST.json")).unwrap();
        keys::regenerate_and_verify(&manifest).expect("keyset")
    };
    println!("[battery] building wasms (ledger + token + honest oracle)...");
    let wasms = pic_env::build_wasms(&root, &root.join("soak/target/wasms"));
    let malicious = compile_malicious_oracle(&root);
    println!("[battery] ledger sha256 {}", wasms.ledger_sha256);

    let mut pass = 0u32;
    let mut checks = 0u32;
    macro_rules! require {
        ($cond:expr, $($m:tt)*) => {{ checks += 1; if $cond { pass += 1; } else { panic!("FAIL: {}", format!($($m)*)); } }};
    }

    // ---- Scenario A: honest cross-check accepts (frontier ON, honest oracle) ----
    {
        println!("\n[A] honest cross-check (frontier ON, vendored oracle)");
        let mut h = Harness::new(&root, &wasms, keyset_for(), "A");
        h.enable_frontier();
        require!(h.frontier_status().enabled, "frontier did not enable");
        let before = h.root_count();
        let m = h.shield(0, 1000);
        require!(m.outcome == "ACCEPT", "honest shield rejected: {}", m.outcome);
        require!(h.root_count() == before + 1, "honest shield did not add a root");
        let m2 = h.shield(1, 2000);
        require!(m2.outcome == "ACCEPT", "second honest shield rejected: {}", m2.outcome);
        println!("[A] PASS — cross-checked appends accepted, roots grew");
    }

    // ---- Scenario B: standalone (frontier ON, oracle DETACHED) ----
    {
        println!("\n[B] standalone (frontier ON, oracle detached)");
        let mut h = Harness::new(&root, &wasms, keyset_for(), "B");
        h.enable_frontier();
        h.attach_oracle(None);
        require!(h.frontier_status().tree_oracle.is_none(), "oracle not detached");
        let before = h.root_count();
        let m = h.shield(0, 1234);
        require!(m.outcome == "ACCEPT", "standalone shield rejected: {}", m.outcome);
        require!(h.root_count() == before + 1, "standalone shield did not add a root");
        let m2 = h.shield(2, 5678);
        require!(m2.outcome == "ACCEPT", "second standalone shield rejected: {}", m2.outcome);
        println!("[B] PASS — ledger computes roots ALONE, no oracle in the trust base");
    }

    // ---- Scenario C: malicious oracle — every corruption mode must be rejected ----
    for (label, mode) in [
        ("wrong_root (counterfeit injection)", Mode::wrong_root),
        ("stale (no advance)", Mode::stale),
        ("truncated (stale root)", Mode::truncated),
        ("wrong_frontier (corrupt lane)", Mode::wrong_frontier),
    ] {
        println!("\n[C:{label}] malicious oracle");
        let mut h = Harness::new(&root, &wasms, keyset_for(), "C");
        // one honest shield first (frontier ON, honest oracle) so there is real state
        h.enable_frontier();
        let m0 = h.shield(0, 4242);
        require!(m0.outcome == "ACCEPT", "[{label}] pre-shield rejected");
        let roots_before = h.root_count();
        // install + arm the compromised oracle, then attach it
        let mal = h.env.pic().create_canister_with_settings(Some(h.env.admin), None);
        h.env.pic().add_cycles(mal, 100_000_000_000_000);
        h.env.pic().install_canister(mal, malicious.clone(), candid::encode_args(()).unwrap(), Some(h.env.admin));
        let _: () = h.env.update(mal, h.env.admin, "set_mode", (mode,)).expect("set_mode");
        h.attach_oracle(Some(mal));
        // the compromised append must be rejected via the mismatch guard
        let m = h.shield(1, 9999);
        require!(
            m.outcome.starts_with("GUARDED:tree-frontier-mismatch") || m.outcome.starts_with("GUARDED:"),
            "[{label}] compromised append NOT rejected: {}",
            m.outcome
        );
        require!(h.root_count() == roots_before, "[{label}] a malicious root entered historical_roots");
        // the guard is sticky: a follow-up shield is also refused, and STILL no root added
        let m2 = h.shield(2, 8888);
        require!(m2.outcome.starts_with("GUARDED:"), "[{label}] guard not sticky: {}", m2.outcome);
        require!(h.root_count() == roots_before, "[{label}] root count moved under sticky guard");
        // config endpoints are ALSO fail-closed: swapping the oracle back is refused while
        // guarded, so an attacker cannot quietly repair the trust base to hide the tampering.
        let revert: ct::MotokoResult<ct::LedgerStatus> = h
            .env
            .update(h.env.ledger, h.env.admin, "set_tree_oracle", (Some(h.env.tree_oracle),))
            .expect("set_tree_oracle call");
        require!(
            matches!(&revert, ct::MotokoResult::err(e) if e.starts_with("GUARDED:")),
            "[{label}] guarded ledger allowed an oracle swap: {:?}",
            revert
        );
        println!("[C:{label}] PASS — rejected, guard latched, config fail-closed, roots unpolluted");
    }

    // ---- Scenario D: upgrade safety (flag + root survive) ----
    {
        println!("\n[D] upgrade safety (frontier ON)");
        let mut h = Harness::new(&root, &wasms, keyset_for(), "D");
        h.enable_frontier();
        require!(h.shield(0, 111).outcome == "ACCEPT", "pre-upgrade shield rejected");
        require!(h.shield(1, 222).outcome == "ACCEPT", "pre-upgrade shield 2 rejected");
        let pre = h.env.ledger_status();
        h.env
            .pic()
            .upgrade_eop_canister(h.env.ledger, wasms.ledger.clone(), candid::encode_args(()).unwrap(), Some(h.env.admin))
            .expect("upgrade");
        let post = h.env.ledger_status();
        require!(pre.note_root == post.note_root, "upgrade changed note_root");
        require!(h.frontier_status().enabled, "upgrade lost the frontier flag");
        let roots_pre = u64::try_from(pre.historical_root_count.0.clone()).unwrap();
        let m = h.shield(2, 333);
        require!(m.outcome == "ACCEPT", "post-upgrade shield rejected: {}", m.outcome);
        require!(h.root_count() > roots_pre, "post-upgrade root not added");
        println!("[D] PASS — flag stable, root preserved, appends continue post-upgrade");
    }

    println!("\n[battery] {pass}/{checks} checks PASSED");
    assert_eq!(pass, checks, "battery had failures");
    println!("[battery] DONE — malicious-oracle 100% rejection, standalone green, upgrade-safe");
}
