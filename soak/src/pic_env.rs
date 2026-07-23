//! PocketIC environment: build the canister wasms from source (recording toolchain pins and
//! wasm SHA-256), start a PocketIC instance, install the five canisters, wire
//! `configure`/`configure_token_ledger` exactly as the demo and `e2e.py` do, and fund the soak
//! accounts on the token fixture.
//!
//! Toolchain resolution (documented in TESTING.md):
//!   - Motoko compiler: $SOAK_MOC, else /opt/moc-1.4.1/moc, else `moc` on PATH.
//!   - mops (package sources): $SOAK_MOPS, else `mops` on PATH.
//!   - PocketIC server: $POCKET_IC_BIN, else the newest dfx cache entry whose
//!     `pocket-ic --version` reports server 13.x, else `pocket-ic` on PATH.

use crate::candid_types as ct;
use candid::utils::ArgumentEncoder;
use candid::{CandidType, Principal};
use pocket_ic::{PocketIc, PocketIcBuilder, PocketIcState};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Clone)]
pub struct BuiltWasms {
    pub ledger: Vec<u8>,
    pub ledger_sha256: String,
    pub token: Vec<u8>,
    pub token_sha256: String,
    pub tree_oracle: Vec<u8>,
    pub tree_oracle_sha256: String,
    pub moc_version: String,
    pub moc_path: String,
}

fn sha_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Copy a directory tree (`cp -a`): `dest` must not exist and ends up an exact copy of `src`.
pub fn copy_dir_recursive(src: &Path, dest: &Path) {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).expect("create snapshot parent dir");
    }
    let out = Command::new("cp")
        .arg("-a")
        .arg(src)
        .arg(dest)
        .output()
        .expect("spawn cp -a");
    if !out.status.success() {
        panic!(
            "state snapshot copy {} -> {} failed: {}",
            src.display(),
            dest.display(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

fn resolve_moc() -> PathBuf {
    if let Ok(p) = std::env::var("SOAK_MOC") {
        return PathBuf::from(p);
    }
    let pinned = PathBuf::from("/opt/moc-1.4.1/moc");
    if pinned.exists() {
        return pinned;
    }
    PathBuf::from("moc")
}

fn resolve_mops() -> PathBuf {
    PathBuf::from(std::env::var("SOAK_MOPS").unwrap_or_else(|_| "mops".into()))
}

pub fn resolve_pocket_ic_server() -> PathBuf {
    if let Ok(p) = std::env::var("POCKET_IC_BIN") {
        return PathBuf::from(p);
    }
    // newest dfx cache entry that reports a 13.x server
    if let Some(home) = std::env::var_os("HOME") {
        let versions = PathBuf::from(home).join(".cache/dfinity/versions");
        if let Ok(entries) = std::fs::read_dir(&versions) {
            let mut candidates: Vec<PathBuf> = entries
                .flatten()
                .map(|e| e.path().join("pocket-ic"))
                .filter(|p| p.exists())
                .collect();
            candidates.sort();
            candidates.reverse();
            for c in candidates {
                if let Ok(out) = Command::new(&c).arg("--version").output() {
                    let v = String::from_utf8_lossy(&out.stdout);
                    if v.contains("pocket-ic-server 13.") {
                        return c;
                    }
                }
            }
        }
    }
    PathBuf::from("pocket-ic")
}

fn run_checked(cmd: &mut Command, what: &str) -> Vec<u8> {
    let out = cmd.output().unwrap_or_else(|e| panic!("{what}: spawn failed: {e}"));
    if !out.status.success() {
        panic!(
            "{what} failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    out.stdout
}

/// Compile the Motoko canisters, build the adapter wasm, and load the vendored tree oracle.
pub fn build_wasms(repo_root: &Path, out_dir: &Path) -> BuiltWasms {
    std::fs::create_dir_all(out_dir).expect("create wasm out dir");
    let moc = resolve_moc();
    let mops = resolve_mops();

    let moc_version = String::from_utf8_lossy(&run_checked(
        Command::new(&moc).arg("--version"),
        "moc --version",
    ))
    .trim()
    .to_string();

    let sources_raw = String::from_utf8_lossy(&run_checked(
        Command::new(&mops).arg("sources").current_dir(repo_root),
        "mops sources",
    ))
    .to_string();
    let source_args: Vec<String> = sources_raw.split_whitespace().map(String::from).collect();

    let compile = |main: &str, out_name: &str| -> Vec<u8> {
        let out_path = out_dir.join(out_name);
        run_checked(
            Command::new(&moc)
                .args(&source_args)
                .arg("-c")
                .arg(main)
                .arg("-o")
                .arg(&out_path)
                .current_dir(repo_root),
            &format!("moc compile {main}"),
        );
        std::fs::read(&out_path).expect("read compiled wasm")
    };

    // Behavior-identity override: run the SAME harness against a
    // pre-built ledger wasm (e.g. compiled from the pre-fix commit) so the only variable
    // between two runs is the ledger module itself.
    let ledger = match std::env::var("SOAK_LEDGER_WASM") {
        Ok(p) => std::fs::read(&p).unwrap_or_else(|e| panic!("read SOAK_LEDGER_WASM {p}: {e}")),
        Err(_) => compile("src/Main.mo", "zk_ledger.wasm"),
    };
    let token = compile("tests/IcpLedgerFixture.mo", "icp_ledger_fixture.wasm");

    let tree_oracle = std::fs::read(repo_root.join("vendor/tree_oracle_bls/tree_oracle_bls.wasm"))
        .expect("read vendored tree oracle wasm");

    BuiltWasms {
        ledger_sha256: sha_hex(&ledger),
        token_sha256: sha_hex(&token),
        tree_oracle_sha256: sha_hex(&tree_oracle),
        ledger,
        token,
        tree_oracle,
        moc_version,
        moc_path: moc.display().to_string(),
    }
}

/// A self-managed PocketIC server process. The crate's built-in server carries a hard 10-minute
/// TTL (`HARD_TTL_SECS`) and hard-exits mid-run regardless of activity, which kills a long soak.
/// We spawn our own server with no hard TTL and a long idle TTL, and point the crate at it via
/// `with_server_url`, so it lives for the entire run. The child is killed on drop.
pub struct ManagedServer {
    child: std::process::Child,
    pub url: url::Url,
}

impl Drop for ManagedServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Spawn a persistent server: `pocket-ic --port-file <f> --ttl 86400` (no `--hard-ttl`, so it
/// never hard-exits; 24h idle TTL so proving/verification gaps never idle it out).
pub fn spawn_server(binary: &Path) -> ManagedServer {
    use std::io::Read;
    // Use a run-specific port-file marker so concurrent soak runs on one machine
    // can scope cleanup (pkill by cmdline marker) to their OWN servers. With a marker
    // shared across runs, one run's cleanup can kill another run's live server
    // mid-soak — observed as abrupt IncompleteMessage client failures.
    let port_file = std::env::temp_dir().join(format!("ledger_soak_pocket_ic_{}.port", std::process::id()));
    let _ = std::fs::remove_file(&port_file);
    let child = Command::new(binary)
        .arg("--port-file")
        .arg(&port_file)
        .arg("--ttl")
        .arg("86400")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn pocket-ic server: {e}"));
    // poll the port file until the server writes a parseable, newline-terminated port
    let start = std::time::Instant::now();
    let port = loop {
        if let Ok(mut f) = std::fs::File::open(&port_file) {
            let mut s = String::new();
            if f.read_to_string(&mut s).is_ok() {
                // the server writes the port followed by a newline once it is ready
                if s.ends_with('\n') {
                    if let Ok(p) = s.trim().parse::<u16>() {
                        break p;
                    }
                }
            }
        }
        if start.elapsed().as_secs() > 60 {
            panic!("pocket-ic server did not report a port within 60s");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    let url = url::Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
    ManagedServer { child, url }
}

pub struct Env {
    // Wrapped in Option so the instance can be recycled: `drop_and_take_state` consumes the
    // PocketIc (freeing the server memory that instance held) and returns the full IC state,
    // from which a fresh, clean-memory instance is rebuilt losslessly. This is the DFINITY
    // blessed way to bound a long-lived instance's growth over a very long run.
    pic: Option<PocketIc>,
    server: std::sync::Arc<ManagedServer>,
    pub admin: Principal,
    pub ledger: Principal,
    pub token: Principal,
    pub tree_oracle: Principal,
    pub ledger_wasm: Vec<u8>,
    pub token_fee: u64,
    pub recycles: u64,
}

/// Fixed deterministic genesis time (2026-07-17T00:00:00Z, ns): block timestamps enter the
/// phash chain, so reruns with the same seed must see identical time.
pub const GENESIS_NS: u64 = 1_784_246_400_000_000_000;

impl Env {
    pub fn pic(&self) -> &PocketIc {
        self.pic.as_ref().expect("pocket-ic instance present")
    }

    /// Recycle the instance: persist and reload the full IC state on a fresh instance so the
    /// server memory the old instance held is released. Canister ids, root key, time, and all
    /// state are preserved exactly.
    pub fn recycle(&mut self) {
        self.recycle_with_snapshot(None);
    }

    /// Like `recycle`, but between drop and rebuild — the only window where the state dir is
    /// flushed and nothing is writing to it — copy `state_dir` to `dest`. The copy forms an
    /// immutable pair with the model checkpoint the caller writes; the live dir advances past
    /// the pair as soon as the run continues, so resume must load the pair, never the live dir.
    pub fn recycle_with_snapshot(&mut self, snapshot: Option<(&Path, &Path)>) {
        let state = self
            .pic
            .take()
            .expect("instance present")
            .drop_and_take_state()
            .expect("state dir configured");
        if let Some((state_dir, dest)) = snapshot {
            copy_dir_recursive(state_dir, dest);
        }
        let pic = PocketIcBuilder::new()
            .with_server_url(self.server.url.clone())
            .with_state(state)
            .with_max_request_time_ms(Some(600_000))
            .build();
        self.pic = Some(pic);
        self.recycles += 1;
    }

    pub fn update<Out: CandidType + for<'de> serde::Deserialize<'de>>(
        &self,
        canister: Principal,
        sender: Principal,
        method: &str,
        args: impl ArgumentEncoder,
    ) -> Result<Out, String> {
        let payload = candid::encode_args(args).map_err(|e| format!("encode {method}: {e}"))?;
        let raw = self
            .pic()
            .update_call(canister, sender, method, payload)
            .map_err(|e| format!("{method} rejected: {e:?}"))?;
        candid::decode_one(&raw).map_err(|e| format!("decode {method}: {e}"))
    }

    pub fn query<Out: CandidType + for<'de> serde::Deserialize<'de>>(
        &self,
        canister: Principal,
        method: &str,
        args: impl ArgumentEncoder,
    ) -> Result<Out, String> {
        let payload = candid::encode_args(args).map_err(|e| format!("encode {method}: {e}"))?;
        let raw = self
            .pic()
            .query_call(canister, Principal::anonymous(), method, payload)
            .map_err(|e| format!("{method} rejected: {e:?}"))?;
        candid::decode_one(&raw).map_err(|e| format!("decode {method}: {e}"))
    }

    pub fn time_ns(&self) -> u64 {
        self.pic().get_time().as_nanos_since_unix_epoch()
    }

    pub fn ledger_status(&self) -> ct::LedgerStatus {
        self.query(self.ledger, "status", ()).expect("status query")
    }

    pub fn ledger_rts(&self) -> ct::RtsStatus {
        self.query(self.ledger, "rts_status", ()).expect("rts_status query")
    }

    pub fn token_balance(&self, account: &ct::Account) -> u128 {
        let n: candid::Nat = self
            .query(self.token, "icrc1_balance_of", (account.clone(),))
            .expect("icrc1_balance_of");
        u128::try_from(n.0).expect("balance fits u128")
    }

    pub fn pool_account(&self) -> ct::Account {
        ct::Account { owner: self.ledger, subaccount: None }
    }
}

/// Rebuild the Env from a durable state directory written by an earlier (crashed) process. The
/// canister ids, root key, time, and all state are reloaded from disk; no configure or funding is
/// redone. Used by the crash-resume path.
pub fn resume(state_dir: &Path, ledger: Principal, token: Principal, tree_oracle: Principal, admin: Principal, token_fee: u64, ledger_wasm: Vec<u8>) -> Env {
    let binary = resolve_pocket_ic_server();
    let server = std::sync::Arc::new(spawn_server(&binary));
    let pic = PocketIcBuilder::new()
        .with_server_url(server.url.clone())
        .with_state_dir(state_dir.to_path_buf())
        .with_max_request_time_ms(Some(600_000))
        .build();
    Env {
        pic: Some(pic),
        server,
        admin,
        ledger,
        token,
        tree_oracle,
        ledger_wasm,
        token_fee,
        recycles: 0,
    }
}

/// Start PocketIC, install and wire all canisters. `state_dir` is a durable directory the run
/// checkpoints into (must be empty for a fresh run).
pub fn setup(wasms: &BuiltWasms, transfer_vk_hex: &str, deposit_vk_hex: &str, state_dir: &Path) -> Env {
    let binary = resolve_pocket_ic_server();
    let server = std::sync::Arc::new(spawn_server(&binary));
    let pic = PocketIcBuilder::new()
        .with_server_url(server.url.clone())
        .with_nns_subnet()
        .with_state_dir(state_dir.to_path_buf())
        .with_max_request_time_ms(Some(600_000))
        .build();
    pic.set_time(pocket_ic::Time::from_nanos_since_unix_epoch(GENESIS_NS));

    let admin = Principal::self_authenticating(Sha256::digest(b"soak-admin-v1"));
    let settings = None;
    let mut create = || {
        let c = pic.create_canister_with_settings(Some(admin), settings.clone());
        pic.add_cycles(c, 100_000_000_000_000);
        c
    };
    let token = create();
    let tree_oracle = create();
    let ledger = create();

    pic.install_canister(token, wasms.token.clone(), candid::encode_args(()).unwrap(), Some(admin));
    pic.install_canister(tree_oracle, wasms.tree_oracle.clone(), candid::encode_args(()).unwrap(), Some(admin));
    pic.install_canister(ledger, wasms.ledger.clone(), candid::encode_args(()).unwrap(), Some(admin));

    // The ledger is a wasm64/EOP module whose wasm-memory high-water mark ratchets under
    // per-op verification churn (grows, never shrinks). The IC default limit (3 GiB) trapped
    // upgrade #1 of the Jul-18 full tier at ~52k notes; 8 GiB matches what the settings allow
    // on mainnet for wasm64 canisters and is headroom, not the fix (see rts telemetry).
    pic.update_canister_settings(
        ledger,
        Some(admin),
        pocket_ic::CanisterSettings {
            wasm_memory_limit: Some(candid::Nat::from(8u64 * 1024 * 1024 * 1024)),
            ..Default::default()
        },
    )
    .expect("raise ledger wasm_memory_limit");

    let env = Env {
        pic: Some(pic),
        server: server.clone(),
        admin,
        ledger,
        token,
        tree_oracle,
        ledger_wasm: wasms.ledger.clone(),
        token_fee: 0,
        recycles: 0,
    };

    // Wire exactly as the demo does (demo-frontend/scripts/redeploy.sh): the ledger's own
    // principal stands in for the legacy verifier id (verification is in-process), and the token
    // fixture serves as its own ICRC-3 history adapter.
    let configured: ct::MotokoResult<ct::LedgerStatus> = env
        .update(
            ledger,
            admin,
            "configure",
            (
                ledger,
                tree_oracle,
                transfer_vk_hex.to_string(),
                deposit_vk_hex.to_string(),
            ),
        )
        .expect("ledger configure call");
    let status = configured.into_result().expect("ledger configure");
    assert!(status.configured, "ledger must report configured");

    let token_configured: ct::MotokoResult<candid::Reserved> = env
        .update(
            ledger,
            admin,
            "configure_token_ledger",
            (token, token, Option::<ct::Blob>::None),
        )
        .expect("configure_token_ledger call");
    token_configured.into_result().expect("configure_token_ledger");

    let fee: candid::Nat = env.query(token, "icrc1_fee", ()).expect("icrc1_fee");
    let token_fee = u64::try_from(fee.0).expect("fee fits u64");

    Env { token_fee, ..env }
}

/// Fund every account on the token fixture and grant the pool a (large) allowance, one call per
/// account. Balances/allowances are test-fixture state, not production paths.
pub fn fund_accounts(env: &Env, principals: &[Principal], balance: u128, allowance: u128) {
    let pool = env.pool_account();
    for p in principals {
        let account = ct::Account { owner: *p, subaccount: None };
        let _: () = env
            .update(env.token, env.admin, "test_set_balance", (account.clone(), candid::Nat::from(balance)))
            .expect("test_set_balance");
        let _: () = env
            .update(
                env.token,
                env.admin,
                "test_set_allowance",
                (account, pool.clone(), candid::Nat::from(allowance)),
            )
            .expect("test_set_allowance");
    }
}
