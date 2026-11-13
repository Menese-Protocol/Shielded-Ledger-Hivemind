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

pub fn sha_hex(bytes: &[u8]) -> String {
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

pub fn resolve_moc() -> PathBuf {
    if let Ok(p) = std::env::var("SOAK_MOC") {
        return PathBuf::from(p);
    }
    let pinned = PathBuf::from("/opt/moc-1.4.1/moc");
    if pinned.exists() {
        return pinned;
    }
    PathBuf::from("moc")
}

pub fn resolve_mops() -> PathBuf {
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

/// The ledger with the admin-gated test-hook fragment (`scripts/test-hooks.frag.mo`) injected before
/// the actor's closing brace — the `scripts/build-test-wasm.sh` construction, compiled with the SAME
/// moc and package sources as `build_wasms`. The shipped wasm never contains these hooks; harnesses
/// that inject faults (`test_arm_fail_after_token_once`) must run against this build. The injection
/// is additive only: removing the hook block yields `src/Main.mo` byte for byte, which is asserted.
pub fn build_hook_ledger(repo_root: &Path, out_dir: &Path) -> Vec<u8> {
    std::fs::create_dir_all(out_dir).expect("create wasm out dir");
    let moc = resolve_moc();
    let mops = resolve_mops();
    let main = std::fs::read_to_string(repo_root.join("src/Main.mo")).expect("read Main.mo");
    let fragment =
        std::fs::read_to_string(repo_root.join("scripts/test-hooks.frag.mo")).expect("read hook fragment");
    let close = main.rfind('}').expect("actor closing brace");
    let begin = "  // ================= TEST HOOKS (generated; NEVER in the shipped wasm) =================\n";
    let end = "\n  // ================= END TEST HOOKS =================\n";
    let generated = format!("{}{begin}{fragment}{end}{}", &main[..close], &main[close..]);
    assert_eq!(generated.replacen(&format!("{begin}{fragment}{end}"), "", 1), main, "hook injection is not additive-only");
    let gen_path = repo_root.join("src/MainTestHooks.harness.generated.mo");
    std::fs::write(&gen_path, &generated).expect("write generated hook source");
    let sources_raw = String::from_utf8_lossy(&run_checked(
        Command::new(&mops).arg("sources").current_dir(repo_root),
        "mops sources",
    ))
    .to_string();
    let source_args: Vec<String> = sources_raw.split_whitespace().map(String::from).collect();
    let out_path = out_dir.join("zk_ledger_hooks.wasm");
    let compiled = Command::new(&moc)
        .args(&source_args)
        .arg("-c")
        .arg(&gen_path)
        .arg("-o")
        .arg(&out_path)
        .current_dir(repo_root)
        .output();
    let _ = std::fs::remove_file(&gen_path);
    let out = compiled.expect("spawn moc for the hook ledger");
    assert!(
        out.status.success(),
        "hook ledger compile failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::read(&out_path).expect("read hook ledger wasm")
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

// ---------------------------------------------------------------------------------------------
// The real NNS ICP ledger as the pool's token (configure_icp_token_ledger, IcpBlock).

/// The mainnet ICP ledger's canister id; installed at the same id on PocketIC's NNS subnet.
pub const ICP_LEDGER_ID: &str = "ryjl3-tyaaa-aaaaa-aaaba-cai";

/// The ICP ledger's transfer fee, as mainnet charges it (0.0001 ICP).
pub const ICP_FEE_E8S: u64 = 10_000;

/// CRC-32 (IEEE), as the ICP account identifier's 4-byte prefix uses it.
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in bytes {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// ICP account identifier: CRC32(h) ‖ h, h = SHA-224("\x0Aaccount-id" ‖ principal ‖ subaccount32).
pub fn icp_account_id(owner: &Principal, subaccount: Option<[u8; 32]>) -> [u8; 32] {
    use sha2::Sha224;
    let mut h = Sha224::new();
    h.update(b"\x0Aaccount-id");
    h.update(owner.as_slice());
    h.update(subaccount.unwrap_or([0u8; 32]));
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out[..4].copy_from_slice(&crc32(&digest).to_be_bytes());
    out[4..].copy_from_slice(&digest);
    out
}

#[derive(CandidType)]
struct IcpTokens {
    e8s: u64,
}
#[derive(CandidType)]
struct IcpArchiveOptions {
    trigger_threshold: u64,
    num_blocks_to_archive: u64,
    node_max_memory_size_bytes: Option<u64>,
    max_message_size_bytes: Option<u64>,
    controller_id: Principal,
    more_controller_ids: Option<Vec<Principal>>,
    cycles_for_archive_creation: Option<u64>,
    max_transactions_per_response: Option<u64>,
}
#[derive(CandidType)]
struct IcpFeatureFlags {
    icrc2: bool,
}
#[derive(CandidType)]
struct IcpInitArgs {
    minting_account: String,
    icrc1_minting_account: Option<ct::Account>,
    initial_values: Vec<(String, IcpTokens)>,
    max_message_size_bytes: Option<u64>,
    transaction_window: Option<IcpDuration>,
    archive_options: Option<IcpArchiveOptions>,
    send_whitelist: Vec<Principal>,
    transfer_fee: Option<IcpTokens>,
    token_symbol: Option<String>,
    token_name: Option<String>,
    feature_flags: Option<IcpFeatureFlags>,
}
#[derive(CandidType)]
struct IcpDuration {
    secs: u64,
    nanos: u32,
}
#[derive(CandidType)]
enum IcpLedgerPayload {
    Init(IcpInitArgs),
}

/// Start PocketIC with the REAL NNS ICP ledger (`icp_ledger_wasm`, e.g. the mainnet revision's
/// ledger-canister_notify-method.wasm.gz) at its mainnet id, ICRC-2 on, a 0.0001 ICP fee, each of
/// `funded` holding `balance_e8s`, and archiving after `archive_trigger` blocks (so archived reads
/// happen in-test). The zk ledger is bound with `configure_icp_token_ledger`: no history adapter.
pub fn setup_icp(
    wasms: &BuiltWasms,
    icp_ledger_wasm: &[u8],
    transfer_vk_hex: &str,
    deposit_vk_hex: &str,
    state_dir: &Path,
    funded: &[Principal],
    balance_e8s: u64,
    archive_trigger: u64,
) -> Env {
    let binary = resolve_pocket_ic_server();
    let server = std::sync::Arc::new(spawn_server(&binary));
    let pic = PocketIcBuilder::new()
        .with_server_url(server.url.clone())
        .with_nns_subnet()
        .with_application_subnet()
        .with_state_dir(state_dir.to_path_buf())
        .with_max_request_time_ms(Some(600_000))
        .build();
    pic.set_time(pocket_ic::Time::from_nanos_since_unix_epoch(GENESIS_NS));
    let admin = Principal::self_authenticating(Sha256::digest(b"soak-admin-v1"));

    let icp = Principal::from_text(ICP_LEDGER_ID).unwrap();
    pic.create_canister_with_id(Some(admin), None, icp).expect("create the ICP ledger at its mainnet id");
    pic.add_cycles(icp, 1_000_000_000_000_000);
    let minting = Principal::self_authenticating(Sha256::digest(b"icp-minting-account"));
    let init = IcpLedgerPayload::Init(IcpInitArgs {
        minting_account: hex::encode(icp_account_id(&minting, None)),
        icrc1_minting_account: None,
        initial_values: funded
            .iter()
            .map(|p| (hex::encode(icp_account_id(p, None)), IcpTokens { e8s: balance_e8s }))
            .collect(),
        max_message_size_bytes: None,
        transaction_window: None,
        archive_options: Some(IcpArchiveOptions {
            trigger_threshold: archive_trigger,
            num_blocks_to_archive: archive_trigger / 2,
            node_max_memory_size_bytes: None,
            max_message_size_bytes: None,
            controller_id: admin,
            more_controller_ids: None,
            cycles_for_archive_creation: Some(10_000_000_000_000),
            max_transactions_per_response: None,
        }),
        send_whitelist: vec![],
        transfer_fee: Some(IcpTokens { e8s: ICP_FEE_E8S }),
        token_symbol: Some("ICP".into()),
        token_name: Some("Internet Computer".into()),
        feature_flags: Some(IcpFeatureFlags { icrc2: true }),
    });
    pic.install_canister(icp, icp_ledger_wasm.to_vec(), candid::encode_one(init).unwrap(), Some(admin));

    let mut create = || {
        let c = pic.create_canister_with_settings(Some(admin), None);
        pic.add_cycles(c, 100_000_000_000_000);
        c
    };
    let tree_oracle = create();
    let ledger = create();
    pic.install_canister(tree_oracle, wasms.tree_oracle.clone(), candid::encode_args(()).unwrap(), Some(admin));
    pic.install_canister(ledger, wasms.ledger.clone(), candid::encode_args(()).unwrap(), Some(admin));
    pic.update_canister_settings(
        ledger,
        Some(admin),
        pocket_ic::CanisterSettings { wasm_memory_limit: Some(candid::Nat::from(8u64 * 1024 * 1024 * 1024)), ..Default::default() },
    )
    .expect("raise ledger wasm_memory_limit");

    let env = Env { pic: Some(pic), server, admin, ledger, token: icp, tree_oracle, ledger_wasm: wasms.ledger.clone(), token_fee: ICP_FEE_E8S, recycles: 0 };
    let configured: ct::MotokoResult<ct::LedgerStatus> = env
        .update(ledger, admin, "configure", (ledger, tree_oracle, transfer_vk_hex.to_string(), deposit_vk_hex.to_string()))
        .expect("ledger configure call");
    configured.into_result().expect("ledger configure");
    let bound: ct::MotokoResult<candid::Reserved> = env
        .update(ledger, admin, "configure_icp_token_ledger", (icp, Option::<ct::Blob>::None))
        .expect("configure_icp_token_ledger call");
    bound.into_result().expect("configure_icp_token_ledger");
    env
}

#[derive(CandidType)]
struct IcpApproveArgs {
    from_subaccount: Option<ct::Blob>,
    spender: ct::Account,
    amount: candid::Nat,
    expected_allowance: Option<candid::Nat>,
    expires_at: Option<u64>,
    fee: Option<candid::Nat>,
    memo: Option<ct::Blob>,
    created_at_time: Option<u64>,
}

#[derive(CandidType, serde::Deserialize, Debug)]
enum IcpApproveResult {
    Ok(candid::Nat),
    Err(candid::Reserved),
}

/// Each owner grants the pool `allowance` with a real `icrc2_approve` on the ICP ledger (the
/// owner pays the ledger fee, as a user would). Pair with `setup_icp`, which seeds the balances.
pub fn icp_approve_pool(env: &Env, owners: &[Principal], allowance: u128) {
    let spender = env.pool_account();
    for owner in owners {
        let r: IcpApproveResult = env
            .update(
                env.token,
                *owner,
                "icrc2_approve",
                (IcpApproveArgs {
                    from_subaccount: None,
                    spender: spender.clone(),
                    amount: candid::Nat::from(allowance),
                    expected_allowance: None,
                    expires_at: None,
                    fee: None,
                    memo: None,
                    created_at_time: None,
                },),
            )
            .expect("icrc2_approve call");
        assert!(matches!(r, IcpApproveResult::Ok(_)), "icrc2_approve for {owner}: {r:?}");
    }
}

// ---------------------------------------------------------------------------------------------
// DFINITY's ICRC ledger (the ckBTC ledger's code) as the pool's token (configure_token_ledger with
// the ledger as its own ICRC-3 history, ICRC1Block / ICRC2Block on legacy `op = "xfer"` blocks).

/// The ckBTC ledger's transfer fee, as mainnet charges it (10 satoshi).
pub const CKBTC_FEE_SATS: u64 = 10;

#[derive(CandidType)]
struct IcrcArchiveOptions {
    num_blocks_to_archive: u64,
    max_transactions_per_response: Option<u64>,
    trigger_threshold: u64,
    max_message_size_bytes: Option<u64>,
    cycles_for_archive_creation: Option<u64>,
    node_max_memory_size_bytes: Option<u64>,
    controller_id: Principal,
    more_controller_ids: Option<Vec<Principal>>,
}
#[derive(CandidType)]
enum IcrcMetadataValue {
    Text(String),
}
#[derive(CandidType)]
struct IcrcInitArgs {
    minting_account: ct::Account,
    fee_collector_account: Option<ct::Account>,
    transfer_fee: candid::Nat,
    decimals: Option<u8>,
    max_memo_length: Option<u16>,
    token_symbol: String,
    token_name: String,
    metadata: Vec<(String, IcrcMetadataValue)>,
    initial_balances: Vec<(ct::Account, candid::Nat)>,
    feature_flags: Option<IcpFeatureFlags>,
    archive_options: IcrcArchiveOptions,
    index_principal: Option<Principal>,
}
#[derive(CandidType)]
enum IcrcLedgerArg {
    Init(IcrcInitArgs),
}

/// The fee collector the test ledger names, as the live ckBTC ledger names one: its blocks then
/// carry `fee_col` / `fee_col_block`, the shape the matchers must read past.
pub fn ckbtc_fee_collector() -> Principal {
    Principal::self_authenticating(Sha256::digest(b"ckbtc-fee-collector"))
}

/// Start PocketIC with DFINITY's ICRC ledger (`icrc_ledger_wasm`, e.g. the ic-icrc1-ledger.wasm.gz
/// the live ckBTC ledger runs) configured as ckBTC is: 8 decimals, a 10-satoshi fee, a fee collector,
/// an 80-byte memo limit, ICRC-2 on; each of `funded` holding `balance`, and archiving after
/// `archive_trigger` blocks (so archived reads happen in-test). The zk ledger is bound with
/// `configure_token_ledger(token, token, null)`: the ICRC ledger serves its own ICRC-3 log.
pub fn setup_icrc_real(
    wasms: &BuiltWasms,
    icrc_ledger_wasm: &[u8],
    transfer_vk_hex: &str,
    deposit_vk_hex: &str,
    state_dir: &Path,
    funded: &[Principal],
    balance: u64,
    archive_trigger: u64,
) -> Env {
    let binary = resolve_pocket_ic_server();
    let server = std::sync::Arc::new(spawn_server(&binary));
    let pic = PocketIcBuilder::new()
        .with_server_url(server.url.clone())
        .with_nns_subnet()
        .with_application_subnet()
        .with_state_dir(state_dir.to_path_buf())
        .with_max_request_time_ms(Some(600_000))
        .build();
    pic.set_time(pocket_ic::Time::from_nanos_since_unix_epoch(GENESIS_NS));
    let admin = Principal::self_authenticating(Sha256::digest(b"soak-admin-v1"));
    let app = pic.topology().get_app_subnets()[0];

    let token = pic.create_canister_on_subnet(Some(admin), None, app);
    pic.add_cycles(token, 1_000_000_000_000_000);
    let minting = Principal::self_authenticating(Sha256::digest(b"ckbtc-minter"));
    let init = IcrcLedgerArg::Init(IcrcInitArgs {
        minting_account: ct::Account { owner: minting, subaccount: None },
        fee_collector_account: Some(ct::Account { owner: ckbtc_fee_collector(), subaccount: None }),
        transfer_fee: candid::Nat::from(CKBTC_FEE_SATS),
        decimals: Some(8),
        max_memo_length: Some(80),
        token_symbol: "ckBTC".into(),
        token_name: "ckBTC".into(),
        metadata: vec![("icrc1:logo".into(), IcrcMetadataValue::Text(String::new()))],
        initial_balances: funded
            .iter()
            .map(|p| (ct::Account { owner: *p, subaccount: None }, candid::Nat::from(balance)))
            .collect(),
        feature_flags: Some(IcpFeatureFlags { icrc2: true }),
        archive_options: IcrcArchiveOptions {
            num_blocks_to_archive: archive_trigger / 2,
            max_transactions_per_response: None,
            trigger_threshold: archive_trigger,
            max_message_size_bytes: None,
            cycles_for_archive_creation: Some(10_000_000_000_000),
            node_max_memory_size_bytes: None,
            controller_id: admin,
            more_controller_ids: None,
        },
        index_principal: None,
    });
    pic.install_canister(token, icrc_ledger_wasm.to_vec(), candid::encode_one(init).unwrap(), Some(admin));

    let mut create = || {
        let c = pic.create_canister_on_subnet(Some(admin), None, app);
        pic.add_cycles(c, 100_000_000_000_000);
        c
    };
    let tree_oracle = create();
    let ledger = create();
    pic.install_canister(tree_oracle, wasms.tree_oracle.clone(), candid::encode_args(()).unwrap(), Some(admin));
    pic.install_canister(ledger, wasms.ledger.clone(), candid::encode_args(()).unwrap(), Some(admin));
    pic.update_canister_settings(
        ledger,
        Some(admin),
        pocket_ic::CanisterSettings { wasm_memory_limit: Some(candid::Nat::from(8u64 * 1024 * 1024 * 1024)), ..Default::default() },
    )
    .expect("raise ledger wasm_memory_limit");

    let env = Env { pic: Some(pic), server, admin, ledger, token, tree_oracle, ledger_wasm: wasms.ledger.clone(), token_fee: CKBTC_FEE_SATS, recycles: 0 };
    let configured: ct::MotokoResult<ct::LedgerStatus> = env
        .update(ledger, admin, "configure", (ledger, tree_oracle, transfer_vk_hex.to_string(), deposit_vk_hex.to_string()))
        .expect("ledger configure call");
    configured.into_result().expect("ledger configure");
    let bound: ct::MotokoResult<candid::Reserved> = env
        .update(ledger, admin, "configure_token_ledger", (token, token, Option::<ct::Blob>::None))
        .expect("configure_token_ledger call");
    bound.into_result().expect("configure_token_ledger");
    let fee: candid::Nat = env.query(token, "icrc1_fee", ()).expect("icrc1_fee");
    assert_eq!(fee, candid::Nat::from(CKBTC_FEE_SATS), "the ICRC ledger must charge the ckBTC fee");
    env
}
