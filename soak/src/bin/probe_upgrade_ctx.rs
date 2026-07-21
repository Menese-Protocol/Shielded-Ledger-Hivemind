//! TX probe: pin the ACTUAL PocketIC-13 behavior of an EOP
//! upgrade fired while a timer-tick's self-call context is open — the exact shape of the
//! background-audit design (tick awaits __audit_chunk). Outcomes to distinguish:
//!   (1) upgrade rejected while the context is open (drain-before-upgrade required),
//!   (2) upgrade succeeds and the orphaned reply is dropped cleanly (catch never fires),
//!   (3) upgrade succeeds and the reply arrives post-upgrade (catch fires / state weirdness).
//! The runner drains the audit before upgrading regardless; this probe makes the failure
//! mode KNOWN rather than assumed.

use candid::Principal;
use pocket_ic::PocketIcBuilder;
use soak::pic_env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf();
    let probe_src = std::env::var("PROBE_MO").expect("set PROBE_MO to UpgradeCtxProbe.mo path");
    let out = std::env::temp_dir().join(format!("upgrade_ctx_probe_{}.wasm", std::process::id()));

    // compile with the pinned toolchain + the lane's mops sources (same as build_wasms)
    let sources_raw = String::from_utf8(
        Command::new("/usr/bin/mops").arg("sources").current_dir(&repo_root).output().expect("mops").stdout,
    )
    .unwrap();
    let source_args: Vec<String> = sources_raw.split_whitespace().map(String::from).collect();
    let status = Command::new("/opt/moc-1.4.1/moc")
        .args(&source_args)
        .arg("-c")
        .arg(&probe_src)
        .arg("-o")
        .arg(&out)
        .current_dir(&repo_root)
        .status()
        .expect("moc spawn");
    assert!(status.success(), "probe compile failed");
    let wasm = std::fs::read(&out).expect("read probe wasm");

    let server = pic_env::spawn_server(&pic_env::resolve_pocket_ic_server());
    let pic = PocketIcBuilder::new()
        .with_server_url(server.url.clone())
        .with_application_subnet()
        .with_max_request_time_ms(Some(600_000))
        .build();

    let admin = Principal::self_authenticating([7u8; 32]);
    let c = pic.create_canister_with_settings(Some(admin), None);
    pic.add_cycles(c, 100_000_000_000_000);
    pic.install_canister(c, wasm.clone(), candid::encode_args(()).unwrap(), Some(admin));

    let state = |label: &str| {
        let raw = pic
            .query_call(c, Principal::anonymous(), "state", candid::encode_args(()).unwrap())
            .expect("state query");
        let (t, d, e): (candid::Nat, candid::Nat, candid::Nat) =
            candid::decode_args(&raw).expect("decode state");
        println!("[probe] {label}: ticks_started={t} chunks_done={d} catches={e}");
    };

    // CASE 1: upgrade while the tick->__chunk context is open
    let msg = pic
        .submit_call(c, admin, "tick", candid::encode_args(()).unwrap())
        .expect("submit tick");
    pic.tick(); // tick starts executing and sends its self-call; context now open
    pic.tick();
    state("mid-flight (before upgrade)");
    let up = pic.upgrade_eop_canister(c, wasm.clone(), candid::encode_args(()).unwrap(), Some(admin));
    println!("[probe] CASE1 upgrade mid-context result: {up:?}");
    let tick_result = pic.await_call(msg);
    println!(
        "[probe] CASE1 in-flight tick outcome: {}",
        match &tick_result {
            Ok(_) => "REPLIED-OK".to_string(),
            Err(e) => format!("REJECTED: code={:?} msg={}", e.reject_code, e.reject_message),
        }
    );
    for _ in 0..80 {
        pic.tick();
    }
    state("after CASE1 settled");

    // CASE 2: control — upgrade with NO open context must succeed
    let up2 = pic.upgrade_eop_canister(c, wasm, candid::encode_args(()).unwrap(), Some(admin));
    println!("[probe] CASE2 upgrade quiescent result: {up2:?}");
    state("after CASE2");
    println!("[probe] DONE");
}
