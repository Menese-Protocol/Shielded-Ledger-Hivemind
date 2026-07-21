//! Driver for tests/FrontierCostProbe.mo — measures the in-canister Poseidon frontier
//! costs on PocketIC (commit the per-append instruction bound BEFORE Main.mo
//! integration) and checks the transfer-shaped step against the message budget with
//! the committed margin.

use candid::Principal;
use pocket_ic::PocketIcBuilder;
use soak::pic_env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf();
    let out = std::env::temp_dir().join(format!("frontier_cost_probe_{}.wasm", std::process::id()));
    let sources_raw = String::from_utf8(
        Command::new("/usr/bin/mops").arg("sources").current_dir(&repo_root).output().expect("mops").stdout,
    )
    .unwrap();
    let source_args: Vec<String> = sources_raw.split_whitespace().map(String::from).collect();
    let status = Command::new("/opt/moc-1.4.1/moc")
        .args(&source_args)
        .arg("-c")
        .arg("tests/FrontierCostProbe.mo")
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
    let admin = Principal::self_authenticating([9u8; 32]);
    let c = pic.create_canister_with_settings(Some(admin), None);
    pic.add_cycles(c, 100_000_000_000_000);
    pic.install_canister(c, wasm, candid::encode_args(()).unwrap(), Some(admin));

    let call = |method: &str, args: Vec<u8>| -> Vec<u8> {
        pic.update_call(c, admin, method, args).unwrap_or_else(|e| panic!("{method}: {e:?}"))
    };

    let perm_iters: u64 = 200;
    let raw = call("measure_perm", candid::encode_args((candid::Nat::from(perm_iters),)).unwrap());
    let (instr, alloc): (u64, candid::Nat) = candid::decode_args(&raw).expect("decode perm");
    let alloc_u: u128 = alloc.0.clone().try_into().unwrap();
    let perm_instr = instr / perm_iters;
    println!("[measure] permutation: {perm_instr} instr, {} B alloc (avg of {perm_iters})", alloc_u / perm_iters as u128);

    let raw = call("measure_perm_core", candid::encode_args((candid::Nat::from(200u64),)).unwrap());
    let (ci, ca): (u64, candid::Nat) = candid::decode_args(&raw).expect("decode perm core");
    let ca_u: u128 = ca.0.clone().try_into().unwrap();
    println!("[measure] permutation CORE (no boundary): {} instr, {} B alloc (avg of 200)", ci / 200, ca_u / 200);

    let raw = call("measure_compress", candid::encode_args((candid::Nat::from(perm_iters),)).unwrap());
    let (instr, alloc): (u64, candid::Nat) = candid::decode_args(&raw).expect("decode compress");
    let alloc_u: u128 = alloc.0.clone().try_into().unwrap();
    let compress_instr = instr / perm_iters;
    println!("[measure] merkle compress: {compress_instr} instr, {} B alloc", alloc_u / perm_iters as u128);

    let raw = call("measure_zero_hashes", candid::encode_args(()).unwrap());
    let (zh_instr, zh_alloc): (u64, candid::Nat) = candid::decode_args(&raw).expect("decode zeros");
    println!("[measure] zeroHashes() one-time init: {zh_instr} instr, {} B alloc", zh_alloc.0);

    let append_count: u64 = 100;
    let raw = call("measure_append", candid::encode_args((candid::Nat::from(append_count),)).unwrap());
    let (instr, alloc, next): (u64, candid::Nat, candid::Nat) = candid::decode_args(&raw).expect("decode append");
    assert_eq!(next, candid::Nat::from(append_count), "append count drift");
    let alloc_u: u128 = alloc.0.clone().try_into().unwrap();
    let append_instr = instr / append_count;
    let append_alloc = alloc_u / append_count as u128;
    println!("[measure] frontier append (32 compresses): {append_instr} instr, {append_alloc} B alloc");

    let raw = call("measure_transfer_step", candid::encode_args(()).unwrap());
    let (ts_instr, ts_alloc): (u64, candid::Nat) = candid::decode_args(&raw).expect("decode transfer step");
    println!(
        "[measure] transfer-shaped step (parse 32-slot wire frontier + 2 appends + emit): {ts_instr} instr, {} B alloc",
        ts_alloc.0
    );

    // Budget check. The ledger's own in-process Groth16 verify measures 12.6B instr in a
    // 40B DTS update budget; the tree step must be noise next to it. Commit: transfer
    // tree step ≤ 1B instructions (≥28x under what verify+step leaves of the budget).
    let committed_bound: u64 = 2_500_000_000;
    println!("[derive] committed bounds: append <= 1.2B instr, transfer tree-step <= 2.5B instr");
    println!(
        "[derive] measured/committed = {:.3}%; verify(12.6B)+step vs 40B budget leaves {:.1}B headroom",
        ts_instr as f64 / committed_bound as f64 * 100.0,
        (40_000_000_000u64 - 12_600_000_000u64 - ts_instr) as f64 / 1e9
    );
    assert!(ts_instr <= committed_bound, "transfer tree step exceeds committed bound");
    assert!(append_instr <= 1_200_000_000, "single append exceeds committed 1.2B bound");
    println!("[probe] DONE — bound holds");
}
