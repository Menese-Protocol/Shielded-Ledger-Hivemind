//! Driver for tests/AuditCostProbe.mo — measures the per-note reference-walk cost,
//! sha256-32B cost, and the set-slot/log-index walk costs on PocketIC, and derives the
//! audit chunk sizes (K, S, L) with a committed ≥4× instruction headroom.

use candid::Principal;
use pocket_ic::PocketIcBuilder;
use soak::pic_env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf();
    let out = std::env::temp_dir().join(format!("audit_cost_probe_{}.wasm", std::process::id()));
    let sources_raw = String::from_utf8(
        Command::new("/usr/bin/mops").arg("sources").current_dir(&repo_root).output().expect("mops").stdout,
    )
    .unwrap();
    let source_args: Vec<String> = sources_raw.split_whitespace().map(String::from).collect();
    let status = Command::new("/opt/moc-1.4.1/moc")
        .args(&source_args)
        .arg("-c")
        .arg("tests/AuditCostProbe.mo")
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

    // population: 20k notes (bulk in 2k batches)
    let total: u64 = 20_000;
    for _ in 0..(total / 2_000) {
        let raw = call("bulk_append", candid::encode_args((candid::Nat::from(2_000u64),)).unwrap());
        let (n,): (candid::Nat,) = candid::decode_args(&raw).expect("decode bulk");
        eprintln!("[grow] note_log at {n}");
    }

    // reference per-note walk over 2k notes mid-log
    let raw = call(
        "measure_reference_walk",
        candid::encode_args((candid::Nat::from(9_000u64), candid::Nat::from(2_000u64))).unwrap(),
    );
    let (instr, alloc, heap): (u64, candid::Nat, candid::Int) = candid::decode_args(&raw).expect("decode walk");
    let per_note_instr = instr / 2_000;
    let alloc_u: u128 = alloc.0.clone().try_into().unwrap();
    let per_note_alloc = alloc_u / 2_000;
    println!("[measure] reference walk: 2000 notes -> {instr} instr, {alloc_u} B alloc, heap delta {heap}");
    println!("[measure] per-note: {per_note_instr} instr, {per_note_alloc} B alloc");

    let raw = call("measure_sha256_32", candid::encode_args((candid::Nat::from(10_000u64),)).unwrap());
    let (sha_instr, sha_alloc): (u64, candid::Nat) = candid::decode_args(&raw).expect("decode sha");
    let sha_alloc_u: u128 = sha_alloc.0.clone().try_into().unwrap();
    println!(
        "[measure] sha256-32B: {} instr/hash, {} B alloc/hash",
        sha_instr / 10_000,
        sha_alloc_u / 10_000
    );

    let raw = call("measure_slot_walk", candid::encode_args(()).unwrap());
    let (sw_instr, sw_alloc, cap): (u64, candid::Nat, u64) = candid::decode_args(&raw).expect("decode slots");
    println!(
        "[measure] set slot walk: capacity {cap} -> {sw_instr} instr ({} instr/slot), {} B alloc total",
        sw_instr / cap.max(1),
        sw_alloc.0
    );

    let raw = call("measure_index_walk", candid::encode_args(()).unwrap());
    let (iw_instr, iw_alloc, entries): (u64, candid::Nat, candid::Nat) = candid::decode_args(&raw).expect("decode idx");
    let entries_u: u128 = entries.0.clone().try_into().unwrap();
    println!(
        "[measure] log index walk: {entries_u} entries -> {iw_instr} instr ({} instr/entry), {} B alloc total",
        iw_instr as u128 / entries_u.max(1),
        iw_alloc.0
    );

    // chunk-size derivation: DTS update budget 40B instructions; ≥4x headroom -> 10B per chunk.
    // heap envelope: keep per-chunk allocation under 256 MiB (24x under the 6 GiB wall).
    let budget_instr: u64 = 40_000_000_000 / 4;
    let budget_alloc: u128 = 256 * 1024 * 1024;
    let k_by_instr = budget_instr / per_note_instr.max(1);
    let k_by_alloc = budget_alloc / per_note_alloc.max(1);
    let k = k_by_instr.min(k_by_alloc as u64);
    println!("[derive] K (notes/chunk): min(instr-bound {k_by_instr}, alloc-bound {k_by_alloc}) = {k}");
    println!("[derive] S (slots/chunk): {}", budget_instr / (sw_instr / cap.max(1)).max(1));
    println!(
        "[derive] L (index entries/chunk): {}",
        budget_instr / (iw_instr as u128 / entries_u.max(1)).max(1) as u64
    );
    println!("[probe] DONE");
}
