//! Driver for tests/ReadPathProbe.mo — read-path A0 + detection-stream cost probe on PocketIC.
//!
//! Measures, on a realistic FRONTEND-shaped note population:
//!   * A0: exact `icrc3_get_blocks` wire bytes per note (shield shape vs transfer shape),
//!     via the marginal candid response length of `note_blocks_range`.
//!   * P3: the `detection_stream` per-note instruction + allocation cost (block decode +
//!     per-note SHA-256 checksum + note_ciphertext[0..40] slice), and the committed
//!     per-message instruction bound with >=4x headroom.
//!   * P3 wire: the packed `detection_stream` payload bytes per note (confirm <= 48).
//!
//! Same construction as probe_audit_cost.rs: compile the probe with moc + `mops sources`,
//! install on a fresh application-subnet PocketIC, drive it, print the numbers.

use candid::Principal;
use pocket_ic::PocketIcBuilder;
use soak::pic_env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf();
    let out = std::env::temp_dir().join(format!("readpath_probe_{}.wasm", std::process::id()));
    let sources_raw = String::from_utf8(
        Command::new("/usr/bin/mops").arg("sources").current_dir(&repo_root).output().expect("mops").stdout,
    )
    .unwrap();
    let source_args: Vec<String> = sources_raw.split_whitespace().map(String::from).collect();
    let status = Command::new("/opt/moc-1.4.1/moc")
        .args(&source_args)
        .arg("-c")
        .arg("tests/ReadPathProbe.mo")
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

    let update = |method: &str, args: Vec<u8>| -> Vec<u8> {
        pic.update_call(c, admin, method, args).unwrap_or_else(|e| panic!("{method}: {e:?}"))
    };
    let query = |method: &str, args: Vec<u8>| -> Vec<u8> {
        pic.query_call(c, admin, method, args).unwrap_or_else(|e| panic!("{method}: {e:?}"))
    };

    // Population: shield region [0, 4000), transfer region [4000, 8000). Bulk in 2k batches
    // so each StableLog grow stays inside one message.
    let shield_total: u64 = 4_000;
    let transfer_total: u64 = 4_000;
    let mut appended: u64 = 0;
    for _ in 0..(shield_total / 2_000) {
        let raw = update("bulk_append", candid::encode_args((candid::Nat::from(2_000u64), candid::Nat::from(0u64))).unwrap());
        let (n,): (candid::Nat,) = candid::decode_args(&raw).expect("decode bulk");
        appended = n.0.clone().try_into().unwrap();
    }
    for _ in 0..(transfer_total / 2_000) {
        let raw = update("bulk_append", candid::encode_args((candid::Nat::from(0u64), candid::Nat::from(2_000u64))).unwrap());
        let (n,): (candid::Nat,) = candid::decode_args(&raw).expect("decode bulk");
        appended = n.0.clone().try_into().unwrap();
    }
    println!("[pop] note_log at {appended} (shield [0,{shield_total}), transfer [{shield_total},{})", shield_total + transfer_total);

    // A0: marginal wire bytes/note = (len(range of W) - len(range of 1)) / (W-1), removing the
    // fixed candid response framing. Measured separately in the shield and transfer regions.
    let wire_marginal = |from: u64, w: u64| -> f64 {
        let l1 = query("note_blocks_range", candid::encode_args((candid::Nat::from(from), candid::Nat::from(1u64))).unwrap()).len();
        let lw = query("note_blocks_range", candid::encode_args((candid::Nat::from(from), candid::Nat::from(w))).unwrap()).len();
        (lw as f64 - l1 as f64) / (w as f64 - 1.0)
    };
    let shield_bpn = wire_marginal(500, 500);
    let transfer_bpn = wire_marginal(4_500, 500);
    println!("[A0] icrc3_get_blocks wire bytes/note: shield {shield_bpn:.1} B, transfer {transfer_bpn:.1} B");

    // P3 wire: packed detection_stream bytes/note (confirm <= 48).
    let ds_marginal = |from: u64, w: u64| -> f64 {
        let l1 = query("detection_stream_bytes", candid::encode_args((candid::Nat::from(from), candid::Nat::from(1u64))).unwrap()).len();
        let lw = query("detection_stream_bytes", candid::encode_args((candid::Nat::from(from), candid::Nat::from(w))).unwrap()).len();
        (lw as f64 - l1 as f64) / (w as f64 - 1.0)
    };
    let ds_bpn = ds_marginal(500, 500);
    println!("[P3-wire] detection_stream bytes/note: {ds_bpn:.2} B (target <= 48)");
    let ratio = shield_bpn / ds_bpn.max(1.0);
    println!("[P3-wire] bandwidth win vs full shield block: {ratio:.1}x");

    // P3 instr: detection_stream core cost per note (decode + sha256 checksum + slice), mid-log.
    let raw = update(
        "measure_detection_slice",
        candid::encode_args((candid::Nat::from(2_000u64), candid::Nat::from(2_000u64))).unwrap(),
    );
    let (instr, alloc, heap): (u64, candid::Nat, candid::Int) = candid::decode_args(&raw).expect("decode slice");
    let per_note_instr = instr / 2_000;
    let alloc_u: u128 = alloc.0.clone().try_into().unwrap();
    let per_note_alloc = alloc_u / 2_000;
    println!("[P3-instr] detection_stream: 2000 notes -> {instr} instr, {alloc_u} B alloc, heap delta {heap}");
    println!("[P3-instr] per-note: {per_note_instr} instr, {per_note_alloc} B alloc");

    // Committed per-message bound: query budget is ~5e9 instructions; with >=4x headroom the
    // per-message serve count and the instruction ceiling follow from the measured per-note cost.
    let query_budget: u64 = 5_000_000_000;
    let headroom = 4u64;
    let max_notes_per_msg = query_budget / headroom / per_note_instr.max(1);
    let committed_bound = per_note_instr * 512; // detection_stream caps at 512 notes/call (mirrors icrc3)
    println!(
        "[P3-derive] per-note {per_note_instr} instr -> {max_notes_per_msg} notes fit under {query_budget}/{headroom}x; \
         512-note call = {committed_bound} instr ({:.1}x under budget)",
        query_budget as f64 / committed_bound.max(1) as f64
    );
    let _ = query("drain_sink", candid::encode_args(()).unwrap());
    println!("[probe] DONE");
}
