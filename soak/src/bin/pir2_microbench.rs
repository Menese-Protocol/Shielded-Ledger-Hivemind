//! Driver for tests/Pir2MicroBench.mo — measures candidate stripe-matvec inner-loop shapes
//! on PocketIC so the production loop is chosen by data. Prints instr/madd per variant and
//! asserts all variants produce the identical checksum.

use candid::{Nat, Principal};
use pocket_ic::PocketIcBuilder;
use soak::pic_env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf();
    let out = std::env::temp_dir().join(format!("pir2_mb_{}.wasm", std::process::id()));
    let sources_raw = String::from_utf8(
        Command::new("/usr/bin/mops").arg("sources").current_dir(&repo_root).output().expect("mops").stdout,
    )
    .unwrap();
    let source_args: Vec<String> = sources_raw.split_whitespace().map(String::from).collect();
    let status = Command::new("/opt/moc-1.4.1/moc")
        .args(&source_args)
        .arg("-c")
        .arg("tests/Pir2MicroBench.mo")
        .arg("-o")
        .arg(&out)
        .current_dir(&repo_root)
        .status()
        .expect("moc spawn");
    assert!(status.success(), "bench compile failed");
    let wasm = std::fs::read(&out).expect("read wasm");

    let server = pic_env::spawn_server(&pic_env::resolve_pocket_ic_server());
    let pic = PocketIcBuilder::new()
        .with_server_url(server.url.clone())
        .with_application_subnet()
        .with_max_request_time_ms(Some(600_000))
        .build();
    let admin = Principal::self_authenticating([3u8; 32]);
    let c = pic.create_canister_with_settings(Some(admin), None);
    pic.add_cycles(c, 1_000_000_000_000_000);
    pic.install_canister(c, wasm, candid::encode_args(()).unwrap(), Some(admin));
    let update = |method: &str, args: Vec<u8>| -> Vec<u8> {
        pic.update_call(c, admin, method, args).unwrap_or_else(|e| panic!("{method}: {e:?}"))
    };

    let cols: u64 = 96;
    let madds: u64 = cols * 17_280;
    update("setup", candid::encode_args((Nat::from(cols),)).unwrap());
    let mut checksums = Vec::new();
    for v in ["v1", "v2", "v3", "v4", "v5", "v6", "v7"] {
        let raw = update(v, candid::encode_args((Nat::from(cols),)).unwrap());
        let (instr, alloc, checksum): (u64, u64, u64) = candid::decode_args(&raw).unwrap();
        println!(
            "[{v}] {} instr total, {:.1} instr/madd, {} B alloc, checksum {checksum:#x}",
            instr,
            instr as f64 / madds as f64,
            alloc
        );
        checksums.push(checksum);
    }
    assert!(checksums.windows(2).all(|w| w[0] == w[1]), "variant checksums diverged: {checksums:?}");
    println!("[bench] checksums identical across variants; DONE");
}
