//! Birthday-directory upgrade probe — REAL DemoDirectory canister, old→new upgrade on PocketIC.
//!
//! The node battery proves the birthday surface against a byte-mirrored MockDirectory; this
//! probe closes the loop on the REAL canister:
//!   1. compile the OLD DemoDirectory.mo (pinned pre-implementation commit) and the NEW one
//!      with the production toolchain (moc + mops sources);
//!   2. install OLD, register two principals;
//!   3. UPGRADE to NEW — pre-upgrade entries must survive (stable map preserved);
//!   4. exercise the new endpoints on-chain: caller-keyed set/get, registration-required,
//!      anonymous rejection, exact-113-byte guard, cross-principal isolation;
//!   5. upgrade NEW→NEW again — the birthdays map itself must survive an upgrade.
//!
//! Same construction as probe_readpath_cost.rs. Exits non-zero on any violated assertion.

use candid::{CandidType, Principal};
use pocket_ic::PocketIcBuilder;
use serde::Deserialize;
use soak::pic_env;
use std::path::PathBuf;
use std::process::Command;

#[derive(CandidType, Deserialize, Debug)]
enum DirResult {
    #[serde(rename = "ok")]
    Ok,
    #[serde(rename = "err")]
    Err(String),
}

#[derive(CandidType, Deserialize, Debug, PartialEq)]
struct Entry {
    shielded_pk: String,
    enc_pk: String,
}

fn compile(moc: &str, cwd: &std::path::Path, source_args: &[String], src: &std::path::Path, out: &std::path::Path) -> Vec<u8> {
    let status = Command::new(moc)
        .args(source_args)
        .arg("-c")
        .arg(src)
        .arg("-o")
        .arg(out)
        .current_dir(cwd) // mops emits repo-relative package paths
        .status()
        .expect("moc spawn");
    assert!(status.success(), "compile failed: {}", src.display());
    std::fs::read(out).expect("read wasm")
}

fn main() {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf();
    let moc = std::env::var("SOAK_MOC").unwrap_or_else(|_| "/opt/moc-1.4.1/moc".into());
    let sources_raw = String::from_utf8(
        Command::new("/usr/bin/mops").arg("sources").current_dir(&repo_root).output().expect("mops").stdout,
    )
    .unwrap();
    let source_args: Vec<String> = sources_raw.split_whitespace().map(String::from).collect();

    // OLD = the pinned pre-implementation revision (last commit before the birthday endpoints).
    const OLD_COMMIT: &str = "eb3d276";
    let old_src_text = String::from_utf8(
        Command::new("git")
            .args(["show", &format!("{OLD_COMMIT}:tests/DemoDirectory.mo")])
            .current_dir(&repo_root)
            .output()
            .expect("git show")
            .stdout,
    )
    .unwrap();
    assert!(!old_src_text.contains("set_birthday"), "OLD source unexpectedly has the new endpoint");
    let tmp = std::env::temp_dir().join(format!("bday_probe_{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let old_mo = tmp.join("OldDemoDirectory.mo");
    std::fs::write(&old_mo, &old_src_text).unwrap();
    let old_wasm = compile(&moc, &repo_root, &source_args, &old_mo, &tmp.join("old.wasm"));
    let new_wasm = compile(&moc, &repo_root, &source_args, &repo_root.join("tests/DemoDirectory.mo"), &tmp.join("new.wasm"));

    let server = pic_env::spawn_server(&pic_env::resolve_pocket_ic_server());
    let pic = PocketIcBuilder::new()
        .with_server_url(server.url.clone())
        .with_application_subnet()
        .with_max_request_time_ms(Some(600_000))
        .build();
    let admin = Principal::self_authenticating([9u8; 32]);
    let alice = Principal::self_authenticating([1u8; 32]);
    let bob = Principal::self_authenticating([2u8; 32]);
    let carol_unregistered = Principal::self_authenticating([3u8; 32]);
    let c = pic.create_canister_with_settings(Some(admin), None);
    pic.add_cycles(c, 100_000_000_000_000);
    pic.install_canister(c, old_wasm, candid::encode_args(()).unwrap(), Some(admin));

    let call = |sender: Principal, method: &str, args: Vec<u8>| -> Vec<u8> {
        pic.update_call(c, sender, method, args).unwrap_or_else(|e| panic!("{method}: {e:?}"))
    };
    let register = |sender: Principal, pk: &str| -> DirResult {
        let raw = call(sender, "register", candid::encode_args((pk.to_string(), "aa".to_string())).unwrap());
        candid::decode_one(&raw).expect("decode register")
    };
    let lookup = |p: Principal| -> Option<Entry> {
        let raw = pic.query_call(c, admin, "lookup", candid::encode_one(p).unwrap()).expect("lookup");
        candid::decode_one(&raw).expect("decode lookup")
    };
    let set_birthday = |sender: Principal, ct: &[u8]| -> DirResult {
        let raw = call(sender, "set_birthday", candid::encode_one(serde_bytes::ByteBuf::from(ct.to_vec())).unwrap());
        candid::decode_one(&raw).expect("decode set_birthday")
    };
    let get_birthday = |sender: Principal| -> Option<serde_bytes::ByteBuf> {
        let raw = call(sender, "get_birthday", candid::encode_args(()).unwrap());
        candid::decode_one(&raw).expect("decode get_birthday")
    };

    // -- pre-upgrade state on the OLD canister --
    assert!(matches!(register(alice, "pk-alice"), DirResult::Ok), "alice register");
    assert!(matches!(register(bob, "pk-bob"), DirResult::Ok), "bob register");
    assert_eq!(lookup(alice).expect("alice entry").shielded_pk, "pk-alice");

    // -- upgrade OLD → NEW: entries must survive --
    pic.upgrade_eop_canister(c, new_wasm.clone(), candid::encode_args(()).unwrap(), Some(admin))
        .expect("old->new upgrade");
    assert_eq!(lookup(alice).expect("alice survives upgrade").shielded_pk, "pk-alice", "STATE LOST in old->new upgrade");
    assert_eq!(lookup(bob).expect("bob survives upgrade").shielded_pk, "pk-bob");

    // -- new endpoints, on-chain guards --
    let ct_alice = [7u8; 113];
    let ct_bob = [8u8; 113];
    assert!(matches!(set_birthday(alice, &ct_alice), DirResult::Ok), "alice set_birthday");
    assert!(matches!(set_birthday(bob, &ct_bob), DirResult::Ok), "bob set_birthday");
    match set_birthday(carol_unregistered, &ct_alice) {
        DirResult::Err(e) => assert_eq!(e, "not-registered"),
        other => panic!("unregistered set_birthday accepted: {other:?}"),
    }
    match set_birthday(Principal::anonymous(), &ct_alice) {
        DirResult::Err(e) => assert_eq!(e, "anonymous-caller"),
        other => panic!("anonymous set_birthday accepted: {other:?}"),
    }
    for bad in [112usize, 114, 0] {
        match set_birthday(alice, &vec![1u8; bad]) {
            DirResult::Err(e) => assert_eq!(e, "bad-birthday-ct-size", "size {bad}"),
            other => panic!("bad size {bad} accepted: {other:?}"),
        }
    }
    // caller-keyed isolation: each principal reads ONLY its own record
    assert_eq!(get_birthday(alice).expect("alice ct").as_ref(), &ct_alice, "alice reads own");
    assert_eq!(get_birthday(bob).expect("bob ct").as_ref(), &ct_bob, "bob reads own, not alice's");
    assert!(get_birthday(carol_unregistered).is_none(), "unregistered has no record");
    assert!(get_birthday(Principal::anonymous()).is_none(), "anonymous gets nothing");

    // -- upgrade NEW → NEW: the birthdays map itself must survive --
    pic.upgrade_eop_canister(c, new_wasm, candid::encode_args(()).unwrap(), Some(admin))
        .expect("new->new upgrade");
    assert_eq!(get_birthday(alice).expect("alice ct post-upgrade").as_ref(), &ct_alice, "BIRTHDAY STATE LOST in upgrade");
    assert_eq!(lookup(alice).expect("alice entry post-upgrade").shielded_pk, "pk-alice");

    println!("PROBE-BIRTHDAY-DIRECTORY: ALL ASSERTIONS PASSED");
    println!("  old->new upgrade: entries preserved; new->new upgrade: birthdays preserved");
    println!("  guards on-chain: not-registered / anonymous-caller / bad-birthday-ct-size (112,114,0)");
    println!("  caller-keyed isolation: own-record-only reads verified for 2 principals");
}
