//! T1/T2/T3 scale-test driver. Subcommands:
//!   fixture-selftest — prove the ScaleFixture itself has teeth: a generated state
//!                      old-walks to #ok, and every corruption primitive produces its
//!                      exact expected error code through the verbatim old-walk oracle.
//!   t1               — postupgrade cost is flat: fixture states at 1k/20k/200k notes,
//!                      upgraded to the REAL ledger wasm; committed threshold: upgrade
//!                      succeeds at all sizes AND postupgrade instructions/heap at 200k
//!                      ≤ 2× the 1k figures.
//!   t2               — differential: old-walk verdict vs the new audit's final verdict
//!                      on the SAME (possibly corrupted) states — byte-equal codes.
//!   t3               — corruption → audit FAIL → fail-closed guard on every update
//!                      endpoint while queries answer (uses the hook-injected test wasm).
//! t1/t2/t3 are wired in as the fixed wasm lands; fixture-selftest runs against the
//! fixture alone and is the harness gate for building on it.

use candid::Principal;
use pocket_ic::{PocketIc, PocketIcBuilder};
use soak::pic_env;
use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

fn compile(source: &str, out_name: &str) -> Vec<u8> {
    let root = repo_root();
    let out = std::env::temp_dir().join(format!("{out_name}_{}.wasm", std::process::id()));
    let sources_raw = String::from_utf8(
        Command::new("/usr/bin/mops").arg("sources").current_dir(&root).output().expect("mops").stdout,
    )
    .unwrap();
    let source_args: Vec<String> = sources_raw.split_whitespace().map(String::from).collect();
    let status = Command::new("/opt/moc-1.4.1/moc")
        .args(&source_args)
        .arg("-c")
        .arg(source)
        .arg("-o")
        .arg(&out)
        .current_dir(&root)
        .status()
        .expect("moc spawn");
    assert!(status.success(), "compile {source} failed");
    std::fs::read(&out).expect("read wasm")
}

struct Ctx {
    pic: PocketIc,
    admin: Principal,
    canister: Principal,
}

impl Ctx {
    fn new(wasm: Vec<u8>) -> (Self, pic_env::ManagedServer) {
        let server = pic_env::spawn_server(&pic_env::resolve_pocket_ic_server());
        let pic = PocketIcBuilder::new()
            .with_server_url(server.url.clone())
            .with_application_subnet()
            .with_max_request_time_ms(Some(600_000))
            .build();
        let admin = Principal::self_authenticating([11u8; 32]);
        let canister = pic.create_canister_with_settings(Some(admin), None);
        pic.add_cycles(canister, 100_000_000_000_000);
        pic.install_canister(canister, wasm, candid::encode_args(()).unwrap(), Some(admin));
        // the ledger is wasm64/EOP: give it the same 8 GiB limit the soak uses
        pic.update_canister_settings(
            canister,
            Some(admin),
            pocket_ic::CanisterSettings {
                wasm_memory_limit: Some(candid::Nat::from(8u64 * 1024 * 1024 * 1024)),
                ..Default::default()
            },
        )
        .expect("raise wasm_memory_limit");
        (Ctx { pic, admin, canister }, server)
    }

    fn call_raw(&self, method: &str, args: Vec<u8>) -> Vec<u8> {
        self.pic
            .update_call(self.canister, self.admin, method, args)
            .unwrap_or_else(|e| panic!("{method}: {e:?}"))
    }

    fn call0(&self, method: &str) {
        let _ = self.call_raw(method, candid::encode_args(()).unwrap());
    }

    fn bulk_to(&self, target: u64) {
        let page = 2_000u64;
        let mut n = 0u64;
        while n < target {
            let want = page.min(target - n);
            let raw = self.call_raw("bulk_append", candid::encode_args((candid::Nat::from(want),)).unwrap());
            let (total,): (candid::Nat,) = candid::decode_args(&raw).expect("bulk decode");
            n = u64::try_from(total.0).unwrap();
        }
    }

    /// Run the fixture's chunked old walk to completion and return the verdict:
    /// Ok(()) for #ok, Err(code) for #err.
    fn old_walk(&self) -> Result<(), String> {
        self.call0("old_walk_reset");
        loop {
            let raw = self.call_raw("old_walk_range", candid::encode_args((candid::Nat::from(2_000u64),)).unwrap());
            let (done,): (bool,) = candid::decode_args(&raw).expect("range decode");
            if done {
                break;
            }
        }
        let raw = self
            .pic
            .query_call(self.canister, Principal::anonymous(), "old_walk_verdict", candid::encode_args(()).unwrap())
            .expect("verdict query");
        let (verdict,): (soak::candid_types::MotokoResult<()>,) = candid::decode_args(&raw).expect("verdict decode");
        verdict.into_result().map(|_| ())
    }
}

fn expect_code(label: &str, got: Result<(), String>, want: &str) -> bool {
    match &got {
        Err(code) if code == want => {
            println!("  PASS: {label} -> {want}");
            true
        }
        other => {
            println!("  FAIL: {label}: want Err({want}), got {other:?}");
            false
        }
    }
}

fn fixture_selftest() -> bool {
    let fixture_wasm = compile("tests/ScaleFixture.mo", "scale_fixture");
    let mut ok = true;

    // one instance per corruption case: corruption primitives are destructive
    let fresh = |notes: u64| -> (Ctx, pic_env::ManagedServer) {
        let (ctx, server) = Ctx::new(fixture_wasm.clone());
        ctx.call0("configure_fixture");
        let _ = ctx.call_raw(
            "configure_token_fixture",
            candid::encode_args((ctx.canister, ctx.canister)).unwrap(),
        );
        ctx.bulk_to(notes);
        (ctx, server)
    };

    println!("== fixture selftest: valid 1k state old-walks to #ok ==");
    let (ctx, _s1) = fresh(1_000);
    match ctx.old_walk() {
        Ok(()) => println!("  PASS: valid state -> #ok"),
        Err(e) => {
            println!("  FAIL: valid state -> Err({e})");
            ok = false;
        }
    }

    println!("== corruption: note byte, checksum NOT fixed -> note-codec:checksum ==");
    let (ctx, _s2) = fresh(1_000);
    let _ = ctx.call_raw(
        "corrupt_note_byte",
        candid::encode_args((candid::Nat::from(500u64), candid::Nat::from(60u64), false)).unwrap(),
    );
    ok &= expect_code("checksum-stale corrupt", ctx.old_walk(), "note-codec:checksum");

    println!("== corruption: commitment byte, checksum fixed -> phash break at next note ==");
    let (ctx, _s3) = fresh(1_000);
    // payload layout: frame 48 + btype len4+7 + phash tag1(+32) + ver8 + pos8 + commitment...
    // note 500 has a phash (position>0): commitment begins at 48+4+7+1+32+8+8 = 108
    let _ = ctx.call_raw(
        "corrupt_note_byte",
        candid::encode_args((candid::Nat::from(500u64), candid::Nat::from(108u64), true)).unwrap(),
    );
    ok &= expect_code("tamper+fixed-checksum", ctx.old_walk(), "stable-state:phash");

    println!("== corruption: stored phash byte, checksum fixed -> phash at that index ==");
    let (ctx, _s4) = fresh(1_000);
    // phash bytes begin at frame 48 + 4 + 7 + 1 = 60
    let _ = ctx.call_raw(
        "corrupt_note_byte",
        candid::encode_args((candid::Nat::from(500u64), candid::Nat::from(60u64), true)).unwrap(),
    );
    ok &= expect_code("stored-phash tamper", ctx.old_walk(), "stable-state:phash");

    println!("== corruption: tamper a historical-root key -> missing-historical-root ==");
    let (ctx, _s5) = fresh(1_000);
    let raw = ctx.call_raw("nth_root", candid::encode_args((candid::Nat::from(500u64),)).unwrap());
    let (root,): (serde_bytes::ByteBuf,) = candid::decode_args(&raw).expect("root");
    let _ = ctx.call_raw("tamper_set_key", candid::encode_args(("roots", root)).unwrap());
    ok &= expect_code("root-key tamper", ctx.old_walk(), "stable-state:missing-historical-root");

    println!("== corruption: tamper a nullifier key -> missing-nullifier ==");
    let (ctx, _s6) = fresh(1_000);
    // note positions %3 != 0 are transfers; position 500 (500*2=1000th nullifier index)
    let raw = ctx.call_raw("nth_nullifier", candid::encode_args((candid::Nat::from(1_000u64),)).unwrap());
    let (nf,): (serde_bytes::ByteBuf,) = candid::decode_args(&raw).expect("nf");
    let _ = ctx.call_raw("tamper_set_key", candid::encode_args(("nullifiers", nf)).unwrap());
    ok &= expect_code("nullifier-key tamper", ctx.old_walk(), "stable-state:missing-nullifier");

    println!("== corruption: zero a roots slot tag -> roots:stable-set:observed-count ==");
    let (ctx, _s7) = fresh(1_000);
    let raw = ctx.call_raw("nth_root", candid::encode_args((candid::Nat::from(700u64),)).unwrap());
    let (root,): (serde_bytes::ByteBuf,) = candid::decode_args(&raw).expect("root");
    let _ = ctx.call_raw("zero_set_slot_tag", candid::encode_args(("roots", root)).unwrap());
    ok &= expect_code("slot-tag zero", ctx.old_walk(), "roots:stable-set:observed-count");

    println!("== corruption: tree root mismatch -> stable-state:tree-root ==");
    let (ctx, _s8) = fresh(1_000);
    let _ = ctx.call_raw(
        "set_tree_root_hex",
        candid::encode_args(("00".repeat(32),)).unwrap(),
    );
    ok &= expect_code("tree-root mismatch", ctx.old_walk(), "stable-state:tree-root");

    println!("== corruption: tampered last_block_hash -> stable-state:last-block-hash ==");
    let (ctx, _s9) = fresh(1_000);
    let _ = ctx.call_raw(
        "set_last_block_hash",
        candid::encode_args((Some(serde_bytes::ByteBuf::from(vec![0u8; 32])),)).unwrap(),
    );
    ok &= expect_code("last-block-hash tamper", ctx.old_walk(), "stable-state:last-block-hash");

    println!("== NoteAudit parity: fast Checker vs verbatim reference, valid 1k state ==");
    let (ctx, _p1) = fresh(1_000);
    let parity = |ctx: &Ctx, label: &str| -> bool {
        let raw = ctx.call_raw("parity_check", candid::encode_args((candid::Nat::from(1_000u64),)).unwrap());
        let (r,): (soak::candid_types::MotokoResult<(candid::Nat, u64, candid::Nat, u64, candid::Nat)>,) =
            candid::decode_args(&raw).expect("parity decode");
        match r.into_result() {
            Ok((checked, fi, fa, ri, ra)) => {
                let n = u64::try_from(checked.0.clone()).unwrap().max(1);
                let fa: u128 = fa.0.try_into().unwrap();
                let ra: u128 = ra.0.try_into().unwrap();
                println!(
                    "  PASS: {label} ({checked} notes; fast {}/note instr {}B/note alloc vs ref {}/note instr {}B/note alloc)",
                    fi / n,
                    fa / n as u128,
                    ri / n,
                    ra / n as u128
                );
                true
            }
            Err(e) => {
                println!("  FAIL: {label}: {e}");
                false
            }
        }
    };
    ok &= parity(&ctx, "valid-state parity + measurement");

    println!("== NoteAudit parity on corrupted states (fallback verdict identity) ==");
    let (ctx, _p2) = fresh(1_000);
    let _ = ctx.call_raw(
        "corrupt_note_byte",
        candid::encode_args((candid::Nat::from(500u64), candid::Nat::from(60u64), false)).unwrap(),
    );
    ok &= parity(&ctx, "checksum-stale parity");
    let (ctx, _p3) = fresh(1_000);
    let _ = ctx.call_raw(
        "corrupt_note_byte",
        candid::encode_args((candid::Nat::from(500u64), candid::Nat::from(60u64), true)).unwrap(),
    );
    ok &= parity(&ctx, "phash-tamper parity");

    println!("== pending_unshield: valid populates -> #ok; corrupted binding -> binding code ==");
    let (ctx, _s10) = fresh(1_000);
    let _ = ctx.call_raw("populate_pending_unshield", candid::encode_args((false,)).unwrap());
    match ctx.old_walk() {
        Ok(()) => println!("  PASS: valid pending_unshield -> #ok"),
        Err(e) => {
            println!("  FAIL: valid pending_unshield -> Err({e})");
            ok = false;
        }
    }
    let (ctx, _s11) = fresh(1_000);
    let _ = ctx.call_raw("populate_pending_unshield", candid::encode_args((true,)).unwrap());
    ok &= expect_code(
        "corrupt recipient_binding",
        ctx.old_walk(),
        "stable-state:pending-unshield-binding",
    );

    ok
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "fixture-selftest".into());
    let ok = match mode.as_str() {
        "fixture-selftest" => fixture_selftest(),
        other => {
            eprintln!("unknown mode {other} (t1/t2/t3 land with the fixed wasm)");
            false
        }
    };
    if ok {
        println!("SCALE-TESTS {mode}: ALL PASS");
    } else {
        println!("SCALE-TESTS {mode}: FAILURES");
        std::process::exit(1);
    }
}
