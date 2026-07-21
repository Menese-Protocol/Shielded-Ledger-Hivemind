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
    // field order is load-bearing: struct fields drop in DECLARATION order, so the
    // PocketIc instance (which sends a delete request on drop) must precede the
    // ManagedServer (which kills the server child on drop)
    pic: PocketIc,
    _server: pic_env::ManagedServer,
    admin: Principal,
    canister: Principal,
}

impl Ctx {
    fn new(wasm: Vec<u8>) -> Self {
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
        Ctx { pic, _server: server, admin, canister }
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
    let fresh = |notes: u64| -> Ctx {
        let ctx = Ctx::new(fixture_wasm.clone());
        ctx.call0("configure_fixture");
        let _ = ctx.call_raw(
            "configure_token_fixture",
            candid::encode_args((ctx.canister, ctx.canister)).unwrap(),
        );
        ctx.bulk_to(notes);
        ctx
    };

    println!("== fixture selftest: valid 1k state old-walks to #ok ==");
    let ctx = fresh(1_000);
    match ctx.old_walk() {
        Ok(()) => println!("  PASS: valid state -> #ok"),
        Err(e) => {
            println!("  FAIL: valid state -> Err({e})");
            ok = false;
        }
    }

    println!("== corruption: note byte, checksum NOT fixed -> note-codec:checksum ==");
    let ctx = fresh(1_000);
    let _ = ctx.call_raw(
        "corrupt_note_byte",
        candid::encode_args((candid::Nat::from(500u64), candid::Nat::from(60u64), false)).unwrap(),
    );
    ok &= expect_code("checksum-stale corrupt", ctx.old_walk(), "note-codec:checksum");

    println!("== corruption: commitment byte, checksum fixed -> phash break at next note ==");
    let ctx = fresh(1_000);
    // payload layout: frame 48 + btype len4+7 + phash tag1(+32) + ver8 + pos8 + commitment...
    // note 500 has a phash (position>0): commitment begins at 48+4+7+1+32+8+8 = 108
    let _ = ctx.call_raw(
        "corrupt_note_byte",
        candid::encode_args((candid::Nat::from(500u64), candid::Nat::from(108u64), true)).unwrap(),
    );
    ok &= expect_code("tamper+fixed-checksum", ctx.old_walk(), "stable-state:phash");

    println!("== corruption: stored phash byte, checksum fixed -> phash at that index ==");
    let ctx = fresh(1_000);
    // phash bytes begin at frame 48 + 4 + 7 + 1 = 60
    let _ = ctx.call_raw(
        "corrupt_note_byte",
        candid::encode_args((candid::Nat::from(500u64), candid::Nat::from(60u64), true)).unwrap(),
    );
    ok &= expect_code("stored-phash tamper", ctx.old_walk(), "stable-state:phash");

    println!("== corruption: tamper a historical-root key -> missing-historical-root ==");
    let ctx = fresh(1_000);
    let raw = ctx.call_raw("nth_root", candid::encode_args((candid::Nat::from(500u64),)).unwrap());
    let (root,): (serde_bytes::ByteBuf,) = candid::decode_args(&raw).expect("root");
    let _ = ctx.call_raw("tamper_set_key", candid::encode_args(("roots", root)).unwrap());
    ok &= expect_code("root-key tamper", ctx.old_walk(), "stable-state:missing-historical-root");

    println!("== corruption: tamper a nullifier key -> missing-nullifier ==");
    let ctx = fresh(1_000);
    // note positions %3 != 0 are transfers; position 500 (500*2=1000th nullifier index)
    let raw = ctx.call_raw("nth_nullifier", candid::encode_args((candid::Nat::from(1_000u64),)).unwrap());
    let (nf,): (serde_bytes::ByteBuf,) = candid::decode_args(&raw).expect("nf");
    let _ = ctx.call_raw("tamper_set_key", candid::encode_args(("nullifiers", nf)).unwrap());
    ok &= expect_code("nullifier-key tamper", ctx.old_walk(), "stable-state:missing-nullifier");

    println!("== corruption: zero a roots slot tag -> roots:stable-set:observed-count ==");
    let ctx = fresh(1_000);
    let raw = ctx.call_raw("nth_root", candid::encode_args((candid::Nat::from(700u64),)).unwrap());
    let (root,): (serde_bytes::ByteBuf,) = candid::decode_args(&raw).expect("root");
    let _ = ctx.call_raw("zero_set_slot_tag", candid::encode_args(("roots", root)).unwrap());
    ok &= expect_code("slot-tag zero", ctx.old_walk(), "roots:stable-set:observed-count");

    println!("== corruption: tree root mismatch -> stable-state:tree-root ==");
    let ctx = fresh(1_000);
    let _ = ctx.call_raw(
        "set_tree_root_hex",
        candid::encode_args(("00".repeat(32),)).unwrap(),
    );
    ok &= expect_code("tree-root mismatch", ctx.old_walk(), "stable-state:tree-root");

    println!("== corruption: tampered last_block_hash -> stable-state:last-block-hash ==");
    let ctx = fresh(1_000);
    let _ = ctx.call_raw(
        "set_last_block_hash",
        candid::encode_args((Some(serde_bytes::ByteBuf::from(vec![0u8; 32])),)).unwrap(),
    );
    ok &= expect_code("last-block-hash tamper", ctx.old_walk(), "stable-state:last-block-hash");

    println!("== NoteAudit parity: fast Checker vs verbatim reference, valid 1k state ==");
    let ctx = fresh(1_000);
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
    let ctx = fresh(1_000);
    let _ = ctx.call_raw(
        "corrupt_note_byte",
        candid::encode_args((candid::Nat::from(500u64), candid::Nat::from(60u64), false)).unwrap(),
    );
    ok &= parity(&ctx, "checksum-stale parity");
    let ctx = fresh(1_000);
    let _ = ctx.call_raw(
        "corrupt_note_byte",
        candid::encode_args((candid::Nat::from(500u64), candid::Nat::from(60u64), true)).unwrap(),
    );
    ok &= parity(&ctx, "phash-tamper parity");

    println!("== pending_unshield: valid populates -> #ok; corrupted binding -> binding code ==");
    let ctx = fresh(1_000);
    let _ = ctx.call_raw("populate_pending_unshield", candid::encode_args((false,)).unwrap());
    match ctx.old_walk() {
        Ok(()) => println!("  PASS: valid pending_unshield -> #ok"),
        Err(e) => {
            println!("  FAIL: valid pending_unshield -> Err({e})");
            ok = false;
        }
    }
    let ctx = fresh(1_000);
    let _ = ctx.call_raw("populate_pending_unshield", candid::encode_args((true,)).unwrap());
    ok &= expect_code(
        "corrupt recipient_binding",
        ctx.old_walk(),
        "stable-state:pending-unshield-binding",
    );

    ok
}

// ==== T1/T2/T3 shared plumbing ====

use soak::candid_types as ct;

impl Ctx {
    fn upgrade_to(&self, wasm: Vec<u8>) -> Result<(), String> {
        self.pic
            .upgrade_eop_canister(self.canister, wasm, candid::encode_args(()).unwrap(), Some(self.admin))
            .map_err(|e| format!("{:?}", e.reject_message))
    }

    fn audit_status(&self) -> ct::AuditStatus {
        let raw = self
            .pic
            .query_call(self.canister, Principal::anonymous(), "audit_status", candid::encode_args(()).unwrap())
            .expect("audit_status");
        let (s,): (ct::AuditStatus,) = candid::decode_args(&raw).expect("audit_status decode");
        s
    }

    /// Drive rounds until the audit is terminal (hard-bounded like the runner's poll).
    fn poll_audit_terminal(&self) -> ct::AuditStatus {
        let notes = {
            let raw = self
                .pic
                .query_call(self.canister, Principal::anonymous(), "status", candid::encode_args(()).unwrap())
                .expect("status");
            let (s,): (ct::LedgerStatus,) = candid::decode_args(&raw).expect("status decode");
            u64::try_from(s.note_count.0).unwrap()
        };
        let max_ticks = (notes / 4_096 + 16) * 16 + 256;
        for _ in 0..max_ticks {
            let s = self.audit_status();
            if !matches!(s.state, ct::AuditState::running) {
                return s;
            }
            self.pic.advance_time(std::time::Duration::from_secs(1));
            self.pic.tick();
        }
        panic!("audit poll bound exhausted: {:?}", self.audit_status());
    }

    fn postupgrade_stats(&self) -> ct::PostupgradeStats {
        let raw = self
            .pic
            .query_call(self.canister, Principal::anonymous(), "postupgrade_stats", candid::encode_args(()).unwrap())
            .expect("postupgrade_stats");
        let (s,): (ct::PostupgradeStats,) = candid::decode_args(&raw).expect("stats decode");
        s
    }

    fn ledger_status(&self) -> ct::LedgerStatus {
        let raw = self
            .pic
            .query_call(self.canister, Principal::anonymous(), "status", candid::encode_args(()).unwrap())
            .expect("status");
        candid::decode_args::<(ct::LedgerStatus,)>(&raw).expect("status decode").0
    }
}

fn build_fixture_at(fixture_wasm: &[u8], notes: u64) -> Ctx {
    let ctx = Ctx::new(fixture_wasm.to_vec());
    ctx.call0("configure_fixture");
    let _ = ctx.call_raw(
        "configure_token_fixture",
        candid::encode_args((ctx.canister, ctx.canister)).unwrap(),
    );
    ctx.bulk_to(notes);
    ctx
}

// ==== T1 — postupgrade cost is flat (1k / 20k / 200k) ====

fn t1() -> bool {
    let fixture_wasm = compile("tests/ScaleFixture.mo", "scale_fixture");
    let ledger_wasm = compile("src/Main.mo", "zk_ledger_fixed");
    let mut ok = true;
    let mut results: Vec<(u64, u64, u128)> = Vec::new();

    for notes in [1_000u64, 20_000, 200_000] {
        println!("== T1 @ {notes} notes: build fixture state, upgrade to REAL wasm ==");
        let t0 = std::time::Instant::now();
        let ctx = build_fixture_at(&fixture_wasm, notes);
        println!("  [t1] state built in {:.1}s", t0.elapsed().as_secs_f64());
        let raw = ctx.call_raw("fixture_status", candid::encode_args(()).unwrap());
        let (fx_notes, _roots, _nfs, fx_root, _lbh): (candid::Nat, candid::Nat, candid::Nat, serde_bytes::ByteBuf, Option<serde_bytes::ByteBuf>) =
            candid::decode_args(&raw).expect("fixture_status");
        let t1s = std::time::Instant::now();
        match ctx.upgrade_to(ledger_wasm.clone()) {
            Ok(()) => println!("  PASS: upgrade Ok at {notes} notes ({:.1}s)", t1s.elapsed().as_secs_f64()),
            Err(e) => {
                println!("  FAIL: upgrade at {notes} notes: {e}");
                ok = false;
                continue;
            }
        }
        // Proof A: measured postupgrade cost
        let stats = ctx.postupgrade_stats();
        let hb = u128::try_from(stats.heap_before.0.clone()).unwrap();
        let ha = u128::try_from(stats.heap_after.0.clone()).unwrap();
        let heap_delta = ha.saturating_sub(hb);
        println!(
            "  [t1] postupgrade @ {notes} notes: {} instructions, heap delta {}B",
            stats.instructions, heap_delta
        );
        // Proof B: state intact + audit over the whole state completes PASS
        let status = ctx.ledger_status();
        let post_notes = u64::try_from(status.note_count.0.clone()).unwrap();
        let same_state = post_notes == u64::try_from(fx_notes.0.clone()).unwrap()
            && status.note_root.as_slice() == fx_root.as_slice();
        if same_state {
            println!("  PASS: post-upgrade state intact ({post_notes} notes, root preserved)");
        } else {
            println!("  FAIL: post-upgrade state mismatch");
            ok = false;
        }
        let audited = ctx.poll_audit_terminal();
        match audited.state {
            ct::AuditState::pass => println!("  PASS: background audit PASS (epoch {})", audited.audit_epoch),
            other => {
                println!("  FAIL: audit terminal state {other:?}");
                ok = false;
            }
        }
        results.push((notes, stats.instructions, heap_delta));
    }

    // committed threshold: 200k cost <= 2x the 1k cost
    if let (Some(small), Some(large)) = (
        results.iter().find(|r| r.0 == 1_000),
        results.iter().find(|r| r.0 == 200_000),
    ) {
        let instr_ok = large.1 <= small.1 * 2;
        let heap_ok = large.2 <= (small.2 * 2).max(8 * 1024 * 1024); // absolute floor: GC granularity noise on tiny deltas
        println!(
            "  {}: T1 threshold — 200k instr {} vs 2x1k {} | 200k heap {} vs 2x1k {} (8MiB noise floor)",
            if instr_ok && heap_ok { "PASS" } else { "FAIL" },
            large.1,
            small.1 * 2,
            large.2,
            small.2 * 2
        );
        ok &= instr_ok && heap_ok;
    } else {
        ok = false;
    }
    ok
}

// ==== T2 — differential equivalence, old walk vs new audit/postupgrade ====

struct DiffCase {
    label: &'static str,
    corrupt: fn(&Ctx),
    /// audit-detected (Some(expected_index)) or postupgrade-trap (None)
    audit_index: Option<u64>,
}

fn nth_root(ctx: &Ctx, i: u64) -> serde_bytes::ByteBuf {
    let raw = ctx.call_raw("nth_root", candid::encode_args((candid::Nat::from(i),)).unwrap());
    candid::decode_args::<(serde_bytes::ByteBuf,)>(&raw).expect("root").0
}

fn nth_nullifier(ctx: &Ctx, i: u64) -> serde_bytes::ByteBuf {
    let raw = ctx.call_raw("nth_nullifier", candid::encode_args((candid::Nat::from(i),)).unwrap());
    candid::decode_args::<(serde_bytes::ByteBuf,)>(&raw).expect("nf").0
}

fn t2() -> bool {
    let fixture_wasm = compile("tests/ScaleFixture.mo", "scale_fixture");
    let ledger_wasm = compile("src/Main.mo", "zk_ledger_fixed");
    let mut ok = true;

    let cases: Vec<DiffCase> = vec![
        DiffCase { label: "valid", corrupt: |_ctx| {}, audit_index: None },
        DiffCase {
            label: "note-checksum-stale",
            corrupt: |ctx| {
                let _ = ctx.call_raw("corrupt_note_byte", candid::encode_args((candid::Nat::from(500u64), candid::Nat::from(60u64), false)).unwrap());
            },
            audit_index: Some(500),
        },
        DiffCase {
            label: "note-tamper-fixed-checksum",
            corrupt: |ctx| {
                let _ = ctx.call_raw("corrupt_note_byte", candid::encode_args((candid::Nat::from(500u64), candid::Nat::from(108u64), true)).unwrap());
            },
            audit_index: Some(501),
        },
        DiffCase {
            label: "stored-phash-tamper",
            corrupt: |ctx| {
                let _ = ctx.call_raw("corrupt_note_byte", candid::encode_args((candid::Nat::from(500u64), candid::Nat::from(60u64), true)).unwrap());
            },
            audit_index: Some(500),
        },
        DiffCase {
            label: "missing-historical-root",
            corrupt: |ctx| {
                let root = nth_root(ctx, 500);
                let _ = ctx.call_raw("tamper_set_key", candid::encode_args(("roots", root)).unwrap());
            },
            audit_index: Some(500),
        },
        DiffCase {
            label: "missing-nullifier",
            corrupt: |ctx| {
                let nf = nth_nullifier(ctx, 1_000);
                let _ = ctx.call_raw("tamper_set_key", candid::encode_args(("nullifiers", nf)).unwrap());
            },
            audit_index: Some(500),
        },
        DiffCase {
            label: "set-slot-tag-zero",
            corrupt: |ctx| {
                let root = nth_root(ctx, 700);
                let _ = ctx.call_raw("zero_set_slot_tag", candid::encode_args(("roots", root)).unwrap());
            },
            audit_index: Some(u64::MAX), // set phase: code compared, index not note-indexed
        },
        DiffCase {
            label: "tree-root-mismatch",
            corrupt: |ctx| {
                let _ = ctx.call_raw("set_tree_root_hex", candid::encode_args(("00".repeat(32),)).unwrap());
            },
            audit_index: None, // postupgrade-trap case
        },
        DiffCase {
            label: "tampered-last-block-hash",
            corrupt: |ctx| {
                let _ = ctx.call_raw("set_last_block_hash", candid::encode_args((Some(serde_bytes::ByteBuf::from(vec![0u8; 32])),)).unwrap());
            },
            audit_index: None,
        },
        DiffCase {
            label: "pending-unshield-binding",
            corrupt: |ctx| {
                let _ = ctx.call_raw("populate_pending_unshield", candid::encode_args((true,)).unwrap());
            },
            audit_index: None, // pendings are O(1) postupgrade checks
        },
    ];

    for (sizes, case_filter) in [
        (1_000u64, None::<&[&str]>),
        (20_000, Some(&["valid", "note-tamper-fixed-checksum", "missing-historical-root"][..])),
    ] {
        for case in &cases {
            if let Some(filter) = case_filter {
                if !filter.contains(&case.label) {
                    continue;
                }
            }
            println!("== T2 @ {sizes} notes: {} ==", case.label);
            let ctx = build_fixture_at(&fixture_wasm, sizes);
            (case.corrupt)(&ctx);
            // OLD verdict: verbatim chunked walk on the SAME state
            let old = ctx.old_walk();
            // NEW verdict: upgrade to the fixed wasm; postupgrade + audit decide
            match ctx.upgrade_to(ledger_wasm.clone()) {
                Ok(()) => {
                    let audited = ctx.poll_audit_terminal();
                    match (&old, &audited.state) {
                        (Ok(()), ct::AuditState::pass) => {
                            println!("  PASS: both verdicts #ok/PASS");
                        }
                        (Err(code), ct::AuditState::fail { code: new_code, index }) => {
                            let code_match = code == new_code;
                            let index_match = match case.audit_index {
                                Some(u64::MAX) | None => true,
                                Some(want) => u64::try_from(index.0.clone()).unwrap() == want,
                            };
                            if code_match && index_match {
                                println!("  PASS: verdicts match — {code} (audit index {index})");
                            } else {
                                println!("  FAIL: old {code} vs new {new_code} at {index} (want index {:?})", case.audit_index);
                                ok = false;
                            }
                        }
                        (o, n) => {
                            println!("  FAIL: verdict divergence — old {o:?} vs audit {n:?}");
                            ok = false;
                        }
                    }
                }
                Err(reject) => {
                    // postupgrade-trap path: the reject must carry the OLD walk's code
                    match &old {
                        Err(code) if reject.contains(&format!("postupgrade:{code}")) => {
                            println!("  PASS: postupgrade trap carries the old code {code}");
                        }
                        other => {
                            println!("  FAIL: upgrade rejected '{reject}' but old verdict {other:?}");
                            ok = false;
                        }
                    }
                }
            }
        }
    }
    ok
}

// ==== T3 — corruption -> audit FAIL -> fail-closed guard on every endpoint ====

fn dummy_output() -> ct::OutputRecord {
    ct::OutputRecord {
        commitment: ct::blob(vec![0u8; 32]),
        ephemeral_key: ct::blob(vec![1u8; 16]),
        note_ciphertext: ct::blob(vec![1u8; 112]),
    }
}

fn t3() -> bool {
    let fixture_wasm = compile("tests/ScaleFixture.mo", "scale_fixture");
    let root = repo_root();
    // hook-injected test build of the REAL ledger (additive-only, never shipped)
    let test_wasm_path = std::env::temp_dir().join(format!("zk_ledger_test_{}.wasm", std::process::id()));
    let status = Command::new("bash")
        .arg("scripts/build-test-wasm.sh")
        .arg("scripts/test-hooks.frag.mo")
        .arg(&test_wasm_path)
        .current_dir(&root)
        .status()
        .expect("build-test-wasm");
    assert!(status.success(), "test wasm build failed");
    let test_wasm = std::fs::read(&test_wasm_path).expect("read test wasm");
    let mut ok = true;

    type Corrupt = fn(&Ctx);
    let cases: Vec<(&str, Corrupt, &str)> = vec![
        ("note-blob", (|ctx: &Ctx| {
            let _ = ctx.call_raw("test_corrupt_note_byte", candid::encode_args((candid::Nat::from(500u64), candid::Nat::from(60u64), false)).unwrap());
        }) as Corrupt, "note-codec:checksum"),
        ("phash-chain", |ctx: &Ctx| {
            let _ = ctx.call_raw("test_corrupt_note_byte", candid::encode_args((candid::Nat::from(500u64), candid::Nat::from(60u64), true)).unwrap());
        }, "stable-state:phash"),
        ("missing-historical-root", |ctx: &Ctx| {
            let raw = ctx.call_raw("test_nth_note_root", candid::encode_args((candid::Nat::from(500u64),)).unwrap());
            let (root,): (serde_bytes::ByteBuf,) = candid::decode_args(&raw).expect("root");
            let _ = ctx.call_raw("test_tamper_set_key", candid::encode_args(("roots", root)).unwrap());
        }, "stable-state:missing-historical-root"),
        ("missing-nullifier", |ctx: &Ctx| {
            let raw = ctx.call_raw("test_nth_note_nullifier", candid::encode_args((candid::Nat::from(500u64),)).unwrap());
            let (nf,): (serde_bytes::ByteBuf,) = candid::decode_args(&raw).expect("nf");
            let _ = ctx.call_raw("test_tamper_set_key", candid::encode_args(("nullifiers", nf)).unwrap());
        }, "stable-state:missing-nullifier"),
        ("tree-root-mismatch", |ctx: &Ctx| {
            let _ = ctx.call_raw("test_set_tree_root_hex", candid::encode_args(("00".repeat(32),)).unwrap());
        }, "stable-state:tree-root"),
        ("tampered-last-block-hash", |ctx: &Ctx| {
            let _ = ctx.call_raw("test_set_last_block_hash", candid::encode_args((Some(serde_bytes::ByteBuf::from(vec![0u8; 32])),)).unwrap());
        }, "stable-state:last-block-hash"),
    ];

    for (label, corrupt, want_code) in &cases {
        println!("== T3: {label} -> audit FAIL({want_code}) -> guard ==");
        let ctx = build_fixture_at(&fixture_wasm, 1_000);
        if let Err(e) = ctx.upgrade_to(test_wasm.clone()) {
            println!("  FAIL: upgrade to test wasm: {e}");
            ok = false;
            continue;
        }
        // clean state first: audit must PASS
        let first = ctx.poll_audit_terminal();
        if !matches!(first.state, ct::AuditState::pass) {
            println!("  FAIL: pre-corruption audit not PASS: {:?}", first.state);
            ok = false;
            continue;
        }
        // corrupt the RUNNING instance, then re-run the audit (admin restart)
        corrupt(&ctx);
        let raw = ctx.call_raw("restart_audit", candid::encode_args(()).unwrap());
        let (r,): (ct::MotokoResult<candid::Reserved>,) = candid::decode_args(&raw).expect("restart decode");
        r.into_result().expect("restart_audit");
        let audited = ctx.poll_audit_terminal();
        // Proof A: the audit_status FAIL record with the right code
        match &audited.state {
            ct::AuditState::fail { code, index } if code == want_code => {
                println!("  PASS (proof A): audit FAIL {code} at index {index}; guard '{}'", audited.guard.clone().unwrap_or_default());
            }
            other => {
                println!("  FAIL: audit state {other:?}, want fail({want_code})");
                ok = false;
                continue;
            }
        }
        // Proof B: every mutating endpoint rejects GUARDED:… while queries answer
        let guard_prefix = format!("GUARDED:stable-state-audit-failed:{want_code}");
        let mut endpoints_ok = true;

        // Result<..>-returning endpoints
        let expect_guarded_result = |method: &str, args: Vec<u8>| -> bool {
            let raw = ctx.call_raw(method, args);
            match candid::decode_one::<ct::MotokoResult<candid::Reserved>>(&raw) {
                Ok(r) => match r.into_result() {
                    Err(e) if e == guard_prefix => true,
                    other => {
                        println!("  FAIL: {method} while guarded: {other:?}");
                        false
                    }
                },
                Err(e) => {
                    println!("  FAIL: {method} decode: {e}");
                    false
                }
            }
        };
        endpoints_ok &= expect_guarded_result(
            "configure",
            candid::encode_args((ctx.canister, ctx.canister, "aa", "aa")).unwrap(),
        );
        endpoints_ok &= expect_guarded_result(
            "rotate_verifying_keys_v2",
            candid::encode_args(("aa", "aa", "bb", "bb")).unwrap(),
        );
        endpoints_ok &= expect_guarded_result(
            "configure_token_ledger",
            candid::encode_args((ctx.canister, ctx.canister, Option::<ct::Blob>::None)).unwrap(),
        );
        endpoints_ok &= expect_guarded_result("test_arm_fail_after_token_once", candid::encode_args(()).unwrap());

        // MutationResult-returning endpoints
        let expect_guarded_mutation = |method: &str, args: Vec<u8>| -> bool {
            let raw = ctx.call_raw(method, args);
            match candid::decode_one::<ct::MutationResult>(&raw) {
                Ok(m) if m.outcome == guard_prefix && m.verifier_outcome == "NOT_CALLED" => true,
                Ok(m) => {
                    println!("  FAIL: {method} while guarded: outcome {} / {}", m.outcome, m.verifier_outcome);
                    false
                }
                Err(e) => {
                    println!("  FAIL: {method} decode: {e}");
                    false
                }
            }
        };
        endpoints_ok &= expect_guarded_mutation(
            "shield",
            candid::encode_args((ct::DepositArgs {
                value: 1,
                from_subaccount: None,
                created_at_time: 1,
                client_nonce: ct::blob(vec![0u8; 32]),
                commitment: ct::blob(vec![0u8; 32]),
                ephemeral_key: ct::blob(vec![1u8; 16]),
                note_ciphertext: ct::blob(vec![1u8; 112]),
                proof_hex: "00".into(),
            },))
            .unwrap(),
        );
        endpoints_ok &= expect_guarded_mutation("resume_shield", candid::encode_args(()).unwrap());
        endpoints_ok &= expect_guarded_mutation("resume_unshield", candid::encode_args(()).unwrap());
        endpoints_ok &= expect_guarded_mutation(
            "confidential_transfer",
            candid::encode_args((ct::TransferArgs {
                anchor: ct::blob(vec![0u8; 32]),
                nullifier_1: ct::blob(vec![1u8; 32]),
                nullifier_2: ct::blob(vec![2u8; 32]),
                output_1: dummy_output(),
                output_2: dummy_output(),
                fee: 0,
                v_pub_out: 0,
                recipient: None,
                created_at_time: None,
                proof_hex: "00".into(),
            },))
            .unwrap(),
        );

        // read surfaces stay up
        let status = ctx.ledger_status();
        let blocks_raw = ctx
            .pic
            .query_call(
                ctx.canister,
                Principal::anonymous(),
                "icrc3_get_blocks",
                candid::encode_args((vec![ct::GetBlocksArgs { start: candid::Nat::from(0u64), length: candid::Nat::from(1u64) }],)).unwrap(),
            )
            .expect("icrc3_get_blocks while guarded");
        let (blocks,): (ct::GetBlocksResult,) = candid::decode_args(&blocks_raw).expect("blocks decode");
        let reads_ok = u64::try_from(status.note_count.0.clone()).unwrap() == 1_000 && blocks.blocks.len() == 1;

        // guard clear requires a NEWER GREEN audit: with corruption still present it must reject
        let raw = ctx.call_raw("clear_audit_guard", candid::encode_args(()).unwrap());
        let (r,): (ct::MotokoResult<candid::Reserved>,) = candid::decode_args(&raw).expect("clear decode");
        let clear_rejected = matches!(r.into_result(), Err(e) if e == "REJECT:guard-requires-green-reaudit");

        if endpoints_ok && reads_ok && clear_rejected {
            println!("  PASS (proof B): 8/8 endpoints GUARDED, queries answering, premature clear rejected");
        } else {
            println!("  FAIL (proof B): endpoints_ok={endpoints_ok} reads_ok={reads_ok} clear_rejected={clear_rejected}");
            ok = false;
        }
    }

    // recovery drill: un-corrupt -> restart_audit -> PASS -> clear_audit_guard -> endpoint unblocked
    println!("== T3 recovery: un-corrupt, green re-audit, guard clear ==");
    let ctx = build_fixture_at(&fixture_wasm, 1_000);
    ctx.upgrade_to(test_wasm.clone()).expect("upgrade to test wasm");
    let first = ctx.poll_audit_terminal();
    assert!(matches!(first.state, ct::AuditState::pass), "clean audit");
    let good_root_hex = {
        let s = ctx.ledger_status();
        s.tree_state.expect("tree state").root
    };
    let _ = ctx.call_raw("test_set_tree_root_hex", candid::encode_args(("00".repeat(32),)).unwrap());
    let raw = ctx.call_raw("restart_audit", candid::encode_args(()).unwrap());
    candid::decode_one::<ct::MotokoResult<candid::Reserved>>(&raw).unwrap().into_result().expect("restart");
    let failed = ctx.poll_audit_terminal();
    assert!(matches!(failed.state, ct::AuditState::fail { .. }), "audit must fail");
    // un-corrupt, re-audit green, clear
    let _ = ctx.call_raw("test_set_tree_root_hex", candid::encode_args((good_root_hex,)).unwrap());
    let raw = ctx.call_raw("restart_audit", candid::encode_args(()).unwrap());
    candid::decode_one::<ct::MotokoResult<candid::Reserved>>(&raw).unwrap().into_result().expect("restart 2");
    let green = ctx.poll_audit_terminal();
    let green_ok = matches!(green.state, ct::AuditState::pass);
    let raw = ctx.call_raw("clear_audit_guard", candid::encode_args(()).unwrap());
    let clear_ok = candid::decode_one::<ct::MotokoResult<candid::Reserved>>(&raw).unwrap().into_result().is_ok();
    // an update endpoint now answers its NORMAL rejection, not GUARDED
    let raw = ctx.call_raw("configure", candid::encode_args((ctx.canister, ctx.canister, "aa", "aa")).unwrap());
    let unblocked = matches!(
        candid::decode_one::<ct::MotokoResult<candid::Reserved>>(&raw).unwrap().into_result(),
        Err(e) if e == "REJECT:already-configured"
    );
    if green_ok && clear_ok && unblocked {
        println!("  PASS: green re-audit -> guard cleared -> endpoints unblocked");
    } else {
        println!("  FAIL: green={green_ok} clear={clear_ok} unblocked={unblocked}");
        ok = false;
    }
    ok
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "fixture-selftest".into());
    let ok = match mode.as_str() {
        "fixture-selftest" => fixture_selftest(),
        "t1" => t1(),
        "t2" => t2(),
        "t3" => t3(),
        other => {
            eprintln!("unknown mode {other} (fixture-selftest | t1 | t2 | t3)");
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
