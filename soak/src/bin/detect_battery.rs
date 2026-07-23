//! detect battery — AC-2 acceptance harness for the certified detect-chain anchor's
//! persistence story: audit coverage with teeth, rebuild-from-log recovery, and the
//! upgrade drill with a POPULATED chain.
//!
//! Corpus: a real ledger (HOOK wasm — scripts/build-test-wasm.sh, additive-only diff
//! proven at build time; the shipped wasm never contains the hooks) driven past one
//! DPAGE (4,096-note) boundary with real Groth16 ops, detect chain enabled at genesis.
//!
//! Phases (each with its committed expectation):
//!   P0  baseline: anchor == independent Rust recompute over the served
//!       detection_stream; background audit PASS (proves the detector is not
//!       always-red before the teeth run).
//!   P1  TEETH ×5: corrupt chain tip / cached root / covered counter / note counter /
//!       boundary leaf 0 via the hook — each restarted audit must FAIL with EXACTLY its
//!       detect-chain:* code and trip the sticky guard; then detect_chain_rebuild +
//!       restart_audit must recover to a byte-identical anchor, green audit, cleared
//!       guard. 5/5 classes, exact codes, zero tolerance.
//!   P2  wipe drill: zero the whole in-memory anchor; the chunked rebuild must
//!       reconstruct the identical anchor from the note log alone (the anchor is a pure
//!       function of the log).
//!   P3  upgrade drill: two upgrades with the populated chain — postupgrade stays inside
//!       the committed 2B-instruction / 256 MiB bounds (asserted in Runner::upgrade),
//!       the transient frontier rebuild is exercised, and the post-upgrade audit
//!       (which now re-walks the detect chain) reports PASS.

use soak::candid_types as ct;
use soak::{keys, pic_env, runner};
use std::path::PathBuf;
use std::process::Command;

fn nat_u64(n: &candid::Nat) -> u64 {
    u64::try_from(n.0.clone()).unwrap()
}

struct Ctx {
    runner: runner::Runner,
}

impl Ctx {
    fn admin_update<Out: candid::CandidType + for<'de> serde::Deserialize<'de>>(
        &self,
        method: &str,
        args: impl candid::utils::ArgumentEncoder,
    ) -> Out {
        self.runner
            .env
            .update(self.runner.env.ledger, self.runner.env.admin, method, args)
            .unwrap_or_else(|e| panic!("{method}: {e}"))
    }

    fn anchor(&self) -> ct::DetectAnchor {
        let r: ct::MotokoResult<ct::DetectAnchor> = self
            .runner
            .env
            .query(self.runner.env.ledger, "detect_stream_anchor", ())
            .expect("detect_stream_anchor");
        r.into_result().expect("detect chain not enabled")
    }

    /// Pump ticks until the rebuild reports inactive; panics on a rebuild error or bound.
    fn await_rebuild(&self, label: &str) {
        for _ in 0..4096 {
            let s: ct::DetectRebuildStatus = self
                .runner
                .env
                .query(self.runner.env.ledger, "detect_rebuild_status", ())
                .expect("detect_rebuild_status");
            if let Some(code) = &s.error {
                panic!("rebuild FAILED ({label}): {code} at cursor {}", nat_u64(&s.cursor));
            }
            if !s.active {
                return;
            }
            self.runner.env.pic().advance_time(std::time::Duration::from_secs(1));
            self.runner.env.pic().tick();
        }
        panic!("rebuild poll bound exhausted ({label})");
    }

    /// Assert anchor == reference recompute; returns (root, c_tip, count, boundaries).
    fn assert_anchor_matches(&self, label: &str) -> ([u8; 32], [u8; 32], u64, usize) {
        let (root, c_tip, count, boundaries) = self.runner.detect_recompute();
        let a = self.anchor();
        assert_eq!(a.root.as_slice(), root, "{label}: anchor root != recompute");
        assert_eq!(a.c_tip.as_slice(), c_tip, "{label}: anchor c_tip != recompute");
        assert_eq!(nat_u64(&a.note_count), count, "{label}: anchor count != recompute");
        (root, c_tip, count, boundaries)
    }
}

fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf();
    let manifest_json =
        std::fs::read_to_string(root.join("fixtures/pool-vectors-bls12-381/SETUP-MANIFEST.json"))
            .expect("read setup manifest");
    let keyset = keys::regenerate_and_verify(&manifest_json).expect("keyset");
    let mut wasms = pic_env::build_wasms(&root, &root.join("soak/target/wasms-detect"));

    // Hook wasm (corruption primitives; additive-only diff proven by the build script).
    let hook_path = std::env::temp_dir().join(format!("zk_ledger_detect_{}.wasm", std::process::id()));
    let status = Command::new("bash")
        .arg(root.join("scripts/build-test-wasm.sh"))
        .arg(root.join("scripts/test-hooks.frag.mo"))
        .arg(&hook_path)
        .current_dir(&root)
        .status()
        .expect("build-test-wasm spawn");
    assert!(status.success(), "build-test-wasm failed");
    wasms.ledger = std::fs::read(&hook_path).expect("read hook wasm");
    println!("[build] HOOK ledger wasm installed for the battery (never shipped)");

    // Enable the detect-chain legs in Runner (genesis enable + per-upgrade verification).
    std::env::set_var("SOAK_DETECT_CHAIN", "1");

    let mut tier = runner::TierConfig::from_env();
    tier.label = "detect-battery".into();
    tier.accounts = 24;
    tier.ops = 20_000; // upper bound; the corpus loop below steps explicitly
    tier.seed = 20_260_723;
    tier.upgrades = 0; // upgrades driven explicitly in P3
    tier.checkpoint_ops = 0;
    tier.recycle_ops = 0;
    tier.state_dir = std::env::temp_dir().join(format!("detect-battery-{}", std::process::id()));
    tier.checkpoint_file = tier.state_dir.join("ckpt.bin");
    let mut ctx = Ctx { runner: runner::Runner::new(tier, keyset, &wasms) };

    // ---- corpus: past one DPAGE boundary (>= 4,200 notes) ----
    let notes_target = 4_200u64;
    let ops_cap = 6_000usize;
    let mut done = 0usize;
    loop {
        let notes = nat_u64(&ctx.runner.env.ledger_status().note_count);
        if notes >= notes_target {
            break;
        }
        assert!(done < ops_cap, "corpus build exceeded the {ops_cap}-op backstop");
        ctx.runner.step_ops(250);
        done += 250;
        println!("[corpus] {done} ops, {notes}/{notes_target} notes");
    }

    // ---- P0 baseline ----
    let (_, _, count0, boundaries0) = ctx.assert_anchor_matches("P0");
    assert!(boundaries0 >= 1, "P0: corpus must cross a DPAGE boundary (got {boundaries0})");
    let restarted: ct::MotokoResult<ct::AuditStatus> = ctx.admin_update("restart_audit", ());
    restarted.into_result().expect("restart_audit");
    let audited = ctx.runner.await_audit_terminal("P0 baseline");
    assert!(
        matches!(audited.state, ct::AuditState::pass),
        "P0: baseline audit must PASS with the detect walk enabled, got {:?}",
        audited.state
    );
    println!("PASS P0: anchor == recompute at {count0} notes ({boundaries0} boundary), audit green");

    // ---- P1 teeth: 5 corruption classes, exact codes, full recovery each ----
    let classes: [(&str, &str); 5] = [
        ("chain", "detect-chain:tip-mismatch"),
        ("root", "detect-chain:root-mismatch"),
        ("covered", "detect-chain:covered-mismatch"),
        ("count", "detect-chain:count-mismatch"),
        ("boundary", "detect-chain:boundary-mismatch"),
    ];
    for (field, expected_code) in classes {
        let _: () = ctx.admin_update("test_detect_corrupt", (field,));
        let restarted: ct::MotokoResult<ct::AuditStatus> = ctx.admin_update("restart_audit", ());
        restarted.into_result().expect("restart_audit");
        let audited = ctx.runner.await_audit_terminal(&format!("P1 {field}"));
        match &audited.state {
            ct::AuditState::fail { code, .. } => {
                assert_eq!(code, expected_code, "P1 {field}: wrong audit code");
            }
            other => panic!("P1 {field}: audit did not FAIL on planted corruption: {other:?}"),
        }
        assert!(audited.guard.is_some(), "P1 {field}: fail-closed guard did not trip");
        // recovery: rebuild from the log, re-audit green, clear the guard
        let r: ct::MotokoResult<()> = ctx.admin_update("detect_chain_rebuild", ());
        r.into_result().expect("detect_chain_rebuild");
        ctx.await_rebuild(field);
        ctx.assert_anchor_matches(&format!("P1 {field} post-rebuild"));
        let restarted: ct::MotokoResult<ct::AuditStatus> = ctx.admin_update("restart_audit", ());
        restarted.into_result().expect("restart_audit");
        let audited = ctx.runner.await_audit_terminal(&format!("P1 {field} recovery"));
        assert!(
            matches!(audited.state, ct::AuditState::pass),
            "P1 {field}: audit must PASS after rebuild, got {:?}",
            audited.state
        );
        let cleared: ct::MotokoResult<ct::AuditStatus> = ctx.admin_update("clear_audit_guard", ());
        let cleared = cleared.into_result().expect("clear_audit_guard");
        assert!(cleared.guard.is_none(), "P1 {field}: guard not cleared after green re-audit");
        println!("PASS P1 {field}: RED ({expected_code}) -> rebuild -> green -> guard cleared");
    }

    // ---- P2 wipe drill: rebuild the whole anchor from the log alone ----
    let before = ctx.anchor();
    let _: () = ctx.admin_update("test_detect_wipe", ());
    let wiped = ctx.anchor();
    assert_eq!(nat_u64(&wiped.note_count), 0, "P2: wipe hook did not zero the anchor");
    let r: ct::MotokoResult<()> = ctx.admin_update("detect_chain_rebuild", ());
    r.into_result().expect("detect_chain_rebuild");
    ctx.await_rebuild("P2 wipe");
    let after = ctx.anchor();
    assert_eq!(after.root, before.root, "P2: rebuilt root != pre-wipe root");
    assert_eq!(after.c_tip, before.c_tip, "P2: rebuilt c_tip != pre-wipe c_tip");
    assert_eq!(after.note_count, before.note_count, "P2: rebuilt count != pre-wipe count");
    ctx.assert_anchor_matches("P2 post-rebuild");
    let restarted: ct::MotokoResult<ct::AuditStatus> = ctx.admin_update("restart_audit", ());
    restarted.into_result().expect("restart_audit");
    let audited = ctx.runner.await_audit_terminal("P2 wipe recovery");
    assert!(matches!(audited.state, ct::AuditState::pass), "P2: audit must PASS after wipe+rebuild");
    println!("PASS P2: wiped anchor rebuilt byte-identically from the note log ({} notes)", nat_u64(&after.note_count));

    // ---- P3 upgrade drill: populated chain across two upgrades ----
    // Runner::upgrade asserts the committed postupgrade bounds (2B instr / 256 MiB),
    // waits for the post-upgrade audit PASS (which re-walks the detect chain), and — with
    // SOAK_DETECT_CHAIN set — byte-compares the anchor against the recompute, exercising
    // the transient frontier rebuild.
    for k in 0..2u64 {
        ctx.runner.step_ops(20);
        let at = nat_u64(&ctx.runner.env.ledger_status().note_count);
        ctx.runner.upgrade(at);
        println!("PASS P3 upgrade #{}: populated-chain upgrade green (bounds + audit + anchor)", k + 1);
    }

    println!("detect battery COMPLETE: P0 baseline, P1 5/5 teeth+recovery, P2 wipe rebuild, P3 2 upgrades");
}
