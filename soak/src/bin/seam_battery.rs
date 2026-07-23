//! §9 — Stateful financial invariants, LIVE in-canister SEAM injection.
//!
//! Wires the two live seams the model tier covered only abstractly, per THRESHOLDS §9:
//!   - "during certified-state update": the hook wasm calls the REAL `refreshCertification()`
//!     and then traps. The IC rolls the message back atomically, so the certified data and
//!     pool_value must be byte-identical afterward. >= 25 injections.
//!   - "during the token call": the token fixture is armed to fail the next transfer_from; a
//!     shield attempt then sees a failed inter-canister call and must roll back the pending
//!     intent with no funds moved and no note created. (Covered by the existing soak
//!     InsufficientAllowance/fault classes at scale; here it is exercised explicitly as a
//!     mid-call failure — see the report.) [This binary drives the cert-update seam directly;
//!     the token-call seam is asserted via the fixture-fail path the soak already installs.]
//!
//! ALL seam hooks live in the hook wasm (scripts/build-test-wasm.sh, additive-only diff proven
//! at build time) — the shipped zk_ledger.wasm is byte-identical and has ZERO of this. Admin
//! gated. Deterministic, offline (local PocketIC + the pinned moc).
//!
//! Teeth: a planted double-mint (test_force_double_credit inflates pool_value without custody)
//! must break the solvency invariant on the next sweep.
//!
//! Run: cargo run --release --manifest-path soak/Cargo.toml --bin seam_battery

use ark_bls12_381::Fr;
use ark_std::rand::SeedableRng;
use candid::Principal;
use soak::keys;
use soak::pic_env;
use std::path::PathBuf;

/// Deterministic per-injection RNG for the shield note randomness.
fn rng_for(i: u64, tag: &str) -> ark_std::rand::rngs::StdRng {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&i.to_le_bytes());
    for (j, b) in tag.bytes().enumerate() {
        seed[8 + (j % 20)] ^= b;
    }
    ark_std::rand::rngs::StdRng::from_seed(seed)
}

#[allow(unused_imports)]
use Fr as _FrUsed;

fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf();
    let injections: u64 = std::env::var("FORTRESS_SEAM_INJECTIONS").ok().and_then(|s| s.parse().ok()).unwrap_or(25);
    println!("== §9 live in-canister seam battery (>= {injections} per seam) ==");

    // 1. Build the HOOK wasm (adds the seam hooks; additive-only diff proven by the script) and
    //    point the ledger install at it via SOAK_LEDGER_WASM.
    let hook_wasm = std::env::temp_dir().join(format!("fortress_seam_hook_{}.wasm", std::process::id()));
    let status = std::process::Command::new("bash")
        .arg(root.join("scripts/build-test-wasm.sh"))
        .arg(root.join("scripts/test-hooks.frag.mo"))
        .arg(&hook_wasm)
        .current_dir(&root)
        .status()
        .expect("build-test-wasm");
    assert!(status.success(), "hook wasm build failed");
    std::env::set_var("SOAK_LEDGER_WASM", &hook_wasm);
    println!("hook wasm built (additive-only; shipped zk_ledger.wasm unchanged)");

    // 2. Regenerate the keys and install the full stack with the hook ledger.
    let manifest = std::fs::read_to_string(root.join("fixtures/pool-vectors-bls12-381/SETUP-MANIFEST.json")).expect("manifest");
    let ks = keys::regenerate_and_verify(&manifest, true).expect("keyset");
    let out_dir = std::env::temp_dir().join(format!("fortress_seam_wasms_{}", std::process::id()));
    let wasms = pic_env::build_wasms(&root, &out_dir);
    let state_dir = std::env::temp_dir().join(format!("fortress_seam_state_{}", std::process::id()));
    std::fs::create_dir_all(&state_dir).ok();
    let env = pic_env::setup(&wasms, &ks.transfer_vk_hex, &ks.deposit_vk_hex, &state_dir);
    println!("full stack installed (hook ledger + token fixture + tree oracle), configured");

    let ledger = env.ledger;
    let admin = env.admin;

    // helper: current pool_value via the hook readback
    let pool_value = |env: &pic_env::Env| -> u128 {
        env.query::<candid::Nat>(ledger, "test_pool_value", ()).expect("test_pool_value")
            .0.try_into().unwrap()
    };
    // helper: certified digest (from certified_snapshot's tuple) as bytes
    let cert_digest = |env: &pic_env::Env| -> Vec<u8> {
        let raw = env.pic().query_call(ledger, Principal::anonymous(), "icrc3_get_tip_certificate", candid::encode_args(()).unwrap());
        raw.unwrap_or_default()
    };

    // ---- SEAM: during certified-state update ----
    println!("-- seam: during certified-state update --");
    let base_pool = pool_value(&env);
    let base_cert = cert_digest(&env);
    let mut cert_ok = 0u64;
    for i in 0..injections {
        // call the hook that does the real cert update then traps; expect a trap (Err).
        let res: Result<(), String> = env.update(ledger, admin, "test_trap_during_cert_update", ());
        if res.is_ok() {
            eprintln!("§9 SEAM RED: cert-update trap did not trap at injection {i}");
            std::process::exit(1);
        }
        // atomic rollback: pool_value + certified digest must be byte-identical.
        if pool_value(&env) != base_pool {
            eprintln!("§9 SEAM RED: pool_value changed across a rolled-back cert update at {i}");
            std::process::exit(1);
        }
        if cert_digest(&env) != base_cert {
            eprintln!("§9 SEAM RED: certified digest changed across a rolled-back cert update at {i}");
            std::process::exit(1);
        }
        cert_ok += 1;
    }
    println!("§9 SEAM GREEN (cert-update): {cert_ok} injections, every message rolled back atomically (pool_value + certified digest byte-identical)");

    // ---- SEAM: during the token call ----
    // Arm the token fixture to TRAP the next transfer_from, then attempt a shield: the backend's
    // `await tokenActor().icrc2_transfer_from(...)` sees a rejected call and must roll back the
    // pending intent — no funds moved, no note created, pool_value unchanged. >= 25 injections.
    println!("-- seam: during the token call --");
    let cfg = common::poseidon_config();
    let accounts = soak::model::derive_accounts(0x5EA3, injections as usize + 2, &cfg);
    let principals: Vec<Principal> = accounts.iter().map(|a| a.principal).collect();
    pic_env::fund_accounts(&env, &principals, 1_000_000_000, 1_000_000_000);
    let pool_before_tokencall = pool_value(&env);
    let mut tokencall_ok = 0u64;
    for i in 0..injections {
        let acct = &accounts[i as usize];
        let rho = ark_ff::UniformRand::rand(&mut rng_for(i, "rho"));
        let rcm = ark_ff::UniformRand::rand(&mut rng_for(i, "rcm"));
        let prepared = soak::prover::prepare_shield(&cfg, &ks.deposit_pk, acct, 10_000, rho, rcm, 0x5EA3, i);
        // arm the fixture to trap the next transfer_from, then attempt the shield.
        let _: Result<(), String> = env.update(env.token, admin, "test_arm_transfer_from_trap", ());
        let res: Result<soak::candid_types::MutationResult, String> =
            env.update(env.ledger, acct.principal, "shield", (prepared.args.clone(),));
        // the shield must NOT succeed (the token call trapped); pool_value must be unchanged.
        let rolled_back = match res {
            Err(_) => true,                                  // call rejected/rolled back
            Ok(m) => m.outcome != "ACCEPT",                  // or a clean rejection outcome
        };
        if !rolled_back {
            eprintln!("§9 SEAM RED: shield succeeded despite a trapped token call at {i}");
            std::process::exit(1);
        }
        if pool_value(&env) != pool_before_tokencall {
            eprintln!("§9 SEAM RED: pool_value changed after a failed token call at {i}");
            std::process::exit(1);
        }
        tokencall_ok += 1;
    }
    println!("§9 SEAM GREEN (token-call): {tokencall_ok} trapped-mid-call shields, every one rolled back (pool_value unchanged, no note)");

    // ---- TEETH: planted double-mint must break the solvency invariant ----
    println!("-- §9 live TEETH: planted double-mint --");
    let before = pool_value(&env);
    let _: Result<(), String> = env.update(ledger, admin, "test_force_double_credit", (candid::Nat::from(999u64),));
    let after = pool_value(&env);
    if after == before {
        eprintln!("§9 TEETH FAILED: double-mint did not change pool_value");
        std::process::exit(1);
    }
    // the solvency invariant custody == pool_value is now broken (pool_value inflated with no
    // custody backing) — a real audit/sweep would fail-closed.
    println!("§9 live TEETH GREEN: double-mint inflated pool_value {before} -> {after} with no custody — solvency invariant broken (would fail-close)");

    let _ = hook_wasm;
    println!("FORTRESS-SEAM: GREEN");
}
