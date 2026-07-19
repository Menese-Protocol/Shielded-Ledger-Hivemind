//! PROFILING DRIVER — measure where the verifier allocates before changing it.
//!
//! Measures the shielded ledger's per-operation allocation churn two independent ways and
//! prints the component table the fix is aimed with:
//!
//!   Stage 1 (end-to-end): builds the REAL zk_ledger wasm (pinned moc), stands up the same
//!   PocketIC environment the soak uses, runs N shields / private transfers / unshields with
//!   real proofs, and reads `rts_status().total_allocation` deltas around EVERY update call —
//!   the per-entry-point MB/op ground truth (same metric as the Jul-18 soak telemetry).
//!
//!   Stage 2 (components): installs `tests/ChurnProfile.mo` (harness-only actor) and probes
//!   each verify component on the FROZEN fixture vectors, in-canister, via
//!   `Prim.rts_total_allocation()` deltas. The component sum must reconcile with the
//!   full-verify probe (printed), and the full-verify probe with the end-to-end per-op deltas.
//!
//! Run: PROFILE_SCRATCH=<dir> cargo run --release --manifest-path soak/Cargo.toml --bin profile

use ark_bls12_381::Fr as F;
use ark_ff::UniformRand;
use candid::{CandidType, Principal};
use serde::Deserialize;
use soak::candid_types as ct;
use soak::crypto::{f_bytes, nat64_field_bytes, MerkleMirror};
use soak::model::{derive_accounts, AccountKeys};
use soak::{keys, pic_env, prover};
use std::path::{Path, PathBuf};
use std::process::Command;

const SEED: u64 = 20260719;

#[derive(CandidType, Deserialize, Debug)]
struct Probe {
    alloc: candid::Nat,
    instructions: u64,
    iters: candid::Nat,
}

#[derive(CandidType, Deserialize, Debug)]
struct GateResult {
    pass: bool,
    checked: candid::Nat,
    detail: String,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

fn nat_u128(n: &candid::Nat) -> u128 {
    u128::try_from(n.0.clone()).expect("nat fits u128")
}

fn mb(bytes: u128) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

/// Compile the profiling actor with the SAME pinned moc + mops sources as the ledger build.
fn compile_profile_wasm(root: &Path, out_dir: &Path) -> Vec<u8> {
    let moc = std::env::var("SOAK_MOC").map(PathBuf::from).unwrap_or_else(|_| {
        let pinned = PathBuf::from("/opt/moc-1.4.1/moc");
        if pinned.exists() {
            pinned
        } else {
            PathBuf::from("moc")
        }
    });
    let mops = std::env::var("SOAK_MOPS").unwrap_or_else(|_| "mops".into());
    let sources = Command::new(&mops)
        .arg("sources")
        .current_dir(root)
        .output()
        .expect("mops sources");
    assert!(sources.status.success(), "mops sources failed");
    let source_args: Vec<String> = String::from_utf8_lossy(&sources.stdout)
        .split_whitespace()
        .map(String::from)
        .collect();
    let out_path = out_dir.join("churn_profile.wasm");
    let out = Command::new(&moc)
        .args(&source_args)
        .arg("-c")
        .arg("tests/ChurnProfile.mo")
        .arg("-o")
        .arg(&out_path)
        .current_dir(root)
        .output()
        .expect("moc compile ChurnProfile");
    assert!(
        out.status.success(),
        "moc ChurnProfile failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::read(&out_path).expect("read churn_profile.wasm")
}

struct LocalNote {
    leaf_index: u64,
    v: u64,
    rho: F,
    rcm: F,
    owner: usize,
}

struct OpStat {
    label: &'static str,
    alloc: u128,
    memory_size: u128,
    heap_size: u128,
}

fn read_fixture(root: &Path, name: &str) -> String {
    std::fs::read_to_string(root.join("fixtures/pool-vectors-bls12-381").join(name))
        .unwrap_or_else(|e| panic!("read fixture {name}: {e}"))
        .trim()
        .to_string()
}

fn fixture_field(root: &Path, name: &str) -> [u8; 32] {
    let bytes = hex::decode(read_fixture(root, name)).unwrap_or_else(|e| panic!("{name}: {e}"));
    bytes.try_into().unwrap_or_else(|_| panic!("{name}: not 32 bytes"))
}

fn fixture_u64(root: &Path, name: &str) -> u64 {
    read_fixture(root, name).parse().unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn inputs_hex(fields: &[[u8; 32]]) -> String {
    let mut b = Vec::with_capacity(8 + 32 * fields.len());
    b.extend_from_slice(&(fields.len() as u64).to_le_bytes());
    for f in fields {
        b.extend_from_slice(f);
    }
    hex::encode(b)
}

/// Fast lane: install ONLY the profiling actor on a throwaway instance and run the
/// representation probes (no keys, no ledger, no proofs). Used to decide/verify the Phase-2
/// limb representation and to gate new limb-layer differential probes during development.
fn repr_mode(root: &Path, scratch: &Path) {
    use sha2::Digest;
    let wasm_dir = scratch.join("wasms");
    std::fs::create_dir_all(&wasm_dir).expect("create wasm dir");
    let profile_wasm = compile_profile_wasm(root, &wasm_dir);
    println!("[build] churn_profile.wasm compiled ({} bytes)", profile_wasm.len());
    let server = pic_env::spawn_server(&pic_env::resolve_pocket_ic_server());
    let pic = pocket_ic::PocketIcBuilder::new()
        .with_server_url(server.url.clone())
        .with_application_subnet()
        .with_max_request_time_ms(Some(600_000))
        .build();
    let admin = Principal::self_authenticating(sha2::Sha256::digest(b"churn-profile-admin"));
    let canister = pic.create_canister_with_settings(Some(admin), None);
    pic.add_cycles(canister, 100_000_000_000_000);
    pic.install_canister(canister, profile_wasm, candid::encode_args(()).unwrap(), Some(admin));
    pic.update_canister_settings(
        canister,
        Some(admin),
        pocket_ic::CanisterSettings {
            wasm_memory_limit: Some(candid::Nat::from(8u64 * 1024 * 1024 * 1024)),
            ..Default::default()
        },
    )
    .expect("wasm_memory_limit");

    let call = |method: &str, iters: u64| -> Probe {
        let payload = candid::encode_args((candid::Nat::from(iters),)).unwrap();
        let raw = pic
            .update_call(canister, admin, method, payload)
            .unwrap_or_else(|e| panic!("{method}: {e:?}"));
        candid::decode_one(&raw).unwrap_or_else(|e| panic!("decode {method}: {e}"))
    };

    println!("\n== representation probes (bytes/op must be ~0 for the chosen limb form) ==");
    println!("{:<28} {:>12} {:>12}", "form", "bytes/op", "instr/op");
    for (name, method, iters) in [
        ("Nat32 [var] store", "probe_nat32_array_store", 100_000u64),
        ("Nat64 [var] store (full)", "probe_nat64_array_store", 100_000),
        ("Nat64 local arith (CIOS)", "probe_nat64_local_arith", 100_000),
        ("Nat64 captured-var store", "probe_nat64_capture_store", 100_000),
        ("montMul (baseline)", "probe_mont_mul", 20_000),
    ] {
        let p = call(method, iters);
        let alloc = u128::try_from(p.alloc.0.clone()).unwrap();
        println!(
            "{name:<28} {:>12.2} {:>12}",
            alloc as f64 / iters as f64,
            p.instructions / iters
        );
    }
    println!("\n== L3 differential gates (flat backend vs L2 anchor) ==");
    let gate = |method: &str, iters: u64| {
        let payload = candid::encode_args((candid::Nat::from(iters),)).unwrap();
        let raw = pic
            .update_call(canister, admin, method, payload)
            .unwrap_or_else(|e| panic!("{method}: {e:?}"));
        let g: GateResult =
            candid::decode_one(&raw).unwrap_or_else(|e| panic!("decode {method}: {e}"));
        let verdict = if g.pass { "PASS" } else { "FAIL" };
        println!(
            "{method:<24} {verdict}  checked={} {}",
            u128::try_from(g.checked.0.clone()).unwrap(),
            g.detail
        );
        assert!(g.pass, "{method} FAILED at vector {}: {}", g.checked.0, g.detail);
    };
    gate("gate_fp_flat", 5_000);
    for (name, method, iters) in [("FpFlat montMul (in-place)", "probe_flat_mont_mul", 20_000u64)] {
        let p = call(method, iters);
        let alloc = u128::try_from(p.alloc.0.clone()).unwrap();
        println!(
            "{name:<28} {:>12.2} bytes/op {:>12} instr/op",
            alloc as f64 / iters as f64,
            p.instructions / iters
        );
    }

    println!("\n[repr] done.");
}

fn main() {
    let root = repo_root();
    let scratch = PathBuf::from(
        std::env::var("PROFILE_SCRATCH").expect("set PROFILE_SCRATCH to a fresh scratch dir"),
    );
    std::fs::create_dir_all(&scratch).expect("create scratch");

    if std::env::args().nth(1).as_deref() == Some("repr") {
        repr_mode(&root, &scratch);
        return;
    }

    // B1a gate: the keys the environment is configured with are the proven pinned setup.
    let manifest_json =
        std::fs::read_to_string(root.join("fixtures/pool-vectors-bls12-381/SETUP-MANIFEST.json"))
            .expect("read SETUP-MANIFEST.json");
    println!("[B1a] regenerating keyset (seed 20260712)...");
    let keyset = keys::regenerate_and_verify(&manifest_json).expect("B1a keyset gate");
    println!("[B1a] PASS");
    keys::verify_frozen_fixtures(&root.join("fixtures/pool-vectors-bls12-381"), &keyset)
        .expect("B1b frozen fixtures");
    println!("[B1b] PASS: frozen fixtures verify under regenerated keys");

    let wasm_dir = scratch.join("wasms");
    let wasms = pic_env::build_wasms(&root, &wasm_dir);
    println!(
        "[build] zk_ledger.wasm sha256 {} ({})",
        wasms.ledger_sha256, wasms.moc_version
    );
    let profile_wasm = compile_profile_wasm(&root, &wasm_dir);
    println!("[build] churn_profile.wasm compiled ({} bytes)", profile_wasm.len());

    let state_dir = scratch.join("profile-state");
    assert!(!state_dir.exists(), "state dir must be fresh: {}", state_dir.display());
    std::fs::create_dir_all(&state_dir).expect("create state dir");
    let env = pic_env::setup(&wasms, &keyset.transfer_vk_hex, &keyset.deposit_vk_hex, &state_dir);
    println!("[env] ledger {} token fee {}", env.ledger, env.token_fee);

    let cfg = common::poseidon_config();
    let accounts: Vec<AccountKeys> = derive_accounts(SEED, 3, &cfg);
    let principals: Vec<Principal> = accounts.iter().map(|a| a.principal).collect();
    pic_env::fund_accounts(&env, &principals, 1 << 45, 1 << 60);
    println!("[env] 3 accounts funded");

    // ---------------- end-to-end per-entry-point deltas ----------------
    let mut mirror = MerkleMirror::new(&cfg);
    let mut notes: Vec<LocalNote> = Vec::new();
    let mut stats: Vec<OpStat> = Vec::new();
    let mut op_index: u64 = 0;

    let rts = |label: &'static str, before: &ct::RtsStatus, after: &ct::RtsStatus| OpStat {
        label,
        alloc: nat_u128(&after.total_allocation) - nat_u128(&before.total_allocation),
        memory_size: nat_u128(&after.memory_size),
        heap_size: nat_u128(&after.heap_size),
    };

    // 8 shields (acct0)
    for i in 0..8u64 {
        let v = 1_000_000 + i;
        let mut rng = prover::op_rng(SEED, op_index, "plan");
        let rho = F::rand(&mut rng);
        let rcm = F::rand(&mut rng);
        let prepared =
            prover::prepare_shield(&cfg, &keyset.deposit_pk, &accounts[0], v, rho, rcm, SEED, op_index);
        let mut args = prepared.args.clone();
        args.created_at_time = env.time_ns();
        let before = env.ledger_rts();
        let m: ct::MutationResult = env
            .update(env.ledger, accounts[0].principal, "shield", (args,))
            .expect("shield call");
        assert_eq!(m.outcome, "ACCEPT", "shield {i}: {} / {}", m.outcome, m.verifier_outcome);
        let after = env.ledger_rts();
        stats.push(rts("shield", &before, &after));
        let cm = common::note_commitment(&cfg, v, accounts[0].pk, rho, rcm);
        let leaf = mirror.append(&cfg, cm);
        assert_eq!(
            f_bytes(&mirror.root()).to_vec(),
            m.note_root.to_vec(),
            "mirror root diverged from ledger after shield {i}"
        );
        notes.push(LocalNote { leaf_index: leaf, v, rho, rcm, owner: 0 });
        op_index += 1;
        println!(
            "[A] shield  #{i}: alloc {:>8.1} MB  mem {:>7.1} MB  heap {:>6.1} MB",
            mb(stats.last().unwrap().alloc),
            mb(stats.last().unwrap().memory_size),
            mb(stats.last().unwrap().heap_size)
        );
    }

    // 4 private transfers (acct0 spends pairs, outputs back to acct0)
    let mut spend_cursor = 0usize;
    let transfer =
        |label: &'static str,
         v_pub_out: u64,
         fee: u64,
         recipient: Option<ct::Account>,
         binding: [u8; 32],
         env: &pic_env::Env,
         mirror: &mut MerkleMirror,
         notes: &mut Vec<LocalNote>,
         stats: &mut Vec<OpStat>,
         spend_cursor: &mut usize,
         op_index: &mut u64| {
            let (i1, i2) = (*spend_cursor, *spend_cursor + 1);
            *spend_cursor += 2;
            let (n1, n2) = (&notes[i1], &notes[i2]);
            assert_eq!(n1.owner, 0);
            assert_eq!(n2.owner, 0);
            let total = n1.v + n2.v;
            assert!(total >= v_pub_out + fee, "value balance");
            let out_v1 = (total - v_pub_out - fee) / 2;
            let out_v2 = total - v_pub_out - fee - out_v1;
            let mut rng = prover::op_rng(SEED, *op_index, "plan");
            let crypto = prover::TransferCrypto {
                anchor: mirror.root(),
                path1: mirror.path(n1.leaf_index),
                path2: mirror.path(n2.leaf_index),
                out_rcm1: F::rand(&mut rng),
                out_rcm2: F::rand(&mut rng),
            };
            let in1 = prover::TransferPlanInput {
                note_index: i1,
                leaf_index: n1.leaf_index,
                v: n1.v,
                nk: accounts[0].nk,
                rho: n1.rho,
                rcm: n1.rcm,
            };
            let in2 = prover::TransferPlanInput {
                note_index: i2,
                leaf_index: n2.leaf_index,
                v: n2.v,
                nk: accounts[0].nk,
                rho: n2.rho,
                rcm: n2.rcm,
            };
            let prepared = prover::prepare_transfer(
                &cfg,
                &keyset.transfer_pk,
                &crypto,
                (&in1, &in2),
                (&accounts[0], &accounts[0]),
                (out_v1, out_v2),
                fee,
                v_pub_out,
                binding,
                recipient,
                None,
                SEED,
                *op_index,
            );
            let mut args = prepared.args.clone();
            if v_pub_out > 0 {
                args.created_at_time = Some(env.time_ns());
            }
            let before = env.ledger_rts();
            let m: ct::MutationResult = env
                .update(env.ledger, accounts[0].principal, "confidential_transfer", (args,))
                .expect("confidential_transfer call");
            assert_eq!(m.outcome, "ACCEPT", "{label}: {} / {}", m.outcome, m.verifier_outcome);
            let after = env.ledger_rts();
            stats.push(rts(label, &before, &after));
            // outputs: rho chained to input nullifiers (prepare_transfer construction)
            let nf1 = common::derive_nf(&cfg, accounts[0].nk, n1.rho);
            let nf2 = common::derive_nf(&cfg, accounts[0].nk, n2.rho);
            let cm1 = common::note_commitment(&cfg, out_v1, accounts[0].pk, nf1, crypto.out_rcm1);
            let cm2 = common::note_commitment(&cfg, out_v2, accounts[0].pk, nf2, crypto.out_rcm2);
            let l1 = mirror.append(&cfg, cm1);
            let l2 = mirror.append(&cfg, cm2);
            assert_eq!(
                f_bytes(&mirror.root()).to_vec(),
                m.note_root.to_vec(),
                "mirror root diverged from ledger after {label}"
            );
            notes.push(LocalNote { leaf_index: l1, v: out_v1, rho: nf1, rcm: crypto.out_rcm1, owner: 0 });
            notes.push(LocalNote { leaf_index: l2, v: out_v2, rho: nf2, rcm: crypto.out_rcm2, owner: 0 });
            *op_index += 1;
            let s = stats.last().unwrap();
            println!(
                "[A] {label:>8}: alloc {:>8.1} MB  mem {:>7.1} MB  heap {:>6.1} MB",
                mb(s.alloc),
                mb(s.memory_size),
                mb(s.heap_size)
            );
        };

    for _ in 0..4 {
        transfer(
            "transfer",
            0,
            0,
            None,
            [0u8; 32],
            &env,
            &mut mirror,
            &mut notes,
            &mut stats,
            &mut spend_cursor,
            &mut op_index,
        );
    }

    // 2 unshields (acct0 to its own transparent account)
    let recipient = ct::Account { owner: accounts[0].principal, subaccount: None };
    let binding_result: ct::MotokoResult<ct::Blob> = env
        .query(env.ledger, "recipient_binding", (recipient.clone(),))
        .expect("recipient_binding query");
    let binding: [u8; 32] = binding_result
        .into_result()
        .expect("recipient_binding")
        .to_vec()
        .try_into()
        .expect("binding 32 bytes");
    for _ in 0..2 {
        transfer(
            "unshield",
            50_000,
            env.token_fee,
            Some(recipient.clone()),
            binding,
            &env,
            &mut mirror,
            &mut notes,
            &mut stats,
            &mut spend_cursor,
            &mut op_index,
        );
    }

    println!("\n== per-entry-point ledger allocation (ground truth) ==");
    for label in ["shield", "transfer", "unshield"] {
        let sel: Vec<&OpStat> = stats.iter().filter(|s| s.label == label).collect();
        let total: u128 = sel.iter().map(|s| s.alloc).sum();
        let avg = total as f64 / sel.len() as f64;
        println!(
            "{label:>9}: n={} avg {:.1} MB/op (min {:.1}, max {:.1})",
            sel.len(),
            avg / (1024.0 * 1024.0),
            sel.iter().map(|s| mb(s.alloc)).fold(f64::INFINITY, f64::min),
            sel.iter().map(|s| mb(s.alloc)).fold(0.0, f64::max),
        );
    }
    let final_rts = env.ledger_rts();
    println!(
        "[A] final: mem {:.1} MB heap {:.1} MB total_alloc {:.1} MB reclaimed {:.1} MB",
        mb(nat_u128(&final_rts.memory_size)),
        mb(nat_u128(&final_rts.heap_size)),
        mb(nat_u128(&final_rts.total_allocation)),
        mb(nat_u128(&final_rts.reclaimed))
    );

    // ---------------- component probes on the frozen vectors ----------------
    let admin = env.admin;
    let profiler = env.pic().create_canister_with_settings(Some(admin), None);
    env.pic().add_cycles(profiler, 100_000_000_000_000);
    env.pic()
        .install_canister(profiler, profile_wasm, candid::encode_args(()).unwrap(), Some(admin));
    // The verify probes run up to ~13B instructions; the profiler is also wasm64/EOP.
    env.pic()
        .update_canister_settings(
            profiler,
            Some(admin),
            pocket_ic::CanisterSettings {
                wasm_memory_limit: Some(candid::Nat::from(8u64 * 1024 * 1024 * 1024)),
                ..Default::default()
            },
        )
        .expect("profiler wasm_memory_limit");

    let transfer_proof_hex = read_fixture(&root, "transfer_proof.hex");
    let transfer_inputs = inputs_hex(&[
        fixture_field(&root, "anchor.hex"),
        fixture_field(&root, "nf1.hex"),
        fixture_field(&root, "nf2.hex"),
        fixture_field(&root, "cm_out1.hex"),
        fixture_field(&root, "cm_out2.hex"),
        nat64_field_bytes(fixture_u64(&root, "fee.txt")),
        nat64_field_bytes(fixture_u64(&root, "v_pub_out.txt")),
        fixture_field(&root, "recipient_binding.hex"),
    ]);
    let deposit_proof_hex = read_fixture(&root, "deposit1_proof.hex");
    let deposit_inputs = inputs_hex(&[
        fixture_field(&root, "deposit1_cm.hex"),
        nat64_field_bytes(fixture_u64(&root, "deposit1_v.txt")),
    ]);

    let set_vk = |hex: &str| {
        let ok: bool = env
            .update(profiler, admin, "set_vk", (hex.to_string(),))
            .expect("set_vk");
        assert!(ok, "set_vk rejected");
    };
    fn per_iter(p: &Probe) -> (f64, u64) {
        let iters = u128::try_from(p.iters.0.clone()).unwrap().max(1);
        (
            mb(u128::try_from(p.alloc.0.clone()).unwrap()) / iters as f64,
            p.instructions / iters as u64,
        )
    }

    macro_rules! probe {
        ($name:expr, ($($arg:expr),*)) => {{
            let p: Probe = env.update(profiler, admin, $name, ($($arg),*,)).expect($name);
            p
        }};
    }

    println!("\n== transfer-statement verify components (frozen vector) ==");
    set_vk(&keyset.transfer_vk_hex);
    let n1 = candid::Nat::from(1u64);
    let full =
        probe!("probe_full_verify", (transfer_proof_hex.clone(), transfer_inputs.clone(), n1.clone()));
    let (full_mb, full_instr) = per_iter(&full);
    let components: Vec<(&str, Probe)> = vec![
        ("hex_decode", probe!("probe_hex", (transfer_proof_hex.clone(), transfer_inputs.clone(), candid::Nat::from(4u64)))),
        ("parse_proof(pt decompress)", probe!("probe_parse_proof", (transfer_proof_hex.clone(), candid::Nat::from(2u64)))),
        ("parse_inputs", probe!("probe_parse_inputs", (transfer_inputs.clone(), candid::Nat::from(8u64)))),
        ("g1_validate_A", probe!("probe_g1_validate_a", (transfer_proof_hex.clone(), n1.clone()))),
        ("g1_validate_C", probe!("probe_g1_validate_c", (transfer_proof_hex.clone(), n1.clone()))),
        ("g2_validate_B", probe!("probe_g2_validate_b", (transfer_proof_hex.clone(), n1.clone()))),
        ("vkX_MSM(8 inputs)", probe!("probe_vkx", (transfer_inputs.clone(), n1.clone()))),
        ("prepare_B", probe!("probe_prepare_b", (transfer_proof_hex.clone(), n1.clone()))),
        ("multi_miller(4 pairs)", probe!("probe_multi_miller", (transfer_proof_hex.clone(), transfer_inputs.clone(), n1.clone()))),
        ("final_exp", probe!("probe_final_exp", (transfer_proof_hex.clone(), transfer_inputs.clone(), n1.clone()))),
    ];
    println!(
        "{:<28} {:>12} {:>16} {:>8}",
        "component", "MB/call", "instr/call", "% alloc"
    );
    let mut sum_mb = 0.0;
    for (name, p) in &components {
        let (m, i) = per_iter(p);
        sum_mb += m;
        println!("{name:<28} {m:>12.2} {i:>16} {:>7.1}%", 100.0 * m / full_mb);
    }
    println!("{:<28} {sum_mb:>12.2} {:>16} {:>7.1}%", "SUM(components)", "", 100.0 * sum_mb / full_mb);
    println!("{:<28} {full_mb:>12.2} {full_instr:>16} {:>7.1}%", "FULL verifyPrepared", 100.0);

    println!("\n== deposit-statement full verify (frozen vector) ==");
    set_vk(&keyset.deposit_vk_hex);
    let dfull = probe!("probe_full_verify", (deposit_proof_hex.clone(), deposit_inputs.clone(), n1.clone()));
    let (dmb, dinstr) = per_iter(&dfull);
    println!("deposit FULL verifyPrepared  {dmb:>10.2} MB  {dinstr} instr");
    let dvkx = probe!("probe_vkx", (deposit_inputs.clone(), n1.clone()));
    let (dvkx_mb, dvkx_instr) = per_iter(&dvkx);
    println!("deposit vkX_MSM(2 inputs)    {dvkx_mb:>10.2} MB  {dvkx_instr} instr");

    println!("\n== primitive micro-probes ==");
    let micro: Vec<(&str, &str, u64)> = vec![
        ("montMul (Mont x Mont)", "probe_mont_mul", 20_000),
        ("FpM.mul (normal, 2x redc)", "probe_fp_mul_normal", 10_000),
        ("FpM.add", "probe_fp_add", 20_000),
        ("fp2Mul", "probe_fp2_mul", 5_000),
        ("fp6Mul", "probe_fp6_mul", 1_000),
        ("fp12SqrFast", "probe_fp12_sqr_fast", 500),
        ("cyclotomicSquare", "probe_cyclotomic_sqr", 500),
        ("g1 Jacobian add", "probe_g1_jac_add", 2_000),
        ("g1 Jacobian dbl", "probe_g1_jac_dbl", 2_000),
    ];
    println!("{:<28} {:>12} {:>14}", "primitive", "bytes/op", "instr/op");
    for (name, method, iters) in micro {
        let p: Probe = env
            .update(profiler, admin, method, (candid::Nat::from(iters),))
            .expect(method);
        let alloc = u128::try_from(p.alloc.0.clone()).unwrap();
        println!(
            "{name:<28} {:>12.1} {:>14}",
            alloc as f64 / iters as f64,
            p.instructions / iters
        );
    }

    println!("\n== ledger-side (non-verify) probes ==");
    let ledger_side: Vec<(&str, &str, u64)> = vec![
        ("ICRC3 hash(block value)", "probe_icrc3_block_hash", 200),
        ("ICRC3 build+hash(block)", "probe_icrc3_build_and_hash", 200),
        ("NoteCodec.encode", "probe_notecodec_encode", 500),
        ("NoteCodec.decode", "probe_notecodec_decode", 500),
        ("blobToHex(32B)", "probe_blob_to_hex", 500),
    ];
    println!("{:<28} {:>12} {:>14}", "path", "bytes/op", "instr/op");
    for (name, method, iters) in ledger_side {
        let p: Probe = env
            .update(profiler, admin, method, (candid::Nat::from(iters),))
            .expect(method);
        let alloc = u128::try_from(p.alloc.0.clone()).unwrap();
        println!(
            "{name:<28} {:>12.1} {:>14}",
            alloc as f64 / iters as f64,
            p.instructions / iters
        );
    }

    println!("\n[profile] done.");
}
