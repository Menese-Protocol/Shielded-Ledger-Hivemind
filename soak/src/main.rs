use soak::{bench, keys, mint_guard, pic_env, runner};
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

fn load_keys(root: &PathBuf) -> keys::Keyset {
    let manifest_path = root.join("fixtures/pool-vectors-bls12-381/SETUP-MANIFEST.json");
    let manifest_json = std::fs::read_to_string(&manifest_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", manifest_path.display()));
    println!("[B1a] regenerating keyset from the deterministic setup (seed 20260712)...");
    match keys::regenerate_and_verify(&manifest_json) {
        Ok(k) => {
            println!("[B1a] PASS: regenerated pk/vk SHA-256 match SETUP-MANIFEST.json");
            k
        }
        Err(e) => {
            eprintln!("[B1a] FAIL: {e}");
            std::process::exit(1);
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("run");
    let root = repo_root();
    let keyset = load_keys(&root);

    match mode {
        "bench" => {
            let batch: usize =
                std::env::var("SOAK_BENCH_BATCH").ok().and_then(|v| v.parse().ok()).unwrap_or(96);
            println!("[bench] measuring native proving throughput (batch {batch})...");
            let r = bench::run(&keyset, batch);
            println!("[bench] cores available          : {}", r.cores);
            println!("[bench] deposit  single-core      : {:.1} ms  ({:.2}/s)", r.deposit_single_ms, 1000.0 / r.deposit_single_ms);
            println!("[bench] transfer single-core      : {:.1} ms  ({:.2}/s)", r.transfer_single_ms, 1000.0 / r.transfer_single_ms);
            println!("[bench] deposit  all-core         : {:.2} proofs/s", r.deposit_allcore_per_s);
            println!("[bench] transfer all-core         : {:.2} proofs/s", r.transfer_allcore_per_s);
            println!("[bench] projection: 100k transfer proofs all-core ~= {:.2} h", 100_000.0 / r.transfer_allcore_per_s / 3600.0);
        }
        "run" => {
            let started = std::time::Instant::now();
            let fixtures = root.join("fixtures/pool-vectors-bls12-381");
            println!("[B1b] verifying frozen fixture proofs under the regenerated keys...");
            keys::verify_frozen_fixtures(&fixtures, &keyset)
                .unwrap_or_else(|e| panic!("[B1b] FAIL: {e}"));
            println!("[B1b] PASS: frozen deposit + transfer proofs verify; frozen tampered proof rejected");

            println!("[A2] native counterfeit-mint circuit checks...");
            let mg = mint_guard::native_counterfeit_check();
            assert!(mg.imbalance_unsatisfiable, "A2: imbalanced counterfeit satisfied the circuit");
            assert!(mg.wrap_unsatisfiable_with_range, "A2: field-wrap mint satisfied the real circuit");
            assert!(mg.wrap_satisfiable_without_range, "A2: no-range variant must satisfy (range check is the defense)");
            println!("[A2] PASS: counterfeit witnesses UNSATISFIABLE; range check shown load-bearing");

            println!("[build] compiling canisters and hashing wasms...");
            let wasms = pic_env::build_wasms(&root, &root.join("soak/target/wasms"));
            println!("[build] moc {} ({})", wasms.moc_version, wasms.moc_path);
            println!("[build] zk_ledger.wasm          sha256 {}", wasms.ledger_sha256);
            println!("[build] icp_ledger_fixture.wasm sha256 {}", wasms.token_sha256);
            println!("[build] tree_oracle_bls.wasm    sha256 {}", wasms.tree_oracle_sha256);

            let tier = runner::TierConfig::from_env();
            println!(
                "[tier] label={} accounts={} ops={} seed={} upgrades>={} batch={}",
                tier.label, tier.accounts, tier.ops, tier.seed, tier.upgrades, tier.batch
            );
            let mut r = runner::Runner::new(tier.clone(), keyset, &wasms);
            let executed = r.run();
            let (battery, state_hash, blocks) = r.verify_full();

            let report = runner::RunReport {
                label: tier.label.clone(),
                seed: tier.seed,
                accounts: tier.accounts,
                ops_requested: tier.ops,
                ops_executed: executed,
                accepted_shields: r.counters.shields,
                accepted_private_transfers: r.counters.private_transfers,
                accepted_unshields: r.counters.unshields,
                fault_recoveries_shield: r.counters.fault_shield,
                fault_recoveries_unshield: r.counters.fault_unshield,
                injections_total: r.counters.injections,
                injections_rejected: r.counters.injections_rejected,
                injection_counts: {
                    let mut counts: Vec<(String, u64)> = r
                        .injection_counts
                        .iter()
                        .map(|(k, v)| (format!("{k:?}"), *v))
                        .collect();
                    counts.sort();
                    counts
                },
                injection_transcripts: r.report_injections.clone(),
                upgrades_performed: r.upgrades_done.len() as u64,
                upgrade_positions: r.upgrades_done.clone(),
                blocks,
                notes_created: r.model.notes.len() as u64,
                notes_spent: r.model.spent_count() as u64,
                final_pool_value: r.model.pool_value,
                final_custody: r.model.pool_custody,
                total_unspent_value: r.model.total_unspent(),
                state_hash: state_hash.clone(),
                wall_clock_seconds: started.elapsed().as_secs_f64(),
                ledger_wasm_sha256: wasms.ledger_sha256.clone(),
                token_wasm_sha256: wasms.token_sha256.clone(),
                tree_oracle_wasm_sha256: wasms.tree_oracle_sha256.clone(),
                moc_version: wasms.moc_version.clone(),
                battery,
            };
            let out_dir = root.join("soak/results");
            std::fs::create_dir_all(&out_dir).expect("create results dir");
            let out_path = out_dir.join(format!("{}-seed{}.json", tier.label, tier.seed));
            std::fs::write(&out_path, serde_json::to_string_pretty(&report).unwrap())
                .expect("write report");

            // the run completed: clear the durable checkpoint so a future rerun starts fresh
            let _ = std::fs::remove_file(&tier.checkpoint_file);
            let _ = std::fs::remove_dir_all(&tier.state_dir);

            println!("=== SOAK COMPLETE ===");
            println!("tier        : {} ({} accounts / {} ops)", tier.label, tier.accounts, executed);
            println!("SEED        : {}", tier.seed);
            println!("STATE-HASH  : {state_hash}");
            println!("wall clock  : {:.1}s", started.elapsed().as_secs_f64());
            println!("report      : {}", out_path.display());
        }
        other => {
            eprintln!("unknown mode: {other} (expected: run | bench)");
            std::process::exit(2);
        }
    }
}
