//! PIR v2 differential oracle: the production Motoko server (src/Pir2.mo via
//! tests/Pir2CostProbe.mo) against the independent Rust reference (soak::pir2). Two phases:
//!
//!   PHASE 1 — append-fold identity: a real-append multi-shard corpus (through the production
//!     append path) whose per-shard hint H, packed cells D, and certified stream chain +
//!     boundary digests must be BYTE-IDENTICAL to the reference, with query round-trips.
//!
//!   PHASE 2 — query byte-identity at 144k scale: given phase 1's fold identity, the server's
//!     D and H are populated DIRECTLY from the reference (region-write speed, not 176M
//!     instr/record), then 1,000 seeded queries over the >=144k-record corpus are byte-compared
//!     stripe-for-stripe and round-tripped.
//!
//! Seeded/reproducible: SEED env (default 20260721); two-seed rule = two runs.

use candid::{CandidType, Nat, Principal};
use pocket_ic::PocketIcBuilder;
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::Deserialize;
use soak::pic_env;
use soak::pir2;
use std::path::PathBuf;
use std::process::Command;

#[derive(CandidType, Deserialize, Debug)]
struct StripeTrace {
    cells_scanned: Nat,
    columns_scanned: Nat,
    selector_decryptions: Nat,
    target_index_parameters: Nat,
    target_dependent_branches: Nat,
    instructions: u64,
}

fn nat(v: u64) -> Nat {
    Nat::from(v)
}

const P1_SHARD_SIZE: usize = 4096;
const P1_CORPUS: usize = 8_192;
const P2_SHARD_SIZE: usize = 4096;
const P2_CORPUS: usize = 144_000;
const QUERIES: usize = 1_000;

fn make_record(rng: &mut ChaCha20Rng, i: usize) -> ([u8; 32], Vec<u8>) {
    let mut commitment = [0u8; 32];
    rng.fill_bytes(&mut commitment);
    let envelope: Vec<u8> = match i % 997 {
        0 => vec![0xFF; pir2::ENVELOPE_BYTES],
        1 => vec![0xAB; 600],
        2 => Vec::new(),
        3 => vec![0u8; 243],
        _ => {
            let mut env = vec![0u8; if i % 2 == 0 { 235 } else { 243 }];
            rng.fill_bytes(&mut env);
            env
        }
    };
    (commitment, envelope)
}

fn compile_probe(repo_root: &PathBuf) -> Vec<u8> {
    let out = std::env::temp_dir().join(format!("pir2_diff_{}.wasm", std::process::id()));
    let sources_raw = String::from_utf8(
        Command::new("/usr/bin/mops").arg("sources").current_dir(repo_root).output().expect("mops").stdout,
    )
    .unwrap();
    let source_args: Vec<String> = sources_raw.split_whitespace().map(String::from).collect();
    let status = Command::new("/opt/moc-1.4.1/moc")
        .args(&source_args)
        .arg("-c")
        .arg("tests/Pir2CostProbe.mo")
        .arg("-o")
        .arg(&out)
        .current_dir(repo_root)
        .status()
        .expect("moc spawn");
    assert!(status.success(), "probe compile failed");
    std::fs::read(&out).expect("read probe wasm")
}

fn main() {
    let seed: u64 = std::env::var("SEED").ok().and_then(|s| s.parse().ok()).unwrap_or(20_260_721);
    println!("[diff] SEED={seed}");
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf();
    let wasm = compile_probe(&repo_root);
    let server = pic_env::spawn_server(&pic_env::resolve_pocket_ic_server());

    // ===== PHASE 1: append-fold identity =====
    {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let geometry = pir2::Geometry::for_shard_size(P1_SHARD_SIZE);
        let shard_count = P1_CORPUS.div_ceil(P1_SHARD_SIZE);
        let mut ref_shards: Vec<pir2::Shard> =
            (0..shard_count).map(|s| pir2::Shard::new(s as u64, geometry)).collect();
        let mut ref_chain = pir2::StreamChain::new();
        let mut records: Vec<[u8; pir2::RECORD_BYTES]> = Vec::with_capacity(P1_CORPUS);
        let mut corpus: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(P1_CORPUS);
        for i in 0..P1_CORPUS {
            let (commitment, envelope) = make_record(&mut rng, i);
            let record = pir2::pack_record(&commitment, &envelope);
            ref_shards[i / P1_SHARD_SIZE].append(&record);
            ref_chain.absorb(&record);
            records.push(record);
            corpus.push((commitment.to_vec(), envelope));
        }
        let pic = PocketIcBuilder::new()
            .with_server_url(server.url.clone())
            .with_application_subnet()
            .with_max_request_time_ms(Some(600_000))
            .build();
        let admin = Principal::self_authenticating([11u8; 32]);
        let c = pic.create_canister_with_settings(Some(admin), None);
        pic.add_cycles(c, 1_000_000_000_000_000);
        pic.install_canister(c, wasm.clone(), candid::encode_args(()).unwrap(), Some(admin));
        let update = |m: &str, a: Vec<u8>| pic.update_call(c, admin, m, a).unwrap_or_else(|e| panic!("{m}: {e:?}"));
        let query = |m: &str, a: Vec<u8>| pic.query_call(c, admin, m, a).unwrap_or_else(|e| panic!("{m}: {e:?}"));
        update("enable", candid::encode_args((nat(P1_SHARD_SIZE as u64),)).unwrap());
        for chunk in corpus.chunks(150) {
            update("bulk_append", candid::encode_args((&chunk.to_vec(),)).unwrap());
        }
        let (chain, count, boundary): (Vec<u8>, Nat, Option<(Vec<u8>, Nat)>) =
            candid::decode_args(&query("chain_info", candid::encode_args(()).unwrap())).unwrap();
        let count_u: usize = count.0.try_into().unwrap();
        assert_eq!(count_u, P1_CORPUS);
        assert_eq!(chain.as_slice(), ref_chain.chain.as_slice(), "P1 chain diverged");
        let (b_digest, _) = boundary.expect("boundary");
        assert_eq!(b_digest.as_slice(), ref_chain.boundaries.last().unwrap().as_slice(), "P1 boundary diverged");
        for shard in 0..shard_count {
            let total = geometry.m_rows * pir2::N * 4;
            let mut got = Vec::with_capacity(total);
            let mut off = 0;
            while off < total {
                let take = (total - off).min(1_900_000);
                let (part,): (Vec<u8>,) = candid::decode_args(&query(
                    "hint_chunk",
                    candid::encode_args((nat(shard as u64), nat(off as u64), nat(take as u64))).unwrap(),
                )).unwrap();
                got.extend_from_slice(&part);
                off += take;
            }
            assert_eq!(got, pir2::to_wire(&ref_shards[shard].h), "P1 hint diverged shard {shard}");
        }
        let (stream,): (Vec<u8>,) =
            candid::decode_args(&query("record_stream", candid::encode_args((nat(0), nat(512u64))).unwrap())).unwrap();
        let mut expect = Vec::new();
        for (i, record) in records[..512].iter().enumerate() {
            expect.extend_from_slice(&(i as u64).to_be_bytes());
            expect.extend_from_slice(record);
        }
        assert_eq!(stream, expect, "P1 record stream diverged");
        for &target in &[0usize, 4095, 4096, 8191] {
            let shard = target / P1_SHARD_SIZE;
            let in_shard = target % P1_SHARD_SIZE;
            let fill = ref_shards[shard].fill;
            let (c_star, r0) = geometry.place(in_shard);
            let secret = pir2::keygen(|| rng.next_u32());
            let qu = pir2::build_query(shard as u64, &geometry, fill, c_star, &secret, || rng.next_u32());
            let mut acc = vec![0u32; geometry.m_rows];
            let stripes = geometry.pinned_columns(fill).div_ceil(128);
            for s in 0..stripes {
                let (ans, trace): (Vec<u8>, StripeTrace) = candid::decode_args(&query(
                    "answer_stripe",
                    candid::encode_args((nat(shard as u64), nat(fill as u64), nat(s as u64), nat(128), &pir2::to_wire(&qu))).unwrap(),
                )).unwrap();
                assert_eq!(ans, pir2::to_wire(&ref_shards[shard].answer_stripe(fill, s, 128, &qu)), "P1 stripe diverged");
                let tdb: u64 = trace.target_dependent_branches.0.try_into().unwrap();
                assert_eq!(tdb, 0);
                for (a, p) in acc.iter_mut().zip(pir2::from_wire(&ans)) {
                    *a = a.wrapping_add(p);
                }
            }
            let got = pir2::decrypt_record(&acc, &ref_shards[shard].h, geometry.m_rows, r0, &secret);
            assert_eq!(got, records[target], "P1 round-trip failed target {target}");
        }
        println!("[diff] PHASE 1 PASS: {P1_CORPUS} real appends, {shard_count} shards - H/D/chain/boundary byte-identical, round-trips exact");
    }

    // ===== PHASE 2: query byte-identity at 144k scale =====
    {
        let mut rng = ChaCha20Rng::seed_from_u64(seed ^ 0x5CA1E);
        let geometry = pir2::Geometry::for_shard_size(P2_SHARD_SIZE);
        let shard_count = P2_CORPUS.div_ceil(P2_SHARD_SIZE);
        let mut ref_shards: Vec<pir2::Shard> =
            (0..shard_count).map(|s| pir2::Shard::new(s as u64, geometry)).collect();
        let mut records: Vec<[u8; pir2::RECORD_BYTES]> = Vec::with_capacity(P2_CORPUS);
        for i in 0..P2_CORPUS {
            let (commitment, envelope) = make_record(&mut rng, i);
            let record = pir2::pack_record(&commitment, &envelope);
            ref_shards[i / P2_SHARD_SIZE].append(&record);
            records.push(record);
        }
        println!("[diff] phase2 reference built ({shard_count} shards)");
        let pic = PocketIcBuilder::new()
            .with_server_url(server.url.clone())
            .with_application_subnet()
            .with_max_request_time_ms(Some(600_000))
            .build();
        let admin = Principal::self_authenticating([12u8; 32]);
        let c = pic.create_canister_with_settings(Some(admin), None);
        pic.add_cycles(c, 5_000_000_000_000_000);
        pic.install_canister(c, wasm, candid::encode_args(()).unwrap(), Some(admin));
        let update = |m: &str, a: Vec<u8>| pic.update_call(c, admin, m, a).unwrap_or_else(|e| panic!("{m}: {e:?}"));
        let query = |m: &str, a: Vec<u8>| pic.query_call(c, admin, m, a).unwrap_or_else(|e| panic!("{m}: {e:?}"));
        update("enable", candid::encode_args((nat(P2_SHARD_SIZE as u64),)).unwrap());
        let mut start = 0usize;
        while start < records.len() {
            let end = (start + 400).min(records.len());
            let batch: Vec<Vec<u8>> = records[start..end].iter().map(|r| r.to_vec()).collect();
            update("store_cells_bulk", candid::encode_args((nat(start as u64), &batch)).unwrap());
            start = end;
            if start % 20_000 < 400 {
                println!("[diff] phase2 stored {start} cells");
            }
        }
        for shard in 0..shard_count {
            let hint = pir2::to_wire(&ref_shards[shard].h);
            let mut off = 0;
            while off < hint.len() {
                let take = (hint.len() - off).min(1_900_000);
                update(
                    "store_hint",
                    candid::encode_args((nat(shard as u64), nat(off as u64), hint[off..off + take].to_vec())).unwrap(),
                );
                off += take;
            }
        }
        update("set_record_count", candid::encode_args((nat(P2_CORPUS as u64),)).unwrap());
        println!("[diff] phase2 populated {P2_CORPUS} records + {shard_count} hints");
        let mut widths = std::collections::BTreeSet::new();
        for qi in 0..QUERIES {
            let shard = rng.gen_range(0..shard_count);
            let fill = ref_shards[shard].fill;
            let in_shard = rng.gen_range(0..fill);
            let target = shard * P2_SHARD_SIZE + in_shard;
            let (c_star, r0) = geometry.place(in_shard);
            let secret = pir2::keygen(|| rng.next_u32());
            let qu = pir2::build_query(shard as u64, &geometry, fill, c_star, &secret, || rng.next_u32());
            let k = *[64usize, 128, 333, 1024].get(qi % 4).unwrap();
            widths.insert(k);
            let stripes = geometry.pinned_columns(fill).div_ceil(k);
            let mut acc = vec![0u32; geometry.m_rows];
            for s in 0..stripes {
                let (ans, trace): (Vec<u8>, StripeTrace) = candid::decode_args(&query(
                    "answer_stripe",
                    candid::encode_args((nat(shard as u64), nat(fill as u64), nat(s as u64), nat(k as u64), &pir2::to_wire(&qu))).unwrap(),
                )).unwrap();
                assert_eq!(ans, pir2::to_wire(&ref_shards[shard].answer_stripe(fill, s, k, &qu)), "P2 stripe diverged q{qi}");
                let tdb: u64 = trace.target_dependent_branches.0.try_into().unwrap();
                assert_eq!(tdb, 0);
                for (a, p) in acc.iter_mut().zip(pir2::from_wire(&ans)) {
                    *a = a.wrapping_add(p);
                }
            }
            let got = pir2::decrypt_record(&acc, &ref_shards[shard].h, geometry.m_rows, r0, &secret);
            assert_eq!(got, records[target], "P2 round-trip failed q{qi} target {target}");
            assert_eq!(&got[..32], &records[target][..32], "P2 commitment integrity q{qi}");
            if (qi + 1) % 200 == 0 {
                println!("[diff] phase2 {}/{QUERIES} queries byte-identical + round-tripped", qi + 1);
            }
        }
        println!("[diff] PHASE 2 PASS: {P2_CORPUS} records, {QUERIES} queries byte-identical (widths {widths:?})");

        // ===== PHASE 3 (S-1): cross-target INSTRUCTION-COUNT equality gate =====
        // §V2.4's auditable invariant says no branch on cell or query content; the trace's
        // `target_dependent_branches = 0` is a DECLARATION. This gate measures the claim:
        // for a fixed (shard, fill, stripe, kCols), the MEASURED `instructions` field must be
        // EXACTLY equal across queries with different targets and different ciphertext
        // content (committed threshold: max == min). Teeth: the probe's `answer_stripe_leaky`
        // (a deliberate branch-on-query-content variant) must produce UNEQUAL counts on the
        // same inputs — proving the gate detects the forbidden shape.
        let s1_shard = 3u64;
        let s1_fill = ref_shards[3].fill;
        let s1_k = 128u64;
        let s1_targets = [0usize, 1, 777, 2048, 4095];
        let mut gate = |method: &str| -> (u64, u64) {
            let mut min = u64::MAX;
            let mut max = 0u64;
            for (ti, &target) in s1_targets.iter().enumerate() {
                let (c_star, _) = geometry.place(target);
                let secret = pir2::keygen(|| rng.next_u32());
                let qu = pir2::build_query(s1_shard, &geometry, s1_fill, c_star, &secret, || rng.next_u32());
                let (_, trace): (Vec<u8>, StripeTrace) = candid::decode_args(&query(
                    method,
                    candid::encode_args((nat(s1_shard), nat(s1_fill as u64), nat(0), nat(s1_k), &pir2::to_wire(&qu))).unwrap(),
                )).unwrap();
                let instr = trace.instructions;
                println!("[diff] S1 {method} target#{ti} instructions={instr}");
                min = min.min(instr);
                max = max.max(instr);
            }
            (min, max)
        };
        let (pmin, pmax) = gate("answer_stripe");
        assert_eq!(
            pmin, pmax,
            "S1 GATE FAIL: production stripe instruction counts differ across targets ({pmin}..{pmax})"
        );
        println!("[diff] S1 PASS: production instruction count EXACTLY equal across {} targets ({pmin})", s1_targets.len());
        let (lmin, lmax) = gate("answer_stripe_leaky");
        assert_ne!(
            lmin, lmax,
            "S1 TEETH FAIL: the leaky variant produced equal instruction counts — the gate cannot detect the forbidden shape"
        );
        println!("[diff] S1 TEETH: leaky variant detected (instructions {lmin}..{lmax} differ across targets)");
    }
    println!("[diff] PASS SEED={seed}: fold identity + 144k-scale query byte-identity + S1 instruction-equality all green");
}
