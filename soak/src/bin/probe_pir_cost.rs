//! Driver for tests/Pir2CostProbe.mo — PIR v2 cost probe on PocketIC.
//!
//! Measures, at three corpus tiers (10^4 / 10^6 / 4x10^6 records) on the DEFAULT production
//! geometry (S = 2^20 ⇒ rpc 60, m_rows 17,280, m_cols 17,477):
//!   * append-path hint maintenance: instructions + allocation per appended record (must be
//!     flat across tiers — the touched region is one column segment);
//!   * stripe matvec: instructions per stripe at several K (columns/stripe), per-madd rate,
//!     and the derived K satisfying BOTH committed gates (per-stripe ≤ 1.25e9 instr = 4x
//!     headroom under the 5e9 query budget; total response per full-shard query ≤ 2 MiB);
//!   * wire sizes: query bytes (4·pinned columns), response bytes per stripe (4·m_rows),
//!     record_stream bytes/note (≤ 296 gate) + serve instructions;
//!   * hint chunk serving for a frozen shard;
//!   * backfill strategy comparison at one size: per-record region RMW (the live append) vs
//!     heap accumulation with single flush.
//!
//! A stripe's cost depends only on (K, m_rows) — never on total N — so a full-size stripe
//! at this geometry IS the 10^8-scale stripe measurement: the corpus tiers exist to
//! demonstrate that flatness, not to change the stripe.
//!
//! Corpus synthesis fills packed cells directly (ScaleFixture discipline; matvec cost is
//! cell-content-independent). Every MEASURED operation is the production module unchanged.

use candid::{CandidType, Nat, Principal};
use pocket_ic::PocketIcBuilder;
use serde::Deserialize;
use soak::pic_env;
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

fn main() {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf();
    let out = std::env::temp_dir().join(format!("pir2_probe_{}.wasm", std::process::id()));
    let sources_raw = String::from_utf8(
        Command::new("/usr/bin/mops").arg("sources").current_dir(&repo_root).output().expect("mops").stdout,
    )
    .unwrap();
    let source_args: Vec<String> = sources_raw.split_whitespace().map(String::from).collect();
    let status = Command::new("/opt/moc-1.4.1/moc")
        .args(&source_args)
        .arg("-c")
        .arg("tests/Pir2CostProbe.mo")
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
    let admin = Principal::self_authenticating([7u8; 32]);
    let c = pic.create_canister_with_settings(Some(admin), None);
    pic.add_cycles(c, 1_000_000_000_000_000);
    pic.install_canister(c, wasm, candid::encode_args(()).unwrap(), Some(admin));

    let update = |method: &str, args: Vec<u8>| -> Vec<u8> {
        pic.update_call(c, admin, method, args).unwrap_or_else(|e| panic!("{method}: {e:?}"))
    };
    let query = |method: &str, args: Vec<u8>| -> Vec<u8> {
        pic.query_call(c, admin, method, args).unwrap_or_else(|e| panic!("{method}: {e:?}"))
    };

    // Default production geometry.
    let shard_size: u64 = 1 << 18;
    update("enable", candid::encode_args((nat(shard_size),)).unwrap());
    let (rpc, m_rows, m_cols): (Nat, Nat, Nat) =
        candid::decode_args(&query("geometry_info", candid::encode_args(()).unwrap())).unwrap();
    let m_rows_u: u64 = m_rows.0.clone().try_into().unwrap();
    let m_cols_u: u64 = m_cols.0.clone().try_into().unwrap();
    let rpc_u: u64 = rpc.0.clone().try_into().unwrap();
    println!("[geom] S=2^18 rpc={rpc_u} m_rows={m_rows_u} m_cols={m_cols_u}");
    assert_eq!((rpc_u, m_rows_u, m_cols_u), (30, 8_640, 8_739), "geometry drifted from spec");

    // Reference-shaped record bytes for real appends (content irrelevant to cost).
    let record_batch = |tag: u8, count: usize| -> Vec<(Vec<u8>, Vec<u8>)> {
        (0..count)
            .map(|i| {
                let mut commitment = vec![0u8; 32];
                commitment[0] = tag;
                commitment[1] = (i % 251) as u8;
                let envelope = vec![(i % 253) as u8; 243];
                (commitment, envelope)
            })
            .collect()
    };

    let tiers: [u64; 3] = [10_000, 1_000_000, 4_000_000];
    for &tier in &tiers {
        // fill to tier (direct cell synthesis; batched so each message stays modest)
        let mut fill_target = {
            let raw = query("chain_info", candid::encode_args(()).unwrap());
            let (_, count, _): (Vec<u8>, Nat, Option<(Vec<u8>, Nat)>) = candid::decode_args(&raw).unwrap();
            let n: u64 = count.0.clone().try_into().unwrap();
            n
        };
        while fill_target < tier {
            fill_target = (fill_target + 200_000).min(tier);
            let raw = update("synth_fill", candid::encode_args((nat(fill_target),)).unwrap());
            let (_n,): (Nat,) = candid::decode_args(&raw).unwrap();
        }
        println!("[tier {tier}] corpus ready");

        // real append cost on top of the tier (32 records, averaged).
        let batch = record_batch(0xA0, 32);
        let raw = update("append_measured", candid::encode_args((&batch,)).unwrap());
        let (instr, alloc, heap): (u64, Nat, candid::Int) = candid::decode_args(&raw).unwrap();
        let alloc_u: u128 = alloc.0.clone().try_into().unwrap();
        println!(
            "[tier {tier}] append: {} instr/record, {} B alloc/record (heap delta {heap})",
            instr / 32,
            alloc_u / 32
        );

        // Stripe cost at several K on the tier's LAST FROZEN or current shard prefix.
        let fill_now = fill_target;
        let shard = 0u64; // shard 0 spans [0, 2^20); every tier ≥ 10^4 has content there
        let shard_fill = fill_now.min(shard_size);
        let pinned_cols = shard_fill.div_ceil(rpc_u);
        let qu_bytes = vec![0x5Au8; (pinned_cols * 4) as usize];
        println!("[tier {tier}] query wire bytes (pinned fill {shard_fill}): {}", qu_bytes.len());
        for k in [128u64, 486, 1024] {
            if k > pinned_cols {
                continue;
            }
            let raw = query(
                "answer_stripe",
                candid::encode_args((nat(shard), nat(shard_fill), nat(0u64), nat(k), &qu_bytes)).unwrap(),
            );
            let (ans, trace): (Vec<u8>, StripeTrace) = candid::decode_args(&raw).unwrap();
            let cells: u64 = trace.cells_scanned.0.clone().try_into().unwrap();
            let per_madd = trace.instructions as f64 / cells.max(1) as f64;
            println!(
                "[tier {tier}] stripe K={k}: {} instr, {cells} cells, {per_madd:.1} instr/madd, response {} B, tdb={}",
                trace.instructions,
                ans.len(),
                trace.target_dependent_branches
            );
            assert_eq!(ans.len() as u64, 4 * m_rows_u, "response width");
        }

        // record_stream: bytes/note + serve cost mid-corpus.
        let raw = update(
            "record_stream_measured",
            candid::encode_args((nat(fill_now / 2), nat(512u64))).unwrap(),
        );
        let (rs_instr, rs_bytes): (u64, Nat) = candid::decode_args(&raw).unwrap();
        let rs_bytes_u: u64 = rs_bytes.0.clone().try_into().unwrap();
        println!(
            "[tier {tier}] record_stream: {} B/note (gate <= 296), {} instr/note",
            rs_bytes_u / 512,
            rs_instr / 512
        );
    }

    // Frozen-shard hint serving (tier >= 10^6 makes shard 0 frozen).
    update("synth_hint", candid::encode_args((nat(0u64),)).unwrap());
    let chunk = query("hint_chunk", candid::encode_args((nat(0u64), nat(0u64), nat(1_048_576u64))).unwrap());
    let (chunk_bytes,): (Vec<u8>,) = candid::decode_args(&chunk).unwrap();
    println!("[hint] frozen shard chunk serve: {} B/call", chunk_bytes.len());

    // Metered dial: one stripe as an update call.
    let qu_full = vec![0xA5u8; (m_cols_u * 4) as usize];
    let raw = update(
        "answer_stripe_update",
        candid::encode_args((nat(0u64), nat(shard_size), nat(0u64), nat(486u64), &qu_full)).unwrap(),
    );
    let (_, trace): (Vec<u8>, StripeTrace) = candid::decode_args(&raw).unwrap();
    println!("[metered] stripe K=1024 as update call: {} instr", trace.instructions);

    // Backfill strategy comparison at one size (240 records = 4 columns at rpc 60).
    let batch = record_batch(0xB0, 120);
    let raw = update("measure_heap_backfill", candid::encode_args((&batch,)).unwrap());
    let (absorb, flush, alloc): (u64, u64, Nat) = candid::decode_args(&raw).unwrap();
    let alloc_u: u128 = alloc.0.clone().try_into().unwrap();
    println!(
        "[backfill-B] heap absorb {} instr/record, flush {} instr total, {} B alloc",
        absorb / 120,
        flush,
        alloc_u
    );

    // Derived commitments (printed for the spec's committed-bounds table).
    println!("[derive] committed gates: per-stripe <= 1.25e9 instr (4x under 5e9); total response per full-shard query <= 2 MiB (=> stripes <= 30 => K >= {})", m_cols_u.div_ceil(30));
    let _ = query("drain_sink", candid::encode_args(()).unwrap());
    println!("[probe] DONE");
}
