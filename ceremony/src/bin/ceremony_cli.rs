//! Local Phase-2 ceremony driver / simulator.
//!
//! This is the operator + battery tool. It can generate a test-tier SRS, initialize a ceremony,
//! simulate honest contributions locally (sampling and destroying each secret in-process — the real
//! contributor client D2 does this in the browser instead), finalize with a public beacon, verify
//! the transcript with the standalone verifier core, and export the final arkworks keys plus a
//! provenance manifest.
//!
//! It is NOT the coordinator: the coordinator is the Motoko canister. This exists so the whole
//! Phase-2 protocol can be exercised as pure crypto, without standing up a replica and many
//! browsers, and to produce transcripts and keys for the battery.
//!
//! Subcommands:
//!   gen-srs   <power> <out.srs.bin>                 real test-tier powers of tau (not-real-value)
//!   init      <srs.bin> <out.transcript.bin>        derive initial params, write empty transcript
//!   contribute <srs.bin> <transcript.bin> <id-hex>  simulate one honest contribution (append)
//!   finalize  <srs.bin> <transcript.bin> <beacon>   apply the public beacon and freeze
//!   verify    <srs.bin> <transcript.bin>            replay + full verification (delegates to D4 core)
//!   export    <srs.bin> <transcript.bin> <outdir>   write final keys, vks, hashes, SETUP-MANIFEST
//!   run       <power> <n> <outdir>                  end-to-end: gen-srs, n contributions, beacon,
//!                                                    verify, export (the battery one-shot)

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ceremony::session::*;
use ceremony::srs::{Phase1Srs, SrsProvenance};
use ceremony::transcript::Transcript;
use rand::SeedableRng;
use std::process::exit;

fn write_obj<T: CanonicalSerialize>(path: &str, x: &T) {
    let mut b = Vec::new();
    x.serialize_compressed(&mut b).unwrap();
    std::fs::write(path, &b).unwrap_or_else(|e| die(&format!("write {path}: {e}")));
    eprintln!("wrote {path} ({} bytes)", b.len());
}
fn read_obj<T: CanonicalDeserialize>(path: &str) -> T {
    let b = std::fs::read(path).unwrap_or_else(|e| die(&format!("read {path}: {e}")));
    T::deserialize_compressed(&b[..]).unwrap_or_else(|e| die(&format!("parse {path}: {e:?}")))
}
fn die(msg: &str) -> ! {
    eprintln!("error: {msg}");
    exit(2)
}

/// Deterministic-but-independent entropy for the local simulator. NOT for real contributions: real
/// contributors sample from the browser CSPRNG. Seeding from OS entropy here keeps simulator runs
/// non-reproducible by design (a real secret must be unpredictable), matching os-csprng tiers.
fn sim_rng() -> rand_chacha::ChaCha20Rng {
    let mut seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
    rand_chacha::ChaCha20Rng::from_seed(seed)
}

fn cmd_gen_srs(power: u32, out: &str) {
    if power < 10 || power > 20 {
        die("power out of the sane range [10,20]");
    }
    eprintln!("generating test-tier powers of tau, power {power} (n={}) ...", 1u64 << power);
    let mut r = sim_rng();
    let srs = Phase1Srs::generate_test_tier(power, &mut r);
    eprintln!("structure_check (sampled indices) ...");
    let n = srs.n();
    let idx: Vec<usize> = [1usize, 2, n / 2, n - 1, n, n + 1, 2 * n - 2]
        .into_iter()
        .filter(|&i| i < srs.tau_g1.len())
        .collect();
    srs.structure_check(&idx).unwrap_or_else(|e| die(&e));
    eprintln!("SRS SHA-256: {}", srs.sha256_hex());
    write_obj(out, &srs);
}

fn cmd_init(srs_path: &str, out: &str) {
    let srs: Phase1Srs = read_obj(srs_path);
    let init = CeremonyInit::from_srs(&srs).unwrap_or_else(|e| die(&e));
    let t = init.empty_transcript();
    eprintln!(
        "initial transfer h/l = {}/{}, deposit h/l = {}/{}",
        init.transfer_initial.h_query.len(),
        init.transfer_initial.l_query.len(),
        init.deposit_initial.h_query.len(),
        init.deposit_initial.l_query.len()
    );
    write_obj(out, &t);
}

fn cmd_contribute(srs_path: &str, t_path: &str, id_hex: &str) {
    let srs: Phase1Srs = read_obj(srs_path);
    let init = CeremonyInit::from_srs(&srs).unwrap_or_else(|e| die(&e));
    let mut t: Transcript = read_obj(t_path);
    let id = hex::decode(id_hex).unwrap_or_else(|_| die("id must be hex"));
    let ts = t.contributions.len() as u64 + 1;
    let mut r = sim_rng();
    simulate_contribution(&init, &mut t, id, ts, &mut r).unwrap_or_else(|e| die(&e));
    eprintln!("appended contribution #{}", t.contributions.len());
    write_obj(t_path, &t);
}

fn cmd_finalize(srs_path: &str, t_path: &str, beacon: &str) {
    let srs: Phase1Srs = read_obj(srs_path);
    let init = CeremonyInit::from_srs(&srs).unwrap_or_else(|e| die(&e));
    let mut t: Transcript = read_obj(t_path);
    let mut r = sim_rng();
    finalize_with_beacon(&init, &mut t, beacon.as_bytes().to_vec(), &mut r)
        .unwrap_or_else(|e| die(&e));
    eprintln!("finalized with beacon {beacon:?}");
    write_obj(t_path, &t);
}

fn cmd_verify(srs_path: &str, t_path: &str) {
    let srs: Phase1Srs = read_obj(srs_path);
    let t: Transcript = read_obj(t_path);
    match verify_full_transcript(&srs, &t) {
        Ok((keys, rep)) => {
            println!("TRANSCRIPT VALID: {} honest, finalized={}", rep.honest_contributions, rep.finalized);
            println!("  transfer vk SHA-256: {}", rep.transfer_vk_sha256);
            println!("  deposit  vk SHA-256: {}", rep.deposit_vk_sha256);
            eprint!("key self-check ... ");
            selfcheck_keys_work(&keys).unwrap_or_else(|e| die(&e));
            println!("KEYS WORK");
        }
        Err(e) => {
            println!("TRANSCRIPT INVALID: {e}");
            exit(1);
        }
    }
}

fn cmd_export(srs_path: &str, t_path: &str, outdir: &str) {
    let srs: Phase1Srs = read_obj(srs_path);
    let t: Transcript = read_obj(t_path);
    let (keys, rep) = verify_full_transcript(&srs, &t).unwrap_or_else(|e| die(&e));
    std::fs::create_dir_all(outdir).unwrap();

    let write_bin = |name: &str, pk: &ark_groth16::ProvingKey<ark_bls12_381::Bls12_381>| {
        let mut b = Vec::new();
        pk.serialize_uncompressed(&mut b).unwrap();
        std::fs::write(format!("{outdir}/{name}"), &b).unwrap();
        eprintln!("wrote {outdir}/{name} ({} bytes)", b.len());
    };
    let write_vk_hex = |name: &str, pk: &ark_groth16::ProvingKey<ark_bls12_381::Bls12_381>| {
        let mut b = Vec::new();
        pk.vk.serialize_compressed(&mut b).unwrap();
        std::fs::write(format!("{outdir}/{name}"), hex::encode(&b)).unwrap();
    };
    write_bin("transfer_pk.bin", &keys.transfer_pk);
    write_bin("deposit_pk.bin", &keys.deposit_pk);
    write_vk_hex("transfer_vk.hex", &keys.transfer_pk);
    write_vk_hex("deposit_vk.hex", &keys.deposit_pk);

    let is_real = srs.provenance == SrsProvenance::InheritedReviewedPhase1 && rep.honest_contributions >= 1;
    let manifest = format!(
        concat!(
            "{{\n",
            "  \"format\": 2,\n",
            "  \"proof_system\": \"Groth16\",\n",
            "  \"curve\": \"BLS12-381\",\n",
            "  \"phase2_ceremony\": true,\n",
            "  \"phase1_provenance\": \"{}\",\n",
            "  \"srs_sha256\": \"{}\",\n",
            "  \"honest_contributions\": {},\n",
            "  \"finalized_with_beacon\": {},\n",
            "  \"multi_party_ceremony\": {},\n",
            "  \"real_value_eligible\": {},\n",
            "  \"transfer_vk_sha256\": \"{}\",\n",
            "  \"deposit_vk_sha256\": \"{}\",\n",
            "  \"note\": \"real_value_eligible requires an inherited reviewed Phase-1 SRS and an independently verified transcript; a test-tier SRS is never real-value eligible.\"\n",
            "}}\n"
        ),
        match srs.provenance {
            SrsProvenance::TestTierKnownSecret => "test-tier-known-secret",
            SrsProvenance::InheritedReviewedPhase1 => "inherited-reviewed-phase1",
        },
        srs.sha256_hex(),
        rep.honest_contributions,
        rep.finalized,
        rep.honest_contributions >= 1,
        is_real,
        rep.transfer_vk_sha256,
        rep.deposit_vk_sha256,
    );
    std::fs::write(format!("{outdir}/SETUP-MANIFEST.json"), &manifest).unwrap();
    eprintln!("wrote {outdir}/SETUP-MANIFEST.json");
    println!("EXPORT OK: transfer_vk {} deposit_vk {}", rep.transfer_vk_sha256, rep.deposit_vk_sha256);
}

fn cmd_import_ptau(response_path: &str, header_len: u64, src_power: u32, target_power: u32, url: &str, out_srs: &str, out_prov: &str) {
    eprintln!("ingesting inherited Phase-1 from {response_path} (src power {src_power} -> target {target_power}) ...");
    eprintln!("running FULL structure_check; will REFUSE on any failure ...");
    match ceremony::phase1_import::import_and_record(
        response_path,
        header_len,
        src_power,
        target_power,
        url,
        vec!["see published Zcash Sapling MPC attestation set".to_string()],
    ) {
        Ok((srs, prov)) => {
            write_obj(out_srs, &srs);
            std::fs::write(out_prov, prov.to_json()).unwrap();
            eprintln!("wrote {out_prov}");
            println!("PHASE-1 INGESTED + VERIFIED");
            println!("  response file SHA-256: {}", prov.response_file_sha256);
            println!("  extracted SRS SHA-256: {}", prov.srs_sha256);
        }
        Err(e) => die(&e),
    }
}

fn cmd_run(power: u32, n: usize, outdir: &str) {
    std::fs::create_dir_all(outdir).unwrap();
    let srs_path = format!("{outdir}/phase1.srs.bin");
    let t_path = format!("{outdir}/transcript.bin");
    cmd_gen_srs(power, &srs_path);
    cmd_init(&srs_path, &t_path);
    for i in 0..n {
        let id = format!("{:02x}{:02x}", 0xc0 + i, i);
        cmd_contribute(&srs_path, &t_path, &id);
    }
    cmd_finalize(&srs_path, &t_path, "local-battery-beacon:bitcoin-block-900000");
    cmd_verify(&srs_path, &t_path);
    cmd_export(&srs_path, &t_path, outdir);
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 2 {
        eprintln!(
            "usage:\n  ceremony-cli gen-srs <power> <out.srs.bin>\n  ceremony-cli init <srs> <out.transcript>\n  ceremony-cli contribute <srs> <transcript> <id-hex>\n  ceremony-cli finalize <srs> <transcript> <beacon>\n  ceremony-cli verify <srs> <transcript>\n  ceremony-cli export <srs> <transcript> <outdir>\n  ceremony-cli run <power> <n> <outdir>"
        );
        exit(2);
    }
    match a[1].as_str() {
        "gen-srs" if a.len() == 4 => cmd_gen_srs(a[2].parse().unwrap_or_else(|_| die("bad power")), &a[3]),
        "init" if a.len() == 4 => cmd_init(&a[2], &a[3]),
        "contribute" if a.len() == 5 => cmd_contribute(&a[2], &a[3], &a[4]),
        "finalize" if a.len() == 5 => cmd_finalize(&a[2], &a[3], &a[4]),
        "verify" if a.len() == 4 => cmd_verify(&a[2], &a[3]),
        "export" if a.len() == 5 => cmd_export(&a[2], &a[3], &a[4]),
        "run" if a.len() == 5 => cmd_run(
            a[2].parse().unwrap_or_else(|_| die("bad power")),
            a[3].parse().unwrap_or_else(|_| die("bad n")),
            &a[4],
        ),
        // import-ptau <response-file> <header-len> <src-power> <target-power> <url> <out.srs.bin> <out-prov.json>
        "import-ptau" if a.len() == 9 => cmd_import_ptau(
            &a[2],
            a[3].parse().unwrap_or_else(|_| die("bad header-len")),
            a[4].parse().unwrap_or_else(|_| die("bad src-power")),
            a[5].parse().unwrap_or_else(|_| die("bad target-power")),
            &a[6],
            &a[7],
            &a[8],
        ),
        _ => die("bad arguments; run with no args for usage"),
    }
}
