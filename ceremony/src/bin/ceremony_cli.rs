//! Local Phase-2 ceremony driver / simulator.
//!
//! This is the local driver + battery tool. It can generate a test-tier SRS, initialize a ceremony,
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
//!   emit-initial <transcript.bin> <outdir>          write the upload_initial_chunk wire payloads
//!   assemble-transcript <srs> <parts> <out>         build a transcript from a LIVE coordinator
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

/// Write the two initial delta-parameter blobs in the coordinator's wire format.
///
/// `upload_initial_chunk` consumes exactly these bytes and `finish_init` parses their lengths out
/// of the stream, but `delta_to_wire` had no caller anywhere in the tree, so the authority
/// launching a ceremony could not produce the payload the canister requires. This is the producer.
///
/// The layout is the one `Main.mo`'s `expectedLen`/`parseLens` decode:
///   delta_g1 (96) | delta_g2 (192) | hLen u32 BE | h_query (hLen * 96) | lLen u32 BE | l (lLen * 96)
fn cmd_emit_initial(t_path: &str, outdir: &str) {
    let t: Transcript = read_obj(t_path);
    std::fs::create_dir_all(outdir).unwrap();
    // Deliberately NOT verified here: these are the transcript's OWN initial parameters, the
    // starting point a verifier re-derives independently from the SRS and the circuits. Run
    // `verify` (or verify-transcript) for that judgement; this command only serializes.
    let write = |name: &str, d: &ceremony::transcript::DeltaParams| {
        let bytes = ceremony::transcript::delta_to_wire(d);
        std::fs::write(format!("{outdir}/{name}"), &bytes).unwrap();
        eprintln!("wrote {outdir}/{name} ({} bytes)", bytes.len());
    };
    write("transfer_initial.wire", &t.transfer_initial);
    write("deposit_initial.wire", &t.deposit_initial);
    eprintln!(
        "these are the upload_initial_chunk payloads; the coordinator must already be configured \
         for power {}",
        t.power
    );
}

/// Assemble a verifiable transcript from a LIVE coordinator's exported parts.
///
/// The standalone verifier is the whole soundness story of this ceremony — docs/CEREMONY.md §5
/// tells every participant and observer to run it — but nothing could turn a deployed
/// coordinator's state into a transcript, so it could only ever verify what the local simulator
/// produced. This is that missing half. The network side stays out of this crate deliberately
/// (`ceremony` carries no agent dependency and is offline by design): a small client downloads the
/// canister's bytes into a parts directory, and this command turns them into a transcript.
///
/// The fixed and initial parameters are taken from the SRS, NOT from the parts, because the SRS is
/// the authority — and the canister's own initial deltas are then compared against the SRS-derived
/// ones and REFUSED on mismatch. That check is the point: it proves the deployed coordinator was
/// initialized with the parameters this SRS implies, which no amount of transcript replay could
/// establish on its own.
///
/// Parts layout (written by scripts/export-live-ceremony.mjs):
///   manifest.tsv          header line `power<TAB>finalized`, then one line per contribution
///   initial_transfer.wire, initial_deposit.wire
///   c<i>_transfer.wire,    c<i>_deposit.wire
fn cmd_assemble_transcript(srs_path: &str, parts: &str, out: &str) {
    use ceremony::transcript::{delta_from_wire, pok_from_wire, CircuitContribution, Contribution};

    let srs: Phase1Srs = read_obj(srs_path);
    let init = CeremonyInit::from_srs(&srs).unwrap_or_else(|e| die(&e));
    let mut t = init.empty_transcript();

    let read_wire = |name: &str| -> Vec<u8> {
        std::fs::read(format!("{parts}/{name}"))
            .unwrap_or_else(|e| die(&format!("read {parts}/{name}: {e}")))
    };
    let unhex = |s: &str, what: &str| -> Vec<u8> {
        hex::decode(s).unwrap_or_else(|_| die(&format!("{what} is not hex")))
    };

    // The coordinator's initial parameters must be the ones this SRS derives.
    for (name, want) in [
        ("initial_transfer.wire", &init.transfer_initial),
        ("initial_deposit.wire", &init.deposit_initial),
    ] {
        let got = delta_from_wire(&read_wire(name)).unwrap_or_else(|e| die(&e));
        if &got != want {
            die(&format!(
                "{name} does not match the initial parameters derived from {srs_path} — the \
                 coordinator was initialized from a different SRS or a different circuit"
            ));
        }
    }
    eprintln!("initial parameters match the SRS-derived ones");

    let manifest = std::fs::read_to_string(format!("{parts}/manifest.tsv"))
        .unwrap_or_else(|e| die(&format!("read manifest.tsv: {e}")));
    let mut lines = manifest.lines();
    let header: Vec<&str> = lines.next().unwrap_or_else(|| die("empty manifest")).split('\t').collect();
    if header.len() != 2 {
        die("manifest header must be `power<TAB>finalized`");
    }
    let power: u32 = header[0].parse().unwrap_or_else(|_| die("bad power in manifest"));
    if power != t.power {
        die(&format!("manifest power {power} != SRS power {}", t.power));
    }
    t.finalized = header[1] == "true";

    for (n, line) in lines.filter(|l| !l.trim().is_empty()).enumerate() {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() != 11 {
            die(&format!("contribution line {n} must have 11 tab-separated fields"));
        }
        let idx: usize = f[0].parse().unwrap_or_else(|_| die("bad index"));
        if idx != n {
            die(&format!("contribution indices must be dense and ordered; got {idx} at position {n}"));
        }
        let mk = |circuit: &str, a: &str, b: &str, c: &str| -> CircuitContribution {
            let delta = delta_from_wire(&read_wire(&format!("c{n}_{circuit}.wire")))
                .unwrap_or_else(|e| die(&format!("c{n}_{circuit}: {e}")));
            let pok = pok_from_wire(
                &unhex(a, "s_g1"), &unhex(b, "s_delta_g1"), &unhex(c, "r_delta_g2"),
            )
            .unwrap_or_else(|e| die(&format!("c{n}_{circuit} pok: {e}")));
            CircuitContribution { delta, pok }
        };
        t.contributions.push(Contribution {
            contributor: unhex(f[1], "contributor"),
            timestamp: f[2].parse().unwrap_or_else(|_| die("bad timestamp")),
            is_beacon: f[3] == "true",
            beacon: unhex(f[4], "beacon"),
            transfer: mk("transfer", f[5], f[6], f[7]),
            deposit: mk("deposit", f[8], f[9], f[10]),
        });
    }

    eprintln!("assembled {} contribution(s), finalized={}", t.contributions.len(), t.finalized);
    write_obj(out, &t);
    eprintln!("now verify it: verify-transcript {srs_path} {out} --selfcheck");
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

    // A ceremony is only as strong as the number of INDEPENDENT parties who destroyed their
    // secret, and docs/TRUSTED-SETUP-POLICY.md requires "multiple independent operators on
    // separately controlled machines". These flags were previously computed as
    // `honest_contributions >= 1`, which made a ONE-party ceremony describe itself as
    // `multi_party_ceremony: true`. The floor below makes that prose executable, and it is
    // deliberately the same number the frontend production gate enforces
    // (demo-frontend/scripts/verify-keyset.mjs, MIN_HONEST_CONTRIBUTIONS). If the two ever
    // disagree, the GATE is authoritative: it re-derives the count from the verifier's own
    // output, whereas this manifest is a hand-editable file that authorises nothing.
    const MIN_HONEST_CONTRIBUTIONS: usize = 5;

    let multi_party = rep.honest_contributions >= MIN_HONEST_CONTRIBUTIONS;
    // Real-value eligibility additionally requires the beacon. Without it the last contributor
    // knew the final parameters before anyone else did.
    let is_real = srs.provenance == SrsProvenance::InheritedReviewedPhase1
        && multi_party
        && rep.finalized;

    let sha256_file = |name: &str| -> String {
        use sha2::{Digest, Sha256};
        let bytes = std::fs::read(format!("{outdir}/{name}")).unwrap();
        hex::encode(Sha256::digest(&bytes))
    };
    // NOTE THE TWO DIFFERENT HASHES, because conflating them is a trap that already cost a
    // silently-unpassable production gate:
    //
    //   * `*_sha256` in the manifest is the hash of the FILE ON DISK -- for the vks that is the
    //     ASCII hex text, not the bytes it encodes. This is what the frontend gate's integrity
    //     loop recomputes, and what the shipped demo keyset has always used.
    //   * `ceremony.*_vk_sha256` is `ceremony::session::vk_sha256`, i.e.
    //     SHA256(vk.serialize_compressed()) -- the hash over the RAW BYTES that the transcript
    //     verifier prints and that docs/CEREMONY.md publishes.
    //
    // They can never be equal, one being the hash of the other's hex encoding. The gate needs
    // both: the first proves the artifact on disk is intact, the second binds it to a transcript.
    let transfer_pk_sha256 = sha256_file("transfer_pk.bin");
    let deposit_pk_sha256 = sha256_file("deposit_pk.bin");
    let transfer_vk_file_sha256 = sha256_file("transfer_vk.hex");
    let deposit_vk_file_sha256 = sha256_file("deposit_vk.hex");

    // `format: 1` and the pk hashes are not cosmetic. demo-frontend/scripts/verify-keyset.mjs is
    // the production gate, and it rejects any other format outright and hashes all FOUR artifacts
    // against the manifest. This exporter previously emitted `format: 2` with no pk hashes and no
    // `ceremony` block, so its output could not pass the gate at all: the two halves of the launch
    // had never been run against each other.
    let manifest = format!(
        concat!(
            "{{\n",
            "  \"format\": 1,\n",
            "  \"proof_system\": \"Groth16\",\n",
            "  \"curve\": \"BLS12-381\",\n",
            "  \"setup_mode\": \"multi-party-phase2-ceremony\",\n",
            "  \"publicly_reproducible_toxic_waste\": {},\n",
            "  \"phase2_ceremony\": true,\n",
            "  \"phase1_provenance\": \"{}\",\n",
            "  \"srs_sha256\": \"{}\",\n",
            "  \"honest_contributions\": {},\n",
            "  \"minimum_honest_contributions\": {},\n",
            "  \"finalized_with_beacon\": {},\n",
            "  \"multi_party_ceremony\": {},\n",
            "  \"real_value_eligible\": {},\n",
            "  \"transfer_pk_sha256\": \"{}\",\n",
            "  \"transfer_vk_sha256\": \"{}\",\n",
            "  \"deposit_pk_sha256\": \"{}\",\n",
            "  \"deposit_vk_sha256\": \"{}\",\n",
            "  \"ceremony\": {{\n",
            "    \"srs\": \"{}\",\n",
            "    \"transcript\": \"{}\",\n",
            "    \"transfer_vk_sha256\": \"{}\",\n",
            "    \"deposit_vk_sha256\": \"{}\"\n",
            "  }},\n",
            "  \"note\": \"real_value_eligible requires an inherited reviewed Phase-1 SRS, at least the minimum honest contributions, and a beacon finalize. It is a LABEL: the production gate re-verifies the transcript and ignores this field.\"\n",
            "}}\n"
        ),
        srs.provenance == SrsProvenance::TestTierKnownSecret,
        match srs.provenance {
            SrsProvenance::TestTierKnownSecret => "test-tier-known-secret",
            SrsProvenance::InheritedReviewedPhase1 => "inherited-reviewed-phase1",
        },
        srs.sha256_hex(),
        rep.honest_contributions,
        MIN_HONEST_CONTRIBUTIONS,
        rep.finalized,
        multi_party,
        is_real,
        transfer_pk_sha256,
        transfer_vk_file_sha256,
        deposit_pk_sha256,
        deposit_vk_file_sha256,
        std::path::Path::new(srs_path).file_name().unwrap().to_string_lossy(),
        std::path::Path::new(t_path).file_name().unwrap().to_string_lossy(),
        rep.transfer_vk_sha256,
        rep.deposit_vk_sha256,
    );
    std::fs::write(format!("{outdir}/SETUP-MANIFEST.json"), &manifest).unwrap();
    eprintln!("wrote {outdir}/SETUP-MANIFEST.json");

    // Export still emits keys below the floor, deliberately: the battery (`ceremony-cli run`) and
    // every local rehearsal produce short ceremonies, and a hard refusal here would break them
    // while buying nothing. Refusing is the PRODUCTION GATE's job, and it is strictly stronger --
    // it re-derives the count from the verifier rather than reading the field written here, so
    // hand-editing this file past the floor does not buy a deployment.
    if !is_real {
        eprintln!();
        eprintln!("*** NOT REAL-VALUE ELIGIBLE — these keys must not secure value ***");
        if rep.honest_contributions < MIN_HONEST_CONTRIBUTIONS {
            eprintln!("    honest contributions: {} (minimum {})",
                      rep.honest_contributions, MIN_HONEST_CONTRIBUTIONS);
        }
        if !rep.finalized {
            eprintln!("    not finalized with a beacon");
        }
        if srs.provenance == SrsProvenance::TestTierKnownSecret {
            eprintln!("    Phase-1 SRS is test-tier: its toxic waste is PUBLICLY KNOWN");
        }
    } else {
        eprintln!();
        eprintln!("real-value eligible. Before running the production gate, place the SRS and the");
        eprintln!("transcript alongside the keys, under the names this manifest records:");
        eprintln!("    cp {srs_path} {outdir}/");
        eprintln!("    cp {t_path} {outdir}/");
        eprintln!("    node demo-frontend/scripts/verify-keyset.mjs {outdir} --require-real-value");
    }
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
            "usage:\n  ceremony-cli gen-srs <power> <out.srs.bin>\n  ceremony-cli init <srs> <out.transcript>\n  ceremony-cli contribute <srs> <transcript> <id-hex>\n  ceremony-cli finalize <srs> <transcript> <beacon>\n  ceremony-cli verify <srs> <transcript>\n  ceremony-cli export <srs> <transcript> <outdir>\n  ceremony-cli emit-initial <transcript> <outdir>\n  ceremony-cli assemble-transcript <srs> <parts-dir> <out.transcript>\n  ceremony-cli run <power> <n> <outdir>"
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
        "emit-initial" if a.len() == 4 => cmd_emit_initial(&a[2], &a[3]),
        "assemble-transcript" if a.len() == 5 => cmd_assemble_transcript(&a[2], &a[3], &a[4]),
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
