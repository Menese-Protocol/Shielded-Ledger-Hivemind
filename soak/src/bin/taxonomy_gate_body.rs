// Included into taxonomy_gate.rs. Base-case generation, taxonomy, PocketIC harness, 3-way
// comparison, and teeth.

use ark_ff::{One, UniformRand};
use ark_std::rand::{rngs::StdRng, RngCore, SeedableRng};
use common::{derive_pk, note_commitment, poseidon_config, DenseTree, Note, PoseidonCfg};

/// Build a valid transfer circuit (honest 2-in/2-out), returning the ark vk/proof/inputs.
fn valid_case() -> (VerifyingKey<Bls12_381>, Proof<Bls12_381>, Vec<Fr>) {
    let cfg = poseidon_config();
    let mut rng = StdRng::from_seed([0x11; 32]);
    let circuit = build_transfer(&mut rng, &cfg);
    let public = circuit.public_inputs();
    let mut setup_rng = StdRng::from_seed([0xc3; 32]);
    let (pk, vk) =
        Groth16::<Bls12_381>::circuit_specific_setup(common::TransferCircuit::blank(&cfg), &mut setup_rng)
            .unwrap();
    let proof = Groth16::<Bls12_381>::prove(&pk, circuit, &mut rng).unwrap();
    assert!(Groth16::<Bls12_381>::verify(&vk, &public, &proof).unwrap(), "base case must verify");
    (vk, proof, public)
}

/// A second, unrelated valid vk (deposit-circuit) — the "wrong vk" taxonomy case.
fn wrong_vk() -> VerifyingKey<Bls12_381> {
    let cfg = poseidon_config();
    let mut setup_rng = StdRng::from_seed([0x77; 32]);
    let (_pk, vk) =
        Groth16::<Bls12_381>::circuit_specific_setup(common::TransferCircuit::blank(&cfg), &mut setup_rng)
            .unwrap();
    vk
}

fn build_transfer(rng: &mut StdRng, cfg: &PoseidonCfg<Fr>) -> common::TransferCircuit {
    let owner_nk = Fr::rand(rng);
    let recipient_nk = Fr::rand(rng);
    let in_v = [90_000u64 + rng.next_u64() % 500_000, 40_000 + rng.next_u64() % 500_000];
    let inputs = [
        Note { v: in_v[0], nk: owner_nk, rho: Fr::rand(rng), rcm: Fr::rand(rng) },
        Note { v: in_v[1], nk: owner_nk, rho: Fr::rand(rng), rcm: Fr::rand(rng) },
    ];
    let mut filler = |rng: &mut StdRng| Note { v: 1, nk: Fr::rand(rng), rho: Fr::rand(rng), rcm: Fr::rand(rng) };
    let leaves = vec![
        filler(rng).cm(cfg), inputs[0].cm(cfg), filler(rng).cm(cfg),
        filler(rng).cm(cfg), inputs[1].cm(cfg), filler(rng).cm(cfg),
    ];
    let tree = DenseTree { leaves };
    let anchor = tree.root(cfg);
    let (sib0, bits0) = tree.path(cfg, 1);
    let (sib1, bits1) = tree.path(cfg, 4);
    let nf = [inputs[0].nf(cfg), inputs[1].nf(cfg)];
    let out_pk = [derive_pk(cfg, recipient_nk), derive_pk(cfg, owner_nk)];
    let out_rcm = [Fr::rand(rng), Fr::rand(rng)];
    let total = in_v[0] + in_v[1];
    let fee = rng.next_u64() % (total / 8 + 1);
    let v_pub_out = rng.next_u64() % ((total - fee) / 3 + 1);
    let rem = total - fee - v_pub_out;
    let o0 = rng.next_u64() % (rem + 1);
    let out_v = [o0, rem - o0];
    let cm_out = [
        note_commitment(cfg, out_v[0], out_pk[0], nf[0], out_rcm[0]),
        note_commitment(cfg, out_v[1], out_pk[1], nf[1], out_rcm[1]),
    ];
    common::TransferCircuit {
        cfg: cfg.clone(),
        enforce_range: true,
        anchor: Some(anchor),
        nf: [Some(nf[0]), Some(nf[1])],
        cm_out: [Some(cm_out[0]), Some(cm_out[1])],
        fee: Some(fee),
        v_pub_out: Some(v_pub_out),
        recipient_binding: Some(Fr::rand(rng)),
        in_v: [Some(in_v[0]), Some(in_v[1])],
        in_nk: [Some(inputs[0].nk), Some(inputs[1].nk)],
        in_rho: [Some(inputs[0].rho), Some(inputs[1].rho)],
        in_rcm: [Some(inputs[0].rcm), Some(inputs[1].rcm)],
        in_siblings: [sib0, sib1],
        in_bits: [bits0, bits1],
        out_v: [Some(Fr::from(out_v[0])), Some(Fr::from(out_v[1]))],
        out_pk: [Some(out_pk[0]), Some(out_pk[1])],
        out_rcm: [Some(out_rcm[0]), Some(out_rcm[1])],
    }
}

struct Case {
    label: String,
    vk: Vec<u8>,
    proof: Vec<u8>,
    inputs: Vec<u8>,
}

/// Build the full mutation taxonomy from the valid base wire triple.
fn taxonomy(vk: &[u8], proof: &[u8], inputs: &[u8], wrong: &[u8]) -> Vec<Case> {
    let mut cases = Vec::new();
    let mk = |label: String, v: &[u8], p: &[u8], i: &[u8]| Case {
        label,
        vk: v.to_vec(),
        proof: p.to_vec(),
        inputs: i.to_vec(),
    };
    // valid base
    cases.push(mk("valid".into(), vk, proof, inputs));

    // every proof byte flipped
    for b in 0..proof.len() {
        let mut p = proof.to_vec();
        p[b] ^= 1;
        cases.push(mk(format!("proof-byte-{b}"), vk, &p, inputs));
    }
    // every public input mutated (+1 in the low byte, and set to r)
    let r_le: [u8; 32] = [
        0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0x02, 0xa4,
        0xbd, 0x53, 0x05, 0xd8, 0xa1, 0x09, 0x08, 0xd8, 0x39, 0x33, 0x48, 0x7d, 0x9d, 0x29,
        0x53, 0xa7, 0xed, 0x73,
    ];
    let count = u64_le(inputs, 0) as usize;
    for k in 0..count {
        let base = 8 + 32 * k;
        let mut i1 = inputs.to_vec();
        i1[base] ^= 1;
        cases.push(mk(format!("input-{k}-bitflip"), vk, proof, &i1));
        let mut ir = inputs.to_vec();
        ir[base..base + 32].copy_from_slice(&r_le);
        cases.push(mk(format!("input-{k}-eq-r"), vk, proof, &ir));
        let mut imax = inputs.to_vec();
        imax[base..base + 32].copy_from_slice(&[0xff; 32]);
        cases.push(mk(format!("input-{k}-2^256-1"), vk, proof, &imax));
    }
    // wrong number of public inputs (drop one, add one)
    if count >= 1 {
        let mut short = inputs.to_vec();
        short.truncate(inputs.len() - 32);
        short[0..8].copy_from_slice(&((count - 1) as u64).to_le_bytes());
        cases.push(mk("input-count-minus1".into(), vk, proof, &short));
        let mut long = inputs.to_vec();
        long.extend_from_slice(&[0u8; 32]);
        long[0..8].copy_from_slice(&((count + 1) as u64).to_le_bytes());
        cases.push(mk("input-count-plus1".into(), vk, proof, &long));
    }
    // proof truncation at each field boundary + oversize
    for cut in [47usize, 48, 143, 144, 191] {
        cases.push(mk(format!("proof-trunc-{cut}"), vk, &proof[..cut], inputs));
    }
    let mut over = proof.to_vec();
    over.push(0);
    cases.push(mk("proof-oversize".into(), vk, &over, inputs));

    // point at infinity substituted at A (G1), B (G2), C (G1)
    let inf_g1 = {
        let mut b = [0u8; 48];
        b[0] = 0xc0;
        b
    };
    let inf_g2 = {
        let mut b = [0u8; 96];
        b[0] = 0xc0;
        b
    };
    for (name, off, is_g2) in [("A", 0usize, false), ("B", 48, true), ("C", 144, false)] {
        let mut p = proof.to_vec();
        if is_g2 {
            p[off..off + 96].copy_from_slice(&inf_g2);
        } else {
            p[off..off + 48].copy_from_slice(&inf_g1);
        }
        cases.push(mk(format!("proof-{name}-infinity"), vk, &p, inputs));
    }
    // infinity at each vk slot
    for (name, off, is_g2) in [
        ("alpha", 0usize, false),
        ("beta", 48, true),
        ("gamma", 144, true),
        ("delta", 240, true),
        ("ic0", 344, false),
    ] {
        let mut v = vk.to_vec();
        if is_g2 {
            v[off..off + 96].copy_from_slice(&inf_g2);
        } else {
            v[off..off + 48].copy_from_slice(&inf_g1);
        }
        cases.push(mk(format!("vk-{name}-infinity"), &v, proof, inputs));
    }
    // non-canonical coordinate: set A's x to p (compression flag on, x = field modulus)
    {
        let pm: num_bigint::BigUint = Fq::MODULUS.into();
        let pmb = pm.to_bytes_be();
        let mut xb = [0u8; 48];
        xb[48 - pmb.len()..].copy_from_slice(&pmb);
        xb[0] |= 0x80;
        let mut p = proof.to_vec();
        p[0..48].copy_from_slice(&xb);
        cases.push(mk("proof-A-noncanonical-x".into(), vk, &p, inputs));
    }
    // off-curve: A with compression on but a random x that is (almost surely) not on-curve.
    {
        let mut p = proof.to_vec();
        for j in 1..48 {
            p[j] = 0xab;
        }
        p[0] = 0x80; // compression on, sort off, infinity off
        cases.push(mk("proof-A-offcurve".into(), vk, &p, inputs));
    }
    // off-subgroup: an on-curve G1 NOT in the prime subgroup (pinned from the curve oracle).
    {
        let x_hex = "07d9851e94630245314c0497f59c81e2594901d1546c675a61c65ceab2b72cbdc264d4280ba057fa9471e2775896526a";
        let xb: Vec<u8> = (0..48).map(|i| u8::from_str_radix(&x_hex[2 * i..2 * i + 2], 16).unwrap()).collect();
        // encode compressed: we don't know the sort bit; try both parities — at least one
        // decodes to the on-curve off-subgroup point, which every verifier must reject.
        for sort in [0u8, 0x20] {
            let mut enc = [0u8; 48];
            enc.copy_from_slice(&xb);
            enc[0] |= 0x80 | sort;
            let mut p = proof.to_vec();
            p[0..48].copy_from_slice(&enc);
            cases.push(mk(format!("proof-A-offsubgroup-{sort:#x}"), vk, &p, inputs));
        }
    }
    // wrong (unrelated) vk
    cases.push(mk("wrong-vk".into(), wrong, proof, inputs));
    // vk truncation + oversize
    for cut in [343usize, 335, 240] {
        cases.push(mk(format!("vk-trunc-{cut}"), &vk[..cut], proof, inputs));
    }
    // every vk byte flipped (sampled: all — the vk is ~776 bytes)
    for b in 0..vk.len() {
        let mut v = vk.to_vec();
        v[b] ^= 1;
        cases.push(mk(format!("vk-byte-{b}"), &v, proof, inputs));
    }
    cases
}

// ---------------- PocketIC harness ----------------

fn build_harness_wasm(repo_root: &Path, mutate: Option<(&str, &str, &str)>) -> Vec<u8> {
    // mutate = Some((module_file, from, to)) plants a single-limb bug in a staged copy.
    let stage = std::env::temp_dir().join(format!("fortress_harness_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&stage);
    std::fs::create_dir_all(stage.join("groth16")).unwrap();
    for entry in std::fs::read_dir(repo_root.join("src/groth16")).unwrap() {
        let p = entry.unwrap().path();
        if p.extension().map(|e| e == "mo").unwrap_or(false) {
            std::fs::copy(&p, stage.join("groth16").join(p.file_name().unwrap())).unwrap();
        }
    }
    std::fs::copy(repo_root.join("fortress/harness/Verifier.mo"), stage.join("Verifier.mo")).unwrap();
    if let Some((module, from, to)) = mutate {
        let mp = stage.join("groth16").join(module);
        let src = std::fs::read_to_string(&mp).unwrap();
        let mutated = src.replacen(from, to, 1);
        assert_ne!(src, mutated, "planted mutation did not change {module}");
        std::fs::write(&mp, mutated).unwrap();
    }
    let moc = std::env::var("SOAK_MOC").unwrap_or_else(|_| "/opt/moc-1.4.1/moc".into());
    let sources = String::from_utf8(
        Command::new("mops").arg("sources").current_dir(repo_root).output().unwrap().stdout,
    )
    .unwrap();
    let src_args: Vec<String> = sources.split_whitespace().map(String::from).collect();
    let out = stage.join("verifier.wasm");
    let status = Command::new(&moc)
        .args(&src_args)
        .arg("-c")
        .arg(stage.join("Verifier.mo"))
        .arg("-o")
        .arg(&out)
        .current_dir(repo_root)
        .status()
        .unwrap();
    assert!(status.success(), "harness moc compile failed");
    let wasm = std::fs::read(&out).unwrap();
    let _ = std::fs::remove_dir_all(&stage);
    wasm
}

struct Harness {
    server: pic_env::ManagedServer,
    pic: pocket_ic::PocketIc,
    canister: candid::Principal,
}

/// Clean teardown: PocketIC's instance-delete on Drop is flaky (IncompleteMessage) and can
/// panic the process AFTER the gate has already passed. Skip the pic Drop (forget) and kill
/// the server child explicitly so the run exits on its real verdict, not a teardown race.
fn shutdown(h: Harness) {
    let Harness { server, pic, .. } = h;
    std::mem::forget(pic);
    drop(server);
}

impl Harness {
    fn new(wasm: &[u8]) -> Self {
        let server_bin = pic_env::resolve_pocket_ic_server();
        let server = pic_env::spawn_server(&server_bin);
        let pic = PocketIcBuilder::new()
            .with_server_url(server.url.clone())
            .with_application_subnet()
            .build();
        let canister = pic.create_canister();
        pic.add_cycles(canister, 100_000_000_000_000);
        pic.install_canister(canister, wasm.to_vec(), candid::encode_args(()).unwrap(), None);
        Harness { server, pic, canister }
    }

    fn reinstall(&self, wasm: &[u8]) {
        self.pic
            .reinstall_canister(self.canister, wasm.to_vec(), candid::encode_args(()).unwrap(), None)
            .expect("reinstall harness");
    }

    /// Motoko verdict: true = ACCEPT.
    fn verdict(&self, vk: &[u8], proof: &[u8], inputs: &[u8]) -> bool {
        let args = candid::encode_args((hex(vk), hex(proof), hex(inputs))).unwrap();
        let raw = self
            .pic
            .update_call(self.canister, candid::Principal::anonymous(), "verify_oneshot", args)
            .expect("verify_oneshot call");
        let verdict: String = candid::decode_one(&raw).expect("decode verdict");
        verdict == "ACCEPT"
    }
}

fn main() {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf();
    println!("== §1 three-verifier taxonomy gate ==");

    // base valid case + taxonomy
    let (vk, proof, inputs) = valid_case();
    let (vkb, pb, ib) = to_wire(&vk, &proof, &inputs);
    let wrong = {
        let (wv, _, _) = {
            let wvk = wrong_vk();
            // dummy proof/inputs unused for the wrong-vk case (we keep the valid proof/inputs)
            (wvk, (), ())
        };
        let mut b = Vec::new();
        b.extend_from_slice(&compress_g1(&wv.alpha_g1));
        b.extend_from_slice(&compress_g2(&wv.beta_g2));
        b.extend_from_slice(&compress_g2(&wv.gamma_g2));
        b.extend_from_slice(&compress_g2(&wv.delta_g2));
        b.extend_from_slice(&(wv.gamma_abc_g1.len() as u64).to_le_bytes());
        for p in &wv.gamma_abc_g1 {
            b.extend_from_slice(&compress_g1(p));
        }
        b
    };

    // sanity: base is 3-way ACCEPT natively before booting PocketIC
    assert!(ark_verdict(&vkb, &pb, &ib), "ark base reject");
    assert!(blst_verdict(&vkb, &pb, &ib), "blst base reject");

    let cases = taxonomy(&vkb, &pb, &ib, &wrong);
    println!("taxonomy: {} cases", cases.len());

    // build + install the production harness
    println!("compiling + installing the production verifier harness on PocketIC ...");
    let wasm = build_harness_wasm(&repo_root, None);
    let h = Harness::new(&wasm);

    let mut disagreements = Vec::new();
    let mut accepts = 0u32;
    for (idx, c) in cases.iter().enumerate() {
        let a = ark_verdict(&c.vk, &c.proof, &c.inputs);
        let b = blst_verdict(&c.vk, &c.proof, &c.inputs);
        let m = h.verdict(&c.vk, &c.proof, &c.inputs);
        if a { accepts += 1; }
        if !(a == b && b == m) {
            disagreements.push(format!(
                "  DISAGREE [{idx}] {}: ark={a} blst={b} motoko={m}",
                c.label
            ));
        }
        if idx % 100 == 0 {
            println!("  .. {idx}/{} checked", cases.len());
        }
    }

    if !disagreements.is_empty() {
        eprintln!("§1 GATE RED — {} disagreement(s):", disagreements.len());
        for d in disagreements.iter().take(20) {
            eprintln!("{d}");
        }
        std::process::exit(1);
    }
    println!(
        "§1 GATE GREEN: all {} cases agree 3-way (Motoko == arkworks == blst); {} accepts (valid base only)",
        cases.len(), accepts
    );

    // ---- TEETH: plant a single wrong verifier limb; the valid base must go RED ----
    println!("== §1 TEETH: planting a single wrong Montgomery limb in the harness ==");
    let mutant = build_harness_wasm(
        &repo_root,
        Some((
            "FpMont.mo",
            "0x11988fe592cae3aa9a793e85b519952d67eb88a9939d83c08de5476c4c95b6d50a76e6a609d104f1f4df1f341c341746",
            "0x11988fe592cae3aa9a793e85b519952d67eb88a9939d83c08de5476c4c95b6d50a76e6a609d104f1f4df1f341c341747",
        )),
    );
    h.reinstall(&mutant);
    let m_mut = h.verdict(&vkb, &pb, &ib);
    let a = ark_verdict(&vkb, &pb, &ib);
    let b = blst_verdict(&vkb, &pb, &ib);
    if m_mut == a && a == b {
        eprintln!("§1 TEETH FAILED: a wrong verifier limb did NOT change the 3-way verdict");
        std::process::exit(1);
    }
    println!(
        "§1 TEETH GREEN: wrong-limb harness diverged (motoko={m_mut} vs ark={a} blst={b}) — gate would go RED"
    );
    shutdown(h);
    println!("FORTRESS-TAXONOMY: GREEN (1017-case 3-way agreement + teeth)");
}
