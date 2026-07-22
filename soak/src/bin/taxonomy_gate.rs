//! §1 — Three independent Groth16 verifiers, one gate.
//!
//! Every taxonomy case is checked by the PRODUCTION Motoko verifier (installed in PocketIC,
//! the exact shipped `Groth16Wire.tryVerify` -> L3 flat path), arkworks, AND blst. The gate
//! fails if any two disagree on accept/reject polarity on any case. The Motoko verdict runs
//! at wasm speed on PocketIC (the L3-flat path is interpreter-hostile — proven in Phase 0 —
//! so the interpreter is NOT used here). arkworks and blst run natively in this driver.
//!
//! Shared wire/verdict/harness code lives in `soak::fortress_gate`. This bin owns the
//! taxonomy enumeration and the teeth.
//!
//! Deterministic, offline. Run: cargo run --release --manifest-path soak/Cargo.toml --bin taxonomy_gate

use ark_bls12_381::Fq;
use ark_ff::PrimeField;
use soak::fortress_gate::*;

struct Case {
    label: String,
    vk: Vec<u8>,
    proof: Vec<u8>,
    inputs: Vec<u8>,
}

/// The full mutation taxonomy from the valid base wire triple.
fn taxonomy(vk: &[u8], proof: &[u8], inputs: &[u8], wrong: &[u8]) -> Vec<Case> {
    let mut cases = Vec::new();
    let mk = |label: String, v: &[u8], p: &[u8], i: &[u8]| Case { label, vk: v.to_vec(), proof: p.to_vec(), inputs: i.to_vec() };
    cases.push(mk("valid".into(), vk, proof, inputs));

    for b in 0..proof.len() {
        let mut p = proof.to_vec();
        p[b] ^= 1;
        cases.push(mk(format!("proof-byte-{b}"), vk, &p, inputs));
    }
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
    for cut in [47usize, 48, 143, 144, 191] {
        cases.push(mk(format!("proof-trunc-{cut}"), vk, &proof[..cut], inputs));
    }
    let mut over = proof.to_vec();
    over.push(0);
    cases.push(mk("proof-oversize".into(), vk, &over, inputs));

    let inf_g1 = { let mut b = [0u8; 48]; b[0] = 0xc0; b };
    let inf_g2 = { let mut b = [0u8; 96]; b[0] = 0xc0; b };
    for (name, off, is_g2) in [("A", 0usize, false), ("B", 48, true), ("C", 144, false)] {
        let mut p = proof.to_vec();
        if is_g2 { p[off..off + 96].copy_from_slice(&inf_g2); } else { p[off..off + 48].copy_from_slice(&inf_g1); }
        cases.push(mk(format!("proof-{name}-infinity"), vk, &p, inputs));
    }
    for (name, off, is_g2) in [("alpha", 0usize, false), ("beta", 48, true), ("gamma", 144, true), ("delta", 240, true), ("ic0", 344, false)] {
        let mut v = vk.to_vec();
        if is_g2 { v[off..off + 96].copy_from_slice(&inf_g2); } else { v[off..off + 48].copy_from_slice(&inf_g1); }
        cases.push(mk(format!("vk-{name}-infinity"), &v, proof, inputs));
    }
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
    {
        let mut p = proof.to_vec();
        for j in 1..48 { p[j] = 0xab; }
        p[0] = 0x80;
        cases.push(mk("proof-A-offcurve".into(), vk, &p, inputs));
    }
    {
        let x_hex = "07d9851e94630245314c0497f59c81e2594901d1546c675a61c65ceab2b72cbdc264d4280ba057fa9471e2775896526a";
        let xb: Vec<u8> = (0..48).map(|i| u8::from_str_radix(&x_hex[2 * i..2 * i + 2], 16).unwrap()).collect();
        for sort in [0u8, 0x20] {
            let mut enc = [0u8; 48];
            enc.copy_from_slice(&xb);
            enc[0] |= 0x80 | sort;
            let mut p = proof.to_vec();
            p[0..48].copy_from_slice(&enc);
            cases.push(mk(format!("proof-A-offsubgroup-{sort:#x}"), vk, &p, inputs));
        }
    }
    cases.push(mk("wrong-vk".into(), wrong, proof, inputs));
    for cut in [343usize, 335, 240] {
        cases.push(mk(format!("vk-trunc-{cut}"), &vk[..cut], proof, inputs));
    }
    for b in 0..vk.len() {
        let mut v = vk.to_vec();
        v[b] ^= 1;
        cases.push(mk(format!("vk-byte-{b}"), &v, proof, inputs));
    }
    cases
}

fn main() {
    let root = repo_root();
    println!("== §1 three-verifier taxonomy gate ==");
    let vt = valid_transfer([0x11; 32]);
    let vkb = vk_to_wire(&vt.vk);
    let pb = proof_to_wire(&vt.proof);
    let ib = inputs_to_wire(&vt.public);
    let wrong = vk_to_wire(&wrong_vk());

    assert!(ark_verdict(&vkb, &pb, &ib), "ark base reject");
    assert!(blst_verdict(&vkb, &pb, &ib), "blst base reject");

    let cases = taxonomy(&vkb, &pb, &ib, &wrong);
    println!("taxonomy: {} cases", cases.len());

    println!("compiling + installing the production verifier harness on PocketIC ...");
    let wasm = build_harness_wasm(&root, None);
    let h = Harness::new(&wasm);

    let mut disagreements = Vec::new();
    let mut accepts = 0u32;
    for (idx, c) in cases.iter().enumerate() {
        let a = ark_verdict(&c.vk, &c.proof, &c.inputs);
        let b = blst_verdict(&c.vk, &c.proof, &c.inputs);
        let m = h.verdict(&c.vk, &c.proof, &c.inputs);
        if a { accepts += 1; }
        if !(a == b && b == m) {
            disagreements.push(format!("  DISAGREE [{idx}] {}: ark={a} blst={b} motoko={m}", c.label));
        }
        if idx % 100 == 0 { println!("  .. {idx}/{} checked", cases.len()); }
    }
    if !disagreements.is_empty() {
        eprintln!("§1 GATE RED — {} disagreement(s):", disagreements.len());
        for d in disagreements.iter().take(20) { eprintln!("{d}"); }
        std::process::exit(1);
    }
    println!("§1 GATE GREEN: all {} cases agree 3-way (Motoko == arkworks == blst); {} accepts (valid base only)", cases.len(), accepts);

    println!("== §1 TEETH: planting a single wrong Montgomery limb in the harness ==");
    let mutant = build_harness_wasm(&root, Some((
        "FpMont.mo",
        "0x11988fe592cae3aa9a793e85b519952d67eb88a9939d83c08de5476c4c95b6d50a76e6a609d104f1f4df1f341c341746",
        "0x11988fe592cae3aa9a793e85b519952d67eb88a9939d83c08de5476c4c95b6d50a76e6a609d104f1f4df1f341c341747",
    )));
    h.reinstall(&mutant);
    let m_mut = h.verdict(&vkb, &pb, &ib);
    let a = ark_verdict(&vkb, &pb, &ib);
    let b = blst_verdict(&vkb, &pb, &ib);
    if m_mut == a && a == b {
        eprintln!("§1 TEETH FAILED: a wrong verifier limb did NOT change the 3-way verdict");
        std::process::exit(1);
    }
    println!("§1 TEETH GREEN: wrong-limb harness diverged (motoko={m_mut} vs ark={a} blst={b}) — gate would go RED");
    shutdown(h);
    println!("FORTRESS-TAXONOMY: GREEN (1017-case 3-way agreement + teeth)");
}
