//! Second-implementation Groth16 oracle over blst.
//!
//! The primary oracle for the frozen fixtures is arkworks, and the Motoko verifier was
//! differentially tested against it. A single reference implementation leaves one risk open:
//! a shared misreading of the BLS12-381/Groth16 specification. This crate closes most of that
//! window by re-verifying every pinned verdict with blst, a pairing library with an unrelated
//! lineage (supranational, C/assembly, used by Ethereum consensus clients). Only the wire
//! framing (offsets and lengths) is shared knowledge; every cryptographic operation — point
//! decompression, canonicality, subgroup membership, scalar range, the vk_x MSM, the Miller
//! loops, and the final exponentiation — is blst's own code.
//!
//! Wire conventions under test (same as `src/groth16/Groth16Wire.mo`):
//!   vk     = alpha:G1 ‖ beta:G2 ‖ gamma:G2 ‖ delta:G2 ‖ u64-LE len ‖ len × G1   (compressed)
//!   proof  = A:G1 ‖ B:G2 ‖ C:G1                                                 (192 bytes)
//!   inputs = 32-byte LITTLE-endian canonical Fr each
//! Compressed points use the ZCash BLS12-381 format, which blst enforces natively.

use blst::*;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Verdict {
    Accept,
    RejectDecode,
    RejectSubgroup,
    RejectScalar,
    RejectPairing,
    RejectShape,
}

fn g1_at(bytes: &[u8], off: usize) -> Result<blst_p1_affine, Verdict> {
    let mut p = blst_p1_affine::default();
    if bytes.len() < off + 48 {
        return Err(Verdict::RejectShape);
    }
    let rc = unsafe { blst_p1_uncompress(&mut p, bytes[off..off + 48].as_ptr()) };
    if rc != BLST_ERROR::BLST_SUCCESS {
        return Err(Verdict::RejectDecode);
    }
    if !unsafe { blst_p1_affine_in_g1(&p) } {
        return Err(Verdict::RejectSubgroup);
    }
    Ok(p)
}

fn g2_at(bytes: &[u8], off: usize) -> Result<blst_p2_affine, Verdict> {
    let mut p = blst_p2_affine::default();
    if bytes.len() < off + 96 {
        return Err(Verdict::RejectShape);
    }
    let rc = unsafe { blst_p2_uncompress(&mut p, bytes[off..off + 96].as_ptr()) };
    if rc != BLST_ERROR::BLST_SUCCESS {
        return Err(Verdict::RejectDecode);
    }
    if !unsafe { blst_p2_affine_in_g2(&p) } {
        return Err(Verdict::RejectSubgroup);
    }
    Ok(p)
}

fn fr_le(bytes: &[u8]) -> Result<blst_scalar, Verdict> {
    if bytes.len() != 32 {
        return Err(Verdict::RejectShape);
    }
    let mut s = blst_scalar::default();
    unsafe { blst_scalar_from_lendian(&mut s, bytes.as_ptr()) };
    if !unsafe { blst_scalar_fr_check(&s) } {
        return Err(Verdict::RejectScalar);
    }
    Ok(s)
}

pub struct Vk {
    alpha: blst_p1_affine,
    beta: blst_p2_affine,
    gamma: blst_p2_affine,
    delta: blst_p2_affine,
    ic: Vec<blst_p1_affine>,
}

pub fn parse_vk(bytes: &[u8]) -> Result<Vk, Verdict> {
    if bytes.len() < 344 {
        return Err(Verdict::RejectShape);
    }
    let alpha = g1_at(bytes, 0)?;
    let beta = g2_at(bytes, 48)?;
    let gamma = g2_at(bytes, 144)?;
    let delta = g2_at(bytes, 240)?;
    let len = u64::from_le_bytes(bytes[336..344].try_into().unwrap()) as usize;
    if len < 1 || len > 1024 || bytes.len() != 344 + 48 * len {
        return Err(Verdict::RejectShape);
    }
    let mut ic = Vec::with_capacity(len);
    for i in 0..len {
        ic.push(g1_at(bytes, 344 + 48 * i)?);
    }
    Ok(Vk { alpha, beta, gamma, delta, ic })
}

/// vk_x = ic[0] + Σ input_i · ic[i+1], all in blst.
fn vk_x(vk: &Vk, inputs: &[blst_scalar]) -> Result<blst_p1_affine, Verdict> {
    if inputs.len() + 1 != vk.ic.len() {
        return Err(Verdict::RejectShape);
    }
    let mut acc = blst_p1::default();
    unsafe { blst_p1_from_affine(&mut acc, &vk.ic[0]) };
    for (i, s) in inputs.iter().enumerate() {
        let mut term = blst_p1::default();
        unsafe {
            blst_p1_from_affine(&mut term, &vk.ic[i + 1]);
            blst_p1_mult(&mut term, &term, s.b.as_ptr(), 255);
            blst_p1_add_or_double(&mut acc, &acc, &term);
        }
    }
    let mut out = blst_p1_affine::default();
    unsafe { blst_p1_to_affine(&mut out, &acc) };
    Ok(out)
}

/// Full Groth16 verify: e(-A,B) · e(alpha,beta) · e(vk_x,gamma) · e(C,delta) == 1.
pub fn verify(vk: &Vk, proof: &[u8], input_bytes: &[&[u8]]) -> Verdict {
    if proof.len() != 192 {
        return Verdict::RejectShape;
    }
    let a = match g1_at(proof, 0) {
        Ok(p) => p,
        Err(v) => return v,
    };
    let b = match g2_at(proof, 48) {
        Ok(p) => p,
        Err(v) => return v,
    };
    let c = match g1_at(proof, 144) {
        Ok(p) => p,
        Err(v) => return v,
    };
    let mut inputs = Vec::with_capacity(input_bytes.len());
    for raw in input_bytes {
        match fr_le(raw) {
            Ok(s) => inputs.push(s),
            Err(v) => return v,
        }
    }
    let x = match vk_x(vk, &inputs) {
        Ok(p) => p,
        Err(v) => return v,
    };

    let mut neg_a = blst_p1::default();
    let mut neg_a_aff = blst_p1_affine::default();
    unsafe {
        blst_p1_from_affine(&mut neg_a, &a);
        blst_p1_cneg(&mut neg_a, true);
        blst_p1_to_affine(&mut neg_a_aff, &neg_a);
    }

    let mut acc = blst_fp12::default();
    let mut term = blst_fp12::default();
    unsafe {
        blst_miller_loop(&mut acc, &b, &neg_a_aff);
        blst_miller_loop(&mut term, &vk.beta, &vk.alpha);
        blst_fp12_mul(&mut acc, &acc, &term);
        blst_miller_loop(&mut term, &vk.gamma, &x);
        blst_fp12_mul(&mut acc, &acc, &term);
        blst_miller_loop(&mut term, &vk.delta, &c);
        blst_fp12_mul(&mut acc, &acc, &term);
        let mut fin = blst_fp12::default();
        blst_final_exp(&mut fin, &acc);
        if blst_fp12_is_one(&fin) {
            Verdict::Accept
        } else {
            Verdict::RejectPairing
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn fixture(name: &str) -> Vec<u8> {
        let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.push("../fixtures/pool-vectors-bls12-381");
        p.push(name);
        let text = fs::read_to_string(&p).unwrap_or_else(|_| panic!("missing fixture {name}"));
        hex::decode(text.trim()).unwrap_or_else(|_| panic!("bad hex in {name}"))
    }

    fn nat(name: &str) -> u64 {
        let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.push("../fixtures/pool-vectors-bls12-381");
        p.push(name);
        fs::read_to_string(&p).unwrap().trim().parse().unwrap()
    }

    fn u64_field(v: u64) -> Vec<u8> {
        let mut out = vec![0u8; 32];
        out[..8].copy_from_slice(&v.to_le_bytes());
        out
    }

    fn transfer_vk() -> Vk {
        parse_vk(&fixture("transfer_vk.hex")).expect("transfer vk must parse in blst")
    }

    fn deposit_vk() -> Vk {
        parse_vk(&fixture("deposit_vk.hex")).expect("deposit vk must parse in blst")
    }

    fn transfer_inputs() -> Vec<Vec<u8>> {
        vec![
            fixture("anchor.hex"),
            fixture("nf1.hex"),
            fixture("nf2.hex"),
            fixture("cm_out1.hex"),
            fixture("cm_out2.hex"),
            u64_field(nat("fee.txt")),
            u64_field(nat("v_pub_out.txt")),
            fixture("recipient_binding.hex"),
        ]
    }

    fn withdraw_inputs() -> Vec<Vec<u8>> {
        vec![
            fixture("withdraw_anchor.hex"),
            fixture("withdraw_nf1.hex"),
            fixture("withdraw_nf2.hex"),
            fixture("withdraw_cm_out1.hex"),
            fixture("withdraw_cm_out2.hex"),
            u64_field(nat("withdraw_fee.txt")),
            u64_field(nat("withdraw_v_pub_out.txt")),
            fixture("withdraw_recipient_binding.hex"),
        ]
    }

    fn refs(v: &[Vec<u8>]) -> Vec<&[u8]> {
        v.iter().map(|x| x.as_slice()).collect()
    }

    #[test]
    fn pinned_verdicts_agree_with_primary_oracle() {
        let tvk = transfer_vk();
        let dvk = deposit_vk();

        // P0: valid transfer ACCEPT.
        let t_in = transfer_inputs();
        assert_eq!(verify(&tvk, &fixture("transfer_proof.hex"), &refs(&t_in)), Verdict::Accept);

        // P1: valid recipient-bound withdraw ACCEPT.
        let w_in = withdraw_inputs();
        assert_eq!(verify(&tvk, &fixture("withdraw_proof.hex"), &refs(&w_in)), Verdict::Accept);

        // P0d: both deposits ACCEPT.
        for (proof, cm, v) in [
            ("deposit1_proof.hex", "deposit1_cm.hex", "deposit1_v.txt"),
            ("deposit2_proof.hex", "deposit2_cm.hex", "deposit2_v.txt"),
        ] {
            let d_in = vec![fixture(cm), u64_field(nat(v))];
            assert_eq!(verify(&dvk, &fixture(proof), &refs(&d_in)), Verdict::Accept);
        }

        // C1: bit-flipped proof must not verify.
        let bad = verify(&tvk, &fixture("transfer_badproof.hex"), &refs(&t_in));
        assert_ne!(bad, Verdict::Accept, "badproof accepted");

        // C2 control: the fabricated-tree proof passes the pairing equation by design; the
        // ledger rejects it at the anchor check, not here. blst must agree with that verdict.
        let fake_in = vec![
            fixture("fake_anchor.hex"),
            fixture("fake_nf1.hex"),
            fixture("fake_nf2.hex"),
            fixture("fake_cm_out1.hex"),
            fixture("fake_cm_out2.hex"),
            u64_field(nat("fee.txt")),
            u64_field(nat("v_pub_out.txt")),
            fixture("recipient_binding.hex"),
        ];
        assert_eq!(verify(&tvk, &fixture("fake_proof.hex"), &refs(&fake_in)), Verdict::Accept);
    }

    #[test]
    fn every_public_input_is_binding() {
        let tvk = transfer_vk();
        let proof = fixture("transfer_proof.hex");
        let base = transfer_inputs();
        assert_eq!(verify(&tvk, &proof, &refs(&base)), Verdict::Accept);
        for i in 0..base.len() {
            let mut mutated = base.clone();
            mutated[i][0] ^= 1;
            let verdict = verify(&tvk, &proof, &refs(&mutated));
            assert_ne!(verdict, Verdict::Accept, "mutated public input {i} accepted");
        }
    }

    #[test]
    fn every_proof_byte_is_binding() {
        let tvk = transfer_vk();
        let base = fixture("transfer_proof.hex");
        let inputs = transfer_inputs();
        let input_refs = refs(&inputs);
        for i in 0..base.len() {
            let mut mutated = base.clone();
            mutated[i] ^= 1;
            let verdict = verify(&tvk, &mutated, &input_refs);
            assert_ne!(verdict, Verdict::Accept, "mutated proof byte {i} accepted");
        }
    }

    #[test]
    fn non_canonical_scalars_and_shapes_reject() {
        let tvk = transfer_vk();
        let proof = fixture("transfer_proof.hex");

        // Fr modulus r (little-endian) is not a canonical scalar; neither is r+1 or 2^256-1.
        let r_le: [u8; 32] = [
            0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0x02, 0xa4,
            0xbd, 0x53, 0x05, 0xd8, 0xa1, 0x09, 0x08, 0xd8, 0x39, 0x33, 0x48, 0x7d, 0x9d, 0x29,
            0x53, 0xa7, 0xed, 0x73,
        ];
        let mut base = transfer_inputs();
        base[7] = r_le.to_vec();
        assert_eq!(verify(&tvk, &proof, &refs(&base)), Verdict::RejectScalar);
        base[7] = vec![0xff; 32];
        assert_eq!(verify(&tvk, &proof, &refs(&base)), Verdict::RejectScalar);

        // Wrong input count and wrong proof length reject on shape.
        let seven = transfer_inputs()[..7].to_vec();
        assert_eq!(verify(&tvk, &proof, &refs(&seven)), Verdict::RejectShape);
        assert_eq!(verify(&tvk, &proof[..191], &refs(&transfer_inputs())), Verdict::RejectShape);

        // Truncated and length-corrupted vks reject.
        assert!(parse_vk(&fixture("transfer_vk.hex")[..343]).is_err());
        let mut vk_bytes = fixture("transfer_vk.hex");
        vk_bytes[336] ^= 0xff;
        assert!(parse_vk(&vk_bytes).is_err());
    }

    #[test]
    fn generator_serialization_round_trips() {
        // The ZCash-format generators must decompress in blst to blst's own generators —
        // anchors the serialization convention itself, independent of any fixture.
        let g1_hex = "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
        let g2_hex = "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8";
        let g1 = g1_at(&hex::decode(g1_hex).unwrap(), 0).unwrap();
        let g2 = g2_at(&hex::decode(g2_hex).unwrap(), 0).unwrap();
        unsafe {
            assert!(blst_p1_affine_is_equal(&g1, blst_p1_affine_generator()));
            assert!(blst_p2_affine_is_equal(&g2, blst_p2_affine_generator()));
        }
        // And a non-canonical encoding (x >= p in the compressed field) must fail to decode.
        let mut bad = hex::decode(g1_hex).unwrap();
        bad[0] |= 0x1f;
        bad[1] = 0xff;
        assert!(g1_at(&bad, 0).is_err());
    }
}
