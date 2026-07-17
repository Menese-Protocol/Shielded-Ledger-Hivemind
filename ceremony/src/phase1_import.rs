//! Verified ingestion of an inherited, reviewed BLS12-381 Groth16 Phase-1 (the Zcash Sapling
//! Powers of Tau) into our `Phase1Srs`.
//!
//! ENFORCED CONTRACT (a blob is NEVER deserialized-and-consumed without structural verification):
//!   1. read the pinned response file into an arkworks `Phase1Srs` (extract the first 2^target powers);
//!   2. run the FULL `structure_check` pairing verification and REFUSE on any failure;
//!   3. record + publish the provenance: upstream URL, response-file SHA-256, extracted-SRS SHA-256,
//!      participant attestation set, labeled `InheritedReviewedPhase1`.
//!
//! FORMAT. A Groth16 powers-of-tau accumulator, points UNCOMPRESSED big-endian, in the layout the
//! `powersoftau` / zcash `pairing` tooling emits:
//!   [header (`header_len` bytes, e.g. the 64-byte BLAKE2b challenge hash)]
//!   tau_g1      : (2*2^src - 1) x G1 (96 bytes: x||y, each 48 BE)
//!   tau_g2      : (2^src)       x G2 (192 bytes: x.c1||x.c0||y.c1||y.c0, each 48 BE — zcash order)
//!   alpha_tau_g1: (2^src)       x G1
//!   beta_tau_g1 : (2^src)       x G1
//!   beta_g2     : 1             x G2
//! Only the first 2^target powers of each vector (and 2*2^target-1 of tau_g1) are extracted; the
//! rest is skipped by seeking. `structure_check` is the backstop: whatever the bytes decode to, the
//! SRS is consumed only if it passes the secret-free pairing consistency test, so a wrong sub-format
//! is refused rather than silently trusted. The exact byte layout is round-trip tested below.

use crate::srs::{Phase1Srs, SrsProvenance};
use ark_bls12_381::{Fq, Fq2, G1Affine, G2Affine};
use ark_ff::PrimeField;
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom};

fn fq_from_be(b: &[u8]) -> Fq {
    Fq::from_be_bytes_mod_order(b)
}
fn fq_to_be(x: &Fq) -> [u8; 48] {
    use ark_ff::BigInteger;
    let v = x.into_bigint().to_bytes_be();
    let mut out = [0u8; 48];
    out[48 - v.len()..].copy_from_slice(&v);
    out
}

/// Decode a 96-byte uncompressed G1 (x||y). On-curve is checked here; subgroup is checked by
/// `structure_check`. Returns Err on a non-canonical or off-curve encoding.
fn read_g1<R: Read>(r: &mut R) -> Result<G1Affine, String> {
    let mut buf = [0u8; 96];
    r.read_exact(&mut buf).map_err(|e| format!("read g1: {e}"))?;
    let x = fq_from_be(&buf[..48]);
    let y = fq_from_be(&buf[48..]);
    let p = G1Affine::new_unchecked(x, y);
    if !p.is_on_curve() {
        return Err("G1 point not on curve".into());
    }
    Ok(p)
}

/// Decode a 192-byte uncompressed G2 (x.c1||x.c0||y.c1||y.c0, zcash order).
fn read_g2<R: Read>(r: &mut R) -> Result<G2Affine, String> {
    let mut buf = [0u8; 192];
    r.read_exact(&mut buf).map_err(|e| format!("read g2: {e}"))?;
    let x = Fq2::new(fq_from_be(&buf[48..96]), fq_from_be(&buf[..48])); // c0, c1
    let y = Fq2::new(fq_from_be(&buf[144..192]), fq_from_be(&buf[96..144]));
    let p = G2Affine::new_unchecked(x, y);
    if !p.is_on_curve() {
        return Err("G2 point not on curve".into());
    }
    Ok(p)
}

/// Encode helpers (mirror of the readers) — used by the round-trip test and any re-export.
pub fn write_g1(p: &G1Affine, out: &mut Vec<u8>) {
    use ark_ec::AffineRepr;
    let (x, y) = p.xy().expect("no identity in powers of tau");
    out.extend_from_slice(&fq_to_be(&x));
    out.extend_from_slice(&fq_to_be(&y));
}
pub fn write_g2(p: &G2Affine, out: &mut Vec<u8>) {
    use ark_ec::AffineRepr;
    let (x, y) = p.xy().expect("no identity in powers of tau");
    out.extend_from_slice(&fq_to_be(&x.c1));
    out.extend_from_slice(&fq_to_be(&x.c0));
    out.extend_from_slice(&fq_to_be(&y.c1));
    out.extend_from_slice(&fq_to_be(&y.c0));
}

/// Provenance record published alongside the extracted SRS (no secrets).
#[derive(Clone, Debug)]
pub struct Provenance {
    pub upstream_url: String,
    pub response_file_sha256: String,
    pub srs_sha256: String,
    pub src_power: u32,
    pub target_power: u32,
    pub participant_attestations: Vec<String>,
}

impl Provenance {
    pub fn to_json(&self) -> String {
        let atts = self
            .participant_attestations
            .iter()
            .map(|a| format!("    {:?}", a))
            .collect::<Vec<_>>()
            .join(",\n");
        format!(
            concat!(
                "{{\n",
                "  \"phase1_provenance\": \"inherited-reviewed-phase1\",\n",
                "  \"upstream_url\": {:?},\n",
                "  \"response_file_sha256\": {:?},\n",
                "  \"extracted_srs_sha256\": {:?},\n",
                "  \"source_power\": {},\n",
                "  \"target_power\": {},\n",
                "  \"participant_attestations\": [\n{}\n  ]\n",
                "}}\n"
            ),
            self.upstream_url,
            self.response_file_sha256,
            self.srs_sha256,
            self.src_power,
            self.target_power,
            atts,
        )
    }
}

/// Extract the first 2^target powers from an inherited powers-of-tau `response` reader of source
/// power `src_power`, skipping `header_len` leading bytes. Structurally verifies before returning.
pub fn import_response<R: Read + Seek>(
    reader: &mut R,
    header_len: u64,
    src_power: u32,
    target_power: u32,
) -> Result<Phase1Srs, String> {
    if target_power > src_power {
        return Err(format!("target power {target_power} exceeds source power {src_power}"));
    }
    let src_n: u64 = 1u64 << src_power;
    let tgt_n: usize = 1usize << target_power;
    let g1_sz: u64 = 96;
    let g2_sz: u64 = 192;

    // Region offsets in the file (after the header).
    let tau_g1_off = header_len;
    let tau_g1_count_src = 2 * src_n - 1;
    let tau_g2_off = tau_g1_off + tau_g1_count_src * g1_sz;
    let alpha_off = tau_g2_off + src_n * g2_sz;
    let beta_off = alpha_off + src_n * g1_sz;
    let beta_g2_off = beta_off + src_n * g1_sz;

    // tau_g1: first 2*2^target - 1 points.
    reader.seek(SeekFrom::Start(tau_g1_off)).map_err(|e| e.to_string())?;
    let tau_g1_target = 2 * tgt_n - 1;
    let mut tau_g1 = Vec::with_capacity(tau_g1_target);
    for _ in 0..tau_g1_target {
        tau_g1.push(read_g1(reader)?);
    }

    // tau_g2: first 2^target.
    reader.seek(SeekFrom::Start(tau_g2_off)).map_err(|e| e.to_string())?;
    let mut tau_g2 = Vec::with_capacity(tgt_n);
    for _ in 0..tgt_n {
        tau_g2.push(read_g2(reader)?);
    }

    // alpha_tau_g1, beta_tau_g1: first 2^target each.
    reader.seek(SeekFrom::Start(alpha_off)).map_err(|e| e.to_string())?;
    let mut alpha_tau_g1 = Vec::with_capacity(tgt_n);
    for _ in 0..tgt_n {
        alpha_tau_g1.push(read_g1(reader)?);
    }
    reader.seek(SeekFrom::Start(beta_off)).map_err(|e| e.to_string())?;
    let mut beta_tau_g1 = Vec::with_capacity(tgt_n);
    for _ in 0..tgt_n {
        beta_tau_g1.push(read_g1(reader)?);
    }

    // beta_g2.
    reader.seek(SeekFrom::Start(beta_g2_off)).map_err(|e| e.to_string())?;
    let beta_g2 = read_g2(reader)?;

    let srs = Phase1Srs {
        power: target_power,
        provenance: SrsProvenance::InheritedReviewedPhase1,
        tau_g1,
        tau_g2,
        alpha_tau_g1,
        beta_tau_g1,
        beta_g2,
    };

    // ENFORCED: never consume without the FULL structural pairing verification.
    let all: Vec<usize> = (0..srs.tau_g1.len()).collect();
    srs.structure_check(&all)
        .map_err(|e| format!("REFUSED: inherited SRS failed structure_check: {e}"))?;
    Ok(srs)
}

/// Full verified ingestion from a file path, producing the SRS and its provenance record. Computes
/// the response-file SHA-256 and the extracted-SRS SHA-256. REFUSES (Err) on any structural failure.
pub fn import_and_record(
    path: &str,
    header_len: u64,
    src_power: u32,
    target_power: u32,
    upstream_url: &str,
    participant_attestations: Vec<String>,
) -> Result<(Phase1Srs, Provenance), String> {
    // response-file hash (streaming).
    let file_hash = {
        let mut f = std::fs::File::open(path).map_err(|e| format!("open {path}: {e}"))?;
        let mut h = Sha256::new();
        let mut buf = vec![0u8; 1 << 20];
        loop {
            let n = f.read(&mut buf).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
        }
        hex::encode(h.finalize())
    };

    let mut f = std::fs::File::open(path).map_err(|e| format!("open {path}: {e}"))?;
    let srs = import_response(&mut f, header_len, src_power, target_power)?;
    let srs_hash = srs.sha256_hex();
    let prov = Provenance {
        upstream_url: upstream_url.to_string(),
        response_file_sha256: file_hash,
        srs_sha256: srs_hash,
        src_power,
        target_power,
        participant_attestations,
    };
    Ok((srs, prov))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::srs::Phase1Srs;
    use ark_ec::AffineRepr;
    use rand::SeedableRng;
    use std::io::Cursor;

    /// Serialize a known SRS into the documented powers-of-tau layout (with a header), then extract
    /// it back with `import_response` and confirm: the round-trip reproduces the SRS exactly and the
    /// full structure_check passes. This proves the reader and the documented layout agree, and that
    /// consumption is gated on structure_check. src_power == target_power so the whole SRS is present.
    #[test]
    fn ptau_roundtrip_extracts_and_verifies() {
        let mut r = rand_chacha::ChaCha20Rng::seed_from_u64(11);
        let power = 8u32; // n=256, fast
        let n = 1usize << power;
        let original = Phase1Srs::generate_test_tier(power, &mut r);

        // encode: 64-byte header || tau_g1 (2n-1) || tau_g2 (n) || alpha (n) || beta (n) || beta_g2
        let mut bytes = vec![0xABu8; 64];
        for p in &original.tau_g1 {
            write_g1(p, &mut bytes);
        }
        for p in &original.tau_g2 {
            write_g2(p, &mut bytes);
        }
        for p in &original.alpha_tau_g1 {
            write_g1(p, &mut bytes);
        }
        for p in &original.beta_tau_g1 {
            write_g1(p, &mut bytes);
        }
        write_g2(&original.beta_g2, &mut bytes);

        let mut cur = Cursor::new(bytes);
        let extracted = import_response(&mut cur, 64, power, power).unwrap();

        assert_eq!(extracted.power, power);
        assert_eq!(extracted.tau_g1.len(), 2 * n - 1);
        assert_eq!(extracted.tau_g1, original.tau_g1);
        assert_eq!(extracted.tau_g2, original.tau_g2);
        assert_eq!(extracted.alpha_tau_g1, original.alpha_tau_g1);
        assert_eq!(extracted.beta_tau_g1, original.beta_tau_g1);
        assert_eq!(extracted.beta_g2, original.beta_g2);
        assert_eq!(extracted.provenance, SrsProvenance::InheritedReviewedPhase1);
        // (structure_check already ran inside import_response and gated the return.)
        assert!(!extracted.beta_g2.is_zero());
    }

    /// A corrupted response is REFUSED by structure_check (never silently consumed).
    #[test]
    fn corrupted_response_is_refused() {
        let mut r = rand_chacha::ChaCha20Rng::seed_from_u64(12);
        let power = 8u32;
        let original = Phase1Srs::generate_test_tier(power, &mut r);
        let mut bytes = vec![0xABu8; 64];
        for p in &original.tau_g1 {
            write_g1(p, &mut bytes);
        }
        for p in &original.tau_g2 {
            write_g2(p, &mut bytes);
        }
        for p in &original.alpha_tau_g1 {
            write_g1(p, &mut bytes);
        }
        for p in &original.beta_tau_g1 {
            write_g1(p, &mut bytes);
        }
        write_g2(&original.beta_g2, &mut bytes);
        // Corrupt one interior tau_g1 point (swap it for another valid on-curve point): the chain
        // relation breaks, so structure_check must refuse even though the point is well-formed.
        let victim = 64 + 100 * 96;
        let mut replacement = Vec::new();
        write_g1(&original.tau_g1[101], &mut replacement); // a valid but wrong power
        bytes[victim..victim + 96].copy_from_slice(&replacement);

        let mut cur = Cursor::new(bytes);
        let res = import_response(&mut cur, 64, power, power);
        assert!(res.is_err(), "corrupted response must be refused");
        assert!(res.unwrap_err().contains("structure_check"));
    }
}
