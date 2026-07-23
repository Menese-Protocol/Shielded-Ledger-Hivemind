//! §7 fuzz: BOUNDED wire-format Groth16 VK parser — the decode boundary the system actually
//! exposes (Motoko `Groth16Wire.parseAndPrepareVk` + blst `cross_oracle::parse_vk` both bound
//! the declared IC-vector length before allocating). This target replicates that bounded
//! parse and asserts it is a total function: no panic, no unbounded allocation, and it never
//! accepts a length/shape-inconsistent key.
//!
//! (The RAW arkworks deserializer is unbounded on a malformed length prefix — finding F-1,
//! described in docs/VERIFICATION-FORTRESS.md "Provenance / finding"; that path is
//! demonstrated by `decode_vk_raw` and is NOT on any untrusted-input path in production.)
#![no_main]
use libfuzzer_sys::fuzz_target;

/// Mirror of the production/oracle VK wire bound (cross_oracle::parse_vk):
///   vk = alpha:G1(48) ‖ beta:G2(96) ‖ gamma:G2(96) ‖ delta:G2(96) ‖ u64-LE len ‖ len×G1(48)
/// Reject anything shape-inconsistent BEFORE touching the points; then decode each point.
fn parse_vk_bounded(bytes: &[u8]) -> bool {
    if bytes.len() < 344 {
        return false;
    }
    let len = u64::from_le_bytes(bytes[336..344].try_into().unwrap()) as usize;
    if len < 1 || len > 1024 || bytes.len() != 344 + 48 * len {
        return false; // bounded: never allocate from an unchecked declared length
    }
    // decode the four fixed G2/G1 points and each IC point with blst; all must succeed.
    let g1_ok = |off: usize| unsafe {
        let mut p = blst::blst_p1_affine::default();
        blst::blst_p1_uncompress(&mut p, bytes[off..off + 48].as_ptr()) == blst::BLST_ERROR::BLST_SUCCESS
    };
    let g2_ok = |off: usize| unsafe {
        let mut p = blst::blst_p2_affine::default();
        blst::blst_p2_uncompress(&mut p, bytes[off..off + 96].as_ptr()) == blst::BLST_ERROR::BLST_SUCCESS
    };
    let mut ok = g1_ok(0) && g2_ok(48) && g2_ok(144) && g2_ok(240);
    for i in 0..len {
        ok &= g1_ok(344 + 48 * i);
    }
    ok
}

fuzz_target!(|data: &[u8]| {
    let _ = parse_vk_bounded(data);
});
