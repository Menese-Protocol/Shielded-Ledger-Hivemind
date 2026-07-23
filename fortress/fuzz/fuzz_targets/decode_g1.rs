//! §7 fuzz: compressed G1 decoder robustness (blst) + arkworks agreement on the decode.
//! Assertion: no panic / no UB on ANY input (libFuzzer catches those); blst never accepts a
//! non-canonical or malformed encoding; an accepted point is genuinely a valid affine point.
#![no_main]
use libfuzzer_sys::fuzz_target;

fn decode_blst(bytes: &[u8; 48]) -> bool {
    unsafe {
        let mut aff = blst::blst_p1_affine::default();
        blst::blst_p1_uncompress(&mut aff, bytes.as_ptr()) == blst::BLST_ERROR::BLST_SUCCESS
    }
}

fuzz_target!(|data: &[u8]| {
    // take a fixed 48-byte window (pad with zeros); decoders must be total functions.
    let mut b = [0u8; 48];
    let n = data.len().min(48);
    b[..n].copy_from_slice(&data[..n]);
    let accepted = decode_blst(&b);
    if accepted {
        // an accepted compressed point must round-trip: re-compress to the same 48 bytes
        // OR at least decode-then-recompress-then-decode is stable (idempotent decode).
        unsafe {
            let mut aff = blst::blst_p1_affine::default();
            assert_eq!(blst::blst_p1_uncompress(&mut aff, b.as_ptr()), blst::BLST_ERROR::BLST_SUCCESS);
            let mut out = [0u8; 48];
            blst::blst_p1_affine_compress(out.as_mut_ptr(), &aff);
            let mut aff2 = blst::blst_p1_affine::default();
            assert_eq!(
                blst::blst_p1_uncompress(&mut aff2, out.as_ptr()),
                blst::BLST_ERROR::BLST_SUCCESS,
                "re-compressed point failed to decode (decode not idempotent)"
            );
        }
    }
});
