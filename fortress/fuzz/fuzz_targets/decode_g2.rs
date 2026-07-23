//! §7 fuzz: compressed G2 decoder robustness (blst). No panic / no UB; idempotent decode.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut b = [0u8; 96];
    let n = data.len().min(96);
    b[..n].copy_from_slice(&data[..n]);
    unsafe {
        let mut aff = blst::blst_p2_affine::default();
        if blst::blst_p2_uncompress(&mut aff, b.as_ptr()) == blst::BLST_ERROR::BLST_SUCCESS {
            let mut out = [0u8; 96];
            blst::blst_p2_affine_compress(out.as_mut_ptr(), &aff);
            let mut aff2 = blst::blst_p2_affine::default();
            assert_eq!(
                blst::blst_p2_uncompress(&mut aff2, out.as_ptr()),
                blst::BLST_ERROR::BLST_SUCCESS,
                "G2 decode not idempotent"
            );
        }
    }
});
