//! §7 fuzz: 32-byte little-endian Fr canonicality (blst scalar check). No panic; the check
//! is a total function and accepts iff the value is < r.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut le = [0u8; 32];
    let n = data.len().min(32);
    le[..n].copy_from_slice(&data[..n]);
    unsafe {
        let mut s = blst::blst_scalar::default();
        blst::blst_scalar_from_lendian(&mut s, le.as_ptr());
        let ok = blst::blst_scalar_fr_check(&s);
        // if it passed the check, converting to/from must be stable
        if ok {
            let mut out = [0u8; 32];
            blst::blst_lendian_from_scalar(out.as_mut_ptr(), &s);
            let mut s2 = blst::blst_scalar::default();
            blst::blst_scalar_from_lendian(&mut s2, out.as_ptr());
            assert!(blst::blst_scalar_fr_check(&s2), "canonical scalar failed re-check");
        }
    }
});
