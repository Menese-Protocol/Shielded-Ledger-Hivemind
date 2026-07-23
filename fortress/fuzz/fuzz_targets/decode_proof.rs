//! §7 fuzz: arkworks Groth16 Proof decoder robustness. No panic / no UB on arbitrary bytes.
#![no_main]
use ark_bls12_381::Bls12_381;
use ark_groth16::Proof;
use ark_serialize::CanonicalDeserialize;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // A malformed proof must yield Err, never a panic or a partial/UB value.
    let _ = Proof::<Bls12_381>::deserialize_compressed(data);
    let _ = Proof::<Bls12_381>::deserialize_uncompressed(data);
});
