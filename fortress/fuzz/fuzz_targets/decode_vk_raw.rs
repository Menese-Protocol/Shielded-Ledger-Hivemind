//! §7 finding F-1 demonstration (NOT a gate target): the RAW arkworks VK deserializer is
//! unbounded on a malformed length prefix. Kept so the finding stays reproducible and as a
//! standing teeth that the bounded `decode_vk` target is the right boundary. The gate does
//! NOT run this target (it is a known, documented uncontrolled-allocation demonstration).
#![no_main]
use ark_bls12_381::Bls12_381;
use ark_groth16::VerifyingKey;
use ark_serialize::CanonicalDeserialize;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = VerifyingKey::<Bls12_381>::deserialize_compressed(data);
});
