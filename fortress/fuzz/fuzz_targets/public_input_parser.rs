//! §7 fuzz: Groth16 public-input wire parser (u64-LE count, then count x 32-byte-LE canonical
//! Fr). Total function on arbitrary bytes: bounded count, no unbounded allocation, no panic;
//! never accepts a non-canonical (>= r) scalar.
#![no_main]
use ark_bls12_381::Fr;
use ark_serialize::CanonicalDeserialize;
use libfuzzer_sys::fuzz_target;

fn parse(bytes: &[u8]) -> Option<Vec<Fr>> {
    if bytes.len() < 8 { return None; }
    let count = u64::from_le_bytes(bytes[0..8].try_into().unwrap()) as usize;
    if count > 1024 { return None; }                    // bound before allocating
    if bytes.len() != 8 + 32 * count { return None; }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        match Fr::deserialize_compressed(&bytes[8 + 32 * i..8 + 32 * (i + 1)]) {
            Ok(f) => out.push(f),
            Err(_) => return None,                       // non-canonical rejected
        }
    }
    Some(out)
}

fuzz_target!(|data: &[u8]| { let _ = parse(data); });
