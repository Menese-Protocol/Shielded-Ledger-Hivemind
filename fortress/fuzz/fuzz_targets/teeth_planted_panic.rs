//! §7 TEETH target: a decoder with a DELIBERATE panic on a specific malformed prefix. The
//! fuzzer must find the crashing input within the gate-tier budget, proving the fuzz harness
//! actually detects a decode bug (a target that can never crash is a stub). This target is
//! NEVER part of the real gate's pass criteria — it exists only to demonstrate detection and
//! its crash input becomes a stored regression.
#![no_main]
use libfuzzer_sys::fuzz_target;

fn buggy_decode(data: &[u8]) -> u32 {
    // realistic shape: a length-prefixed record whose "count" is trusted without bound.
    if data.len() >= 4 && &data[..4] == b"BUG!" {
        // planted: an unchecked index that panics on this exact prefix.
        let idx = data[4] as usize; // out of bounds when len==4
        return data[idx] as u32; // PANIC on the planted input
    }
    data.iter().map(|b| *b as u32).sum()
}

fuzz_target!(|data: &[u8]| {
    let _ = buggy_decode(data);
});
