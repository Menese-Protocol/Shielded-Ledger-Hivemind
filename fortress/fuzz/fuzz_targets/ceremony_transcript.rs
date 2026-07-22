//! §7 fuzz: ceremony transcript-level decode. A transcript is a sequence of contribution
//! deltas; this target frames the input as length-prefixed delta records and decodes each,
//! asserting the decoder is total (no panic / unbounded alloc) on arbitrary framing.
#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let mut off = 0usize;
    let mut budget = 64; // never loop unbounded on adversarial length prefixes
    while off + 4 <= data.len() && budget > 0 {
        let len = u32::from_le_bytes(data[off..off + 4].try_into().unwrap()) as usize;
        off += 4;
        if len > data.len() - off { break; }
        let _ = ceremony::transcript::delta_from_wire(&data[off..off + len]);
        off += len;
        budget -= 1;
    }
});
