//! §7 fuzz: ceremony contribution wire decoder (ceremony::transcript::delta_from_wire).
//! A malformed contribution must yield Err, never a panic / unbounded allocation.
#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| { let _ = ceremony::transcript::delta_from_wire(data); });
