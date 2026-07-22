//! §7 fuzz: soak checkpoint / stable-record decoder (bincode::deserialize::<Checkpoint>). The
//! checkpoint is the stable-state record the soak persists and reloads; a corrupt record must
//! yield Err, never a panic or an unbounded allocation.
#![no_main]
use libfuzzer_sys::fuzz_target;
use soak::checkpoint::Checkpoint;
fuzz_target!(|data: &[u8]| { let _ = bincode::deserialize::<Checkpoint>(data); });
