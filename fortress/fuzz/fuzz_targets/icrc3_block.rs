//! §7 fuzz: ICRC-3 block candid decoder (the replayer's block value shape). A malformed block
//! blob must yield Err from candid, never a panic or an unbounded allocation.
#![no_main]
use libfuzzer_sys::fuzz_target;
use soak::candid_types::{BlockEntry, GetBlocksResult, Value};
fuzz_target!(|data: &[u8]| {
    let _ = candid::decode_one::<Value>(data);
    let _ = candid::decode_one::<BlockEntry>(data);
    let _ = candid::decode_one::<GetBlocksResult>(data);
});
