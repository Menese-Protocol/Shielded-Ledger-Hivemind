//! Randomized, model-checked PocketIC soak suite for the shielded ledger.
//!
//! Modules are layered bottom-up: `crypto` (wire encoding + Merkle mirror), `keys` (keyset
//! reproduction + frozen-fixture gate), and `icrc3_hash` have no PocketIC dependency and are
//! unit-tested in isolation; `bench` measures native proving throughput; `mint_guard` holds the
//! named counterfeit-mint circuit checks; `model`/`prover`/`pic_env`/`runner` build the
//! state-machine soak; `scan`, `replayer`, `observer`, and `cert` are the independent
//! verification paths the battery compares against.

pub mod bench;
pub mod candid_types;
pub mod cert;
pub mod crypto;
pub mod icrc3_hash;
pub mod keys;
pub mod mint_guard;
pub mod model;
pub mod observer;
pub mod pic_env;
pub mod prover;
pub mod replayer;
pub mod runner;
pub mod scan;
