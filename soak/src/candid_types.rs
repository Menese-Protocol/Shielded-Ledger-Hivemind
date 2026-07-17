//! Candid type mirror of the exact Motoko/Rust canister interfaces the harness drives. Field
//! names and shapes match `src/Main.mo`, `tests/IcpLedgerFixture.mo`, and `nns_adapter`. Blob
//! fields use `ByteBuf` so they encode as candid `blob`.

use candid::{CandidType, Nat, Principal};
use serde::Deserialize;
use serde_bytes::ByteBuf;

pub type Blob = ByteBuf;

pub fn blob(bytes: impl Into<Vec<u8>>) -> Blob {
    ByteBuf::from(bytes.into())
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct Account {
    pub owner: Principal,
    pub subaccount: Option<Blob>,
}

// Motoko `Result<T> = variant { ok : T; err : text }`
#[derive(CandidType, Deserialize, Debug)]
#[allow(non_camel_case_types)]
pub enum MotokoResult<T> {
    ok(T),
    err(String),
}

impl<T> MotokoResult<T> {
    pub fn into_result(self) -> Result<T, String> {
        match self {
            MotokoResult::ok(v) => Ok(v),
            MotokoResult::err(e) => Err(e),
        }
    }
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct TreeState {
    pub filled: Vec<String>,
    pub root: String,
    pub next_index: u64,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct LedgerStatus {
    pub configured: bool,
    pub note_root: Blob,
    pub note_count: Nat,
    pub log_length: Nat,
    pub nullifier_count: Nat,
    pub historical_root_count: Nat,
    pub pool_value: Nat,
    pub epoch: Nat,
    pub tree_state: Option<TreeState>,
    pub transfer_statement_version: Nat,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct MutationResult {
    pub outcome: String,
    pub verifier_outcome: String,
    pub note_root: Blob,
    pub note_count: Nat,
    pub nullifier_count: Nat,
    pub pool_value: Nat,
    pub epoch: Nat,
}

#[derive(CandidType, Clone, Debug)]
pub struct DepositArgs {
    pub value: u64,
    pub from_subaccount: Option<Blob>,
    pub created_at_time: u64,
    pub client_nonce: Blob,
    pub commitment: Blob,
    pub ephemeral_key: Blob,
    pub note_ciphertext: Blob,
    pub proof_hex: String,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct OutputRecord {
    pub commitment: Blob,
    pub ephemeral_key: Blob,
    pub note_ciphertext: Blob,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct TransferArgs {
    pub anchor: Blob,
    pub nullifier_1: Blob,
    pub nullifier_2: Blob,
    pub output_1: OutputRecord,
    pub output_2: OutputRecord,
    pub fee: u64,
    pub v_pub_out: u64,
    pub recipient: Option<Account>,
    pub created_at_time: Option<u64>,
    pub proof_hex: String,
}

// ---- ICRC-3 block reading (ledger) ----

#[derive(CandidType, Clone, Debug)]
pub struct GetBlocksArgs {
    pub start: Nat,
    pub length: Nat,
}

/// ICRC-3 `Value` — the recursive representation-independent block value.
#[derive(CandidType, Deserialize, Clone, Debug)]
pub enum Value {
    Blob(Blob),
    Text(String),
    Nat(Nat),
    Int(candid::Int),
    Array(Vec<Value>),
    Map(Vec<(String, Value)>),
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct BlockEntry {
    pub id: Nat,
    pub block: Value,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct GetBlocksResult {
    pub log_length: Nat,
    pub blocks: Vec<BlockEntry>,
    // archived_blocks carries query callbacks (func refs); the soak ledger never archives, so we
    // decode it as an opaque reserved list to avoid pulling in the func type.
    pub archived_blocks: candid::Reserved,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct DataCertificate {
    pub certificate: Blob,
    pub hash_tree: Blob,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct CertifiedSnapshot {
    pub last_block_index: Option<Nat>,
    pub last_block_hash: Option<Blob>,
    pub note_root: Blob,
    pub note_count: Nat,
    pub encoding_version: Nat,
    pub archive_manifest: Blob,
    pub certificate: Option<Blob>,
    pub hash_tree: Blob,
}

// ---- token fixture (IcpLedgerFixture.mo) ----

#[derive(CandidType, Clone, Debug)]
pub struct ApproveArgs {
    pub from_subaccount: Option<Blob>,
    pub spender: Account,
    pub amount: Nat,
    pub expected_allowance: Option<Nat>,
    pub expires_at: Option<u64>,
    pub fee: Option<Nat>,
    pub memo: Option<Blob>,
    pub created_at_time: Option<u64>,
}
