//! Pinned legacy NNS ICP Candid/protobuf model.
//!
//! Oracle source: dfinity/ic c6a37193d91ddad3254fccce83fff18809fbbc1d.

use candid::{CandidType, Int};
use prost::Message;
use serde::Deserialize;
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha224, Sha256};

#[derive(Clone, Copy, Debug, CandidType, Deserialize, PartialEq, Eq)]
pub struct Tokens {
    pub e8s: u64,
}

#[derive(Clone, Copy, Debug, CandidType, Deserialize, PartialEq, Eq)]
pub struct TimeStamp {
    pub timestamp_nanos: u64,
}

#[derive(Clone, Debug, CandidType, Deserialize, PartialEq, Eq)]
pub enum Operation {
    Mint {
        to: ByteBuf,
        amount: Tokens,
    },
    Burn {
        from: ByteBuf,
        spender: Option<ByteBuf>,
        amount: Tokens,
    },
    Transfer {
        from: ByteBuf,
        to: ByteBuf,
        amount: Tokens,
        fee: Tokens,
        spender: Option<ByteBuf>,
    },
    Approve {
        from: ByteBuf,
        spender: ByteBuf,
        allowance_e8s: Int,
        allowance: Tokens,
        fee: Tokens,
        expires_at: Option<TimeStamp>,
        expected_allowance: Option<Tokens>,
    },
}

#[derive(Clone, Debug, CandidType, Deserialize, PartialEq, Eq)]
pub struct Transaction {
    pub memo: u64,
    pub icrc1_memo: Option<ByteBuf>,
    pub operation: Option<Operation>,
    pub created_at_time: TimeStamp,
}

#[derive(Clone, Debug, CandidType, Deserialize, PartialEq, Eq)]
pub struct Block {
    pub parent_hash: Option<ByteBuf>,
    pub transaction: Transaction,
    pub timestamp: TimeStamp,
}

#[derive(Clone, Copy, Debug, CandidType, Deserialize, PartialEq, Eq)]
pub struct GetBlocksArgs {
    pub start: u64,
    pub length: u64,
}

#[derive(Clone, Debug, CandidType, Deserialize, PartialEq, Eq)]
pub struct BlockRange {
    pub blocks: Vec<Block>,
}

#[derive(Clone, Debug, CandidType, Deserialize, PartialEq, Eq)]
pub enum GetBlocksError {
    BadFirstBlockIndex {
        requested_index: u64,
        first_valid_index: u64,
    },
    Other {
        error_code: u64,
        error_message: String,
    },
}

pub type GetBlocksResult = Result<BlockRange, GetBlocksError>;
pub type GetEncodedBlocksResult = Result<Vec<ByteBuf>, GetBlocksError>;

candid::define_function!(pub QueryArchiveFn : (GetBlocksArgs) -> (GetBlocksResult) query);
candid::define_function!(pub QueryArchiveEncodedFn : (GetBlocksArgs) -> (GetEncodedBlocksResult) query);

#[derive(Clone, Debug, CandidType, Deserialize, PartialEq, Eq)]
pub struct ArchivedBlocksRange {
    pub start: u64,
    pub length: u64,
    pub callback: QueryArchiveFn,
}

#[derive(Clone, Debug, CandidType, Deserialize, PartialEq, Eq)]
pub struct ArchivedEncodedBlocksRange {
    pub start: u64,
    pub length: u64,
    pub callback: QueryArchiveEncodedFn,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct QueryBlocksResponse {
    pub chain_length: u64,
    pub certificate: Option<ByteBuf>,
    pub blocks: Vec<Block>,
    pub first_block_index: u64,
    pub archived_blocks: Vec<ArchivedBlocksRange>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct QueryEncodedBlocksResponse {
    pub chain_length: u64,
    pub certificate: Option<ByteBuf>,
    pub blocks: Vec<ByteBuf>,
    pub first_block_index: u64,
    pub archived_blocks: Vec<ArchivedEncodedBlocksRange>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct Archives {
    pub archives: Vec<Archive>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct Archive {
    pub canister_id: candid::Principal,
}

#[derive(Clone, PartialEq, Message)]
pub struct PbBlock {
    #[prost(message, optional, tag = "1")]
    pub parent_hash: Option<PbHash>,
    #[prost(message, optional, tag = "2")]
    pub timestamp: Option<PbTimeStamp>,
    #[prost(message, optional, tag = "3")]
    pub transaction: Option<PbTransaction>,
}

#[derive(Clone, PartialEq, Message)]
pub struct PbHash {
    #[prost(bytes = "vec", tag = "1")]
    pub hash: Vec<u8>,
}

#[derive(Clone, Copy, PartialEq, Message)]
pub struct PbTimeStamp {
    #[prost(uint64, tag = "1")]
    pub timestamp_nanos: u64,
}

#[derive(Clone, PartialEq, Message)]
pub struct PbTransaction {
    #[prost(message, optional, tag = "4")]
    pub memo: Option<PbMemo>,
    #[prost(message, optional, tag = "7")]
    pub icrc1_memo: Option<PbIcrc1Memo>,
    #[prost(message, optional, tag = "5")]
    pub created_at: Option<PbBlockIndex>,
    #[prost(message, optional, tag = "6")]
    pub created_at_time: Option<PbTimeStamp>,
    #[prost(oneof = "pb_transaction::Transfer", tags = "1, 2, 3")]
    pub transfer: Option<pb_transaction::Transfer>,
}

pub mod pb_transaction {
    use super::{PbBurn, PbMint, PbSend};
    use prost::Oneof;

    #[derive(Clone, PartialEq, Oneof)]
    pub enum Transfer {
        #[prost(message, tag = "1")]
        Burn(PbBurn),
        #[prost(message, tag = "2")]
        Mint(PbMint),
        #[prost(message, tag = "3")]
        Send(PbSend),
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct PbSend {
    #[prost(message, optional, tag = "1")]
    pub from: Option<PbAccountIdentifier>,
    #[prost(message, optional, tag = "2")]
    pub to: Option<PbAccountIdentifier>,
    #[prost(message, optional, tag = "3")]
    pub amount: Option<PbTokens>,
    #[prost(message, optional, tag = "4")]
    pub max_fee: Option<PbTokens>,
    #[prost(oneof = "pb_send::Extension", tags = "5, 6")]
    pub extension: Option<pb_send::Extension>,
}

pub mod pb_send {
    use super::{PbApprove, PbTransferFrom};
    use prost::Oneof;

    #[derive(Clone, PartialEq, Oneof)]
    pub enum Extension {
        #[prost(message, tag = "5")]
        Approve(PbApprove),
        #[prost(message, tag = "6")]
        TransferFrom(PbTransferFrom),
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct PbTransferFrom {
    #[prost(message, optional, tag = "1")]
    pub spender: Option<PbAccountIdentifier>,
}

#[derive(Clone, Copy, PartialEq, Message)]
pub struct PbApprove {
    #[prost(message, optional, tag = "1")]
    pub allowance: Option<PbTokens>,
    #[prost(message, optional, tag = "2")]
    pub expires_at: Option<PbTimeStamp>,
    #[prost(message, optional, tag = "3")]
    pub expected_allowance: Option<PbTokens>,
}

#[derive(Clone, PartialEq, Message)]
pub struct PbMint {
    #[prost(message, optional, tag = "2")]
    pub to: Option<PbAccountIdentifier>,
    #[prost(message, optional, tag = "3")]
    pub amount: Option<PbTokens>,
}

#[derive(Clone, PartialEq, Message)]
pub struct PbBurn {
    #[prost(message, optional, tag = "1")]
    pub from: Option<PbAccountIdentifier>,
    #[prost(message, optional, tag = "3")]
    pub amount: Option<PbTokens>,
    #[prost(message, optional, tag = "4")]
    pub spender: Option<PbAccountIdentifier>,
}

#[derive(Clone, PartialEq, Message)]
pub struct PbAccountIdentifier {
    #[prost(bytes = "vec", tag = "1")]
    pub hash: Vec<u8>,
}

#[derive(Clone, Copy, PartialEq, Message)]
pub struct PbTokens {
    #[prost(uint64, tag = "1")]
    pub e8s: u64,
}

#[derive(Clone, Copy, PartialEq, Message)]
pub struct PbMemo {
    #[prost(uint64, tag = "1")]
    pub memo: u64,
}

#[derive(Clone, PartialEq, Message)]
pub struct PbIcrc1Memo {
    #[prost(bytes = "vec", tag = "1")]
    pub memo: Vec<u8>,
}

#[derive(Clone, Copy, PartialEq, Message)]
pub struct PbBlockIndex {
    #[prost(uint64, tag = "1")]
    pub height: u64,
}

#[derive(Clone, Debug)]
pub struct DecodedBlock {
    pub block: Block,
    pub created_at_time_present: bool,
    pub encoded_hash: [u8; 32],
}

fn required<T>(value: Option<T>, field: &str) -> Result<T, String> {
    value.ok_or_else(|| format!("missing protobuf field {field}"))
}

fn canonical_account(value: PbAccountIdentifier) -> Result<ByteBuf, String> {
    match value.hash.len() {
        28 => {
            let checksum = crc32fast::hash(&value.hash).to_be_bytes();
            let mut result = Vec::with_capacity(32);
            result.extend_from_slice(&checksum);
            result.extend_from_slice(&value.hash);
            Ok(ByteBuf::from(result))
        }
        32 => {
            let checksum = crc32fast::hash(&value.hash[4..]).to_be_bytes();
            if value.hash[..4] != checksum {
                return Err("account identifier checksum mismatch".into());
            }
            Ok(ByteBuf::from(value.hash))
        }
        length => Err(format!("account identifier has invalid length {length}")),
    }
}

fn pb_tokens(value: Option<PbTokens>, field: &str) -> Result<Tokens, String> {
    Ok(Tokens {
        e8s: required(value, field)?.e8s,
    })
}

fn decode_operation(value: pb_transaction::Transfer) -> Result<Operation, String> {
    use pb_send::Extension;
    use pb_transaction::Transfer;
    match value {
        Transfer::Mint(value) => Ok(Operation::Mint {
            to: canonical_account(required(value.to, "mint.to")?)?,
            amount: pb_tokens(value.amount, "mint.amount")?,
        }),
        Transfer::Burn(value) => Ok(Operation::Burn {
            from: canonical_account(required(value.from, "burn.from")?)?,
            spender: value.spender.map(canonical_account).transpose()?,
            amount: pb_tokens(value.amount, "burn.amount")?,
        }),
        Transfer::Send(value) => {
            let from = canonical_account(required(value.from, "send.from")?)?;
            let to = canonical_account(required(value.to, "send.to")?)?;
            let amount = pb_tokens(value.amount, "send.amount")?;
            let fee = pb_tokens(value.max_fee, "send.max_fee")?;
            match value.extension {
                None => Ok(Operation::Transfer {
                    from,
                    to,
                    amount,
                    fee,
                    spender: None,
                }),
                Some(Extension::TransferFrom(extension)) => Ok(Operation::Transfer {
                    from,
                    to,
                    amount,
                    fee,
                    spender: Some(canonical_account(required(
                        extension.spender,
                        "transfer_from.spender",
                    )?)?),
                }),
                Some(Extension::Approve(extension)) => {
                    let allowance = pb_tokens(extension.allowance, "approve.allowance")?;
                    Ok(Operation::Approve {
                        from,
                        spender: to,
                        allowance_e8s: Int::from(allowance.e8s),
                        allowance,
                        fee,
                        expires_at: extension.expires_at.map(|value| TimeStamp {
                            timestamp_nanos: value.timestamp_nanos,
                        }),
                        expected_allowance: extension
                            .expected_allowance
                            .map(|value| Tokens { e8s: value.e8s }),
                    })
                }
            }
        }
    }
}

pub fn decode_exact(encoded: &[u8]) -> Result<DecodedBlock, String> {
    let protobuf = PbBlock::decode(encoded).map_err(|error| error.to_string())?;
    let mut roundtrip = Vec::with_capacity(protobuf.encoded_len());
    protobuf
        .encode(&mut roundtrip)
        .map_err(|error| error.to_string())?;
    if roundtrip != encoded {
        let first = roundtrip
            .iter()
            .zip(encoded)
            .position(|(left, right)| left != right)
            .unwrap_or(roundtrip.len().min(encoded.len()));
        return Err(format!(
            "protobuf decode/re-encode differs byte-for-byte at {first}: encoded={} reencoded={}",
            hex::encode(encoded),
            hex::encode(&roundtrip),
        ));
    }
    let parent_hash = protobuf
        .parent_hash
        .map(|value| {
            if value.hash.len() != 32 {
                return Err("parent hash is not 32 bytes".to_string());
            }
            Ok(ByteBuf::from(value.hash))
        })
        .transpose()?;
    let timestamp = required(protobuf.timestamp, "block.timestamp")?.timestamp_nanos;
    let transaction = required(protobuf.transaction, "block.transaction")?;
    if transaction.created_at.is_some() {
        return Err("obsolete created_at block index is unsupported".into());
    }
    let created_at_time_present = transaction.created_at_time.is_some();
    let created_at_time = transaction
        .created_at_time
        .map(|value| value.timestamp_nanos)
        .unwrap_or(timestamp);
    let operation = transaction.transfer.map(decode_operation).transpose()?;
    let block = Block {
        parent_hash,
        transaction: Transaction {
            memo: transaction.memo.map(|value| value.memo).unwrap_or(0),
            icrc1_memo: transaction
                .icrc1_memo
                .map(|value| ByteBuf::from(value.memo)),
            operation,
            created_at_time: TimeStamp {
                timestamp_nanos: created_at_time,
            },
        },
        timestamp: TimeStamp {
            timestamp_nanos: timestamp,
        },
    };
    Ok(DecodedBlock {
        block,
        created_at_time_present,
        encoded_hash: Sha256::digest(encoded).into(),
    })
}

fn pb_account(value: &ByteBuf) -> PbAccountIdentifier {
    PbAccountIdentifier {
        hash: value.as_ref().to_vec(),
    }
}

fn pb_amount(value: Tokens) -> PbTokens {
    PbTokens { e8s: value.e8s }
}

fn encode_operation(operation: &Operation) -> pb_transaction::Transfer {
    use pb_send::Extension;
    use pb_transaction::Transfer;
    match operation {
        Operation::Mint { to, amount } => Transfer::Mint(PbMint {
            to: Some(pb_account(to)),
            amount: Some(pb_amount(*amount)),
        }),
        Operation::Burn {
            from,
            spender,
            amount,
        } => Transfer::Burn(PbBurn {
            from: Some(pb_account(from)),
            amount: Some(pb_amount(*amount)),
            spender: spender.as_ref().map(pb_account),
        }),
        Operation::Transfer {
            from,
            to,
            amount,
            fee,
            spender,
        } => Transfer::Send(PbSend {
            from: Some(pb_account(from)),
            to: Some(pb_account(to)),
            amount: Some(pb_amount(*amount)),
            max_fee: Some(pb_amount(*fee)),
            extension: spender.as_ref().map(|spender| {
                Extension::TransferFrom(PbTransferFrom {
                    spender: Some(pb_account(spender)),
                })
            }),
        }),
        Operation::Approve {
            from,
            spender,
            allowance,
            fee,
            expires_at,
            expected_allowance,
            ..
        } => Transfer::Send(PbSend {
            from: Some(pb_account(from)),
            to: Some(pb_account(spender)),
            amount: Some(pb_amount(Tokens { e8s: 0 })),
            max_fee: Some(pb_amount(*fee)),
            extension: Some(Extension::Approve(PbApprove {
                allowance: Some(pb_amount(*allowance)),
                expires_at: expires_at.map(|value| PbTimeStamp {
                    timestamp_nanos: value.timestamp_nanos,
                }),
                expected_allowance: expected_allowance.map(pb_amount),
            })),
        }),
    }
}

/// Reconstruct protobuf bytes from the lossy Candid block using an explicit construction-time
/// presence bit. This is used only as an oracle: encoded bytes remain the source of truth.
pub fn encode_from_candid(block: &Block, created_at_time_present: bool) -> Result<Vec<u8>, String> {
    let protobuf = PbBlock {
        parent_hash: block.parent_hash.as_ref().map(|value| PbHash {
            hash: value.as_ref().to_vec(),
        }),
        timestamp: Some(PbTimeStamp {
            timestamp_nanos: block.timestamp.timestamp_nanos,
        }),
        transaction: Some(PbTransaction {
            memo: Some(PbMemo {
                memo: block.transaction.memo,
            }),
            icrc1_memo: block.transaction.icrc1_memo.as_ref().map(|value| PbIcrc1Memo {
                memo: value.as_ref().to_vec(),
            }),
            created_at: None,
            created_at_time: created_at_time_present.then_some(PbTimeStamp {
                timestamp_nanos: block.transaction.created_at_time.timestamp_nanos,
            }),
            transfer: block
                .transaction
                .operation
                .as_ref()
                .map(encode_operation),
        }),
    };
    let mut output = Vec::with_capacity(protobuf.encoded_len());
    protobuf
        .encode(&mut output)
        .map_err(|error| error.to_string())?;
    Ok(output)
}

pub fn account_identifier(owner: &candid::Principal, subaccount: Option<&[u8]>) -> Result<[u8; 32], String> {
    let subaccount = match subaccount {
        Some(value) if value.len() == 32 => value,
        Some(value) => return Err(format!("subaccount has length {}, expected 32", value.len())),
        None => &[0_u8; 32],
    };
    let mut hash = Sha224::new();
    hash.update(b"\x0Aaccount-id");
    hash.update(owner.as_slice());
    hash.update(subaccount);
    let digest = hash.finalize();
    let checksum = crc32fast::hash(&digest).to_be_bytes();
    let mut result = [0_u8; 32];
    result[..4].copy_from_slice(&checksum);
    result[4..].copy_from_slice(&digest);
    Ok(result)
}

pub fn hash_encoded(encoded: &[u8]) -> [u8; 32] {
    Sha256::digest(encoded).into()
}
