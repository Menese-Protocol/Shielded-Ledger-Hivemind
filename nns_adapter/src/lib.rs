//! Certified local NNS ICP -> canonical ICRC-3 history adapter.
//!
//! Token mutation never passes through this canister. It obtains legacy history through replicated
//! inter-canister calls, byte-validates the paired protobuf/Candid forms, resolves the exact archive
//! callbacks, and emits canonical blocks only after account and transaction-provenance preimages
//! have been verified and sealed.

pub mod legacy;

use candid::{CandidType, Deserialize, Nat, Principal};
use ic_certification::{fork, labeled, leaf, HashTree};
use legacy::{
    account_identifier, decode_exact, hash_encoded, ArchivedBlocksRange,
    ArchivedEncodedBlocksRange, Block as LegacyBlock, GetBlocksArgs as LegacyGetBlocksArgs,
    GetBlocksResult as LegacyGetBlocksResult,
    GetEncodedBlocksResult as LegacyGetEncodedBlocksResult, Operation as LegacyOperation,
    QueryBlocksResponse, QueryEncodedBlocksResponse,
};
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

const ICRC3_URL: &str = "https://github.com/dfinity/ICRC-1/tree/5d670e54d9a58fbf472bf0a25f33743d60cfd0e6/standards/ICRC-3";

#[derive(Clone, Debug, CandidType, Deserialize, PartialEq, Eq)]
pub enum Value {
    Blob(ByteBuf),
    Text(String),
    Nat(Nat),
    Int(candid::Int),
    Array(Vec<Value>),
    Map(Vec<(String, Value)>),
}

#[derive(Clone, Debug, CandidType, Deserialize, PartialEq, Eq)]
pub struct Account {
    pub owner: Principal,
    pub subaccount: Option<ByteBuf>,
}

#[derive(Clone, Debug, CandidType, Deserialize, PartialEq, Eq)]
pub struct TransactionHint {
    pub block_index: u64,
    pub btype: String,
    pub from: Account,
    pub to: Option<Account>,
    pub spender: Option<Account>,
    pub amount: u64,
    pub effective_fee: u64,
    pub fee_was_supplied: bool,
    pub memo: Option<ByteBuf>,
    pub created_at_time: Option<u64>,
    pub expected_allowance: Option<u64>,
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
#[allow(non_camel_case_types)]
pub enum TextResult {
    ok(String),
    err(String),
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct Metadata {
    pub configured: bool,
    pub ledger: Option<Principal>,
    pub fee: Option<Nat>,
    pub decimals: Option<u8>,
    pub source_blocks: Nat,
    pub translated_blocks: Nat,
    pub registered_accounts: Nat,
    pub registered_hints: Nat,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct SyncReport {
    pub source_blocks: Nat,
    pub translated_blocks: Nat,
    pub archive_ranges: Nat,
    pub encoded_roundtrips: Nat,
    pub candid_semantic_matches: Nat,
    pub source_tip_hash: Option<ByteBuf>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
#[allow(non_camel_case_types)]
pub enum SyncResult {
    ok(SyncReport),
    err(String),
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct GetBlocksArgs {
    pub start: Nat,
    pub length: Nat,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct BlockWithId {
    pub id: Nat,
    pub block: Value,
}

candid::define_function!(pub GetBlocksCallback : (Vec<GetBlocksArgs>) -> (GetBlocksResult) query);

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct ArchivedBlocks {
    pub args: Vec<GetBlocksArgs>,
    pub callback: GetBlocksCallback,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct GetBlocksResult {
    pub log_length: Nat,
    pub blocks: Vec<BlockWithId>,
    pub archived_blocks: Vec<ArchivedBlocks>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct GetArchivesArgs {
    pub from: Option<Principal>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct ArchiveInfo {
    pub canister_id: Principal,
    pub start: Nat,
    pub end: Nat,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct BlockType {
    pub block_type: String,
    pub url: String,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct DataCertificate {
    pub certificate: ByteBuf,
    pub hash_tree: ByteBuf,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct AuditBinding {
    pub adapter_tip_index: Option<Nat>,
    pub adapter_tip_hash: Option<ByteBuf>,
    pub source_tip_hash: Option<ByteBuf>,
    pub source_ledger: Option<Principal>,
}

#[derive(Clone)]
struct SourceBlock {
    candid: LegacyBlock,
    encoded: Vec<u8>,
    encoded_hash: [u8; 32],
    created_at_time_present: bool,
}

#[derive(Default)]
struct State {
    ledger: Option<Principal>,
    registrar: Option<Principal>,
    fee: Option<Nat>,
    decimals: Option<u8>,
    accounts: BTreeMap<[u8; 32], Account>,
    hints: BTreeMap<u64, TransactionHint>,
    sealed_conflicts: BTreeSet<u64>,
    source: Vec<SourceBlock>,
    translated: Vec<Value>,
    archive_ranges: usize,
    encoded_roundtrips: usize,
    candid_semantic_matches: usize,
}

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
}

fn text_result(result: Result<String, String>) -> TextResult {
    match result {
        Ok(value) => TextResult::ok(value),
        Err(error) => TextResult::err(error),
    }
}

fn account_id(account: &Account) -> Result<[u8; 32], String> {
    account_identifier(
        &account.owner,
        account.subaccount.as_ref().map(|value| value.as_ref()),
    )
}

fn account_value(account: &Account) -> Value {
    let mut values = vec![Value::Blob(ByteBuf::from(account.owner.as_slice().to_vec()))];
    if let Some(subaccount) = &account.subaccount {
        values.push(Value::Blob(subaccount.clone()));
    }
    Value::Array(values)
}

fn nat(value: u64) -> Value {
    Value::Nat(Nat::from(value))
}

pub fn hash_value(value: &Value) -> [u8; 32] {
    match value {
        Value::Blob(value) => Sha256::digest(value.as_ref()).into(),
        Value::Text(value) => Sha256::digest(value.as_bytes()).into(),
        Value::Nat(value) => {
            let mut digits = value.0.to_radix_le(128);
            if digits.is_empty() {
                digits.push(0);
            }
            let last = digits.len() - 1;
            for digit in &mut digits[..last] {
                *digit |= 0x80;
            }
            Sha256::digest(digits).into()
        }
        Value::Int(value) => {
            let mut number = value.0.clone();
            let mut encoded = Vec::new();
            loop {
                let low = ((&number % 128_u16) + 128_u16) % 128_u16;
                let byte = low.to_u32_digits().1.first().copied().unwrap_or(0) as u8;
                let next = (&number - low) / 128_u16;
                let done = (next == 0.into() && byte & 0x40 == 0)
                    || (next == (-1).into() && byte & 0x40 != 0);
                encoded.push(if done { byte } else { byte | 0x80 });
                if done {
                    break;
                }
                number = next;
            }
            Sha256::digest(encoded).into()
        }
        Value::Array(values) => {
            let mut digest = Sha256::new();
            for value in values {
                digest.update(hash_value(value));
            }
            digest.finalize().into()
        }
        Value::Map(entries) => {
            let mut pairs: Vec<([u8; 32], [u8; 32])> = entries
                .iter()
                .map(|(key, value)| {
                    (
                        Sha256::digest(key.as_bytes()).into(),
                        hash_value(value),
                    )
                })
                .collect();
            pairs.sort_unstable();
            let mut digest = Sha256::new();
            for (key, value) in pairs {
                digest.update(key);
                digest.update(value);
            }
            digest.finalize().into()
        }
    }
}

fn leb128(value: usize) -> Vec<u8> {
    let mut output = Vec::new();
    leb128::write::unsigned(&mut output, value as u64).expect("Vec write cannot fail");
    output
}

fn certification_tree(state: &State) -> Option<HashTree> {
    let adapter_tip = state.translated.last()?;
    let source_tip = state.source.get(state.translated.len().checked_sub(1)?)?;
    let ledger = state.ledger?;
    Some(fork(
        labeled("last_block_hash", leaf(hash_value(adapter_tip).to_vec())),
        fork(
            labeled(
                "last_block_index",
                leaf(leb128(state.translated.len() - 1)),
            ),
            fork(
                labeled(
                    "source_ledger",
                    leaf(ledger.as_slice().to_vec()),
                ),
                labeled(
                    "source_legacy_tip_hash",
                    leaf(source_tip.encoded_hash.to_vec()),
                ),
            ),
        ),
    ))
}

fn refresh_certification(state: &State) {
    let digest = certification_tree(state)
        .map(|tree| tree.digest())
        .unwrap_or([0_u8; 32]);
    ic_cdk::api::set_certified_data(&digest);
}

fn registered_account(state: &State, account: &Account) -> Result<[u8; 32], String> {
    let id = account_id(account)?;
    match state.accounts.get(&id) {
        Some(registered) if registered == account => Ok(id),
        Some(_) => Err("account identifier collision with different preimage".into()),
        None => Err(format!("account preimage {} is not registered", hex::encode(id))),
    }
}

fn expect_account(
    state: &State,
    account: &Account,
    observed: &[u8],
    field: &str,
) -> Result<(), String> {
    let id = registered_account(state, account)?;
    if observed != id {
        return Err(format!("{field} account preimage does not match legacy identifier"));
    }
    Ok(())
}

fn verify_hint(state: &State, hint: &TransactionHint) -> Result<(), String> {
    let source = state
        .source
        .get(hint.block_index as usize)
        .ok_or_else(|| "source block has not been synced".to_string())?;
    if source.created_at_time_present != hint.created_at_time.is_some() {
        return Err("created_at_time presence bit differs from encoded protobuf".into());
    }
    if source.candid.transaction.icrc1_memo.as_ref() != hint.memo.as_ref() {
        return Err("memo presence/value differs from legacy block".into());
    }
    if source.candid.transaction.memo != 0 {
        return Err("numeric legacy memo is not an ICRC request hint".into());
    }
    if let Some(created_at_time) = hint.created_at_time {
        if source.candid.transaction.created_at_time.timestamp_nanos != created_at_time {
            return Err("created_at_time differs from legacy block".into());
        }
    } else if source.candid.transaction.created_at_time.timestamp_nanos
        != source.candid.timestamp.timestamp_nanos
    {
        return Err("absent construction time was not substituted by block time".into());
    }

    let operation = source
        .candid
        .transaction
        .operation
        .as_ref()
        .ok_or_else(|| "legacy operation is absent".to_string())?;
    match (hint.btype.as_str(), operation) {
        (
            "1xfer",
            LegacyOperation::Transfer {
                from,
                to,
                amount,
                fee,
                spender: None,
            },
        ) => {
            expect_account(state, &hint.from, from.as_ref(), "from")?;
            let to_hint = hint.to.as_ref().ok_or("1xfer hint is missing to")?;
            expect_account(state, to_hint, to.as_ref(), "to")?;
            if hint.spender.is_some() {
                return Err("1xfer hint unexpectedly has spender".into());
            }
            if hint.expected_allowance.is_some() || hint.expires_at.is_some() {
                return Err("1xfer hint contains approve-only fields".into());
            }
            if amount.e8s != hint.amount || fee.e8s != hint.effective_fee {
                return Err("1xfer amount/effective fee differs".into());
            }
        }
        (
            "2xfer",
            LegacyOperation::Transfer {
                from,
                to,
                amount,
                fee,
                spender: Some(observed_spender),
            },
        ) => {
            expect_account(state, &hint.from, from.as_ref(), "from")?;
            expect_account(
                state,
                hint.to.as_ref().ok_or("2xfer hint is missing to")?,
                to.as_ref(),
                "to",
            )?;
            expect_account(
                state,
                hint.spender.as_ref().ok_or("2xfer hint is missing spender")?,
                observed_spender.as_ref(),
                "spender",
            )?;
            if amount.e8s != hint.amount || fee.e8s != hint.effective_fee {
                return Err("2xfer amount/effective fee differs".into());
            }
            if hint.expected_allowance.is_some() || hint.expires_at.is_some() {
                return Err("2xfer hint contains approve-only fields".into());
            }
        }
        (
            "2approve",
            LegacyOperation::Approve {
                from,
                spender,
                allowance,
                allowance_e8s,
                fee,
                expires_at,
                expected_allowance,
                ..
            },
        ) => {
            expect_account(state, &hint.from, from.as_ref(), "from")?;
            expect_account(
                state,
                hint
                    .spender
                    .as_ref()
                    .ok_or("2approve hint is missing spender")?,
                spender.as_ref(),
                "spender",
            )?;
            if hint.to.is_some() {
                return Err("2approve hint unexpectedly has to".into());
            }
            if allowance.e8s != hint.amount || fee.e8s != hint.effective_fee {
                return Err("2approve allowance/effective fee differs".into());
            }
            if allowance_e8s != &candid::Int::from(allowance.e8s) {
                return Err("2approve deprecated allowance_e8s differs from allowance".into());
            }
            if expires_at.map(|value| value.timestamp_nanos) != hint.expires_at
                || expected_allowance.map(|value| value.e8s) != hint.expected_allowance
            {
                return Err("2approve optional fields differ".into());
            }
        }
        _ => return Err("hint operation kind differs from legacy operation".into()),
    }
    Ok(())
}

fn translate(state: &State, hint: &TransactionHint, parent: Option<[u8; 32]>) -> Value {
    let source = &state.source[hint.block_index as usize];
    let mut tx = vec![
        ("amt".into(), nat(hint.amount)),
        ("from".into(), account_value(&hint.from)),
    ];
    if let Some(to) = &hint.to {
        tx.push(("to".into(), account_value(to)));
    }
    if let Some(spender) = &hint.spender {
        tx.push(("spender".into(), account_value(spender)));
    }
    if hint.fee_was_supplied {
        tx.push(("fee".into(), nat(hint.effective_fee)));
    }
    if let Some(memo) = &hint.memo {
        tx.push(("memo".into(), Value::Blob(memo.clone())));
    }
    if let Some(created_at_time) = hint.created_at_time {
        tx.push(("ts".into(), nat(created_at_time)));
    }
    if let Some(expected_allowance) = hint.expected_allowance {
        tx.push((
            "expected_allowance".into(),
            nat(expected_allowance),
        ));
    }
    if let Some(expires_at) = hint.expires_at {
        tx.push(("expires_at".into(), nat(expires_at)));
    }
    let mut block = vec![("btype".into(), Value::Text(hint.btype.clone()))];
    if !hint.fee_was_supplied {
        block.push(("fee".into(), nat(hint.effective_fee)));
    }
    if let Some(parent) = parent {
        block.push(("phash".into(), Value::Blob(ByteBuf::from(parent.to_vec()))));
    }
    block.push((
        "ts".into(),
        nat(source.candid.timestamp.timestamp_nanos),
    ));
    block.push(("tx".into(), Value::Map(tx)));
    Value::Map(block)
}

fn rebuild_translated(state: &mut State) -> Result<(), String> {
    let mut translated = Vec::new();
    for index in 0..state.source.len() {
        let Some(hint) = state.hints.get(&(index as u64)) else {
            break;
        };
        verify_hint(state, hint)?;
        let parent = translated.last().map(hash_value);
        translated.push(translate(state, hint, parent));
    }
    state.translated = translated;
    refresh_certification(state);
    Ok(())
}

async fn call_ledger<R>(
    canister: Principal,
    method: &str,
    args: impl candid::utils::ArgumentEncoder,
) -> Result<R, String>
where
    R: for<'a> candid::utils::ArgumentDecoder<'a>,
{
    ic_cdk::call::<_, R>(canister, method, args)
        .await
        .map_err(|(code, message)| format!("{method} rejected {code:?}: {message}"))
}

fn place<T: Clone>(
    slots: &mut [Option<T>],
    start: u64,
    values: &[T],
    label: &str,
) -> Result<(), String> {
    for (offset, value) in values.iter().enumerate() {
        let index = start as usize + offset;
        let slot = slots
            .get_mut(index)
            .ok_or_else(|| format!("{label} block index {index} exceeds chain"))?;
        if slot.is_some() {
            return Err(format!("duplicate {label} block index {index}"));
        }
        *slot = Some(value.clone());
    }
    Ok(())
}

async fn resolve_candid_archives(
    slots: &mut [Option<LegacyBlock>],
    ranges: &[ArchivedBlocksRange],
) -> Result<(), String> {
    for range in ranges {
        if range.callback.0.method != "get_blocks" {
            return Err(format!(
                "unexpected legacy archive method {}",
                range.callback.0.method
            ));
        }
        let args = LegacyGetBlocksArgs {
            start: range.start,
            length: range.length,
        };
        let (result,): (LegacyGetBlocksResult,) = call_ledger(
            range.callback.0.principal,
            &range.callback.0.method,
            (args,),
        )
        .await?;
        let result = result.map_err(|error| format!("legacy archive error: {error:?}"))?;
        if result.blocks.len() != range.length as usize {
            return Err("legacy archive returned a partial declared range".into());
        }
        place(slots, range.start, &result.blocks, "legacy archive")?;
    }
    Ok(())
}

async fn resolve_encoded_archives(
    slots: &mut [Option<Vec<u8>>],
    ranges: &[ArchivedEncodedBlocksRange],
) -> Result<(), String> {
    for range in ranges {
        if range.callback.0.method != "get_encoded_blocks" {
            return Err(format!(
                "unexpected encoded archive method {}",
                range.callback.0.method
            ));
        }
        let args = LegacyGetBlocksArgs {
            start: range.start,
            length: range.length,
        };
        let (result,): (LegacyGetEncodedBlocksResult,) = call_ledger(
            range.callback.0.principal,
            &range.callback.0.method,
            (args,),
        )
        .await?;
        let result = result.map_err(|error| format!("encoded archive error: {error:?}"))?;
        if result.len() != range.length as usize {
            return Err("encoded archive returned a partial declared range".into());
        }
        let values: Vec<Vec<u8>> = result.into_iter().map(ByteBuf::into_vec).collect();
        place(slots, range.start, &values, "encoded archive")?;
    }
    Ok(())
}

fn validate_archive_pairing(
    candid: &[ArchivedBlocksRange],
    encoded: &[ArchivedEncodedBlocksRange],
) -> Result<(), String> {
    if candid.len() != encoded.len() {
        return Err("Candid/encoded archive range counts differ".into());
    }
    for (left, right) in candid.iter().zip(encoded) {
        if left.start != right.start
            || left.length != right.length
            || left.callback.0.principal != right.callback.0.principal
        {
            return Err("Candid/encoded archive callback identity or interval differs".into());
        }
    }
    Ok(())
}

async fn fetch_source(ledger: Principal) -> Result<(Vec<SourceBlock>, usize), String> {
    let request = LegacyGetBlocksArgs {
        start: 0,
        length: u32::MAX as u64,
    };
    let (candid,): (QueryBlocksResponse,) =
        call_ledger(ledger, "query_blocks", (request,)).await?;
    let (encoded,): (QueryEncodedBlocksResponse,) =
        call_ledger(ledger, "query_encoded_blocks", (request,)).await?;
    if candid.chain_length != encoded.chain_length {
        return Err("Candid/encoded chain lengths differ".into());
    }
    validate_archive_pairing(&candid.archived_blocks, &encoded.archived_blocks)?;
    let length = candid.chain_length as usize;
    let mut candid_slots = vec![None; length];
    let mut encoded_slots = vec![None; length];
    place(
        &mut candid_slots,
        candid.first_block_index,
        &candid.blocks,
        "ledger Candid",
    )?;
    let local_encoded: Vec<Vec<u8>> = encoded
        .blocks
        .iter()
        .map(|value| value.as_ref().to_vec())
        .collect();
    place(
        &mut encoded_slots,
        encoded.first_block_index,
        &local_encoded,
        "ledger encoded",
    )?;
    resolve_candid_archives(&mut candid_slots, &candid.archived_blocks).await?;
    resolve_encoded_archives(&mut encoded_slots, &encoded.archived_blocks).await?;
    let mut source: Vec<SourceBlock> = Vec::with_capacity(length);
    for index in 0..length {
        let candid = candid_slots[index]
            .take()
            .ok_or_else(|| format!("missing Candid block {index}"))?;
        let encoded = encoded_slots[index]
            .take()
            .ok_or_else(|| format!("missing encoded block {index}"))?;
        let decoded = decode_exact(&encoded)?;
        if decoded.block != candid {
            return Err(format!(
                "encoded protobuf and query_blocks semantics differ at {index}"
            ));
        }
        if index == 0 {
            if candid.parent_hash.is_some() {
                return Err("genesis block unexpectedly has parent hash".into());
            }
        } else {
            let expected = hash_encoded(&source[index - 1].encoded);
            if candid.parent_hash.as_ref().map(|value| value.as_ref()) != Some(expected.as_slice())
            {
                return Err(format!("legacy parent hash mismatch at {index}"));
            }
        }
        source.push(SourceBlock {
            candid,
            encoded,
            encoded_hash: decoded.encoded_hash,
            created_at_time_present: decoded.created_at_time_present,
        });
    }
    Ok((source, candid.archived_blocks.len()))
}

#[ic_cdk::update]
async fn configure(ledger: Principal) -> TextResult {
    let already_configured = STATE.with(|state| state.borrow().ledger.is_some());
    if already_configured {
        return TextResult::err("REJECT:already-configured".into());
    }
    let fee = match call_ledger::<(Nat,)>(ledger, "icrc1_fee", ()).await {
        Ok((value,)) => value,
        Err(error) => return TextResult::err(format!("REJECT:fee:{error}")),
    };
    let decimals = match call_ledger::<(u8,)>(ledger, "icrc1_decimals", ()).await {
        Ok((value,)) => value,
        Err(error) => return TextResult::err(format!("REJECT:decimals:{error}")),
    };
    if decimals != 8 {
        return TextResult::err(format!("REJECT:decimals:{decimals}"));
    }
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.ledger = Some(ledger);
        state.registrar = Some(ic_cdk::caller());
        state.fee = Some(fee.clone());
        state.decimals = Some(decimals);
        refresh_certification(&state);
    });
    TextResult::ok(format!("fee={fee};decimals={decimals}"))
}

#[ic_cdk::update]
fn register_account(account: Account) -> TextResult {
    text_result((|| {
        let id = account_id(&account)?;
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            match state.accounts.get(&id) {
                Some(existing) if existing == &account => Ok(hex::encode(id)),
                Some(_) => Err("account identifier collision with different preimage".into()),
                None => {
                    state.accounts.insert(id, account);
                    Ok(hex::encode(id))
                }
            }
        })
    })())
}

#[ic_cdk::update]
fn register_transaction_hint(hint: TransactionHint) -> TextResult {
    let caller = ic_cdk::caller();
    text_result(STATE.with(|state| {
        let mut state = state.borrow_mut();
        if state.registrar != Some(caller) {
            return Err("REJECT:not-registrar".into());
        }
        if let Some(existing) = state.hints.get(&hint.block_index) {
            if existing == &hint {
                return Ok(format!("sealed:{}", hint.block_index));
            }
            state.sealed_conflicts.insert(hint.block_index);
            return Err(format!(
                "REJECT:conflicting-sealed-hint:{}",
                hint.block_index
            ));
        }
        verify_hint(&state, &hint)?;
        state.hints.insert(hint.block_index, hint.clone());
        rebuild_translated(&mut state)?;
        Ok(format!("sealed:{}", hint.block_index))
    }))
}

#[ic_cdk::update]
async fn sync() -> SyncResult {
    let ledger = match STATE.with(|state| state.borrow().ledger) {
        Some(value) => value,
        None => return SyncResult::err("REJECT:unconfigured".into()),
    };
    let (source, archive_ranges) = match fetch_source(ledger).await {
        Ok(value) => value,
        Err(error) => return SyncResult::err(format!("REJECT:source:{error}")),
    };
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        if source.len() < state.source.len() {
            return SyncResult::err("REJECT:source-rollback".into());
        }
        for (index, previous) in state.source.iter().enumerate() {
            if previous.encoded != source[index].encoded {
                return SyncResult::err(format!("REJECT:source-rewrite:{index}"));
            }
        }
        let count = source.len();
        state.source = source;
        state.archive_ranges = archive_ranges;
        state.encoded_roundtrips = count;
        state.candid_semantic_matches = count;
        if let Err(error) = rebuild_translated(&mut state) {
            return SyncResult::err(format!("REJECT:translation:{error}"));
        }
        SyncResult::ok(SyncReport {
            source_blocks: Nat::from(state.source.len()),
            translated_blocks: Nat::from(state.translated.len()),
            archive_ranges: Nat::from(state.archive_ranges),
            encoded_roundtrips: Nat::from(state.encoded_roundtrips),
            candid_semantic_matches: Nat::from(state.candid_semantic_matches),
            source_tip_hash: state
                .source
                .last()
                .map(|block| ByteBuf::from(block.encoded_hash.to_vec())),
        })
    })
}

#[ic_cdk::query]
fn metadata() -> Metadata {
    STATE.with(|state| {
        let state = state.borrow();
        Metadata {
            configured: state.ledger.is_some(),
            ledger: state.ledger,
            fee: state.fee.clone(),
            decimals: state.decimals,
            source_blocks: Nat::from(state.source.len()),
            translated_blocks: Nat::from(state.translated.len()),
            registered_accounts: Nat::from(state.accounts.len()),
            registered_hints: Nat::from(state.hints.len()),
        }
    })
}

#[ic_cdk::query]
fn audit_binding() -> AuditBinding {
    STATE.with(|state| {
        let state = state.borrow();
        AuditBinding {
            adapter_tip_index: state
                .translated
                .len()
                .checked_sub(1)
                .map(Nat::from),
            adapter_tip_hash: state
                .translated
                .last()
                .map(|block| ByteBuf::from(hash_value(block).to_vec())),
            source_tip_hash: state
                .source
                .get(state.translated.len().saturating_sub(1))
                .filter(|_| !state.translated.is_empty())
                .map(|block| ByteBuf::from(block.encoded_hash.to_vec())),
            source_ledger: state.ledger,
        }
    })
}

fn nat_to_usize(value: &Nat) -> Option<usize> {
    value.0.to_u64_digits().first().copied().and_then(|value| {
        if value <= usize::MAX as u64 {
            Some(value as usize)
        } else {
            None
        }
    }).or_else(|| if value.0 == 0_u8.into() { Some(0) } else { None })
}

#[ic_cdk::query]
fn icrc3_get_blocks(ranges: Vec<GetBlocksArgs>) -> GetBlocksResult {
    STATE.with(|state| {
        let state = state.borrow();
        let mut blocks = Vec::new();
        for range in ranges {
            let Some(start) = nat_to_usize(&range.start) else {
                continue;
            };
            let Some(length) = nat_to_usize(&range.length) else {
                continue;
            };
            let end = state.translated.len().min(start.saturating_add(length));
            for index in start..end {
                blocks.push(BlockWithId {
                    id: Nat::from(index),
                    block: state.translated[index].clone(),
                });
            }
        }
        GetBlocksResult {
            // The source and adapter indices are intentionally identical. Missing/unhinted source
            // blocks are unavailable and therefore fail Gate-4's exact lookup closed.
            log_length: Nat::from(state.source.len()),
            blocks,
            archived_blocks: Vec::new(),
        }
    })
}

#[ic_cdk::query]
fn icrc3_get_tip_certificate() -> Option<DataCertificate> {
    let certificate = ic_cdk::api::data_certificate()?;
    STATE.with(|state| {
        let tree = certification_tree(&state.borrow())?;
        let hash_tree = serde_cbor::to_vec(&tree).ok()?;
        Some(DataCertificate {
            certificate: ByteBuf::from(certificate),
            hash_tree: ByteBuf::from(hash_tree),
        })
    })
}

#[ic_cdk::query]
fn icrc3_get_archives(_args: GetArchivesArgs) -> Vec<ArchiveInfo> {
    Vec::new()
}

#[ic_cdk::query]
fn icrc3_supported_block_types() -> Vec<BlockType> {
    ["1xfer", "2approve", "2xfer"]
        .into_iter()
        .map(|block_type| BlockType {
            block_type: block_type.into(),
            url: ICRC3_URL.into(),
        })
        .collect()
}

#[ic_cdk::post_upgrade]
fn post_upgrade() {
    STATE.with(|state| refresh_certification(&state.borrow()));
}

ic_cdk::export_candid!();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icrc3_hash_map_order_is_independent() {
        let left = Value::Map(vec![
            ("z".into(), Value::Nat(Nat::from(1_u8))),
            ("a".into(), Value::Text("x".into())),
        ]);
        let right = Value::Map(vec![
            ("a".into(), Value::Text("x".into())),
            ("z".into(), Value::Nat(Nat::from(1_u8))),
        ]);
        assert_eq!(hash_value(&left), hash_value(&right));
    }

    #[test]
    fn account_identifier_is_checksum_plus_sha224() {
        let account = Account {
            owner: Principal::anonymous(),
            subaccount: None,
        };
        let id = account_id(&account).unwrap();
        assert_eq!(crc32fast::hash(&id[4..]).to_be_bytes(), id[..4]);
    }
}
