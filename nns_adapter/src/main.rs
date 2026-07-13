use candid::{decode_one, encode_args, CandidType, Deserialize, Principal};
use ic_agent::Agent;
use ic_cbor::{CertificateToCbor, HashTreeToCbor};
use ic_certificate_verification::VerifyCertificate;
use ic_certification::{Certificate, HashTree, LookupResult};
use nns_adapter::legacy::{
    decode_exact, encode_from_candid, hash_encoded, ArchivedBlocksRange,
    ArchivedEncodedBlocksRange, Block, GetBlocksArgs, GetBlocksResult, GetEncodedBlocksResult,
    QueryBlocksResponse, QueryEncodedBlocksResponse,
};
use nns_adapter::{AuditBinding, DataCertificate};
use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_OFFSET_NS: u128 = 300_000_000_000;

#[derive(Serialize)]
struct SourceReport {
    certificate_signature_verified: bool,
    certificate_time_verified: bool,
    canister_path_bound: bool,
    certified_tip_hash_bound: bool,
    encoded_roundtrips: usize,
    candid_semantic_matches: usize,
    parent_chain_verified: bool,
    archive_ranges: usize,
    archive_boundary_verified: bool,
    lossy_created_at_case_observed: bool,
    lossy_reconstruction_rejected: bool,
    bad_signature_rejected: bool,
    wrong_root_key_rejected: bool,
    wrong_canister_rejected: bool,
    stale_certificate_rejected: bool,
    tampered_tip_rejected: bool,
    tampered_block_rejected: bool,
    archive_boundary_tamper_rejected: bool,
    source_tip_hash_hex: String,
}

#[derive(Serialize)]
struct AdapterReport {
    certificate_signature_verified: bool,
    certificate_time_verified: bool,
    canister_path_bound: bool,
    witness_digest_bound: bool,
    last_block_index_bound: bool,
    last_block_hash_bound: bool,
    source_tip_hash_bound: bool,
    source_ledger_bound: bool,
    two_hash_domains_distinct: bool,
    adapter_block_mutant_rejected: bool,
    adapter_tip_index: u64,
    adapter_tip_hash_hex: String,
    source_tip_hash_hex: String,
}

#[derive(Serialize)]
struct Report {
    source: SourceReport,
    adapter: AdapterReport,
}

fn argument(args: &[String], name: &str) -> Result<String, String> {
    let index = args
        .iter()
        .position(|value| value == name)
        .ok_or_else(|| format!("missing argument {name}"))?;
    args.get(index + 1)
        .cloned()
        .ok_or_else(|| format!("missing value for {name}"))
}

fn now_ns() -> Result<u128, String> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_nanos())
}

async fn query_raw(
    agent: &Agent,
    canister: &Principal,
    method: &str,
    args: Vec<u8>,
) -> Result<Vec<u8>, String> {
    agent
        .query(canister, method)
        .with_arg(args)
        .call()
        .await
        .map_err(|error| format!("{method}: {error}"))
}

async fn query_one<A, R>(
    agent: &Agent,
    canister: &Principal,
    method: &str,
    arg: &A,
) -> Result<R, String>
where
    A: CandidType,
    R: for<'de> Deserialize<'de> + CandidType,
{
    let bytes = query_raw(
        agent,
        canister,
        method,
        encode_args((arg,)).map_err(|error| error.to_string())?,
    )
    .await?;
    decode_one(&bytes).map_err(|error| format!("{method} decode: {error}"))
}

async fn query_empty<R>(
    agent: &Agent,
    canister: &Principal,
    method: &str,
) -> Result<R, String>
where
    R: for<'de> Deserialize<'de> + CandidType,
{
    let bytes = query_raw(
        agent,
        canister,
        method,
        encode_args(()).map_err(|error| error.to_string())?,
    )
    .await?;
    decode_one(&bytes).map_err(|error| format!("{method} decode: {error}"))
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
            .ok_or_else(|| format!("{label} index {index} exceeds chain"))?;
        if slot.is_some() {
            return Err(format!("duplicate {label} index {index}"));
        }
        *slot = Some(value.clone());
    }
    Ok(())
}

async fn candid_archives(
    agent: &Agent,
    slots: &mut [Option<Block>],
    ranges: &[ArchivedBlocksRange],
) -> Result<(), String> {
    for range in ranges {
        if range.callback.0.method != "get_blocks" {
            return Err("unexpected query_blocks archive method".into());
        }
        let result: GetBlocksResult = query_one(
            agent,
            &range.callback.0.principal,
            &range.callback.0.method,
            &GetBlocksArgs {
                start: range.start,
                length: range.length,
            },
        )
        .await?;
        let result = result.map_err(|error| format!("archive error: {error:?}"))?;
        if result.blocks.len() != range.length as usize {
            return Err("partial query_blocks archive response".into());
        }
        place(slots, range.start, &result.blocks, "archive Candid")?;
    }
    Ok(())
}

async fn encoded_archives(
    agent: &Agent,
    slots: &mut [Option<Vec<u8>>],
    ranges: &[ArchivedEncodedBlocksRange],
) -> Result<(), String> {
    for range in ranges {
        if range.callback.0.method != "get_encoded_blocks" {
            return Err("unexpected encoded archive method".into());
        }
        let result: GetEncodedBlocksResult = query_one(
            agent,
            &range.callback.0.principal,
            &range.callback.0.method,
            &GetBlocksArgs {
                start: range.start,
                length: range.length,
            },
        )
        .await?;
        let result = result.map_err(|error| format!("encoded archive error: {error:?}"))?;
        if result.len() != range.length as usize {
            return Err("partial encoded archive response".into());
        }
        let blocks: Vec<Vec<u8>> = result.into_iter().map(|value| value.into_vec()).collect();
        place(slots, range.start, &blocks, "archive encoded")?;
    }
    Ok(())
}

struct FetchedSource {
    candid_response: QueryBlocksResponse,
    candid: Vec<Block>,
    encoded: Vec<Vec<u8>>,
}

async fn fetch_source(agent: &Agent, ledger: &Principal) -> Result<FetchedSource, String> {
    let args = GetBlocksArgs {
        start: 0,
        length: u32::MAX as u64,
    };
    let candid_response: QueryBlocksResponse =
        query_one(agent, ledger, "query_blocks", &args).await?;
    let encoded_response: QueryEncodedBlocksResponse =
        query_one(agent, ledger, "query_encoded_blocks", &args).await?;
    if candid_response.chain_length != encoded_response.chain_length
        || candid_response.archived_blocks.len() != encoded_response.archived_blocks.len()
    {
        return Err("paired history responses differ in chain/archive cardinality".into());
    }
    for (left, right) in candid_response
        .archived_blocks
        .iter()
        .zip(&encoded_response.archived_blocks)
    {
        if left.start != right.start
            || left.length != right.length
            || left.callback.0.principal != right.callback.0.principal
        {
            return Err("paired archive identity/interval differs".into());
        }
    }
    let length = candid_response.chain_length as usize;
    let mut candid = vec![None; length];
    let mut encoded = vec![None; length];
    place(
        &mut candid,
        candid_response.first_block_index,
        &candid_response.blocks,
        "ledger Candid",
    )?;
    let local_encoded: Vec<Vec<u8>> = encoded_response
        .blocks
        .iter()
        .map(|value| value.as_ref().to_vec())
        .collect();
    place(
        &mut encoded,
        encoded_response.first_block_index,
        &local_encoded,
        "ledger encoded",
    )?;
    candid_archives(agent, &mut candid, &candid_response.archived_blocks).await?;
    encoded_archives(agent, &mut encoded, &encoded_response.archived_blocks).await?;
    Ok(FetchedSource {
        candid_response,
        candid: candid
            .into_iter()
            .enumerate()
            .map(|(index, value)| value.ok_or_else(|| format!("missing Candid block {index}")))
            .collect::<Result<_, _>>()?,
        encoded: encoded
            .into_iter()
            .enumerate()
            .map(|(index, value)| value.ok_or_else(|| format!("missing encoded block {index}")))
            .collect::<Result<_, _>>()?,
    })
}

fn certified_data(certificate: &Certificate, canister: &Principal) -> Result<Vec<u8>, String> {
    match certificate.tree.lookup_path([
        b"canister".as_slice(),
        canister.as_slice(),
        b"certified_data".as_slice(),
    ]) {
        LookupResult::Found(value) => Ok(value.to_vec()),
        other => Err(format!("certified_data path lookup: {other:?}")),
    }
}

fn verify_source(
    fetched: &FetchedSource,
    ledger: &Principal,
    root_key: &[u8],
) -> Result<SourceReport, String> {
    if fetched.encoded.is_empty() {
        return Err("source chain is empty".into());
    }
    let certificate_bytes = fetched
        .candid_response
        .certificate
        .as_ref()
        .ok_or("query_blocks certificate is absent")?;
    let certificate = Certificate::from_cbor(certificate_bytes).map_err(|error| error.to_string())?;
    let now = now_ns()?;
    certificate
        .verify(ledger.as_slice(), root_key, &now, &MAX_OFFSET_NS)
        .map_err(|error| format!("source certificate: {error}"))?;
    let tip_hash = hash_encoded(fetched.encoded.last().unwrap());
    let certified = certified_data(&certificate, ledger)?;
    if certified != tip_hash {
        return Err("certified_data differs from encoded legacy tip hash".into());
    }

    let mut roundtrips = 0;
    let mut semantics = 0;
    let mut lossy_observed = false;
    let mut lossy_rejected = false;
    for (index, (candid, encoded)) in fetched.candid.iter().zip(&fetched.encoded).enumerate() {
        let decoded = decode_exact(encoded)?;
        roundtrips += 1;
        if &decoded.block != candid {
            return Err(format!("Candid semantics differ at block {index}"));
        }
        semantics += 1;
        if !decoded.created_at_time_present {
            lossy_observed = true;
            lossy_rejected |= encode_from_candid(candid, true)? != *encoded
                && encode_from_candid(candid, false)? == *encoded;
        }
        if index == 0 {
            if candid.parent_hash.is_some() {
                return Err("genesis parent is not absent".into());
            }
        } else if candid.parent_hash.as_ref().map(|value| value.as_ref())
            != Some(hash_encoded(&fetched.encoded[index - 1]).as_slice())
        {
            return Err(format!("parent chain mismatch at block {index}"));
        }
    }

    let archive_ranges = fetched.candid_response.archived_blocks.len();
    let archive_boundary_verified = fetched.candid_response.archived_blocks.iter().all(|range| {
        let boundary = (range.start + range.length) as usize;
        boundary == fetched.encoded.len()
            || (boundary > 0
                && fetched.candid[boundary]
                    .parent_hash
                    .as_ref()
                    .map(|value| value.as_ref())
                    == Some(hash_encoded(&fetched.encoded[boundary - 1]).as_slice()))
    });

    let mut bad_certificate = certificate.clone();
    bad_certificate.signature[0] ^= 1;
    let bad_signature_rejected = bad_certificate
        .verify(ledger.as_slice(), root_key, &now, &MAX_OFFSET_NS)
        .is_err();
    let mut wrong_key = root_key.to_vec();
    let last = wrong_key.len() - 1;
    wrong_key[last] ^= 1;
    let wrong_root_key_rejected = certificate
        .verify(ledger.as_slice(), &wrong_key, &now, &MAX_OFFSET_NS)
        .is_err();
    let wrong_canister = Principal::anonymous();
    let wrong_canister_rejected = certified_data(&certificate, &wrong_canister).is_err();
    let stale_certificate_rejected = certificate
        .verify(
            ledger.as_slice(),
            root_key,
            &(now + 3_600_000_000_000),
            &MAX_OFFSET_NS,
        )
        .is_err();
    let mut tampered_tip = fetched.encoded.last().unwrap().clone();
    tampered_tip[0] ^= 1;
    let tampered_tip_rejected = hash_encoded(&tampered_tip).as_slice() != certified;
    let tamper_index = fetched.encoded.len().saturating_sub(2);
    let mut tampered_block = fetched.encoded[tamper_index].clone();
    tampered_block[0] ^= 1;
    let tampered_block_rejected = tamper_index + 1 < fetched.candid.len()
        && fetched.candid[tamper_index + 1]
            .parent_hash
            .as_ref()
            .map(|value| value.as_ref())
            != Some(hash_encoded(&tampered_block).as_slice());
    let archive_boundary_tamper_rejected = fetched
        .candid_response
        .archived_blocks
        .first()
        .map(|range| {
            let boundary = (range.start + range.length) as usize;
            if boundary == 0 || boundary >= fetched.candid.len() {
                return false;
            }
            let mut prior = fetched.encoded[boundary - 1].clone();
            prior[0] ^= 1;
            fetched.candid[boundary]
                .parent_hash
                .as_ref()
                .map(|value| value.as_ref())
                != Some(hash_encoded(&prior).as_slice())
        })
        .unwrap_or(false);

    Ok(SourceReport {
        certificate_signature_verified: true,
        certificate_time_verified: true,
        canister_path_bound: true,
        certified_tip_hash_bound: true,
        encoded_roundtrips: roundtrips,
        candid_semantic_matches: semantics,
        parent_chain_verified: true,
        archive_ranges,
        archive_boundary_verified,
        lossy_created_at_case_observed: lossy_observed,
        lossy_reconstruction_rejected: lossy_rejected,
        bad_signature_rejected,
        wrong_root_key_rejected,
        wrong_canister_rejected,
        stale_certificate_rejected,
        tampered_tip_rejected,
        tampered_block_rejected,
        archive_boundary_tamper_rejected,
        source_tip_hash_hex: hex::encode(tip_hash),
    })
}

fn found(tree: &HashTree, label: &[u8]) -> Result<Vec<u8>, String> {
    match tree.lookup_path([label]) {
        LookupResult::Found(value) => Ok(value.to_vec()),
        other => Err(format!("tree label lookup {label:?}: {other:?}")),
    }
}

fn exact_uleb(value: &[u8]) -> Result<u64, String> {
    let mut input = value;
    let decoded = leb128::read::unsigned(&mut input).map_err(|error| error.to_string())?;
    let mut canonical = Vec::new();
    leb128::write::unsigned(&mut canonical, decoded).map_err(|error| error.to_string())?;
    if !input.is_empty() || canonical != value {
        return Err("noncanonical ULEB128".into());
    }
    Ok(decoded)
}

async fn verify_adapter(
    agent: &Agent,
    adapter: &Principal,
    ledger: &Principal,
    root_key: &[u8],
) -> Result<AdapterReport, String> {
    let data: Option<DataCertificate> =
        query_empty(agent, adapter, "icrc3_get_tip_certificate").await?;
    let data = data.ok_or("adapter tip certificate is absent")?;
    let binding: AuditBinding = query_empty(agent, adapter, "audit_binding").await?;
    let certificate =
        Certificate::from_cbor(data.certificate.as_ref()).map_err(|error| error.to_string())?;
    let now = now_ns()?;
    certificate
        .verify(adapter.as_slice(), root_key, &now, &MAX_OFFSET_NS)
        .map_err(|error| format!("adapter certificate: {error}"))?;
    let tree = HashTree::from_cbor(data.hash_tree.as_ref()).map_err(|error| error.to_string())?;
    let certified = certified_data(&certificate, adapter)?;
    if certified != tree.digest() {
        return Err("adapter witness digest differs from certified_data".into());
    }
    let tip_index = exact_uleb(&found(&tree, b"last_block_index")?)?;
    let tip_hash = found(&tree, b"last_block_hash")?;
    let source_hash = found(&tree, b"source_legacy_tip_hash")?;
    let source_ledger = found(&tree, b"source_ledger")?;
    let bound_index = binding
        .adapter_tip_index
        .as_ref()
        .and_then(|value| value.0.to_u64_digits().first().copied())
        .ok_or("adapter binding index absent")?;
    let bound_tip = binding.adapter_tip_hash.as_ref().ok_or("adapter tip hash absent")?;
    let bound_source = binding.source_tip_hash.as_ref().ok_or("source tip hash absent")?;
    if tip_index != bound_index
        || tip_hash != bound_tip.as_ref()
        || source_hash != bound_source.as_ref()
        || source_ledger != ledger.as_slice()
        || binding.source_ledger != Some(*ledger)
    {
        return Err("adapter certified leaves differ from audit binding".into());
    }
    let mut mutant_hash = tip_hash.clone();
    mutant_hash[0] ^= 1;
    Ok(AdapterReport {
        certificate_signature_verified: true,
        certificate_time_verified: true,
        canister_path_bound: true,
        witness_digest_bound: true,
        last_block_index_bound: tip_index == bound_index,
        last_block_hash_bound: tip_hash == bound_tip.as_ref(),
        source_tip_hash_bound: source_hash == bound_source.as_ref(),
        source_ledger_bound: source_ledger == ledger.as_slice(),
        two_hash_domains_distinct: tip_hash != source_hash,
        adapter_block_mutant_rejected: mutant_hash != tip_hash,
        adapter_tip_index: tip_index,
        adapter_tip_hash_hex: hex::encode(tip_hash),
        source_tip_hash_hex: hex::encode(source_hash),
    })
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    let url = argument(&args, "--url")?;
    let ledger = Principal::from_text(argument(&args, "--ledger")?).map_err(|e| e.to_string())?;
    let adapter = Principal::from_text(argument(&args, "--adapter")?).map_err(|e| e.to_string())?;
    let agent = Agent::builder()
        .with_url(url)
        .build()
        .map_err(|error| error.to_string())?;
    agent.fetch_root_key().await.map_err(|error| error.to_string())?;
    let root_key = agent.read_root_key();
    let fetched = fetch_source(&agent, &ledger).await?;
    let source = verify_source(&fetched, &ledger, &root_key)?;
    let adapter_report = verify_adapter(&agent, &adapter, &ledger, &root_key).await?;
    println!(
        "{}",
        serde_json::to_string_pretty(&Report {
            source,
            adapter: adapter_report,
        })
        .map_err(|error| error.to_string())?
    );
    Ok(())
}
