use candid::{CandidType, Decode, Deserialize, Principal};
use ic_agent::Agent;
use ic_cbor::{CertificateToCbor, HashTreeToCbor};
use ic_certificate_verification::VerifyCertificate;
use ic_certification::{fork, labeled, leaf, Certificate, HashTree, LookupResult};
use serde::{Deserialize as SerdeDeserialize, Serialize};
use std::io::{self, Read};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_CERTIFICATE_OFFSET_NS: u128 = 300_000_000_000;

#[derive(CandidType, Deserialize)]
struct DataCertificate {
    certificate: Vec<u8>,
    hash_tree: Vec<u8>,
}

#[derive(Clone)]
struct ExpectedTuple {
    tip_index: u64,
    tip_hash: Vec<u8>,
    note_count: u64,
    note_root: Vec<u8>,
    encoding_version: u64,
    archive_manifest: Vec<u8>,
    /// digest of the background audit verdict leaf (ICRC-3 map hash of {state:"pass"}
    /// on a healthy ledger); callers assert audit PASS before fetching
    audit_digest: Vec<u8>,
    /// optional PIR-v2 record-stream boundary leaf (digest(32) ‖ covered 8B BE) — present
    /// only on deployments with the pir2 layer enabled AND a DPAGE boundary reached; the
    /// canonical tree without it is byte-identical to the pre-pir2 one
    pir2_boundary: Option<Vec<u8>>,
    minimum_tip: u64,
}

#[derive(Debug, Serialize, SerdeDeserialize)]
struct Envelope {
    certificate_hex: String,
    hash_tree_hex: String,
}

#[derive(Debug, Serialize)]
struct Report {
    valid: bool,
    certificate_signature_verified: bool,
    certificate_time_verified: bool,
    canister_path_bound: bool,
    witness_digest_bound: bool,
    tuple_leaves_verified: bool,
    monotonic_tip_verified: bool,
    certificate_signature_mutant_rejected: bool,
    wrong_root_key_rejected: bool,
    note_root_witness_mutant_rejected: bool,
    ascii_tip_index_mutant_rejected: bool,
    certified_data_hex: String,
    tree_digest_hex: String,
    tip_index: u64,
    tip_hash_hex: String,
    note_count: u64,
    note_root_hex: String,
    encoding_version: u64,
    archive_manifest_hex: String,
    envelope: Envelope,
}

fn argument(args: &[String], name: &str) -> Result<String, String> {
    let position = args
        .iter()
        .position(|value| value == name)
        .ok_or_else(|| format!("missing argument {name}"))?;
    args.get(position + 1)
        .cloned()
        .ok_or_else(|| format!("missing value for {name}"))
}

fn expected(args: &[String]) -> Result<ExpectedTuple, String> {
    Ok(ExpectedTuple {
        tip_index: argument(args, "--tip-index")?.parse().map_err(|e| format!("tip index: {e}"))?,
        tip_hash: hex::decode(argument(args, "--tip-hash")?).map_err(|e| e.to_string())?,
        note_count: argument(args, "--note-count")?.parse().map_err(|e| format!("note count: {e}"))?,
        note_root: hex::decode(argument(args, "--note-root")?).map_err(|e| e.to_string())?,
        encoding_version: argument(args, "--encoding-version")?
            .parse()
            .map_err(|e| format!("encoding version: {e}"))?,
        archive_manifest: hex::decode(argument(args, "--archive-manifest")?)
            .map_err(|e| e.to_string())?,
        audit_digest: hex::decode(argument(args, "--audit-digest")?).map_err(|e| e.to_string())?,
        pir2_boundary: match args.iter().position(|value| value == "--pir2-boundary") {
            Some(position) => Some(
                hex::decode(args.get(position + 1).ok_or("missing value for --pir2-boundary")?)
                    .map_err(|e| e.to_string())?,
            ),
            None => None,
        },
        minimum_tip: argument(args, "--minimum-tip")?
            .parse()
            .map_err(|e| format!("minimum tip: {e}"))?,
    })
}

fn leb128(value: u64) -> Vec<u8> {
    let mut output = Vec::new();
    leb128::write::unsigned(&mut output, value).expect("Vec write cannot fail");
    output
}

fn canonical_tree(tuple: &ExpectedTuple, tip_index_leaf: Vec<u8>, note_root: Vec<u8>) -> HashTree {
    fork(
        labeled(
            "tip",
            fork(
                labeled("last_block_hash", leaf(tuple.tip_hash.clone())),
                labeled("last_block_index", leaf(tip_index_leaf)),
            ),
        ),
        labeled(
            "zk",
            fork(
                labeled("archive_manifest", leaf(tuple.archive_manifest.clone())),
                fork(
                    labeled("audit", leaf(tuple.audit_digest.clone())),
                    fork(
                        labeled("encoding_version", leaf(leb128(tuple.encoding_version))),
                        fork(
                            labeled("note_count", leaf(leb128(tuple.note_count))),
                            match &tuple.pir2_boundary {
                                Some(boundary) => fork(
                                    labeled("note_root", leaf(note_root)),
                                    labeled("pir2_boundary", leaf(boundary.clone())),
                                ),
                                None => labeled("note_root", leaf(note_root)),
                            },
                        ),
                    ),
                ),
            ),
        ),
    )
}

fn found(tree: &HashTree, path: &[&[u8]]) -> Result<Vec<u8>, String> {
    match tree.lookup_path(path.iter().copied()) {
        LookupResult::Found(value) => Ok(value.to_vec()),
        other => Err(format!("path {:?} was not found: {other:?}", path)),
    }
}

fn exact_uleb(value: &[u8], expected: u64, field: &str) -> Result<(), String> {
    let mut input = value;
    let decoded = leb128::read::unsigned(&mut input).map_err(|e| format!("{field}: {e}"))?;
    if decoded != expected || !input.is_empty() || value != leb128(expected) {
        return Err(format!("{field}: non-canonical or wrong unsigned LEB128"));
    }
    Ok(())
}

fn current_time_ns() -> Result<u128, String> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_nanos())
}

struct Verified {
    certificate: Certificate,
    tree: HashTree,
    certified_data: Vec<u8>,
}

fn verify_bundle(
    certificate_bytes: &[u8],
    tree_bytes: &[u8],
    canister: &Principal,
    root_key: &[u8],
    tuple: &ExpectedTuple,
) -> Result<Verified, String> {
    let certificate = Certificate::from_cbor(certificate_bytes).map_err(|e| e.to_string())?;
    certificate
        .verify(
            canister.as_slice(),
            root_key,
            &current_time_ns()?,
            &MAX_CERTIFICATE_OFFSET_NS,
        )
        .map_err(|e| format!("certificate verification: {e}"))?;

    let tree = HashTree::from_cbor(tree_bytes).map_err(|e| e.to_string())?;
    let certified_data = match certificate.tree.lookup_path([
        "canister".as_bytes(),
        canister.as_slice(),
        "certified_data".as_bytes(),
    ]) {
        LookupResult::Found(value) => value.to_vec(),
        other => return Err(format!("certified_data path lookup failed: {other:?}")),
    };
    if tree.digest().as_slice() != certified_data {
        return Err("witness digest is not the certified_data value".into());
    }

    let tip_hash = found(&tree, &[b"tip", b"last_block_hash"])?;
    let tip_index = found(&tree, &[b"tip", b"last_block_index"])?;
    let archive_manifest = found(&tree, &[b"zk", b"archive_manifest"])?;
    let audit_digest = found(&tree, &[b"zk", b"audit"])?;
    let encoding_version = found(&tree, &[b"zk", b"encoding_version"])?;
    let note_count = found(&tree, &[b"zk", b"note_count"])?;
    let note_root = found(&tree, &[b"zk", b"note_root"])?;

    exact_uleb(&tip_index, tuple.tip_index, "last_block_index")?;
    exact_uleb(&encoding_version, tuple.encoding_version, "encoding_version")?;
    exact_uleb(&note_count, tuple.note_count, "note_count")?;
    if tip_hash != tuple.tip_hash
        || archive_manifest != tuple.archive_manifest
        || audit_digest != tuple.audit_digest
        || note_root != tuple.note_root
    {
        return Err("tuple leaf differs from independent expected value".into());
    }
    if tuple.tip_index < tuple.minimum_tip {
        return Err(format!(
            "rollback: certified tip {} is below trusted minimum {}",
            tuple.tip_index, tuple.minimum_tip
        ));
    }

    let canonical = canonical_tree(tuple, leb128(tuple.tip_index), tuple.note_root.clone());
    if canonical.digest() != tree.digest() {
        return Err("witness is not the canonical tuple tree".into());
    }

    Ok(Verified {
        certificate,
        tree,
        certified_data,
    })
}

async fn fetch_bundle(agent: &Agent, canister: &Principal) -> Result<DataCertificate, String> {
    let response = agent
        .query(canister, "icrc3_get_tip_certificate")
        .with_arg(candid::encode_args(()).map_err(|e| e.to_string())?)
        .call()
        .await
        .map_err(|e| e.to_string())?;
    let value = Decode!(&response, Option<DataCertificate>).map_err(|e| e.to_string())?;
    value.ok_or_else(|| "tip certificate unexpectedly absent".into())
}

fn negative_controls(
    verified: &Verified,
    canister: &Principal,
    root_key: &[u8],
    tuple: &ExpectedTuple,
) -> Result<(bool, bool, bool, bool), String> {
    let now = current_time_ns()?;
    let mut bad_certificate = verified.certificate.clone();
    if bad_certificate.signature.is_empty() {
        return Err("certificate signature is empty".into());
    }
    bad_certificate.signature[0] ^= 1;
    let signature_rejected = bad_certificate
        .verify(canister.as_slice(), root_key, &now, &MAX_CERTIFICATE_OFFSET_NS)
        .is_err();

    let mut wrong_key = root_key.to_vec();
    let last = wrong_key.len().checked_sub(1).ok_or("root key is empty")?;
    wrong_key[last] ^= 1;
    let wrong_key_rejected = verified
        .certificate
        .verify(canister.as_slice(), &wrong_key, &now, &MAX_CERTIFICATE_OFFSET_NS)
        .is_err();

    let mut changed_note_root = tuple.note_root.clone();
    changed_note_root[0] ^= 1;
    let witness_rejected = canonical_tree(tuple, leb128(tuple.tip_index), changed_note_root).digest()
        .as_slice()
        != verified.certified_data;
    let ascii_index_rejected = canonical_tree(
        tuple,
        tuple.tip_index.to_string().into_bytes(),
        tuple.note_root.clone(),
    )
    .digest()
    .as_slice()
        != verified.certified_data;

    Ok((
        signature_rejected,
        wrong_key_rejected,
        witness_rejected,
        ascii_index_rejected,
    ))
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("fetch");
    let url = argument(&args, "--url")?;
    let canister = Principal::from_text(argument(&args, "--canister")?).map_err(|e| e.to_string())?;
    let tuple = expected(&args)?;

    let agent = Agent::builder()
        .with_url(url)
        .build()
        .map_err(|e| e.to_string())?;
    agent.fetch_root_key().await.map_err(|e| e.to_string())?;
    let root_key = agent.read_root_key();

    let bundle = if mode == "verify-envelope" {
        let mut input = String::new();
        io::stdin()
            .read_to_string(&mut input)
            .map_err(|e| e.to_string())?;
        let envelope: Envelope = serde_json::from_str(&input).map_err(|e| e.to_string())?;
        DataCertificate {
            certificate: hex::decode(envelope.certificate_hex).map_err(|e| e.to_string())?,
            hash_tree: hex::decode(envelope.hash_tree_hex).map_err(|e| e.to_string())?,
        }
    } else if mode == "fetch" {
        fetch_bundle(&agent, &canister).await?
    } else {
        return Err(format!("unknown mode {mode}"));
    };

    let verified = verify_bundle(
        &bundle.certificate,
        &bundle.hash_tree,
        &canister,
        &root_key,
        &tuple,
    )?;
    let (signature_mutant, wrong_key, witness_mutant, ascii_mutant) =
        negative_controls(&verified, &canister, &root_key, &tuple)?;
    if !(signature_mutant && wrong_key && witness_mutant && ascii_mutant) {
        return Err("one or more certificate negative controls unexpectedly accepted".into());
    }

    let report = Report {
        valid: true,
        certificate_signature_verified: true,
        certificate_time_verified: true,
        canister_path_bound: true,
        witness_digest_bound: true,
        tuple_leaves_verified: true,
        monotonic_tip_verified: true,
        certificate_signature_mutant_rejected: signature_mutant,
        wrong_root_key_rejected: wrong_key,
        note_root_witness_mutant_rejected: witness_mutant,
        ascii_tip_index_mutant_rejected: ascii_mutant,
        certified_data_hex: hex::encode(&verified.certified_data),
        tree_digest_hex: hex::encode(verified.tree.digest()),
        tip_index: tuple.tip_index,
        tip_hash_hex: hex::encode(&tuple.tip_hash),
        note_count: tuple.note_count,
        note_root_hex: hex::encode(&tuple.note_root),
        encoding_version: tuple.encoding_version,
        archive_manifest_hex: hex::encode(&tuple.archive_manifest),
        envelope: Envelope {
            certificate_hex: hex::encode(bundle.certificate),
            hash_tree_hex: hex::encode(bundle.hash_tree),
        },
    };
    println!("{}", serde_json::to_string(&report).map_err(|e| e.to_string())?);
    Ok(())
}
