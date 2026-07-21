//! B6: verify the ledger's `icrc3_get_tip_certificate` against the PocketIC root key, with the
//! same canonical-tuple-tree binding the repository's `cert_oracle/` enforces, plus negative
//! controls proving the checks have teeth (a mutated signature byte, a wrong root key, and a
//! mutated note_root witness must all be rejected).

use candid::Principal;
use ic_cbor::{CertificateToCbor, HashTreeToCbor};
use ic_certificate_verification::VerifyCertificate;
use ic_certification::{fork, labeled, leaf, Certificate, HashTree, LookupResult};

const MAX_CERTIFICATE_OFFSET_NS: u128 = 300_000_000_000;

pub struct ExpectedTuple {
    pub tip_index: u64,
    pub tip_hash: [u8; 32],
    pub note_count: u64,
    pub note_root: [u8; 32],
    pub encoding_version: u64,
    pub archive_manifest: Vec<u8>,
    /// digest of the background audit verdict — the runner asserts audit PASS before
    /// fetching the certificate, then expects the ICRC-3 map hash of {state: "pass"}
    pub audit_digest: Vec<u8>,
}

fn leb128(value: u64) -> Vec<u8> {
    let mut output = Vec::new();
    leb128::write::unsigned(&mut output, value).expect("Vec write cannot fail");
    output
}

fn canonical_tree(t: &ExpectedTuple, tip_index_leaf: Vec<u8>, note_root: Vec<u8>) -> HashTree {
    fork(
        labeled(
            "tip",
            fork(
                labeled("last_block_hash", leaf(t.tip_hash.to_vec())),
                labeled("last_block_index", leaf(tip_index_leaf)),
            ),
        ),
        labeled(
            "zk",
            fork(
                labeled("archive_manifest", leaf(t.archive_manifest.clone())),
                fork(
                    labeled("audit", leaf(t.audit_digest.clone())),
                    fork(
                        labeled("encoding_version", leaf(leb128(t.encoding_version))),
                        fork(
                            labeled("note_count", leaf(leb128(t.note_count))),
                            labeled("note_root", leaf(note_root)),
                        ),
                    ),
                ),
            ),
        ),
    )
}

pub struct CertReport {
    pub valid: bool,
    pub signature_mutant_rejected: bool,
    pub wrong_root_key_rejected: bool,
    pub note_root_witness_mutant_rejected: bool,
}

/// Verify certificate + witness against the expected tuple. `now_ns` should be the PocketIC
/// instance time (block timestamps and certificate time share that clock).
pub fn verify_tip_certificate(
    certificate_bytes: &[u8],
    tree_bytes: &[u8],
    canister: &Principal,
    root_key: &[u8],
    tuple: &ExpectedTuple,
    now_ns: u128,
) -> Result<CertReport, String> {
    let certificate = Certificate::from_cbor(certificate_bytes).map_err(|e| e.to_string())?;
    certificate
        .verify(canister.as_slice(), root_key, &now_ns, &MAX_CERTIFICATE_OFFSET_NS)
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

    // The witness must be EXACTLY the canonical tuple tree for the independently expected values.
    let canonical = canonical_tree(tuple, leb128(tuple.tip_index), tuple.note_root.to_vec());
    if canonical.digest() != tree.digest() {
        return Err("witness is not the canonical tuple tree for the expected values".into());
    }

    // Negative controls (proof 2: the checker has teeth).
    let mut bad_certificate = Certificate::from_cbor(certificate_bytes).map_err(|e| e.to_string())?;
    if bad_certificate.signature.is_empty() {
        return Err("certificate signature is empty".into());
    }
    bad_certificate.signature[0] ^= 1;
    let signature_mutant_rejected = bad_certificate
        .verify(canister.as_slice(), root_key, &now_ns, &MAX_CERTIFICATE_OFFSET_NS)
        .is_err();

    let mut wrong_key = root_key.to_vec();
    let last = wrong_key.len() - 1;
    wrong_key[last] ^= 1;
    let wrong_root_key_rejected = certificate
        .verify(canister.as_slice(), &wrong_key, &now_ns, &MAX_CERTIFICATE_OFFSET_NS)
        .is_err();

    let mut changed_root = tuple.note_root.to_vec();
    changed_root[0] ^= 1;
    let note_root_witness_mutant_rejected =
        canonical_tree(tuple, leb128(tuple.tip_index), changed_root).digest().as_slice()
            != certified_data.as_slice();

    Ok(CertReport {
        valid: true,
        signature_mutant_rejected,
        wrong_root_key_rejected,
        note_root_witness_mutant_rejected,
    })
}
