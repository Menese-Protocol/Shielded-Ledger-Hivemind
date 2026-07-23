//! Independent detect-chain reference (AC-2): recomputes the certified detection-stream
//! anchor — per-entry hash chain, DPAGE boundaries, promote-lone-node Merkle root, and the
//! certified `detect_stream` leaf — from the WIRE bytes the ledger serves
//! (`detection_stream` pages), with no shared code with `src/DetectChain.mo` or the JS
//! client. The detect battery and the `SOAK_DETECT_CHAIN` runner leg byte-compare this
//! against `detect_stream_anchor` and the certified tuple leaf.

use sha2::{Digest, Sha256};

pub const DPAGE: usize = 4096;
pub const ENTRY_LEN: usize = 48;

fn sha(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

pub fn leaf_hash(v: &[u8; 32]) -> [u8; 32] {
    sha(&[&[0x00], v])
}

pub fn node_hash(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    sha(&[&[0x01], a, b])
}

/// RFC-6962-style root with the lone node PROMOTED unchanged (the reference is the full
/// level-by-level recompute — deliberately NOT the frontier form under test).
pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut level: Vec<[u8; 32]> = leaves.iter().map(leaf_hash).collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            next.push(if pair.len() == 2 { node_hash(&pair[0], &pair[1]) } else { pair[0] });
        }
        level = next;
    }
    level[0]
}

pub fn detect_leaf(root: &[u8; 32], c_tip: &[u8; 32], note_count: u64) -> [u8; 32] {
    sha(&[root, c_tip, &note_count.to_le_bytes()])
}

/// Streaming recompute over served `detection_stream` bytes (48-byte entries).
pub struct Stream {
    pub chain: [u8; 32],
    pub boundaries: Vec<[u8; 32]>,
    pub count: u64,
}

impl Stream {
    pub fn new() -> Self {
        Stream { chain: [0u8; 32], boundaries: Vec::new(), count: 0 }
    }

    /// Fold one wire entry (position BE8 ‖ ciphertext[0..40)); asserts the served
    /// position matches the expected stream position (wire-integrity check).
    pub fn fold_entry(&mut self, entry: &[u8]) {
        assert_eq!(entry.len(), ENTRY_LEN, "detect entry must be 48 bytes");
        let mut pos_bytes = [0u8; 8];
        pos_bytes.copy_from_slice(&entry[..8]);
        assert_eq!(u64::from_be_bytes(pos_bytes), self.count, "served position != stream position");
        self.chain = sha(&[&self.chain, entry]);
        self.count += 1;
        if self.count as usize % DPAGE == 0 {
            self.boundaries.push(self.chain);
        }
    }

    /// Fold a whole served page (concatenated 48-byte entries).
    pub fn fold_page(&mut self, page: &[u8]) {
        assert_eq!(page.len() % ENTRY_LEN, 0, "detection_stream page not entry-aligned");
        for entry in page.chunks(ENTRY_LEN) {
            self.fold_entry(entry);
        }
    }

    pub fn root(&self) -> [u8; 32] {
        merkle_root(&self.boundaries)
    }

    pub fn leaf(&self) -> [u8; 32] {
        detect_leaf(&self.root(), &self.chain, self.count)
    }
}

impl Default for Stream {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pinned against tests/detect-chain-vectors.json (the frozen JS-reference vectors):
    // chain over 10 deterministic entries E_i[b] = (i*7 + b*3) & 0xff, plus the empty-root
    // detect leaf — proving THIS reference agrees with the construction both other
    // implementations pin.
    #[test]
    fn chain_and_leaf_match_frozen_vectors() {
        let mut chain = [0u8; 32];
        for i in 0..10u64 {
            let entry: Vec<u8> = (0..48u64).map(|b| ((i * 7 + b * 3) % 256) as u8).collect();
            chain = sha(&[&chain, &entry]);
        }
        assert_eq!(
            hex::encode(chain),
            "ef7cf10099fa5178456e0fb6ec6aea47e73c8a4d2db2073b17c179c1727af173"
        );
        assert_eq!(
            hex::encode(detect_leaf(&[0u8; 32], &chain, 10)),
            "cef356a6203e2c1e689488d8c6402dfddf935b055d01185279503ab5b5561617"
        );
    }

    #[test]
    fn merkle_matches_frozen_vectors() {
        let leaves: Vec<[u8; 32]> = (0..5u64)
            .map(|j| {
                let mut leaf = [0u8; 32];
                for (b, slot) in leaf.iter_mut().enumerate() {
                    *slot = ((j * 11 + b as u64) % 256) as u8;
                }
                leaf
            })
            .collect();
        assert_eq!(
            hex::encode(merkle_root(&leaves)),
            "fe4b113438fa846e52048b7a29c078d5c22517634cd1e1093dbe9388298f2739"
        );
        assert_eq!(
            hex::encode(leaf_hash(&leaves[0])),
            "699cacdb4c39d8e0bb1223352765a7f7acdc51dec6694f7b54c3d0a47f0cc409"
        );
    }
}
