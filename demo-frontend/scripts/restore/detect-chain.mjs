// Certified detection-stream construction — the ONE source of truth shared by the mock mirror,
// the client verifier, and (via generated vectors) the Motoko port (Menese DeFi Team).
//
//   entry E_i        = (pos_i BE8) || note_ciphertext_i[0..40]              (48 B)
//   chain c_{i+1}    = SHA256(c_i || E_i),   c_0 = 0^32
//   boundary L_j     = c_{DPAGE*(j+1)}       (chain after complete segment j)
//   Merkle root R    = RFC-6962-style tree over [L_0 .. L_{covered-1}]
//   c_tip            = c_{note_count}        (covers the partial tail directly)
//   detect leaf      = SHA256(R || c_tip || note_count LE8)   -> folded into certifiedTuple
//
// Merkle: leafHash = SHA256(0x00 || v), nodeHash = SHA256(0x01 || a || b), odd node promoted
// unchanged (RFC 6962). Empty tree root = 0^32.
import crypto from "node:crypto";

export const DPAGE = 4096;
export const ENTRY_LEN = 48;
const ZERO32 = new Uint8Array(32);

const sha256 = (...parts) => {
  const h = crypto.createHash("sha256");
  for (const p of parts) h.update(p);
  return new Uint8Array(h.digest());
};

export function posBE8(pos) {
  const b = new Uint8Array(8);
  let p = pos;
  for (let k = 7; k >= 0; k--) { b[k] = p & 0xff; p = Math.floor(p / 256); }
  return b;
}
function u64LE(n) {
  const b = new Uint8Array(8);
  let v = n;
  for (let k = 0; k < 8; k++) { b[k] = v & 0xff; v = Math.floor(v / 256); }
  return b;
}

// Fold one 48-B entry into the running chain.
export const foldEntry = (chain, entry48) => sha256(chain, entry48);

// ---- Merkle (RFC-6962-style, single-byte domain separation) ----
export const leafHash = (v32) => sha256(Uint8Array.of(0x00), v32);
export const nodeHash = (a, b) => sha256(Uint8Array.of(0x01), a, b);

export function merkleRoot(leafValues) {
  if (leafValues.length === 0) return ZERO32.slice();
  let level = leafValues.map(leafHash);
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(i + 1 < level.length ? nodeHash(level[i], level[i + 1]) : level[i]);
    }
    level = next;
  }
  return level[0];
}

// Inclusion proof for leaf index j: [{hash, right}] bottom-up (right=true => sibling is on the right).
export function merkleProof(leafValues, j) {
  const path = [];
  let level = leafValues.map(leafHash);
  let idx = j;
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      const hasRight = i + 1 < level.length;
      if (i === idx || i + 1 === idx) {
        if (idx === i && hasRight) path.push({ hash: level[i + 1], right: true });
        else if (idx === i + 1) path.push({ hash: level[i], right: false });
        // lone promoted node (no sibling): no path element at this level
      }
      next.push(hasRight ? nodeHash(level[i], level[i + 1]) : level[i]);
    }
    idx = Math.floor(idx / 2);
    level = next;
  }
  return path;
}

// Precompute all tree levels once; extract O(log) proofs cheaply (avoids O(n) rebuild per proof).
export function merkleTree(leafValues) {
  const levels = [leafValues.map(leafHash)];
  while (levels[levels.length - 1].length > 1) {
    const cur = levels[levels.length - 1], next = [];
    for (let i = 0; i < cur.length; i += 2) next.push(i + 1 < cur.length ? nodeHash(cur[i], cur[i + 1]) : cur[i]);
    levels.push(next);
  }
  const root = leafValues.length ? levels[levels.length - 1][0] : ZERO32.slice();
  const proof = (j) => {
    const path = []; let idx = j;
    for (let l = 0; l < levels.length - 1; l++) {
      const cur = levels[l];
      if (idx % 2 === 0) { if (idx + 1 < cur.length) path.push({ hash: cur[idx + 1], right: true }); }
      else path.push({ hash: cur[idx - 1], right: false });
      idx = Math.floor(idx / 2);
    }
    return path;
  };
  return { root, proof };
}

export function verifyMerkle(leafValue, j, path, root) {
  let h = leafHash(leafValue);
  for (const step of path) h = step.right ? nodeHash(h, step.hash) : nodeHash(step.hash, h);
  return Buffer.from(h).equals(Buffer.from(root));
}

export const detectLeaf = (root, cTip, noteCount) => sha256(root, cTip, u64LE(noteCount));

// Build the full certified state from an entry generator over [0, noteCount).
// entryAt(i) -> Uint8Array(48). Returns { boundaries:[L_j], root, cTip, noteCount, leaf }.
export function buildStream(entryAt, noteCount) {
  let chain = ZERO32.slice();
  const boundaries = [];
  for (let i = 0; i < noteCount; i++) {
    chain = foldEntry(chain, entryAt(i));
    if ((i + 1) % DPAGE === 0) boundaries.push(chain.slice());
  }
  const root = merkleRoot(boundaries);
  return { boundaries, root, cTip: chain.slice(), noteCount, leaf: detectLeaf(root, chain, noteCount) };
}

// Recompute a segment's chain from its start anchor over the segment's entries.
// Returns the end-chain value; the caller compares to the trusted boundary/cTip.
export function recomputeSegment(startChain, entryAt, from, to) {
  let chain = startChain.slice();
  for (let i = from; i < to; i++) chain = foldEntry(chain, entryAt(i));
  return chain;
}

export const zero32 = () => ZERO32.slice();
