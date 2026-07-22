// PIR v2 client model + request-logging mock server for the B12 privacy battery
// (Menese DeFi Team). Faithful to src/Pir2.mo / soak/src/pir2.rs: n=1152, q=2^32, p=2^8,
// Delta=2^24, sigma=12.8, uniform secret; A expanded from the fixed domain constant. This is
// the JS twin used to assert transcript indistinguishability and selector statistics — byte
// equality against the ledger is the Rust differential's job, not this file's.

import { createHash } from "node:crypto";

export const N = 1152;
export const Q = 2 ** 32;
export const DELTA = 2 ** 24;
export const SIGMA = 12.8;
export const RECORD_BYTES = 288;
const A_DOMAIN = Buffer.from("zk-ledger/pir2/v1/A");

const u32 = (x) => x >>> 0;
const mulmod32 = (a, b) => {
  // 32x32 -> low 32 bits, exact via 16-bit split (avoids float rounding above 2^53).
  const aLo = a & 0xffff, aHi = a >>> 16;
  const bLo = b & 0xffff, bHi = b >>> 16;
  const cross = (aLo * bHi + aHi * bLo) & 0xffff;
  return u32(aLo * bLo + (cross << 16));
};
const addmod32 = (a, b) => u32(a + b);

const le64 = (v) => {
  const b = Buffer.alloc(8);
  b.writeUInt32LE(v >>> 0, 0);
  b.writeUInt32LE(Math.floor(v / 2 ** 32) >>> 0, 4);
  return b;
};

export function geometry(shardSize) {
  const target = Math.floor(Math.sqrt(shardSize * RECORD_BYTES));
  const rpc = Math.max(1, Math.floor((target + Math.floor(RECORD_BYTES / 2)) / RECORD_BYTES));
  return { shardSize, rpc, mRows: RECORD_BYTES * rpc, mCols: Math.ceil(shardSize / rpc) };
}

export function place(g, i) {
  return { c: Math.floor(i / g.rpc), r0: RECORD_BYTES * (i % g.rpc) };
}
export const pinnedColumns = (g, fill) => Math.ceil(fill / g.rpc);

// A[c,:] for shard s — 144 SHA-256 blocks, 8 LE u32 words each.
export function aRow(shard, c) {
  const out = new Uint32Array(N);
  for (let k = 0; k < N / 8; k++) {
    const h = createHash("sha256");
    h.update(A_DOMAIN);
    h.update(le64(shard));
    h.update(le64(c));
    h.update(le64(k));
    const block = h.digest();
    for (let w = 0; w < 8; w++) out[8 * k + w] = block.readUInt32LE(4 * w);
  }
  return out;
}

// Deterministic PRNG (seeded) so batteries are reproducible.
export function rng(seed) {
  let s = seed >>> 0;
  return () => {
    s = u32(s * 1664525 + 1013904223);
    // splitmix-ish extra mixing for u32 quality
    let x = s;
    x ^= x >>> 16; x = mulmod32(x, 0x7feb352d);
    x ^= x >>> 15; x = mulmod32(x, 0x846ca68b);
    x ^= x >>> 16;
    return u32(x);
  };
}

export function keygen(next) {
  const s = new Uint32Array(N);
  for (let i = 0; i < N; i++) s[i] = next();
  return s;
}

export function gaussian(next) {
  const scale = 2 ** 53;
  const a = ((next() * 2 ** 32 + next()) / 2 ** 11 + 1) / (scale + 1);
  const b = ((next() * 2 ** 32 + next()) / 2 ** 11 + 1) / (scale + 1);
  const normal = Math.sqrt(-2 * Math.log(a)) * Math.cos(2 * Math.PI * b);
  const e = Math.round(normal * SIGMA);
  return u32(e < 0 ? e + Q : e);
}

// qu[c] = A[c,:]·s + e_c + Delta·[c==cStar]. The wire carries no index.
export function buildQuery(shard, g, fill, cStar, secret, next) {
  const cols = pinnedColumns(g, fill);
  const qu = new Uint32Array(cols);
  for (let c = 0; c < cols; c++) {
    const a = aRow(shard, c);
    let dot = 0;
    for (let j = 0; j < N; j++) dot = addmod32(dot, mulmod32(a[j], secret[j]));
    let v = addmod32(dot, gaussian(next));
    if (c === cStar) v = addmod32(v, DELTA);
    qu[c] = v;
  }
  return qu;
}

// A request-logging mock of the pir2 server surface. Records exactly the caller-visible
// arguments (never the secret / target) so the battery asserts what the server sees.
export class MockPir2Ledger {
  constructor(shardSize) {
    this.g = geometry(shardSize);
    this.shardSize = shardSize;
    this.requestLog = [];
  }
  resetLog() {
    this.requestLog = [];
  }
  // server sees: shard, fill (pin), stripe, kCols, and the qu byte length — not the target
  answerStripe(shard, fill, stripe, kCols, quWireLen) {
    this.requestLog.push({ method: "pir2_query", shard, fill, stripe, kCols, quWireLen });
    return this.g.mRows * 4; // dense response byte length
  }
  hintChunk(shard, offset, len) {
    this.requestLog.push({ method: "pir2_hint_chunk", shard, offset, len });
    return len;
  }
  recordStream(start, count) {
    this.requestLog.push({ method: "pir2_record_stream", start, count });
    return count * 296;
  }
}

// The SHIPPED client access policy: fetch/query is a public function of (shardSet, kCols)
// only — never of the target. It runs the FULL stripe schedule of the pinned fill on every
// scheduled shard, with a dummy target where it has no match. `leaky` flips it into the
// forbidden shape (skip stripes that don't contain the target) so the battery's oracle can
// prove it detects the leak.
export function runScheduledQueries(ledger, { shardSet, fill, kCols, targets, secretSeed, leaky = false }) {
  const g = ledger.g;
  const next = rng(secretSeed);
  const cols = pinnedColumns(g, fill);
  const stripes = Math.ceil(cols / kCols);
  for (const shard of shardSet) {
    const target = targets[shard]; // may be undefined (no match) -> dummy target 0
    const cStar = target === undefined ? 0 : place(g, target).c;
    const secret = keygen(next);
    const qu = buildQuery(shard, g, fill, cStar, secret, next);
    const quWireLen = qu.length * 4;
    for (let s = 0; s < stripes; s++) {
      if (leaky) {
        const lo = s * kCols, hi = Math.min(lo + kCols, cols);
        if (!(cStar >= lo && cStar < hi)) continue; // FORBIDDEN: schedule depends on target
      }
      ledger.answerStripe(shard, fill, s, kCols, quWireLen);
    }
  }
}

// A canonical transcript string over the server-visible fields (target-independent by design).
export function pir2Transcript(ledger) {
  return ledger.requestLog
    .map((e) =>
      e.method === "pir2_query"
        ? `Q:${e.shard}:${e.fill}:${e.stripe}:${e.kCols}:${e.quWireLen}`
        : `${e.method}:${JSON.stringify(e)}`
    )
    .join(",");
}
