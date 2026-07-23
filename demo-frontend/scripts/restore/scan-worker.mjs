// Parallel restore scan worker (Menese DeFi Team). Processes a CHUNK of consecutive DPAGE-aligned
// segments in one tight loop (amortizes message overhead → near-linear scaling) while preserving
// per-segment VERIFY-BEFORE-SCAN and bounded memory (one segment's bytes held at a time). Per
// segment: recompute the chain, verify its end boundary against the trusted certified root (chain
// value == mirror-served boundary AND that boundary's Merkle path resolves to root), and only then
// scan its entries (ECDH + view-tag). A segment that fails verification aborts the chunk (the
// chain is broken past it) and is reported rejected — its entries never influence the owned set.
import { parentPort, workerData } from "node:worker_threads";
import { makeMatcher, ENTRY_LEN } from "./kernel.mjs";
import { DPAGE, foldEntry, verifyMerkle, zero32 } from "./detect-chain.mjs";
import { makeSynthetic } from "./mirror.mjs";

const { mode, encSk, root: rootArr } = workerData;
const matcher = makeMatcher(mode, Uint8Array.from(encSk));
const ROOT = Uint8Array.from(rootArr);
const PAGE = 512;
const pageOf = (p) => Math.floor(p / PAGE) * PAGE;
const u8 = (a) => (a == null ? null : Uint8Array.from(a));
const eqBytes = (a, b) => { if (a.length !== b.length) return false; for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false; return true; };

function processChunk(t) {
  const t0 = process.hrtime.bigint();
  const gen = t.seedText != null ? makeSynthetic(t.seedText, new Map((t.planted ?? []).map(([p, e]) => [p, { ephPk: u8(e.ephPk), tag: u8(e.tag) }]))) : null;
  // chunk start anchor: L_{startSeg-1}, Merkle-verified, or 0^32 for segment 0
  let chain;
  if (t.startFrom === 0) chain = zero32();
  else {
    const sv = u8(t.startAnchor.value), sp = t.startAnchor.path.map((s) => ({ hash: u8(s.hash), right: s.right }));
    if (!t.skipVerify && !verifyMerkle(sv, t.startFrom / DPAGE - 1, sp, ROOT)) return reply(t.id, { rejected: [{ seg: t.startFrom / DPAGE, reason: "start-merkle" }] }, t0);
    chain = sv;
  }
  const matchedPages = new Set();
  let scanned = 0;
  for (let si = 0; si < t.segs.length; si++) {
    const s = t.segs[si];
    // materialize one segment's bytes (provided by the untrusted mirror, or generated for scale)
    let bytes;
    if (t.segBytes) bytes = new Uint8Array(t.segBytes[si]);
    else { const n = s.to - s.from; bytes = new Uint8Array(n * ENTRY_LEN); for (let i = s.from; i < s.to; i++) bytes.set(gen(i), (i - s.from) * ENTRY_LEN); }
    // count is derived from the ACTUAL served bytes — a truncated/malformed mirror page yields a
    // chain over fewer entries (⇒ verify mismatch), and never reads past the buffer while scanning.
    if (bytes.length % ENTRY_LEN !== 0) return reply(t.id, { rejected: [{ seg: s.from / DPAGE, reason: "malformed-length" }], matchedPages: [...matchedPages], scanned }, t0);
    const count = bytes.length / ENTRY_LEN;
    // fold this segment into the running chain
    let segChain = chain;
    for (let i = 0; i < count; i++) segChain = foldEntry(segChain, bytes.subarray(i * ENTRY_LEN, i * ENTRY_LEN + ENTRY_LEN));
    // VERIFY before scan
    if (!t.skipVerify) {
      if (s.isTip) { if (!eqBytes(segChain, u8(t.cTip))) return reply(t.id, { rejected: [{ seg: s.from / DPAGE, reason: "tip-mismatch" }], matchedPages: [...matchedPages], scanned }, t0); }
      else {
        const ea = u8(s.endAnchor);
        if (!eqBytes(segChain, ea)) return reply(t.id, { rejected: [{ seg: s.from / DPAGE, reason: "chain-mismatch" }], matchedPages: [...matchedPages], scanned }, t0);
        const ep = s.endProof.map((x) => ({ hash: u8(x.hash), right: x.right }));
        if (!verifyMerkle(ea, s.leafIndex, ep, ROOT)) return reply(t.id, { rejected: [{ seg: s.from / DPAGE, reason: "end-merkle" }], matchedPages: [...matchedPages], scanned }, t0);
      }
    }
    chain = segChain;
    // SCAN (only reached for a verified segment)
    for (let i = 0; i < count; i++) {
      const entry = bytes.subarray(i * ENTRY_LEN, i * ENTRY_LEN + ENTRY_LEN);
      let pos = 0; for (let k = 0; k < 8; k++) pos = pos * 256 + entry[k];
      if (pos < t.from0) continue;
      if (pos < t.eff) { matchedPages.add(pageOf(pos)); continue; }
      if (matcher(entry).match) matchedPages.add(pageOf(pos));
    }
    scanned += count;
  }
  reply(t.id, { rejected: [], matchedPages: [...matchedPages], scanned }, t0);
}

function reply(id, fields, t0) {
  parentPort.postMessage({ id, rejected: fields.rejected ?? [], matchedPages: fields.matchedPages ?? [], scanned: fields.scanned ?? 0, elapsedNs: Number(process.hrtime.bigint() - t0) });
}

parentPort.on("message", (msg) => { if (msg.stop) return parentPort.close(); processChunk(msg); });
