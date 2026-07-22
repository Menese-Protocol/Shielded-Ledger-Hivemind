// Parallel restore scan worker (Menese DeFi Team). One persistent worker per core; processes
// DPAGE-aligned segment tasks: VERIFY-BEFORE-SCAN (Merkle boundary proofs + chain recompute
// against the trusted certified root) then the per-note ECDH+view-tag recognition. A segment that
// fails verification is REJECTED and never scanned — a tampered/truncated page cannot inject a
// false match nor silently drop a planted note into the owned set.
import { parentPort, workerData } from "node:worker_threads";
import { makeMatcher, ENTRY_LEN } from "./kernel.mjs";
import { DPAGE, foldEntry, verifyMerkle, zero32 } from "./detect-chain.mjs";
import { makeSynthetic } from "./mirror.mjs";

const { mode, encSk } = workerData;
const matcher = makeMatcher(mode, Uint8Array.from(encSk));
const PAGE = 512;
const pageOf = (p) => Math.floor(p / PAGE) * PAGE;

function processTask(t) {
  const t0 = process.hrtime.bigint();
  // 1) materialize segment bytes (provided by the untrusted mirror, or generated for scale)
  let bytes;
  if (t.segBytes) bytes = new Uint8Array(t.segBytes);
  else {
    const planted = new Map((t.planted ?? []).map(([p, e]) => [p, { ephPk: Uint8Array.from(e.ephPk), tag: Uint8Array.from(e.tag) }]));
    const gen = makeSynthetic(t.seedText, planted);
    bytes = new Uint8Array((t.to - t.from) * ENTRY_LEN);
    for (let i = t.from; i < t.to; i++) bytes.set(gen(i), (i - t.from) * ENTRY_LEN);
  }
  const root = Uint8Array.from(t.root);
  // skipVerify is a TEST-ONLY affordance (default off): the tamper battery uses it to prove that
  // WITHOUT verify-before-scan a truncated page silently drops a planted note (an FN) — i.e. that
  // the verification below is load-bearing. Production never sets it.
  if (t.skipVerify) return scanOnly(t, bytes, t0);
  // 2) VERIFY before scan
  // start anchor
  let startChain;
  if (t.from === 0) startChain = zero32();
  else {
    const sa = Uint8Array.from(t.startAnchor), sp = t.startProof.map((s) => ({ hash: Uint8Array.from(s.hash), right: s.right }));
    if (!verifyMerkle(sa, t.from / DPAGE - 1, sp, root)) return reject(t.id, "start-merkle", t0);
    startChain = sa;
  }
  // recompute chain across the segment
  let chain = startChain;
  const count = bytes.length / ENTRY_LEN;
  for (let i = 0; i < count; i++) chain = foldEntry(chain, bytes.subarray(i * ENTRY_LEN, i * ENTRY_LEN + ENTRY_LEN));
  // expected end
  let expected;
  if (t.isTip) expected = Uint8Array.from(t.cTip); // certified directly
  else {
    const ea = Uint8Array.from(t.endAnchor), ep = t.endProof.map((s) => ({ hash: Uint8Array.from(s.hash), right: s.right }));
    if (!verifyMerkle(ea, t.leafIndex, ep, root)) return reject(t.id, "end-merkle", t0);
    expected = ea;
  }
  let eq = chain.length === expected.length;
  for (let i = 0; eq && i < chain.length; i++) if (chain[i] !== expected[i]) eq = false;
  if (!eq) return reject(t.id, "chain-mismatch", t0);
  // 3) SCAN (only reached on a verified segment)
  return scanOnly(t, bytes, t0);
}

function scanOnly(t, bytes, t0) {
  const count = bytes.length / ENTRY_LEN;
  const matchedPages = new Set();
  for (let i = 0; i < count; i++) {
    const entry = bytes.subarray(i * ENTRY_LEN, i * ENTRY_LEN + ENTRY_LEN);
    let pos = 0; for (let k = 0; k < 8; k++) pos = pos * 256 + entry[k];
    if (pos < t.from0) continue;
    if (pos < t.eff) { matchedPages.add(pageOf(pos)); continue; }
    if (matcher(entry).match) matchedPages.add(pageOf(pos));
  }
  parentPort.postMessage({ id: t.id, rejected: false, matchedPages: [...matchedPages], scanned: count, elapsedNs: Number(process.hrtime.bigint() - t0) });
}

function reject(id, reason, t0) {
  parentPort.postMessage({ id, rejected: true, reason, matchedPages: [], scanned: 0, elapsedNs: Number(process.hrtime.bigint() - t0) });
}

parentPort.on("message", (msg) => {
  if (msg.stop) { parentPort.close(); return; }
  processTask(msg);
});
