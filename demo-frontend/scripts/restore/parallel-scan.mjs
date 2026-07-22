// Parallel, streaming, resumable birthday-less restore scanner (Menese DeFi Team) — A-3.
//
// Streams DPAGE(4096)-aligned segments from an untrusted mirror, dispatches each to a
// worker_threads pool that VERIFIES-before-SCANs against the trusted certified detect_stream root,
// unions matched 512-pages, and (main thread) retrieves + recognizes owned notes from the trusted
// canister page store. Bounded memory (never holds the full stream), resumable (checkpointed
// cursor that LAGS the durable matched-set), correctness-first (owned set identical to the
// sequential reference). The kernel mode ("reference"|"native") is byte-identical either way.
import { Worker } from "node:worker_threads";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { DPAGE } from "./detect-chain.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const PAGE = 512;

class Pool {
  constructor(mode, encSk, size) {
    this.workers = Array.from({ length: size }, () => new Worker(resolve(here, "scan-worker.mjs"), { workerData: { mode, encSk: Array.from(encSk) } }));
    this.free = [...this.workers];
    this.waiters = [];
    this.pending = new Map();
    for (const w of this.workers) w.on("message", (m) => this._onMsg(w, m));
  }
  _onMsg(w, m) {
    const res = this.pending.get(m.id); this.pending.delete(m.id);
    this.free.push(w);
    const nx = this.waiters.shift(); if (nx) nx();
    res(m);
  }
  async run(task) {
    while (this.free.length === 0) await new Promise((r) => this.waiters.push(r));
    const w = this.free.pop();
    return new Promise((resolve) => { this.pending.set(task.id, resolve); w.postMessage(task, task.segBytes ? [task.segBytes] : []); });
  }
  async close() { await Promise.all(this.workers.map((w) => w.terminate())); }
}

// opts: { mode, workers, mirror, trusted, encSk, from0, eff, total,
//         seedText?, plantedByRange?, recognize, checkpoint?, onCheckpoint?, injectDropTail? }
// mirror: { segmentBytes(from,to), boundaryProof(j) }  (UNTRUSTED)
// trusted: { root, cTip, noteCount }                    (certified anchor)
// recognize(matchedPages:number[]) -> notes[]           (trusted canister retrieval + open + cm-check)
export async function parallelScan(opts) {
  const { mode, workers, mirror, trusted, encSk, from0, eff, total, seedText, plantedByRange, recognize } = opts;
  const startSeg = Math.floor(from0 / DPAGE);
  const lastComplete = Math.floor(total / DPAGE);       // number of complete segments
  const hasTip = total > lastComplete * DPAGE;
  const segIndices = [];
  for (let k = startSeg; k < lastComplete; k++) segIndices.push(k);
  const tipIndex = hasTip ? lastComplete : null;        // tip segment id (by its start-segment k)

  // resume state
  const matched = new Set((opts.checkpoint?.matchedPages) ?? []);
  const done = new Set();                                // completed segment ids (k, or "tip")
  let cursor = opts.checkpoint?.cursorSeg ?? startSeg;   // contiguous-completed prefix boundary
  const rejected = [];
  const timings = [];

  const pool = new Pool(mode, encSk, workers);
  let idc = 0;

  const buildTask = (k, isTip) => {
    const from = k * DPAGE;
    const to = isTip ? total : (k + 1) * DPAGE;
    // inject: drop the tail of the LAST segment's bytes (proves the FN battery has teeth)
    let segBytes = null, planted = null;
    if (seedText != null) { planted = (plantedByRange && plantedByRange(from, to)) || []; }
    else { segBytes = mirror.segmentBytes(from, to).buffer; }
    const task = { id: ++idc, from, to, leafIndex: isTip ? -1 : k, isTip: !!isTip,
      root: Array.from(trusted.root), cTip: isTip ? Array.from(trusted.cTip) : null,
      from0, eff, segBytes, seedText: seedText ?? null, planted, skipVerify: !!opts.skipVerify };
    if (from !== 0) { const bp = mirror.boundaryProof(k - 1); task.startAnchor = Array.from(bp.leaf); task.startProof = bp.path.map((s) => ({ hash: Array.from(s.hash), right: s.right })); }
    if (!isTip) { const bp = mirror.boundaryProof(k); task.endAnchor = Array.from(bp.leaf); task.endProof = bp.path.map((s) => ({ hash: Array.from(s.hash), right: s.right })); }
    return task;
  };

  const advanceCursor = () => {
    // cursor may only pass a segment once it AND all prior are done and their matched pages recorded
    while (done.has(cursor)) { cursor++; }
  };

  const inflight = [];
  const dispatch = (k, isTip) => {
    const p = pool.run(buildTask(k, isTip)).then((m) => {
      timings.push(m.elapsedNs);
      if (m.rejected) { rejected.push({ seg: k, reason: m.reason }); }
      else { for (const mp of m.matchedPages) matched.add(mp); }
      // DURABLE matched-set write happens-before cursor advance (resume invariant P0-2/DELTA-C)
      done.add(isTip ? tipIndex : k);
      if (opts.onCheckpoint) opts.onCheckpoint({ cursorSeg: cursor, matchedPages: [...matched] });
      advanceCursor();
    });
    inflight.push(p);
  };

  for (const k of segIndices) dispatch(k, false);
  // injectDropTail is a TEST-ONLY affordance (default off, no production effect): it skips the
  // tip segment so the correctness battery can prove a dropped-tail bug surfaces as a MISSED
  // planted note (RED-provable-by-injection). The real scanner always dispatches the tip.
  if (hasTip && !opts.injectDropTail) dispatch(tipIndex, true);
  await Promise.all(inflight);
  await pool.close();

  const matchedPages = [...matched].sort((a, b) => a - b);
  const notes = rejected.length ? [] : await recognize(matchedPages); // a rejected run yields no owned set (refetch from an honest mirror)
  return { notes, matchedPages, rejected, segments: segIndices.length + (hasTip ? 1 : 0),
    workerNs: timings.reduce((a, b) => a + b, 0), maxWorkerNs: Math.max(0, ...timings) };
}

export { PAGE, DPAGE };
