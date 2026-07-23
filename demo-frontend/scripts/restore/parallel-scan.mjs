// Parallel, streaming, resumable birthday-less restore scanner (Menese DeFi Team) — A-3.
//
// Streams DPAGE(4096)-aligned segments from an untrusted mirror in CHUNKS to a worker_threads pool
// (native ECDH kernel). Each worker VERIFIES-BEFORE-SCANS every segment against the trusted
// certified detect_stream root, unions matched 512-pages, and (main thread) retrieves + recognizes
// owned notes from the trusted canister page store. Bounded memory (one segment held per worker at
// a time — never the full stream), resumable (checkpointed chunk cursor that LAGS the durable
// matched-set), correctness-first (owned set identical to the sequential reference). Kernel mode
// ("reference"|"native") yields a byte-identical owned set either way.
import { Worker } from "node:worker_threads";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { DPAGE, detectLeaf } from "./detect-chain.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const PAGE = 512;
const ser = (path) => path.map((s) => ({ hash: Array.from(s.hash), right: s.right }));

class Pool {
  constructor(mode, encSk, size, root, throttleDuty) {
    // Hard per-worker heap cap: a streaming worker holds ONE segment (192 KB) at a time, so 96 MB
    // is enormous headroom — but it structurally PROVES the design never buffers the stream (the
    // full 10^8 stream is 4.8 GB; a worker that tried to hold it would crash against this cap).
    // throttleDuty (bench-only, default undefined): CPU duty-cycle fraction the worker may use —
    // models background-tab / battery-saver throttling for the device-envelope rows.
    this.workers = Array.from({ length: size }, () => new Worker(resolve(here, "scan-worker.mjs"), { workerData: { mode, encSk: Array.from(encSk), root: Array.from(root), throttleDuty }, resourceLimits: { maxOldGenerationSizeMb: 96 } }));
    this.free = [...this.workers]; this.waiters = []; this.pending = new Map();
    for (const w of this.workers) w.on("message", (m) => this._onMsg(w, m));
  }
  _onMsg(w, m) { const res = this.pending.get(m.id); this.pending.delete(m.id); this.free.push(w); const nx = this.waiters.shift(); if (nx) nx(); res(m); }
  async run(task, transfer) { while (this.free.length === 0) await new Promise((r) => this.waiters.push(r)); const w = this.free.pop(); return new Promise((resolve) => { this.pending.set(task.id, resolve); w.postMessage(task, transfer ?? []); }); }
  async close() { await Promise.all(this.workers.map((w) => w.terminate())); }
}

// opts: { mode, workers, mirror, trusted, encSk, from0, eff, total, seedText?, plantedByRange?,
//         recognize, checkpoint?, onCheckpoint?, chunkSegments?, injectDropTail?, skipVerify? }
export async function parallelScan(opts) {
  const { mode, workers, mirror, trusted, encSk, from0, eff, total, seedText, plantedByRange, recognize } = opts;
  // CERTIFICATE BINDING (before any mirror traffic): root, cTip, and noteCount MUST come
  // from ONE certificate. The certified tuple leaf is SHA256(root ‖ cTip ‖ count LE8), so
  // recomputing it over the caller's triple and comparing to the certificate's leaf
  // rejects any cross-certificate mix (root from cert A + tip/count from cert B) —
  // including a stale-prefix mix over the same honest stream, which every per-segment
  // check would otherwise accept. `skipLeafBinding` exists ONLY for the battery's teeth.
  if (!opts.skipLeafBinding) {
    if (trusted.leaf == null) {
      return { notes: [], matchedPages: [], rejected: [{ seg: -1, reason: "leaf-binding-missing" }], segments: 0, chunks: 0, workerNs: 0, maxWorkerNs: 0 };
    }
    const expected = detectLeaf(trusted.root, trusted.cTip, total);
    if (!Buffer.from(expected).equals(Buffer.from(trusted.leaf))) {
      return { notes: [], matchedPages: [], rejected: [{ seg: -1, reason: "leaf-binding" }], segments: 0, chunks: 0, workerNs: 0, maxWorkerNs: 0 };
    }
  }
  const startSeg = Math.floor(from0 / DPAGE);
  const lastComplete = Math.floor(total / DPAGE);
  const hasTip = total > lastComplete * DPAGE && !opts.injectDropTail;
  // resume: skip segments already completed (absolute segment ids), keep their matched pages
  const completed = new Set(opts.checkpoint?.doneSegs ?? []);
  const segList = [];
  for (let k = startSeg; k < lastComplete; k++) if (!completed.has(k)) segList.push({ k, isTip: false });
  if (hasTip && !completed.has(lastComplete)) segList.push({ k: lastComplete, isTip: true });

  // target ~8 chunks per worker for good load balance without excessive message overhead
  const chunkSegs = Math.max(1, opts.chunkSegments ?? (Math.floor(segList.length / (8 * workers)) || 1));
  const chunks = [];
  for (let i = 0; i < segList.length; i += chunkSegs) chunks.push(segList.slice(i, i + chunkSegs));

  const matched = new Set((opts.checkpoint?.matchedPages) ?? []);
  const rejected = [];
  const timings = [];
  const pool = new Pool(mode, encSk, workers, trusted.root, opts.workerThrottleDuty);
  let idc = 0;

  // Bandwidth shaping (bench-only, opt-in): a token bucket over the bytes each chunk puts
  // on the "wire" — dispatch of a chunk waits until the shaped link could have delivered
  // its bytes. Synthetic (seedText) chunks are charged their wire-equivalent size.
  const pace = opts.paceMbps ? { t0: Date.now(), consumed: 0, bytesPerMs: (opts.paceMbps * 1e6) / 8 / 1000 } : null;
  const paceTake = async (bytes) => {
    if (!pace) return;
    pace.consumed += bytes;
    const wait = pace.t0 + pace.consumed / pace.bytesPerMs - Date.now();
    if (wait > 0) await new Promise((r) => setTimeout(r, wait));
  };

  const buildTask = (chunk) => {
    const startFrom = chunk[0].k * DPAGE;
    const transfer = [];
    const segs = chunk.map(({ k, isTip }) => {
      const from = k * DPAGE, to = isTip ? total : (k + 1) * DPAGE;
      if (isTip) return { from, to, isTip: true };
      const bp = mirror.boundaryProof(k);
      return { from, to, isTip: false, leafIndex: k, endAnchor: Array.from(bp.leaf), endProof: ser(bp.path) };
    });
    const task = { id: ++idc, segs, startFrom, from0, eff, skipVerify: !!opts.skipVerify,
      cTip: chunk.some((c) => c.isTip) ? Array.from(trusted.cTip) : null };
    if (startFrom !== 0) { const bp = mirror.boundaryProof(chunk[0].k - 1); task.startAnchor = { value: Array.from(bp.leaf), path: ser(bp.path) }; }
    if (seedText != null) { task.seedText = seedText; task.planted = (plantedByRange && plantedByRange(startFrom, chunk[chunk.length - 1].isTip ? total : (chunk[chunk.length - 1].k + 1) * DPAGE)) || []; }
    else { task.segBytes = segs.map((s) => { const b = mirror.segmentBytes(s.from, s.to).buffer; transfer.push(b); return b; }); }
    return { task, transfer };
  };

  const dispatch = (chunk) => {
    const { task, transfer } = buildTask(chunk);
    const wireBytes = task.segBytes
      ? task.segBytes.reduce((a, b) => a + b.byteLength, 0)
      : chunk.reduce((a, c) => a + ((c.isTip ? total : (c.k + 1) * DPAGE) - c.k * DPAGE) * 48, 0);
    const run = () => pool.run(task, transfer).then((m) => {
      timings.push(m.elapsedNs);
      for (const mp of m.matchedPages) matched.add(mp);       // (1) durable matched-set write ...
      if (m.rejected.length) { for (const r of m.rejected) rejected.push(r); return; } // rejected chunk: don't mark done
      for (const c of chunk) completed.add(c.k);              // (2) ... happens-before the checkpoint advance (P0-2/DELTA-C)
      if (opts.onCheckpoint) opts.onCheckpoint({ doneSegs: [...completed], matchedPages: [...matched] });
    });
    return pace ? paceTake(wireBytes).then(run) : run();
  };
  const inflight = [];
  for (const chunk of chunks) {
    if (pace) await paceTake(0); // keep dispatch ordering stable under shaping
    inflight.push(dispatch(chunk));
  }
  await Promise.all(inflight);
  await pool.close();

  const matchedPages = [...matched].sort((a, b) => a - b);
  const notes = rejected.length ? [] : await recognize(matchedPages); // a rejected run yields no owned set (refetch from an honest mirror)
  return { notes, matchedPages, rejected, segments: segList.length, chunks: chunks.length,
    workerNs: timings.reduce((a, b) => a + b, 0), maxWorkerNs: Math.max(0, ...timings) };
}

export { PAGE, DPAGE };
