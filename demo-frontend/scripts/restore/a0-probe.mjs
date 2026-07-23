// A0 baseline probe for birthday-less restore at scale (Menese DeFi Team).
//
// Measures, on THIS box, the PRIMITIVES the parallel scanner is later built to beat — BEFORE the
// production scanner exists, so the committed acceptance bounds are measurement-derived, not
// retro-fitted (bounded-verification discipline):
//   1. per-note detection cost, both byte-identical kernels (reference nacl / native OpenSSL)
//   2. verification cost: SHA-256 chain fold per 48-B entry (the mirror page-verify inner op)
//   3. worker_threads scaling at W = 1/2/4/8 (native kernel) + reference at W = 1/8
//   4. streaming memory: peak RSS over an on-the-fly 500k scan (never buffers the stream)
// Emits scripts/restore/a0-results.json and a human table. Reproduce: `node a0-probe.mjs`.
import { Worker } from "node:worker_threads";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { writeFileSync } from "node:fs";
import crypto from "node:crypto";
import nacl from "tweetnacl";
import { makeMatcher, ENTRY_LEN } from "./kernel.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const CORES = (await import("node:os")).cpus().length;

// ---- 1. single-thread per-note cost, both kernels ----
function singleThreadCost(mode, M) {
  const encSk = nacl.box.keyPair().secretKey;
  const matcher = makeMatcher(mode, encSk);
  const pool = [];
  for (let i = 0; i < 2048; i++) pool.push(crypto.randomBytes(32));
  const entry = new Uint8Array(ENTRY_LEN);
  // warm
  for (let i = 0; i < 2000; i++) { entry.set(pool[i & 2047], 8); matcher(entry); }
  let matched = 0;
  const t0 = process.hrtime.bigint();
  for (let i = 0; i < M; i++) {
    entry.set(pool[i & 2047], 8);
    let p = i; for (let k = 7; k >= 0; k--) { entry[k] = p & 0xff; p = Math.floor(p / 256); }
    if (matcher(entry).match) matched++;
  }
  const t1 = process.hrtime.bigint();
  const nsPerNote = Number(t1 - t0) / M;
  return { mode, nsPerNote, notesPerSec: 1e9 / nsPerNote, matched };
}

// ---- 2. SHA-256 chain-fold verification cost ----
function verifyCost(S) {
  let h = Buffer.alloc(32);
  const entry = Buffer.alloc(ENTRY_LEN);
  const t0 = process.hrtime.bigint();
  for (let i = 0; i < S; i++) h = crypto.createHash("sha256").update(h).update(entry).digest();
  const t1 = process.hrtime.bigint();
  const nsPerEntry = Number(t1 - t0) / S;
  return { nsPerEntry, entriesPerSec: 1e9 / nsPerEntry };
}

// ---- 3. worker-pool scaling ----
function runWorker(mode, encSk, count) {
  return new Promise((res, rej) => {
    const w = new Worker(resolve(here, "a0-worker.mjs"), { workerData: { mode, encSk: Array.from(encSk), count } });
    w.once("message", (m) => { w.terminate(); res(m); });
    w.once("error", rej);
  });
}
async function scaling(mode, totalNotes, widths) {
  const encSk = nacl.box.keyPair().secretKey;
  const rows = [];
  let baseWall = null;
  for (const W of widths) {
    const per = Math.floor(totalNotes / W);
    const t0 = process.hrtime.bigint();
    const results = await Promise.all(Array.from({ length: W }, () => runWorker(mode, encSk, per)));
    const wallNs = Number(process.hrtime.bigint() - t0);
    const done = results.reduce((a, r) => a + r.count, 0);
    if (W === 1) baseWall = wallNs;
    rows.push({ workers: W, notes: done, wallSec: wallNs / 1e9, notesPerSec: done / (wallNs / 1e9), speedup: baseWall ? baseWall / wallNs : 1 });
  }
  return rows;
}

// ---- 4. streaming memory ----
function memoryProbe(mode, N) {
  const encSk = nacl.box.keyPair().secretKey;
  const matcher = makeMatcher(mode, encSk);
  const pool = []; for (let i = 0; i < 4096; i++) pool.push(crypto.randomBytes(32));
  const baseline = process.memoryUsage().rss;
  let peak = baseline;
  const entry = new Uint8Array(ENTRY_LEN);
  const matchedPages = new Set();
  for (let i = 0; i < N; i++) {
    entry.set(pool[i & 4095], 8);
    const { pos, match } = matcher(entry);
    if (match) matchedPages.add(Math.floor(pos / 512) * 512);
    if ((i & 0x3ffff) === 0) { const r = process.memoryUsage().rss; if (r > peak) peak = r; }
  }
  const r = process.memoryUsage().rss; if (r > peak) peak = r;
  return { baselineMB: baseline / 2 ** 20, peakMB: peak / 2 ** 20, deltaMB: (peak - baseline) / 2 ** 20, scanned: N };
}

// ---- run ----
console.log(`A0 probe — cores=${CORES}, node=${process.version}\n`);

const ref = singleThreadCost("reference", 60000);
const nat = singleThreadCost("native", 200000);
console.log("[1] single-thread per-note detection cost");
for (const r of [ref, nat]) console.log(`    ${r.mode.padEnd(9)} ${r.nsPerNote.toFixed(0).padStart(7)} ns/note   ${r.notesPerSec.toFixed(0).padStart(8)} notes/s`);

const ver = verifyCost(1_000_000);
console.log(`\n[2] verification: sha256 chain fold ${ver.nsPerEntry.toFixed(0)} ns/entry (${ver.entriesPerSec.toFixed(0)} entries/s) — ${(ver.nsPerEntry / nat.nsPerNote * 100).toFixed(1)}% of a native detect op`);

console.log(`\n[3] worker_threads scaling (native kernel, 2,000,000 notes total workload)`);
const natScale = await scaling("native", 2_000_000, [1, 2, 4, 8]);
for (const r of natScale) console.log(`    W=${r.workers}  ${r.wallSec.toFixed(2).padStart(6)}s  ${r.notesPerSec.toFixed(0).padStart(9)} notes/s  speedup ${r.speedup.toFixed(2)}x`);
console.log(`    reference kernel (300,000 notes total):`);
const refScale = await scaling("reference", 300_000, [1, 8]);
for (const r of refScale) console.log(`    W=${r.workers}  ${r.wallSec.toFixed(2).padStart(6)}s  ${r.notesPerSec.toFixed(0).padStart(9)} notes/s  speedup ${r.speedup.toFixed(2)}x`);

console.log(`\n[4] streaming memory (native, 1,000,000 notes on-the-fly, never buffered)`);
const mem = memoryProbe("native", 1_000_000);
console.log(`    baseline ${mem.baselineMB.toFixed(1)} MB   peak ${mem.peakMB.toFixed(1)} MB   delta ${mem.deltaMB.toFixed(1)} MB`);

// projections to scale, using measured native 8-worker throughput
const nat8 = natScale.find((r) => r.workers === 8);
const proj = {};
for (const N of [1e6, 1e7, 1e8]) proj[N] = { native8wMin: N / nat8.notesPerSec / 60, wireGB: N * ENTRY_LEN / 2 ** 30 };
console.log(`\n[proj] native @8 workers (${nat8.notesPerSec.toFixed(0)} notes/s):`);
for (const N of [1e6, 1e7, 1e8]) console.log(`    N=${N.toExponential(0)}  scan ~${proj[N].native8wMin.toFixed(2)} min   wire ${proj[N].wireGB.toFixed(2)} GB (48 B/note)`);

const out = { box: { cores: CORES, node: process.version }, single: { reference: ref, native: nat }, verify: ver, scaling: { native: natScale, reference: refScale }, memory: mem, projection: proj, ts_note: "generated by a0-probe.mjs" };
writeFileSync(resolve(here, "a0-results.json"), JSON.stringify(out, null, 2));
console.log(`\nwrote ${resolve(here, "a0-results.json")}`);
