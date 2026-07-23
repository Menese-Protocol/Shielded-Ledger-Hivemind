// AC-4 device-envelope restore benchmarks (Menese DeFi Team) — every headless-measurable
// row of docs/RESTORE-BENCHMARKS.md. One row per invocation (fresh heap, no cross-row
// contamination); a driver loop or the doc's commands run them all.
//
//   node bench-envelope.mjs baseline   — N=1e6 real-byte mirror scan, 4 workers (reference wall)
//   node bench-envelope.mjs cores4     — N=1e7 synthetic scan pinned to 4 cores (taskset -c 0-3)
//   node bench-envelope.mjs shaped10   — N=1e6 real-byte scan over a 10 Mbps-shaped stream
//   node bench-envelope.mjs shaped50   — N=1e6 real-byte scan over a 50 Mbps-shaped stream
//   node bench-envelope.mjs throttle   — N=1e6, workers duty-cycled to 25% CPU (background tab model)
//   node bench-envelope.mjs resume     — N=1e6, child scan SIGKILLed mid-run, resumed from its
//                                        persisted checkpoint file; zero-FN must survive the kill
//
// Every row ends with a zero-FN census: the recognized owned set must equal the planted
// set exactly (positions first/middle/last). Rows append JSON to bench-results.jsonl.
import "../readpath/setup-declarations.mjs";
import naclPkg from "tweetnacl";
import { appendFileSync, writeFileSync, renameSync, readFileSync, existsSync, unlinkSync } from "node:fs";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { wasmShim, makeAccount } from "../readpath/shim.mjs";
import { ENTRY_LEN, DPAGE } from "./detect-chain.mjs";
import { makeSynthetic, plantOwned, buildAnchor, makeMirror } from "./mirror.mjs";
import { parallelScan } from "./parallel-scan.mjs";

const nacl = naclPkg.default ?? naclPkg;
const here = dirname(fileURLToPath(import.meta.url));
const row = process.argv[2] ?? "baseline";
const RESULTS = resolve(here, "bench-results.jsonl");
const CKPT = resolve(here, "bench-resume.ckpt.json");

function corpus(N) {
  const account = makeAccount(nacl, 7);
  const seedText = `bench/${N}`;
  const plantPositions = [0, Math.floor(N / 2), N - 1];
  const plantedNotes = plantPositions.map((p, i) => plantOwned(account, wasmShim, p, 30 + i));
  const plantedMap = new Map(plantedNotes.map((pn) => [pn.position, { ephPk: pn.ephPk, tag: pn.tag }]));
  const entryAt = makeSynthetic(seedText, plantedMap);
  const anchor = buildAnchor(entryAt, N);
  const trusted = { root: anchor.root, cTip: anchor.cTip, noteCount: N, leaf: anchor.leaf };
  const byPage = new Map();
  for (const pn of plantedNotes) { const ps = Math.floor(pn.position / 512) * 512; if (!byPage.has(ps)) byPage.set(ps, []); byPage.get(ps).push(pn); }
  const openReal = (pn) => {
    const env = pn.ciphertext; const ephPk = env.subarray(0, 32), nonce = env.subarray(40, 64), boxed = env.subarray(64);
    const opened = nacl.box.open.after(boxed, nonce, nacl.box.before(ephPk, account.encSk));
    if (!opened) return null; const p = JSON.parse(new TextDecoder().decode(opened)); return { v: BigInt(p.v), rho: p.rho, rcm: p.rcm };
  };
  const recognize = async (matchedPages) => {
    const notes = [];
    for (const ps of matchedPages) for (const pn of byPage.get(ps) ?? []) {
      const note = openReal(pn); if (!note) continue;
      if (wasmShim.note_commitment_hex(note.v, account.pk, note.rho, note.rcm) !== Buffer.from(pn.commitment).toString("hex")) continue;
      notes.push({ position: pn.position, v: note.v });
    }
    return notes;
  };
  const plantedByRange = (from, to) => plantedNotes.filter((pn) => pn.position >= from && pn.position < to).map((pn) => [pn.position, { ephPk: Array.from(pn.ephPk), tag: Array.from(pn.tag) }]);
  return { account, seedText, entryAt, anchor, trusted, recognize, plantPositions, plantedByRange };
}

const census = (r, plantPositions) =>
  r.rejected.length === 0 && r.notes.length === plantPositions.length && plantPositions.every((p) => r.notes.some((n) => n.position === p));

function report(rowName, out) {
  appendFileSync(RESULTS, JSON.stringify({ row: rowName, ...out }) + "\n");
  console.log(`ROW ${rowName}: ${JSON.stringify(out)}`);
  if (!out.zeroFN) { console.error(`FAIL ${rowName}: zero-FN census failed`); process.exit(1); }
}

async function realByteRun(N, extra = {}, label = row) {
  const c = corpus(N);
  const mirror = makeMirror(c.entryAt, N, { anchor: c.anchor });
  const t0 = process.hrtime.bigint();
  const r = await parallelScan({ mode: "native", workers: 4, mirror, trusted: c.trusted, encSk: c.account.encSk, from0: 0, eff: 0, total: N, recognize: c.recognize, ...extra });
  const wallSec = Number(process.hrtime.bigint() - t0) / 1e9;
  return { label, N, workers: 4, wallSec, notesPerSec: Math.round(N / wallSec), wireMB: +(N * ENTRY_LEN / 2 ** 20).toFixed(1), zeroFN: census(r, c.plantPositions), rejected: r.rejected.length, ...("paceMbps" in extra ? { paceMbps: extra.paceMbps, floorSec: +(N * ENTRY_LEN * 8 / (extra.paceMbps * 1e6)).toFixed(1) } : {}), ...("workerThrottleDuty" in extra ? { duty: extra.workerThrottleDuty } : {}) };
}

if (row === "baseline") {
  report(row, await realByteRun(1_000_000));
} else if (row === "shaped10") {
  report(row, await realByteRun(1_000_000, { paceMbps: 10 }));
} else if (row === "shaped50") {
  report(row, await realByteRun(1_000_000, { paceMbps: 50 }));
} else if (row === "throttle") {
  report(row, await realByteRun(1_000_000, { workerThrottleDuty: 0.25 }));
} else if (row === "cores4") {
  // pin THIS scan to 4 cores: re-exec under taskset, synthetic self-gen mode at 1e7
  // (workers generate their DPAGE-aligned segments; generation stands in for the network
  // download exactly as in the A-4 scale proof)
  const inner = spawnSync("taskset", ["-c", "0-3", process.execPath, fileURLToPath(import.meta.url), "cores4-inner"], { stdio: "inherit" });
  process.exit(inner.status ?? 1);
} else if (row === "cores4-inner") {
  const N = 10_000_000;
  const c = corpus(N);
  const t0 = process.hrtime.bigint();
  const r = await parallelScan({ mode: "native", workers: 4, mirror: { total: N, boundaryProof: (j) => c.anchor.proofFor(j) }, trusted: c.trusted, encSk: c.account.encSk, from0: 0, eff: 0, total: N, seedText: c.seedText, plantedByRange: c.plantedByRange, recognize: c.recognize });
  const wallSec = Number(process.hrtime.bigint() - t0) / 1e9;
  report("cores4", { N, workers: 4, cpuSet: "0-3", wallSec, notesPerSec: Math.round(N / wallSec), zeroFN: census(r, c.plantPositions), rejected: r.rejected.length });
} else if (row === "resume") {
  // parent: spawn the child scan, SIGKILL it mid-run, resume from its checkpoint file
  if (existsSync(CKPT)) unlinkSync(CKPT);
  const child = spawn(process.execPath, [fileURLToPath(import.meta.url), "resume-child"], { stdio: "inherit" });
  const KILL_AT_SEGS = 90; // ~37% of the 245 segments: a genuine mid-scan kill
  const killed = await new Promise((res) => {
    const timer = setInterval(() => {
      if (!existsSync(CKPT)) return;
      try {
        const snap = JSON.parse(readFileSync(CKPT, "utf8")); // atomic rename => never partial
        if (snap.doneSegs.length >= KILL_AT_SEGS) { clearInterval(timer); child.kill("SIGKILL"); res(true); }
      } catch { /* transient read race on rename; retry next tick */ }
    }, 20);
    child.on("exit", () => { clearInterval(timer); res(false); }); // finished before kill = row invalid
  });
  if (!killed) { console.error("FAIL resume: child finished before the kill — enlarge N"); process.exit(1); }
  const ckpt = JSON.parse(readFileSync(CKPT, "utf8"));
  console.log(`child SIGKILLed after checkpoint (${ckpt.doneSegs.length} segments durable); resuming...`);
  const N = 1_000_000;
  const c = corpus(N);
  const mirror = makeMirror(c.entryAt, N, { anchor: c.anchor });
  const t0 = process.hrtime.bigint();
  const r = await parallelScan({ mode: "native", workers: 4, mirror, trusted: c.trusted, encSk: c.account.encSk, from0: 0, eff: 0, total: N, recognize: c.recognize, checkpoint: ckpt });
  const wallSec = Number(process.hrtime.bigint() - t0) / 1e9;
  report("resume", { N, workers: 4, killedAfterSegs: ckpt.doneSegs.length, totalSegs: Math.ceil(N / DPAGE), resumeWallSec: +wallSec.toFixed(2), zeroFN: census(r, c.plantPositions), rejected: r.rejected.length });
} else if (row === "resume-child") {
  const N = 1_000_000;
  const c = corpus(N);
  const mirror = makeMirror(c.entryAt, N, { anchor: c.anchor });
  await parallelScan({ mode: "native", workers: 4, mirror, trusted: c.trusted, encSk: c.account.encSk, from0: 0, eff: 0, total: N, recognize: c.recognize, chunkSegments: 8,
    onCheckpoint: (ck) => { writeFileSync(CKPT + ".tmp", JSON.stringify(ck)); renameSync(CKPT + ".tmp", CKPT); } });
  process.exit(0);
} else {
  console.error(`unknown row: ${row}`);
  process.exit(1);
}
