// A-4 scale proof — ONE clean measurement of a birthday-less restore at N notes with W workers
// (Menese DeFi Team). Run one (N,W) per process (fresh heap, no cross-run contamination); a shell
// loop drives the 1/2/4/8 table and the tiers. Workers self-generate their DPAGE-aligned synthetic
// segments (no 4.8 GB on disk — generation stands in for the network download), VERIFY each chunk
// against the trusted certified detect_stream root (chain recompute + Merkle boundary proofs), then
// scan (native ECDH). Real owned notes planted at first/middle/last are recognized end-to-end; the
// owned set must equal the planted set exactly (zero FN at scale). Peak RSS sampled cheaply at
// chunk-completion callbacks (never a tight timer, which would contend the dispatch thread).
//
// Usage: node scale-run.mjs <N> <W> [chunkSegments]
import "../readpath/setup-declarations.mjs";
import naclPkg from "tweetnacl";
import { appendFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { wasmShim, makeAccount } from "../readpath/shim.mjs";
import { ENTRY_LEN } from "./detect-chain.mjs";
import { makeSynthetic, plantOwned, buildAnchor, makeMirror } from "./mirror.mjs";
import { parallelScan } from "./parallel-scan.mjs";

const nacl = naclPkg.default ?? naclPkg;
const N = Number(process.argv[2] ?? 1_000_000);
const W = Number(process.argv[3] ?? 8);
const chunkSegments = process.argv[4] ? Number(process.argv[4]) : undefined;
const here = dirname(fileURLToPath(import.meta.url));
const account = makeAccount(nacl, 7);
const seedText = `scale/${N}`;

const plantPositions = [0, Math.floor(N / 2), N - 1];
const plantedNotes = plantPositions.map((p, i) => plantOwned(account, wasmShim, p, 20 + i));
const plantedMap = new Map(plantedNotes.map((pn) => [pn.position, { ephPk: pn.ephPk, tag: pn.tag }]));
const entryAt = makeSynthetic(seedText, plantedMap);
const plantedByRange = (from, to) => plantedNotes.filter((pn) => pn.position >= from && pn.position < to).map((pn) => [pn.position, { ephPk: Array.from(pn.ephPk), tag: Array.from(pn.tag) }]);

const ab0 = process.hrtime.bigint();
const anchor = buildAnchor(entryAt, N);                       // canister-side incremental chain (measured separately)
const anchorBuildSec = Number(process.hrtime.bigint() - ab0) / 1e9;
const trusted = { root: anchor.root, cTip: anchor.cTip, noteCount: N };
const mirror = makeMirror(entryAt, N, { anchor });

const byPage = new Map();
for (const pn of plantedNotes) { const ps = Math.floor(pn.position / 512) * 512; if (!byPage.has(ps)) byPage.set(ps, []); byPage.get(ps).push(pn); }
function openReal(pn) {
  const env = pn.ciphertext; const ephPk = env.subarray(0, 32), nonce = env.subarray(40, 64), boxed = env.subarray(64);
  const opened = nacl.box.open.after(boxed, nonce, nacl.box.before(ephPk, account.encSk));
  if (!opened) return null; const p = JSON.parse(new TextDecoder().decode(opened)); return { v: BigInt(p.v), rho: p.rho, rcm: p.rcm };
}
const recognize = async (matchedPages) => {
  const notes = [];
  for (const ps of matchedPages) for (const pn of byPage.get(ps) ?? []) {
    const note = openReal(pn); if (!note) continue;
    if (wasmShim.note_commitment_hex(note.v, account.pk, note.rho, note.rcm) !== Buffer.from(pn.commitment).toString("hex")) continue;
    notes.push({ position: pn.position, v: note.v });
  }
  return notes;
};

let peakRss = process.memoryUsage().rss;
const t0 = process.hrtime.bigint();
const r = await parallelScan({ mode: "native", workers: W, mirror, trusted, encSk: account.encSk, from0: 0, eff: 0, total: N, seedText, plantedByRange, recognize, chunkSegments,
  onCheckpoint: () => { const rss = process.memoryUsage().rss; if (rss > peakRss) peakRss = rss; } });
const wallSec = Number(process.hrtime.bigint() - t0) / 1e9;
const ownedOk = r.rejected.length === 0 && plantPositions.every((p) => new Set(r.notes.map((n) => n.position)).has(p)) && r.notes.length === plantPositions.length;
const peakMB = peakRss / 2 ** 20;
const out = { N, W, chunkSegments: chunkSegments ?? null, wallSec, notesPerSec: N / wallSec, ownedOk, rejected: r.rejected.length, chunks: r.chunks, anchorBuildSec, peakMB, wireGB: N * ENTRY_LEN / 2 ** 30 };
console.log(`N=${N.toExponential(0)} W=${W}  ${wallSec.toFixed(2)}s  ${(N / wallSec).toFixed(0)} notes/s  zeroFN=${ownedOk}  peakRSS=${peakMB.toFixed(0)}MB  chunks=${r.chunks}  wire=${out.wireGB.toFixed(2)}GB  anchorBuild=${anchorBuildSec.toFixed(1)}s`);
appendFileSync(resolve(here, "scale-results.jsonl"), JSON.stringify(out) + "\n");
