// B-RESTORE-CORRECTNESS — A-3 zero-false-negative gate (Menese DeFi Team).
//
// On a MIXED-format corpus with owned notes planted at ADVERSARIAL positions (first, last,
// page-boundary-straddling, dense cluster, inside the legacy-below-cutover region, and across a
// DPAGE segment boundary), for 2 seeds: the PARALLEL scanner's owned-note set is BYTE-IDENTICAL
// (canonical position-sorted) to (1) the sequential reference `wallet.detectionScan` and (2) an
// independent genesis-walk oracle; the NATIVE and REFERENCE kernels agree tag-for-tag; and resume
// (two-halves via checkpoint) yields the identical set. RED teeth: a dropped-tail injection MUST
// miss the last planted note (proves the census check catches a miss). Zero FN is absolute.
import assert from "node:assert/strict";
import "../readpath/setup-declarations.mjs";
import naclPkg from "tweetnacl";
import * as wallet from "../../src/wallet.js";
import { hexToBytes } from "../../src/ic.js";
import { wasmShim, makeAccount } from "../readpath/shim.mjs";
import { MockLedger } from "../readpath/mock-ledger.mjs";
import { genesisScanOracle } from "../readpath/corpus.mjs";
import { posBE8, DPAGE } from "./detect-chain.mjs";
import { buildAnchor, makeMirror } from "./mirror.mjs";
import { parallelScan } from "./parallel-scan.mjs";

const nacl = naclPkg.default ?? naclPkg;
const results = [];
const record = (name, ok, detail) => (results.push({ name, ok }), console.log(`${ok ? "PASS" : "FAIL"}  ${name}  ${detail}`));
const canon = (notes) => [...notes].map((n) => `${n.position}:${n.v}:${n.cm}`).sort().join("|");
const setPos = (notes) => new Set(notes.map((n) => n.position));

const TOTAL = 3 * DPAGE + 517;         // 3 complete segments + partial tip (real Merkle paths)
const CUTOVER = 512;                   // legacy below, tagged at/above

async function buildRestoreCorpus(seed) {
  const account = makeAccount(nacl, seed);
  const other = makeAccount(nacl, seed + 50);
  const ledger = new MockLedger();
  // adversarial owned positions for `account`
  const ownedPos = new Set([0, 100, 511, 512, 600, 601, 602, 603, 604, 4095, 4096, 8000, TOTAL - 1]);
  let st = (seed * 2654435761) >>> 0;
  const rnd = () => ((st = (st * 1103515245 + 12345) >>> 0), st / 0xffffffff);
  const planted = [];
  for (let position = 0; position < TOTAL; position++) {
    const isNew = position >= CUTOVER;
    const v = BigInt(1 + Math.floor(rnd() * 1_000_000));
    const rho = wasmShim.random_field(), rcm = wasmShim.random_field();
    let owner = null, recipientEncPk;
    if (ownedPos.has(position)) { owner = account; recipientEncPk = account.encPk; }
    else if (rnd() < 0.5) { owner = other; recipientEncPk = other.encPk; }     // noise-for-account
    else { recipientEncPk = nacl.box.keyPair().publicKey; }                     // pure noise
    const commitment = Buffer.from(wasmShim.note_commitment_hex(v, owner ? owner.pk : "noise", rho, rcm), "hex");
    const ciphertext = wallet.sealNote(recipientEncPk, { v, rho, rcm }, { viewTag: isNew });
    await ledger.append({ commitment: new Uint8Array(commitment), origin: "shield", ephemeralKey: new Uint8Array(32), ciphertext, nullifiers: [] });
    if (owner === account) planted.push({ position, v });
  }
  return { account, ledger, planted, ownedPos };
}

for (const seed of [1, 2]) {
  const { account, ledger, planted } = await buildRestoreCorpus(seed);
  const actors = { ledger: ledger.ledger, principal: null };
  // trusted certified anchor + untrusted mirror over the true detection bytes
  const entryAt = (i) => { const e = new Uint8Array(48); e.set(posBE8(i), 0); const ct = ledger.records[i].ciphertext; for (let j = 0; j < 40; j++) e[8 + j] = ct[j] ?? 0; return e; };
  const anchor = buildAnchor(entryAt, TOTAL);
  const trusted = { root: anchor.root, cTip: anchor.cTip, noteCount: TOTAL };
  const mirror = makeMirror(entryAt, TOTAL, { anchor });

  // recognition over matched pages (trusted canister retrieval + open + commitment proof)
  const recognize = async (matchedPages) => {
    const notes = [];
    for (const ps of matchedPages) {
      const page = await wallet.retrieveMatchedPage(actors, ps, Math.min(ps + 512, TOTAL));
      for (const rec of page) {
        const note = wallet.openEnvelope(account.encSk, hexToBytes(rec.ciphertext));
        if (!note) continue;
        const cm = wasmShim.note_commitment_hex(note.v, account.pk, note.rho, note.rcm);
        if (cm !== rec.commitment) continue;
        notes.push({ ...note, cm, position: rec.position });
      }
    }
    return notes;
  };

  // references
  ledger.resetLog();
  const seq = await wallet.detectionScan(actors, wasmShim, account, { cutover: CUTOVER });
  const oracle = genesisScanOracle(ledger, account, wallet.openEnvelope);

  const common = { mirror, trusted, encSk: account.encSk, from0: 0, eff: CUTOVER, total: TOTAL, recognize };
  const par = await parallelScan({ mode: "reference", workers: 4, ...common });
  const parNative = await parallelScan({ mode: "native", workers: 4, ...common });

  // Proof 1: parallel (reference kernel) owned set == sequential reference (canonical)
  record(`correctness/seed${seed} proof1(parallel==sequential)`, canon(par.notes) === canon(seq.notes),
    `seq=${seq.notes.length} par=${par.notes.length} rejected=${par.rejected.length}`);
  // Proof 2: planted census — every planted note present, exact count, zero extras/dups
  const pset = setPos(par.notes);
  const allPlanted = planted.every((p) => pset.has(p.position));
  const noExtra = par.notes.length === planted.length && pset.size === planted.length;
  record(`correctness/seed${seed} proof2(planted-census)`, allPlanted && noExtra,
    `planted=${planted.length} recognized=${par.notes.length} allPresent=${allPlanted} noExtra=${noExtra}`);
  // Proof 3: native kernel == reference kernel (client-side differential AC-DIFF)
  record(`correctness/seed${seed} proof3(native==reference)`, canon(parNative.notes) === canon(par.notes),
    `ref=${par.notes.length} native=${parNative.notes.length}`);
  // Proof 4: parallel == independent oracle recognized set
  const oracleSet = oracle.recognizedSet, parRecog = new Set(par.notes.map((n) => `${n.position}:${n.v}`));
  const eqOracle = oracleSet.size === parRecog.size && [...oracleSet].every((k) => parRecog.has(k));
  record(`correctness/seed${seed} proof4(parallel==oracle)`, eqOracle, `oracle=${oracleSet.size} parallel=${parRecog.size}`);
  // Proof 5: resume == single-shot. Interrupt after a checkpoint that covers the first few
  // segments, then resume from that checkpoint (same total) — must reproduce the one-shot set.
  let ckpt = null;
  const stopAfter = 2; // capture the checkpoint once >=2 segments are done, then "crash"
  await parallelScan({ mode: "native", workers: 4, ...common, chunkSegments: 1, onCheckpoint: (c) => { if (c.doneSegs.length >= stopAfter && !ckpt) ckpt = c; } });
  const resumed = await parallelScan({ mode: "native", workers: 4, ...common, checkpoint: ckpt });
  record(`correctness/seed${seed} proof5(resume==oneshot)`, ckpt != null && canon(resumed.notes) === canon(parNative.notes),
    `resumed=${resumed.notes.length} oneshot=${parNative.notes.length} ckptSegs=${ckpt?.doneSegs.length}`);
  // RED teeth: dropped-tail injection MUST miss the last planted note (proves census has teeth)
  const injured = await parallelScan({ mode: "native", workers: 4, ...common, injectDropTail: true });
  const missedLast = !setPos(injured.notes).has(TOTAL - 1) && setPos(par.notes).has(TOTAL - 1);
  record(`correctness/seed${seed} redTeeth(inject-drop-tail-misses-last)`, missedLast,
    `injured_has_last=${setPos(injured.notes).has(TOTAL - 1)} real_has_last=${setPos(par.notes).has(TOTAL - 1)}`);
}

const failed = results.filter((r) => !r.ok);
console.log(`\nB-RESTORE-CORRECTNESS: ${results.length - failed.length}/${results.length} checks passed`);
if (failed.length) process.exit(1);
