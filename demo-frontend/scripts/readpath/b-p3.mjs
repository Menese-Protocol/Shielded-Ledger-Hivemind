// B-P3 — view tags + compact detection stream (Menese DeFi Team).
//
// On a MIXED old/new-format log (old-format [0,C), new-format [C,N)), 2 seeds:
//   Proof A (recognition differential): detectionScan with cutover=C recognizes EXACTLY the owned
//     set a full trial-decrypt finds (old notes full-opened below C, new notes tag-detected at/above
//     C). The safe default (cutover=null ⇒ full-open all) also recognizes exactly that set. And a
//     cutover set TOO LOW silently MISSES old-format notes above it — the failure mode that makes
//     the safe default mandatory (D2′).
//   Proof B (wire bytes + measured instruction bound): detection_stream is ≤ 48 B/note on the wire
//     (mock re-measured here; PocketIC ReadPathProbe measured 48.00 B/note, 12.2× bandwidth win,
//     417,869 instr/note ⇒ a 512-note call is 23.4× under the 5×10⁹ query budget, ≥4× headroom).

import assert from "node:assert/strict";
import "./setup-declarations.mjs";
import naclPkg from "tweetnacl";
import * as wallet from "../../src/wallet.js";
import { wasmShim, makeAccount } from "./shim.mjs";
import { buildCorpus, genesisScanOracle } from "./corpus.mjs";
import { MAX_BLOCKS_PER_CALL } from "./mock-ledger.mjs";

const nacl = naclPkg.default ?? naclPkg;
const NOTE_COUNT = 1400;
const CUTOVER = 700; // old-format below, new-format at/above
const results = [];
const record = (name, ok, detail) => (results.push({ name, ok, detail }), console.log(`${ok ? "PASS" : "FAIL"}  ${name}  ${detail}`));
const eqSet = (a, b) => a.size === b.size && [...a].every((k) => b.has(k));
const setOf = (notes) => new Set(notes.map((n) => `${n.position}:${n.v}`));

for (const seed of [1, 2]) {
  const accounts = [makeAccount(nacl, seed), makeAccount(nacl, seed + 100)];
  const { ledger } = await buildCorpus(nacl, {
    seed,
    noteCount: NOTE_COUNT,
    accounts,
    sealFn: (pk, note, isNew) => wallet.sealNote(pk, note, { viewTag: isNew }),
    newFormatFrom: CUTOVER,
    spendEvery: 43,
  });
  const account = accounts[0];
  const actors = { ledger: ledger.ledger, principal: null };
  const oracle = genesisScanOracle(ledger, account, wallet.openEnvelope);
  // corpus really is mixed and owns notes in both regions
  assert.ok(oracle.recognized.some((n) => n.position < CUTOVER) && oracle.recognized.some((n) => n.position >= CUTOVER),
    "corpus bug: not mixed-format ownership");

  // Proof A: correct cutover recognition == full trial-decrypt recognized set
  ledger.resetLog();
  const det = await wallet.detectionScan(actors, wasmShim, account, { cutover: CUTOVER });
  record(`B-P3/seed${seed} proofA(recognition-cutover)`, eqSet(setOf(det.notes), oracle.recognizedSet),
    `oracle=${oracle.recognizedSet.size} detected=${det.notes.length}`);
  // fetches are page-aligned (no position isolation) — feeds B-P5
  const isolating = ledger.positionIsolatingFetches();
  record(`B-P3/seed${seed} proofA(page-aligned)`, isolating.length === 0, `isolating_fetches=${isolating.length}`);

  // safe default (cutover=null): full-open everything, still exactly the owned set
  const detSafe = await wallet.detectionScan(actors, wasmShim, account, { cutover: null });
  record(`B-P3/seed${seed} proofA(safe-default)`, eqSet(setOf(detSafe.notes), oracle.recognizedSet),
    `oracle=${oracle.recognizedSet.size} detected=${detSafe.notes.length}`);

  // Failure mode (why the safe default is mandatory, D2′): on an ALL-OLD-format log, a cutover set
  // below the tip makes the region above it "tag-trusted" — but old notes carry no tag, so
  // match-free pages there are never opened → owned notes silently MISSED. The safe default
  // (cutover=null ⇒ full-open) finds them all.
  const allOld = await buildCorpus(nacl, {
    seed: seed + 500,
    noteCount: 1100,
    accounts,
    sealFn: (pk, note) => wallet.sealNote(pk, note, { viewTag: false }), // all legacy
    spendEvery: 0,
  });
  const aoActors = { ledger: allOld.ledger.ledger, principal: null };
  const aoOracle = genesisScanOracle(allOld.ledger, account, wallet.openEnvelope);
  const aoLow = await wallet.detectionScan(aoActors, wasmShim, account, { cutover: 512 });
  const aoSafe = await wallet.detectionScan(aoActors, wasmShim, account, { cutover: null });
  const lowMissed = [...aoOracle.recognizedSet].filter((k) => !setOf(aoLow.notes).has(k));
  const lowMissedAbove = lowMissed.map((k) => Number(k.split(":")[0])).filter((p) => p >= 512);
  record(`B-P3/seed${seed} proofA(too-low-misses+safe-recovers)`,
    lowMissedAbove.length > 0 && eqSet(setOf(aoSafe.notes), aoOracle.recognizedSet),
    `too-low missed above 512=${lowMissedAbove.length}, safe-default found=${aoSafe.notes.length}/${aoOracle.recognizedSet.size}`);

  // Proof B: detection_stream wire bytes/note (mock, faithful to Main.mo) ≤ 48
  const s = 512;
  const packed = await ledger.ledger.detection_stream(BigInt(s), BigInt(MAX_BLOCKS_PER_CALL));
  const perNote = packed.length / MAX_BLOCKS_PER_CALL;
  // faithfulness: entry ephPk||tag == note_ciphertext[0..40]
  const rec0 = ledger.records[s];
  const ephTagOk = [...packed.slice(8, 48)].every((b, i) => b === rec0.ciphertext[i]);
  record(`B-P3/seed${seed} proofB(wire<=48+faithful)`, perNote <= 48 && ephTagOk,
    `bytes/note=${perNote} faithful=${ephTagOk} (PocketIC probe: 48.00 B/note, 23.4x headroom)`);
}

const failed = results.filter((r) => !r.ok);
console.log(`\nB-P3: ${results.length - failed.length}/${results.length} checks passed`);
if (failed.length) process.exit(1);
