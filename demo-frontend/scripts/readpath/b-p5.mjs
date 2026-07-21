// B-P5 — read-path privacy (keyless-observer transcript) (Menese DeFi Team).
//
// Two proofs (2 seeds):
//   A (keyless-observer / indistinguishable from paging): two wallets with DIFFERENT keys and
//     DIFFERENT owned sets, each running the shipped balance scan over the same ledger, produce
//     BYTE-IDENTICAL block-fetch request transcripts (same page ranges, same order) — so an
//     observer of the request log learns nothing about which notes are owned. And no scan issues
//     any is_nullifier_spent point query (which would leak ownership).
//   B (no position isolation): a tag-matching detection scan's block fetches are ALL 512-aligned
//     full pages — never a `[p, small]` position-targeted fetch that would isolate an owned note.
//     (The residual page-set leak of matched-page retrieval is closed by PIR; retrieveMatchedPage
//     is the seam. Documented in READ-PATH-SPEC.md.)

import "./setup-declarations.mjs";
import naclPkg from "tweetnacl";
import * as wallet from "../../src/wallet.js";
import { wasmShim, makeAccount } from "./shim.mjs";
import { buildCorpus } from "./corpus.mjs";

const nacl = naclPkg.default ?? naclPkg;
const results = [];
const record = (name, ok, detail) => (results.push({ name, ok, detail }), console.log(`${ok ? "PASS" : "FAIL"}  ${name}  ${detail}`));

// Canonical string of the block-fetch ranges in the request log (order preserved).
const blockFetchTranscript = (ledger) =>
  ledger.requestLog
    .filter((e) => e.method === "icrc3_get_blocks")
    .map((e) => e.ranges.map((r) => `${r.start}:${r.length}`).join("|"))
    .join(",");
const nfQueries = (ledger) => ledger.requestLog.filter((e) => e.method === "is_nullifier_spent").length;

for (const seed of [1, 2]) {
  const A = makeAccount(nacl, seed);
  const B = makeAccount(nacl, seed + 100);
  const accounts = [A, B, makeAccount(nacl, seed + 200)];
  const { ledger } = await buildCorpus(nacl, {
    seed, noteCount: 1500, accounts,
    sealFn: (pk, note, isNew) => wallet.sealNote(pk, note, { viewTag: isNew }),
    newFormatFrom: 700, spendEvery: 45,
  });
  const actors = { ledger: ledger.ledger, principal: null };

  // ---- Proof A: two different-key wallets, identical block-fetch transcripts ----
  ledger.resetLog();
  await wallet.scanNotes(actors, wasmShim, A); // full balance scan
  const tA = blockFetchTranscript(ledger);
  const nfA = nfQueries(ledger);

  ledger.resetLog();
  await wallet.scanNotes(actors, wasmShim, B);
  const tB = blockFetchTranscript(ledger);
  const nfB = nfQueries(ledger);

  record(`B-P5/seed${seed} proofA(keyless-observer)`,
    tA === tB && tA.length > 0 && nfA === 0 && nfB === 0,
    `transcripts_equal=${tA === tB} pages=${tA.split(",").length} nfQueries=${nfA}/${nfB}`);

  // ---- Proof B: detection scan fetches never isolate a position ----
  ledger.resetLog();
  await wallet.detectionScan(actors, wasmShim, A, { cutover: 700 });
  const isolating = ledger.positionIsolatingFetches();
  const allPageAligned = ledger.requestLog
    .filter((e) => e.method === "icrc3_get_blocks")
    .every((e) => e.ranges.length === 1 && e.ranges[0].start % 512 === 0 && e.ranges[0].length <= 512);
  record(`B-P5/seed${seed} proofB(no-position-isolation)`,
    isolating.length === 0 && allPageAligned && nfQueries(ledger) === 0,
    `isolating_fetches=${isolating.length} all_page_aligned=${allPageAligned}`);
}

const failed = results.filter((r) => !r.ok);
console.log(`\nB-P5: ${results.length - failed.length}/${results.length} checks passed`);
if (failed.length) process.exit(1);
