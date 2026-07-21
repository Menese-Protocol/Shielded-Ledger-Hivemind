// B-P2 — wallet birthday (Menese DeFi Team).
//
// A note created before the wallet existed cannot be its own, so a birthday wallet scans
// [birthday, tip]. Two proofs (2 seeds):
//   Proof A (note-set differential): the birthday scan finds EXACTLY the account's owned-unspent
//     set (identical to the genesis oracle), AND a birthday-less restore (birthday 0) finds the
//     same set.
//   Proof B (instrumented fetch log): the birthday scan issues ZERO fetches below the birthday's
//     page — no pre-birthday history is re-downloaded.

import assert from "node:assert/strict";
import "./setup-declarations.mjs";
import naclPkg from "tweetnacl";
import * as wallet from "../../src/wallet.js";
import { wasmShim, makeAccount } from "./shim.mjs";
import { buildCorpus, genesisScanOracle } from "./corpus.mjs";
import { MAX_BLOCKS_PER_CALL } from "./mock-ledger.mjs";

const nacl = naclPkg.default ?? naclPkg;
const NOTE_COUNT = 1600;
const results = [];
const record = (name, ok, detail) => (results.push({ name, ok, detail }), console.log(`${ok ? "PASS" : "FAIL"}  ${name}  ${detail}`));
const eqSet = (a, b) => a.size === b.size && [...a].every((k) => b.has(k));

for (const seed of [1, 2]) {
  const BIRTH = 640; // account 0's wallet birthday (mid-log, spans a page boundary at 512)
  const accounts = [makeAccount(nacl, seed), makeAccount(nacl, seed + 100)];
  const { ledger } = await buildCorpus(nacl, {
    seed,
    noteCount: NOTE_COUNT,
    accounts,
    sealFn: (pk, note) => wallet.sealNote(pk, note, { viewTag: false }),
    spendEvery: 41,
    births: [BIRTH, 0],
  });
  const account = accounts[0];
  const actors = { ledger: ledger.ledger, principal: null };
  const oracle = genesisScanOracle(ledger, account, wallet.openEnvelope);
  assert.ok(oracle.notes.every((n) => n.position >= BIRTH), "corpus bug: owned note before birthday");
  assert.ok(oracle.notes.length > 0, "corpus bug: account owns nothing");

  // ---- birthday scan ----
  ledger.resetLog();
  const bday = await wallet.scanNotes(actors, wasmShim, account, { birthday: BIRTH });
  const bdaySet = new Set(bday.notes.map((n) => `${n.position}:${n.v}`));
  record(`B-P2/seed${seed} proofA(birthday-set-equal)`, eqSet(bdaySet, oracle.set),
    `oracle=${oracle.set.size} birthdayFound=${bdaySet.size}`);

  const birthdayPage = Math.floor(BIRTH / MAX_BLOCKS_PER_CALL) * MAX_BLOCKS_PER_CALL;
  const below = ledger.fetchesBelow(birthdayPage);
  record(`B-P2/seed${seed} proofB(no-fetch-below-birthday)`, below.length === 0,
    `birthdayPage=${birthdayPage} fetches_below=${below.length}`);

  // ---- birthday-less restore ----
  ledger.resetLog();
  const full = await wallet.scanNotes(actors, wasmShim, account, { birthday: 0 });
  const fullSet = new Set(full.notes.map((n) => `${n.position}:${n.v}`));
  record(`B-P2/seed${seed} proofA(birthdayless-set-equal)`, eqSet(fullSet, oracle.set),
    `oracle=${oracle.set.size} restoreFound=${fullSet.size}`);
}

const failed = results.filter((r) => !r.ok);
console.log(`\nB-P2: ${results.length - failed.length}/${results.length} checks passed`);
if (failed.length) process.exit(1);
