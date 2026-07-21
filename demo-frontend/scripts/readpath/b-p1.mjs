// B-P1 — pagination + incremental cursor (Menese DeFi Team).
//
// Red baseline (reproduces the live bug on the corpus, independent of shipped code): the OLD single-call
// `icrc3_get_blocks([{0,total}])` fetch pattern truncates at 512, so a genesis scan built on it
// MISSES every owned note past block 512.
//   Proof A (set diff): legacy-scan owned-set ⊊ genesis oracle; every missed note is at pos ≥ 512.
//   Proof B (page accounting): the legacy call returns exactly 512 blocks though log_length > 512.
// FIX (the shipped wallet.js): paginated scanNotes == genesis oracle (set-equal); the spend-path
// leaf set is complete (indexOf past 512 resolves); every fetch is a single range ≤ 512 (a
// multi-range single call would re-trigger the total cap).
//   Two proofs: note-set differential + single-range/page-accounting over the request log.

import assert from "node:assert/strict";
import "./setup-declarations.mjs";
import naclPkg from "tweetnacl";
import * as wallet from "../../src/wallet.js";
import { hexToBytes, bytesToHex } from "../../src/ic.js";
import { wasmShim, makeAccount } from "./shim.mjs";
import { buildCorpus, genesisScanOracle } from "./corpus.mjs";
import { MAX_BLOCKS_PER_CALL } from "./mock-ledger.mjs";

const nacl = naclPkg.default ?? naclPkg;
const NOTE_COUNT = 1300; // > 2 pages, forces truncation past 512
const results = [];
const record = (name, ok, detail) => {
  results.push({ name, ok, detail });
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}  ${detail}`);
};

// The OLD truncating fetch+scan, reconstructed inline so the red baseline does not depend on shipped code.
async function legacyTruncatingScan(ledger, account) {
  const total = Number((await ledger.ledger.status()).log_length);
  const res = await ledger.ledger.icrc3_get_blocks([{ start: 0n, length: BigInt(total) }]);
  const spent = new Set();
  const recs = res.blocks.map(({ block }) => {
    const map = Object.fromEntries(block.Map);
    const nulls = (map.nullifiers?.Array || []).map((v) => bytesToHex(new Uint8Array(v.Blob)));
    for (const n of nulls) spent.add(n);
    return {
      position: Number(map.note_position.Nat),
      commitment: bytesToHex(new Uint8Array(map.commitment.Blob)),
      ciphertext: bytesToHex(new Uint8Array(map.note_ciphertext.Blob)),
    };
  });
  const found = new Set();
  for (const rec of recs) {
    const note = wallet.openEnvelope(account.encSk, hexToBytes(rec.ciphertext));
    if (!note) continue;
    if (wasmShim.note_commitment_hex(note.v, account.pk, note.rho, note.rcm) !== rec.commitment) continue;
    if (spent.has(wasmShim.note_nullifier_hex(account.nk, note.rho))) continue;
    found.add(`${rec.position}:${note.v}`);
  }
  return { found, scanned: res.blocks.length };
}

for (const seed of [1, 2]) {
  const accounts = [makeAccount(nacl, seed), makeAccount(nacl, seed + 100)];
  const { ledger } = await buildCorpus(nacl, {
    seed,
    noteCount: NOTE_COUNT,
    accounts,
    sealFn: (pk, note) => wallet.sealNote(pk, note, { viewTag: false }),
    spendEvery: 37,
  });
  const account = accounts[0];
  const actors = { ledger: ledger.ledger, principal: null };
  const oracle = genesisScanOracle(ledger, account, wallet.openEnvelope);
  assert.ok(oracle.notes.length > 0 && oracle.notes.some((n) => n.position >= MAX_BLOCKS_PER_CALL),
    "corpus does not exercise truncation");

  // ---- red baseline ----
  ledger.resetLog();
  const legacy = await legacyTruncatingScan(ledger, account);
  const missed = [...oracle.set].filter((k) => !legacy.found.has(k));
  const missedPos = missed.map((k) => Number(k.split(":")[0]));
  record(
    `B-P1 red/seed${seed} proofA(set-diff)`,
    missed.length > 0 && missedPos.every((p) => p >= MAX_BLOCKS_PER_CALL),
    `oracle=${oracle.set.size} legacyFound=${legacy.found.size} missed=${missed.length} minMissedPos=${Math.min(...missedPos)}`
  );
  record(
    `B-P1 red/seed${seed} proofB(page-acct)`,
    legacy.scanned === MAX_BLOCKS_PER_CALL,
    `legacy_scanned=${legacy.scanned} log_length=${NOTE_COUNT}`
  );

  // ---- FIX: paginated scanNotes ----
  ledger.resetLog();
  const fix = await wallet.scanNotes(actors, wasmShim, account); // full scan from genesis
  const fixFound = new Set(fix.notes.map((n) => `${n.position}:${n.v}`));
  const setEqual = fixFound.size === oracle.set.size && [...oracle.set].every((k) => fixFound.has(k));
  record(`B-P1 fix/seed${seed} proofA(set-equal)`, setEqual,
    `oracle=${oracle.set.size} fixFound=${fixFound.size} cursor=${fix.cursor}`);

  // spend-path completeness: every owned unspent commitment resolves via leavesInOrder past 512.
  const leaves = await wallet.leavesInOrder(actors);
  const allResolve = fix.notes.every((n) => leaves.indexOf(n.cm) >= 0);
  record(`B-P1 fix/seed${seed} proofB(spend-path)`, allResolve && leaves.length === NOTE_COUNT,
    `leaves=${leaves.length} allResolve=${allResolve}`);

  // every fetch is a single range ≤ 512, and NO is_nullifier_spent point-query (D9 privacy).
  const badFetch = ledger.requestLog.filter(
    (e) => e.method === "icrc3_get_blocks" && !(e.ranges.length === 1 && e.ranges[0].length <= MAX_BLOCKS_PER_CALL)
  );
  const nfQueries = ledger.requestLog.filter((e) => e.method === "is_nullifier_spent").length;
  record(`B-P1 fix/seed${seed} proofC(single-range+no-nf-query)`, badFetch.length === 0 && nfQueries === 0,
    `bad_fetches=${badFetch.length} nf_queries=${nfQueries}`);
}

const failed = results.filter((r) => !r.ok);
console.log(`\nB-P1: ${results.length - failed.length}/${results.length} checks passed`);
if (failed.length) process.exit(1);
