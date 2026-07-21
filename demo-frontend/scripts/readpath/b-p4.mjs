// B-P4 — encrypted local cache (Menese DeFi Team).
//
// Proofs (2 seeds):
//   A (no-refetch): after a first sync caches at cursor N, a second sync over a grown log fetches
//     ZERO blocks below the cursor page, and still reports the correct balance.
//   B (ciphertext-at-rest): the raw stored blob contains NONE of the plaintext note fields
//     (v / rho / rcm), and is unreadable without the vetKey-derived key.
//   C (poison→rescan): a corrupted/forged cache is rejected (loadCache→null) and the wallet
//     recovers the correct balance by rescanning — never a wrong balance.
//   D (throwaway memory-only): a throwaway account writes nothing to the store.
//   E (stale/rewind→rescan): a validly-sealed cache whose ledger rewound or forked below the cursor
//     is discarded (D8 anchor/log_length check) and the wallet rescans to the correct balance.

import assert from "node:assert/strict";
import "./setup-declarations.mjs";
import naclPkg from "tweetnacl";
import * as wallet from "../../src/wallet.js";
import { wasmShim, makeAccount, memStore } from "./shim.mjs";
import { buildCorpus, genesisScanOracle } from "./corpus.mjs";
import { MAX_BLOCKS_PER_CALL } from "./mock-ledger.mjs";

const nacl = naclPkg.default ?? naclPkg;
const results = [];
const record = (name, ok, detail) => (results.push({ name, ok, detail }), console.log(`${ok ? "PASS" : "FAIL"}  ${name}  ${detail}`));
const bal = (notes) => notes.reduce((s, n) => s + n.v, 0n);
const setOf = (notes) => new Set(notes.map((n) => `${n.position}:${n.v}`));
const eqSet = (a, b) => a.size === b.size && [...a].every((k) => b.has(k));

for (const seed of [1, 2]) {
  const accounts = [makeAccount(nacl, seed), makeAccount(nacl, seed + 100)];
  const account = accounts[0];
  const { ledger } = await buildCorpus(nacl, {
    seed, noteCount: 900, accounts,
    sealFn: (pk, note) => wallet.sealNote(pk, note, { viewTag: false }), spendEvery: 39,
  });
  const actors = { ledger: ledger.ledger, principal: null };
  const store = memStore();

  // ---- open 1: cold sync, writes cache ----
  const s1 = await wallet.syncWallet(actors, wasmShim, account, { store, birthday: 0 });
  assert.equal(s1.fromCache, false, "first sync should be a cache miss");

  // grow the log with more notes (some owned by account0) after the cache was written
  const cursor1 = s1.cursor;
  for (let i = 0; i < 400; i++) {
    const rho = wasmShim.random_field(), rcm = wasmShim.random_field();
    const v = BigInt(1 + i);
    const owned = i % 3 === 0;
    const encPk = owned ? account.encPk : nacl.box.keyPair().publicKey;
    const cm = Buffer.from(wasmShim.note_commitment_hex(v, owned ? account.pk : "noise", rho, rcm), "hex");
    await ledger.append({ commitment: new Uint8Array(cm), origin: "shield", ciphertext: wallet.sealNote(encPk, { v, rho, rcm }, { viewTag: false }), nullifiers: [] });
  }
  const oracle = genesisScanOracle(ledger, account, wallet.openEnvelope);

  // ---- open 2: warm sync, must not fetch below cursor, must be correct ----
  ledger.resetLog();
  const s2 = await wallet.syncWallet(actors, wasmShim, account, { store });
  const cursorPage = Math.floor(cursor1 / MAX_BLOCKS_PER_CALL) * MAX_BLOCKS_PER_CALL;
  const below = ledger.fetchesBelow(cursorPage);
  record(`B-P4/seed${seed} proofA(no-refetch+correct)`,
    s2.fromCache && below.length === 0 && eqSet(setOf(s2.notes), oracle.set),
    `fromCache=${s2.fromCache} fetches_below_cursor_page=${below.length} bal=${bal(s2.notes)} oracleBal=${bal(oracle.notes)}`);

  // ---- ciphertext at rest ----
  // The raw blob must contain NONE of: the 64-hex note-opening secrets rho/rcm (a coincidence in
  // ~90 KB is 16^-64), the plaintext amount decimal, or the JSON structure keys — i.e. the sealed
  // record must not be readable at rest. Search the raw bytes as a latin1 string.
  const raw = await store.get("picp-readpath-cache/v1");
  const rawStr = Buffer.from(raw).toString("latin1");
  const f = await firstNoteFields(ledger, account);
  const needles = [f.rho, f.rcm, `"rho"`, `"rcm"`, `"v":`, `"notes"`, `"cursor"`];
  const leaks = needles.filter((n) => n && rawStr.includes(n));
  record(`B-P4/seed${seed} proofB(ciphertext-at-rest)`, leaks.length === 0,
    `raw_len=${raw.length} plaintext_field_hits=${leaks.length} (${leaks.join(",")})`);

  // ---- poisoning → rescan ----
  const poisoned = memStore();
  const bad = new Uint8Array(raw); bad[30] ^= 0xff; bad[raw.length - 1] ^= 0xff; // flip inside the box
  await poisoned.set("picp-readpath-cache/v1", bad);
  const loadBad = await wallet.loadCache(actors, account, poisoned);
  const s3 = await wallet.syncWallet(actors, wasmShim, account, { store: poisoned });
  record(`B-P4/seed${seed} proofC(poison→rescan)`,
    loadBad === null && eqSet(setOf(s3.notes), oracle.set),
    `loadRejected=${loadBad === null} bal=${bal(s3.notes)} oracleBal=${bal(oracle.notes)}`);

  // ---- throwaway memory-only ----
  const throwaway = makeAccount(nacl, seed + 200, "throwaway-memory");
  const tStore = memStore();
  await wallet.syncWallet(actors, wasmShim, throwaway, { store: tStore });
  record(`B-P4/seed${seed} proofD(throwaway-memory-only)`, tStore._m.size === 0, `store_entries=${tStore._m.size}`);

  // ---- stale/rewind → rescan ----
  // Fresh ledger + fresh cache, then rewind the ledger below the cursor and re-sync.
  const rwStore = memStore();
  await wallet.syncWallet(actors, wasmShim, account, { store: rwStore }); // cache at current tip
  const before = await wallet.loadCache(actors, account, rwStore);
  await ledger.rewind(600); // reinstall / rollback to fewer notes than the cursor
  const oracleRw = genesisScanOracle(ledger, account, wallet.openEnvelope);
  const loadStale = await wallet.loadCache(actors, account, rwStore);
  const s4 = await wallet.syncWallet(actors, wasmShim, account, { store: rwStore });
  record(`B-P4/seed${seed} proofE(rewind→rescan)`,
    before && before.cursor > 600 && loadStale === null && eqSet(setOf(s4.notes), oracleRw.set),
    `cachedCursor=${before && before.cursor} staleRejected=${loadStale === null} bal=${bal(s4.notes)} oracleBal=${bal(oracleRw.notes)}`);
}

// Recover the first owned note's rho/rcm (for the at-rest leak check).
async function firstNoteFields(ledger, account) {
  for (const rec of ledger.records) {
    const note = wallet.openEnvelope(account.encSk, rec.ciphertext);
    if (note && wasmShim.note_commitment_hex(note.v, account.pk, note.rho, note.rcm) === Buffer.from(rec.commitment).toString("hex")) {
      return { rho: note.rho, rcm: note.rcm };
    }
  }
  return {};
}

const failed = results.filter((r) => !r.ok);
console.log(`\nB-P4: ${results.length - failed.length}/${results.length} checks passed`);
if (failed.length) process.exit(1);
