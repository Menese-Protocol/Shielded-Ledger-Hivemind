// B-B — device-portable wallet birthday battery (Menese DeFi Team).
//
// Seven acceptance items, two proofs
// per item, thresholds committed here before the run. B-B1 is the baseline red test: it reproduces, on the
// wallet code as shipped TODAY, the fresh-device (empty cache, birthday unknown ⇒ 0) full-history
// scan at 100k scale — the exact heavy case birthday recovery removes. It was committed and run
// red-first, before set_birthday/get_birthday existed anywhere.
//
// 100k-corpus cost note (engineering choice, NOT a threshold change): owned notes and a fixed
// 1-in-20 calibration slice of noise are sealed with REAL nacl.box (ECDH exercised on scan); the
// remaining noise records are sub-minimum-length blobs that openEnvelope rejects structurally
// (wallet.js:85) before any ECDH. The committed proofs — request-log page accounting, scanned
// counts, and note-set equality against the exhaustive genesis oracle — are exact regardless of
// noise weight; the per-note ECDH cost for the 10^8 extrapolation is measured separately on a
// 2048-note all-real slice and reported.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import "./setup-declarations.mjs";
import naclPkg from "tweetnacl";
import * as wallet from "../../src/wallet.js";
import { wasmShim, makeAccount, memStore } from "./shim.mjs";
import { buildCorpus, genesisScanOracle } from "./corpus.mjs";
import { MockLedger, MAX_BLOCKS_PER_CALL } from "./mock-ledger.mjs";
import { MockDirectory, BIRTHDAY_CT_SIZE } from "./mock-directory.mjs";

const nacl = naclPkg.default ?? naclPkg;
const results = [];
const record = (name, ok, detail) =>
  (results.push({ name, ok, detail }), console.log(`${ok ? "PASS" : "FAIL"}  ${name}  ${detail}`));
const eqSet = (a, b) => a.size === b.size && [...a].every((k) => b.has(k));
const setOf = (notes) => new Set(notes.map((n) => `${n.position}:${n.v}`));
const bal = (notes) => notes.reduce((s, n) => s + n.v, 0n);
const pageOf = (p) => Math.floor(p / MAX_BLOCKS_PER_CALL) * MAX_BLOCKS_PER_CALL;

// ---- light 100k corpus: real crypto where it proves something, structural noise elsewhere ----
async function buildLightCorpus(
  { seed, noteCount, account, birth, ownedEvery = 400, realNoiseEvery = 20, spendEvery = 9 }
) {
  const ledger = new MockLedger();
  let state = (seed * 2654435761) >>> 0;
  const rnd = () => ((state = (state * 1103515245 + 12345) >>> 0), state / 0xffffffff);
  const owned = [];
  let ownedSinceSpend = 0;
  for (let position = 0; position < noteCount; position++) {
    let ciphertext;
    let commitment;
    let note = null;
    const isOwned = position >= birth && position % ownedEvery === 0;
    if (isOwned) {
      const v = BigInt(1 + Math.floor(rnd() * 1_000_000));
      const rho = wasmShim.random_field();
      const rcm = wasmShim.random_field();
      note = { v, rho, rcm };
      ciphertext = wallet.sealNote(account.encPk, note, { viewTag: false });
      commitment = new Uint8Array(Buffer.from(wasmShim.note_commitment_hex(v, account.pk, rho, rcm), "hex"));
    } else if (position % realNoiseEvery === 0) {
      // real envelope sealed to a key nobody holds — scanner pays a real ECDH + failed open
      const v = BigInt(1 + Math.floor(rnd() * 1_000_000));
      ciphertext = wallet.sealNote(nacl.box.keyPair().publicKey, { v, rho: wasmShim.random_field(), rcm: wasmShim.random_field() }, { viewTag: false });
      commitment = new Uint8Array(Buffer.from(wasmShim.note_commitment_hex(v, "noise", "x", "y"), "hex"));
    } else {
      // structurally-rejected noise (below the 72-byte envelope minimum, wallet.js:85)
      ciphertext = new Uint8Array(60);
      for (let i = 0; i < 60; i++) ciphertext[i] = Math.floor(rnd() * 256);
      commitment = new Uint8Array(Buffer.from(wasmShim.note_commitment_hex(0n, "noise", String(position), "z"), "hex"));
    }
    const nullifiers = [];
    if (note) {
      owned.push({ position, ...note, spent: false });
      ownedSinceSpend++;
      if (spendEvery > 0 && ownedSinceSpend >= spendEvery) {
        ownedSinceSpend = 0;
        const victim = owned.find((o) => !o.spent && o.position < position);
        if (victim) {
          victim.spent = true;
          nullifiers.push(new Uint8Array(Buffer.from(wasmShim.note_nullifier_hex(account.nk, victim.rho), "hex")));
        }
      }
    }
    await ledger.append({ commitment, origin: nullifiers.length ? "confidential_transfer" : "shield", ciphertext, nullifiers });
  }
  return { ledger, owned };
}

// ============================== B-B1 — fresh-device full-history baseline (pre-feature code) ==============================
// Fresh device today: empty cache, vetkeyShieldedAccountFor returns birthday=null ⇒ sync scans
// from genesis. Committed thresholds, per seed, N=100_000, BIRTH=60_000:
//   Proof A (request-log): pages fetched == ceil(N/512) == 196, first page start == 0, and
//     >= 117 page-fetches lie ENTIRELY below the birthday page (floor(60000/512)*512 = 59904)
//     — the provably-wasted pre-birthday download this feature removes.
//   Proof B (scan accounting + correctness): scanned == N (every record processed) AND the
//     found set is set-equal to the exhaustive genesis oracle (correct, maximally expensive).
const N = 100_000;
const BIRTH = 60_000;

for (const seed of [1, 2]) {
  const account = makeAccount(nacl, seed);
  const t0 = Date.now();
  const { ledger } = await buildLightCorpus({ seed, noteCount: N, account, birth: BIRTH });
  const buildMs = Date.now() - t0;
  const oracle = genesisScanOracle(ledger, account, wallet.openEnvelope);
  assert.ok(oracle.notes.length > 0, "corpus bug: account owns nothing unspent");
  assert.ok(oracle.notes.every((n) => n.position >= BIRTH), "corpus bug: owned note before birth");

  ledger.resetLog();
  const actors = { ledger: ledger.ledger, principal: null };
  const t1 = Date.now();
  // Exactly the shipped fresh-device path: empty store, no known birthday.
  const sync = await wallet.syncWallet(actors, wasmShim, account, { store: memStore(), birthday: 0 });
  const scanMs = Date.now() - t1;

  const fetches = ledger.requestLog.filter((e) => e.method === "icrc3_get_blocks");
  const starts = fetches.map((e) => e.ranges[0].start);
  const expectedPages = Math.ceil(N / MAX_BLOCKS_PER_CALL);
  const birthdayPage = pageOf(BIRTH);
  const wastedBelow = fetches.filter((e) => e.ranges.every((r) => r.start + r.length <= birthdayPage)).length;
  // saveCache's anchorAt re-fetches one page; count DISTINCT page starts for full-coverage proof.
  const distinctStarts = new Set(starts);
  record(`B-B1/seed${seed} proofA(full-history-fetch)`,
    distinctStarts.size === expectedPages && Math.min(...starts) === 0 && wastedBelow >= 117,
    `distinct_pages=${distinctStarts.size}/${expectedPages} min_start=${Math.min(...starts)} wasted_below_birthday_page=${wastedBelow} build_ms=${buildMs} scan_ms=${scanMs}`);

  record(`B-B1/seed${seed} proofB(scanned-all+correct)`,
    sync.cursor === N && eqSet(setOf(sync.notes), oracle.set),
    `cursor=${sync.cursor} oracle=${oracle.set.size} found=${setOf(sync.notes).size} bal=${bal(sync.notes)}`);
}

// ---- per-note ECDH calibration for the 10^8 extrapolation (reported, not thresholded) ----
{
  const account = makeAccount(nacl, 7);
  const other = makeAccount(nacl, 8);
  const slice = [];
  for (let i = 0; i < 2048; i++) {
    slice.push(wallet.sealNote(other.encPk, { v: 1n, rho: wasmShim.random_field(), rcm: wasmShim.random_field() }, { viewTag: false }));
  }
  const t = Date.now();
  let opened = 0;
  for (const ct of slice) if (wallet.openEnvelope(account.encSk, ct)) opened++;
  const perNoteUs = ((Date.now() - t) * 1000) / slice.length;
  console.log(`CALIB  per-note trial-decrypt ≈ ${perNoteUs.toFixed(1)} µs ⇒ 10^8 notes ≈ ${(perNoteUs * 1e8 / 3.6e9).toFixed(1)} h CPU (opened=${opened})`);
}

// ---- shared setup for B-B2..B-B7: full-crypto corpus + registered directory accounts ----
// The wallet under test always runs with birthdayRecovery: true here (the battery IS the flag-on
// world); B-B7 proves the flag-off world is byte-identical to today.
const OPTS_ON = { birthdayRecovery: true };
async function rig(seed, { noteCount = 1600, births = [900, 0], spendEvery = 41 } = {}) {
  const accounts = [makeAccount(nacl, seed), makeAccount(nacl, seed + 100)];
  const { ledger } = await buildCorpus(nacl, {
    seed, noteCount, accounts,
    sealFn: (pk, note) => wallet.sealNote(pk, note, { viewTag: false }),
    spendEvery, births,
  });
  const dir = new MockDirectory();
  const actorsOf = (account, opts) => ({ ledger: ledger.ledger, principal: null, directory: dir.for(account.principalText, opts) });
  for (const a of accounts) {
    const reg = await actorsOf(a).directory.register(a.pk, "aa");
    assert.ok("ok" in reg, "rig registration failed");
  }
  dir.resetLog();
  ledger.resetLog();
  return { ledger, dir, accounts, actorsOf };
}
const decryptStored = (dir, account) => {
  const ct = dir.storedCt(account.principalText);
  return ct ? wallet.openBirthdayRecord(account.birthdayKey, ct) : null;
};

// ============================== B-B2 — round-trip recovery ==============================
// Committed thresholds (2 seeds; seed2 uses a PAGE-ALIGNED birthday to pin the edge):
//   Proof A: fresh-device (empty cache) sync recovers the published birthday (status
//     "recovered", exact height), and its note set is SET-EQUAL to the exhaustive genesis
//     oracle — for BOTH publish paths (creation-sample and genesis-scan-derived backfill).
//   Proof B: exactly ONE get_birthday round-trip; ZERO block fetches with start below the
//     page containing birthday-1 (the anchor-verification page — page-aligned camouflage);
//     at most ONE fetch on that anchor page below the birthday page proper.
for (const seed of [1, 2]) {
  const BIRTH = seed === 1 ? 900 : 1024; // seed2: exactly page-aligned (1024 = 2*512)
  const { ledger, dir, accounts, actorsOf } = await rig(seed, { births: [BIRTH, 0] });
  const [acct, acct2] = accounts;
  const actors = actorsOf(acct);
  const oracle = genesisScanOracle(ledger, acct, wallet.openEnvelope);
  assert.ok(oracle.notes.length > 0 && oracle.notes.every((n) => n.position >= BIRTH), "corpus bug");

  // -- creation session: sample published via creationBirthday (directory has no record) --
  const s1 = await wallet.syncWallet(actors, wasmShim, acct, { ...OPTS_ON, store: memStore(), creationBirthday: BIRTH });
  const stored1 = decryptStored(dir, acct);
  assert.ok(stored1 && stored1.b === BIRTH, `creation publish missing (${stored1?.b})`);

  // -- fresh device: empty cache, no hints — recover + scan [birthday, tip] --
  dir.resetLog();
  ledger.resetLog();
  const s2 = await wallet.syncWallet(actors, wasmShim, acct, { ...OPTS_ON, store: memStore() });
  record(`B-B2/seed${seed} proofA(fresh-device-recovers+set-equal)`,
    s2.recovery === "recovered" && s2.birthday === BIRTH && eqSet(setOf(s2.notes), oracle.set) && eqSet(setOf(s1.notes), oracle.set),
    `recovery=${s2.recovery} birthday=${s2.birthday} oracle=${oracle.set.size} found=${setOf(s2.notes).size}`);

  const gets = dir.requestLog.filter((e) => e.method === "get_birthday").length;
  const anchorPage = pageOf(Math.max(0, BIRTH - 1));
  const birthdayPage = pageOf(BIRTH);
  const belowAnchor = ledger.fetchesBelow(anchorPage).length;
  const onAnchorPage = ledger.requestLog.filter(
    (e) => e.method === "icrc3_get_blocks" && e.ranges.some((r) => r.start >= anchorPage && r.start < birthdayPage)
  ).length;
  record(`B-B2/seed${seed} proofB(one-get+zero-below-anchor-page)`,
    gets === 1 && belowAnchor === 0 && onAnchorPage <= 1,
    `get_birthday=${gets} fetches_below_anchor_page(${anchorPage})=${belowAnchor} anchor_page_fetches=${onAnchorPage}`);

  // -- genesis-scan-derived backfill (account2: pre-feature, no record, no hint) --
  const oracle2 = genesisScanOracle(ledger, acct2, wallet.openEnvelope);
  const actors2 = actorsOf(acct2);
  const s3 = await wallet.syncWallet(actors2, wasmShim, acct2, { ...OPTS_ON, store: memStore() });
  const bStar = oracle2.notes.length ? Math.min(...oracle2.notes.map((n) => n.position)) : Number(ledger.records.length);
  const stored2 = decryptStored(dir, acct2);
  dir.resetLog();
  ledger.resetLog();
  const s4 = await wallet.syncWallet(actors2, wasmShim, acct2, { ...OPTS_ON, store: memStore() });
  record(`B-B2/seed${seed} proofA2(backfill-publish+recover+set-equal)`,
    stored2 && stored2.b === bStar && s4.recovery === "recovered" && s4.birthday === bStar &&
      eqSet(setOf(s3.notes), oracle2.set) && eqSet(setOf(s4.notes), oracle2.set),
    `published=${stored2?.b} expected_bStar=${bStar} recovery=${s4.recovery} oracle=${oracle2.set.size}`);
}

// ============================== B-B3 — ciphertext-only at rest ==============================
// Committed thresholds (2 seeds):
//   Proof A: the stored blob contains neither the birthday as ASCII decimal nor as its 8-byte BE
//     encoding, nor any record-structure ASCII marker; a DIFFERENT principal's birthday key and
//     the SAME principal's cache key both fail to open it; the right key round-trips exactly.
//   Proof B (size invariance): every stored ct — heights 0, mid, page-aligned, huge — is EXACTLY
//     113 bytes, so length reveals nothing about magnitude.
for (const seed of [1, 2]) {
  const { ledger, dir, accounts, actorsOf } = await rig(seed, { noteCount: 1200, births: [700, 0] });
  const [acct, acct2] = accounts;
  const actors = actorsOf(acct);
  const heights = [0, 700, 1024, 1199];
  const lens = [];
  let allRoundTrip = true;
  for (const b of heights) {
    assert.ok(await wallet.publishBirthday(actors, acct, b), `publish(${b}) failed`);
    const ct = dir.storedCt(acct.principalText);
    lens.push(ct.length);
    const rec = wallet.openBirthdayRecord(acct.birthdayKey, ct);
    if (!rec || rec.b !== b) allRoundTrip = false;
  }
  // leave the mid height stored for the needle scan
  await wallet.publishBirthday(actors, acct, 700);
  const ct = dir.storedCt(acct.principalText);
  const latin = Buffer.from(ct).toString("latin1");
  const be = new Uint8Array(8);
  for (let k = 0; k < 8; k++) be[k] = Math.floor(700 / 256 ** (7 - k)) % 256;
  const needles = ["700", '"b"', "birthday", "anchor", "binding"];
  const asciiHits = needles.filter((n) => latin.includes(n));
  const beHit = latin.includes(Buffer.from(be).toString("latin1"));
  const wrongKey = wallet.openBirthdayRecord(acct2.birthdayKey, ct);
  const cacheKey = wallet.openBirthdayRecord(acct.cacheKey, ct);
  record(`B-B3/seed${seed} proofA(at-rest+key-separation)`,
    asciiHits.length === 0 && !beHit && wrongKey === null && cacheKey === null && allRoundTrip,
    `ascii_hits=${asciiHits.length} be_hit=${beHit} wrong_key_open=${wrongKey !== null} cache_key_open=${cacheKey !== null}`);
  record(`B-B3/seed${seed} proofB(size-invariance)`,
    lens.every((l) => l === BIRTHDAY_CT_SIZE),
    `lens=${lens.join(",")} (required all ${BIRTHDAY_CT_SIZE})`);
}

// ============================== B-B4 — caller-keying + too-HIGH layers ==============================
// Committed thresholds (2 seeds):
//   Proof A (canister guards, mirrored byte-for-byte from DemoDirectory.mo): an attacker's
//     set_birthday writes ONLY its own record (victim's bytes unchanged); anonymous ⇒
//     "anonymous-caller"; unregistered ⇒ "not-registered"; sizes 112/114/0 ⇒
//     "bad-birthday-ct-size"; get_birthday returns only the caller's own record.
//   Proof B (too-HIGH defense layers, each proven):
//     B1 warm immunity — with ANY inflated directory value planted, a cached device syncs the
//        correct oracle balance with ZERO birthday endpoint calls.
//     B2 floor invariant — EVERY genuine value the shipped client ever published (full history)
//        decrypts to ≤ the oracle's min owned-unspent position.
//     B3 replay safety — with the directory serving the OLDEST genuine ciphertext (rollback),
//        a fresh device still syncs the exact oracle set.
//     B4 heal — with a validly-sealed INFLATED record (owner-compromise class), a fresh device's
//        under-report is bounded exactly to notes below the inflated height (documented
//        contract); fullRescan restores the oracle balance AND republishes the true floor, after
//        which a NEW fresh device is exactly correct again.
for (const seed of [1, 2]) {
  const { ledger, dir, accounts, actorsOf } = await rig(seed, { noteCount: 1600, births: [0, 0] });
  const [victim, attacker] = accounts;
  const vActors = actorsOf(victim);
  const aActors = actorsOf(attacker);
  const oracle = genesisScanOracle(ledger, victim, wallet.openEnvelope);
  const oracleMin = Math.min(...oracle.notes.map((n) => n.position));

  // seed a genuine conservative floor FIRST (so the genuine history holds two DIFFERENT values
  // and the replay proof below exercises a real rollback, not a same-value no-op), then a
  // genesis-derived publish + a cache
  assert.ok(await wallet.publishBirthday(vActors, victim, 0), "seed publish failed");
  const store = memStore();
  const s1 = await wallet.syncWallet(vActors, wasmShim, victim, { ...OPTS_ON, store });
  assert.ok(decryptStored(dir, victim), "victim publish missing");

  // -- proof A: guards --
  const victimBytes = Buffer.from(dir.storedCt(victim.principalText)).toString("hex");
  const attCt = wallet.sealBirthdayRecord(attacker.birthdayKey, 1500, "genesis");
  const attRes = await aActors.directory.set_birthday(attCt);
  const anonRes = await dir.for(victim.principalText, { anonymous: true }).set_birthday(attCt);
  const unregRes = await dir.for("never-registered").set_birthday(attCt);
  const badSizes = [];
  for (const n of [112, 114, 0]) badSizes.push((await vActors.directory.set_birthday(new Uint8Array(n))).err);
  const attGet = await aActors.directory.get_birthday();
  const attSeesOwn = attGet.length && Buffer.from(attGet[0]).toString("hex") === Buffer.from(attCt).toString("hex");
  record(`B-B4/seed${seed} proofA(caller-keyed+guards)`,
    "ok" in attRes &&
      Buffer.from(dir.storedCt(victim.principalText)).toString("hex") === victimBytes &&
      anonRes.err === "anonymous-caller" && unregRes.err === "not-registered" &&
      badSizes.every((e) => e === "bad-birthday-ct-size") && attSeesOwn,
    `victim_unchanged=${Buffer.from(dir.storedCt(victim.principalText)).toString("hex") === victimBytes} anon=${anonRes.err} unreg=${unregRes.err} sizes=${badSizes.join("|")}`);

  // -- B1: warm immunity against a planted inflated value --
  const tip = Number(ledger.records.length);
  const inflated = wallet.sealBirthdayRecord(victim.birthdayKey, tip, await (async () => {
    // valid chain anchor for tip so every read-side verification passes — the worst case
    const page = await wallet.readNotes(vActors, { from: pageOf(tip - 1), to: pageOf(tip - 1) + MAX_BLOCKS_PER_CALL });
    return page.find((r) => r.position === tip - 1)?.noteRootAfter ?? "genesis";
  })());
  dir.plant(victim.principalText, inflated);
  dir.resetLog();
  const warm = await wallet.syncWallet(vActors, wasmShim, victim, { ...OPTS_ON, store });
  record(`B-B4/seed${seed} proofB1(warm-immunity)`,
    warm.fromCache && eqSet(setOf(warm.notes), oracle.set) && dir.birthdayCalls().length === 0,
    `fromCache=${warm.fromCache} balance_ok=${eqSet(setOf(warm.notes), oracle.set)} birthday_calls=${dir.birthdayCalls().length}`);

  // -- B4: fresh device vs inflated record — bounded under-report, then heal --
  const fresh1 = await wallet.syncWallet(vActors, wasmShim, victim, { ...OPTS_ON, store: memStore() });
  const found1 = setOf(fresh1.notes);
  const missing = [...oracle.set].filter((k) => !found1.has(k));
  const boundedExactly = [...found1].every((k) => oracle.set.has(k)) && missing.every((k) => Number(k.split(":")[0]) < tip);
  const healStore = memStore();
  const healed = await wallet.syncWallet(vActors, wasmShim, victim, { ...OPTS_ON, store: healStore, fullRescan: true });
  const storedHealed = decryptStored(dir, victim);
  const fresh2 = await wallet.syncWallet(vActors, wasmShim, victim, { ...OPTS_ON, store: memStore() });
  record(`B-B4/seed${seed} proofB4(inflated-bounded+fullRescan-heals)`,
    fresh1.recovery === "recovered" && boundedExactly && missing.length > 0 &&
      eqSet(setOf(healed.notes), oracle.set) && storedHealed && storedHealed.b === oracleMin &&
      fresh2.recovery === "recovered" && fresh2.birthday === oracleMin && eqSet(setOf(fresh2.notes), oracle.set),
    `under_report_missing=${missing.length} bounded=${boundedExactly} healed_publish=${storedHealed?.b} expected=${oracleMin} post_heal_ok=${eqSet(setOf(fresh2.notes), oracle.set)}`);

  // -- B2: floor invariant over every genuine publish the shipped client made --
  const floors = (dir.history.get(victim.principalText) ?? []).map((c) => wallet.openBirthdayRecord(victim.birthdayKey, c)?.b);
  record(`B-B4/seed${seed} proofB2(floor-invariant)`,
    floors.length >= 2 && floors.every((b) => b != null && b <= oracleMin),
    `published_values=${floors.join(",")} oracle_min=${oracleMin}`);

  // -- B3: rollback/replay of the oldest genuine ciphertext — a REAL rollback: the served value
  // must differ from the current one (0 vs the healed oracleMin), and the balance must still be
  // exactly the oracle set (the floor invariant: every genuine historical value is a floor) --
  const currentB = decryptStored(dir, victim)?.b;
  dir.replayOldest = true;
  const replayed = await wallet.syncWallet(vActors, wasmShim, victim, { ...OPTS_ON, store: memStore() });
  dir.replayOldest = false;
  record(`B-B4/seed${seed} proofB3(replay-safety)`,
    replayed.recovery === "recovered" && replayed.birthday === 0 && currentB === oracleMin &&
      replayed.birthday !== currentB && eqSet(setOf(replayed.notes), oracle.set),
    `replayed_b=${replayed.birthday} current_b=${currentB} differs=${replayed.birthday !== currentB} balance_ok=${eqSet(setOf(replayed.notes), oracle.set)}`);
}

// ============================== B-B5 — fail-safe matrix ==============================
// Committed thresholds (2 seeds): EVERY failure mode resolves to birthday 0 with the exact
// expected status (Proof A), and the resulting sync is a genesis scan whose note set equals the
// oracle — never a wrong balance (Proof B: fetch log contains page 0; set-equal).
for (const seed of [1, 2]) {
  const { ledger, dir, accounts, actorsOf } = await rig(seed, { noteCount: 700, births: [0, 0], spendEvery: 33 });
  const [acct, other] = accounts;
  const actors = actorsOf(acct);
  const oracle = genesisScanOracle(ledger, acct, wallet.openEnvelope);
  const tip = Number(ledger.records.length);

  const wrongVersion = (() => {
    const ct = wallet.sealBirthdayRecord(acct.birthdayKey, 300, "genesis");
    // re-seal with a corrupted version byte INSIDE the box: craft plaintext manually
    const pt = new Uint8Array(73);
    pt[0] = 2; // unknown version
    const nonce = ct.slice(0, 24);
    const boxed = nacl.secretbox(pt, nonce, acct.birthdayKey);
    const out = new Uint8Array(113);
    out.set(nonce, 0);
    out.set(boxed, 24);
    return out;
  })();

  const cases = [
    ["absent", () => dir.birthdays.delete(acct.principalText), "absent"],
    ["random-bytes", () => dir.plant(acct.principalText, crypto.getRandomValues(new Uint8Array(113))), "undecryptable"],
    ["wrong-version", () => dir.plant(acct.principalText, wrongVersion), "undecryptable"],
    ["foreign-principal-ct", () => dir.plant(acct.principalText, wallet.sealBirthdayRecord(other.birthdayKey, 300, "genesis")), "undecryptable"],
    ["wrong-ledger", () => dir.plant(acct.principalText, wallet.sealBirthdayRecord(acct.birthdayKey, 300, "genesis", { binding: wallet.birthdayBinding("aaaaa-aa", "https://elsewhere.example") })), "wrong-ledger"],
    ["beyond-tip", () => dir.plant(acct.principalText, wallet.sealBirthdayRecord(acct.birthdayKey, tip + 500, "genesis")), "beyond-tip"],
    ["anchor-mismatch", () => dir.plant(acct.principalText, wallet.sealBirthdayRecord(acct.birthdayKey, 400, bytesToHexLocal(crypto.getRandomValues(new Uint8Array(32))))), "anchor-mismatch"],
    ["unreachable", () => { dir.unreachable = true; }, "unreachable"],
  ];
  const statuses = [];
  let allCorrect = true;
  let allGenesis = true;
  for (const [, setup, expected] of cases) {
    setup();
    ledger.resetLog();
    const s = await wallet.syncWallet(actors, wasmShim, acct, { ...OPTS_ON, store: memStore() });
    dir.unreachable = false;
    statuses.push(`${expected}:${s.recovery}`);
    if (s.recovery !== expected || s.birthday !== 0) allCorrect = false;
    if (!eqSet(setOf(s.notes), oracle.set)) allCorrect = false;
    if (!ledger.requestLog.some((e) => e.method === "icrc3_get_blocks" && e.ranges.some((r) => r.start === 0))) allGenesis = false;
  }
  // no-key custody: never touches the directory at all
  const legacy = makeAccount(nacl, seed + 300, "legacy-localStorage");
  dir.resetLog();
  const sLegacy = await wallet.syncWallet(actorsOf(legacy), wasmShim, legacy, { ...OPTS_ON, store: memStore() });
  const legacyOk = dir.birthdayCalls().length === 0 && sLegacy.recovery === null;
  record(`B-B5/seed${seed} proofA(status-matrix)`,
    allCorrect && legacyOk,
    `${statuses.join(" ")} legacy_silent=${legacyOk}`);
  record(`B-B5/seed${seed} proofB(always-genesis-fallback)`, allGenesis, `all_cases_scanned_from_page0=${allGenesis}`);
}
function bytesToHexLocal(b) {
  return Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
}

// ============================== B-B6 — no-regression (flag-ON specifics) ==============================
// Committed thresholds (2 seeds): a WARM open is pure cache path — zero birthday endpoint calls,
// zero block fetches below the cursor page, oracle-correct balance over a grown log (Proof A);
// a THROWAWAY account never touches the directory's birthday endpoints and writes nothing (Proof
// B). (The read-path half — B-P1..B-P5 40/40 on this code — is enforced by the
// runner, which runs those items from this same tree.)
for (const seed of [1, 2]) {
  const { ledger, dir, accounts, actorsOf } = await rig(seed, { noteCount: 1100, births: [0, 0] });
  const acct = accounts[0];
  const actors = actorsOf(acct);
  const store = memStore();
  const s1 = await wallet.syncWallet(actors, wasmShim, acct, { ...OPTS_ON, store });
  // grow the log (some owned)
  for (let i = 0; i < 300; i++) {
    const rho = wasmShim.random_field(), rcm = wasmShim.random_field();
    const v = BigInt(1 + i);
    const owned = i % 4 === 0;
    const encPk = owned ? acct.encPk : nacl.box.keyPair().publicKey;
    const cm = Buffer.from(wasmShim.note_commitment_hex(v, owned ? acct.pk : "noise", rho, rcm), "hex");
    await ledger.append({ commitment: new Uint8Array(cm), origin: "shield", ciphertext: wallet.sealNote(encPk, { v, rho, rcm }, { viewTag: false }), nullifiers: [] });
  }
  const oracle = genesisScanOracle(ledger, acct, wallet.openEnvelope);
  dir.resetLog();
  ledger.resetLog();
  const warm = await wallet.syncWallet(actors, wasmShim, acct, { ...OPTS_ON, store });
  const below = ledger.fetchesBelow(pageOf(s1.cursor)).length;
  record(`B-B6/seed${seed} proofA(warm-zero-birthday-traffic)`,
    warm.fromCache && dir.birthdayCalls().length === 0 && below === 0 && eqSet(setOf(warm.notes), oracle.set),
    `fromCache=${warm.fromCache} birthday_calls=${dir.birthdayCalls().length} below_cursor=${below} balance_ok=${eqSet(setOf(warm.notes), oracle.set)}`);

  const throwaway = makeAccount(nacl, seed + 200, "throwaway-memory");
  const tStore = memStore();
  dir.resetLog();
  await wallet.syncWallet(actorsOf(throwaway), wasmShim, throwaway, { ...OPTS_ON, store: tStore });
  record(`B-B6/seed${seed} proofB(throwaway-silence)`,
    dir.birthdayCalls().length === 0 && tStore._m.size === 0,
    `birthday_calls=${dir.birthdayCalls().length} store_entries=${tStore._m.size}`);
}

// ============================== B-B7 — gated & additive ==============================
// Committed thresholds:
//   Proof A (2 seeds, flag OFF ⇒ byte-identical to today): with birthdayRecovery: false —
//     store null, creationBirthday supplied (must be inert) — the block-fetch transcript is
//     BYTE-IDENTICAL to the pre-change direct scanNotes path, ZERO birthday endpoint calls,
//     identical note set.
//   Proof B (toolchain, once): the OLD DemoDirectory.mo (pinned pre-implementation commit
//     eb3d276) vs the NEW one: `moc --stable-compatible old.most new.most` exits 0, and the
//     candid diff is PURELY additive — every old method unchanged, exactly
//     {get_birthday, set_birthday} added.
const transcript = (ledger) =>
  ledger.requestLog
    .filter((e) => e.method === "icrc3_get_blocks")
    .map((e) => e.ranges.map((r) => `${r.start}:${r.length}`).join("|"))
    .join(",");
for (const seed of [1, 2]) {
  const { ledger, dir, accounts, actorsOf } = await rig(seed, { noteCount: 1300, births: [0, 0] });
  const acct = accounts[0];
  const actors = actorsOf(acct);
  ledger.resetLog();
  const ref = await wallet.scanNotes(actors, wasmShim, acct); // today's app path (pre-change behavior)
  const tRef = transcript(ledger);
  dir.resetLog();
  ledger.resetLog();
  const off = await wallet.syncWallet(actors, wasmShim, acct, { birthdayRecovery: false, store: null, creationBirthday: 999 });
  const tOff = transcript(ledger);
  record(`B-B7/seed${seed} proofA(flag-off-byte-identical)`,
    tOff === tRef && tOff.length > 0 && dir.birthdayCalls().length === 0 && eqSet(setOf(off.notes), setOf(ref.notes)),
    `transcripts_equal=${tOff === tRef} pages=${tOff.split(",").length} birthday_calls=${dir.birthdayCalls().length}`);
}
{
  const here = dirname(fileURLToPath(import.meta.url));
  const repo = resolve(here, "../../..");
  const MOC = "/root/.cache/dfinity/versions/0.31.0/moc";
  const OLD_COMMIT = "eb3d276"; // last commit BEFORE the birthday endpoints existed
  const tmp = mkdtempSync(join(tmpdir(), "bday-ac7-"));
  const oldSrc = execFileSync("git", ["show", `${OLD_COMMIT}:tests/DemoDirectory.mo`], { cwd: repo });
  writeFileSync(join(tmp, "OldDemoDirectory.mo"), oldSrc);
  const pkg = ["--package", "core", resolve(repo, ".mops/core@1.0.0/src"), "--package", "sha2", resolve(repo, ".mops/sha2@0.1.9/src")];
  execFileSync(MOC, [...pkg, "--stable-types", "--idl", join(tmp, "OldDemoDirectory.mo"), "-o", join(tmp, "old.wasm")], { cwd: repo });
  execFileSync(MOC, [...pkg, "--stable-types", "--idl", resolve(repo, "tests/DemoDirectory.mo"), "-o", join(tmp, "new.wasm")], { cwd: repo });
  let stableOk = true;
  try {
    execFileSync(MOC, ["--stable-compatible", join(tmp, "old.most"), join(tmp, "new.most")]);
  } catch {
    stableOk = false;
  }
  const methods = (did) => [...did.matchAll(/^\s{2}(\w+):\s*\(/gm)].map((m) => m[1]).sort();
  const oldM = methods(readFileSync(join(tmp, "old.did"), "utf8"));
  const newM = methods(readFileSync(join(tmp, "new.did"), "utf8"));
  const added = newM.filter((m) => !oldM.includes(m));
  const removed = oldM.filter((m) => !newM.includes(m));
  record(`B-B7 proofB(stable-compatible+candid-additive)`,
    stableOk && removed.length === 0 && added.sort().join(",") === "get_birthday,set_birthday",
    `stable_compatible=${stableOk} removed=${removed.length} added=${added.join(",")}`);
}

const failed = results.filter((r) => !r.ok);
console.log(`\nB-B: ${results.length - failed.length}/${results.length} checks passed`);
if (failed.length) process.exit(1);
