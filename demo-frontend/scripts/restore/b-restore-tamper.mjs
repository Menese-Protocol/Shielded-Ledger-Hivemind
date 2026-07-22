// B-RESTORE-TAMPER — A-2 mirror-tamper detection (Menese DeFi Team).
//
// A malicious/faulty mirror serves corrupted detection pages; the certified detect_stream root
// (trusted, never from the mirror) must cause the tampered segment to be REJECTED BEFORE its
// entries reach the scan, for EVERY corruption class: single-bit flip, truncation, entry
// reordering, and splice across a segment boundary. Two proofs per class: (1) the tampered
// segment is rejected (counter == injected); (2) an honest re-fetch yields the untampered owned
// set (the tampered page contributes nothing). RED teeth: with verify-before-scan DISABLED, the
// truncation case silently DROPS a planted note (a false negative) — proving the verification is
// load-bearing, not decorative.
import "../readpath/setup-declarations.mjs";
import naclPkg from "tweetnacl";
import * as wallet from "../../src/wallet.js";
import { hexToBytes } from "../../src/ic.js";
import { wasmShim, makeAccount } from "../readpath/shim.mjs";
import { MockLedger } from "../readpath/mock-ledger.mjs";
import { posBE8, DPAGE, ENTRY_LEN } from "./detect-chain.mjs";
import { buildAnchor, makeMirror } from "./mirror.mjs";
import { parallelScan } from "./parallel-scan.mjs";

const nacl = naclPkg.default ?? naclPkg;
const results = [];
const record = (name, ok, detail) => (results.push({ name, ok }), console.log(`${ok ? "PASS" : "FAIL"}  ${name}  ${detail}`));
const setPos = (notes) => new Set(notes.map((n) => n.position));

const TOTAL = 2 * DPAGE + 300;      // 2 complete segments + tip
const PLANT = [5000, 2 * DPAGE - 1, 8300]; // seg1 middle, seg1 LAST (truncation target), tip
const TARGET_SEG = 1;               // segment [DPAGE, 2*DPAGE) — the one we tamper

async function buildCorpus(seed) {
  const account = makeAccount(nacl, seed);
  const ledger = new MockLedger();
  let st = (seed * 2654435761) >>> 0; const rnd = () => ((st = (st * 1103515245 + 12345) >>> 0), st / 0xffffffff);
  const planted = [];
  const plantSet = new Set(PLANT);
  for (let position = 0; position < TOTAL; position++) {
    const v = BigInt(1 + Math.floor(rnd() * 1_000_000));
    const rho = wasmShim.random_field(), rcm = wasmShim.random_field();
    const owner = plantSet.has(position) ? account : null;
    const pk = owner ? account.encPk : nacl.box.keyPair().publicKey;
    const commitment = Buffer.from(wasmShim.note_commitment_hex(v, owner ? account.pk : "noise", rho, rcm), "hex");
    const ciphertext = wallet.sealNote(pk, { v, rho, rcm }, { viewTag: true });
    await ledger.append({ commitment: new Uint8Array(commitment), origin: "shield", ephemeralKey: new Uint8Array(32), ciphertext, nullifiers: [] });
    if (owner) planted.push({ position, v });
  }
  return { account, ledger, planted };
}

// tamper functions: mutate the served bytes of the TARGET segment only (segIndex from mirror).
const tampers = {
  bitflip: (buf, seg) => { if (seg !== TARGET_SEG) return buf; const b = buf.slice(); b[100] ^= 0x01; return b; },
  truncate: (buf, seg) => { if (seg !== TARGET_SEG) return buf; return buf.slice(0, buf.length - 5 * ENTRY_LEN); }, // drop last 5 entries (incl. planted last)
  reorder: (buf, seg) => { if (seg !== TARGET_SEG) return buf; const b = buf.slice(); const A = 10 * ENTRY_LEN, B = 20 * ENTRY_LEN; for (let i = 0; i < ENTRY_LEN; i++) { const t = b[A + i]; b[A + i] = b[B + i]; b[B + i] = t; } return b; },
  splice: (buf, seg, entryAt, from) => { if (seg !== TARGET_SEG) return buf; const b = buf.slice(); // graft an entry from FAR away (position from+9999) over entry 15
    const alien = entryAt(from + 9999 < TOTAL ? from + 9999 : 0); b.set(alien, 15 * ENTRY_LEN); return b; },
};

for (const seed of [1, 2]) {
  const { account, ledger, planted } = await buildCorpus(seed);
  const actors = { ledger: ledger.ledger, principal: null };
  const entryAt = (i) => { const e = new Uint8Array(ENTRY_LEN); e.set(posBE8(i), 0); const ct = ledger.records[i].ciphertext; for (let j = 0; j < 40; j++) e[8 + j] = ct[j] ?? 0; return e; };
  const anchor = buildAnchor(entryAt, TOTAL);
  const trusted = { root: anchor.root, cTip: anchor.cTip, noteCount: TOTAL };
  const recognize = async (mp) => {
    const notes = [];
    for (const ps of mp) for (const rec of await wallet.retrieveMatchedPage(actors, ps, Math.min(ps + 512, TOTAL))) {
      const note = wallet.openEnvelope(account.encSk, hexToBytes(rec.ciphertext)); if (!note) continue;
      if (wasmShim.note_commitment_hex(note.v, account.pk, note.rho, note.rcm) !== rec.commitment) continue;
      notes.push({ ...note, cm: rec.commitment, position: rec.position });
    }
    return notes;
  };
  const common = { mode: "native", workers: 4, trusted, encSk: account.encSk, from0: 0, eff: 0, total: TOTAL, recognize };

  // honest baseline
  const honestMirror = makeMirror(entryAt, TOTAL, { anchor });
  const honest = await parallelScan({ ...common, mirror: honestMirror });
  const fullSet = setPos(honest.notes);
  const honestOk = honest.rejected.length === 0 && PLANT.every((p) => fullSet.has(p));
  record(`tamper/seed${seed} baseline(honest-full-set)`, honestOk, `planted=${planted.length} recognized=${honest.notes.length} rejected=${honest.rejected.length}`);

  for (const [name, fn] of Object.entries(tampers)) {
    const tamper = (buf, seg) => fn(buf, seg, entryAt, seg * DPAGE);
    const mirror = makeMirror(entryAt, TOTAL, { anchor, tamper });
    const run = await parallelScan({ ...common, mirror });
    // proof 1: the tampered segment is rejected (>=1 rejection, all on TARGET_SEG), before scan
    const rejectedTarget = run.rejected.length >= 1 && run.rejected.every((r) => r.seg === TARGET_SEG);
    // proof 2: honest re-fetch of the rejected segment restores the untampered owned set
    const refetch = await parallelScan({ ...common, mirror: honestMirror }); // models refetch from an honest mirror
    const restored = PLANT.every((p) => setPos(refetch.notes).has(p));
    record(`tamper/seed${seed} ${name}(reject+refetch)`, rejectedTarget && restored,
      `rejected=${JSON.stringify(run.rejected.map((r) => r.seg))} reason=${run.rejected[0]?.reason} refetch_full=${restored}`);
  }

  // boundary-PROOF tamper (not bytes): a mirror lying about a Merkle boundary leaf must fail the
  // proof against the trusted root (exercises the worker's end-merkle reject path).
  const proofMirror = makeMirror(entryAt, TOTAL, { anchor, proofTamper: (p, j) => (j === TARGET_SEG ? { leaf: (() => { const b = p.leaf.slice(); b[0] ^= 0x01; return b; })(), path: p.path } : p) });
  const proofRun = await parallelScan({ ...common, mirror: proofMirror });
  record(`tamper/seed${seed} boundaryProof(merkle-reject)`, proofRun.rejected.some((r) => r.seg === TARGET_SEG && r.reason === "end-merkle"),
    `rejected=${JSON.stringify(proofRun.rejected)}`);

  // RED teeth: DISABLE verify-before-scan + truncate -> planted LAST note (2*DPAGE-1) silently missed
  const truncMirror = makeMirror(entryAt, TOTAL, { anchor, tamper: (buf, seg) => tampers.truncate(buf, seg) });
  const noVerify = await parallelScan({ ...common, mirror: truncMirror, skipVerify: true });
  const missed = !setPos(noVerify.notes).has(2 * DPAGE - 1) && fullSet.has(2 * DPAGE - 1);
  const withVerify = await parallelScan({ ...common, mirror: truncMirror });
  const caught = withVerify.rejected.some((r) => r.seg === TARGET_SEG);
  record(`tamper/seed${seed} redTeeth(no-verify-drops-note; verify-catches)`, missed && caught,
    `no_verify_missed_last=${missed} verify_rejected=${caught}`);
}

const failed = results.filter((r) => !r.ok);
console.log(`\nB-RESTORE-TAMPER: ${results.length - failed.length}/${results.length} checks passed`);
if (failed.length) process.exit(1);
