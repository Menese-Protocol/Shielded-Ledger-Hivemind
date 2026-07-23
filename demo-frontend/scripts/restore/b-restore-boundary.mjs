// B-RESTORE-BOUNDARY — AC-3 adversarial wire-protocol battery at segment boundaries
// (Menese DeFi Team). Beyond the tamper classes, this battery attacks the SEGMENT PROTOCOL
// itself, per case RED-proven by injection through the mirror harness:
//   entry count   — segment served one entry short / one entry long (still 48-aligned)
//   continuity    — gap (entry removed mid-segment), duplicate (entry repeated, count kept)
//   position parse— position field beyond 2^53 (Number.isSafeInteger hazard)
//   tip binding   — the final PARTIAL segment: short tail, long tail (noteCount binding)
//   cross-cert    — root/cTip/noteCount mixed from TWO certificates MUST reject via the
//                   leaf binding BEFORE any mirror traffic (call-counted), including the
//                   stale-prefix mix over the SAME honest stream that every per-segment
//                   check would accept
// Teeth per case: the same corruption with the detector disabled (skipVerify for chain
// cases, skipLeafBinding for the certificate binding) is accepted silently or caught only
// by the deeper guard — proving each check is load-bearing, not decorative. Zero pages
// from a poisoned segment: the planted note inside the tampered segment must never reach
// the owned set in a rejecting run.
import "../readpath/setup-declarations.mjs";
import naclPkg from "tweetnacl";
import * as wallet from "../../src/wallet.js";
import { hexToBytes } from "../../src/ic.js";
import { wasmShim, makeAccount } from "../readpath/shim.mjs";
import { MockLedger } from "../readpath/mock-ledger.mjs";
import { posBE8, DPAGE, ENTRY_LEN, buildStream, detectLeaf } from "./detect-chain.mjs";
import { buildAnchor, makeMirror } from "./mirror.mjs";
import { parallelScan } from "./parallel-scan.mjs";

const nacl = naclPkg.default ?? naclPkg;
const results = [];
const record = (name, ok, detail) => (results.push({ name, ok }), console.log(`${ok ? "PASS" : "FAIL"}  ${name}  ${detail}`));
const setPos = (notes) => new Set(notes.map((n) => n.position));

const TOTAL = 2 * DPAGE + 300;            // 2 complete segments + 300-entry tail
const PLANT = [5000, 2 * DPAGE - 1, 8300]; // seg1 middle, seg1 LAST, tip
const TARGET_SEG = 1;

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

// segment-protocol tampers over the TARGET segment (all keep length 48-aligned so only
// the protocol checks — not the malformed-length guard — can catch them)
const E = ENTRY_LEN;
const tampers = {
  // exact entry count: one short (drop last entry), one long (append a copy of the last)
  countShort: (buf) => buf.slice(0, buf.length - E),
  countLong: (buf) => { const b = new Uint8Array(buf.length + E); b.set(buf, 0); b.set(buf.subarray(buf.length - E), buf.length); return b; },
  // continuity: gap (remove entry 100), duplicate (repeat entry 100 over entry 101)
  gap: (buf) => { const b = new Uint8Array(buf.length - E); b.set(buf.subarray(0, 100 * E), 0); b.set(buf.subarray(101 * E), 100 * E); return b; },
  duplicate: (buf) => { const b = buf.slice(); b.set(buf.subarray(100 * E, 101 * E), 101 * E); return b; },
  // position parse: entry 10's position field set beyond 2^53 (0xFF…FF)
  overflowPos: (buf) => { const b = buf.slice(); for (let k = 0; k < 8; k++) b[10 * E + k] = 0xff; return b; },
};

for (const seed of [1, 2]) {
  const { account, ledger, planted } = await buildCorpus(seed);
  const actors = { ledger: ledger.ledger, principal: null };
  const entryAt = (i) => { const e = new Uint8Array(E); e.set(posBE8(i), 0); const ct = ledger.records[i].ciphertext; for (let j = 0; j < 40; j++) e[8 + j] = ct[j] ?? 0; return e; };
  const anchor = buildAnchor(entryAt, TOTAL);
  const trusted = { root: anchor.root, cTip: anchor.cTip, noteCount: TOTAL, leaf: anchor.leaf };
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
  const honestMirror = makeMirror(entryAt, TOTAL, { anchor });

  // baseline sanity: honest mirror, leaf binding on, full planted set
  const honest = await parallelScan({ ...common, mirror: honestMirror });
  record(`boundary/seed${seed} baseline`, honest.rejected.length === 0 && PLANT.every((p) => setPos(honest.notes).has(p)),
    `recognized=${honest.notes.length} rejected=${honest.rejected.length}`);

  // ---- segment-protocol tampers: reject at TARGET_SEG, poisoned note never recognized ----
  for (const [name, fn] of Object.entries(tampers)) {
    const mirror = makeMirror(entryAt, TOTAL, { anchor, tamper: (buf, seg) => (seg === TARGET_SEG ? fn(buf) : buf) });
    const run = await parallelScan({ ...common, mirror });
    const rejectedTarget = run.rejected.length >= 1 && run.rejected.every((r) => r.seg === TARGET_SEG);
    const poisonedClean = !setPos(run.notes).has(5000) && !setPos(run.notes).has(2 * DPAGE - 1);
    record(`boundary/seed${seed} ${name}(reject+no-poisoned-note)`, rejectedTarget && poisonedClean,
      `rejected=${JSON.stringify(run.rejected.map((r) => ({ seg: r.seg, reason: r.reason })))}`);
    // teeth: same corruption with the chain verify DISABLED. countShort keeps positions
    // continuous, so without the verify it is accepted silently — the chain check is
    // load-bearing for it. countLong/gap/duplicate/overflowPos break position continuity,
    // so the second, independent guard (position-mismatch) must still fire — proving the
    // defense in depth is real, not redundant.
    const noVerify = await parallelScan({ ...common, mirror, skipVerify: true });
    if (name === "countShort") {
      record(`boundary/seed${seed} ${name}-teeth(no-verify-accepts-silently)`, noVerify.rejected.length === 0,
        `rejected=${noVerify.rejected.length} (silent acceptance proves the chain verify is load-bearing)`);
    } else {
      record(`boundary/seed${seed} ${name}-teeth(position-guard-fires-without-verify)`,
        noVerify.rejected.some((r) => r.reason === "position-mismatch"),
        `rejected=${JSON.stringify(noVerify.rejected.map((r) => r.reason))}`);
    }
  }

  // ---- final PARTIAL segment binding: tail served short / long vs the ONE-cert count ----
  for (const [name, delta] of [["tipShort", -3], ["tipLong", +3]]) {
    const gen = (i) => entryAt(Math.min(i, TOTAL - 1)); // tipLong pads with copies of the last entry
    const mirror = {
      total: TOTAL,
      segmentBytes(from, to) {
        const end = Math.min(to, TOTAL);
        const realEnd = end === TOTAL ? TOTAL + delta : end; // only the tail is resized
        const out = new Uint8Array(Math.max(0, realEnd - from) * E);
        for (let i = from; i < realEnd; i++) out.set(gen(i), (i - from) * E);
        return out;
      },
      boundaryProof: (j) => anchor.proofFor(j),
    };
    const run = await parallelScan({ ...common, mirror });
    const tipSeg = Math.floor(TOTAL / DPAGE);
    record(`boundary/seed${seed} ${name}(tip-binding)`,
      run.rejected.some((r) => r.seg === tipSeg && (r.reason === "tip-mismatch" || r.reason === "position-mismatch")),
      `rejected=${JSON.stringify(run.rejected.map((r) => ({ seg: r.seg, reason: r.reason })))}`);
  }

  // ---- cross-certificate mixing: every field of the trusted triple swapped for cert B's ----
  // Cert B: a DIFFERENT stream (one flipped ciphertext byte at position 0 changes every chain value).
  const entryAtB = (i) => { const e = entryAt(i); if (i === 0) { const b = e.slice(); b[9] ^= 0x01; return b; } return e; };
  const anchorB = buildAnchor(entryAtB, TOTAL);
  const mixes = {
    rootFromB: { root: anchorB.root, cTip: anchor.cTip, noteCount: TOTAL, leaf: anchor.leaf },
    cTipFromB: { root: anchor.root, cTip: anchorB.cTip, noteCount: TOTAL, leaf: anchor.leaf },
    leafFromB: { root: anchor.root, cTip: anchor.cTip, noteCount: TOTAL, leaf: anchorB.leaf },
  };
  for (const [name, mixed] of Object.entries(mixes)) {
    let mirrorCalls = 0;
    const countingMirror = { total: TOTAL, segmentBytes(from, to) { mirrorCalls++; return honestMirror.segmentBytes(from, to); }, boundaryProof(j) { mirrorCalls++; return honestMirror.boundaryProof(j); } };
    const run = await parallelScan({ ...common, trusted: mixed, mirror: countingMirror });
    record(`boundary/seed${seed} crossCert-${name}(leaf-binding-rejects-before-traffic)`,
      run.rejected.length === 1 && run.rejected[0].reason === "leaf-binding" && mirrorCalls === 0 && run.notes.length === 0,
      `rejected=${JSON.stringify(run.rejected)} mirrorCalls=${mirrorCalls}`);
  }

  // stale-prefix mix over the SAME honest stream: root from cert A (TOTAL) + cTip/count
  // from cert B' (an earlier, equally honest certificate at TOTAL-1000). Per-segment
  // checks alone accept this silently (teeth below) — only the leaf binding rejects it.
  const PREFIX = TOTAL - 1000;
  const stPrefix = buildStream(entryAt, PREFIX);
  const stale = { root: anchor.root, cTip: stPrefix.cTip, noteCount: PREFIX, leaf: anchor.leaf };
  const staleRun = await parallelScan({ ...common, trusted: stale, total: PREFIX, mirror: honestMirror });
  record(`boundary/seed${seed} crossCert-stalePrefix(rejected)`,
    staleRun.rejected.length === 1 && staleRun.rejected[0].reason === "leaf-binding",
    `rejected=${JSON.stringify(staleRun.rejected)}`);
  // TEETH: binding disabled -> the same mix scans "successfully" at the stale count and
  // silently MISSES the tip-planted note — the under-scan the binding exists to prevent.
  const staleTeeth = await parallelScan({ ...common, trusted: stale, total: PREFIX, mirror: honestMirror, skipLeafBinding: true });
  record(`boundary/seed${seed} crossCert-stalePrefix-teeth(no-binding-underscans)`,
    staleTeeth.rejected.length === 0 && !setPos(staleTeeth.notes).has(8300) && setPos(honest.notes).has(8300),
    `rejected=${staleTeeth.rejected.length} missed_tip_note=${!setPos(staleTeeth.notes).has(8300)}`);

  // consistency guard: detectLeaf really is the binding function (self-check, not a tamper)
  record(`boundary/seed${seed} leafBinding-selfcheck`,
    Buffer.from(detectLeaf(anchor.root, anchor.cTip, TOTAL)).equals(Buffer.from(anchor.leaf)),
    `leaf recomputes from (root, cTip, count)`);
}

const failed = results.filter((r) => !r.ok);
console.log(`\nB-RESTORE-BOUNDARY: ${results.length - failed.length}/${results.length} checks passed`);
if (failed.length) process.exit(1);
