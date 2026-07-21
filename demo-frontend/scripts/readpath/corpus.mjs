// Corpus builder + independent ground-truth oracle for the read-path battery (Menese DeFi Team).
//
// Builds a MockLedger populated with REAL nacl.box envelopes for a set of accounts, with owned and
// unowned notes, old/new envelope formats, and spends (a spent note's nullifier is planted on a
// later block, exactly as confidential_transfer does — src/Main.mo:2153-2154). The genesis oracle
// is deliberately INDEPENDENT of the wallet's scan logic: it reads every record straight from the
// ledger store (bypassing pagination) and opens it, so "wallet scan == oracle" is a true
// differential over the scan/pagination/tag/cursor logic under test.

import { MockLedger } from "./mock-ledger.mjs";
import { wasmShim } from "./shim.mjs";

// A "seal function" maps (recipientEncPk, note, format) -> envelope Uint8Array. The battery passes
// the wallet's real sealNote (old) or sealNoteTagged (new).
export async function buildCorpus(
  nacl,
  { seed = 1, noteCount = 1200, accounts, sealFn, newFormatFrom = Infinity, spendEvery = 0, births = null } = {}
) {
  // births[k] = the position at/after which account k can own notes (its wallet birthday). A note
  // before an account's birthday cannot be its own — the account did not exist yet.
  const birth = births ?? accounts.map(() => 0);
  const ledger = new MockLedger();
  // Deterministic PRNG (seeded) so runs are reproducible across the required 2 seeds.
  let state = (seed * 2654435761) >>> 0;
  const rnd = () => ((state = (state * 1103515245 + 12345) >>> 0), state / 0xffffffff);
  const pick = (arr) => arr[Math.floor(rnd() * arr.length) % arr.length];

  const owned = []; // notes owned by a battery account, in creation order
  const planted = []; // {position, owner, v, rho, rcm, spent}

  for (let position = 0; position < noteCount; position++) {
    // ~60% of notes are owned by one of the battery accounts, ~40% are noise (unowned). An account
    // can only own notes at/after its birthday.
    let ownerIdx = rnd() < 0.6 ? Math.floor(rnd() * accounts.length) % accounts.length : -1;
    if (ownerIdx >= 0 && position < birth[ownerIdx]) ownerIdx = -1;
    const isNew = position >= newFormatFrom;
    const v = BigInt(1 + Math.floor(rnd() * 1_000_000));
    const rho = wasmShim.random_field();
    const rcm = wasmShim.random_field();

    let recipientEncPk;
    let owner = null;
    if (ownerIdx >= 0) {
      owner = accounts[ownerIdx];
      recipientEncPk = owner.encPk;
    } else {
      // noise note sealed to a throwaway key nobody in the test set holds
      recipientEncPk = nacl.box.keyPair().publicKey;
    }
    const commitment = Buffer.from(wasmShim.note_commitment_hex(v, owner ? owner.pk : "noise", rho, rcm), "hex");
    const ciphertext = sealFn(recipientEncPk, { v, rho, rcm }, isNew);

    // Occasionally spend an earlier owned note: plant its nullifier on THIS block.
    const nullifiers = [];
    if (spendEvery > 0 && owned.length > 0 && position % spendEvery === 0) {
      const victim = pick(owned.filter((o) => !o.spent));
      if (victim) {
        victim.spent = true;
        nullifiers.push(Buffer.from(wasmShim.note_nullifier_hex(victim.owner.nk, victim.rho), "hex"));
      }
    }

    await ledger.append({
      commitment: new Uint8Array(commitment),
      origin: nullifiers.length ? "confidential_transfer" : "shield",
      ephemeralKey: new Uint8Array(32),
      ciphertext,
      nullifiers,
    });

    const note = { position, owner, v, rho, rcm, spent: false };
    planted.push(note);
    if (owner) owned.push(note);
  }
  return { ledger, planted, owned };
}

// Ground-truth owned-unspent set for `account`, computed by an exhaustive genesis walk that is
// independent of the wallet's pagination. `openFn(encSk, envelope)` is the wallet's real
// openEnvelope (old or auto-detecting). Returns a Set of "position:value" strings + the raw list.
export function genesisScanOracle(ledger, account, openFn) {
  // Spent set = union of every block's nullifiers (D9 invariant; matches soak/src/scan.rs).
  const spent = new Set();
  for (const rec of ledger.records) {
    for (const nf of rec.nullifiers) spent.add(Buffer.from(nf).toString("hex"));
  }
  const notes = []; // owned-unspent (balance)
  const recognized = []; // owned regardless of spent (recognition — for B-P3 detection differential)
  for (const rec of ledger.records) {
    const note = openFn(account.encSk, rec.ciphertext);
    if (!note) continue;
    const cm = wasmShim.note_commitment_hex(note.v, account.pk, note.rho, note.rcm);
    if (cm !== Buffer.from(rec.commitment).toString("hex")) continue; // ownership proof
    recognized.push({ position: rec.position, v: note.v });
    const nf = wasmShim.note_nullifier_hex(account.nk, note.rho);
    if (spent.has(nf)) continue;
    notes.push({ position: rec.position, v: note.v });
  }
  return {
    set: new Set(notes.map((n) => `${n.position}:${n.v}`)),
    notes,
    recognizedSet: new Set(recognized.map((n) => `${n.position}:${n.v}`)),
    recognized,
  };
}
