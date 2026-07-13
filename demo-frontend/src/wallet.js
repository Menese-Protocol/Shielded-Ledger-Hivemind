// Shielded-wallet flow logic (Menese DeFi Team).
//
// The wallet's private state is a spend key nk plus an X25519 note-opening key. Authenticated
// accounts derive both ephemerally from a principal-bound vetKey; the old browser-local account
// format is read only long enough to migrate existing demo notes. Everything shown in the UI is
// recovered from PUBLIC chain data plus those in-memory secrets: notes are found by trial-
// decrypting every sealed envelope, ownership is checked by recomputing the note commitment, and
// spent-ness is checked against the public nullifier set. The node provider sees the same log —
// and can open none of it.
import nacl from "tweetnacl";
import { hexToBytes, bytesToHex } from "./ic.js";
import { CANISTERS, BASE } from "./config.js";
import { Principal } from "@dfinity/principal";

export const TOKEN_FEE = 10_000n; // 0.0001 DEMO, charged by the token ledger per approve/transfer
export const SHIELD_OVERHEAD = TOKEN_FEE * 2n; // one approve + one transfer_from
export const UNSHIELD_FEE = TOKEN_FEE; // circuit burn exactly matches the pool's public-ledger fee
const ZERO_FIELD = "00".repeat(32);

function randomBytes(n) {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

// ---- sealed note envelopes (X25519 + XSalsa20-Poly1305, the Zcash "sealed to recipient" idea) ----
// Layout on the wire: ephemeralPk(32) || nonce(24) || box(payload). The whole envelope is what
// the chain (and the node provider) stores — opaque bytes.

export function sealNote(recipientEncPk, note /* {v, rho, rcm} */) {
  const eph = nacl.box.keyPair();
  const nonce = randomBytes(24);
  const payload = new TextEncoder().encode(
    JSON.stringify({ v: note.v.toString(), rho: note.rho, rcm: note.rcm })
  );
  const boxed = nacl.box(payload, nonce, recipientEncPk, eph.secretKey);
  const envelope = new Uint8Array(32 + 24 + boxed.length);
  envelope.set(eph.publicKey, 0);
  envelope.set(nonce, 32);
  envelope.set(boxed, 56);
  return envelope;
}

export function openEnvelope(encSk, envelope) {
  if (envelope.length < 32 + 24 + 16) return null;
  try {
    const ephPk = envelope.slice(0, 32);
    const nonce = envelope.slice(32, 56);
    const boxed = envelope.slice(56);
    const opened = nacl.box.open(boxed, nonce, ephPk, encSk);
    if (!opened) return null;
    const p = JSON.parse(new TextDecoder().decode(opened));
    return { v: BigInt(p.v), rho: p.rho, rcm: p.rcm };
  } catch {
    return null;
  }
}

// ---- transparent side ----

export async function faucet(actors) {
  return actors.token.faucet();
}

export async function tokenBalance(actors, principal) {
  return actors.token.icrc1_balance_of({ owner: principal, subaccount: [] });
}

// Approve the pool canister as spender so shield's transfer_from can pull the deposit.
export async function approvePool(actors, amount) {
  return actors.token.icrc2_approve({
    from_subaccount: [],
    spender: { owner: Principal.fromText(CANISTERS.zk_ledger), subaccount: [] },
    amount,
    expected_allowance: [],
    expires_at: [],
    fee: [],
    memo: [],
    created_at_time: [],
  });
}

// ---- the pool's public log ----

// Read all note records from the ledger's PUBLIC ICRC-3 block log, in position order.
// This is the honest, public part: rebuildable by anyone, including the provider.
export async function readNotes(actors) {
  const status = await actors.ledger.status();
  const total = Number(status.log_length);
  if (total === 0) return [];
  const res = await actors.ledger.icrc3_get_blocks([{ start: 0n, length: BigInt(total) }]);
  const notes = [];
  for (const { id, block } of res.blocks) {
    const map = Object.fromEntries(block.Map);
    const commitment = bytesToHex(new Uint8Array(map.commitment.Blob));
    const position = Number(map.note_position.Nat);
    const origin = map.origin.Text;
    const ciphertext = bytesToHex(new Uint8Array(map.note_ciphertext.Blob));
    const nullifiers = (map.nullifiers?.Array || []).map((v) => bytesToHex(new Uint8Array(v.Blob)));
    notes.push({ id: Number(id), position, commitment, origin, ciphertext, nullifiers });
  }
  notes.sort((a, b) => a.position - b.position);
  return notes;
}

export async function leavesInOrder(actors) {
  const notes = await readNotes(actors);
  return notes.map((n) => n.commitment);
}

// ---- balance discovery: trial-decrypt the whole public log with YOUR key ----
// Returns { notes: owned unspent notes, scanned, opened } — `opened` counts envelopes the key
// fit, before spent-filtering. Each owned note carries everything needed to spend it.
export async function scanNotes(actors, wasm, account /* {nk, pk, encSk} */) {
  const log = await readNotes(actors);
  const candidates = [];
  for (const rec of log) {
    const note = openEnvelope(account.encSk, hexToBytes(rec.ciphertext));
    if (!note) continue;
    // The envelope opened with our key; the commitment proves the note is really addressed to
    // our shielded pk (and that the decrypted amount is the committed amount).
    const cm = wasm.note_commitment_hex(note.v, account.pk, note.rho, note.rcm);
    if (cm !== rec.commitment) continue;
    candidates.push({ ...note, cm, position: rec.position });
  }
  const spent = await Promise.all(
    candidates.map((n) =>
      actors.ledger.is_nullifier_spent(hexToBytes(wasm.note_nullifier_hex(account.nk, n.rho)))
    )
  );
  return {
    notes: candidates.filter((_, i) => !spent[i]),
    scanned: log.length,
    opened: candidates.length,
  };
}

// ---- shield: prove the deposit, approve the pool, deposit. Note sealed to YOURSELF ----
export async function shield(actors, wasm, keys, account, valueE8s) {
  const value = valueE8s;
  const rho = wasm.random_field();
  const rcm = wasm.random_field();
  const dep = JSON.parse(wasm.prove_deposit(keys.deposit, value, account.pk, rho, rcm));

  const approveRes = await approvePool(actors, value + TOKEN_FEE);
  if ("Err" in approveRes) throw new Error("approve failed: " + JSON.stringify(approveRes.Err));

  const args = {
    value,
    from_subaccount: [],
    created_at_time: BigInt(Date.now()) * 1_000_000n,
    client_nonce: randomBytes(32),
    commitment: hexToBytes(dep.cm_hex),
    ephemeral_key: randomBytes(32),
    note_ciphertext: sealNote(account.encPk, { v: value, rho, rcm }),
    proof_hex: dep.proof_hex,
  };
  const res = await actors.ledger.shield(args);
  return { res, cm: dep.cm_hex };
}

// ---- private transfer: two owned notes -> sealed note to ANY registered principal + change ----
// `recipient` is a directory entry: { shielded_pk, enc_pk (hex) }.
export async function privateTransfer(actors, wasm, keys, account, inNotes, recipient, sendE8s, feeE8s) {
  const leaves = await leavesInOrder(actors);
  const in1 = inNotes[0], in2 = inNotes[1];
  const idx1 = leaves.indexOf(in1.cm), idx2 = leaves.indexOf(in2.cm);
  if (idx1 < 0 || idx2 < 0) throw new Error("input note not found in public log");

  const total = in1.v + in2.v;
  const send = sendE8s;
  const fee = feeE8s;
  if (total < send + fee) throw new Error("insufficient shielded balance");
  const change = total - send - fee;

  const out1rcm = wasm.random_field();
  const out2rcm = wasm.random_field();
  const witness = {
    leaves,
    in1: { v: Number(in1.v), nk: account.nk, rho: in1.rho, rcm: in1.rcm, index: idx1 },
    in2: { v: Number(in2.v), nk: account.nk, rho: in2.rho, rcm: in2.rcm, index: idx2 },
    out1: { v: Number(send), pk: recipient.shielded_pk, rcm: out1rcm },
    out2: { v: Number(change), pk: account.pk, rcm: out2rcm },
    fee: Number(fee),
    v_pub_out: 0,
    recipient_binding: ZERO_FIELD,
  };
  const tx = JSON.parse(wasm.prove_transfer(keys.transfer, JSON.stringify(witness)));

  const recipientEncPk = hexToBytes(recipient.enc_pk);
  const args = {
    anchor: hexToBytes(tx.anchor_hex),
    nullifier_1: hexToBytes(tx.nf1_hex),
    nullifier_2: hexToBytes(tx.nf2_hex),
    output_1: {
      commitment: hexToBytes(tx.cm_out1_hex),
      ephemeral_key: randomBytes(32),
      note_ciphertext: sealNote(recipientEncPk, { v: send, rho: tx.out1_rho_hex, rcm: out1rcm }),
    },
    output_2: {
      commitment: hexToBytes(tx.cm_out2_hex),
      ephemeral_key: randomBytes(32),
      note_ciphertext: sealNote(account.encPk, { v: change, rho: tx.out2_rho_hex, rcm: out2rcm }),
    },
    fee,
    v_pub_out: 0n,
    recipient: [],
    created_at_time: [],
    proof_hex: tx.proof_hex,
  };
  const res = await actors.ledger.confidential_transfer(args);
  return { res };
}

// ---- unshield: bind the exact public ICRC account inside the proof, then pay it atomically ----
export async function unshield(actors, wasm, keys, account, inNotes, outE8s) {
  const leaves = await leavesInOrder(actors);
  const in1 = inNotes[0], in2 = inNotes[1];
  const idx1 = leaves.indexOf(in1.cm), idx2 = leaves.indexOf(in2.cm);
  const total = in1.v + in2.v;
  const out = outE8s;
  const fee = UNSHIELD_FEE;
  if (total < out + fee) throw new Error("insufficient shielded balance for withdrawal + privacy fee");
  const change = total - out - fee;
  const recipient = { owner: actors.principal, subaccount: [] };
  const bindingResult = await actors.ledger.recipient_binding(recipient);
  if ("err" in bindingResult) throw new Error("recipient binding failed: " + bindingResult.err);
  const recipientBinding = bytesToHex(new Uint8Array(bindingResult.ok));
  const out1rcm = wasm.random_field();
  const out2rcm = wasm.random_field();
  const witness = {
    leaves,
    in1: { v: Number(in1.v), nk: account.nk, rho: in1.rho, rcm: in1.rcm, index: idx1 },
    in2: { v: Number(in2.v), nk: account.nk, rho: in2.rho, rcm: in2.rcm, index: idx2 },
    out1: { v: 0, pk: account.pk, rcm: out1rcm },
    out2: { v: Number(change), pk: account.pk, rcm: out2rcm },
    fee: Number(fee),
    v_pub_out: Number(out),
    recipient_binding: recipientBinding,
  };
  const tx = JSON.parse(wasm.prove_transfer(keys.transfer, JSON.stringify(witness)));
  const mkOut = (cmHex, value, rho, rcm) => ({
    commitment: hexToBytes(cmHex),
    ephemeral_key: randomBytes(32),
    note_ciphertext: sealNote(account.encPk, { v: value, rho, rcm }),
  });
  const createdAt = BigInt(Date.now()) * 1_000_000n;
  const args = {
    anchor: hexToBytes(tx.anchor_hex),
    nullifier_1: hexToBytes(tx.nf1_hex),
    nullifier_2: hexToBytes(tx.nf2_hex),
    output_1: mkOut(tx.cm_out1_hex, 0n, tx.out1_rho_hex, out1rcm),
    output_2: mkOut(tx.cm_out2_hex, change, tx.out2_rho_hex, out2rcm),
    fee,
    v_pub_out: out,
    recipient: [recipient],
    created_at_time: [createdAt],
    proof_hex: tx.proof_hex,
  };
  return actors.ledger.confidential_transfer(args);
}

// ---- PIR: private note lookup. Encrypted selectors leave the browser; NO index is ever sent ----
export async function pirLookup(actors, wasm, targetIndex, recordCount) {
  const sk = wasm.pir_keygen();
  const selectorsJson = wasm.pir_selectors(sk, targetIndex, recordCount);
  const parsed = JSON.parse(selectorsJson);
  const selectors = parsed.map((s) => ({
    a: s.a.map((x) => BigInt(x)),
    b: BigInt(s.b),
  }));
  const selectorPreview = parsed[0].a.slice(0, 6);
  const resp = await actors.ledger.pir_query_lwe({ selectors });
  // candid `vec nat64` decodes to a BigUint64Array; .map on a typed array coerces back to BigInt,
  // so use Array.from to get real strings the wasm JSON parser accepts.
  const wire = resp.ciphertexts.map((c) => ({
    a: Array.from(c.a, (x) => x.toString()),
    b: c.b.toString(),
  }));
  const recovered = wasm.pir_decrypt(sk, JSON.stringify(wire));
  const trace = Object.fromEntries(Object.entries(resp.trace).map(([k, v]) => [k, Number(v)]));
  return { recovered, trace, selectorPreview, snapshotRoot: bytesToHex(new Uint8Array(resp.snapshot_root)) };
}

// ---- directory ----
export async function registerInDirectory(actors, account, encPkHex) {
  return actors.directory.register(account.pk, encPkHex);
}
export async function lookupPrincipal(actors, principalText) {
  const res = await actors.directory.lookup(Principal.fromText(principalText));
  return res.length ? res[0] : null;
}
