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
import { CANISTERS, BASE, HOST, VIEW_TAG_ENABLED, VIEW_TAG_CUTOVER, BLOCKS_PER_PAGE } from "./config.js";
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
// Two wire layouts, both opaque to the chain:
//   legacy : ephPk(32) || nonce(24) || box
//   tagged : ephPk(32) || tag(8)   || nonce(24) || box     (Zcash NU5-style view tag)
// tag = H("picp-note-viewtag/v1" || shared)[0..8], where `shared` is the X25519→HSalsa20 shared
// key from nacl.box.before. The tag lets a scanner recognize its own new-format notes from 8 bytes
// (the compact detection stream) without a full box-open. The READ path auto-detects both layouts
// unconditionally; only WRITING the tagged layout is gated (VIEW_TAG_ENABLED). H is SHA-512
// (nacl.hash) truncated — collision/preimage-resistant and already in-bundle.
const VIEW_TAG_DOMAIN = new TextEncoder().encode("picp-note-viewtag/v1");
export const VIEW_TAG_LEN = 8;

function viewTag(shared) {
  const buf = new Uint8Array(VIEW_TAG_DOMAIN.length + shared.length);
  buf.set(VIEW_TAG_DOMAIN, 0);
  buf.set(shared, VIEW_TAG_DOMAIN.length);
  return nacl.hash(buf).slice(0, VIEW_TAG_LEN);
}

function encodeNote(note) {
  return new TextEncoder().encode(
    JSON.stringify({ v: note.v.toString(), rho: note.rho, rcm: note.rcm })
  );
}
function decodeNote(opened) {
  const p = JSON.parse(new TextDecoder().decode(opened));
  return { v: BigInt(p.v), rho: p.rho, rcm: p.rcm };
}
const bytesEqual = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

export function sealNote(recipientEncPk, note /* {v, rho, rcm} */, { viewTag: withTag = VIEW_TAG_ENABLED } = {}) {
  const eph = nacl.box.keyPair();
  const nonce = randomBytes(24);
  const payload = encodeNote(note);
  // Derive the ECDH shared key ONCE (nacl.box == before+after, so viewTag=false stays byte-identical
  // to the legacy envelope), reuse it for the box and the tag.
  const shared = nacl.box.before(recipientEncPk, eph.secretKey);
  const boxed = nacl.box.after(payload, nonce, shared);
  if (withTag) {
    const tag = viewTag(shared);
    const envelope = new Uint8Array(32 + VIEW_TAG_LEN + 24 + boxed.length);
    envelope.set(eph.publicKey, 0);
    envelope.set(tag, 32);
    envelope.set(nonce, 32 + VIEW_TAG_LEN);
    envelope.set(boxed, 32 + VIEW_TAG_LEN + 24);
    return envelope;
  }
  const envelope = new Uint8Array(32 + 24 + boxed.length);
  envelope.set(eph.publicKey, 0);
  envelope.set(nonce, 32);
  envelope.set(boxed, 56);
  return envelope;
}

// Auto-detect old/new format. The X25519 ECDH is derived exactly ONCE (nacl.box.before) and reused
// by the tag check and both open attempts. Poly1305 authentication (nacl.box.open.after → null on
// failure) is the arbiter: a wrong-format parse cannot authenticate to wrong plaintext, so trying
// the tagged layout first and falling back to legacy is always correct.
export function openEnvelope(encSk, envelope) {
  if (envelope.length < 32 + 24 + 16) return null;
  try {
    const ephPk = envelope.slice(0, 32);
    const shared = nacl.box.before(ephPk, encSk);
    // tagged layout (only if long enough to hold tag + a minimal box)
    if (envelope.length >= 32 + VIEW_TAG_LEN + 24 + 16) {
      const tag = envelope.slice(32, 32 + VIEW_TAG_LEN);
      if (bytesEqual(tag, viewTag(shared))) {
        const nonce = envelope.slice(32 + VIEW_TAG_LEN, 32 + VIEW_TAG_LEN + 24);
        const boxed = envelope.slice(32 + VIEW_TAG_LEN + 24);
        const opened = nacl.box.open.after(boxed, nonce, shared);
        if (opened) return decodeNote(opened);
        // tag matched but box failed (corrupt/forged): fall through to the legacy interpretation
      }
    }
    // legacy layout
    const nonce = envelope.slice(32, 56);
    const boxed = envelope.slice(56);
    const opened = nacl.box.open.after(boxed, nonce, shared);
    if (!opened) return null;
    return decodeNote(opened);
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

// Read note records from the ledger's PUBLIC ICRC-3 block log, in position order, over [from, to).
// The ledger caps a single `icrc3_get_blocks` response at 512 blocks TOTAL across all ranges
// (src/Main.mo:1573,1583), so a whole-log fetch MUST paginate: this issues one page-aligned,
// SINGLE-range call per 512-block page (concurrently). Single-range keeps each call under the cap
// (a multi-range call would share the cap and re-truncate); page-alignment keeps the request
// transcript indistinguishable from ordinary paging (B-P5 privacy assertion). `to` is pinned by the
// caller (from one status() read) so the fetched leaf set is a frozen prefix that matches a
// historical Merkle root even under concurrent appends.
export async function readNotes(actors, { from = 0, to = null } = {}) {
  const total = to != null ? to : Number((await actors.ledger.status()).log_length);
  if (total <= from) return [];
  const PAGE = BLOCKS_PER_PAGE;
  const starts = [];
  for (let s = Math.floor(from / PAGE) * PAGE; s < total; s += PAGE) starts.push(s);
  const pages = await Promise.all(
    starts.map((s) =>
      actors.ledger.icrc3_get_blocks([{ start: BigInt(s), length: BigInt(Math.min(PAGE, total - s)) }])
    )
  );
  const notes = [];
  for (const res of pages) {
    for (const { id, block } of res.blocks) {
      const map = Object.fromEntries(block.Map);
      const position = Number(map.note_position.Nat);
      if (position < from || position >= total) continue;
      notes.push({
        id: Number(id),
        position,
        commitment: bytesToHex(new Uint8Array(map.commitment.Blob)),
        origin: map.origin.Text,
        ciphertext: bytesToHex(new Uint8Array(map.note_ciphertext.Blob)),
        nullifiers: (map.nullifiers?.Array || []).map((v) => bytesToHex(new Uint8Array(v.Blob))),
        // note_root_after anchors the encrypted local cache to the chain (D8); available on the
        // wire (NoteAudit.blockValue) — parsed here, may be absent on a minimal mock.
        noteRootAfter: map.note_root_after ? bytesToHex(new Uint8Array(map.note_root_after.Blob)) : null,
      });
    }
  }
  notes.sort((a, b) => a.position - b.position);
  return notes;
}

// Every commitment leaf, in position order — the Merkle-tree order that spend proofs index into.
// Pins `to` once so the leaf set is a consistent prefix (matches a historical root).
export async function leavesInOrder(actors) {
  const total = Number((await actors.ledger.status()).log_length);
  const notes = await readNotes(actors, { from: 0, to: total });
  return notes.map((n) => n.commitment);
}

// A wallet's birthday is the ledger log length at account creation — a note created before the
// wallet existed cannot be its own, so first sync scans [birthday, tip] instead of from genesis.
// New accounts persist this alongside the seed; a seed restore without a stored birthday falls back
// to a full-history scan (birthday 0).
export async function recordBirthday(actors) {
  return Number((await actors.ledger.status()).log_length);
}

// Spent-nullifier set built LOCALLY from the public log's nullifier fields — the union of every
// block's nullifiers EQUALS the canister's spent set (each nullifier is added via addNullifier in
// lock-step with the appendBlock that carries it — src/Main.mo:526,1907-1914,2147-2154). Computing
// spent-ness locally removes the per-owned-note `is_nullifier_spent` point queries, which would
// otherwise tell the node provider exactly which and how many notes the session owns.
function spentSetFrom(records) {
  const spent = new Set();
  for (const rec of records) for (const nf of rec.nullifiers) spent.add(nf);
  return spent;
}

// ---- balance discovery: trial-decrypt the log tail with YOUR key ----
// Scans only [max(birthday, cursor), tip] (P1 cursor + P2 birthday) and merges previously-discovered
// `cachedNotes`. Ownership is proven by recomputing the commitment; spent-ness is decided
// LOCALLY (no nullifier queries). Returns owned-unspent notes plus the new cursor (= tip).
export async function scanNotes(actors, wasm, account /* {nk, pk, encSk} */, opts = {}) {
  const { birthday = 0, cursor = 0, cachedNotes = [] } = opts;
  const total = Number((await actors.ledger.status()).log_length);
  const from = Math.max(birthday, cursor);
  const tail = await readNotes(actors, { from, to: total });
  const candidates = [];
  for (const rec of tail) {
    const note = openEnvelope(account.encSk, hexToBytes(rec.ciphertext));
    if (!note) continue;
    // The envelope opened with our key; the commitment proves the note is really addressed to our
    // shielded pk (and that the decrypted amount is the committed amount).
    const cm = wasm.note_commitment_hex(note.v, account.pk, note.rho, note.rcm);
    if (cm !== rec.commitment) continue;
    candidates.push({ ...note, cm, position: rec.position });
  }
  // A cached note (unspent as of `cursor`) can only be newly spent by a nullifier in the tail; a
  // tail note's spend cannot appear below its own creation. So the tail's nullifiers suffice.
  const spent = spentSetFrom(tail);
  const merged = [...cachedNotes, ...candidates];
  const notes = merged.filter((n) => !spent.has(wasm.note_nullifier_hex(account.nk, n.rho)));
  return { notes, scanned: tail.length, opened: candidates.length, cursor: total };
}

// ---- P3: compact detection stream + view-tag RECOGNITION ----
// Detection is Ω(N) by privacy design (no recipient index is allowed to exist). This streams
// 48 B/note `(position||ephPk||tag)` — ~12× less than full ~588 B blocks — and spends ONE ECDH +
// one tag compare per note, full-fetching only the PAGES that contain a candidate. Fetches are
// 512-aligned full pages (full-page camouflage) so the request transcript never isolates an owned
// position; the residual page-set leak is what PIR closes (retrieveMatchedPage is the seam it
// replaces). Below the format cutover (legacy notes may be tag-less) whole pages are opened rather
// than trusting the tag, so recognition never misses a legacy note. This is a RECOGNITION path: it
// returns the owned set (envelope opens + commitment matches), the same set a full trial-decrypt
// finds; spent-filtering for a spendable balance is scanNotes' job (it holds the full tail).
export async function detectionScan(actors, wasm, account, opts = {}) {
  const { birthday = 0, cursor = 0, cutover = VIEW_TAG_CUTOVER } = opts;
  const total = Number((await actors.ledger.status()).log_length);
  const from = Math.max(birthday, cursor);
  if (total <= from) return { notes: [], scanned: 0, matchedPages: [] };
  const PAGE = BLOCKS_PER_PAGE;
  // Effective cutover: at/above it, notes are guaranteed new-format so the tag is trustworthy;
  // below it, full-open. null ⇒ full-open everything (never-miss default, no tag trust).
  const eff = cutover == null ? total : cutover;
  const matchedPages = new Set();
  const pageOf = (p) => Math.floor(p / PAGE) * PAGE;

  for (let s = Math.floor(from / PAGE) * PAGE; s < total; s += PAGE) {
    const count = Math.min(PAGE, total - s);
    if (s + count <= eff) {
      // page entirely in the legacy region → must full-open it (tag not trustworthy)
      matchedPages.add(s);
      continue;
    }
    const packed = new Uint8Array(await actors.ledger.detection_stream(BigInt(s), BigInt(count)));
    for (let off = 0; off + 48 <= packed.length; off += 48) {
      let pos = 0;
      for (let k = 0; k < 8; k++) pos = pos * 256 + packed[off + k];
      if (pos < from) continue;
      if (pos < eff) {
        matchedPages.add(pageOf(pos)); // legacy note → open its page
        continue;
      }
      const ephPk = packed.slice(off + 8, off + 40);
      const tag = packed.slice(off + 40, off + 48);
      const shared = nacl.box.before(ephPk, account.encSk);
      if (bytesEqual(tag, viewTag(shared))) matchedPages.add(pageOf(pos));
    }
  }
  // Retrieve matched pages (camouflaged) and recognize owned notes.
  const notes = [];
  for (const ps of [...matchedPages].sort((a, b) => a - b)) {
    const page = await retrieveMatchedPage(actors, ps, Math.min(ps + PAGE, total));
    for (const rec of page) {
      if (rec.position < from) continue;
      const note = openEnvelope(account.encSk, hexToBytes(rec.ciphertext));
      if (!note) continue;
      const cm = wasm.note_commitment_hex(note.v, account.pk, note.rho, note.rcm);
      if (cm !== rec.commitment) continue;
      notes.push({ ...note, cm, position: rec.position });
    }
  }
  return { notes, scanned: total - from, matchedPages: [...matchedPages].sort((a, b) => a - b) };
}

// The private-retrieval seam. Today: fetch the whole 512-aligned page containing a match
// (indistinguishable from paging at page granularity). PIR replaces this one function with a
// private single-record fetch, closing the residual page-set leak. MUST stay page-aligned — a
// position-targeted fetch here would deanonymize the owned note.
export async function retrieveMatchedPage(actors, pageStart, pageEnd) {
  return readNotes(actors, { from: pageStart, to: pageEnd });
}

// ---- P4: encrypted local cache (IndexedDB), sealed under the vetKey session ----
// Discovered notes + cursor + birthday persist sealed with XSalsa20-Poly1305 (nacl.secretbox)
// under a key derived from the principal-bound vetKey session (account.cacheKey). Nothing plaintext
// at rest. Throwaway accounts (custody ≠ ii-vetkey, or no cacheKey) write NOTHING — their custody
// model is ephemerality. The cache is bound to the ledger canister id + host AND to a chain anchor
// (note_root_after at the cursor): on load, a canister/host/anchor mismatch or a rewind
// (log_length < cursor) discards the cache and forces a full rescan — a validly-sealed-but-stale
// cache can never yield a wrong balance.
const CACHE_KEY = "picp-readpath-cache/v1";
const serializeNote = (n) => ({ v: n.v.toString(), rho: n.rho, rcm: n.rcm, cm: n.cm, position: n.position });
const deserializeNote = (n) => ({ v: BigInt(n.v), rho: n.rho, rcm: n.rcm, cm: n.cm, position: n.position });

function cacheable(account) {
  return account.custody === "ii-vetkey" && account.cacheKey instanceof Uint8Array && account.cacheKey.length === 32;
}

// Anchor = note_root_after of the last block below the cursor (the chain state the cache reflects).
async function anchorAt(actors, cursor) {
  if (cursor <= 0) return "genesis";
  const page = await readNotes(actors, { from: cursor - 1, to: cursor });
  const rec = page.find((r) => r.position === cursor - 1);
  return rec && rec.noteRootAfter ? rec.noteRootAfter : null;
}

export async function saveCache(actors, account, { notes, cursor, birthday }, store) {
  if (!cacheable(account) || !store) return false;
  const anchor = await anchorAt(actors, cursor);
  const record = {
    canisterId: CANISTERS.zk_ledger,
    host: HOST,
    cursor,
    birthday,
    anchor,
    notes: notes.map(serializeNote),
  };
  const plaintext = new TextEncoder().encode(JSON.stringify(record));
  const nonce = randomBytes(24);
  const boxed = nacl.secretbox(plaintext, nonce, account.cacheKey);
  const blob = new Uint8Array(24 + boxed.length);
  blob.set(nonce, 0);
  blob.set(boxed, 24);
  await store.set(CACHE_KEY, blob);
  return true;
}

// Returns { notes, cursor, birthday } on a fresh, authenticated, chain-consistent cache; null
// (⇒ caller rescans from birthday) on any absence / auth failure / staleness.
export async function loadCache(actors, account, store) {
  if (!cacheable(account) || !store) return null;
  const blob = await store.get(CACHE_KEY);
  if (!blob || blob.length < 24 + 16) return null;
  const nonce = blob.slice(0, 24);
  const boxed = blob.slice(24);
  const opened = nacl.secretbox.open(boxed, nonce, account.cacheKey);
  if (!opened) return null; // corrupt / poisoned / wrong key
  let record;
  try {
    record = JSON.parse(new TextDecoder().decode(opened));
  } catch {
    return null;
  }
  if (record.canisterId !== CANISTERS.zk_ledger || record.host !== HOST) return null; // different ledger/network
  const total = Number((await actors.ledger.status()).log_length);
  if (total < record.cursor) return null; // rewind / reinstall
  const anchor = await anchorAt(actors, record.cursor);
  if (anchor !== record.anchor) return null; // fork / divergent chain at the cursor
  return { notes: record.notes.map(deserializeNote), cursor: record.cursor, birthday: record.birthday };
}

// One-call wallet sync: load the encrypted cache if present, scan only the tail past the
// cursor, persist the updated cache. A cache miss / stale cache falls back to a scan from `birthday`
// (or genesis). Returns owned-unspent notes and the new cursor.
export async function syncWallet(actors, wasm, account, { store = null, birthday = 0 } = {}) {
  const cached = store ? await loadCache(actors, account, store) : null;
  const cursor = cached ? cached.cursor : 0;
  const bday = cached ? cached.birthday : birthday;
  const cachedNotes = cached ? cached.notes : [];
  const scan = await scanNotes(actors, wasm, account, { birthday: bday, cursor, cachedNotes });
  if (store) await saveCache(actors, account, { notes: scan.notes, cursor: scan.cursor, birthday: bday }, store);
  return { notes: scan.notes, cursor: scan.cursor, fromCache: !!cached };
}

// IndexedDB-backed store for the browser; tests inject their own {get,set,delete}. Kept tiny and
// dependency-free.
export function indexedDbStore(dbName = "picp-readpath", storeName = "cache") {
  const open = () =>
    new Promise((resolve, reject) => {
      const req = indexedDB.open(dbName, 1);
      req.onupgradeneeded = () => req.result.createObjectStore(storeName);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  const tx = async (mode, fn) => {
    const db = await open();
    return new Promise((resolve, reject) => {
      const t = db.transaction(storeName, mode);
      const os = t.objectStore(storeName);
      const r = fn(os);
      t.oncomplete = () => resolve(r.result);
      t.onerror = () => reject(t.error);
    });
  };
  return {
    get: (k) => tx("readonly", (os) => os.get(k)),
    set: (k, v) => tx("readwrite", (os) => os.put(v, k)),
    delete: (k) => tx("readwrite", (os) => os.delete(k)),
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
