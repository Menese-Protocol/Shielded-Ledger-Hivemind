// Deterministic circuit-crypto shim for the read-path battery (Menese DeFi Team).
//
// The read-path battery exercises pagination / view tags / cursor / cache. The note COMMITMENT and
// NULLIFIER are Groth16 circuit outputs — OUT of the read path's scope — so this shim replaces the
// prover-wasm's `note_commitment_hex` / `note_nullifier_hex` / `shielded_address` / `random_field`
// with deterministic SHA-256 stand-ins. It is used SYMMETRICALLY: the corpus builder seals notes
// with exactly these functions and the scanner recomputes with them, so ownership/spent round-trip
// is exact and no read-path bug can hide behind the shim. The ENVELOPE crypto (nacl.box / X25519 +
// XSalsa20-Poly1305) is the REAL tweetnacl, never shimmed — that is what the read path depends on.

import { createHash, randomBytes } from "node:crypto";

const h = (...parts) => {
  const d = createHash("sha256");
  for (const p of parts) d.update(typeof p === "string" ? Buffer.from(p, "utf8") : Buffer.from(p));
  return d.digest();
};
const hex = (buf) => Buffer.from(buf).toString("hex");

export const wasmShim = {
  // A field element is a 32-byte hex string (matches the frontend's hex-field convention).
  random_field: () => hex(randomBytes(32)),
  field_from_seed: (seed) => hex(h("field-from-seed", Buffer.from(seed))),
  // pk is bound to nk (spend key).
  shielded_address: (nk) => hex(h("shielded-address/v1", nk)),
  // commitment binds (value, pk, rho, rcm) — the scanner recomputes and compares to the block.
  note_commitment_hex: (v, pk, rho, rcm) =>
    hex(h("note-commitment/v1", String(v), pk, rho, rcm)),
  // nullifier binds (nk, rho) — a spend reveals it; membership decides spent-ness.
  note_nullifier_hex: (nk, rho) => hex(h("note-nullifier/v1", nk, rho)),
};

// Build a shielded account of the same shape wallet.js expects: {nk, pk, encPk, encSk, custody}.
// `nacl` is passed in so the battery uses the same tweetnacl instance everywhere.
export function makeAccount(nacl, seedByte, custody = "ii-vetkey") {
  const nk = hex(h("nk-seed", Uint8Array.of(seedByte)));
  const pair = nacl.box.keyPair.fromSecretKey(h("enc-seed", Uint8Array.of(seedByte)));
  const account = {
    nk,
    pk: wasmShim.shielded_address(nk),
    encPk: pair.publicKey,
    encSk: pair.secretKey,
    custody,
  };
  // Only vetKey-backed accounts get a persistent cache key (throwaway accounts stay memory-only)
  // and a birthday key (distinct derivation, mirroring the /cache/v1 vs /birthday/v1 info-string
  // domain separation in auth.js).
  if (custody === "ii-vetkey") {
    account.cacheKey = new Uint8Array(h("cache-seed", Uint8Array.of(seedByte)));
    account.birthdayKey = new Uint8Array(h("birthday-seed", Uint8Array.of(seedByte)));
    account.principalText = `mock-principal-${seedByte}`;
  }
  return account;
}

// A simple in-memory {get,set,delete} store standing in for IndexedDB in the node battery.
export function memStore() {
  const m = new Map();
  return {
    _m: m,
    get: async (k) => m.get(k),
    set: async (k, v) => void m.set(k, v),
    delete: async (k) => void m.delete(k),
  };
}
