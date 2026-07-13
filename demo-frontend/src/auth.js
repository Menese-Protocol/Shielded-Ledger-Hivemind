// Identity + key management for the demo (Menese DeFi Team).
//
// Two ways in: Internet Identity (id.ai) — your real, stable ICP principal — or a throwaway
// identity generated in-tab for instant trying. For authenticated accounts, the directory asks
// the IC's vetKey system for a deterministic principal-bound key encrypted to a fresh one-use
// browser transport key. The browser verifies it and derives the spend/note-opening keys in
// memory. The II/passkey private key is never exported, and no shielded secret is persisted.
import { AuthClient } from "@dfinity/auth-client";
import { Ed25519KeyIdentity } from "@dfinity/identity";
import { DerivedPublicKey, EncryptedVetKey, TransportSecretKey } from "@dfinity/vetkeys";
import nacl from "tweetnacl";

const II_URL = "https://id.ai";
const SESSION_TTL_NS = BigInt(8 * 60 * 60) * 1_000_000_000n; // 8 hours

let authClient = null;

export async function getAuthClient() {
  if (!authClient) authClient = await AuthClient.create();
  return authClient;
}

// Resolves to the II identity if a valid session exists, else null.
export async function existingSession() {
  const client = await getAuthClient();
  if (await client.isAuthenticated()) return client.getIdentity();
  return null;
}

export async function loginWithInternetIdentity() {
  const client = await getAuthClient();
  await new Promise((resolve, reject) =>
    client.login({
      identityProvider: II_URL,
      maxTimeToLive: SESSION_TTL_NS,
      onSuccess: resolve,
      onError: (e) => reject(new Error(e || "Internet Identity sign-in was cancelled")),
    })
  );
  return client.getIdentity();
}

export async function logout() {
  const client = await getAuthClient();
  await client.logout();
}

export function throwawayIdentity(seed) {
  return Ed25519KeyIdentity.generate(seed);
}

// Instant-demo accounts deliberately have no recovery promise: random keys live only for the
// current tab and never consume a network vetKey derivation. II sessions use the deterministic
// vetKey path below.
export function ephemeralShieldedAccountFor(wasm) {
  const nk = wasm.random_field();
  const pair = nacl.box.keyPair();
  return {
    nk,
    pk: wasm.shielded_address(nk),
    encPk: pair.publicKey,
    encSk: pair.secretKey,
    custody: "throwaway-memory",
  };
}

// ---- shielded account keys ----

const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const storageKey = (principalText) => `picp-demo-keys:${principalText}`;

// Legacy demo account loader. It exists only to migrate notes created by the original frontend;
// new accounts never write shielded secrets to localStorage.
export function legacyShieldedAccountFor(wasm, principalText) {
  const raw = localStorage.getItem(storageKey(principalText));
  if (!raw) return null;
  try {
    const saved = JSON.parse(raw);
    const pair = nacl.box.keyPair.fromSecretKey(unb64(saved.encSk));
    return {
      nk: saved.nk,
      pk: wasm.shielded_address(saved.nk),
      encPk: pair.publicKey,
      encSk: pair.secretKey,
      custody: "legacy-localStorage",
    };
  } catch {
    return null;
  }
}

// Inventory old demo accounts on this origin. This also recovers the important case where notes
// were made with a throwaway principal that disappeared on reload: possession of the note spend
// key, not possession of that obsolete public principal, authorizes the private migration.
export function legacyShieldedAccounts(wasm) {
  return Object.keys(localStorage)
    .filter((key) => key.startsWith("picp-demo-keys:"))
    .map((key) => {
      const principalText = key.slice("picp-demo-keys:".length);
      return { principalText, account: legacyShieldedAccountFor(wasm, principalText) };
    })
    .filter((entry) => entry.account);
}

export function forgetLegacyShieldedAccount(principalText) {
  localStorage.removeItem(storageKey(principalText));
}

const asBytes = (value) => new Uint8Array(value);

// Recover the same account on any device authenticated as the same principal. The transport
// secret and derived seeds are deliberately ephemeral; only public keys are returned on-chain.
export async function vetkeyShieldedAccountFor(wasm, actors) {
  const input = asBytes(actors.principal.toUint8Array());
  const transport = TransportSecretKey.random();
  const [publicKeyWire, encryptedResult] = await Promise.all([
    actors.directory.vetkey_public_key(),
    actors.directory.derive_shielded_key(transport.publicKeyBytes()),
  ]);
  if ("err" in encryptedResult) {
    throw new Error("vetKey derivation failed: " + encryptedResult.err);
  }

  const derivedPublicKey = DerivedPublicKey.deserialize(asBytes(publicKeyWire));
  const encryptedVetKey = EncryptedVetKey.deserialize(asBytes(encryptedResult.ok));
  const vetKey = encryptedVetKey.decryptAndVerify(transport, derivedPublicKey, input);
  const nkSeed = vetKey.deriveSymmetricKey("picp-shielded-account/nk/v1", 64);
  const encSeed = vetKey.deriveSymmetricKey("picp-shielded-account/x25519/v1", 32);
  try {
    const nk = wasm.field_from_seed(nkSeed);
    const pair = nacl.box.keyPair.fromSecretKey(encSeed);
    return {
      nk,
      pk: wasm.shielded_address(nk),
      encPk: pair.publicKey,
      encSk: pair.secretKey,
      custody: "ii-vetkey",
    };
  } finally {
    nkSeed.fill(0);
    encSeed.fill(0);
  }
}

export const encPkHex = (encPk) => Array.from(encPk, (b) => b.toString(16).padStart(2, "0")).join("");
