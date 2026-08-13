// Keyset ↔ on-chain anchor binding.
//
// Run: node demo-frontend/tests/keyset-anchor.test.mjs
//
// The case that matters is the COHERENT FIVE-FILE SWAP: an attacker who controls the served
// assets replaces transfer_pk, deposit_pk, transfer_vk, deposit_vk AND SETUP-MANIFEST.json with
// a mutually consistent set of their own. Every same-origin hash check passes. Only a comparison
// against canister state can reject it, because canister state is the one thing the attacker
// serving the page cannot rewrite.
//
// The RED leg reproduces the pre-fix algorithm verbatim (transcribed from ffb582a
// demo-frontend/src/prover.js) and shows it ACCEPTS the swap. The GREEN leg runs the shipped
// loadKeyset and shows it REJECTS it. A test never shown failing proves nothing.

import { loadKeyset, anchorDigestHex } from "../src/keyset.js";

let pass = 0, fail = 0;
const ok = (name) => { pass++; console.log(`  PASS  ${name}`); };
const bad = (name, expected, actual) => {
  fail++; console.log(`  FAIL  ${name}`);
  console.log(`        expected: ${expected}`); console.log(`        actual:   ${actual}`);
};
async function rejects(name, fn, mustContain) {
  try { await fn(); bad(name, `throws containing "${mustContain}"`, "resolved successfully"); }
  catch (e) {
    if (String(e.message).includes(mustContain)) ok(name);
    else bad(name, `message containing "${mustContain}"`, e.message);
  }
}
async function resolves(name, fn) {
  try { const v = await fn(); ok(name); return v; }
  catch (e) { bad(name, "resolves", `threw: ${e.message}`); return null; }
}

const enc = new TextEncoder();
const sha256Hex = async (bytes) =>
  [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))]
    .map((v) => v.toString(16).padStart(2, "0")).join("");

// Build a self-consistent served keyset: four files plus a manifest that correctly describes
// them. `tag` distinguishes the honest keyset from the attacker's.
async function makeKeyset(tag) {
  const transferPk = enc.encode(`transfer-proving-key-${tag}`);
  const depositPk = enc.encode(`deposit-proving-key-${tag}`);
  const transferVk = `aa${tag}`;
  const depositVk = `bb${tag}`;
  const transferVkBytes = enc.encode(transferVk);
  const depositVkBytes = enc.encode(depositVk);
  const manifest = {
    format: 1, proof_system: "Groth16", curve: "BLS12-381",
    publicly_reproducible_toxic_waste: false, setup_mode: "ceremony",
    transfer_pk_sha256: await sha256Hex(transferPk),
    deposit_pk_sha256: await sha256Hex(depositPk),
    transfer_vk_sha256: await sha256Hex(transferVkBytes),
    deposit_vk_sha256: await sha256Hex(depositVkBytes),
  };
  return { transferPk, depositPk, transferVk, depositVk, transferVkBytes, depositVkBytes, manifest };
}

const fetchFor = (ks) => async (path) => {
  const body = {
    "/keys/SETUP-MANIFEST.json": ks.manifest,
    "/keys/transfer_pk.bin": ks.transferPk,
    "/keys/deposit_pk.bin": ks.depositPk,
    "/keys/transfer_vk.hex": ks.transferVkBytes,
    "/keys/deposit_vk.hex": ks.depositVkBytes,
  }[path];
  if (body === undefined) return { ok: false, status: 404 };
  return {
    ok: true, status: 200,
    json: async () => body,
    arrayBuffer: async () => body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength),
  };
};

// The canister's certified anchor for a given keyset.
async function anchorFor(ks, epoch) {
  return {
    transfer_vk_hex: ks.transferVk, deposit_vk_hex: ks.depositVk,
    digest: await anchorDigestHex(ks.transferVk, ks.depositVk),
    epoch, certified: true,
  };
}

// ---- RED: the pre-fix algorithm, transcribed from ffb582a demo-frontend/src/prover.js ----
async function legacyLoadProvingKeys(fetchImpl) {
  const get = async (p, kind) => {
    const r = await fetchImpl(p);
    if (!r.ok) throw new Error(`keyset asset ${p} returned HTTP ${r.status}`);
    return kind === "json" ? r.json() : r.arrayBuffer();
  };
  const [manifest, transfer, deposit, tVk, dVk] = await Promise.all([
    get("/keys/SETUP-MANIFEST.json", "json"), get("/keys/transfer_pk.bin"),
    get("/keys/deposit_pk.bin"), get("/keys/transfer_vk.hex"), get("/keys/deposit_vk.hex"),
  ]);
  if (manifest.format !== 1 || manifest.proof_system !== "Groth16" || manifest.curve !== "BLS12-381")
    throw new Error("unsupported or malformed proving-key manifest");
  if (manifest.publicly_reproducible_toxic_waste)
    throw new Error("refusing proving keys made with the public deterministic test setup");
  for (const [field, bytes] of Object.entries({
    transfer_pk_sha256: transfer, deposit_pk_sha256: deposit,
    transfer_vk_sha256: tVk, deposit_vk_sha256: dVk,
  })) {
    if (await sha256Hex(bytes) !== manifest[field]) throw new Error(`keyset integrity mismatch: ${field}`);
  }
  return { manifest };
}

const honest = await makeKeyset("honest");
const attacker = await makeKeyset("attacker");
const anchor = await anchorFor(honest, 7);

console.log("=== keyset ↔ on-chain anchor binding ===");
console.log(`  honest vk   = ${honest.transferVk} / ${honest.depositVk}`);
console.log(`  attacker vk = ${attacker.transferVk} / ${attacker.depositVk}`);
console.log(`  on-chain anchor pins epoch ${anchor.epoch}, digest ${anchor.digest.slice(0, 16)}…`);

console.log("\n--- RED leg: the pre-fix algorithm (same-origin manifest check only) ---");
await resolves("red: pre-fix code accepts the honest keyset", () => legacyLoadProvingKeys(fetchFor(honest)));
await resolves("red: pre-fix code ALSO accepts a coherently-swapped keyset — the attack",
  () => legacyLoadProvingKeys(fetchFor(attacker)));

console.log("\n--- GREEN leg: shipped loadKeyset, bound to the anchor ---");
const loaded = await resolves("green: honest keyset + matching anchor loads",
  () => loadKeyset(anchor, { fetchImpl: fetchFor(honest) }));
if (loaded) {
  if (loaded.transferVk === honest.transferVk) ok("green: returns the on-chain vk for downstream lineage checks");
  else bad("green: returns the on-chain vk", honest.transferVk, loaded.transferVk);
  if (loaded.keysetEpoch === 7) ok("green: surfaces the keyset epoch");
  else bad("green: surfaces the keyset epoch", "7", String(loaded.keysetEpoch));
}
await rejects("green: a COHERENTLY-SWAPPED five-file keyset is REJECTED",
  () => loadKeyset(anchor, { fetchImpl: fetchFor(attacker) }), "verifying-key mismatch");
await rejects("green: refuses to load at all without an anchor (cannot degrade to the old check)",
  () => loadKeyset(undefined, { fetchImpl: fetchFor(honest) }), "no on-chain verifying-key anchor");
await rejects("green: refuses an anchor whose digest does not cover its own vk fields",
  () => loadKeyset({ ...anchor, digest: "00".repeat(32) }, { fetchImpl: fetchFor(honest) }),
  "internally inconsistent");
await rejects("green: refuses when the ledger reports no configured keys",
  () => loadKeyset({ ...anchor, transfer_vk_hex: "" }, { fetchImpl: fetchFor(honest) }),
  "no configured verifying keys");

console.log("\n--- rotation detectability ---");
const rotated = await anchorFor(attacker, 8); // ledger rotated to a different keyset
await rejects("green: after a rotation the stale local keyset is REJECTED",
  () => loadKeyset(rotated, { fetchImpl: fetchFor(honest) }), "verifying-key mismatch");
await resolves("green: and the matching keyset loads under the new epoch",
  () => loadKeyset(rotated, { fetchImpl: fetchFor(attacker) }));

console.log(`\n=== RESULT: ${pass} passed, ${fail} failed ===`);
process.exit(fail === 0 ? 0 : 1);
