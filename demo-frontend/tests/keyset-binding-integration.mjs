// Keyset binding, against the REAL served key files and a LIVE canister anchor.
//
// The unit test (keyset-anchor.test.mjs) uses synthetic keysets. This one uses the actual
// 12.85 MB demo-frontend/public/keys/* artefacts and reads the anchor from a running canister
// via dfx, so the contrast is measured on the real thing rather than on fixtures.
//
// Usage: node demo-frontend/tests/keyset-binding-integration.mjs <canister> [--rotate-to <t> <d>]
//   run from the project root of a tree with a live local replica.

import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { loadKeyset, anchorDigestHex } from "../src/keyset.js";

const CANISTER = process.argv[2];
if (!CANISTER) { console.error("usage: keyset-binding-integration.mjs <canister>"); process.exit(2); }

let pass = 0, fail = 0;
const ok = (n) => { pass++; console.log(`  PASS  ${n}`); };
const bad = (n, e, a) => { fail++; console.log(`  FAIL  ${n}`); console.log(`        expected: ${e}`); console.log(`        actual:   ${a}`); };
async function rejects(n, fn, must) {
  try { await fn(); bad(n, `throws containing "${must}"`, "resolved"); }
  catch (e) { String(e.message).includes(must) ? ok(n) : bad(n, `"${must}"`, e.message); }
}
async function resolves(n, fn) {
  try { const v = await fn(); ok(n); return v; } catch (e) { bad(n, "resolves", `threw: ${e.message}`); return null; }
}

const dfx = (...args) =>
  execFileSync("dfx", args, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env, PATH: `/root/.local/share/dfx/bin:${process.env.PATH}` } });

function readAnchor() {
  const out = dfx("canister", "call", CANISTER, "verifying_key_anchor", "()");
  const g = (re) => (out.match(re) || [])[1];
  return {
    transfer_vk_hex: g(/transfer_vk_hex = "([^"]*)"/),
    deposit_vk_hex: g(/deposit_vk_hex = "([^"]*)"/),
    epoch: Number(g(/epoch = ([0-9_]+)/).replace(/_/g, "")),
    digest: (g(/digest = blob "([^"]*)"/) || "").replace(/\\/g, "").toLowerCase(),
    certified: /certified = true/.test(out),
  };
}

// fetchImpl over real files on disk, with optional overrides for the swapped keyset
const KEYS = "demo-frontend/public/keys";
const realFile = (p) => readFileSync(`${KEYS}/${p}`);
function fetchFrom(overrides = {}) {
  const map = {
    "/keys/SETUP-MANIFEST.json": "SETUP-MANIFEST.json",
    "/keys/transfer_pk.bin": "transfer_pk.bin",
    "/keys/deposit_pk.bin": "deposit_pk.bin",
    "/keys/transfer_vk.hex": "transfer_vk.hex",
    "/keys/deposit_vk.hex": "deposit_vk.hex",
  };
  return async (path) => {
    if (overrides[path] !== undefined) {
      const b = overrides[path];
      return { ok: true, status: 200, json: async () => JSON.parse(Buffer.from(b).toString()),
               arrayBuffer: async () => b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) };
    }
    const name = map[path];
    if (!name) return { ok: false, status: 404 };
    const b = realFile(name);
    return { ok: true, status: 200, json: async () => JSON.parse(b.toString()),
             arrayBuffer: async () => b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) };
  };
}

const sha256Hex = async (bytes) =>
  [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))].map((v) => v.toString(16).padStart(2, "0")).join("");

// the pre-fix loader, transcribed from ffb582a demo-frontend/src/prover.js
async function legacyLoad(fetchImpl) {
  const get = async (p, k) => { const r = await fetchImpl(p);
    if (!r.ok) throw new Error(`keyset asset ${p} returned HTTP ${r.status}`);
    return k === "json" ? r.json() : r.arrayBuffer(); };
  const [m, t, d, tv, dv] = await Promise.all([
    get("/keys/SETUP-MANIFEST.json", "json"), get("/keys/transfer_pk.bin"),
    get("/keys/deposit_pk.bin"), get("/keys/transfer_vk.hex"), get("/keys/deposit_vk.hex")]);
  if (m.format !== 1 || m.proof_system !== "Groth16" || m.curve !== "BLS12-381") throw new Error("bad manifest");
  if (m.publicly_reproducible_toxic_waste) throw new Error("deterministic test setup");
  for (const [f, b] of Object.entries({ transfer_pk_sha256: t, deposit_pk_sha256: d,
                                        transfer_vk_sha256: tv, deposit_vk_sha256: dv }))
    if (await sha256Hex(b) !== m[f]) throw new Error(`keyset integrity mismatch: ${f}`);
  return { manifest: m };
}

// --- an attacker's COHERENT five-file swap over the real artefacts ---
async function swappedKeyset() {
  const tPk = Buffer.concat([realFile("transfer_pk.bin"), Buffer.from("SWAPPED")]);
  const dPk = Buffer.concat([realFile("deposit_pk.bin"), Buffer.from("SWAPPED")]);
  const tVk = Buffer.from(realFile("transfer_vk.hex").toString().trim().replace(/^../, "ff"));
  const dVk = Buffer.from(realFile("deposit_vk.hex").toString().trim().replace(/^../, "ff"));
  const manifest = { ...JSON.parse(realFile("SETUP-MANIFEST.json").toString()),
    transfer_pk_sha256: await sha256Hex(tPk), deposit_pk_sha256: await sha256Hex(dPk),
    transfer_vk_sha256: await sha256Hex(tVk), deposit_vk_sha256: await sha256Hex(dVk) };
  return { "/keys/transfer_pk.bin": tPk, "/keys/deposit_pk.bin": dPk,
           "/keys/transfer_vk.hex": tVk, "/keys/deposit_vk.hex": dVk,
           "/keys/SETUP-MANIFEST.json": Buffer.from(JSON.stringify(manifest)) };
}

console.log("=== keyset binding, real artefacts + live canister anchor ===");
const sizes = ["transfer_pk.bin", "deposit_pk.bin", "transfer_vk.hex", "deposit_vk.hex", "SETUP-MANIFEST.json"]
  .map((f) => `${f}=${realFile(f).length}`);
console.log(`  served keyset: ${sizes.join(" ")}`);
// PRECONDITION. rotate_verifying_keys_v2 rotates FROM the current keys, and on a freshly installed
// ledger both vk hex fields are "" -- there is nothing to rotate from, so keyset.js:65 refuses to
// load and the GREEN leg fails on staging rather than on the property under test. configure() is
// what populates those fields. Established here rather than out of band: a suite that needs a manual
// step cannot run unattended, and a suite that is red on staging is one people learn to ignore.
// No assertion below is changed; configure() only populates the anchor fields the GREEN leg reads.
{
  const pre = readAnchor();
  if (!pre.transfer_vk_hex || !pre.deposit_vk_hex) {
    const verifier = dfx("canister", "id", process.env.KEYSET_VERIFIER || "scale_fixture").trim();
    const oracle = dfx("canister", "id", process.env.KEYSET_TREE_ORACLE || "honest_tree_oracle").trim();
    const tHex = realFile("transfer_vk.hex").toString().trim();
    const dHex = realFile("deposit_vk.hex").toString().trim();
    try {
      dfx("canister", "call", CANISTER, "configure",
        `(principal "${verifier}", principal "${oracle}", "${tHex}", "${dHex}")`);
      console.log("  setup: ledger reported no configured verifying keys — configure() called with the served keyset");
    } catch (e) {
      // configure mints the administrator and refuses a second call. Idempotence requires tolerating
      // that ONE refusal and nothing else, so a real configure failure still surfaces.
      const text = String(e.stdout || "") + String(e.stderr || "") + String(e.message || "");
      if (!text.includes("already-configured")) throw e;
      console.log("  setup: ledger already configured — reusing it");
    }
  }
}

// Establish a known baseline so the battery is idempotent: its own rotation step below leaves
// the canister on a different keyset, and a re-run must not inherit that.
{
  const cur = readAnchor();
  const tHex0 = realFile("transfer_vk.hex").toString().trim();
  const dHex0 = realFile("deposit_vk.hex").toString().trim();
  if (cur.transfer_vk_hex !== tHex0 || cur.deposit_vk_hex !== dHex0) {
    dfx("canister", "call", CANISTER, "rotate_verifying_keys_v2",
      `("${cur.transfer_vk_hex}", "${cur.deposit_vk_hex}", "${tHex0}", "${dHex0}")`);
    console.log("  setup: rotated the canister onto the served keyset to establish a baseline");
  }
}
const anchor = readAnchor();
console.log(`  live anchor: epoch=${anchor.epoch} certified=${anchor.certified} digest=${anchor.digest.slice(0, 16)}…`);

// the canister's digest must be reproducible from its own key text
const recomputed = await anchorDigestHex(anchor.transfer_vk_hex, anchor.deposit_vk_hex);
recomputed === anchor.digest
  ? ok("anchor digest recomputes from the on-chain key text")
  : bad("anchor digest recomputes from the on-chain key text", recomputed, anchor.digest);

console.log("\n--- RED leg: the pre-fix loader on the REAL files ---");
await resolves("red: pre-fix loader accepts the genuine keyset", () => legacyLoad(fetchFrom()));
const swap = await swappedKeyset();
await resolves("red: pre-fix loader ALSO accepts a coherently-swapped keyset — the attack",
  () => legacyLoad(fetchFrom(swap)));

console.log("\n--- GREEN leg: shipped loader, bound to the live anchor ---");
await resolves("green: genuine keyset + live anchor loads", () => loadKeyset(anchor, { fetchImpl: fetchFrom() }));
await rejects("green: the SAME coherently-swapped keyset is REJECTED",
  () => loadKeyset(anchor, { fetchImpl: fetchFrom(swap) }), "verifying-key mismatch");

// --- load cost, measured on the real 12.85 MB keyset ---
console.log("\n--- keyset load cost (real artefacts) ---");
const time = async (fn) => { const t0 = performance.now(); await fn(); return performance.now() - t0; };
const beforeMs = await time(() => legacyLoad(fetchFrom()));
const anchorMs = await time(async () => readAnchor());
const afterMs = await time(() => loadKeyset(anchor, { fetchImpl: fetchFrom() }));
const bytes = ["transfer_pk.bin", "deposit_pk.bin", "transfer_vk.hex", "deposit_vk.hex", "SETUP-MANIFEST.json"]
  .reduce((n, f) => n + realFile(f).length, 0);
console.log(`  bytes read+hashed         : ${bytes}`);
console.log(`  BEFORE (pre-fix loader)   : ${beforeMs.toFixed(1)} ms`);
console.log(`  AFTER  (bound loader)     : ${afterMs.toFixed(1)} ms`);
console.log(`  anchor query round-trip   : ${anchorMs.toFixed(1)} ms  (added by the fix)`);
console.log(`  NOTE: keyset caching is NOT implemented here — no caching, streaming or compression`);
console.log(`  was added, so the ${bytes}-byte read is unchanged by this fix. These numbers are the`);
console.log(`  baseline a cache has to beat, not evidence of an improvement.`);

// --- live rotation: rotate the canister's keyset, then re-pin ---
console.log("\n--- rotation detectability (live rotate_verifying_keys_v2) ---");
const tHex = realFile("transfer_vk.hex").toString().trim();
const dHex = realFile("deposit_vk.hex").toString().trim();
// rotate to a DIFFERENT but still valid keyset by swapping the two real verifying keys, so
// parseAndPrepareVk succeeds on both and the rotation is accepted
const rot = dfx("canister", "call", CANISTER, "rotate_verifying_keys_v2",
  `("${anchor.transfer_vk_hex}", "${anchor.deposit_vk_hex}", "${dHex}", "${tHex}")`);
console.log(`  rotate -> ${/variant \{\s*ok/.test(rot) ? "ok" : rot.slice(0, 80)}`);
const anchor2 = readAnchor();
console.log(`  anchor now: epoch=${anchor2.epoch} digest=${anchor2.digest.slice(0, 16)}…`);
anchor2.epoch === anchor.epoch + 1
  ? ok("live: rotation bumped the on-chain keyset epoch")
  : bad("live: rotation bumped the on-chain keyset epoch", String(anchor.epoch + 1), String(anchor2.epoch));
anchor2.digest !== anchor.digest
  ? ok("live: rotation changed the anchor digest")
  : bad("live: rotation changed the anchor digest", "different", anchor2.digest);
await rejects("live: the client pinned to the pre-rotation keyset now REFUSES",
  () => loadKeyset(anchor2, { fetchImpl: fetchFrom() }), "verifying-key mismatch");

console.log(`\n=== RESULT: ${pass} passed, ${fail} failed ===`);
process.exit(fail === 0 ? 0 : 1);
