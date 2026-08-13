// Keyset cache — correctness and cost.
//
// The keyset is 13 MB and was re-fetched on every cold start. src/keysetCache.js caches the bytes
// across sessions, keyed by the on-chain verifying-key anchor digest.
//
// ACCEPTANCE, committed before the run:
//   1. a cold load reports fromCache=false and a warm load reports fromCache=true
//   2. the warm load fetches NOTHING — asset fetches on the second load must be 0
//   3. both loads return byte-identical proving keys and the same on-chain vk text
//   4. a ROTATED anchor must miss the cache and re-fetch, with no eviction logic involved
//   5. a TAMPERED cache entry must be REFUSED, not trusted — the verdict is never cached — and the
//      poisoned entry must be dropped so the next load recovers
//   6. the warm load must be faster than the cold one; both numbers are reported
//
// Run: node scripts/measure-keyset-cache.mjs
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { loadKeyset, anchorDigestHex } from "../src/keyset.js";
import { memoryKeysetStore } from "../src/keysetCache.js";

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const keysDir = path.join(root, "public", "keys");

let pass = 0;
let fail = 0;
const ok = (m) => { pass += 1; console.log(`  PASS  ${m}`); };
const bad = (m, e, a) => { fail += 1; console.log(`  FAIL  ${m}\n        expected: ${e}\n        actual:   ${a}`); };
const eq = (m, e, a) => (String(e) === String(a) ? ok(`${m} (${a})`) : bad(m, e, a));

let fetches = 0;
let fetchedBytes = 0;
async function fetchImpl(assetPath) {
  const bytes = await readFile(path.join(keysDir, path.basename(assetPath)));
  fetches += 1;
  fetchedBytes += bytes.byteLength;
  const buffer = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
  return {
    ok: true,
    status: 200,
    arrayBuffer: async () => buffer,
    json: async () => JSON.parse(new TextDecoder().decode(buffer)),
  };
}

const transferVk = (await readFile(path.join(keysDir, "transfer_vk.hex"), "utf8")).trim();
const depositVk = (await readFile(path.join(keysDir, "deposit_vk.hex"), "utf8")).trim();
const anchor = {
  transfer_vk_hex: transferVk,
  deposit_vk_hex: depositVk,
  digest: await anchorDigestHex(transferVk, depositVk),
  epoch: 1n,
  certified: true,
};

console.log("=== keyset cache battery ===");

const store = memoryKeysetStore();

fetches = 0; fetchedBytes = 0;
let t0 = performance.now();
const cold = await loadKeyset(anchor, { fetchImpl, store });
const coldMs = performance.now() - t0;
const coldFetches = fetches;
const coldBytes = fetchedBytes;

fetches = 0; fetchedBytes = 0;
t0 = performance.now();
const warm = await loadKeyset(anchor, { fetchImpl, store });
const warmMs = performance.now() - t0;
const warmFetches = fetches;

console.log(`  cold: ${coldMs.toFixed(1)} ms, ${coldFetches} asset fetches, ${coldBytes} bytes`);
console.log(`  warm: ${warmMs.toFixed(1)} ms, ${warmFetches} asset fetches, 0 bytes`);

eq("1. the first load is a miss", "false", String(cold.fromCache));
eq("1. the second load is a hit", "true", String(warm.fromCache));
eq("2. the warm load fetches nothing", "0", String(warmFetches));
eq("3. the proving keys are byte-identical", "true",
   String(Buffer.compare(Buffer.from(cold.transfer), Buffer.from(warm.transfer)) === 0
       && Buffer.compare(Buffer.from(cold.deposit), Buffer.from(warm.deposit)) === 0));
eq("3. the on-chain vk text is unchanged", "true", String(cold.transferVk === warm.transferVk
  && cold.depositVk === warm.depositVk && warm.transferVk === anchor.transfer_vk_hex));

// 4. rotation
const rotated = { ...anchor, transfer_vk_hex: transferVk.replace(/.$/, transferVk.endsWith("0") ? "1" : "0") };
rotated.digest = await anchorDigestHex(rotated.transfer_vk_hex, rotated.deposit_vk_hex);
fetches = 0;
try {
  await loadKeyset(rotated, { fetchImpl, store });
  bad("4. a rotated anchor is refused", "a verifying-key mismatch", "it loaded");
} catch (error) {
  if (String(error.message).includes("verifying-key mismatch")) {
    ok("4. a rotated anchor misses the cache, re-fetches, and is then refused on the binding");
  } else {
    bad("4. a rotated anchor is refused on the binding", "verifying-key mismatch", error.message);
  }
}
eq("4. and it really did go back to the network", "5", String(fetches));

// 5. a tampered cache entry
const key = await anchorDigestHex(transferVk, depositVk);
const poisoned = await store.get(key);
const corrupted = Buffer.from(poisoned.transfer);
corrupted[0] ^= 0x01;
await store.put(key, { ...poisoned, transfer: corrupted.buffer.slice(corrupted.byteOffset, corrupted.byteOffset + corrupted.byteLength) });
try {
  await loadKeyset(anchor, { fetchImpl, store });
  bad("5. a tampered cache entry is refused", "keyset integrity mismatch", "it loaded");
} catch (error) {
  if (String(error.message).includes("keyset integrity mismatch")) {
    ok("5. a tampered cache entry is REFUSED — the bytes are cached, the verdict is not");
  } else {
    bad("5. a tampered cache entry is refused", "keyset integrity mismatch", error.message);
  }
}
fetches = 0;
const recovered = await loadKeyset(anchor, { fetchImpl, store });
eq("5. the poisoned entry was dropped, so the next load recovers", "false", String(recovered.fromCache));
eq("5. by going back to the network", "5", String(fetches));

eq("6. the warm load is faster than the cold one", "true", String(warmMs < coldMs));

console.log(`\n=== RESULT: ${pass} passed, ${fail} failed ===`);
process.exit(fail === 0 ? 0 : 1);
