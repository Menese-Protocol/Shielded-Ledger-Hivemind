import assertRaw from "node:assert/strict";

// Executed-assertion counter. Delegates to node:assert/strict UNCHANGED and records what actually
// EXECUTED. No assertion is weakened, added or reordered
// (the executed count is itself the check: a wrapper that altered, added or reordered an
// assertion would move it) -- this wraps, it does not alter. A
// runtime counter is required rather than a static one: this file runs its assertions in loops,
// so a call-site grep undercounts them.
let passed = 0;
const count = (fn) => (...a) => { const r = fn(...a); passed += 1; return r; };
const assert = new Proxy(assertRaw, {
  apply: (t, self, a) => { const r = Reflect.apply(t, self, a); passed += 1; return r; },
  get: (t, p) => { const v = Reflect.get(t, p); return typeof v === "function" ? count(v.bind(t)) : v; },
});
import { mkdtemp, cp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const frontend = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const verifier = join(frontend, "scripts", "verify-keyset.mjs");
const source = join(frontend, "public", "keys");

function run(directory, extra = []) {
  return spawnSync(process.execPath, [verifier, directory, ...extra], {
    cwd: frontend,
    encoding: "utf8",
  });
}

const integrityDir = await mkdtemp(join(tmpdir(), "picp-keyset-integrity-"));
await cp(source, integrityDir, { recursive: true });
const vkPath = join(integrityDir, "transfer_vk.hex");
const vk = Buffer.from(await readFile(vkPath));
vk[Math.floor(vk.length / 2)] ^= 1;
await writeFile(vkPath, vk);
const integrity = run(integrityDir);
assert.notEqual(integrity.status, 0, "one-byte verifying-key mutation was accepted");
assert.match(integrity.stderr, /integrity mismatch/);

const toxicDir = await mkdtemp(join(tmpdir(), "picp-keyset-toxic-"));
await cp(source, toxicDir, { recursive: true });
const manifestPath = join(toxicDir, "SETUP-MANIFEST.json");
const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
manifest.publicly_reproducible_toxic_waste = true;
await writeFile(manifestPath, JSON.stringify(manifest));
const toxic = run(toxicDir);
assert.notEqual(toxic.status, 0, "publicly reproducible setup randomness was accepted");
assert.match(toxic.stderr, /publicly reproducible setup randomness/);

// The production gate no longer turns on the manifest's `real_value_eligible` boolean -- a
// hand-editable field cannot authorise a deployment -- so this asserts the new refusal AND that
// flipping the boolean does not buy a pass. The second half is the one that matters: it is the
// exact edit someone in a hurry would make.
const production = run(source, ["--require-real-value"]);
assert.notEqual(production.status, 0, "single-party DEMO keyset was accepted for real value");
assert.match(production.stderr, /no ceremony transcript recorded/);

const flippedDir = await mkdtemp(join(tmpdir(), "picp-keyset-flipped-"));
await cp(source, flippedDir, { recursive: true });
const flippedPath = join(flippedDir, "SETUP-MANIFEST.json");
const flipped = JSON.parse(await readFile(flippedPath, "utf8"));
flipped.real_value_eligible = true;
await writeFile(flippedPath, JSON.stringify(flipped));
const flippedRun = run(flippedDir, ["--require-real-value"]);
assert.notEqual(flippedRun.status, 0, "flipping real_value_eligible to true bought a production pass");
assert.match(flippedRun.stderr, /no ceremony transcript recorded/);

console.log("KEYSET NEGATIVES: byte mutation, public toxic waste, real-value gate, and manifest-flip GREEN");
console.log(`=== RESULT: ${passed} passed, 0 failed ===`);
