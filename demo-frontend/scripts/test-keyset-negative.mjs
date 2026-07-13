import assert from "node:assert/strict";
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

const production = run(source, ["--require-real-value"]);
assert.notEqual(production.status, 0, "single-party DEMO keyset was misclassified as real-value eligible");
assert.match(production.stderr, /not real-value eligible/);

console.log("KEYSET NEGATIVES: byte mutation, public toxic waste, and real-value gate GREEN");
