import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

const args = process.argv.slice(2);
const requireRealValue = args.includes("--require-real-value");
const directory = resolve(args.find((value) => !value.startsWith("--")) || "public/keys");
const manifest = JSON.parse(await readFile(resolve(directory, "SETUP-MANIFEST.json"), "utf8"));

if (manifest.format !== 1 || manifest.proof_system !== "Groth16" || manifest.curve !== "BLS12-381") {
  throw new Error("unsupported or malformed SETUP-MANIFEST.json");
}
if (manifest.publicly_reproducible_toxic_waste) {
  throw new Error("deployment forbidden: keyset uses publicly reproducible setup randomness");
}

const artifacts = {
  "transfer_pk.bin": "transfer_pk_sha256",
  "deposit_pk.bin": "deposit_pk_sha256",
  "transfer_vk.hex": "transfer_vk_sha256",
  "deposit_vk.hex": "deposit_vk_sha256",
};
for (const [name, field] of Object.entries(artifacts)) {
  const bytes = await readFile(resolve(directory, name));
  const actual = createHash("sha256").update(bytes).digest("hex");
  const expected = manifest[field];
  if (!expected || actual !== expected) throw new Error(`keyset integrity mismatch: ${name}`);
}

console.log(`KEYSET OK: ${manifest.setup_mode}`);
console.log(`REAL VALUE ELIGIBLE: ${manifest.real_value_eligible}`);
if (!manifest.real_value_eligible) {
  console.log("DEMO ONLY: a verified multi-party ceremony transcript is still required.");
  if (requireRealValue) throw new Error("production deployment forbidden: keyset is not real-value eligible");
}
