import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

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
// Reported, never authorising. `real_value_eligible` is a hand-editable JSON boolean, and a
// production gate that turns on it would pass on a text edit -- the deployment would be authorised
// by the very file it is supposed to be checking. It stays as a label; the gate below is the check.
console.log(`REAL VALUE ELIGIBLE (manifest label, not the gate): ${manifest.real_value_eligible}`);

if (requireRealValue) {
  // THE GATE: verify the ceremony transcript itself, and bind the shipped keys to it.
  //
  // Three things have to hold, and each closes a different way of passing without a ceremony:
  //   1. the manifest names a transcript and an SRS          -- otherwise there is nothing to check
  //   2. the standalone verifier accepts them                -- the transcript is actually valid
  //   3. the vk hashes the VERIFIER reports equal the ones   -- these keys came from THAT transcript
  //      this manifest pins for the shipped artifacts           rather than from some other one
  //
  // Without (3) a valid transcript for an unrelated ceremony would authorise any keyset.
  const ceremony = manifest.ceremony;
  if (!ceremony || !ceremony.transcript || !ceremony.srs) {
    throw new Error(
      "production deployment forbidden: no ceremony transcript recorded in SETUP-MANIFEST.json " +
      "(--require-real-value verifies a transcript, not a manifest field)"
    );
  }
  const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
  const verifier = process.env.VERIFY_TRANSCRIPT_BIN
    || resolve(repoRoot, "ceremony/target/release/verify-transcript");
  if (!existsSync(verifier)) {
    throw new Error(`production deployment forbidden: transcript verifier not built at ${verifier}`);
  }
  const srsPath = resolve(directory, ceremony.srs);
  const transcriptPath = resolve(directory, ceremony.transcript);
  for (const p of [srsPath, transcriptPath]) {
    if (!existsSync(p)) throw new Error(`production deployment forbidden: missing ceremony artifact ${p}`);
  }
  const run = spawnSync(verifier, [srsPath, transcriptPath], { encoding: "utf8" });
  const output = `${run.stdout || ""}${run.stderr || ""}`;
  if (run.status !== 0 || !output.includes("TRANSCRIPT VALID")) {
    throw new Error(
      `production deployment forbidden: transcript verification FAILED (exit ${run.status})\n` +
      output.split("\n").filter((l) => l.trim()).slice(-5).join("\n")
    );
  }
  const reported = Object.fromEntries(
    [...output.matchAll(/^\s*(transfer|deposit)\s+vk SHA-256\s*:\s*([0-9a-f]{64})/gm)]
      .map((m) => [m[1], m[2]])
  );
  for (const [circuit, field] of [["transfer", "transfer_vk_sha256"], ["deposit", "deposit_vk_sha256"]]) {
    if (!reported[circuit]) {
      throw new Error(`production deployment forbidden: the verifier reported no ${circuit} vk hash`);
    }
    if (reported[circuit] !== manifest[field]) {
      throw new Error(
        `production deployment forbidden: the shipped ${circuit} vk is NOT the one this transcript produces\n` +
        `  transcript: ${reported[circuit]}\n  manifest:   ${manifest[field]}`
      );
    }
  }
  console.log(`CEREMONY TRANSCRIPT VERIFIED: ${transcriptPath}`);
  console.log("REAL VALUE GATE: PASSED — both vks match the verified transcript");
} else if (!manifest.real_value_eligible) {
  console.log("DEMO ONLY: a verified multi-party ceremony transcript is still required.");
}
