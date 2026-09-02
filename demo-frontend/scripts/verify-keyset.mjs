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

// The minimum number of honest contributions a production keyset must rest on.
//
// docs/TRUSTED-SETUP-POLICY.md requires "contributions from multiple independent operators on
// separately controlled machines". Until this constant existed that requirement lived only in
// prose, while the machine-checkable flags were computed as `honest_contributions >= 1` -- so a
// ONE-party ceremony stamped itself `multi_party_ceremony: true`. A named floor makes the policy
// executable. Raising it is a governance decision, not a refactor.
const MIN_HONEST_CONTRIBUTIONS = 5;

if (requireRealValue) {
  // THE GATE: verify the ceremony transcript itself, and bind the shipped keys to it.
  //
  // Five things have to hold, and each closes a different way of passing without a ceremony:
  //   1. the manifest names a transcript and an SRS          -- otherwise there is nothing to check
  //   2. the standalone verifier accepts them                -- the transcript is actually valid
  //   3. the vk hashes the VERIFIER reports equal the ones   -- these keys came from THAT transcript
  //      this manifest pins for the shipped artifacts           rather than from some other one
  //   4. the verifier reports >= MIN_HONEST_CONTRIBUTIONS    -- one party is not a multi-party ceremony
  //   5. the verifier reports the beacon finalize            -- without it the ending was predictable
  //
  // Without (3) a valid transcript for an unrelated ceremony would authorise any keyset.
  //
  // (4) and (5) are read from the VERIFIER'S OWN OUTPUT, never from the manifest, for the same
  // reason `real_value_eligible` is only a label here: a number in a hand-editable JSON file
  // cannot be the thing that authorises a deployment.
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
  // The binding hash is NOT the top-level `*_vk_sha256`. Those are hashes of the FILES on disk --
  // for a vk that is the ASCII hex text -- and the integrity loop above already checks them. The
  // transcript verifier prints a hash over the RAW vk bytes, i.e. SHA256 of what that hex encodes,
  // so the two can never be equal. Comparing the verifier's value against the file hash is
  // unsatisfiable, and because this whole block sits behind the "no ceremony transcript recorded"
  // throw it was never once executed: `--require-real-value` could not have passed for ANY keyset.
  // The ceremony-derived value therefore lives in its own field.
  for (const [circuit, field] of [["transfer", "transfer_vk_sha256"], ["deposit", "deposit_vk_sha256"]]) {
    if (!reported[circuit]) {
      throw new Error(`production deployment forbidden: the verifier reported no ${circuit} vk hash`);
    }
    const bound = ceremony[field];
    if (!bound) {
      throw new Error(
        `production deployment forbidden: SETUP-MANIFEST.json records no ceremony.${field}\n` +
        "  without it the shipped keys are not bound to any transcript"
      );
    }
    if (reported[circuit] !== bound) {
      throw new Error(
        `production deployment forbidden: the shipped ${circuit} vk is NOT the one this transcript produces\n` +
        `  transcript: ${reported[circuit]}\n  manifest:   ${bound}`
      );
    }
  }
  const honest = output.match(/^\s*honest contributions\s*:\s*(\d+)/m);
  if (!honest) {
    throw new Error("production deployment forbidden: the verifier reported no honest contribution count");
  }
  if (Number(honest[1]) < MIN_HONEST_CONTRIBUTIONS) {
    throw new Error(
      `production deployment forbidden: ${honest[1]} honest contribution(s), ` +
      `${MIN_HONEST_CONTRIBUTIONS} required\n` +
      "  a ceremony is only as strong as the number of INDEPENDENT parties who destroyed their\n" +
      "  secret; one party mixing in its own randomness is a single-party setup wearing a chain"
    );
  }

  const finalized = output.match(/^\s*finalized \(beacon\)\s*:\s*(true|false)/m);
  if (!finalized) {
    throw new Error("production deployment forbidden: the verifier reported no beacon finalize state");
  }
  if (finalized[1] !== "true") {
    throw new Error(
      "production deployment forbidden: the transcript is not finalized with a beacon\n" +
      "  without it the final parameters were predictable to whoever contributed last"
    );
  }

  console.log(`CEREMONY TRANSCRIPT VERIFIED: ${transcriptPath}`);
  console.log(`  honest contributions: ${honest[1]} (minimum ${MIN_HONEST_CONTRIBUTIONS})`);
  console.log("  finalized with beacon: true");
  console.log("REAL VALUE GATE: PASSED — both vks match the verified transcript");
} else if (!manifest.real_value_eligible) {
  console.log("DEMO ONLY: a verified multi-party ceremony transcript is still required.");
}
