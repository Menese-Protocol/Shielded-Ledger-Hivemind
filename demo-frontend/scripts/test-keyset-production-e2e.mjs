// End-to-end test of the seam between the ceremony and the money.
//
// `ceremony-cli export` produces a keyset; `verify-keyset.mjs --require-real-value` is the gate
// that authorises it for real value. Until this test existed the two halves had NEVER been run
// against each other, and they did not fit: the exporter wrote `format: 2` with no pk hashes and
// no `ceremony` block, all three of which the gate requires, so a real launch would have failed
// at the last step with the ceremony already sealed and unrepeatable.
//
// This is deliberately NOT in the fast suite. It needs a real multi-contribution transcript over
// the inherited Phase-1 SRS, which takes minutes to produce, and it is a pre-deployment gate
// rather than a unit test.
//
//   node scripts/test-keyset-production-e2e.mjs <fixture-dir>
//
// <fixture-dir> must contain phase1.srs.bin plus transcripts built by ceremony-cli:
//   t.bin            >= MIN honest contributions, finalized with a beacon   (must PASS)
//   t-after-4.bin    one short of the floor, not finalized                  (must be REFUSED)
//   t-under.bin      optional: any transcript from a DIFFERENT ceremony     (must be REFUSED)
import assertRaw from "node:assert/strict";
let passed = 0;
const count = (fn) => (...a) => { const r = fn(...a); passed += 1; return r; };
const assert = new Proxy(assertRaw, {
  apply: (t, self, a) => { const r = Reflect.apply(t, self, a); passed += 1; return r; },
  get: (t, p) => { const v = Reflect.get(t, p); return typeof v === "function" ? count(v.bind(t)) : v; },
});
import { mkdtemp, cp, readFile, writeFile, copyFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const frontend = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repo = resolve(frontend, "..");
const gate = join(frontend, "scripts", "verify-keyset.mjs");
const cli = join(repo, "ceremony", "target", "release", "ceremony-cli");
if (!process.argv[2]) {
  throw new Error(
    "usage: node scripts/test-keyset-production-e2e.mjs <fixture-dir>\n\n" +
    "The fixture is a real multi-contribution ceremony over the INHERITED Phase-1 SRS, because\n" +
    "that is what the gate checks; a test-tier SRS is refused for real value by design. Build one:\n\n" +
    "  CLI=ceremony/target/release/ceremony-cli\n" +
    "  SRS=ceremony-launch-p14/sapling-phase1-p14.srs.bin\n" +
    "  mkdir -p <dir> && cp $SRS <dir>/phase1.srs.bin\n" +
    "  $CLI init <dir>/phase1.srs.bin <dir>/t.bin\n" +
    "  for i in 1 2 3 4 5; do\n" +
    "    $CLI contribute <dir>/phase1.srs.bin <dir>/t.bin <32-hex-id>\n" +
    "    cp <dir>/t.bin <dir>/t-after-$i.bin        # t-after-4.bin drives the below-floor control\n" +
    "  done\n" +
    "  $CLI finalize <dir>/phase1.srs.bin <dir>/t.bin <beacon-hex>\n\n" +
    "Optionally add t-foreign.bin, any valid transcript from a DIFFERENT ceremony, to exercise\n" +
    "the cross-ceremony binding control."
  );
}
const fixture = resolve(process.argv[2]);

for (const p of [cli, join(fixture, "phase1.srs.bin"), join(fixture, "t.bin")]) {
  if (!existsSync(p)) throw new Error(`missing prerequisite: ${p}`);
}

const runGate = (dir, extra = []) =>
  spawnSync(process.execPath, [gate, dir, ...extra], { cwd: frontend, encoding: "utf8" });

async function exportKeyset(transcriptName) {
  const out = await mkdtemp(join(tmpdir(), "picp-e2e-"));
  const srs = join(fixture, "phase1.srs.bin");
  const transcript = join(fixture, transcriptName);
  const r = spawnSync(cli, ["export", srs, transcript, out], { encoding: "utf8" });
  if (r.status !== 0) throw new Error(`export failed:\n${r.stdout}${r.stderr}`);
  // The gate resolves ceremony.srs / ceremony.transcript relative to the keyset directory, so the
  // two inputs must sit beside the keys under the names the manifest records.
  await copyFile(srs, join(out, "phase1.srs.bin"));
  await copyFile(transcript, join(out, transcriptName));
  return out;
}

// ---- POSITIVE CONTROL: a real, finalized, at-or-above-floor ceremony must pass ---------------
const good = await exportKeyset("t.bin");
const manifest = JSON.parse(await readFile(join(good, "SETUP-MANIFEST.json"), "utf8"));
assert.equal(manifest.format, 1, "the gate only accepts format 1");
assert.equal(manifest.setup_mode, "multi-party-phase2-ceremony");
assert.equal(manifest.publicly_reproducible_toxic_waste, false);
assert.equal(manifest.multi_party_ceremony, true);
assert.equal(manifest.real_value_eligible, true);
assert.equal(manifest.finalized_with_beacon, true);
assert.ok(manifest.transfer_pk_sha256, "the gate hashes transfer_pk.bin against the manifest");
assert.ok(manifest.deposit_pk_sha256, "the gate hashes deposit_pk.bin against the manifest");
assert.ok(manifest.ceremony?.srs && manifest.ceremony?.transcript, "gate needs the ceremony block");

const pass = runGate(good, ["--require-real-value"]);
assert.equal(pass.status, 0, `production gate refused a valid ceremony:\n${pass.stderr}`);
assert.match(pass.stdout, /REAL VALUE GATE: PASSED/);
assert.match(pass.stdout, /CEREMONY TRANSCRIPT VERIFIED/);
console.log("POSITIVE: a finalized at-floor ceremony passes the production gate");

// ---- CAN-FAIL 1: below the floor, and not finalized -------------------------------------------
// The whole point of the constant. This transcript is a real, VALID ceremony -- it simply does not
// rest on enough independent parties, which is precisely the case that used to stamp itself
// `multi_party_ceremony: true` and sail through.
if (existsSync(join(fixture, "t-after-4.bin"))) {
  const short = await exportKeyset("t-after-4.bin");
  const shortManifest = JSON.parse(await readFile(join(short, "SETUP-MANIFEST.json"), "utf8"));
  assert.equal(shortManifest.multi_party_ceremony, false, "4 contributions is not multi-party");
  assert.equal(shortManifest.real_value_eligible, false);
  const refused = runGate(short, ["--require-real-value"]);
  assert.notEqual(refused.status, 0, "a below-floor ceremony was accepted for real value");
  assert.match(refused.stderr, /honest contribution|not finalized/);
  console.log("CAN-FAIL 1: a below-floor ceremony is refused");

  // ---- CAN-FAIL 2: the edit someone in a hurry makes ------------------------------------------
  // Flip every manifest flag to the values a passing keyset would carry. The gate must still
  // refuse, because it re-derives the count from the VERIFIER rather than reading these fields.
  const forged = join(short, "SETUP-MANIFEST.json");
  const f = JSON.parse(await readFile(forged, "utf8"));
  f.multi_party_ceremony = true;
  f.real_value_eligible = true;
  f.honest_contributions = 99;
  f.finalized_with_beacon = true;
  await writeFile(forged, JSON.stringify(f, null, 2));
  const stillRefused = runGate(short, ["--require-real-value"]);
  assert.notEqual(stillRefused.status, 0, "hand-edited manifest flags bought a production pass");
  console.log("CAN-FAIL 2: hand-editing the manifest flags does not buy a pass");
}

// ---- CAN-FAIL 3: keys from one ceremony, transcript from another ------------------------------
// A valid transcript for an UNRELATED ceremony must not authorise this keyset.
if (existsSync(join(fixture, "t-foreign.bin"))) {
  const swapped = await exportKeyset("t.bin");
  const m = JSON.parse(await readFile(join(swapped, "SETUP-MANIFEST.json"), "utf8"));
  await copyFile(join(fixture, "t-foreign.bin"), join(swapped, m.ceremony.transcript));
  const refused = runGate(swapped, ["--require-real-value"]);
  assert.notEqual(refused.status, 0, "a foreign transcript authorised this keyset");
  // Assert the SPECIFIC refusal. The vk-binding check runs before the contribution-count check,
  // so a loose match here could pass on the count instead and leave the binding untested.
  assert.match(refused.stderr, /is NOT the one this transcript produces/);
  console.log("CAN-FAIL 3: a foreign transcript does not authorise these keys");
}

console.log(`\nKEYSET PRODUCTION E2E OK (${passed} assertions executed)`);
