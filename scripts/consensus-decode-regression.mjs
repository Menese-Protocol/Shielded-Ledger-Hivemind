// Consensus-decode regression battery (audit §4 rec 3), behavioral leg.
//
// Feeds non-canonical / overflow / boundary field encodings through the REAL ledger decode
// path — src/groth16/Groth16Wire.verifyPrepared over the shipped hardened fixture vk/proof —
// and asserts the EXACT verdict class for each. The headline regression: if the decode were
// ever "optimized" to reduce mod r instead of rejecting (the F2 weakening), the `nf1 + r`
// encoding would reduce to the proven nullifier and the pairing would ACCEPT — turning the
// expected REJECT:inputs-deserialize into an ACCEPT and failing this battery loudly. The
// canonical-but-wrong boundary encodings (r-1, 0, fee=2^64) prove the decode is EXACTLY
// `< r`: they pass decoding and die at the pairing, pinning where each defense lives.
//
// fee = 2^64 in particular documents the F1b/F3 dependency: the wire layer accepts ANY
// canonical field element for fee/v_pub_out — nothing below Main.mo's `Nat64` typing +
// nat64Field bounds them for the legacy statement. That seam is pinned structurally by
// scripts/consensus-seam-guard.sh; this case proves the wire really would carry the wrapped
// value if the typing seam ever widened.
//
// The ledger's non-decode nullifier guards (REJECT:nullifier-noncanonical, ordered before the
// spent-set write) are exercised against the live canister by the e2e replica battery
// (e2e.py, Z-DECODE section); this script needs only moc + the frozen fixtures.

import { execFileSync, spawnSync } from "node:child_process";
import { readFile, readdir, unlink, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const fixture = join(root, "fixtures", "pool-vectors-bls12-381-hardened");

// BLS12-381 scalar-field modulus r (Fr.mo pins the same constant; the seam guard checks it).
const R = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n;

async function hex(name) {
  const value = (await readFile(join(fixture, name), "utf8")).trim().toLowerCase();
  if (!/^[0-9a-f]+$/.test(value) || value.length % 2 !== 0) {
    throw new Error(`malformed hex fixture: ${name}`);
  }
  return value;
}
async function nat(name) {
  const value = (await readFile(join(fixture, name), "utf8")).trim();
  if (!/^\d+$/.test(value)) throw new Error(`malformed integer fixture: ${name}`);
  return BigInt(value);
}

// 32-byte little-endian hex of a BigInt (the arkworks compressed-Fr wire encoding).
function leHex(value) {
  if (value < 0n || value >= 1n << 256n) throw new Error("field encoding out of 32 bytes");
  const bytes = Buffer.alloc(32);
  let v = value;
  for (let i = 0; i < 32; i++) { bytes[i] = Number(v & 0xffn); v >>= 8n; }
  return bytes.toString("hex");
}
const leInt = (hexStr) => {
  const bytes = Buffer.from(hexStr, "hex");
  let v = 0n;
  for (let i = 31; i >= 0; i--) v = (v << 8n) | BigInt(bytes[i]);
  return v;
};
function inputVector(fields) {
  const count = Buffer.alloc(8);
  count.writeBigUInt64LE(BigInt(fields.length));
  return count.toString("hex") + fields.join("");
}

const fee = await nat("fee.txt");
const publicOut = await nat("v_pub_out.txt");
const base = [
  await hex("anchor.hex"),
  await hex("nf1.hex"),
  await hex("nf2.hex"),
  await hex("cm_out1.hex"),
  await hex("cm_out2.hex"),
  leHex(fee),
  leHex(publicOut),
  await hex("recipient_binding.hex"),
];
const nf1 = leInt(base[1]);
const anchor = leInt(base[0]);
if (nf1 >= R || anchor >= R) throw new Error("fixture fields must be canonical");

const withField = (index, encodedHex) => {
  const fields = base.slice();
  fields[index] = encodedHex;
  return inputVector(fields);
};

const vectors = {
  transferVk: await hex("transfer_vk.hex"),
  transferProof: await hex("transfer_proof.hex"),
  baseline: inputVector(base),
  // non-canonical: same field element as nf1, second byte encoding (nf1 + r < 2^256)
  nf1PlusR: withField(1, leHex(nf1 + R)),
  // non-canonical: exactly r (the smallest non-canonical value)
  nf1ExactR: withField(1, leHex(R)),
  // non-canonical: 2^256 - 1 (every bit set)
  nf1AllOnes: withField(1, leHex((1n << 256n) - 1n)),
  // non-canonical in a different slot: the anchor
  anchorPlusR: withField(0, leHex(anchor + R)),
  // canonical BOUNDARY encodings: decode must ACCEPT these and the pairing must reject
  nf1RMinusOne: withField(1, leHex(R - 1n)),
  nf1Zero: withField(1, leHex(0n)),
  // fee = 2^64: canonical for the field, IMPOSSIBLE through nat64Field(Nat64) — the wire
  // accepts it, proving the Nat64 typing seam (not this decode) is the fee range bound
  feeTwoPow64: withField(5, leHex(1n << 64n)),
};

const source = `
import Debug "mo:core/Debug";
import Runtime "mo:core/Runtime";
import W "../src/groth16/Groth16Wire";

func fail(message : Text) { Runtime.trap("CONSENSUS-DECODE FAIL: " # message) };
func expect(name : Text, got : Text, want : Text) {
  if (got != want) { fail(name # ": got " # got # ", expected " # want) };
};

let vk = switch (W.parseAndPrepareVk("${vectors.transferVk}")) {
  case (?value) { value };
  case (null) { fail("hardened transfer vk rejected"); Runtime.trap("") };
};
let proof = "${vectors.transferProof}";

// the baseline proves the harness reaches the pairing at all — a battery whose ACCEPT leg
// is broken would "reject" everything and prove nothing
expect("baseline (all-canonical)", W.verifyPrepared(vk, proof, "${vectors.baseline}"), "ACCEPT");

// non-canonical encodings: REJECTED AT DECODE, exact class, regardless of slot
expect("nf1 + r (second encoding of the proven nullifier)", W.verifyPrepared(vk, proof, "${vectors.nf1PlusR}"), "REJECT:inputs-deserialize");
expect("nf1 = r (smallest non-canonical)", W.verifyPrepared(vk, proof, "${vectors.nf1ExactR}"), "REJECT:inputs-deserialize");
expect("nf1 = 2^256 - 1 (overflow encoding)", W.verifyPrepared(vk, proof, "${vectors.nf1AllOnes}"), "REJECT:inputs-deserialize");
expect("anchor + r (non-canonical in another slot)", W.verifyPrepared(vk, proof, "${vectors.anchorPlusR}"), "REJECT:inputs-deserialize");

// canonical boundary encodings: decode ACCEPTS (strictly < r), pairing rejects the wrong value
expect("nf1 = r - 1 (canonical boundary)", W.verifyPrepared(vk, proof, "${vectors.nf1RMinusOne}"), "REJECT:pairing-check");
expect("nf1 = 0 (canonical floor)", W.verifyPrepared(vk, proof, "${vectors.nf1Zero}"), "REJECT:pairing-check");
expect("fee = 2^64 (canonical; unreachable through nat64Field)", W.verifyPrepared(vk, proof, "${vectors.feeTwoPow64}"), "REJECT:pairing-check");

Debug.print("CONSENSUS-DECODE REGRESSION: ALL 8 VERDICT CLASSES EXACT");
Debug.print("  non-canonical encodings REJECT:inputs-deserialize in every slot;");
Debug.print("  canonical boundaries reach the pairing — the decode is exactly (< r), never a reduction");
`;

const generated = join(root, "tests", `.ConsensusDecodeRegression.${process.pid}.mo`);
await writeFile(generated, source, { mode: 0o600 });
try {
  const cache = execFileSync("dfx", ["cache", "show"], { encoding: "utf8" }).trim();
  const moc = process.env.MOC || join(cache, "moc");
  const packages = await readdir(join(root, ".mops"));
  const core = packages.find((name) => name.startsWith("core@"));
  if (!core) throw new Error("mo:core package is not installed");
  const result = spawnSync(
    moc,
    ["-r", "--package", "core", join(root, ".mops", core, "src"), generated],
    { cwd: root, encoding: "utf8", maxBuffer: 16 * 1024 * 1024 },
  );
  process.stdout.write(result.stdout || "");
  process.stderr.write(result.stderr || "");
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`consensus-decode regression exited ${result.status}`);
} finally {
  await unlink(generated).catch(() => {});
}
