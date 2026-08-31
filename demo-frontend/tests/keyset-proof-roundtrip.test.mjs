// Real proof round-trip against the SERVED keyset: the browser prover wasm (run under node)
// proves a shield and a 2-in/2-out transfer with demo-frontend/public/keys/*, and the vendored
// Motoko ledger verifier (src/groth16/Groth16Wire) verifies those proofs against the served
// verifying keys — the exact prove/verify pair a live deployment executes. A tampered public
// input must still REJECT, so the ACCEPTs are not vacuous.
//
// Run from the repo root: node demo-frontend/tests/keyset-proof-roundtrip.test.mjs
// Requires: src/prover-pkg built (wasm-pack --target web), .mops installed, dfx cache (moc).

import { execFileSync, spawnSync } from "node:child_process";
import { readFile, readdir, unlink, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const frontend = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const root = resolve(frontend, "..");
const keysDir = join(frontend, "public", "keys");

const wasmJs = join(frontend, "src", "prover-pkg", "pool_prover_wasm.js");
const wasmBin = join(frontend, "src", "prover-pkg", "pool_prover_wasm_bg.wasm");
const prover = await import(wasmJs);
await prover.default(await readFile(wasmBin));

const transferPk = new Uint8Array(await readFile(join(keysDir, "transfer_pk.bin")));
const depositPk = new Uint8Array(await readFile(join(keysDir, "deposit_pk.bin")));
const transferVk = (await readFile(join(keysDir, "transfer_vk.hex"), "utf8")).trim();
const depositVk = (await readFile(join(keysDir, "deposit_vk.hex"), "utf8")).trim();

// The prover's own integrity gate: the served proving keys must embed the served vks.
if (prover.assert_pk_matches_vk(transferPk, transferVk) !== true) {
  throw new Error("transfer_pk.bin does not embed transfer_vk.hex");
}
if (prover.assert_pk_matches_vk(depositPk, depositVk) !== true) {
  throw new Error("deposit_pk.bin does not embed deposit_vk.hex");
}
console.log("  PASS  served proving keys embed the served verifying keys");

// deterministic-but-arbitrary wallet secrets (proof randomness itself is WebCrypto-backed)
const seed = (tag) => new TextEncoder().encode(`keyset-roundtrip/${tag}`.padEnd(48, "#"));
const aliceNk = prover.field_from_seed(seed("alice-nk"));
const bobNk = prover.field_from_seed(seed("bob-nk"));
const alicePk = prover.shielded_address(aliceNk);
const bobPk = prover.shielded_address(bobNk);
const rho1 = prover.field_from_seed(seed("rho1"));
const rcm1 = prover.field_from_seed(seed("rcm1"));
const rho2 = prover.field_from_seed(seed("rho2"));
const rcm2 = prover.field_from_seed(seed("rcm2"));
const outRcm1 = prover.field_from_seed(seed("out-rcm1"));
const outRcm2 = prover.field_from_seed(seed("out-rcm2"));

// two shields (70 + 30), proven with the served deposit key
const dep1 = JSON.parse(prover.prove_deposit(depositPk, 70n, alicePk, rho1, rcm1));
const dep2 = JSON.parse(prover.prove_deposit(depositPk, 30n, alicePk, rho2, rcm2));
console.log("  PASS  wasm prover produced two deposit proofs (self-verified in wasm)");

// a 2-in/2-out transfer spending both (55 to Bob, 40 change, fee 5), served transfer key
const witness = {
  leaves: [dep1.cm_hex, dep2.cm_hex],
  in1: { v: 70, nk: aliceNk, rho: rho1, rcm: rcm1, index: 0 },
  in2: { v: 30, nk: aliceNk, rho: rho2, rcm: rcm2, index: 1 },
  out1: { v: 55, pk: bobPk, rcm: outRcm1 },
  out2: { v: 40, pk: alicePk, rcm: outRcm2 },
  fee: 5,
  v_pub_out: 0,
  recipient_binding: "0".repeat(64),
};
const xfer = JSON.parse(prover.prove_transfer(transferPk, JSON.stringify(witness)));
console.log("  PASS  wasm prover produced the transfer proof (hardened statement witness)");

// ---- verify with the vendored Motoko ledger verifier, against the SERVED vks ----
function u64Field(value) {
  const bytes = Buffer.alloc(32);
  bytes.writeBigUInt64LE(BigInt(value));
  return bytes.toString("hex");
}
function inputVector(fields) {
  const count = Buffer.alloc(8);
  count.writeBigUInt64LE(BigInt(fields.length));
  return count.toString("hex") + fields.join("");
}
const transferInputs = inputVector([
  xfer.anchor_hex, xfer.nf1_hex, xfer.nf2_hex, xfer.cm_out1_hex, xfer.cm_out2_hex,
  u64Field(5), u64Field(0), "0".repeat(64),
]);
const tamperedInputs = inputVector([
  xfer.anchor_hex, xfer.nf1_hex, xfer.nf2_hex, xfer.cm_out1_hex, xfer.cm_out2_hex,
  u64Field(6), u64Field(0), "0".repeat(64),
]);
const dep1Inputs = inputVector([dep1.cm_hex, u64Field(70)]);
const dep2Inputs = inputVector([dep2.cm_hex, u64Field(30)]);

const source = `
import Debug "mo:core/Debug";
import Runtime "mo:core/Runtime";
import W "../src/groth16/Groth16Wire";

func fail(message : Text) { Runtime.trap("KEYSET ROUND-TRIP FAIL: " # message) };
func expect(name : Text, got : Text, want : Text) {
  if (got != want) { fail(name # ": got " # got # ", expected " # want) };
};

let transferVk = switch (W.parseAndPrepareVk("${transferVk}")) {
  case (?vk) { vk };
  case (null) { fail("served transfer vk rejected by the ledger verifier"); Runtime.trap("") };
};
let depositVk = switch (W.parseAndPrepareVk("${depositVk}")) {
  case (?vk) { vk };
  case (null) { fail("served deposit vk rejected by the ledger verifier"); Runtime.trap("") };
};

expect("wasm transfer proof vs served vk", W.verifyPrepared(transferVk, "${xfer.proof_hex}", "${transferInputs}"), "ACCEPT");
expect("wasm deposit proof 1 vs served vk", W.verifyPrepared(depositVk, "${dep1.proof_hex}", "${dep1Inputs}"), "ACCEPT");
expect("wasm deposit proof 2 vs served vk", W.verifyPrepared(depositVk, "${dep2.proof_hex}", "${dep2Inputs}"), "ACCEPT");
expect("tampered fee must still reject", W.verifyPrepared(transferVk, "${xfer.proof_hex}", "${tamperedInputs}"), "REJECT:pairing-check");

Debug.print("KEYSET PROOF ROUND-TRIP: browser-wasm proofs verify under the served keys; tamper rejects");
`;

const generated = join(root, "tests", `.KeysetProofRoundTrip.${process.pid}.mo`);
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
  if (result.status !== 0) throw new Error(`round-trip verifier exited ${result.status}`);
} finally {
  await unlink(generated).catch(() => {});
}
