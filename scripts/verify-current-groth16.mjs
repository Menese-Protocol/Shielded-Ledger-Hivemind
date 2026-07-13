import { execFileSync, spawnSync } from "node:child_process";
import { readFile, readdir, unlink, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const fixture = join(root, "fixtures", "pool-vectors-bls12-381");

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

function u64Field(value) {
  if (value < 0n || value > 0xffff_ffff_ffff_ffffn) throw new Error("u64 fixture overflow");
  const field = Buffer.alloc(32);
  field.writeBigUInt64LE(value);
  return field.toString("hex");
}

function inputVector(fields) {
  const count = Buffer.alloc(8);
  count.writeBigUInt64LE(BigInt(fields.length));
  return count.toString("hex") + fields.join("");
}

function mutateCanonicalField(value) {
  const bytes = Buffer.from(value, "hex");
  bytes[0] ^= 1;
  return bytes.toString("hex");
}

const fee = await nat("fee.txt");
const publicOut = await nat("v_pub_out.txt");
const withdrawFee = await nat("withdraw_fee.txt");
const withdrawPublicOut = await nat("withdraw_v_pub_out.txt");
const deposit1Value = await nat("deposit1_v.txt");
const deposit2Value = await nat("deposit2_v.txt");

const transferFields = [
  await hex("anchor.hex"),
  await hex("nf1.hex"),
  await hex("nf2.hex"),
  await hex("cm_out1.hex"),
  await hex("cm_out2.hex"),
  u64Field(fee),
  u64Field(publicOut),
  await hex("recipient_binding.hex"),
];
const fakeTreeFields = [
  await hex("fake_anchor.hex"),
  await hex("fake_nf1.hex"),
  await hex("fake_nf2.hex"),
  await hex("fake_cm_out1.hex"),
  await hex("fake_cm_out2.hex"),
  u64Field(fee),
  u64Field(publicOut),
  await hex("recipient_binding.hex"),
];
const withdrawFields = [
  await hex("withdraw_anchor.hex"),
  await hex("withdraw_nf1.hex"),
  await hex("withdraw_nf2.hex"),
  await hex("withdraw_cm_out1.hex"),
  await hex("withdraw_cm_out2.hex"),
  u64Field(withdrawFee),
  u64Field(withdrawPublicOut),
  await hex("withdraw_recipient_binding.hex"),
];
const deposit1Fields = [await hex("deposit1_cm.hex"), u64Field(deposit1Value)];
const deposit2Fields = [await hex("deposit2_cm.hex"), u64Field(deposit2Value)];

const badFeeFields = transferFields.slice();
badFeeFields[5] = u64Field(fee + 1n);
const badRecipientFields = transferFields.slice();
badRecipientFields[7] = mutateCanonicalField(badRecipientFields[7]);
const badWithdrawRecipientFields = withdrawFields.slice();
badWithdrawRecipientFields[7] = mutateCanonicalField(badWithdrawRecipientFields[7]);
const depositAmountLieFields = deposit1Fields.slice();
depositAmountLieFields[1] = u64Field(deposit1Value + 1n);

const values = {
  transferVk: await hex("transfer_vk.hex"),
  depositVk: await hex("deposit_vk.hex"),
  transferProof: await hex("transfer_proof.hex"),
  badProof: await hex("transfer_badproof.hex"),
  fakeProof: await hex("fake_proof.hex"),
  withdrawProof: await hex("withdraw_proof.hex"),
  deposit1Proof: await hex("deposit1_proof.hex"),
  deposit2Proof: await hex("deposit2_proof.hex"),
  transferInputs: inputVector(transferFields),
  badFeeInputs: inputVector(badFeeFields),
  badRecipientInputs: inputVector(badRecipientFields),
  sevenInputs: inputVector(transferFields.slice(0, 7)),
  fakeInputs: inputVector(fakeTreeFields),
  withdrawInputs: inputVector(withdrawFields),
  badWithdrawRecipientInputs: inputVector(badWithdrawRecipientFields),
  deposit1Inputs: inputVector(deposit1Fields),
  deposit2Inputs: inputVector(deposit2Fields),
  depositAmountLieInputs: inputVector(depositAmountLieFields),
};

const source = `
import Debug "mo:core/Debug";
import Runtime "mo:core/Runtime";
import W "../src/groth16/Groth16Wire";

func fail(message : Text) { Runtime.trap("CURRENT-GROTH16 FAIL: " # message) };
func expect(name : Text, got : Text, want : Text) {
  if (got != want) { fail(name # ": got " # got # ", expected " # want) };
};

let transferVk = switch (W.parseAndPrepareVk("${values.transferVk}")) {
  case (?vk) { vk };
  case (null) { fail("current transfer vk rejected"); Runtime.trap("") };
};
let depositVk = switch (W.parseAndPrepareVk("${values.depositVk}")) {
  case (?vk) { vk };
  case (null) { fail("current deposit vk rejected"); Runtime.trap("") };
};

expect("current transfer", W.verifyPrepared(transferVk, "${values.transferProof}", "${values.transferInputs}"), "ACCEPT");
expect("tampered fee", W.verifyPrepared(transferVk, "${values.transferProof}", "${values.badFeeInputs}"), "REJECT:pairing-check");
expect("tampered transfer recipient", W.verifyPrepared(transferVk, "${values.transferProof}", "${values.badRecipientInputs}"), "REJECT:pairing-check");
expect("old seven-input shape", W.verifyPrepared(transferVk, "${values.transferProof}", "${values.sevenInputs}"), "REJECT:error:E_BAD_LENGTH");
expect("fabricated tree pairing control", W.verifyPrepared(transferVk, "${values.fakeProof}", "${values.fakeInputs}"), "ACCEPT");
expect("current withdraw", W.verifyPrepared(transferVk, "${values.withdrawProof}", "${values.withdrawInputs}"), "ACCEPT");
expect("tampered withdraw recipient", W.verifyPrepared(transferVk, "${values.withdrawProof}", "${values.badWithdrawRecipientInputs}"), "REJECT:pairing-check");
expect("deposit one", W.verifyPrepared(depositVk, "${values.deposit1Proof}", "${values.deposit1Inputs}"), "ACCEPT");
expect("deposit two", W.verifyPrepared(depositVk, "${values.deposit2Proof}", "${values.deposit2Inputs}"), "ACCEPT");
expect("deposit amount lie", W.verifyPrepared(depositVk, "${values.deposit1Proof}", "${values.depositAmountLieInputs}"), "REJECT:pairing-check");
expect("truncated proof", W.verifyPrepared(transferVk, "00", "${values.transferInputs}"), "REJECT:proof-deserialize");
expect("malformed hex", W.verifyPrepared(transferVk, "zz", "${values.transferInputs}"), "REJECT:hex");

let badProofVerdict = W.verifyPrepared(transferVk, "${values.badProof}", "${values.transferInputs}");
if (badProofVerdict != "REJECT:proof-deserialize" and badProofVerdict != "REJECT:pairing-check") {
  fail("one-bit proof mutation accepted: " # badProofVerdict);
};

Debug.print("CURRENT Groth16 fixture gate: ALL GREEN");
Debug.print("  current 8-input transfer + recipient-bound withdraw ACCEPT");
Debug.print("  fee/recipient/amount/proof/shape mutations REJECT; fake-tree control pairing-ACCEPT");
`;

const generated = join(root, "tests", `.CurrentGroth16FixtureTest.${process.pid}.mo`);
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
  if (result.status !== 0) throw new Error(`Motoko current-fixture gate exited ${result.status}`);
} finally {
  await unlink(generated).catch(() => {});
}
