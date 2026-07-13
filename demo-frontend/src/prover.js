// Thin loader for the client-side WASM prover (Menese DeFi Team).
// All privacy-critical crypto (note secrets, proofs, PIR selectors) runs here in the browser.
import init, * as wasm from "./prover-pkg/pool_prover_wasm.js";

let ready = null;
export async function loadProver() {
  if (!ready) ready = init();
  await ready;
  return wasm;
}

async function checkedFetch(path, kind = "arrayBuffer") {
  const response = await fetch(path);
  if (!response.ok) throw new Error(`keyset asset ${path} returned HTTP ${response.status}`);
  return kind === "json" ? response.json() : response.arrayBuffer();
}

async function sha256Hex(bytes) {
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((value) => value.toString(16).padStart(2, "0")).join("");
}

// Fetch one provenance-bound keyset. A production build refuses the old deterministic setup even
// if all four files are mutually consistent: matching compromised artifacts is not soundness.
export async function loadProvingKeys() {
  const [manifest, transfer, deposit, transferVkBytes, depositVkBytes] = await Promise.all([
    checkedFetch("/keys/SETUP-MANIFEST.json", "json"),
    checkedFetch("/keys/transfer_pk.bin"),
    checkedFetch("/keys/deposit_pk.bin"),
    checkedFetch("/keys/transfer_vk.hex"),
    checkedFetch("/keys/deposit_vk.hex"),
  ]);
  if (manifest.format !== 1 || manifest.proof_system !== "Groth16" || manifest.curve !== "BLS12-381") {
    throw new Error("unsupported or malformed proving-key manifest");
  }
  if (manifest.publicly_reproducible_toxic_waste) {
    throw new Error("refusing proving keys made with the public deterministic test setup");
  }
  const expected = {
    transfer_pk_sha256: transfer,
    deposit_pk_sha256: deposit,
    transfer_vk_sha256: transferVkBytes,
    deposit_vk_sha256: depositVkBytes,
  };
  for (const [field, bytes] of Object.entries(expected)) {
    const actual = await sha256Hex(bytes);
    if (actual !== manifest[field]) throw new Error(`keyset integrity mismatch: ${field}`);
  }
  const decoder = new TextDecoder();
  return {
    transfer: new Uint8Array(transfer),
    deposit: new Uint8Array(deposit),
    transferVk: decoder.decode(transferVkBytes).trim(),
    depositVk: decoder.decode(depositVkBytes).trim(),
    manifest,
  };
}
