// Thin loader for the client-side WASM prover (Menese DeFi Team).
// All privacy-critical crypto (note secrets, proofs, PIR selectors) runs here in the browser.
import init, * as wasm from "./prover-pkg/pool_prover_wasm.js";
import { loadKeyset } from "./keyset.js";

let ready = null;
export async function loadProver() {
  if (!ready) ready = init();
  await ready;
  return wasm;
}

export async function loadProvingKeys(anchor) {
  return loadKeyset(anchor);
}
