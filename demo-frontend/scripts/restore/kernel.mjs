// Detection-scan kernel — the per-note hot loop for birthday-less restore (Menese DeFi Team).
//
// Two byte-IDENTICAL shared-key kernels back the same view-tag recognition:
//   - "reference": nacl.box.before (X25519 + HSalsa20), the demo/sequential scanner's exact
//     primitive. It is the correctness ORACLE — the owned set it produces is ground truth.
//   - "native": node's OpenSSL X25519 (crypto.diffieHellman, byte-identical to nacl.scalarMult
//     by RFC 7748) followed by nacl's own HSalsa20 core, then SHA-512 (node crypto == nacl.hash)
//     for the view tag. A drop-in that is ~13x faster and DIFFERENTIALLY GATED to be
//     byte-identical to the reference (scripts/restore/a0-probe.mjs + the correctness battery
//     prove tag-for-tag identity on 2 seeds + every planted note). This is the "native/WebGPU
//     port is a drop-in" the read-path spec anticipates; the boundary the kernel exposes is a
//     pure (ephPk32, encSk32) -> shared32, so a WASM/GPU implementation slots in the same way.
//
// The view tag saves the full nacl.box.open trial-decrypt, NOT the per-note ECDH: box.before is
// unconditional per note (wallet.js:273). So this kernel's cost IS the Omega(N) detection cost.
import nacl from "tweetnacl";
import crypto from "node:crypto";

const SIGMA = new TextEncoder().encode("expand 32-byte k");
const VIEW_TAG_DOMAIN = new TextEncoder().encode("picp-note-viewtag/v1");
export const VIEW_TAG_LEN = 8;
export const ENTRY_LEN = 48; // (position 8B BE) || note_ciphertext[0..40] == ephPk(32) || tag(8)

// SHA-512-truncated view tag (matches wallet.js `viewTag`: nacl.hash(domain||shared)[0..8]).
// nacl.hash IS SHA-512, so node's SHA-512 is byte-identical and faster in the native path.
function viewTagNacl(shared) {
  const buf = new Uint8Array(VIEW_TAG_DOMAIN.length + shared.length);
  buf.set(VIEW_TAG_DOMAIN, 0);
  buf.set(shared, VIEW_TAG_DOMAIN.length);
  return nacl.hash(buf).slice(0, VIEW_TAG_LEN);
}
function viewTagNative(shared) {
  const h = crypto.createHash("sha512");
  h.update(VIEW_TAG_DOMAIN);
  h.update(shared);
  return new Uint8Array(h.digest().buffer, 0, VIEW_TAG_LEN);
}

// Wrap a raw 32-byte X25519 scalar / point into node KeyObjects (DER prefixes are the fixed
// PKCS8 / SPKI headers for id-X25519).
const PKCS8_X25519 = Buffer.from("302e020100300506032b656e04220420", "hex");
const SPKI_X25519 = Buffer.from("302a300506032b656e032100", "hex");
function privKeyObject(sk32) {
  return crypto.createPrivateKey({ key: Buffer.concat([PKCS8_X25519, Buffer.from(sk32)]), format: "der", type: "pkcs8" });
}
function pubKeyObject(pk32) {
  return crypto.createPublicKey({ key: Buffer.concat([SPKI_X25519, Buffer.from(pk32)]), format: "der", type: "spki" });
}

// Build a matcher closure over a fixed encryption secret key. Returns matchEntry(entry48) ->
// { pos, match }. `sharedOf(ephPk32) -> shared32` is the swappable primitive.
export function makeMatcher(mode, encSk32) {
  let sharedOf, tagOf;
  if (mode === "native") {
    const skObj = privKeyObject(encSk32);
    sharedOf = (pk32) => {
      const raw = crypto.diffieHellman({ privateKey: skObj, publicKey: pubKeyObject(pk32) });
      const out = new Uint8Array(32);
      nacl.lowlevel.crypto_core_hsalsa20(out, new Uint8Array(16), new Uint8Array(raw), SIGMA);
      return out;
    };
    tagOf = viewTagNative;
  } else if (mode === "reference") {
    const sk = Uint8Array.from(encSk32);
    sharedOf = (pk32) => nacl.box.before(pk32, sk);
    tagOf = viewTagNacl;
  } else {
    throw new Error(`unknown kernel mode: ${mode}`);
  }
  return function matchEntry(entry /* Uint8Array length 48 */) {
    let pos = 0;
    for (let k = 0; k < 8; k++) pos = pos * 256 + entry[k];
    const ephPk = entry.subarray(8, 40);
    const tag = entry.subarray(40, 48);
    const shared = sharedOf(ephPk);
    const t = tagOf(shared);
    let eq = true;
    for (let i = 0; i < VIEW_TAG_LEN; i++) if (t[i] !== tag[i]) { eq = false; break; }
    return { pos, match: eq };
  };
}

// Expose the raw shared-key primitive for the differential gate (kernel equivalence proof).
export function sharedKey(mode, encSk32, ephPk32) {
  if (mode === "native") {
    const raw = crypto.diffieHellman({ privateKey: privKeyObject(encSk32), publicKey: pubKeyObject(ephPk32) });
    const out = new Uint8Array(32);
    nacl.lowlevel.crypto_core_hsalsa20(out, new Uint8Array(16), new Uint8Array(raw), SIGMA);
    return out;
  }
  return nacl.box.before(ephPk32, Uint8Array.from(encSk32));
}
