// Mirror + trusted-anchor model for the restore harness (Menese DeFi Team).
//
// Separates a TRUSTED anchor (root, cTip, note_count — what the IC certificate binds via the
// `detect_stream` tuple leaf) from UNTRUSTED SERVING (segment bytes + boundary proofs, which a
// CDN/mirror provides and may corrupt). The parallel scanner verifies mirror bytes against the
// trusted anchor before scanning; tamper batteries corrupt only the mirror path.
import crypto from "node:crypto";
import nacl from "tweetnacl";
import { DPAGE, ENTRY_LEN, posBE8, buildStream, merkleProof } from "./detect-chain.mjs";
import { sharedKey } from "./kernel.mjs";

const enc = new TextEncoder();
const DOMAIN = enc.encode("picp-note-viewtag/v1");
function viewTag(shared) {
  const h = crypto.createHash("sha512"); h.update(DOMAIN); h.update(shared);
  return new Uint8Array(h.digest().buffer, 0, 8);
}

// ---- synthetic stream (scale mode): deterministic non-owned entries + a few planted owned ----
// plantedMap: Map<position, {ephPk:Uint8Array(32), tag:Uint8Array(8)}> for owned notes.
export function makeSynthetic(seedText, plantedMap = new Map()) {
  const seed = crypto.createHash("sha256").update(seedText).digest();
  return function entryAt(i) {
    const e = new Uint8Array(ENTRY_LEN);
    e.set(posBE8(i), 0);
    const planted = plantedMap.get(i);
    if (planted) { e.set(planted.ephPk, 8); e.set(planted.tag, 40); return e; }
    const r = crypto.createHash("sha256").update(seed).update(posBE8(i)).digest();
    e.set(new Uint8Array(r.buffer, 0, 32), 8);   // ephPk (valid X25519 u-coord)
    const t = crypto.createHash("sha256").update(seed).update("tag").update(posBE8(i)).digest();
    e.set(new Uint8Array(t.buffer, 0, 8), 40);   // non-matching tag
    return e;
  };
}

// Build a real owned note for planting: returns {position, ephPk, tag, ciphertext, commitment, v,rho,rcm}.
export function plantOwned(account, wasmShim, position, seedByte) {
  const ephSeed = crypto.createHash("sha256").update("plant").update(Uint8Array.of(seedByte)).update(posBE8(position)).digest();
  const eph = nacl.box.keyPair.fromSecretKey(new Uint8Array(ephSeed));
  const shared = sharedKey("native", account.encSk, eph.publicKey); // == nacl.box.before
  const tag = viewTag(shared);
  const v = BigInt(1 + (seedByte * 131 + position) % 1_000_000);
  const rho = wasmShim.random_field(), rcm = wasmShim.random_field();
  const commitment = Buffer.from(wasmShim.note_commitment_hex(v, account.pk, rho, rcm), "hex");
  // real envelope (tagged) so retrieval opens + commitment-checks it
  const nonce = crypto.randomBytes(24);
  const payload = enc.encode(JSON.stringify({ v: v.toString(), rho, rcm }));
  const boxed = nacl.box.after(payload, nonce, nacl.box.before(eph.publicKey, account.encSk));
  const envelope = new Uint8Array(32 + 8 + 24 + boxed.length);
  envelope.set(eph.publicKey, 0); envelope.set(tag, 32); envelope.set(nonce, 40); envelope.set(boxed, 64);
  return { position, ephPk: eph.publicKey, tag, ciphertext: envelope, commitment: new Uint8Array(commitment), v, rho, rcm };
}

// Trusted anchor over an entry generator (models the ledger's certified detect_stream leaf).
export function buildAnchor(entryAt, total) {
  const st = buildStream(entryAt, total);
  return {
    root: st.root, cTip: st.cTip, noteCount: total, leaf: st.leaf, boundaries: st.boundaries,
    // boundary proof for leaf j (0-based complete-segment index)
    proofFor: (j) => ({ leaf: st.boundaries[j], path: merkleProof(st.boundaries, j) }),
  };
}

// A mirror serving segment bytes AND boundary proofs from an entry generator; both are UNTRUSTED
// and tamperable. root/cTip stay on the trusted side (buildAnchor). tamper(segBytes, segIndex) ->
// possibly-mutated Uint8Array (shorter => truncation). proofTamper(proof, j) -> mutated proof.
export function makeMirror(entryAt, total, { tamper = null, anchor = null, proofTamper = null } = {}) {
  return {
    total,
    segmentBytes(from, to) {
      const end = Math.min(to, total);
      const out = new Uint8Array((end - from) * ENTRY_LEN);
      for (let i = from; i < end; i++) out.set(entryAt(i), (i - from) * ENTRY_LEN);
      return tamper ? tamper(out, Math.floor(from / DPAGE)) : out;
    },
    // boundary leaf j + Merkle path (mirror-served; verified against the trusted root by the client)
    boundaryProof(j) {
      const p = anchor.proofFor(j);
      return proofTamper ? proofTamper(p, j) : p;
    },
  };
}

export { viewTag, DPAGE, ENTRY_LEN };
