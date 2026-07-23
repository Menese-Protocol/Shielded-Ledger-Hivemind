// AC-1 cross-language vector generator (Menese DeFi Team): the JS reference construction
// (detect-chain.mjs, full merkleRoot recompute + buildStream) emits frozen vectors that the
// Motoko incremental frontier must reproduce byte-for-byte (consumer:
// tests/DetectFrontierCross.mo; comparer: scripts/detect-battery.sh).
//
// Leaf formula (language-neutral, exact in both JS Number and Motoko Nat):
//   leaf[i][b] = (i*2654435761 + b*40503) mod 256            (32-byte boundary leaves)
// Append-path entries are REAL protocol entries: posBE8(i) ‖ ct_i[0..40) with the
// ciphertext formula ct_i[j] = (i*7 + j*3) mod 256 — so the Motoko side exercises the
// actual DetectChain.append/entryBytes path, not a raw fold.
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { merkleRoot, buildStream, posBE8, DPAGE } from "./detect-chain.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const hex = (u8) => Buffer.from(u8).toString("hex");

const leafAt = (i) => {
  const b = new Uint8Array(32);
  for (let k = 0; k < 32; k++) b[k] = (i * 2654435761 + k * 40503) % 256;
  return b;
};

// merkle cross-check sizes: every boundary-shape class (powers of two, +/-1 neighbours,
// DPAGE neighbours) plus the 10^8-note scale count 24,414
const MERKLE_SIZES = [1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17, 255, 256, 257, 1023, 1024, 1025, 4095, 4096, 4097, 12207, 24413, 24414];
const maxSize = Math.max(...MERKLE_SIZES);
const leaves = [];
const merkleRoots = {};
for (let i = 0; i < maxSize; i++) {
  leaves.push(leafAt(i));
  if (MERKLE_SIZES.includes(i + 1)) merkleRoots[i + 1] = hex(merkleRoot(leaves));
}

// append-path: 25 complete segments + a 517-entry partial tail (cTip != last boundary),
// through REAL protocol entries (position prefix + ciphertext slice)
const APPEND_N = 25 * DPAGE + 517; // 102,917 notes → 25 boundaries + tail
const entryAt = (i) => {
  const e = new Uint8Array(48);
  e.set(posBE8(i), 0);
  for (let j = 0; j < 40; j++) e[8 + j] = (i * 7 + j * 3) % 256;
  return e;
};
const st = buildStream(entryAt, APPEND_N);

const out = {
  leafFormula: "leaf[i][b] = (i*2654435761 + b*40503) mod 256",
  entryFormula: "entry[i] = posBE8(i) || ct_i[0..40), ct_i[j] = (i*7 + j*3) mod 256",
  merkleSizes: MERKLE_SIZES,
  merkleRoots,
  appendN: APPEND_N,
  appendBoundaries: st.boundaries.length,
  appendRoot: hex(st.root),
  appendCTip: hex(st.cTip),
  appendLeaf: hex(st.leaf),
};
const target = resolve(here, "../../../tests/detect-frontier-vectors.json");
writeFileSync(target, JSON.stringify(out, null, 2) + "\n");
console.log(`wrote ${target}: ${MERKLE_SIZES.length} merkle sizes (max ${maxSize}), append N=${APPEND_N} (${st.boundaries.length} boundaries)`);
