// AC-1 cross-language comparer (Menese DeFi Team): reads the Motoko consumer's stdout
// (`key=hex` lines from tests/DetectFrontierCross.mo via wasmtime) on stdin and compares
// EVERY vector in tests/detect-frontier-vectors.json byte-for-byte. Exits nonzero on any
// missing or mismatched vector — the mechanical half of scripts/detect-battery.sh.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(readFileSync(resolve(here, "../../../tests/detect-frontier-vectors.json"), "utf8"));
const input = readFileSync(0, "utf8");
const got = new Map();
for (const line of input.split("\n")) {
  const m = line.match(/^([a-zA-Z]+(?:\[\d+\])?)=([0-9a-f]+|\d+)$/);
  if (m) got.set(m[1], m[2]);
}

let checked = 0, failed = 0;
const expect = (key, value) => {
  checked++;
  if (got.get(key) !== String(value)) {
    failed++;
    console.error(`MISMATCH ${key}: motoko=${got.get(key) ?? "<missing>"} js=${value}`);
  }
};
for (const size of vectors.merkleSizes) expect(`merkle[${size}]`, vectors.merkleRoots[size]);
expect("appendBoundaries", vectors.appendBoundaries);
expect("appendRoot", vectors.appendRoot);
expect("appendCTip", vectors.appendCTip);
expect("appendLeaf", vectors.appendLeaf);

if (failed) {
  console.error(`FRONTIER-CROSS: ${failed}/${checked} MISMATCHED`);
  process.exit(1);
}
console.log(`FRONTIER-CROSS: ${checked}/${checked} vectors byte-identical (JS reference == Motoko frontier)`);
