// A0 microbench worker — runs the detection kernel over `count` synthetic entries and reports
// wall time. Used only to measure worker_threads scaling (Menese DeFi Team).
import { parentPort, workerData } from "node:worker_threads";
import crypto from "node:crypto";
import { makeMatcher, ENTRY_LEN } from "./kernel.mjs";

const { mode, encSk, count } = workerData;
const matcher = makeMatcher(mode, Uint8Array.from(encSk));

// A pool of random 32-byte u-coordinates (valid X25519 public inputs); cycling the pool keeps
// keypair generation out of the measured loop while exercising a full scalarmult per note.
const POOL = 4096;
const pool = [];
for (let i = 0; i < POOL; i++) pool.push(crypto.randomBytes(32));

const entry = new Uint8Array(ENTRY_LEN);
let matched = 0;
const t0 = process.hrtime.bigint();
for (let i = 0; i < count; i++) {
  const pk = pool[i & (POOL - 1)];
  entry.set(pk, 8);
  // random 8-byte tag region (won't match, which is the realistic non-owner case)
  const r = pool[(i + 1) & (POOL - 1)];
  for (let j = 0; j < 8; j++) entry[40 + j] = r[j];
  // encode position big-endian
  let p = i;
  for (let k = 7; k >= 0; k--) { entry[k] = p & 0xff; p = Math.floor(p / 256); }
  if (matcher(entry).match) matched++;
}
const t1 = process.hrtime.bigint();
parentPort.postMessage({ elapsedNs: Number(t1 - t0), matched, count });
