import assertRaw from "node:assert/strict";

// Executed-assertion counter. Delegates to node:assert/strict UNCHANGED and records what actually
// EXECUTED. No assertion is weakened, added or reordered
// (docs/thresholds/THRESHOLDS-assertion-count.md N-6) -- this wraps, it does not alter. A
// runtime counter is required rather than a static one: this file runs its assertions in loops,
// so a call-site grep undercounts them.
let passed = 0;
const count = (fn) => (...a) => { const r = fn(...a); passed += 1; return r; };
const assert = new Proxy(assertRaw, {
  apply: (t, self, a) => { const r = Reflect.apply(t, self, a); passed += 1; return r; },
  get: (t, p) => { const v = Reflect.get(t, p); return typeof v === "function" ? count(v.bind(t)) : v; },
});
import { parseDemoAmount } from "../src/amounts.js";

const accepted = new Map([
  ["0", 0n],
  ["1", 100_000_000n],
  ["1.", 100_000_000n],
  ["0.00000001", 1n],
  ["1.23456789", 123_456_789n],
  ["12,345.00000001", 1_234_500_000_001n],
  [" 42.5 ", 4_250_000_000n],
]);
for (const [text, expected] of accepted) {
  assert.equal(parseDemoAmount(text), expected, `wrong exact amount for ${JSON.stringify(text)}`);
}

for (const text of ["", " ", ".1", "-1", "+1", "1e3", "1.000000001", "1,2,3", "NaN", "∞"]) {
  assert.equal(parseDemoAmount(text), null, `malformed amount accepted: ${JSON.stringify(text)}`);
}

console.log("AMOUNT PARSER: exact 8-decimal and malformed-input battery GREEN");
console.log(`=== RESULT: ${passed} passed, 0 failed ===`);
