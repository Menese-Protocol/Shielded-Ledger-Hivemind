import assert from "node:assert/strict";
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
