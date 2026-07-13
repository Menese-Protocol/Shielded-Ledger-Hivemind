import { BASE } from "./config.js";

/** Parse a user-entered DEMO amount without ever passing through floating point. */
export function parseDemoAmount(text) {
  const trimmed = text.trim();
  const plain = /^\d+(\.\d{0,8})?$/;
  const grouped = /^\d{1,3}(,\d{3})+(\.\d{0,8})?$/;
  if (!plain.test(trimmed) && !grouped.test(trimmed)) return null;
  const normalized = trimmed.replaceAll(",", "");
  const [whole, fraction = ""] = normalized.split(".");
  return BigInt(whole) * BASE + BigInt(fraction.padEnd(8, "0"));
}
