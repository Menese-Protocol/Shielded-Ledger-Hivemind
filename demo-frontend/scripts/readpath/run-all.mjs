// Run the whole read-path battery — B-P1..B-P5 + wallet birthday (B-B) — and aggregate
// (Menese DeFi Team).
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
// The declaration stubs must exist BEFORE a battery module graph is linked (ESM resolves the
// whole graph statically, so an in-battery side-effect import runs too late on a fresh
// worktree) — generate them in a separate process first.
execFileSync(process.execPath, [resolve(here, "setup-declarations.mjs")], { stdio: "inherit" });
const items = ["b-p1", "b-p2", "b-p3", "b-p4", "b-p5", "b-birthday"];
let failed = 0;
for (const item of items) {
  console.log(`\n===== ${item} =====`);
  try {
    execFileSync(process.execPath, [resolve(here, `${item}.mjs`)], { stdio: "inherit" });
  } catch {
    failed++;
  }
}
console.log(`\n########## READ-PATH BATTERY: ${items.length - failed}/${items.length} items green ##########`);
process.exit(failed ? 1 : 0);
