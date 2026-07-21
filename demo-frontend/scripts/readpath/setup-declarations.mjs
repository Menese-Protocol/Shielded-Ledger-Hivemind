// Ensure the (gitignored) generated candid declarations exist so `wallet.js -> ic.js` imports
// resolve under plain node (Menese DeFi Team). The read-path battery replaces the real actors with
// a MockLedger, so only a syntactically-valid `idlFactory` export is needed here; the real build
// still runs `dfx generate`. Idempotent: never overwrites a real generated file.
import { mkdirSync, existsSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const declRoot = resolve(here, "../../src/declarations");
const stub = "export const idlFactory = ({ IDL }) => IDL.Service({});\nexport const init = () => [];\n";

for (const name of ["zk_ledger", "demo_token"]) {
  const dir = resolve(declRoot, name);
  const file = resolve(dir, `${name}.did.js`);
  if (!existsSync(file)) {
    mkdirSync(dir, { recursive: true });
    writeFileSync(file, stub);
  }
}
