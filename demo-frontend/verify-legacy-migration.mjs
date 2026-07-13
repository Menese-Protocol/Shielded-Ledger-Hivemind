// Development-only Playwright proof that an original localStorage wallet can move all of its
// notes into the deterministic principal-bound vetKey account and recover them after reload.
import { chromium } from "playwright";
import { randomBytes } from "crypto";
import fs from "fs";

const URL = process.env.DEMO_URL || "http://127.0.0.1:5178/";
const SHOT = process.env.SHOT_DIR || "verify-shots-legacy-migration";
const seed = randomBytes(32).toString("hex");
const legacySeed = randomBytes(32).toString("hex");
const target = `${URL}?mode=demo&e2e_seed=${seed}`;
fs.mkdirSync(SHOT, { recursive: true });

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1440, height: 1700 } });
page.on("console", (message) => {
  if (message.type() === "error") console.error("[browser]", message.text());
});
page.on("pageerror", (error) => console.error("[pageerror]", error.stack || error.message));

async function ready() {
  await page.waitForFunction(
    () => document.querySelector('[data-testid="status"]')?.textContent === "ready",
    undefined,
    { timeout: 240_000 },
  );
  await page.waitForSelector('[data-testid="principal"]', { timeout: 120_000 });
}

async function idle() {
  await page.waitForTimeout(300);
  await page.waitForFunction(
    () => !document.querySelector('[data-testid="stage"]'),
    undefined,
    { timeout: 240_000 },
  );
}

try {
  await page.goto(target, { waitUntil: "domcontentloaded", timeout: 60_000 });
  await ready();

  const prepared = await page.evaluate(async ({ currentSeedHex, legacySeedHex }) => {
    const A = await import("/src/auth.js");
    const IC = await import("/src/ic.js");
    const P = await import("/src/prover.js");
    const W = await import("/src/wallet.js");
    const wasm = await P.loadProver();
    const keys = await P.loadProvingKeys();
    const currentIdentity = A.throwawayIdentity(IC.hexToBytes(currentSeedHex));
    const currentActors = await IC.actorsFor(currentIdentity);
    const currentPrincipal = currentActors.principal.toText();
    const legacyIdentity = A.throwawayIdentity(IC.hexToBytes(legacySeedHex));
    const actors = await IC.actorsFor(legacyIdentity);
    const principal = actors.principal.toText();
    if (principal === currentPrincipal) throw new Error("test identities unexpectedly match");

    const nk = wasm.random_field();
    const encSk = crypto.getRandomValues(new Uint8Array(32));
    const encSkB64 = btoa(String.fromCharCode(...encSk));
    localStorage.setItem(`picp-demo-keys:${principal}`, JSON.stringify({ nk, encSk: encSkB64 }));
    const legacy = A.legacyShieldedAccountFor(wasm, principal);
    if (!legacy) throw new Error("could not reconstruct legacy account");
    const registered = await W.registerInDirectory(actors, legacy, A.encPkHex(legacy.encPk));
    if ("err" in registered) throw new Error(`legacy registration: ${registered.err}`);

    await W.faucet(actors);
    for (const value of [30_000n, 20_000n]) {
      const shielded = await W.shield(actors, wasm, keys, legacy, value * 100_000_000n);
      if (shielded.res.outcome !== "ACCEPT") {
        throw new Error(`legacy shield rejected: ${shielded.res.outcome}`);
      }
    }
    const before = await W.scanNotes(actors, wasm, legacy);
    return {
      principal,
      currentPrincipal,
      notes: before.notes.length,
      value: before.notes.reduce((sum, note) => sum + note.v, 0n).toString(),
      storageKey: `picp-demo-keys:${principal}`,
    };
  }, { currentSeedHex: seed, legacySeedHex: legacySeed });

  if (prepared.notes !== 2 || prepared.value !== "5000000000000") {
    throw new Error(`legacy setup mismatch: ${JSON.stringify(prepared)}`);
  }

  // Reloading the same development-only identity exercises the real connect-time chooser:
  // directory + localStorage match the old account, while vetKey supplies the migration target.
  await page.reload({ waitUntil: "domcontentloaded", timeout: 60_000 });
  await ready();
  await page.waitForSelector('[data-testid="key-migration"]', { timeout: 120_000 });
  await page.screenshot({ path: `${SHOT}/01-legacy-detected.png`, fullPage: true });

  await page.click('[data-testid="migrate-keys"]');
  await idle();
  await page.waitForSelector('[data-testid="key-migration"]', { state: "detached", timeout: 240_000 });

  const afterMigration = await page.evaluate((storageKey) => ({
    legacySecret: localStorage.getItem(storageKey),
    leakedSecretKeys: Object.keys(localStorage).filter((key) => key.startsWith("picp-demo-keys:")),
  }), prepared.storageKey);
  if (afterMigration.legacySecret !== null || afterMigration.leakedSecretKeys.length !== 0) {
    throw new Error(`legacy secret survived migration: ${JSON.stringify(afterMigration)}`);
  }

  await page.reload({ waitUntil: "domcontentloaded", timeout: 60_000 });
  await ready();
  await page.click('[data-testid="view-mine"]');
  await page.click('[data-testid="rescan-mine"]');
  await idle();
  const recovered = await page.textContent('[data-testid="shielded-bal"]');
  if (!recovered?.includes("50,000")) {
    throw new Error(`vetKey account did not recover the migrated value: ${recovered}`);
  }
  if (await page.locator('[data-testid="key-migration"]').count()) {
    throw new Error("migration prompt returned after vetKey recovery");
  }
  await page.screenshot({ path: `${SHOT}/02-vetkey-recovered.png`, fullPage: true });
  console.log(JSON.stringify({ ...prepared, recovered, legacySecretErased: true }, null, 2));
  console.log("VERIFY LEGACY MIGRATION: ALL GREEN");
} catch (error) {
  console.error("VERIFY LEGACY MIGRATION: FAIL", error.message);
  await page.screenshot({ path: `${SHOT}/error.png`, fullPage: true }).catch(() => {});
  process.exitCode = 1;
} finally {
  await browser.close();
}
