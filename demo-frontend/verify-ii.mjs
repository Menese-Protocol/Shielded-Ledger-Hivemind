// Mainnet Internet Identity smoke test with Chromium's virtual platform passkey.
// The credential exists only inside this disposable browser process.
import { chromium } from "playwright";
import fs from "fs";

const URL = process.env.DEMO_URL || "https://nl5gm-2aaaa-aaaau-ag27q-cai.icp0.io/";
const SHOT = process.env.SHOT_DIR || "verify-shots-mainnet-ii";
fs.mkdirSync(SHOT, { recursive: true });
const results = {};
const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

async function idle(page) {
  await page.waitForTimeout(300);
  await page.waitForFunction(
    () => !document.querySelector('[data-testid="stage"]'),
    undefined,
    { timeout: 240_000 },
  );
}

const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width: 1440, height: 1200 } });
const app = await context.newPage();
async function addVirtualPasskey(page) {
  const session = await context.newCDPSession(page);
  await session.send("WebAuthn.enable");
  const { authenticatorId } = await session.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  return { session, authenticatorId };
}

await addVirtualPasskey(app);

app.on("console", (message) => {
  if (message.type() === "error") console.error("[app console]", message.text());
});
app.on("pageerror", (error) => console.error("[app error]", error.message));
app.on("response", (response) => {
  if (response.status() >= 400) console.error(`[app response] ${response.status()} ${response.url()}`);
});
app.on("requestfailed", (request) => console.error(`[app request failed] ${request.url()} ${request.failure()?.errorText}`));

try {
  console.log("II: loading live app");
  await app.goto(URL, { waitUntil: "domcontentloaded", timeout: 60_000 });
  await app.waitForFunction(
    () => document.querySelector('[data-testid="status"]')?.textContent === "ready",
    undefined,
    { timeout: 240_000 },
  );
  console.log("II: app ready; opening id.ai");
  const popupPromise = context.waitForEvent("page", { timeout: 60_000 });
  await app.click('[data-testid="connect-ii"]');
  const ii = await popupPromise;
  await addVirtualPasskey(ii);
  ii.on("console", (message) => {
    if (message.type() === "error") console.error("[II console]", message.text());
  });
  ii.on("pageerror", (error) => console.error("[II error]", error.message));
  await ii.waitForLoadState("domcontentloaded", { timeout: 60_000 });
  await ii.waitForTimeout(4_000);
  console.log(JSON.stringify({
    url: ii.url(),
    title: await ii.title(),
    body: (await ii.locator("body").innerText()).slice(0, 10_000),
    buttons: await ii.locator("button").allTextContents(),
    inputs: await ii.locator("input").evaluateAll((inputs) => inputs.map((input) => ({
      type: input.type,
      name: input.name,
      placeholder: input.placeholder,
      aria: input.getAttribute("aria-label"),
    }))),
  }, null, 2));
  await ii.screenshot({ path: `${SHOT}/01-ii-entry.png`, fullPage: true });
  await ii.getByRole("button", { name: /^Create\b/ }).click();
  await ii.waitForTimeout(2_000);
  console.log("II CREATE:", JSON.stringify({
    url: ii.url(),
    body: (await ii.locator("body").innerText()).slice(0, 10_000),
    buttons: await ii.locator("button").allTextContents(),
    links: await ii.locator("a").allTextContents(),
  }, null, 2));
  await ii.screenshot({ path: `${SHOT}/02-ii-create.png`, fullPage: true });
  await ii.getByRole("button", { name: /Create with passkey/i }).click();
  await ii.waitForTimeout(5_000).catch(() => {});
  if (!ii.isClosed()) {
    console.log("II PASSKEY:", JSON.stringify({
      url: ii.url(),
      body: (await ii.locator("body").innerText()).slice(0, 10_000),
      buttons: await ii.locator("button").allTextContents(),
      inputs: await ii.locator("input").evaluateAll((inputs) => inputs.map((input) => ({
        type: input.type,
        name: input.name,
        placeholder: input.placeholder,
        aria: input.getAttribute("aria-label"),
      }))),
    }, null, 2));
    await ii.screenshot({ path: `${SHOT}/03-ii-passkey.png`, fullPage: true });
    const nameInput = ii.getByPlaceholder("Identity name");
    if (await nameInput.count()) {
      await nameInput.fill("pICP Playwright disposable");
      await ii.getByRole("button", { name: /^Create identity$/ }).click();
      await Promise.race([
        ii.waitForEvent("close", { timeout: 20_000 }),
        ii.waitForTimeout(20_000),
      ]).catch(() => {});
      if (!ii.isClosed()) {
        console.log("II AFTER NAME:", JSON.stringify({
          url: ii.url(),
          body: (await ii.locator("body").innerText()).slice(0, 10_000),
          buttons: await ii.locator("button").allTextContents(),
        }, null, 2));
        await ii.screenshot({ path: `${SHOT}/04-ii-after-name.png`, fullPage: true });
        const continueButton = ii.getByRole("button", { name: /^Continue$/ });
        if (await continueButton.count()) {
          await continueButton.click();
          await ii.waitForEvent("close", { timeout: 60_000 }).catch(() => {});
          console.log(`II CONTINUE: authorization window ${ii.isClosed() ? "closed" : "still open"}`);
        }
      } else {
        console.log("II AFTER NAME: authorization window closed");
      }
    }
  } else {
    console.log("II PASSKEY: authorization window closed");
  }
  await app.waitForSelector('[data-testid="principal"]', { timeout: 240_000 });
  console.log("APP AFTER II:", JSON.stringify({
    url: app.url(),
    body: (await app.locator("body").innerText()).slice(0, 6_000),
  }, null, 2));
  await app.screenshot({ path: `${SHOT}/04-app-after-ii.png`, fullPage: true });

  results.principal = await app.getAttribute('[data-testid="principal"]', "data-principal");
  results.identityLabel = (await app.textContent('[data-testid="principal"]')).trim();
  assert(results.principal, "II did not return an application principal");
  assert(results.identityLabel.startsWith("II ·"), `unexpected identity label: ${results.identityLabel}`);
  const storedSecrets = await app.evaluate(() =>
    Object.keys(localStorage).filter((key) => key.startsWith("picp-demo-keys:")),
  );
  assert(storedSecrets.length === 0, `shielded secrets persisted: ${storedSecrets.join(",")}`);

  await app.click('[data-testid="faucet-run"]');
  await idle(app);
  results.faucetBalance = (await app.textContent('[data-testid="bal"]')).trim();
  assert(results.faucetBalance.includes("100,000"), `II faucet balance: ${results.faucetBalance}`);

  for (const [amount, expectedNotes] of [["40000", "1"], ["25000", "2"]]) {
    await app.fill('[data-testid="shield-amt"]', amount);
    await app.click('[data-testid="shield-run"]');
    await idle(app);
    const notes = (await app.textContent('[data-testid="note-count"]')).trim();
    assert(notes === expectedNotes, `II notes after shielding ${amount}: ${notes}`);
  }
  await app.screenshot({ path: `${SHOT}/05-ii-two-notes.png`, fullPage: true });

  await app.click('[data-testid="act-5"]');
  const before = (await app.textContent('[data-testid="bal"]')).trim();
  const payoutsBefore = await app.locator('[data-testid="ledger-entry"][data-btype="1xfer"]').count();
  await app.fill('[data-testid="unshield-amt"]', "777");
  await app.click('[data-testid="unshield-run"]');
  await idle(app);
  const withdrawal = (await app.textContent('[data-testid="unshield-result"]')).trim();
  const after = (await app.textContent('[data-testid="bal"]')).trim();
  const payoutsAfter = await app.locator('[data-testid="ledger-entry"][data-btype="1xfer"]').count();
  assert(withdrawal.includes("FINALIZED") && withdrawal.includes("ACCEPT"), `II withdrawal: ${withdrawal}`);
  assert(withdrawal.includes("777 DEMO"), `II custom withdrawal amount: ${withdrawal}`);
  assert(before !== after, `II public balance did not rise: ${before}`);
  assert(payoutsAfter === payoutsBefore + 1, `II payout block delta: ${payoutsAfter - payoutsBefore}`);
  results.withdrawal = { before, after, result: withdrawal };
  await app.screenshot({ path: `${SHOT}/06-ii-withdraw-finalized.png`, fullPage: true });

  // AuthClient restores the II delegation; vetKeys must deterministically recover the same
  // shielded account without any app-owned secret in localStorage.
  await app.reload({ waitUntil: "domcontentloaded", timeout: 60_000 });
  await app.waitForSelector('[data-testid="principal"]', { timeout: 240_000 });
  const recoveredPrincipal = await app.getAttribute('[data-testid="principal"]', "data-principal");
  const recoveredSecrets = await app.evaluate(() =>
    Object.keys(localStorage).filter((key) => key.startsWith("picp-demo-keys:")),
  );
  await app.click('[data-testid="view-mine"]');
  await app.waitForSelector('[data-testid="shielded-bal"]', { timeout: 30_000 });
  await app.waitForFunction(
    () => Number(document.querySelector('[data-testid="note-count"]')?.textContent || "0") > 0,
    undefined,
    { timeout: 240_000 },
  );
  results.recovered = {
    samePrincipal: recoveredPrincipal === results.principal,
    shieldedBalance: (await app.textContent('[data-testid="shielded-bal"]')).trim(),
    notes: (await app.textContent('[data-testid="shielded-notes"]')).trim(),
    storedSecrets: recoveredSecrets.length,
  };
  assert(results.recovered.samePrincipal, "II reload changed the application principal");
  assert(recoveredSecrets.length === 0, "II reload found an app-owned shielded secret");
  assert(!results.recovered.shieldedBalance.startsWith("0"), "vetKey reload did not recover the change note");
  await app.screenshot({ path: `${SHOT}/07-ii-vetkey-recovered.png`, fullPage: true });
  console.log("II VERIFY:", JSON.stringify(results, null, 2));
  console.log("II VERIFY: ALL GREEN");
} catch (error) {
  console.error("II FAIL:", error.message);
  await app.screenshot({ path: `${SHOT}/error.png`, fullPage: true }).catch(() => {});
  process.exitCode = 1;
} finally {
  await browser.close();
}
