// Playwright verify rig for the pICP shielded-pool demo (Menese DeFi Team).
// Two browser contexts = two people: A (sender) and B (recipient), each with its own throwaway
// principal. Drives the full journey — register → faucet → shield ×2 → private send to B's
// principal → "nothing was written" stamp → B discovers the money by rescanning → PIR →
// recipient-bound withdrawal — and screenshots each beat. Bounded assertions, committed first.
import { chromium } from "playwright";
import fs from "fs";
import { execFileSync } from "child_process";

const URL = process.env.DEMO_URL || "http://localhost:5178/";
const SHOT = process.env.SHOT_DIR || "verify-shots";
fs.mkdirSync(SHOT, { recursive: true });
const results = {};
const fail = (m) => { console.error("FAIL:", m); process.exitCode = 1; };

const browser = await chromium.launch();

async function newUser(name) {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 1700 } });
  const page = await ctx.newPage();
  page.on("console", (m) => { if (m.type() === "error") console.log(`[${name} browser error]`, m.text()); });
  const pageUrl = new URL(URL);
  pageUrl.searchParams.set("mode", "demo");
  await page.goto(pageUrl.toString(), { waitUntil: "domcontentloaded", timeout: 60000 });
  await page.waitForFunction(
    () => document.querySelector('[data-testid="status"]')?.textContent === "ready",
    undefined,
    { timeout: 240000 }
  );
  await page.waitForSelector('[data-testid="principal"]', { timeout: 120000 });
  const principal = await page.getAttribute('[data-testid="principal"]', "data-principal");
  const persistedSecrets = await page.evaluate(() =>
    Object.keys(localStorage).filter((key) => key.startsWith("picp-demo-keys:"))
  );
  if (persistedSecrets.length) fail(`${name} persisted a shielded secret: ${persistedSecrets.join(",")}`);
  return { page, principal, name };
}

async function idle(page) {
  // an operation is finished when the stage spinner is gone and no button is mid-flight
  await page.waitForTimeout(300);
  await page.waitForFunction(
    () => !document.querySelector('[data-testid="stage"]'),
    undefined,
    { timeout: 240000 }
  );
}

try {
  // B first — the recipient registers, then does nothing until money arrives.
  const B = await newUser("B");
  results.bPrincipal = B.principal;
  const A = await newUser("A");
  results.aPrincipal = A.principal;
  if (!A.principal || !B.principal || A.principal === B.principal) fail("distinct principals expected");
  // Baseline pool size — assertions below are deltas, so the rig also runs against
  // a mainnet pool that already holds records from earlier sessions.
  await A.page.waitForSelector('[data-testid="pool-notes"]', { timeout: 60000 });
  const poolStart = Number(await A.page.textContent('[data-testid="pool-notes"]'));
  results.poolStart = poolStart;
  await A.page.screenshot({ path: `${SHOT}/01-signed-in.png`, fullPage: true });

  // A: faucet
  await A.page.click('[data-testid="faucet-run"]');
  await idle(A.page);
  const bal = await A.page.textContent('[data-testid="bal"]');
  results.aBalance = bal;
  if (!bal.includes("100,000")) fail("A faucet balance: " + bal);
  const mints = await A.page.locator('[data-testid="ledger-entry"][data-btype="1mint"]').count();
  if (mints < 1) fail("expected a public 1mint ledger entry, saw " + mints);
  await A.page.screenshot({ path: `${SHOT}/02-faucet-public-mint.png`, fullPage: true });

  // A: shield twice (40,000 then 25,000 — fee-aware defaults)
  for (const [amt, expect] of [["40000", "1"], ["25000", "2"]]) {
    await A.page.fill('[data-testid="shield-amt"]', amt);
    await A.page.click('[data-testid="shield-run"]');
    await idle(A.page);
    const n = await A.page.textContent('[data-testid="note-count"]');
    results[`aNotesAfterShield${amt}`] = n;
    if (n !== expect) fail(`A note count after shielding ${amt}: ${n} (expected ${expect})`);
  }
  const approves = await A.page.locator('[data-testid="ledger-entry"][data-btype="2approve"]').count();
  const pulls = await A.page.locator('[data-testid="ledger-entry"][data-btype="2xfer"]').count();
  if (approves < 2 || pulls < 2) fail(`expected 2 public approve+pull pairs, saw ${approves}/${pulls}`);
  await A.page.screenshot({ path: `${SHOT}/03-shielded-deposits-public.png`, fullPage: true });

  // A: send privately to B's principal
  await A.page.click('[data-testid="act-3"]');
  await A.page.fill('[data-testid="send-to"]', B.principal);
  await A.page.fill('[data-testid="send-amt"]', "12000");
  await A.page.click('[data-testid="send-run"]');
  await idle(A.page);
  const stamp = await A.page.locator('[data-testid="no-entry-stamp"]').count();
  results.noEntryStamp = stamp === 1;
  if (stamp !== 1) fail("expected the NOTHING WAS WRITTEN HERE stamp after the private send");
  await A.page.screenshot({ path: `${SHOT}/04-private-send-no-entry.png`, fullPage: true });

  // B: discovers the money with its key
  await B.page.click('[data-testid="view-mine"]');
  await B.page.click('[data-testid="rescan-mine"]');
  await idle(B.page);
  const bBal = await B.page.textContent('[data-testid="shielded-bal"]');
  results.bShieldedBalance = bBal;
  if (!bBal.includes("12,000")) fail("B shielded balance after rescan: " + bBal);
  await B.page.screenshot({ path: `${SHOT}/05-recipient-found-money.png`, fullPage: true });

  // A: this run added 2 (shields) + 2 (transfer outputs) = 4 sealed records
  await A.page.click('[data-testid="view-provider"]');
  const poolNotes = await A.page.textContent('[data-testid="pool-notes"]');
  results.poolNotes = poolNotes;
  if (Number(poolNotes) !== poolStart + 4) fail(`pool sealed-record count: ${poolNotes} (expected ${poolStart + 4} = start ${poolStart} + 4)`);

  // A: PIR private lookup
  await A.page.click('[data-testid="act-4"]');
  await A.page.click('[data-testid="pir-run"]');
  await idle(A.page);
  const pirMatch = await A.page.textContent('[data-testid="pir-match"]');
  const pirBranches = await A.page.textContent('[data-testid="pir-branches"]');
  results.pir = { match: pirMatch, branches: pirBranches };
  if (!pirMatch.includes("✓")) fail("PIR match: " + pirMatch);
  if (pirBranches !== "0") fail("PIR target_dependent_branches: " + pirBranches);
  await A.page.screenshot({ path: `${SHOT}/06-pir.png`, fullPage: true });

  // A: shield once more (needs 2 notes for the withdraw proof), then withdraw to its own
  // principal. The public balance must rise and the result must be finalized, not merely queued.
  await A.page.click('[data-testid="act-2"]');
  await A.page.fill('[data-testid="shield-amt"]', "10000");
  await A.page.click('[data-testid="shield-run"]');
  await idle(A.page);
  await A.page.click('[data-testid="act-5"]');
  const beforeWithdraw = await A.page.textContent('[data-testid="bal"]');
  await A.page.fill('[data-testid="unshield-amt"]', "1234");
  const transferBlocksBefore = await A.page.locator('[data-testid="ledger-entry"][data-btype="1xfer"]').count();
  if (process.env.ARM_UNSHIELD_FAULT === "1") {
    execFileSync("dfx", ["canister", "call", "zk_ledger", "test_arm_fail_after_token_once", "()"], {
      cwd: process.cwd(), stdio: "pipe",
    });
  }
  await A.page.click('[data-testid="unshield-run"]');
  await idle(A.page);
  if (process.env.ARM_UNSHIELD_FAULT === "1") {
    const fault = await A.page.textContent('[data-testid="action-error"]');
    results.injectedFault = fault;
    if (!fault?.includes("fail-after-token-before-unshield-finalize")) fail("fault was not observed: " + fault);
    await A.page.click('[data-testid="resume-unshield"]');
    await idle(A.page);
  }
  const withdrawal = await A.page.textContent('[data-testid="unshield-result"]');
  const afterWithdraw = await A.page.textContent('[data-testid="bal"]');
  const transferBlocksAfter = await A.page.locator('[data-testid="ledger-entry"][data-btype="1xfer"]').count();
  results.unshield = { result: withdrawal, before: beforeWithdraw, after: afterWithdraw };
  if (!withdrawal.includes("FINALIZED") || !withdrawal.includes("ACCEPT")) {
    fail("withdraw did not finalize: " + withdrawal);
  }
  if (!withdrawal.includes("1,234 DEMO")) fail("custom withdrawal amount missing from result: " + withdrawal);
  if (beforeWithdraw === afterWithdraw) fail(`public balance did not change: ${beforeWithdraw}`);
  if (transferBlocksAfter !== transferBlocksBefore + 1) {
    fail(`expected exactly one ICRC-1 payout block, saw delta ${transferBlocksAfter - transferBlocksBefore}`);
  }
  await A.page.screenshot({ path: `${SHOT}/07-withdraw-finalized.png`, fullPage: true });

  console.log(JSON.stringify(results, null, 2));
  console.log(process.exitCode ? "VERIFY: FAILURES ABOVE" : "VERIFY: ALL GREEN");
} catch (e) {
  console.error("FAIL:", e.message);
  try {
    const pages = browser.contexts().flatMap((c) => c.pages());
    if (pages[pages.length - 1]) await pages[pages.length - 1].screenshot({ path: `${SHOT}/error.png`, fullPage: true });
  } catch {}
  console.log(JSON.stringify(results, null, 2));
  process.exitCode = 1;
} finally {
  await browser.close();
}
