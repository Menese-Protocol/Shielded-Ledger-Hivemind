import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const frontend = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const port = Number(process.env.STATIC_BOOT_PORT || 5197);
const origin = `http://127.0.0.1:${port}`;
const preview = spawn(
  process.execPath,
  [join(frontend, "node_modules", "vite", "bin", "vite.js"), "preview", "--host", "127.0.0.1", "--port", String(port), "--strictPort"],
  { cwd: frontend, stdio: ["ignore", "pipe", "pipe"] },
);
let previewLog = "";
preview.stdout.on("data", (chunk) => { previewLog += chunk; });
preview.stderr.on("data", (chunk) => { previewLog += chunk; });

let browser;
try {
  let reachable = false;
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (preview.exitCode !== null) throw new Error(`Vite preview exited early:\n${previewLog}`);
    try {
      const response = await fetch(origin);
      if (response.ok) { reachable = true; break; }
    } catch {}
    await delay(100);
  }
  assert.equal(reachable, true, `Vite preview never became reachable:\n${previewLog}`);

  browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  const consoleErrors = [];
  page.on("console", (message) => {
    if (message.type() === "error") consoleErrors.push(message.text());
  });
  await page.goto(origin, { waitUntil: "domcontentloaded" });
  await page.locator('[data-testid="status"]').filter({ hasText: "ready" }).waitFor({ timeout: 120_000 });
  const body = await page.locator("body").innerText();
  assert.match(body, /keyset integrity verified/);
  assert.match(body, /setup: os-csprng-single-party/);
  assert.equal(await page.locator('[data-testid="action-error"]').count(), 0);
  assert.equal(consoleErrors.length, 0, `browser console errors:\n${consoleErrors.join("\n")}`);

  const randomSamples = await page.evaluate(() => {
    const values = [];
    for (let i = 0; i < 16; i += 1) {
      const bytes = new Uint8Array(32);
      crypto.getRandomValues(bytes);
      values.push([...bytes].map((value) => value.toString(16).padStart(2, "0")).join(""));
    }
    return values;
  });
  assert.equal(new Set(randomSamples).size, randomSamples.length, "browser CSPRNG repeated a 256-bit sample");
  assert(randomSamples.every((sample) => !/^0+$/.test(sample)), "browser CSPRNG returned all-zero entropy");

  console.log("STATIC BROWSER BOOT: WASM, manifest hashes, key lineage, and WebCrypto GREEN");
} finally {
  await browser?.close();
  if (preview.exitCode === null) {
    preview.kill("SIGTERM");
    const exited = await Promise.race([
      new Promise((resolve) => preview.once("exit", resolve)),
      delay(2_000).then(() => false),
    ]);
    if (exited === false && preview.exitCode === null) preview.kill("SIGKILL");
  }
}
