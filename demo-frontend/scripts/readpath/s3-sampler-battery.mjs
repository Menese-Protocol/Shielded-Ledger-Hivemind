// S-3 sampler-hardening battery (Menese DeFi Team) — moment/tail regression for the PIR
// noise samplers, with committed thresholds and mutation teeth.
//
// Samplers under test:
//   1. The v2 JS battery twin `gaussian` (pir2-client.mjs, sigma = 12.8) — seeded,
//      deterministic: exact committed bounds.
//   2. The v1 WASM client sampler (prover-wasm `pir_gaussian_error`, sigma = 2^49) —
//      exercised THROUGH THE SHIPPED ARTIFACT: `pir_selectors` returns b = a·s + bit·Δ + e,
//      so with a known secret the battery recovers every REAL production-path noise sample
//      as e = b − a·s (− Δ at the target). Browser entropy is non-deterministic, so bounds
//      carry a stated flake budget (< 2e-4 per run, dominated by the 3.5σ tail count).
//   3. `pir_random_u64` uniformity smoke via the same ciphertexts' `a` words (chi-square on
//      byte marginals).
//
// The math (documented in docs/PIR-V2-SPEC.md §V2.1 note): Box–Muller over 53-bit uniforms has
// a hard tail cap at sqrt(2·ln(2^53+1)) ≈ 8.57σ (true-Gaussian mass beyond ≈ 1e-17), and
// ROUNDED Gaussians carry variance σ² + 1/12 (at σ=12.8: +0.025%, security-conservative
// vs the estimator's discrete-Gaussian model).
//
// Teeth: every assertion is also run against a mutated sampler (scaled σ, |z| bias,
// 3σ-clipped, zero-suppressed) and MUST fail there.

import { gaussian, rng, SIGMA } from "./pir2-client.mjs";

const Q = 2 ** 32;

// ==== the committed assertion set ====
// n samples; sigma the design constant. Thresholds (all committed BEFORE running):
//   |mean|      <= 4·sigma/sqrt(n)                (4-sigma unbiasedness bound)
//   sigma_hat   within ±relSigma of sigma          (both directions; sd(σ̂) ≈ σ/√(2n))
//   count(|e| > 4σ)   >= minTail4                  (a clipped/thin-tailed sampler yields 0)
//   count(|e| > 6.5σ) == 0                         (P ≈ 8e-11 per sample)
//   zero-fraction within ±10% of erf(0.5/(σ√2))    (only when zeroFrac=true, i.e. small σ)
function assertMoments(samples, sigma, { relSigma, minTail4, tail4Sigma = 4, zeroFrac = false, label }) {
  const n = samples.length;
  const failures = [];
  let sum = 0, sumSq = 0, zeros = 0, tail4 = 0, tail65 = 0;
  for (const e of samples) {
    sum += e;
    sumSq += e * e;
    if (e === 0) zeros++;
    if (Math.abs(e) > tail4Sigma * sigma) tail4++;
    if (Math.abs(e) > 6.5 * sigma) tail65++;
  }
  const mean = sum / n;
  const sigmaHat = Math.sqrt(sumSq / n);
  const meanBound = (4 * sigma) / Math.sqrt(n);
  if (Math.abs(mean) > meanBound) failures.push(`mean ${mean} exceeds ±${meanBound}`);
  if (sigmaHat < sigma * (1 - relSigma) || sigmaHat > sigma * (1 + relSigma))
    failures.push(`sigma_hat ${sigmaHat} outside ${sigma}·(1±${relSigma})`);
  if (tail4 < minTail4) failures.push(`tail>${tail4Sigma}σ count ${tail4} < ${minTail4} (thin/clipped tail)`);
  if (tail65 !== 0) failures.push(`tail>6.5σ count ${tail65} != 0 (fat tail)`);
  if (zeroFrac) {
    const p0 = erf(0.5 / (sigma * Math.SQRT2));
    const f0 = zeros / n;
    if (f0 < p0 * 0.9 || f0 > p0 * 1.1) failures.push(`zero-fraction ${f0} outside ${p0}·(1±0.1)`);
  }
  return { failures, mean, sigmaHat, tail4, tail65, zeros, label };
}

// Abramowitz–Stegun 7.1.26 erf approximation (|err| < 1.5e-7 — far inside the ±10% window)
function erf(x) {
  const t = 1 / (1 + 0.3275911 * x);
  const y =
    1 -
    (((((1.061405429 * t - 1.453152027) * t) + 1.421413741) * t - 0.284496736) * t + 0.254829592) *
      t *
      Math.exp(-x * x);
  return x >= 0 ? y : -y;
}

function centered(u32) {
  return u32 >= Q / 2 ? u32 - Q : u32;
}

let checks = 0;
let failed = 0;
function report(name, ok, detail) {
  checks++;
  if (!ok) failed++;
  console.log(`${ok ? "PASS" : "FAIL"}  S3/${name}  ${detail}`);
}

// ==== 1. JS twin (sigma 12.8), seeded → deterministic ====
{
  const n = 200_000;
  const next = rng(20260722);
  const samples = new Array(n);
  for (let i = 0; i < n; i++) samples[i] = centered(gaussian(next));
  const r = assertMoments(samples, SIGMA, { relSigma: 0.01, minTail4: 3, zeroFrac: true, label: "js-twin" });
  report(
    "js-twin-moments",
    r.failures.length === 0,
    `n=${n} mean=${r.mean.toFixed(4)} σ̂=${r.sigmaHat.toFixed(4)} tail4σ=${r.tail4} tail6.5σ=${r.tail65} zeros=${r.zeros}${r.failures.length ? " | " + r.failures.join("; ") : ""}`
  );

  // teeth: each mutation must trip at least one committed bound
  const mutations = [
    ["scaled+5%", (next) => centered(gaussian(next)) * 1.05],
    ["abs-biased", (next) => Math.abs(centered(gaussian(next)))],
    ["clipped-3σ", (next) => Math.max(-3 * SIGMA, Math.min(3 * SIGMA, centered(gaussian(next))))],
    ["zero-suppressed", (next) => { const e = centered(gaussian(next)); return e === 0 ? 1 : e; }],
  ];
  for (const [name, mutant] of mutations) {
    const nx = rng(20260722);
    const ms = new Array(n);
    for (let i = 0; i < n; i++) ms[i] = mutant(nx);
    const mr = assertMoments(ms, SIGMA, { relSigma: 0.01, minTail4: 3, zeroFrac: true, label: name });
    report(`teeth-${name}`, mr.failures.length > 0, mr.failures.length ? `tripped: ${mr.failures[0]}` : "NOT DETECTED — gate has no teeth");
  }
}

// ==== 2 + 3. WASM v1 sampler through the shipped pir_selectors path ====
// Loaded lazily so the JS-twin half still runs if the wasm pkg is not built.
const SIGMA_V1 = 2 ** 49;
const DELTA_V1 = 2n ** 63n;
const MASK64 = (1n << 64n) - 1n;
try {
  const wasm = await import("../../prover-wasm/pkg-node/pool_prover_wasm.js");
  const calls = 24;
  const perCall = 1000;
  const samples = [];
  const aBytes = [];
  for (let c = 0; c < calls; c++) {
    const secret = JSON.parse(wasm.pir_keygen());
    const cts = JSON.parse(wasm.pir_selectors(JSON.stringify(secret), 0, perCall));
    for (let i = 0; i < cts.length; i++) {
      const ct = cts[i];
      let dot = 0n;
      for (let j = 0; j < ct.a.length; j++) {
        const aj = BigInt(ct.a[j]);
        if (secret[j] === 1) dot = (dot + aj) & MASK64;
        // byte-marginal pool for the pir_random_u64 uniformity smoke (first 2 a-words/ct)
        if (j < 2) {
          for (let k = 0n; k < 64n; k += 8n) aBytes.push(Number((aj >> k) & 0xffn));
        }
      }
      let e = (BigInt(ct.b) - dot) & MASK64;
      if (i === 0) e = (e - DELTA_V1) & MASK64; // target bit 1 at index 0
      const signed = e >= 1n << 63n ? e - (1n << 64n) : e;
      samples.push(Number(signed)); // |e| ≲ 8.6σ = 2^52.1 < 2^53: exact in f64
    }
  }
  const r = assertMoments(samples, SIGMA_V1, { relSigma: 0.02, minTail4: 2, tail4Sigma: 3.5, label: "wasm-v1" });
  report(
    "wasm-v1-moments",
    r.failures.length === 0,
    `n=${samples.length} (browser entropy; committed flake budget <2e-4) mean=${r.mean.toExponential(3)} σ̂/σ=${(r.sigmaHat / SIGMA_V1).toFixed(5)} tail3.5σ=${r.tail4} tail6.5σ=${r.tail65}${r.failures.length ? " | " + r.failures.join("; ") : ""}`
  );
  // teeth on the same extraction (mutate the recovered samples)
  const scaled = samples.map((e) => e * 1.05);
  const mt = assertMoments(scaled, SIGMA_V1, { relSigma: 0.02, minTail4: 2, tail4Sigma: 3.5, label: "wasm-scaled" });
  report("teeth-wasm-scaled+5%", mt.failures.length > 0, mt.failures.length ? `tripped: ${mt.failures[0]}` : "NOT DETECTED");

  // pir_random_u64 uniformity smoke: chi-square on byte marginals, 255 df.
  // Committed: chi < 330.6 (0.1% critical) on ≥ 300k bytes; teeth: a masked-high-bit
  // mutation must exceed it.
  const counts = new Array(256).fill(0);
  for (const b of aBytes) counts[b]++;
  const exp = aBytes.length / 256;
  let chi = 0;
  for (const c of counts) chi += ((c - exp) * (c - exp)) / exp;
  report("wasm-u64-uniformity", chi < 330.6, `chi=${chi.toFixed(1)} < 330.6 over ${aBytes.length} bytes`);
  const skewCounts = new Array(256).fill(0);
  for (const b of aBytes) skewCounts[b & 0x7f]++;
  let skewChi = 0;
  for (const c of skewCounts) skewChi += ((c - exp) * (c - exp)) / exp;
  report("teeth-u64-skew", skewChi > 330.6, `masked-bit chi=${skewChi.toFixed(0)} > 330.6`);
} catch (err) {
  report("wasm-v1-moments", false, `prover-wasm pkg-node not loadable: ${err.message} — build with: cd demo-frontend/prover-wasm && wasm-pack build --target nodejs --out-dir pkg-node`);
}

console.log(`\nS3: ${checks - failed}/${checks} checks green`);
process.exit(failed === 0 ? 0 : 1);
