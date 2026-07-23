# Restore benchmarks: the device envelope

What a birthday-less, verify-before-scan restore costs on constrained clients. The scanner
streams DPAGE (4,096-entry) segments from an untrusted mirror, verifies every segment
against the certified `detect_stream` anchor before scanning it, and recognizes owned notes
end-to-end (ECDH + view tag + commitment check). Every measured row below ends with a
zero-false-negative census: the recognized owned set must equal the planted set exactly
(notes planted at the first, middle, and last positions). Zero false negatives holds across
the complete 100-million-record acceptance corpus and all published test variants; each row
here re-proves it under its specific constraint.

Reproduce any row with one command from `demo-frontend/`
(`node scripts/restore/bench-envelope.mjs <row>`); results append to
`scripts/restore/bench-results.jsonl`. The 10⁸-scale table lives in the A-4 scale proof
(`scripts/restore/scale-run.mjs`); this document is the CONSTRAINED-device envelope.

## Measured rows (headless, reproducible)

| Row | Constraint | Corpus | Wall | Throughput | Zero-FN census |
|---|---|---|---|---|---|
| `baseline` | 4 workers, unconstrained link | 10⁶ notes, real bytes (45.8 MB wire) | 7.3 s | 137,619 notes/s | PASS |
| `cores4` | **4-core CPU cap** (`taskset -c 0-3`), 4 workers | 10⁷ notes | 84.1 s | 118,932 notes/s | PASS |
| `shaped10` | **10 Mbps shaped stream** (token-bucket over served bytes) | 10⁶ notes, 45.8 MB wire | 40.3 s (link floor 38.4 s → +5%) | 24,806 notes/s | PASS |
| `shaped50` | **50 Mbps shaped stream** | 10⁶ notes, 45.8 MB wire | 8.4 s (floor 7.7 s → +9%) | 119,306 notes/s | PASS |
| `throttle` | **25% CPU duty cycle** per worker (background-tab / battery-saver model) | 10⁶ notes | 27.6 s (3.8× baseline) | 36,250 notes/s | PASS |
| `resume` | **SIGKILL mid-scan** at 96/245 durable segments, resume from the checkpoint file | 10⁶ notes | 5.0 s to finish after resume | — | PASS (kill loses no recognized note) |

Reading the envelope:

- **CPU-bound**: on 4 pinned cores the scan holds ~119k notes/s — a 10⁸-record history is
  ~14 minutes on a 4-core budget device, linearly better with more cores (the A-4 proof
  measured 10⁸ in 6.47 min at 8 workers).
- **Bandwidth-bound**: at 10 Mbps the wall tracks the link floor within 5% — verification
  and scanning hide entirely behind the download. At 50 Mbps the two are balanced. The
  wire cost is 48 B/note, so a full 10⁸ stream is 4.8 GB: on slow links, restore cost is
  the download, not the crypto.
- **Throttled**: a worker pool starved to a 25% duty cycle degrades throughput ~3.8× and
  nothing else — verification still precedes every scan, the census still passes.
- **Interrupted**: the checkpoint cursor deliberately LAGS the durable matched-set, so a
  hard kill (SIGKILL, no cleanup) re-scans at most the in-flight chunks and can never skip
  one. The resumed run completes the remaining 149 segments and the census passes.

## Operator-owed device passes (not headless-measurable)

These rows need physical hardware or a real browser power regime; they are explicitly owed
by an operator device pass and are NOT claimed by this document:

| Row | Device | Status |
|---|---|---|
| Midrange Android (Chrome, WASM + workers) | e.g. 4-core A-series/Snapdragon 6xx | **operator-owed device pass** |
| iPhone Safari (WASM worker caps, JIT policy) | any recent iPhone | **operator-owed device pass** |
| Real background-tab throttling (browser-scheduled, not modeled) | desktop Chrome/Safari | **operator-owed device pass** |

The `cores4` and `throttle` rows are the headless stand-ins for these regimes (core cap ≈
midrange CPU budget; duty cycle ≈ background scheduling); the device pass replaces the
model with the real thing.

## Method notes

- Bandwidth shaping is a token bucket over the bytes each chunk puts on the wire; chunk
  dispatch waits until the shaped link could have delivered them. It bounds the DELIVERY
  rate; verification/scan overlap the stream exactly as on a real link.
- The duty-cycle throttle stalls each worker after every segment so its CPU share is the
  configured fraction (a blocking `Atomics.wait`, zero busy-CPU) — a deliberately harsh
  model: real browsers throttle timers, not straight-line WASM.
- All rows run the hardened client: certificate-leaf binding before any mirror traffic,
  per-segment verify-before-scan, and the position-continuity guard
  (`scripts/restore/parallel-scan.mjs`, `scan-worker.mjs`; battery:
  `b-restore-boundary.mjs`).
