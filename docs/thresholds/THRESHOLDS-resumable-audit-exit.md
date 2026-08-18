# Committed thresholds — resumable audit exit and pre-flight refusal, CORRECTED PAIRING. Fixed BEFORE the change.

**Supersedes nothing by editing.** An earlier criterion conflated two shapes: it specified
**pre-flight refusal** (the indivisible-operation mechanism) but named `__audit_chunk` (a **chunked
walk**). **Two shapes, two operations, two mechanisms.** This document pairs them correctly; the
earlier document's observable check was sound and is reused here rather than redone.

## 0. Observables and cost signal

**Observables — previously enumerated and counted:** all ten `AuditStatus` fields, among them
`cursor`, `state`, `guard`, `chunk_retries`, `total`. **No new method required.**

**Cost signal — already in-file, no new primitive:** `Prim.performanceCounter(0)` at `Main.mo:1642`,
with `pir2_last_chunk_instructions` stored at `:1648`/`:1667`.

## 1. SHAPE ONE — resumable exit, for `__audit_chunk`

**Decision: bound the walk by measured instructions and exit with the cursor.** The `resume_cursor`
surface made this possible; before it there was nothing to exit *with*.

| id | criterion | pass |
|---|---|---|
| **R-1** | A chunk that reaches the instruction bound mid-walk | returns **`done = false`** with a `resume_cursor` **strictly greater** than the one it started from |
| **R-2** | The next chunk | **resumes at that cursor** — `audit_status().cursor` continues from it, and the walk **completes** |
| **R-3** | **NEGATIVE CONTROL — must NOT exit early.** The same walk with the bound raised beyond reach | runs to completion in one chunk, `done = true` — proving `R-1`'s early exit is caused by **the bound**, not by the walk ending anyway |
| **R-4** | **NEGATIVE CONTROL — must FAIL.** A build whose early exit returns a cursor **equal to or less than** its start | **fails `R-1`** — proving `R-1` tests *forward progress*, not merely *an exit*. Without it a guard that always exits at 0 would pass |

**`R-4` asserts progress**: an exit that never advances is indistinguishable from a working one
unless progress is asserted.

## 2. SHAPE TWO — pre-flight refusal, for `configure`

**Decision: NOT SPECIFIED HERE, and that is deliberate.** The vk-preparation measurement recorded
**20,428,523,632 instructions = 51.1% of budget** on **two indivisible vk preparations**. A
pre-flight predictor needs a **cost model for vk preparation as a function of vk size** — and the
measurement recorded the growth as **superlinear** with only **~2× headroom, unobserved**.

**Writing criteria for a predictor whose model does not exist would be a criterion presuming
something the system does not provide.** **What is owed first is the cost model, and that is a
measurement, not a threshold.**

## 3. What is NOT claimed

- **Not that the `configure` cost is addressed.** §2 — it needs a cost model first.
- **Not that the bound value is chosen.** Where it sits is a protocol question; `R-1`..`R-4` assert
  the **mechanism and forward progress**, not the number.
- **Not implemented by this document.**
