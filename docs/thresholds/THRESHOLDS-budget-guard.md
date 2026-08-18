# Committed thresholds — the instruction-budget guard. BEFORE measurement.

No prior thresholds file is touched.

The root cause covered here pairs the audit-chunk byte path (an item cap that cannot bound
variable-cost work) with the live-bound clamp
(`docs/thresholds/THRESHOLDS-validateindexrange.md`).

## 0. The defect — enumerated, not sampled

**Nine `performanceCounter` sites across `src/`, and every one is telemetry:**

| site | use |
|---|---|
| `Main.mo:1636`, `:1642`, `:1661` | `c0` then store the difference into `pir2_last_chunk_instructions` |
| `Main.mo:1842` | store into `postupgrade_instructions` |
| `Main.mo:1866` | store into a status field `instructions =` |
| `Main.mo:4286`, `:4320` | `c0`/`c1` pair, difference recorded |
| `Pir2.mo:368`, `:400` | `c0`/`c1` pair, difference recorded |

**Zero appear in a comparison, a loop exit, or a rejection.** The ledger measures its own instruction
consumption in nine places and **acts on it in none.**

## 1. Why an item cap is not a substitute — the reason this is one finding, not two

The audit-chunk byte path (the chunk caps notes, per-note cost unbounded in note bytes) and the
live-bound clamp (`validateIndexRange` bounds by the **live** `entry_count` while its sibling uses
the **captured** bound) are the same defect: **a bound on the number of items cannot bound work whose
per-item cost is variable.** A 112-byte note and a 10 KB note both count as one.

**Therefore the remedy is not a better cap.** It is a guard that reads the actual counter and stops.

## 2. Design decision

**A budget guard checked inside every unbounded loop, comparing `performanceCounter(0)` against a
named ceiling, exiting with a resumable cursor rather than trapping.**

- **Exit, not trap.** A trap rolls back the whole message; the work already done is lost and the
  caller retries into the same wall. The chunked migration
  (`docs/thresholds/THRESHOLDS-chunked-migration.md`) already establishes the resumable-cursor
  pattern in this codebase.
- **A named constant per loop class**, not one global — the audit walk, the reconcile scan and the
  PIR fold have different natural chunk sizes.
- **Deliberately NOT done: removing the item caps.** They are cheap and they bound the common case.
  The guard is the backstop for the variable-cost case. Both, not either.

**Deliberately NOT done: a guard on query paths that already have a 5e9 ceiling enforced by the
platform** — unless a measurement shows a query can exceed it, which remains an open measurement
question.

### References

1. **IC execution limits** — 40e9 instructions/update, 5e9/query. A message that exceeds them is
   rejected wholesale (IC0522), so the canister must stop itself first or lose the message.
2. **`docs/thresholds/THRESHOLDS-chunked-migration.md`** — the resumable-cursor pattern this
   codebase already ships.
3. **Gray & Reuter §4 (bounded work per transaction)** — the unit of admission must be work, not items.
4. **The review's cross-cutting observation** — "there are no instruction guards at all, so this
   class is universal rather than site-specific."

## 3. Acceptance criteria

| id | criterion | pass |
|---|---|---|
| **W-1** | **THE WITNESS, staged-red-first.** A single message driven to IC0522 on an unbounded loop, with the item cap satisfied | the message is **rejected wholesale** and its work is lost — showing the cap did not bound it |
| **W-2** | **The variable-cost half.** The same item count with larger per-item payloads | instruction count rises with bytes while the item cap is unchanged — the mechanism of both defects |
| **F-1** | With the guard, the same input | **completes across messages** with a resumable cursor; no IC0522, no trap, no lost work |
| **F-2** | **NEGATIVE CONTROL — must FAIL.** The guard is disabled or its ceiling set absurdly high | W-1's rejection returns. **If it does not, F-1 proved nothing** |
| **F-3** | The guard fires on **instructions**, not on a proxy | shown by holding the item count fixed and varying only per-item bytes; the guard must trip on the second and not the first |
| **F-4** | No path silently truncates | a caller can distinguish "finished" from "budget exhausted, resume" — a named result, not a short answer |
| **F-5** | **No regression.** | the pinned-count sweep at its committed counts, `option-b-battery.sh` pinned 40/2, canister-ID binding proven |

## 4. What is NOT claimed

- **Not that this closes every unbounded site.** The review enumerates specific unbounded sites; the
  guard is the mechanism they would each use, and each still needs its own derivation.
- **Not that the ceilings chosen are correct.** They are engineering choices to be measured, and F-3
  is what stops a ceiling from being chosen to make a test pass.
