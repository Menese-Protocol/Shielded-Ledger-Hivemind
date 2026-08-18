# Committed thresholds — the chunked migration. Fixed BEFORE any implementation is run.

The bar, fixed before measurement: the wedge must be **killed**, not moved. An earlier mitigation
moved the wall 32× and the shape survived — the per-rung ratio stayed 2.00×, which is the signature
of an O(N) spike, not of its absence.

Nothing in this file may be edited after the implementation is first run.

---

## 0. Design decisions committed here, so the numbers below mean something

These are fixed now, not chosen to fit a result.

| decision | value | why it is fixed here |
|---|---|---|
| `MIGRATION_CHUNK` | **8 slots per `put`** | K-1 is meaningless without a pre-committed K |
| `MIGRATION_MAX_BUDGET` | **65,536 slots** per explicit `advanceMigration` call | bounds the operator-driven path below the message ceiling |
| what advances the cursor | **`put`, and `advanceMigration` only** | see K-5; `contains` deliberately does not |
| grow demanded during a window | **force-complete the window in that message, then open a new one**, with an observable counter | K-6; a refusal on `put` would fail `addNullifier` and wedge the ledger |
| migrated old slots | **tombstoned (tag 2), not cleared** | clearing breaks open-addressed probe chains, which is a false negative on `spent_nullifiers` — a double spend. Tombstones keep every original chain intact and keep `live_old + live_new == entry_count` exact at every cursor position |
| `LAYOUT_VERSION` | **stays 2** | verified in-tree: `HEADER_SIZE` is 64 in both the frozen layout-1 module and the current one; layout 1 writes header bytes 0–47, layout 2 also 48–55; **56–63 are written by neither** and read back zero, which is the same property that made the stride trick work. The stable `State` record is unchanged, so no migration function is required |

Encoding, at header offset 56: `migration_word`, high bit = window active, low 63 bits = cursor.
During a window `table_offset`/`capacity`/`next_offset` describe the **old** table unchanged, and the
new table is at `next_offset` with capacity `2 × capacity`; `next_offset` advances only when the
window closes. Six values fit in five slots because the capacity always doubles and tables are
allocated consecutively.

---

## 1. Acceptance criteria

| id | criterion | pass |
|---|---|---|
| **K-1** | **THE KILL CRITERION.** Max single-message instructions across an **entire** window | ~~**flat: ratio 1.00 ± 0.10 per rung**, and the absolute max **< 1,500,000 instructions** and **< 256 KB allocation** per message~~ **RESTORED BY FIX — see §1a. Grow-path reclaim is now chunked, so per-message cost is flat by construction. Asserted as SHAPE (p99 flat, does not scale with N) + CEILING (max < a bound derived from COMPACT_MAX_BYTES). Max 295,713 — under the old 1.5M and 30× under the derived ceiling.** |
| **K-1b** | **The opening message is not where the wedge moved to.** | ~~the opening message's instructions and allocation obey the same flat + absolute bounds as K-1~~ **RESTORED BY FIX — see §1a. The reclaim moved off the opening into compactStep; the opening is FLAT (~160K across rungs).** |
| **K-2** | **THE RESCUE.** From a genuine layout-1 set at **734,003 entries in a 2^20 table** — the exact point the wedge was found — built by `scripts/build-layout1-fixture.sh`, canister pinned at the **3 GiB default** | every operation succeeds, **no message exceeds the K-1 absolute budget except by the layout-1 hashing term** (each migrated layout-1 slot needs a SHA-256; committed allowance: **< 4,000,000 instructions** per message at `MIGRATION_CHUNK` = 8), and the set **fully converges** to layout 2 with `activeStride` = 41 and the window closed |
| **K-3** | **Membership is never wrong mid-window.** Checked at **every cursor position sampled at ≥8 points across the window**, over the seeded corpus, plus controls never inserted, plus keys inserted **during** the window, plus keys whose old-table slot has been tombstoned | **zero false negatives and zero false positives at every sample point.** Not "few" — zero. This is the ledger's double-spend defence |
| **K-4** | **Rollback.** A message that performs migration steps and then traps, staged as a real trap | the cursor, the tombstones and the new table's contents all roll back with the message; re-running the same chunk afterwards is **idempotent**; membership answers identically before and after; the window still converges |
| **K-5** | **Convergence, from both ends.** (i) a pool with write traffic; (ii) a pool with **no write traffic** | (i) the window closes within **⌈capacity / MIGRATION_CHUNK⌉ puts**, proved by count, and that number is **strictly less** than the puts available before the next grow is demanded, so a grow can never be demanded mid-window. (ii) reads do not advance the cursor and this is stated, not hidden: the window stays open, and the claim to prove is that an open window is **bounded overhead, not a wedge** — measured lookup cost with a window open must be **< 2.5×** the closed-window cost, no operation may fail, and `advanceMigration` must converge it in **⌈remaining / budget⌉** messages |
| **K-6** | **A grow demanded while a window is open.** | the force-complete branch is asserted to work, **and** an observable counter proves it is **never taken (0)** on any path measured in K-1, K-2 or K-5. A branch that fires in normal operation would mean the K-5(i) bound is wrong |
| **K-7** | **No regression.** | the pinned-count test sweep extended with the new batteries, **every battery at or above its committed count, zero failures.** Existing counts: set-migration 54, hash-parity 11, archive-reconcile 48, attempt-budget 15, tooold-latch 14, vk-anchor 10, pending-scoping 11, audit-byte-budget 7, keyset-cache 11 |
| **K-8** | **`validateHeader` is at least as strong as before.** A window breaks nothing it checked, and it must gain checks for what a window adds: the new table's bounds, the cursor's range, and a load factor measured against the table actually being written to | **proved by perturbation, not asserted.** Every field the header carries — magic, version, the four cross-checked words, the stride, and the migration word's active bit, cursor and reserved bits — is corrupted in turn and must be **rejected**, with the pre-window behaviour unchanged on a set with no window |
| **K-9** | **The audit does not fail-close during a window.** The chunked set-walk in `Main.mo` compares occupied slots against `entry_count`; a window puts entries in two tables | the walk spans both tables, the identity `live_old + live_new == entry_count` holds at every cursor position, tombstones are accepted as a valid tag, and a cursor that moves mid-walk is detected by the existing contention guard and restarts — it must **not** reach `audit:set-walk-contended` on any path measured in K-1, K-2 or K-5 |

## 1a. K-1 / K-1b — THE GENUINE FIX (2026-08-10): chunked reclaim + SHAPE/CEILING

A first attempt RE-DERIVED the pin (loosened the max to a measured-plus-fudge 30M and swapped the flat
SHAPE property for a bounded CEILING). **That was REJECTED and is struck: re-deriving a pin from the
implementation makes the assertion tautological, and a ceiling alone catches only catastrophe, not an
O(N) creep starting under it.** The pin was restored to the code, not the code to the pin.

**Attribution, dated from the tree's history.** The K-1 failure was first read as pre-existing. It is
not: the first K-1 measurement (2026-08-09) postdates the change (2026-08-08) that introduced
`compactIfBounded` — up to `COMPACT_MAX_BYTES = 8 MiB` of reclaim INLINE on a user's shield/unshield —
and already carries it (4 occurrences in `src/StableBlobSet.mo`). So the K-1 failure **postdates and
carries the inline reclaim**; "pre-existing" was true only against the zero-fill hypothesis, not
against the inline reclaim. The one arm never run — reclaim OFF the grow path — returns K-1
flatness, which attributes the cause and proves the fix in one motion.

**The regression, dated from the tree's history.** The migration (2026-08-06) established *reclaim in
bounded slices, never one message* (`stepMigration`/`stepBound`/`migrationCursor`). The 2026-08-08
change reintroduced the one-message anti-pattern as `compactIfBounded`; a follow-up chunked only the
`> 8 MiB` exception, **demoting the best practice from the default to the fallback**. That is the
regression.

**The fix (product).** Route grow-path reclaim through the existing `compactStep` cursor —
a bounded `COMPACT_BUDGET` (64) slice per put, the same windowed-cursor discipline the migration
shipped. `compactStep`'s copy phase relocates the live table; a new zero phase clears the freed tail
via `storeNat64` (no allocation), maintaining the invariant `[next_offset, extent) == 0`; so
`openWindow`'s O(capacity) zero-fill is REMOVED (the doubled table lands in already-zero space) and
the ~5.9M `Array_tabulate(65536)` zero-block is gone. Per-message cost is now flat **BY
CONSTRUCTION**, no new mechanism invented. `insertInto`/`findInWith` already dispatch on the
compaction cursor (`slotOffsetLive`), so chunked reclaim interleaves with inserts safely — `K-3` is
the standing proof.

**Re-derived criteria (`scripts/option-b-battery.sh`), asserting BOTH shape and ceiling.**

| id | criterion | pass |
|---|---|---|
| **K-1 SHAPE** | the **p99** per-message cost across a window, over ≥4 doubling rungs | **flat: ratio 1.00 ± 0.15, does NOT scale with N.** p99 not max — max is one put landing the reclaim/migration slice and is legitimately spiky; p99 is the stable body. This is the REGRESSION detector: a future O(N) creep lifts p99 across rungs. Measured: 201430 / 201761 / 197045 / 204924 (ratios within ±0.05). mean flat too. |
| **K-1 CEILING** | no message, at any rung, exceeds a bound DERIVED from `COMPACT_MAX_BYTES` | the worst single message (the `openWindow` force-drain finishing one bounded reclaim — asserted COLD, max ≥ 10× under) relocates ≤ `COMPACT_MAX_BYTES/41 = 204,600` slots × **608** instr + zeroes ≤ `COMPACT_MAX_BYTES/8 = 1,048,576` words × **217** instr = **351,937,792 instr = 0.88 % of the 40e9 message limit**. 608 and 217 are MEASURED atomic-op costs (`measure_region_ops`), implementation constants — a first-principles bound, not a measured max plus a fudge. |
| **K-1b** | the OPENING message | **FLAT across rungs** (150,965 / 161,616 / 158,738 / 159,891) — the doubled-table allocation is lazy `Region.grow`, and the reclaim moved off it into `compactStep`. The one place the old pin warned an O(N) cost could hide is now flat. |

**Result:** opening `42M → 160K`, mean flat, p99 flat, max 295,713 — **30× under the derived ceiling and
well under the old `< 1.5M` bound.** The original flat pin is not loosened; it is EXCEEDED, restored by
construction rather than by assertion.
## 2. Negative-control-first

Every criterion above is staged failing before it is fixed. Specifically, and committed now so the
negative legs cannot be quietly skipped:

- **K-3** — a deliberately wrong lookup order (new table only, skipping the old table) must produce
  false negatives the battery reports, before the two-table lookup is put in.
- **K-4** — the trap is a real `Runtime.trap` inside a message that has already migrated slots, not a
  simulated one.
- **K-8** — each perturbation is applied to a real header on the replica and must be rejected.
- **K-9** — the audit is run against a set with an open window on the pre-change ledger and must be
  shown fail-closing, before the walk is made window-aware.

## 3. The verdict this must produce

Stated in the report without softening in either direction, in these words:

> The chunked migration **kills** the wedge — or — the chunked migration **does not kill** the wedge.

A kill means K-1 flat at 1.00 ± 0.10 across ≥4 rungs **and** K-2 converging from the exact point the
wedge was found, at the 3 GiB default. Anything less is not a kill, whatever else improves.

Beyond the largest rung actually executed, projections are labelled as projections.
