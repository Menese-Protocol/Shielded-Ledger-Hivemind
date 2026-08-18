# Committed thresholds — `StableLog.validateIndexRange`: captured bound AND resumable cost exit. Fixed BEFORE the change.

No previously committed thresholds document is touched.

## 0. Observable check FIRST

A criterion must not presume an observable the system lacks. Checked **before** writing criteria,
not after:

| what a criterion needs | observable | exists? |
|---|---|---|
| the clamp uses a **captured** bound, not the live one | the source clamp expression | **YES** — `:188` |
| a cost-bounded early return carries progress | the function's return value | **YES** — it already returns `Result<Nat64>` |
| the audit still advances across chunks | `audit_status().cursor` | **YES** |

**No new surface required.**

## 1. Why these are ONE change, not two defects

`StableLog.validateIndexRange` (`:180`) is **both**:

- **the live-bound defect** — `let end = if (from + count > state.entry_count) state.entry_count else from + count;` (`:188`) clamps to the **LIVE** `entry_count`, while its sibling `StableBlobSet.countTagsRange` (`:575`) takes a **captured** `count` parameter;
- **the cost-exit blocker** — the `log_index` arm has no loop of its own; **the walk is this function's `while (index < end)` (`:189`)**, so the only place a cost bound can live is here.

**A walk that returns early with a cursor MUST also decide which bound it walked against**, or the
resumed walk clamps to a different `entry_count` than the one it started under. **Fixing either alone
leaves the other incoherent.**

## 2. Design decision

**Decision: take a CAPTURED bound as a parameter, and return early on a cost bound carrying the index
reached.**

- **Captured bound**: mirrors the sibling that already does this (`countTagsRange`), so the two
  validators of the same shape stop disagreeing — which is the defect's entire complaint.
- **Early return carrying the index**: the only shape that lets `log_index` resume, and it is why
  the resumable-cursor surface had to land first.
- **Deliberately NOT done: lowering `AUDIT_INDEX_PER_CHUNK`.** That caps **WORK**; the
  instruction-budget thresholds (`docs/thresholds/THRESHOLDS-budget-guard.md`) exist because the
  caps already do that and **COST** is what the 40e9 limit charges.

## 3. Acceptance criteria

| id | criterion | pass |
|---|---|---|
| **V-1** | The clamp | uses a **captured** bound passed in, **not** `state.entry_count` read live |
| **V-2** | A walk that reaches the cost bound | returns **early** carrying the **index reached**, and the caller resumes from it |
| **V-3** | **NEGATIVE CONTROL — must FAIL.** A build still clamping to live `state.entry_count` | **fails `V-1`** — proving `V-1` tests the bound's **source**, not merely that a parameter exists |
| **V-4** | **NEGATIVE CONTROL — must FAIL.** An early return that carries `from` instead of the index reached | **fails `V-2`** — proving forward progress, not merely "it returned early". **A one-sided check would pass a walk that never advances** |
| **V-5** | The stated symptom | the two validators of the same shape **agree** on which bound is authoritative |
| **V-6** | **No regression.** | `set-migration` 59/0, `rescue` 13/0, audit phases and failure strings unchanged **[negative-control legs require locally built baseline binaries that are not distributed]** |

## 4. What is NOT claimed

- **Not that this closes the audit-chunk byte path.** It shares this root cause and is covered by
  `docs/thresholds/THRESHOLDS-budget-guard.md`.
- **Not implemented by this document.**
- **Not that `V-6`'s batteries have been run** — they are the regression bar, owed at implementation.
