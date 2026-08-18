# Committed thresholds — make `keyset-binding-integration.mjs` establish its own precondition, then pin it. Fixed BEFORE the change.

No previously committed thresholds document is touched.

## 0. The gap, from the measurement that found it

Measured live: the suite's own setup calls `rotate_verifying_keys_v2`, which populates the anchor
**digest** but leaves `transfer_vk_hex` and `deposit_vk_hex` as `""`. `keyset.js:65` requires both
non-empty, so the GREEN leg failed **on the suite's inability to establish its own precondition**,
not on the property under test.

The green leg passes once `configure(...)` is called by hand (**8 passed, 0 failed**). **A suite
that needs a manual out-of-band step cannot be a sweep entry** — the sweep would go red on staging,
and a staging-red entry is one people learn to ignore.

## 1. Design decision — where the precondition is established

**Decision: the suite establishes it itself, idempotently, and SAYS SO in its output.**

On start it reads the anchor; if either vk hex is empty it calls `configure` with the **served**
`transfer_vk.hex` / `deposit_vk.hex`, and tolerates `REJECT:already-configured` so a second run is a
no-op.

- **Why not a wrapper script**: the precondition belongs to the test that requires it. A wrapper is a
  second place to forget.
- **Why not leave it manual**: §0 — it cannot be pinned, so the integration coverage it exists for
  would never actually run.
- **Why tolerate `already-configured`**: `configure` mints the administrator and refuses a second
  call. Treating that refusal as failure would make the suite pass exactly once per canister.
- **Deliberately NOT done: weakening `keyset.js`'s check.** The empty-vk-hex refusal at `:65` is
  correct and is part of what the suite exists to verify. **The staging is fixed, never the assertion.**

### References

1. **The live measurement** — establishing the exact missing field (`transfer_vk_hex` /
   `deposit_vk_hex` empty after `rotate_verifying_keys_v2`).
2. **`Main.mo:2193` `configure`** — `REJECT:already-configured`, and the controller binding it mints.
3. **The staging-red discipline** — an entry that cannot go green on its own is refused, because a
   permanently red entry is one people learn to ignore.

## 2. Acceptance criteria

| id | criterion | pass |
|---|---|---|
| **Y-1** | The suite run against a ledger whose vk hex is **empty** | it configures itself, **says so in its output**, and reports `8 passed, 0 failed` |
| **Y-2** | The suite run **again** on the now-configured ledger | still `8 passed, 0 failed` — `already-configured` tolerated, so it is repeatable, which a sweep entry must be |
| **Y-3** | **NEGATIVE CONTROL — must FAIL.** The pinned entry fed a run reporting **fewer** than 8 passed | the sweep **FAILS, exit non-zero** |
| **Y-4** | **NEGATIVE CONTROL — must FAIL.** The pinned entry fed a run with a **non-zero failed** count | the sweep **FAILS, exit non-zero** |
| **Y-5** | The entry appears in the pinned-count sweep pinned exact `8`/`0`; entries rise **27 → 28** | asserted by enumeration |
| **Y-6** | **No assertion in the suite is weakened, added or reordered**, and `keyset.js` is untouched | diff shows setup plumbing only **[negative-control legs require locally built baseline binaries that are not distributed]** |

## 3. What is NOT claimed

- **Not that the sweep has been observed green at 28.** Each entry is present, correctly wired and
  **capable of failing**.
- **Not a change to what the suite verifies.** Y-6 is the check on that.
- **Not that `configure`'s cost is acceptable in a sweep** — it is the 20.4e9-instruction call
  (`docs/thresholds/THRESHOLDS-resumable-audit-exit.md` §2), and it now runs **once per fresh
  canister** inside this entry. Recorded, not hidden.
