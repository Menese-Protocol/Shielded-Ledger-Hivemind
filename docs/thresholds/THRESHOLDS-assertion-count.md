# Committed thresholds — swept suites must report an executed-assertion count. Fixed BEFORE the change.

No previously committed thresholds document is touched.

## 0. The defect

`demo-frontend/scripts/test-amounts.mjs` and `demo-frontend/scripts/test-keyset-negative.mjs` each
emit **exactly one banner line and nothing else** — measured: **0 countable assertion lines**.

Their assertions throw, so the banner *is* conditional and reaching it means nothing threw. **But
with no count the sweep cannot distinguish "every assertion passed" from "the assertions were
removed".** A file reduced to its banner alone would still print GREEN and exit 0. That is the same
class as the circuit-suite defect (`docs/thresholds/THRESHOLDS-circuit-test-guard.md`): a green that
cannot distinguish "all passed" from "nothing ran".

**Measured, and it is why a call-site grep is not the answer:** `test-amounts.mjs` has **2
`assert.equal` call sites** but executes **17 assertions** — 7 accepted amounts and 10 malformed
inputs, both inside loops. A static count of call sites would report 2 and be wrong by 8×. **Only a
runtime counter measures what executed.**

## 1. Design decision — which remedy

**Decision: a runtime executed-assertion counter emitting the existing `=== RESULT: N passed, M
failed ===` line**, so the suites can be pinned by the pinned-count sweep's **existing exact-count
helper**, replacing the banner-only entries.

- **Why not a new runner**: the banner-only runner exists because the output had no count. Giving
  the output a count removes the reason for it. Fewer runners is fewer places for a runner/gate
  contract mismatch to hide — a mismatch there is invisible from a green sweep.
- **Why not a static call-site count**: measured above — wrong by 8× on the first file.
- **Why not leave the banner**: the banner stays. It is human-readable and costs nothing; the
  `RESULT` line is what the sweep binds to.
- **Deliberately NOT done: changing any assertion.** The counter wraps; it does not weaken, add or
  reorder a single check. The suites must test exactly what they tested before.

### References

1. **`docs/thresholds/THRESHOLDS-circuit-test-guard.md`** — a green that cannot distinguish "all
   passed" from "nothing ran".
2. **The runner-count discipline** — the number of distinct runners is kept small, because a
   runner/gate contract mismatch is invisible from a green sweep.
3. **The pinned-count sweep's exact-count helper** — the existing helper this output targets.

## 2. Acceptance criteria

| id | criterion | pass |
|---|---|---|
| **N-1** | Both suites emit `=== RESULT: N passed, 0 failed ===` and still emit their banner | both lines present; exit 0 |
| **N-2** | **The counts are the MEASURED executed totals**, not call-site counts | `test-amounts.mjs` reports **17** — the value a static grep gets wrong |
| **N-3** | **NEGATIVE CONTROL — must FAIL.** A copy of each suite with assertions deleted | reports a **lower** count, and the sweep entry pinned to the real count **FAILS, exit non-zero**. This is the criterion the whole change exists for: it proves the pin detects assertion removal, which the banner could not |
| **N-4** | **NEGATIVE CONTROL — must FAIL.** A copy with one assertion made to fail | non-zero exit **and** a non-zero `failed` count; the sweep entry FAILS |
| **N-5** | The banner-only entries are replaced by exact-count entries; sweep entry count unchanged at 26 | asserted by enumeration |
| **N-6** | **No assertion is weakened, added or reordered.** | diff shows only counter plumbing and the `RESULT` line **[negative-control legs require locally built baseline binaries that are not distributed]** |

## 3. What is NOT claimed

- **Not an audit of what these suites assert.** The counter records how many ran, not whether they
  are the right checks.
- **Not a claim the sweep has been observed green at 26 with the new pins.** As before: each entry is
  present, correctly wired and **capable of failing**.
- **Not a removal of the banner-only runner** if another entry still needs it — its removal is
  asserted only if no entry uses it.
