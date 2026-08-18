# Committed thresholds — a frozen-thresholds guard. Fixed BEFORE the change.

No previously committed thresholds document is touched. **This document will itself be covered by
the guard it specifies, from its own first commit.**

## 0. Why a guard rather than a resolution to be careful

A real excursion is decisive on this point: **the rule had been stated correctly and applied
correctly twice within the preceding ninety minutes — and was then broken anyway.**

**Intention is demonstrably not sufficient here.** The same conclusion reached for other
repeated-mistake classes applies: **the remedy is a mechanical check, not a firmer resolution.**

## 1. Design decision

**Decision: a manifest of `sha256` at first commit for every `THRESHOLDS-*.md`, and a checker that
fails on any divergence. Report-only; never auto-restore.**

- **Why a manifest, not `git log --follow` counting**: a threshold may legitimately be *created* in
  any commit; what must never change is its **content after** that. A hash pins content directly.
- **Why report-only**: restoring automatically would erase the evidence that an excursion happened,
  which is the opposite of what this is for. A real excursion is only auditable because it was
  recorded.
- **Deliberately NOT done: blocking commits.** No hook is installed; the guard does not own anyone's
  git configuration.

## 2. Acceptance criteria

| id | criterion | pass |
|---|---|---|
| **G-1** | The manifest covers **every** `docs/thresholds/THRESHOLDS-*.md` | count in the manifest equals count on disk; **no file omitted** |
| **G-2** | The checker against the current tree | **PASSES** — every threshold matches its first-commit hash |
| **G-3** | **NEGATIVE CONTROL — must FAIL, retrospectively.** The checker against a historical tree in which one threshold's live hash had drifted from its frozen hash | **FAILS**, naming that file. A *real historical* excursion, not a synthetic one |
| **G-4** | **NEGATIVE CONTROL — must FAIL.** A single byte appended to any threshold in a scratch copy | **FAILS** — proving it detects one file, not only a known one |
| **G-5** | Pinned into the pinned-count sweep with `RC=1` on failure | asserted at birth |
| **G-6** | **No regression.** | no threshold file modified by this work **[negative-control legs require locally built baseline binaries that are not distributed]** |

## 3. What is NOT claimed

- **Not that this would have prevented the excursion.** It detects, after the fact, at sweep time.
- **Not a claim that every `THRESHOLDS-*.md` is correct** — only that its content has not moved since
  it was frozen.
