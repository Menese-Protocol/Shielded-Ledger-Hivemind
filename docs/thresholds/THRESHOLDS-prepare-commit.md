# Committed thresholds — the total commit (PREPARE before commit). Fixed BEFORE implementation.

Same discipline as `docs/thresholds/THRESHOLDS-chunked-migration.md`: committed in its own commit
before a line of PREPARE is written, and not edited afterwards.

The defect is already witnessed on the unfixed build — a lying receipt: a rejection returned to the
caller while the tokens had in fact moved (negative battery: 13 passed, 0 failed). These thresholds
judge the fix, not the finding.

## 0. Design decisions committed here, so the numbers below mean something

| decision | value | why fixed here |
|---|---|---|
| PREPARE dominates **both** routes into the commit | before the **reconcile**, not merely before the payout | `finalizeUnshield` is reachable via `reconcileFirst → #found` with no payout in that message; that is the common case on the resume path |
| the encodings live in | a **new top-level stable variable**, not a field of `PendingUnshield` | a field would require a migration function; the pattern is `pending_unshield_prepaid_debit` |
| the prepared record is | a **cache, not authority** — recomputable, id-checked, cleared at all three sites that clear `pending_unshield` | an authoritative copy would need migration; a cache does not |
| headroom is | an idempotent **predicate**, not a reservation counter | `resume_unshield` concurrency is unbounded; a counter leaks one per caller |
| a PREPARE failure is | a reject with no token movement — **including a trap** | a trap in PREPARE is an honest receipt: nothing happened, no money moved |
| totality is claimed | **only while `detect_chain_enabled` is false** | per the detect-chain coupling analysis; the flag is asserted at the point the claim is measured |

## 1. Acceptance criteria

| id | criterion | pass |
|---|---|---|
| **F-1** | **THE FIX.** The same injected fault at `:3322` can no longer produce a rejection alongside a movement | **both legs asserted, not just the first**: either the receipt is a success **and** the tokens moved, or the receipt is a reject **and** the tokens did not. The conjunction (reject ∧ moved) must be **unreachable** |
| **F-2** | **The honest-receipt case.** A PREPARE that fails | a clean reject **and zero token movement**, with the recipient balance read from the token ledger before and after |
| **F-3** | **The commit is total: no allocation happens there.** Commit-phase instructions and allocation across **≥3 doubling rungs** of set size | **constant in N**, with the **window state FIXED**, and the closed-window and open-window cases **reported separately**. Banded at **±0.10 on the mean**, and on a max statistic only after its seed spread is measured first — the K-1 lesson (see `docs/thresholds/THRESHOLDS-chunked-migration.md`) is that a single-draw max cannot be held to a tight band |
| **F-4** | **No regression.** The full pinned-count sweep | every battery at its committed count, zero failures, `option-b-battery.sh` at its pinned 40/2 |
| **F-5** | **Headroom survives interleaving.** A competing writer driven across the await | cannot consume the reservation. Given the exclusion invariant (exclusion-invariant battery, 8/0) the derived bound is **one** in-flight intent, so this asserts the *consequence*: with a pending unshield, every other money path is refused and no set count moves |
| **W-1** | **Waste.** PREPARE-then-abort **≥5 times** on the same intent | the note log's **data-region bytes**, its **index-region bytes**, and **every set's `bytesAllocated`** are **unchanged after the first attempt**. Not argued — measured |
| **U-1** | **The upgrade path.** A pool holding a **live pending intent** upgrades to the PREPARE build | the intent's shape is unchanged, the prepared record starts absent, the resume rebuilds it, and the intent finalizes — every key and both nullifiers accounted for |
| **P-1** | **The precondition is asserted, not assumed.** | `detect_chain_enabled` is read and asserted **false** at the point F-3 measures totality, so the claim can never be read as unconditional |

## 2. Negative-control-first

Committed now so the negative legs cannot be quietly skipped:

- **F-1** red is the lying-receipt witness itself — already recorded on the unfixed build. The
  fixed build re-runs the identical staging and must produce the opposite conjunction.
- **W-1** must be shown able to fail: a deliberately non-idempotent headroom (one that grows
  unconditionally) must make the region sizes move on attempt 2.
- **F-3** must be measured on a build where the commit *does* allocate, to show the measurement can
  distinguish the two. The pre-PREPARE build is that build.

## 3. What is NOT claimed

- **Not a money-loss fix.** The defect is a lying receipt; the recovery path shows the money
  converges. This closes the receipt, not a loss.
- **Not unconditional totality.** See P-1 and the detect-chain coupling analysis.
- **Not the class.** The ckBTC-style `#InFlight` API closes the class and remains recorded and
  unadopted. If any criterion above proves unreachable, that is the fallback and it goes back to the
  maintainers as a decision rather than being half-built.
