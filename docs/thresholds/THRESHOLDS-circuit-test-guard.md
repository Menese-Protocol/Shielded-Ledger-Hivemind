# Committed thresholds — the circuit suite must not report success while executing nothing

Committed BEFORE any measurement.

## 0. The defect

Five of seven files in `circuit/common/tests/` open `#![cfg(feature = "bls12-381")]`
(`violation_matrix.rs:12`); `bls12-381` is **not a default feature**. `cargo test` therefore prints
**`ok. 0 passed; 0 failed`** for the soundness matrix, under-constrained detection, statement↔vk
binding, dimension pins and security properties. **`semantic_audit.rs` and `witness_uniqueness.rs`
are NOT gated and do run.**

**The gate concealed a real red:** a genuinely failing soundness assertion
(`docs/thresholds/THRESHOLDS-prover-negative-path.md`) was invisible to `cargo test`.

## 1. Design decision

**A guard script that asserts a NON-ZERO test count per file**, not merely a zero exit.

**Why a count and not pass/fail:** a pass/fail assertion **cannot distinguish "everything passed"
from "nothing ran"** — that is the whole defect. **Only a count can.**

**Deliberately NOT done: removing the feature gate.** The gate may exist for good reason (build time,
optional dependency). **The defect is that its effect is silent, not that it exists.**

## 2. Acceptance criteria

| id | criterion | pass |
|---|---|---|
| **G-1** | The guard run **without** `--features bls12-381` | **FAILS**, naming the files that executed zero tests |
| **G-2** | The guard run **with** the feature | **passes**, and reports a **per-file count** |
| **G-3** | **NEGATIVE CONTROL — must FAIL.** A file whose tests are all `#[ignore]`d, or a deliberately emptied filter | the guard **still fails**, proving it checks *executed* count and not merely *presence* |
| **G-4** | The guard **surfaces the failing soundness test** rather than hiding it | with the feature, the run's non-zero exit from `violated_witness_fails_proof_generation_or_verification` is **reported, not swallowed** |
| **G-5** | **No regression.** | the guard is additive; no existing battery count changes **[negative-control legs require locally built baseline binaries that are not distributed]** |

## 3. What is NOT claimed

- **Not that the gated tests fail.** They pass except the profile-dependent soundness test
  (`docs/thresholds/THRESHOLDS-prover-negative-path.md`), which is a test-expectation defect against
  `ark-groth16` 0.5.0, not a soundness break.
- **Not a CI integration.** This delivers the **guard**; wiring it into CI is a deployment step.
