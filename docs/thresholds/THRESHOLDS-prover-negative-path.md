# Committed thresholds — the profile-dependent soundness test in `violation_matrix.rs`. Fixed BEFORE the fix.

No previously committed thresholds document is touched, including
`docs/thresholds/THRESHOLDS-circuit-test-guard.md`, whose **G-2 is blocked on this defect**.

## 0. The defect, stated from the source and not from the symptom

`circuit/common/tests/violation_matrix.rs:225`,
`violated_witness_fails_proof_generation_or_verification`, fails with
`assertion failed: cs.is_satisfied().unwrap()`.

The test's own comment at `:227` and `:244` asserts a premise about the library:

> "Groth16 proving on an unsatisfied CS **errors**"

**That premise is false**, and both `match` arms at `:246-254` are built on it. The real surface is
`ark-groth16-0.5.0/src/prover.rs:193`:

```rust
debug_assert!(cs.is_satisfied().unwrap());
```

It is a **`debug_assert!`**, not a returned `Err`. Consequences, and this is the finding:

1. Under `cargo test`, debug-assertions are ON, so proving a violated witness **panics**. The panic
   unwinds past the `match`, so **neither** the `Err(_)` arm nor the `Ok(proof)` arm is ever reached.
2. Under a release profile the assertion is **compiled out**, so the same test would take the
   `Ok(proof)` arm instead.

**The test's outcome therefore depends on the build profile**, which is not a property a soundness
test may have. This is a defect in the test, not in the circuit.

## 1. What is NOT wrong — recorded so the fix is not oversold

**The soundness property itself holds.** A value-imbalanced witness leaves the constraint system
unsatisfied — that is precisely what the panicking assertion observes. The circuit constrains value
balance. Nothing here is evidence of a proving-system weakness, and this defect must not be written
up as one. What failed is the test's ability to *assert* the property.

## 2. Design decision — which remedy

**Decision: assert the constraint system directly, AND drive the end-to-end negative path under
`catch_unwind`.** Both, not either.

- **Direct CS assertion.** Build the constraint system for the violated witness and assert
  `cs.is_satisfied()` is **false**. This is profile-independent and it is the soundness-relevant
  statement: the violated witness does not satisfy the R1CS.
- **`catch_unwind` around `prove`.** Keeps the end-to-end leg — a panic, an `Err`, or an `Ok(proof)`
  that fails verification are all acceptable *negative* outcomes; an `Ok(proof)` that **verifies** is
  the only failure. This makes the test correct in **both** profiles rather than one.

**Why not `catch_unwind` alone**: a profile with `panic = "abort"` cannot unwind, so the test would
abort rather than assert. The direct CS check does not depend on unwinding at all.

**Why not relax the test to "proving fails somehow"**: that cannot distinguish "the circuit rejects
the imbalance" from "the prover crashed for an unrelated reason". The CS assertion names the cause.

**Deliberately NOT done: patching or forking `ark-groth16`.** The vendored dependency is unmodified.
The defect is in this repository's test.

### References

1. **`ark-groth16-0.5.0/src/prover.rs:193`** — the `debug_assert!` that is the actual surface.
2. **Rust Reference, `debug_assert!`** — compiled out when `debug-assertions` is off; the
   profile-dependence follows directly.
3. **`ark-relations` `ConstraintSystem::is_satisfied`** — the supported way to ask the question the
   assertion asks, as a value rather than as a panic.
4. **`std::panic::catch_unwind` / `UnwindSafe`** — and its documented non-applicability under
   `panic = "abort"`, which is why it is the second leg and not the only one.

## 3. Acceptance criteria

| id | criterion | pass |
|---|---|---|
| **R-1** | **NEGATIVE CONTROL — must FAIL.** The fixed negative-path harness applied to the **honest** witness | **fails** — the honest CS *is* satisfied and the honest proof *does* verify, so a harness that passes here proves nothing. This is what stops `catch_unwind` from swallowing everything into a green |
| **R-2** | The violated witness, constraint system checked directly | `cs.is_satisfied()` is **false**, asserted as a value, with no reliance on a panic |
| **R-3** | The end-to-end leg under `catch_unwind` | panic / `Err` / non-verifying `Ok` all accepted; a **verifying** proof for the imbalanced witness is the sole failure |
| **R-4** | `cargo test --features bls12-381` on `violation_matrix.rs` | **3 passed, 0 failed** — the file's other two tests unchanged |
| **R-5** | **Unblocks `docs/thresholds/THRESHOLDS-circuit-test-guard.md` G-2.** The full guard run with the feature | **passes**, seven files, per-file counts, cargo status 0 |
| **R-6** | **No regression.** | no existing battery count changes; `circuit/gen` untouched; `ark-groth16` unmodified **[negative-control legs require locally built baseline binaries that are not distributed]** |

## 4. What is NOT claimed

- **Not a soundness defect.** §1. The property holds; the assertion of it was profile-dependent.
- **Not a fix to `ark-groth16`.** The dependency is untouched.
- **Not closure of the circuit-test-guard thresholds.** Those close on their own five criteria; R-5
  only removes this defect as their blocker.
