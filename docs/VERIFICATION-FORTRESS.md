# The Verification Fortress

A deterministic, reproducible testing/verification structure for the hand-rolled crypto,
verifier, circuits, ledger, and privacy of the shielded pool. The goal is to stand on our
own evidence: every claim below is re-runnable from one command with a published seed, and
every detector is proven able to fail (a planted bug turns it RED) before it is trusted to
pass. This composes with — never replaces — the existing batteries (`scripts/security-gate.sh`,
`e2e.py`, `soak/`, the read-path battery).

Run it all: `scripts/fortress.sh` (add `--fast` for a smoke pass). Each section also has its
own one-command driver under `scripts/fortress-*.sh`. Every driver prints its seed and tier
on each run; the committed full-tier knobs are documented per section in `scripts/fortress.sh`.

## The teeth-first principle

A test that has never been shown to fail proves nothing. Every fortress detector ships with a
**teeth** proof: a deliberately planted bug (a wrong field limb, an under-constrained circuit
variable, a value-nonconserving witness, a secret-dependent branch) that the detector is
demonstrated to catch by going RED. The planted bug always lives in a throwaway staged copy or
a test-only mutant — the shipped tree is never modified. If a teeth proof ever stops going
RED, the detector has regressed and the gate fails.

## What each section proves

| § | Detector | What it proves | Teeth (planted bug → RED) |
|---|---|---|---|
| §1 | Three-verifier taxonomy | The production Motoko verifier (on PocketIC, the shipped L3 path), arkworks, and blst agree on accept/reject across a 1017-case mutation taxonomy | one wrong Montgomery limb makes Motoko diverge from ark/blst |
| §2 | Per-op arithmetic differential | 63 op classes of the production Motoko field/tower/curve/pairing/decode layers match an independent arkworks/blst oracle over millions of seeded cases | wrong RR/PINV limb, wrong modulus bit, broken Fp2 mul, wrong curve b |
| §3 | Algebraic properties | Field/curve/pairing identities hold on the production L2/L3 layers (field 100k/family incl a·a⁻¹=1, sqr=mul, Frobenius order; curve [a+b]P=[a]P+[b]P, [r]P=O, [2]P=P+P; pairing bilinearity, additivity, degeneracy) | a broken-distributivity Fp2 mutant |
| §4 | Independent reference model + violation matrix | An independent (stdlib-Python) Poseidon + circuit model reproduces every production value; 13 single-rule circuit violations are all unsatisfiable | non-stdlib import, wrong round constant, a satisfied violation |
| §5 | Under-constrained detection | Every one of the transfer circuit's 20,213 witness variables is constrained and noticed; no unconstrained witnesses | a planted dead witness + a boolean missing its booleanity |
| §6 | Metamorphic | Validity-preserving proof transforms stay accepted; validity-destroying transforms are rejected — all 3-way | a destroying transform mislabeled preserving |
| §7 | Coverage-guided fuzzing | Ten cargo-fuzz decoder targets + a Motoko-side battery (≥250k inputs/decoder): every wire/crypto/ceremony/ICRC-3/checkpoint decoder is total on arbitrary bytes (no panic, no unbounded alloc, no non-canonical accept) | a decoder with a deliberate out-of-bounds panic |
| §9 | Stateful financial invariants | Model tier: 2,000,000 seeded ops, custody/pool/conservation/nullifier invariants hold after every op with atomic seam rollback. Live tier: the two remaining in-canister seams (during-token-call, during-cert-update) injected via hook wasm, ≥25 each, every message rolled back | a double-mint credited without matching custody |
| §10 | Differential side-channel | Across transfer/shield/unshield verify classes (≥200 pairs) + a 2000-probe resource-difference sweep over 64 candidate bits, no secret bit is recoverable from the instruction-count class; response size/error class constant | a branch keyed on a secret bit |
| ceremony | PoK cross-language | The Motoko on-chain PoK verifier accepts a genuine Rust-produced ceremony contribution and rejects tampered/wrong/identity ones | (existing negative controls in the vector) |

## Proven vs. testimonial — the honest boundaries

**Proven by these tests (mechanical, reproducible):**
- The production Motoko verifier agrees byte-for-verdict with two independent
  implementations (arkworks and blst) across the full mutation taxonomy and millions of
  per-op differentials — a shared misreading of the BLS12-381/Groth16 spec across all three
  is the only way a verifier bug survives, and §4's independent-lineage Poseidon closes even
  the shared-Poseidon-parameter window.
- The transfer circuit rejects every single-rule violation and has no unconstrained witness
  variable (the highest-value ZK bug class).
- The wire decoders are total functions on arbitrary bytes.
- The ledger's value-conservation / custody / nullifier invariants hold across millions of
  abstract operations with failure injection at every logical seam.
- The verifier's instruction-count class does not leak a chosen secret bit.

**Testimonial / out of these tests' scope (rests on design + review, honestly stated):**
- **Circuit soundness against a novel parameter flaw** — §4 proves the circuit enforces its
  documented rules and rejects the enumerated violations; it does not prove the Groth16 setup
  is free of a structural flaw. That rests on the trusted-setup policy
  (`docs/TRUSTED-SETUP-POLICY.md`), the ceremony (`docs/CEREMONY.md`), and circuit review.
- **Cryptographic unlinkability** — §10, the keyless-observer (B10), and the linkage audit
  (B11) are leakage *regression guards* on the block encoding and empirical unlinkability
  confirmations for the tested dataset; they are not a substitute for the circuit's
  unlinkability argument.
- **Constant-time execution** — §10's stated objective is explicitly NOT CPU-cycle constant
  time (the IC does not offer it). It proves no *observable secret-dependent class*, not
  bit-exact timing invariance. Benign data-dependent variation from scalar-multiplication bit
  patterns is present and expected (~0.05% of the verify).
- **§9 live in-canister seams** — the model tier proves the invariant algebra at 2M-op scale.
  The live stateful tier is the `soak/` suite (seams before-ledger-call, after-success-
  before-commit via the shipped `trapAfterToken`, during-upgrade, during-recovery) PLUS the
  fortress seam battery (`scripts/fortress-seam.sh`), which wires the two remaining seams —
  *during the token call* (the token fixture traps `transfer_from` mid-shield → the backend
  rolls back the pending intent) and *during certified-state update* (the hook calls the real
  `refreshCertification()` then traps → the IC rolls the cert update back atomically), 25
  injections each, all verified rolled back. Every seam hook lives in the hook wasm
  (`build-test-wasm.sh`, additive-only; the shipped `zk_ledger.wasm` is byte-identical). Seam
  *during-commit* remains N/A by construction — the finalize is a single no-await region the
  IC rolls back atomically (asserted by the model tier's atomic-rollback invariant).

## Determinism

Every randomized suite takes a seed, prints it, and is a pure function of it; a failing case
reproduces from its printed seed alone. No wall-clock, no unseeded RNG, no network in the
offline gate. The Motoko interpreter version is asserted (the dfx-cache moc the existing gate
uses); the L3-flat verifier — interpreter-hostile by measurement — runs compiled on PocketIC.

## Provenance / finding

§7 surfaced finding **F-1**: arkworks' raw VerifyingKey
deserializer performs an unbounded allocation on a malformed length prefix. It is not a
production exposure (VKs decode only through the bounded wire parsers); the gate target fuzzes
the bounded parser the system actually uses.
