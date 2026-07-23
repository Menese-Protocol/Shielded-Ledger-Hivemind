# Testing map

Everything in this repository that asserts something, what it asserts, and how to run it. Six
independent surfaces cover the system: an offline security battery, a stateful replica suite, a
randomized model-checked soak under PocketIC, the wallet read-path battery, the Motoko unit
tests the first two drive, and the verification fortress (deterministic teeth-first
cross-implementation gate).

| Surface | Command | What it proves |
|---|---|---|
| Offline security battery | `./scripts/security-gate.sh` | Fixtures, circuit, verifier, oracles, key provenance, frontend build. No canister installs. |
| Stateful replica suite | `dfx start --clean` then `dfx deploy && python3 e2e.py` | The deployed ledger's gates: ICRC-3 conformance, certified tuple, stable upgrade, token atomicity, PIR. |
| Randomized soak (this document, `soak/`) | `cargo run --release --manifest-path soak/Cargo.toml -- run` | Tens of thousands of seeded random operations against a reference model, with full-population verification. |
| Wallet read-path battery | `cd demo-frontend && npm run test:readpath` | Pagination, view tags, encrypted cache, birthday recovery, fetch-transcript privacy oracles. 75 checks. |
| Motoko unit tests | driven by the two suites above | Codec, stable storage, block matching. |
| Verification fortress (`docs/VERIFICATION-FORTRESS.md`) | `./scripts/fortress.sh` (`--fast` to smoke) | Teeth-first cross-implementation gate: 3-verifier taxonomy (§1), per-op arithmetic differential (§2/§3), independent reference model + violation matrix (§4), under-constrained detection (§5), metamorphic (§6), coverage-guided fuzzing (§7), stateful-invariant model tier (§9), differential side-channel (§10), ceremony PoK. Every detector proven RED-capable by a planted bug. |

## 0. The verification fortress: `scripts/fortress.sh`

Deterministic, offline, teeth-first. Each section (`scripts/fortress-*.sh`) asserts its
detectors AND runs a planted-bug teeth proof that turns the detector RED. Published seeds;
one-command reproduction; PocketIC/proving sections default to a gate tier
(env-overridable to the committed full tier). See `docs/VERIFICATION-FORTRESS.md` for what is
proven vs. testimonial; every section driver prints its seed and tier on each run. The
fortress composes with (never replaces) the five surfaces below and reuses their oracles
(`cross_oracle/`, `circuit/`, `src/groth16/`, `verifier-lab/`, `soak/`).

## 1. The offline security battery: `scripts/security-gate.sh`

One command, no replica. Its steps, in order:

1. **Frozen fixture integrity**: `sha256sum -c fixtures/SHA256SUMS` over every pinned vector.
2. **Deterministic reproducibility**: regenerates the entire BLS12-381 vector set from the
   fixed, loudly-labeled test seed and diffs it against the frozen fixtures byte for byte. The
   setup manifest must say `insecure-deterministic-test` and `real_value_eligible: false`.
3. **Circuit properties and mutation battery**: randomized circuit-property tests
   (`circuit/common/tests/security_properties.rs`) plus the Groth16 mutation battery: all eight
   public inputs and every one of the 192 compressed proof bytes mutated; each mutant must be
   rejected.
4. **Browser prover parity**: the wasm prover compiles against the identical circuit crate.
5. **Motoko verifier vectors**: the current eight-public-input vectors through the vendored
   Motoko Groth16 verifier.
6. **Second implementation**: the blst cross-oracle (`cross_oracle/`) must return the identical
   accept/reject verdict as arkworks on every frozen fixture.
7. **Independent Motoko oracles**: arithmetic, subgroup, pairing, and wire-decode batteries.
8. **Ledger hashing and block matching**: ICRC-3 official hash vectors, exact-block matching.
9. **Compile gates and API boundary**: every canister compiles; the DEMO token fixture's
   test-only surface stays inside the fixture.
10. **Key provenance**: manifest hashes with negative controls.
11. **Frontend build** booted in a real browser, and patch hygiene.

## 2. The stateful replica suite: `e2e.py`

Requires `dfx`, [`mops`](https://mops.one), `didc`, and a Motoko compiler (the suite invokes
`/opt/moc-1.4.1/moc`; adjust to your install). Run `dfx start --clean` in one terminal, then
`dfx deploy && python3 e2e.py`. It prints one assertion table; every key must be `True`. The
assertion keys group into gates:

- **`G1-*` (ICRC-3 conformance)**: representation-independent hashing against the official
  vectors, canonical map encoding, block shape, `phash` parent linkage, and range queries on
  `icrc3_get_blocks`.
- **`G2-*` (certified tuple)**: the tree/certificate/witness triple behind
  `icrc3_get_tip_certificate` and `certified_snapshot`, atomicity of certification with state
  changes, and rollback behavior.
- **`G3-*` (stable upgrade)**: note codec and stable-region storage invariants, upgrade with
  state preserved, re-certification after upgrade, operation continuing across the boundary, and
  the portable-layout boundary test.
- **`G4-*` (token atomicity)**: the ICRC-2 shield leg: capability probing, a full shield, crash
  recovery via the idempotency key (including after the ledger's dedup window has expired, using
  the fixture's clock advance), and fail-closed behavior when the token leg cannot complete.
- **`ICP-*` / `NNS-*`**: the token fixture's ICRC-1/2 surface, and the certified NNS-to-ICRC-3
  adapter: candid byte oracles against pinned interface files, certificate controls, archive
  boundary, hint preimages, canonical emission, dynamic metadata, and a shield round-trip driven
  through the adapter.
- **`Z0..Z3`**: the shielded core: valid transfer accepted; tampered proof rejected; unknown
  anchor rejected; spent nullifier rejected.
- **`PIR`**: the LWE private-lookup endpoint answers with a full uniform scan
  (`records_scanned` equals the whole log, `target_dependent_branches` is zero) and the client
  decrypts the right record.

`security-gate.sh --with-replica-e2e` chains both suites.

## 3. The randomized soak: `soak/`

The soak answers a different question from `e2e.py`. The replica suite proves each gate once
with hand-built vectors; the soak drives the ledger with **tens of thousands of seeded random
operations across thousands of accounts** and proves the *population-level* invariants: every
balance, every block link, solvency, and rejection of every adversarial class, at scale, across
upgrades, deterministically reproducible.

### Prerequisites

- Rust (stable) with the `wasm32-unknown-unknown` target
- A Motoko compiler `moc` (1.4.1 is the pinned version; set `SOAK_MOC=/path/to/moc`, or install
  via `mops toolchain use moc 1.4.1`; the harness also falls back to `/opt/moc-1.4.1/moc`, then
  `moc` on PATH)
- [`mops`](https://mops.one) with packages installed: `mops install`
- The PocketIC server binary, version 13.x. Either point `POCKET_IC_BIN` at one (dfx ≥ 0.32.0
  caches it at `~/.cache/dfinity/versions/<v>/pocket-ic`), or download it in one command:

```bash
curl -sL https://github.com/dfinity/pocketic/releases/download/13.0.0/pocket-ic-x86_64-linux.gz \
  | gunzip > /usr/local/bin/pocket-ic && chmod +x /usr/local/bin/pocket-ic
```

The `pocket-ic` crate is pinned to `=13.0.0` in `soak/Cargo.toml`.

### Running

```bash
mops install                                              # once
cargo run --release --manifest-path soak/Cargo.toml -- run    # smoke tier by default
```

Tiers are environment-parameterized:

```bash
# smoke tier (default): 200 accounts / 1,000 ops
SOAK_ACCOUNTS=200 SOAK_OPS=1000 cargo run --release --manifest-path soak/Cargo.toml -- run

# full tier: 10,000 accounts / 100,000 ops
SOAK_LABEL=full SOAK_ACCOUNTS=10000 SOAK_OPS=100000 \
  cargo run --release --manifest-path soak/Cargo.toml -- run

# change the seed (the whole run is a deterministic function of it)
SOAK_SEED=12345 cargo run --release --manifest-path soak/Cargo.toml -- run
```

Other knobs: `SOAK_UPGRADES` (minimum mid-run upgrades, default 3), `SOAK_BATCH` (ops proved per
parallel batch, default 46), `SOAK_CHECK_INTERVAL` (ops between cheap invariant sweeps, default
1000). The proving benchmark alone: `... -- bench`.

Every run prints its `SEED` and a final `STATE-HASH`, and writes a JSON report to
`soak/results/<label>-seed<seed>.json` with the wasm SHA-256s, toolchain pins, operation and
rejection counts, and the battery verdicts. Re-running with the same seed must reproduce the
identical state hash.

### What one run does

1. **Keyset gate**: regenerates the proving/verifying keys in-process from the deterministic
   test setup (seed 20260712) and asserts their SHA-256 against
   `fixtures/pool-vectors-bls12-381/SETUP-MANIFEST.json`; then verifies the frozen fixture
   proofs under the regenerated keys (and that the frozen tampered proof still fails). The soak
   proves against exactly the keys the ledger is configured with.
2. **Counterfeit-mint guard (native)**: constructs withdrawal witnesses whose claimed public
   value exceeds the committed note value (the plain imbalance and the field-wrap variant of
   the 2018 Zcash counterfeiting class) and asserts the circuit is UNSATISFIABLE for both,
   while the range-check-free circuit variant accepts the wrap (the range constraint is the
   load-bearing defense). This guards the known bug class; it does not prove circuit soundness
   against a novel parameter flaw; that rests on the trusted-setup policy and circuit review.
3. **Environment**: compiles `src/Main.mo` and `tests/IcpLedgerFixture.mo` with the pinned
   `moc`, records all wasm SHA-256s, boots PocketIC, installs the ledger + token fixture +
   vendored tree oracle, and wires `configure` / `configure_token_ledger` exactly as the demo
   does (`demo-frontend/scripts/redeploy.sh`): the token fixture serves as its own ICRC-3
   history adapter.
4. **Accounts**: N accounts, each a distinct caller principal with its own shielded keypair
   (`nk`, `pk = H(1, nk)` per the circuit), funded on the token fixture.
5. **Operations**: M seeded random ops: shields, private 2-in/2-out transfers (the circuit's
   arity), recipient-bound unshields, occasional fault-injected shield/unshield recoveries
   through `resume_shield`/`resume_unshield`, plus ~10% adversarial injections (threshold: at
   least 2%) drawn from seven classes, every one of which must be rejected:
   double-spend (spent nullifier), proof replay, single-byte proof mutation, fabricated-tree
   anchor (valid pairing, unknown anchor), wrong recipient binding, insufficient shield
   allowance, and counterfeit-mint (claimed `v_pub_out` beyond the pool's total value, which the
   `poolDebit > pool_value` turnstile must reject with the verifier never consulted).
6. **Reference model**: the harness maintains its own account of every note, nullifier, balance,
   expected block, pool value, and an independent Merkle tree; after every accepted operation
   the canister's reported state must match the model exactly.
7. **Upgrades**: at least 3 canister upgrades at seeded random points mid-run (mode upgrade,
   `wasm_memory_persistence = keep`). The harness drains any in-flight background audit before
   upgrading, asserts the postupgrade hook stays inside committed bounds (2B instructions /
   256 MiB heap delta), then polls the ledger's background stable-state audit and counts the
   upgrade complete only when the audit reports PASS with its verdict published as a certified
   audit leaf; all invariants are re-checked after each, and the block chain must link across
   every boundary.
8. **Full-population verification** (no sampling): for ALL N accounts, the model balance must
   equal (a) a wallet-style trial-recognition scan over the public block log minus spent
   nullifiers, and (b) the balance computed by an **independent replayer** that reconstructs
   state purely from the `icrc3_get_blocks` stream, verifying every `phash` link over the whole
   chain and rebuilding the commitment tree with a separate implementation. Solvency is asserted
   three ways: token custody == ledger `pool_value` == Σ unspent note values, from both the model
   and the replayer, plus the cumulative form pool_value == Σ shield-ins − Σ unshield-outs.
9. **Certification**: the final `icrc3_get_tip_certificate` verifies against the PocketIC root
   key with the canonical tuple-tree binding, the certified tip hash must equal the replayer's
   independently computed chain hash, and tampered signature / wrong root key / mutated witness
   must all be rejected.
10. **Keyless-observer leakage audit**: a scanner holding NO account keys walks the same block
    stream and must find zero plaintext amounts and zero user principals in the opaque fields of
    confidential-transfer blocks, and must fail to recognize a single note ciphertext, while
    the keyed replayer reads all of them on the same stream. This is a leakage regression guard
    on the block encoding, not a proof of cryptographic unlinkability (that rests on the circuit
    design and its review). Shield/unshield token legs are public by design and out of scope.
11. **Statistical correlation / cryptanalysis audit**: a keyless adversary sees only the public
    block log (commitments, nullifiers, proof bytes, ordering and timestamps, and the public
    shield/unshield amounts) and runs genuine linkage attacks, each scored against the model's
    ground truth. (a) Nullifier-to-commitment linkage: for every spend, rank the true input
    commitment against 255 decoys by byte correlation to the nullifier; the true input's
    percentile rank must stay within a sample-size epsilon of 0.5 and the top-1 rate within
    epsilon of 1/256. (b) Same-account linkage: classify balanced same-owner vs different-owner
    output-commitment pairs by byte similarity; balanced accuracy must stay within epsilon of
    0.5. Both are pass/fail cryptographic checks; a score that beats chance is treated as
    a real leak, fails the run, and is written up as a proposal rather than softened. Like the
    keyless-observer audit, they empirically confirm cryptographic unlinkability for this
    dataset and are a regression guard; they are not a substitute for the circuit's
    unlinkability argument.

### The postupgrade audit and scale batteries

The ledger's `postupgrade` is O(1)/O(k): it validates structure headers and the tail block
only, and hands full-state validation to a timer-driven chunked background audit whose verdict
is published as a certified audit leaf. Any audit failure fail-closes every update endpoint
until an admin-triggered re-audit passes. `soak/src/bin/scale_tests.rs` proves this protocol
at scale on synthetic states built through the real codec and chain code
(`tests/ScaleFixture.mo`):

- **Fixture selftest**: every corruption primitive produces its exact reference-walk error code.
- **Flat postupgrade cost**: postupgrade instructions stay flat (within a committed threshold)
  across 1k/20k/200k-note states, with the audit passing at every size.
- **Differential equivalence**: the chunked audit and the verbatim single-message reference
  walk agree case-by-case on the same valid and corrupted states.
- **Fail-closed drill**: six corruption classes injected into a RUNNING canister (via the
  admin-gated hook wasm from `scripts/build-test-wasm.sh`, never present in the shipped wasm)
  must each produce an audit FAIL record, guarded update endpoints, live queries, rejection of
  premature guard clears, and a full recovery: un-corrupt, re-audit green, guard cleared.

Run with `cd soak && cargo run --release --bin scale_tests`.

### Scope notes

- Private transfers carry `fee = 0` and unshields carry exactly the transparent token fee, so
  the solvency identity `custody == pool_value == Σ unspent` holds exactly. The circuit supports
  other fee choices; the ledger burns any shielded fee above the token fee.
- The unshield finalization path requires the proof anchor to be the ledger's CURRENT root, so
  the harness predicts each operation's exact submission-time root during batch planning. A
  wallet whose unshield loses that race simply re-proves against the new root.
- The PIR endpoint is covered by `e2e.py` at small scale by design: a PIR query must carry one
  encrypted selector per log record, so its payload grows with the log and it is not a
  soak-scale operation. The soak leaves PIR to the replica suite.

## 3b. The PIR v2 harness: differential oracle + cost probes + privacy battery

PIR v2 (`src/Pir2.mo`, default-off behind `pir2_enable`) is proven by an oracle-first harness
that runs BEFORE the ledger integration is trusted: an independent Rust reference, on-replica
cost probes, an inner-loop micro-bench, and a keyless-observer privacy battery.

- **Differential oracle** — `POCKET_IC_BIN=… cargo run --release --manifest-path soak/Cargo.toml
  --bin pir2_differential` (set `SEED` for the second seed). Feeds one seeded ≥144k-record,
  multi-shard corpus with adversarial content (all-0xFF / oversized / empty / zero envelopes)
  to both the production `Pir2.mo` server (under PocketIC) and the Rust reference
  (`soak/src/pir2.rs`); byte-compares every stripe answer (several widths, full + partial
  pins), the accumulated answer, sampled frozen-shard hints, record-stream slices, and the
  certified chain + boundary digests; and round-trips every one of 1,000 queries to the exact
  288-byte record with the commitment-prefix integrity check.
- **Reference self-tests** — `cargo test --release --manifest-path soak/Cargo.toml --lib pir2`:
  geometry vs spec constants, A-expansion pinned vectors, round-trip on adversarial envelopes,
  stripe composition, pinning-under-growth, client-hint == server hint, chain tamper-detection,
  wire, noise margin.
- **Cost probe** — `cargo run --release --manifest-path soak/Cargo.toml --bin probe_pir_cost`:
  append-path hint maintenance (flat across 10⁴/10⁶/10⁷), stripe instructions per multiply-add
  and per stripe, query/response/record-stream wire bytes, hint-chunk serving, the metered
  update-call dial, and the backfill-strategy comparison. Drives `tests/Pir2CostProbe.mo`.
- **Inner-loop micro-bench** — `cargo run --release --manifest-path soak/Cargo.toml --bin
  pir2_microbench`: seven candidate matvec loops on-replica, checksum-identical, so the
  production loop is chosen by measured instructions/madd. Drives `tests/Pir2MicroBench.mo`.
- **B12 privacy battery** — folded into `npm run test:readpath` (`b-p12-pir`): transcript
  indistinguishability for different targets, selector-marginal chi-square (with a skew
  self-test for teeth), a negative control that detects a leaking partial-schedule client,
  match-independent shard set, and the uniform-scan schedule — two seeds, 11 checks.
- **S-1 instruction-equality gate** — differential PHASE 3: the measured `instructions`
  trace field must be EXACTLY equal across different-target queries at identical
  (shard, fill, stripe, kCols); teeth via the probe's deliberately leaky
  `answer_stripe_leaky` variant (harness-only), which must produce unequal counts.
- **Derived-index battery** — `PIRDX_EXPECT=decoupled PIRDX_TIER=small cargo run --release
  --manifest-path soak/Cargo.toml --bin pirdx_battery` (and `PIRDX_TIER=big` for the ≥10⁴
  scale tier): money-path containment under injected fold traps (AC-D1), catch-up/gating/
  repair/upgrade-resume byte-identity against the Rust reference fed from the ledger's own
  block log (AC-D2..D5), money-message instruction delta + fold-chunk budget (AC-D6), and
  the certified `pir2_boundary` leaf (D7). `PIRDX_EXPECT=coupled` runs the same assertions
  as the recorded RED against a synchronous-fold build.
- **S-3 sampler battery** — `cd demo-frontend && node scripts/readpath/s3-sampler-battery.mjs`
  (build `prover-wasm/pkg-node` first with `wasm-pack build --target nodejs --out-dir
  pkg-node`): committed moment/tail/zero-fraction bounds with mutation teeth for the JS twin,
  the shipped wasm sampler (via `pir_selectors` noise extraction), and `pir_random_u64`;
  mirrored in `cargo test --lib pir2` (`sampler_moments_*`).

All numbers land in `docs/PIR-V2-SPEC.md` §V2.7.

## 3c. The Poseidon frontier harness: differential gate + malicious-oracle battery + cost probe

The in-canister Poseidon Merkle frontier (`src/PoseidonTree.mo`, default-off behind a single
admin-gated switch in `src/Main.mo`) is proven oracle-first: the ledger's root computation is
byte-compared against the real arkworks code path before it is ever trusted, and the external
tree oracle it replaces is demoted to a cross-check that the ledger itself polices.

- **Source-of-truth oracle** — `cargo run --release --manifest-path Cargo.toml --bin
  frontier-oracle -- constants|vectors <seed> <name>`: dumps the Poseidon sponge constants and
  seeded input/output vectors from the vendored arkworks tree code (bls12-381), with in-binary
  self-checks. The committed `tests/FrontierVectorsA/B.mo` fixtures are its output.
- **Differential gate** — compile `tests/PoseidonDifferential.mo` with `moc $(mops sources)
  -wasi-system-api` and run under wasmtime: 2 passes × 9,180 comparisons across seeded
  absorb/permute/frontier-append families; traps on the first divergence with its coordinates.
  Formula-mutant negative controls prove the gate turns red.
- **Malicious-oracle battery** — `cargo run --release --manifest-path soak/Cargo.toml --bin
  frontier_battery`: 38 checks. Honest-oracle cross-check mode, standalone mode (oracle fully
  detached, ledger computes every root alone), four corruption families from an adversarial
  oracle (wrong root, stale, truncated, corrupt lane — all rejected, historical roots never
  polluted, the fail-closed guard latches sticky), and an upgrade-safety leg (flag and
  authoritative root survive a canister upgrade).
- **Cost probe** — `cargo run --release --manifest-path soak/Cargo.toml --bin
  probe_frontier_cost`: per-append instructions and response bytes for the allocation-flat
  `src/groth16/FrFlat.mo` backend, committed against the measured bound before integration.

## 4. Motoko unit tests

- `tests/ICRC3HashTest.mo`, `tests/ICRC2BlockTest.mo`: hashing and exact block matching
  (driven by `e2e.py` and the security gate via `moc -r`).
- `tests/Gate3StableTest.mo`: note codec + stable storage module invariants (deployed and
  queried by `e2e.py`).
- `tests/IcpLedgerFixture.mo`, `tests/NnsArchiveFixture.mo`: the ICRC-1/2 token fixture (with
  test-only balance/allowance/clock hooks) and the NNS archive fixture the suites run against.

## 5. The wallet read-path battery: `demo-frontend/scripts/readpath/`

```bash
cd demo-frontend && npm install   # once
npm run test:readpath
```

Node-only; no canister installs. Six items, 75 checks, two seeds each, with committed
thresholds. All envelope cryptography is real `tweetnacl`; the transport is mocked at the actor
boundary by a mock ledger modelled byte-for-byte on `src/Main.mo` (request-logged, so the
batteries assert exactly what a wallet fetched) and an adversary-capable mock directory
(replay, inflated records, malformed ciphertexts).

- **B-P1..B-P5** (40 checks): correct-and-complete paginated scanning against an exhaustive
  genesis oracle; view-tag detection with zero misses; cursor/cache warm opens that fetch only
  the tail; cache integrity (wrong key, wrong ledger, stale root all fail safe to rescan); the
  keyless-observer property; wallets with different keys produce byte-identical fetch
  transcripts, and any position-isolating fetch shape fails the battery.
- **B-B** (35 checks): birthday round-trip on both publish paths; ciphertext-only at rest with
  size invariance (every record exactly 113 bytes); caller-keyed writes with on-chain-mirrored
  guards; the publish-floor invariant plus replay and inflated-record adversaries, including
  the `fullRescan` heal; the 8-mode fail-safe matrix (every bad record falls back to a genesis
  scan with an oracle-equal balance); and the gating proof that the recovery surface stays
  additive.
- `soak/src/bin/probe_readpath_cost.rs` and `soak/src/bin/probe_birthday_directory.rs` run the
  on-chain counterparts under PocketIC: wire bytes/note and instructions/note for
  `detection_stream`, and the directory's old-to-new upgrade with stable-map survival and
  guard re-verification.

## 5b. The restore battery: `demo-frontend/scripts/restore/`

Node-only, standalone (`node scripts/restore/<file>` from `demo-frontend/`):

- **`b-restore-correctness.mjs`** (12 checks, 2 seeds): the parallel verify-before-scan
  client's owned set is byte-identical to the sequential reference AND an independent
  genesis-walk oracle; native == reference kernel; resume == one-shot; planted census
  exact. RED teeth: a dropped-tail injection misses the last planted note.
- **`b-restore-tamper.mjs`** (14 checks): mirror corruption classes (bitflip, truncation,
  reorder, splice, Merkle-path tamper) all rejected BEFORE scan; honest refetch restores
  the full set. RED teeth: verify disabled → the truncation silently drops a note.
- **`b-restore-boundary.mjs`** (38 checks): the segment PROTOCOL battery — exact entry
  count per segment, position continuity (gap/duplicate/overflow-in-parse), partial-tip
  binding (short/long tail vs the one-certificate noteCount), and cross-certificate
  mixing (root/cTip/leaf from two certificates, plus the stale-prefix mix) rejected by
  the mandatory certificate-leaf binding with ZERO mirror traffic. Teeth per case: each
  corruption re-run with its detector disabled is either accepted silently (chain verify
  load-bearing) or caught by the independent position-continuity guard (defense in depth).
- **`bench-envelope.mjs`** (device envelope, one row per invocation) +
  **`scale-run.mjs`** (A-4 scale proof): the measured rows and zero-FN censuses published
  in `docs/RESTORE-BENCHMARKS.md`.

## 5c. The detect-chain battery: frontier + persistence

- **Offline half** — `./scripts/detect-battery.sh`: frozen-vector reproducibility
  (`tests/detect-frontier-vectors.json` regenerates byte-identically from the JS
  reference), the Motoko frontier differential with planted-mutant teeth
  (`tests/DetectFrontierDifferential.mo`: exhaustive 0..300, 1,000 seeded random sizes,
  the 24,414-boundary scale point, rebuild-from-boundaries), cross-language vectors
  through the production `DetectChain.append` path, the detect-chain unit vectors, and
  the certified-tuple flag-off byte-identity proof.
- **Stateful half** — `cargo run --release --manifest-path soak/Cargo.toml --bin
  detect_battery` (PocketIC, hook wasm): audit teeth (5 corruption classes → exact
  `detect-chain:*` FAIL codes + sticky guard), rebuild-from-log recovery (byte-identical
  anchor from the note log alone, including a full wipe), and the populated-chain upgrade
  drill under the committed postupgrade bounds.
- **Soak leg** — `SOAK_DETECT_CHAIN=1 cargo run --release --manifest-path soak/Cargo.toml
  -- run`: the whole corpus maintains the anchor; every upgrade byte-compares it against
  an independent Rust recompute over the served `detection_stream`; the final certified
  tuple must carry exactly the recomputed `detect_stream` leaf. Default OFF — the
  flag-off smoke's STATE-HASH is the byte-identity gate.

## 6. Reading a soak report

`soak/results/<label>-seed<seed>.json` contains: the seed and tier, every wasm SHA-256 and the
`moc` version, operation counts by type, rejection counts by adversarial class with one
transcript per class (the exact canister error string), upgrade positions, the final solvency
numbers, the battery table, and the deterministic `state_hash`. Two runs with the same seed on
the same commit must produce the same `state_hash`; a divergence is a bug, in the harness or
in the ledger. If a soak assertion ever fires, the printed seed reproduces the exact op sequence.
