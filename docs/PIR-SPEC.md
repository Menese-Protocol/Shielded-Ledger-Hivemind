# PIR specification: v1 linear baseline and v2 preprocessed query layer

The ledger lets a client read one record from the public commitment log without revealing
which record it read. Two schemes coexist: **v1**, the linear LWE baseline (`pir_query_lwe`),
kept as the simple, self-verifying reference; and **v2** (`pir2_*`, default-off behind
`PIR_V2_ENABLED`), a SimplePIR-shaped query layer whose one-time hint is maintained
*incrementally by the ledger itself* as the append-only log grows, so v2 scales to the 10⁸
target while v1's query grows linearly and stops being transportable near ~400 records.

The authoritative implementations are `demo-frontend/prover-wasm/src/lib.rs` (v1 client),
`src/Main.mo` (v1 endpoint), `src/Pir2.mo` (v2 module), and `soak/src/pir2.rs` (the v2
differential reference). Every measured number below is produced by the probes named in §V2.7.

---

## Part I — v1: linear LWE baseline

Plain Regev LWE, one query bit per record.

The client encrypts a selector vector of `N` bits, one per record, target bit 1. For each of
the record's 256 output bits the ledger homomorphically sums the selector ciphertexts of
every record whose public database bit is set. Branching depends only on the public database
bit; the encrypted selector is never decrypted or branched on. The response is 256
ciphertexts; the client decrypts and rounds.

### Parameters

| parameter | value | where |
|---|---|---|
| dimension `n` | 630 | `LWE_DIMENSION` |
| modulus `q` | 2^64 (wrapping `Nat64`) | arithmetic type |
| plaintext scale Δ | 2^63 | `PIR_DELTA` |
| noise | rounded Gaussian, σ = 2^49 | `PIR_NOISE_SIGMA` |
| secret | uniform binary, length 630, fresh per query | `pir_keygen` |
| record width | 256 bits (the 32-byte commitment) | `RECORD_BITS` |
| ciphertext | 630×u64 + u64 = 5,048 B | wire structs |

### Cost and boundary

Query = N × 5,048 B (172 KB at N=34, 5.05 MB at N=1,000); response 256 × 5,048 B constant.
The ~2 MiB ingress cap bounds a single-call query to ~400 records. v1 is the honest baseline
— simple enough to verify, its privacy property checkable in the response — but linear query
growth is why v2 exists. What v1 claims and does not claim (index privacy at the algorithmic
level via full uniform scan + zero target-dependent branches; fresh-key queries; no claim
against a malicious ledger beyond stale/fork detection via `snapshot_root`) is unchanged and
still asserted by the security gate and `e2e.py`.

---

## Part II — v2: preprocessed query layer (SimplePIR pattern, ledger-maintained hint)

### V2.0 Scheme

The note log is projected into fixed **R = 288-byte records**
(`commitment(32) ‖ note_ciphertext[0..256)` zero-padded), arranged per shard as an
`m_rows × m_cols` byte matrix D over Z_p in column-major record fill. The client downloads (or
self-computes) a one-time **hint H = D·A**, then sends a single `m_cols`-length query vector
`qu`; the server's whole work is the plain integer matrix-vector product `D·qu`, computed in
public column-range stripes. The client recovers its record from `D·qu − (D·A)·s = Δ·D[:,c*]`.

The distinguishing property from textbook SimplePIR: **there is no offline preprocessing
step.** The ledger is append-only, so each append folds exactly one column segment into H
inside the same replicated, instruction-metered transaction that writes the note — the ledger
IS the preprocessor, and consensus replicates it. Hint integrity therefore reduces to ledger
certification (§V2.5), not to server honesty.

### V2.1 Parameters

| parameter | value |
|---|---|
| LWE dimension n | 1152 |
| modulus q | 2³² (native wrapping `Nat32`/u32) |
| plaintext p | 2⁸ (one cell = one byte) |
| Δ | 2²⁴ |
| noise σ | 12.8, rounded Gaussian, fresh per query (client-side) |
| secret | uniform Z_q^n, fresh per query |
| record R | 288 B = commitment(32) ‖ note_ciphertext[0..256) zero-padded |
| shard size S | fixed at `pir2_enable`, certified in `pir2_params` (default 2²⁰) |

**Public matrix A** is expanded from a fixed nothing-up-my-sleeve constant — never chosen by
any party, never shipped. Normative definition: for shard σ, column c, block
k ∈ [0, n/8), `A[c, 8k..8k+8) = SHA-256("zk-ledger/pir2/v1/A" ‖ σ_le64 ‖ c_le64 ‖ k_le64)`
read as 8 little-endian u32 words. Every client and the reference COMPILE IN the constant and
MUST trap if `pir2_params` echoes a different one (certification proves what the canister
says, not that a seed is honest; the compiled constant is the actual defense against a
trapdoored A).

**Derived geometry** (pure integer function of S, R; `src/Pir2.mo:geometry`, byte-identical in
the Rust reference and every client): `rpc = max(1, (isqrt(S·R)+R/2) div R)`,
`m_rows = R·rpc`, `m_cols = ⌈S/rpc⌉`. Record i in a shard occupies column `i div rpc`, rows
`[R·(i mod rpc), R·(i mod rpc)+R)`.

At **S = 2²⁰**: rpc 60, m_rows 17,280, m_cols 17,477; query 69,908 B, response 69,120 B per
stripe, hint 79.6 MB/shard (m_rows·n·4). At 10⁸: 96 shards, D ≈ 28.8 GB, H ≈ 7.6 GB stable
(inside the IC 500 GiB stable bound).

### V2.2 Correctness

Client phase error = Σ_c D[r,c]·e_c over m_cols pinned columns. Worst case is
adversary-chosen cells (envelope bytes are caller-controlled): all-255 gives
std ≈ 12.8·255·√m_cols. At S = 2²⁰ (m_cols 17,477): std ≈ 2^18.7 vs Δ/2 = 2²³ → ≈19.4σ
margin (per-cell decode failure 3.5×10⁻⁸⁴); uniform-byte data ≈33.5σ. The differential oracle
verifies exact decode on every query and tolerates none.

### V2.3 Security

(n=1152, q=2³², σ=12.8, uniform Z_q secret) — the deployed parameter set — estimates to
**2¹⁴⁷·⁷ classical operations** (cheapest attack: primal-BDD; usvp 2¹⁴⁹·⁵, dual 2¹⁵²·⁷),
comfortably above the ≥128-bit gate. This is a direct lattice-estimator run
(malb/lattice-estimator, sage 10.7) against the exact deployment exposure model: **m_cols LWE
samples exposed per query under one fresh uniform secret; one fixed public A reused across all
clients and queries per shard** (multi-secret LWE, standard hybrid argument, captured by the
estimator's unbounded-sample m=∞ setting); the hint is a public function of public (A, D) with
no secret dependence. The set was chosen for future headroom: the baseline SimplePIR
parameterization (n=1024, σ=6.4) estimates to only 2¹²¹·⁵ under this uniform-secret/m=∞
exposure, so both the dimension and the noise were raised. Any later parameter change
re-triggers the estimator run before deployment.

### V2.4 Query protocol and privacy invariants

A client retrieving position `idx` in shard σ at pinned fill `f` (pinned to a column boundary
by default, quantizing the sync-point fingerprint):

1. `qu = A_σ·s + e + Δ·u_{c*}` over `m_cols(f)` columns, sent as a little-endian u32 Blob.
2. Per stripe `pir2_query(σ, f, stripe, kCols, qu)` scans EXACTLY the stripe's pinned columns
   — bounds are public functions of `(f, stripe)`, never of the target. Response = dense
   `m_rows`-word partial vector + a trace (`cells_scanned`, `target_dependent_branches`,
   `instructions`) + the current fill (client requires ≥ f, catching lagging replicas).
3. Client sums the stripe partials and decodes its R rows; **integrity for free**: decrypted
   cells [0..32) MUST equal the target's expected commitment from the detection stream, and
   the envelope's Poly1305 authenticates the rest.

**Client MUST-clauses (normative — a third-party client that violates them leaks):** always
fetch the full hint; always run the full stripe schedule of the pinned fill; always both
keyword candidates (§V2.6); pin fills to column boundaries. The privacy battery's oracle
detects a partial-schedule client (B12 proof C).

**Auditable invariants:** every stripe's trace carries `records_scanned = full stripe` and
`target_dependent_branches = 0` as canister state, replayable by anyone. `answerStripe`
carries no data-dependent branch on cell or query content.

### V2.5 Certification — the on-chain novelty

- **The ledger is the preprocessor.** Preprocessing is replicated, instruction-metered, and
  transactional with the append. No offline step exists.
- **Certified frozen hints.** Only frozen shards serve hint downloads. At freeze a chunked job
  Merkle-digests 64 KB hint pages and publishes the root in the certified tree next to
  `note_root`; `pir2_hint_chunk` responses verify against the IC certificate. SimplePIR's
  silent-wrong-hint failure becomes detectable equivocation.
- **Certified record stream.** `pir2_record_stream` serves densely packed
  `(position 8B BE ‖ 288 cells)` (296 B/note, measured — the tail hint's verifiable inputs).
  A per-append chained digest `chain_i = SHA-256(chain_{i−1} ‖ cells_i)` with boundaries every
  4,096 records; the latest boundary lives in the certified tree, so a streaming client's
  recomputed chain is anchored.
- **Metering dial and production policy.** The striping design drops into metered update
  execution unchanged — a stripe measured as an update call costs the same 1.098×10⁹
  instructions as the query call (probe, both modes). The demo ships the unmetered query
  path. **Production policy: real-value deployments serve stripes as caller-paid update
  calls (the metered mode), fronted by boundary-side rate limiting**; the unmetered query
  mode is a demo/read-replica configuration, not a production posture. This bounds the
  per-caller cost of the ~1.1×10⁹-instruction stripe the same way any update is bounded,
  and answers the operational-DoS surface of an expensive open query endpoint.

### V2.6 Epoch shards, uniform access, keyword mode

Only the last shard is mutable; frozen shards (D, H, digests) are immutable forever. The
client's hint acquisition AND query schedule are public functions of (birthday, tip, sync
round) ONLY — never of matches: it queries every scheduled shard in [birthday, tip] each
round with a dummy target where it has no match (LWE queries are indistinguishable, so the
transcript is match-independent). The residual leak is the shard set itself — anonymity set
per shard 2²⁰, not 10⁸ — and the transcript-indistinguishability is same-schedule scoped; both are
stated, not hidden. A synced wallet computes the tail hint itself from `pir2_record_stream`
(248 B/note marginal over today's 48 B detection entry) and downloads no hint; it queries only
the tail shard.

**Hint distribution does not need the canister.** A frozen shard's hint is public,
immutable, target-independent data whose 64 KB pages are Merkle-digested with the root in
the certified tree — so hints can be served by any untrusted mirror, CDN, or peer and
verified page-by-page against the certified root at zero trust or privacy cost (the
download reveals only the shard set, which the query schedule reveals anyway). The
canister's `pir2_hint_chunk` (1 MiB/call) is the fallback path, not the distribution
plan: a wallet whose [birthday, tip] window spans k frozen shards acquires its k × 79.6 MB
of hints from mirrors at ordinary CDN speeds, once, and caches them forever (frozen shards
never change).

**Keyword mode** (fetch-by-commitment, for deep-restore repair) uses a STATIC per-shard cuckoo
directory built at freeze (never on the append path — eviction contradicts write-once cells
and would spike the money path), served through the same PIR machinery as a small second
matrix; a client always reads both cuckoo candidates. Tail-shard keyword lookups use the
camouflaged page path until freeze. Reference: keyword-PIR bucketing (Chor–Gilboa–Naor '98).

### V2.7 Cost model (measured)

Measured on PocketIC by `soak/src/bin/probe_pir_cost.rs` (driving `tests/Pir2CostProbe.mo`,
the production `src/Pir2.mo` module) and the seven-variant inner-loop bench
`tests/Pir2MicroBench.mo`. Geometry S = 2¹⁸ for the probe run (rpc 30, m_rows 8,640,
m_cols 8,739); the stripe cost is a function of (kCols, m_rows) only, independent of N, so it
IS the 10⁸-scale stripe measurement.

| quantity | measured | note |
|---|---|---|
| append hint maintenance | 198.2M instr, 2.54 MB alloc / record | **flat across 10⁴/10⁶/4×10⁶**; small next to the ~9B-instr Groth16 verify already on the append path |
| stripe matvec | 258–280 instr/madd; K=486 → 1.098e9 instr | `target_dependent_branches = 0`; **flat across tiers** |
| inner loop | 283 instr/madd (pure-Nat32 widening) | measured winner of 7 variants (v6); vs 360 for the Nat64 shape |
| query wire | 4·m_cols(pinned) | 34,956 B at a 2¹⁸ shard's full fill |
| response wire | 4·m_rows = 34,560 B / stripe | ≪ 2 MiB per message |
| record stream | 296 B/note (gate ≤ 296) | 248 B/note marginal over detection stream |
| hint chunk serve | 1 MiB/call sustained | frozen-shard only |
| backfill | heap-accumulated per shard, single flush | vs naive per-record RMW (~266 TB stable I/O at 10⁸ for 7.6 GB of output) |

**Committed gates:** per-stripe ≤ 1.25×10⁹ instructions (4× headroom under the 5×10⁹ query
budget); total response per full-shard query ≤ 2 MiB (⇒ ≤ 30 stripes ⇒ K derived from
the probe). At S = 2²⁰: K ≈ 600 columns/stripe satisfies both.

**Scaling law to 10⁸:** append and stripe costs are N-independent by construction and
measured flat across three tiers; a full-size stripe at 10⁸-scale content is directly runnable
(a stripe is bounded by (K, m_rows)). The 10⁸ table: 96 shards, query 69.9 KB/shard, response
69.1 KB/stripe, hint 79.6 MB/frozen shard, append 198M instr — all measured constants.

### V2.8 Flag, migration, boundaries

`PIR_V2_ENABLED` (stable, default false) is armed by one-shot `pir2_enable(S)` (repeat traps;
S immutable for the deployment's life; no disable surface). Flag off ⇒ the append path skips
all maintenance and every v2 endpoint rejects; `pir_query_lwe` and all existing behavior are
byte-identical. Enabling on a non-empty log starts a chunked heap-accumulated backfill; v2
queries reject until it completes. New stable regions carry layout-version headers; postupgrade
does O(1) header checks; `moc --stable-compatible` old→new (old = public `08ff678`) passes and
the candid diff is additive-only.

Stated boundaries: the demo configuration serves queries unmetered — production serves
stripes as caller-paid metered updates behind boundary rate limiting (§V2.5, measured at
identical instruction cost); the shard-set access pattern leaks epoch-granularity membership (2²⁰
anonymity set); and the security parameter set is pinned by the estimator run in §V2.3 —
any future parameter change re-triggers that estimate before deployment.
