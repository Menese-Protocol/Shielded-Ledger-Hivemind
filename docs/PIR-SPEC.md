# PIR specification: parameters, security estimate, and cost model

The ledger's `pir_query_lwe` endpoint lets a client read one record from the public commitment
log without revealing which record it read. This document states the exact scheme, its
parameters, what security is and is not claimed, and what it costs; the numbers here are the
authoritative reference for the implementation in `demo-frontend/prover-wasm/src/lib.rs`
(client) and `src/Main.mo` (ledger).

## Scheme

Plain LWE (Regev-style) private information retrieval, one query bit per record.

The client encrypts a selector vector of `N` bits, one per record, where exactly the target
record's bit is 1. For each of the record's 256 output bits, the ledger homomorphically sums
the selector ciphertexts of every record whose public database bit is set. Branching in that
scan depends only on the public database bit; the encrypted selector is never decrypted,
inspected, or branched on. The response is 256 ciphertexts; the client decrypts each and
rounds to recover the record.

## Parameters

| parameter | value | where |
|---|---|---|
| dimension `n` | 630 | `PIR_DIMENSION` / `LWE_DIMENSION` |
| ciphertext modulus `q` | 2^64 (native wrapping `u64`/`Nat64`) | arithmetic type |
| plaintext scale Δ | 2^63 (one bit per ciphertext) | `PIR_DELTA` |
| decoding threshold | 2^62 | `PIR_ROUNDING` |
| noise | rounded Gaussian, σ = 2^49 (Box–Muller over OS/browser entropy) | `PIR_NOISE_SIGMA` |
| secret | uniform binary, length 630, fresh per query | `pir_keygen` |
| record width | 256 bits (the 32-byte note commitment) | `PIR_OUTPUT_BITS` / `RECORD_BITS` |
| ciphertext | 630 × u64 (`a`) + 1 × u64 (`b`) = 5,048 bytes | wire structs |

The ledger rejects, by trapping, any query whose selector count differs from the full note-log
length or whose ciphertext dimension differs from 630. Coefficients travel as full-width 64-bit
integers (strings in JSON on the frontend boundary, `nat64` in candid), so no coefficient is
ever range-reduced by the transport.

## Security estimate

The noise-to-modulus regime is `q/σ = 2^15` at dimension 630 with a binary secret. The closest
well-studied reference point is FrodoKEM-640 (n = 640, `q/σ ≈ 2^13.5`), which targets NIST
Level 1, roughly 128-bit classical security. This scheme sits in the same neighborhood with a
slightly wider noise gap and a binary rather than small-Gaussian secret, both of which cost
some margin; a first-order honest claim is therefore **on the order of 2^100–2^128 classical
operations**, and a precise figure from the
[lattice estimator](https://github.com/malb/lattice-estimator) is an open item that must be
pinned before any real-value deployment.

What is claimed, precisely:

- **Index privacy at the algorithmic level.** The scan touches every record and performs no
  target-dependent branch; each response reports `records_scanned` (always the full log) and
  `target_dependent_branches` (always zero), and the security gate asserts both.
- **Fresh-key queries.** The secret is generated per lookup and never reused, so query
  repetition compounds no key exposure; each query is an independent LWE instance.
- **Safe handling of malformed input.** Wrong selector counts and wrong dimensions trap before
  any scan. All coefficient arithmetic is wrapping; a malformed coefficient value cannot leave
  the `u64` domain, cannot trap mid-scan, and produces only garbage for the client to decrypt.

What is **not** claimed:

- Network- and transport-level metadata (that you queried at all, when, and from where) is out
  of scope; PIR hides the index, not the act of querying.
- No claim is made against a malicious ledger that returns wrong answers; the response carries
  the certified `snapshot_root` so the client can detect a stale or forked view, but response
  correctness against a fully malicious server is not part of the LWE PIR guarantee.
- The parameter set has not yet been through the lattice estimator or independent review; see
  the audit boundary in the README.

## Cost model

For a log of `N` records:

| quantity | formula | at N = 34 (today) | at N = 1,000 |
|---|---|---|---|
| query size | N × 5,048 B | 172 KB | 5.05 MB |
| response size | 256 × 5,048 B, **constant in N and in the target** | 1.26 MB | 1.26 MB |
| ledger work | ≈ N × 256 × 631 / 2 wrapping adds (density ~½) | ~2.7M adds | ~80.7M adds |

Correctness has enormous margin: the summed error grows as σ·√N ≈ 2^49·√N against a decoding
threshold of 2^62, so per-bit decoding failure stays negligible past 10^6 records; the message
size limit binds long before the noise does.

## Known boundaries at scale

Two limits are stated openly rather than hidden:

1. **Query size grows linearly.** The ingress message limit (~2 MB) bounds a single-call query
   to roughly 400 records. Beyond that the query must be chunked across calls, or the scheme
   upgraded to a batched or recursive PIR construction; that upgrade is the stated production
   path, not an afterthought.
2. **Query calls are unmetered on the Internet Computer.** A query costs the caller nothing
   while the node performs the full linear scan, so at production scale a cheap caller can
   force expensive work. The production design must bound this: moving heavy PIR behind
   metered update calls, capping served log windows, or serving PIR from dedicated replicas.
   For the valueless demo the exposure is accepted and documented.

Linear-scan PIR is the honest baseline: it is simple enough to verify and its privacy property
is checkable in the response itself. At meaningful ledger size the scan becomes the dominant
cost even though it stays private; treating that as a scaling problem to engineer, rather than
a reason to weaken the privacy property, is the design position of this repository.
