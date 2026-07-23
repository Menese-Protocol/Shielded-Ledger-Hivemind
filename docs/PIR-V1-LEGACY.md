# PIR v1 (legacy): the linear LWE baseline — SUPERSEDED

> **Status: superseded.** The deployed, normative PIR specification is
> [`PIR-V2-SPEC.md`](PIR-V2-SPEC.md) (v2: n = 1152, q = 2^32, σ = 12.8, derived index,
> certified mirrors, `pir2_boundary`). This file preserves the v1 baseline (n = 630,
> q = 2^64) for provenance: v1 remains in the artifact as the simple, self-verifying
> reference (`pir_query_lwe`), and nothing in this file is normative for deployments.
> The section below is relocated VERBATIM from the original combined `PIR-SPEC.md`.

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
