# Fortress coverage-guided fuzzing (§7)

cargo-fuzz / libFuzzer targets for every parser and crypto-decode boundary that ingests
untrusted bytes. Each target asserts the decoder is a **total function**: no panic, no trap,
no uncontrolled allocation, no unbounded loop, and no acceptance of a malformed or
non-canonical encoding. libFuzzer catches panics/aborts/OOM/timeouts automatically; the
targets add domain assertions (idempotent decode, canonical re-check).

## Targets

| target | boundary | assertion |
|---|---|---|
| `decode_g1` | compressed G1 (blst, ZCash format) | total; accepted point re-compresses and re-decodes (idempotent) |
| `decode_g2` | compressed G2 (blst) | total; idempotent decode |
| `decode_fr` | 32-byte LE Fr canonicality (blst) | total; accepted scalar survives a round-trip re-check |
| `decode_proof` | arkworks Groth16 proof (compressed + uncompressed) | total; malformed → Err, never panic |
| `decode_vk` | arkworks Groth16 verifying key | total; malformed → Err, never panic |
| `teeth_planted_panic` | a decoder with a DELIBERATE out-of-bounds panic on the `BUG!` prefix | **must crash** — proves the harness detects a real decode bug; NOT part of the gate pass criteria; its crash input is stored as a regression |

The Motoko-side decoders that cargo-fuzz cannot reach (`Groth16Wire`, `Decode`/`DecodeG2`,
`NoteCodec`, ICRC-3 block codec) are covered by the equivalent seeded random-bytes battery
in the §2 decode suite (`dec.g1`/`dec.g2`/`dec.frle` in `fortress/motoko/PairingDiff.mo`),
which runs the production Motoko decoders against the blst oracle with the same
no-trap-except-typed-reject / no-acceptance-of-non-canonical assertions.

Additional targets to add when the ceremony proposal is approved: `decode_ceremony_transcript`,
`decode_contribution` (`ceremony/src/`), and an `icrc3_block` differential.

## Seed corpora

`corpus/<target>/` ships hand-picked valid + boundary seeds (curve generators, the infinity
encoding, canonical scalars, real proofs/keys from the frozen fixtures) plus every crash the
fuzzer has ever found (stored as a regression — currently the planted-panic regression under
`corpus/teeth_planted_panic/`). libFuzzer grows the corpus by coverage during a run.

## Run policy

- **Per commit (gate tier, offline, deterministic):** each real target `-runs=200000 -seed=1`
  plus a full corpus replay; zero crashes. One command: `scripts/fortress-fuzz.sh`.
- **Per release:** each real target ≥ 24 h wall-clock, or until coverage plateaus, whichever
  is longer, with the growing corpus committed back.
- **Teeth (every gate run):** `teeth_planted_panic` MUST reproduce its stored crash — if it
  ever stops crashing, the fuzz harness has regressed and the gate fails.

## One-command invocation

```bash
# offline gate tier (all real targets, fixed budget, + teeth)
scripts/fortress-fuzz.sh

# a single target, longer
cd fortress && cargo +nightly fuzz run decode_g1 -- -runs=10000000

# release soak
cd fortress && cargo +nightly fuzz run decode_proof -- -max_total_time=86400
```

Provisioning (network, done once, out-of-band — the offline gate never installs anything):
`cargo install cargo-fuzz` (0.13.2 pinned) + a nightly toolchain (`rustup toolchain install
nightly`). The gate runs the pre-built targets; it performs no network access.
