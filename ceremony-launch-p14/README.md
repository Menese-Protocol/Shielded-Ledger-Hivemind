# Phase-2 ceremony opening parameters, power 14 — 2026-08-31

Supersedes `ceremony-launch-aug24/` (power 16), which is now stale: those parameters were
derived for a 2^16 QAP domain and this circuit is 2^14. Their own README says they are
"valid ONLY if this fork ships unchanged"; the fork changed twice since
(tag-into-capacity, then the 4-ary tree), so they do not apply.

The earlier power-15 artifacts and the power-16 artifacts in
`ceremony-launch-aug24/` both stay valid as history. Neither fits the circuit.

## Why power 14

`statement_dims` pins the hardened and legacy QAP domains at 2^14 by assertion
(`h_query.len() + 1 == 16384`). The hardened transfer statement is 14,261 constraints /
14,335 wires, which fits 2^14; before the tree change it was 20,277 and did not.

Note for anyone reading the older commit messages: `aed8f80` describes the tree as "5-ary,
14 levels". The shipped code is **arity 4 over 16 levels** — `4^16 == 2^32` exactly, and
arity 5 measured 0.99x on the frontier bench, i.e. break-even. The "5-ary" naming is stale.
The domain is 2^14 either way, so the proving key is byte-for-byte identical between the two
arities and this ceremony is unaffected by that naming error.

## Provenance — same pinned record, re-verified

Phase-1 was re-extracted at power 14 from the SAME upstream Sapling record used at powers 15
and 16. The record's hash was verified against its published pin BEFORE extraction; the
originals were read only.

- upstream record `final_record.bin` sha256
  `b656a7ee2fd23f184b58db584d0e8dd45bfed06efd9f5b47bb5cbaeb58a3f8d3`
  — matches the published pin recorded alongside the record, and the same value recorded for the
  earlier power-16 extraction from this record, which is the cross-check that the two extractions
  read the same upstream bytes.
- upstream url
  `https://archive.org/download/transcript_201804/transcript#record-88-of-89-bytes-106300550400-107508511199`
- extraction (FULL pairing structure check, refuses on any failure):
  `ceremony-cli import-ptau final_record.bin 0 21 14 <pinned-url> sapling-phase1-p14.srs.bin PROVENANCE-p14.json`
  → `PHASE-1 INGESTED + VERIFIED`

## Artifacts

| file | sha256 | size |
|---|---|---|
| `sapling-phase1-p14.srs.bin` | `94f268950305fd23b50fa77dec3d540e2742d3472d7416160cce627566ae39e8` | 4,718,677 B |
| `ceremony-transcript-p14.bin` (opening) | `de0ae68d71877fc1b8967ceb406972d58a6a49cf8969dd27375595018aaf9b84` | 4,451,869 B |
| `PROVENANCE-p14.json` | `e68298ad3b89c5cf8d8442f2c85781ca99a45c6c4b148c4eafb5fbefb9fbe186` | 505 B |

Opening parameter shape: transfer h/l = **16383/14326**, deposit h/l = **1023/726**.
`h = 2^14 - 1` as the domain requires; the `l` counts are the statements' finalized witness
counts.

## Verification

```
verify-transcript sapling-phase1-p14.srs.bin ceremony-transcript-p14.bin --selfcheck

SRS: power 14 (32767 G1 tau powers), provenance InheritedReviewedPhase1
SRS SHA-256: 94f268950305fd23b50fa77dec3d540e2742d3472d7416160cce627566ae39e8
transcript: 0 contributions, finalized=false
TRANSCRIPT VALID
  honest contributions : 0
  finalized (beacon)   : false
  transfer vk SHA-256  : 08e15807338263653a5e3ed96fa5c5d71df03d67863f4ff784b4ef278f8dd720
  deposit  vk SHA-256  : 5c6cfc31de04ab1c1b07aa5c596d8deaf1cc4ca940e3ed04a0f6a7dc30ff2d83
KEYS WORK (real transfer + deposit proofs verify)
```

- The opening **transfer** vk `08e15807…` is distinct from the power-16 opening
  (`8dcfec7d…`) and from the stale Jul-18 opening (`06a78e29…`), as a domain change requires.
- The opening **deposit** vk `5c6cfc31…` is **byte-identical to both** earlier openings.
  That is the expected consistency check, not an anomaly: the deposit circuit carries no
  Merkle path, so it is untouched by the tree changes, and each SRS is a prefix-extension of
  the same tau, leaving its 2^10-domain parameters unchanged. A change here would have
  indicated a corrupted extraction.

## A fix this required, and why it matters

`ceremony/src/session.rs` did not compile against the current circuit. Its `KEYS WORK`
self-check built a witness in the old binary-tree shape (`in_siblings` / `in_bits`); the
circuit now takes the 4-ary row-plus-position witness (`in_rows` / `in_pos`). Until this was
fixed, the self-check could not run at all, so parameters could have been generated with no
way to confirm they produce verifying proofs.

The fix also had to route the tree hashing through `poseidon_config_tree()` rather than the
note/commitment `poseidon_config()`. Those are different Poseidon instances (the tree is
width 6, rate = TREE_ARITY). Wrapping the wrong one in a `TreeCfg` typechecks and then
silently produces an anchor under the wrong permutation, which is the failure mode this
comment exists to prevent.

## Status

These are PRE-ceremony **opening** parameters. Production verifying keys come only from
contributions plus the beacon finalize, per `docs/CEREMONY.md`. Nothing here is real-value
eligible yet and nothing here touches mainnet.

**Still required before contributions can be opened:**

1. A deployed coordinator. There is none; the Aug-24 launch did not deploy one either.
2. The coordinator must serve THESE power-14 opening parameters, not the Aug-24 power-16 set
   and not the Jul-18 set.
3. `PHASE1-PIN.md` should gain the power-14 extraction
   record above. The p15 and p16 artifacts remain valid history.
4. These parameters are valid only while `circuit/common` is unchanged. Any further circuit
   edit re-stales them, exactly as happened twice already.

Menese DeFi Team
