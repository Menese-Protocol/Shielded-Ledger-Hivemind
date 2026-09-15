# Finalize beacon for the power-14 ceremony

Published 2026-09-15, before the contribution window closes. The coordinator
`osqjo-zyaaa-aaaad-agxua-cai` reports `end_time = 1789492820000000000`, which is
**2026-09-15 17:20:20 UTC**. This file, and the commit that carries it, exist so that the
beacon is fixed by a rule nobody can steer once the rule is public, and so that anyone can
recompute it later without trusting us.

## The rule

```
T = 2026-09-16 12:00:00 UTC   (1789560000000000000 nanoseconds since the Unix epoch)

beacon block = the ICP ledger block with the SMALLEST index whose block timestamp is >= T
beacon bytes = ASCII  "icp-ledger-block:<index>:<sha256 hex of the encoded block>"
```

- The ledger is the ICP token ledger, canister `ryjl3-tyaaa-aaaaa-aaaba-cai`. It is an
  append-only, hash-chained log. Every block is served forever, either by the ledger itself
  (`query_encoded_blocks`) or by one of its archive canisters (`get_encoded_blocks`), which
  the ledger names in its reply.
- The block hash is SHA-256 over the block's protobuf encoding exactly as those endpoints
  return it. That is the ledger's own chaining hash: block `i+1` carries it as `parent_hash`.
  `icp-beacon.py` checks that equality on every resolution.
- The coordinator folds the beacon in as `d = hash_to_fr("beacon" || beacon bytes)` and
  refuses a finalize whose delta is not exactly that (`coordinator/src/PokVerify.mo`,
  `verifyBeaconStep`). The transcript records the beacon bytes, so the transcript verifier
  recomputes `d` from them; nothing about the beacon is taken on trust from the authority.

## Why a timestamp and not a block index

A named future *index* is only unpredictable if it is mined after the window closes, and
the ICP ledger's block rate is bursty: a large airdrop or exchange sweep can multiply it for
hours. An index chosen for tomorrow could land today. A timestamp cannot. T is 18 hours and
39 minutes after `end_time`, so no contribution accepted by the canister was made with the
beacon block in existence.

## Why this is a valid beacon

The block's hash depends on its parent hash and on the transaction it carries: whoever
happens to submit the first ICP transfer at or after T, with whatever amount, fee, memo and
timestamp they use. That transaction is not known to anyone before T, and T is after the
window closes, so no contributor, and not the authority, can have chosen their contribution
with knowledge of the beacon.

What a beacon does and does not do: it prevents the last contributor (or a coalition of every
contributor) from steering the final parameters to a value they precomputed. It does not
change the 1-of-N honesty argument: the keys are safe if at least one of the 25 contributors
discarded their secret, beacon or no beacon.

Limits, stated plainly:

- A party who deliberately submits the transaction that becomes the beacon block can choose
  among a handful of candidate hashes by varying their memo. That is a choice among a few
  unpredictable values, made after every contribution is already fixed; it cannot recover a
  secret and cannot make the output predictable to anyone earlier. Bitcoin miners have the
  same freedom over a named block, and drand rounds do not, which is why drand would have
  been the stronger choice on this one axis. We chose the ledger for being native to the
  chain the shielded ledger runs on and for being checkable with one query by its users.
- The authority identity could finalize before T with a beacon of its choosing. The
  coordinator only checks that the delta matches whatever bytes it is handed. The defence is
  this commitment: a finalize whose recorded beacon bytes do not equal the rule's output, as
  recomputed by `icp-beacon.py verify`, is a finalize the community should reject, and the
  transcript makes that visible to everyone.

## How to check it

```
pip install ic-py
python3 ceremony-launch-p14/icp-beacon.py resolve 2026-09-16T12:00:00Z
```

Before T this prints `NOT YET`. After T it prints the block index, its timestamp, its hash,
the chaining cross-check against the next block, and the exact beacon string. Once the
ceremony is finalized, compare against what the transcript recorded:

```
python3 ceremony-launch-p14/icp-beacon.py verify 'icp-ledger-block:<index>:<hex>' 2026-09-16T12:00:00Z
```

which exits 0 and prints `BEACON VALID` only when the claimed string is the rule's output.
`icp-beacon.py check <index>` shows any single block's timestamp and hash.

The resolver was exercised before publication against two past timestamps (one served by the
ledger, one by an archive), a round trip through `verify`, and a deliberately altered claim,
which failed as it must.

## Order of events from here

1. 2026-09-15 17:20:20 UTC: the window closes; the coordinator refuses further contributions.
2. 2026-09-16 12:00:00 UTC: T passes; the beacon block exists and `resolve` names it.
3. The authority applies the beacon step off-chain to the assembled transcript
   (`ceremony-cli finalize`), uploads the resulting parameters and proof, and calls
   `submit_beacon` with the exact beacon bytes.
4. Anyone runs `verify-transcript ... --selfcheck` on the published transcript and
   `icp-beacon.py verify` on the recorded beacon. Only then are the keys production
   candidates, per `docs/CEREMONY.md` and `docs/TRUSTED-SETUP-POLICY.md`.

Menese DeFi Team
