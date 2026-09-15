# Phase-2 ceremony launch runbook — power 14

The exact sequence that takes the verified power-14 opening parameters in this directory to a live,
contributable coordinator. Written against `coordinator/coordinator.did` and
`coordinator/src/Main.mo` at the commit that carries this file.

Read `docs/CEREMONY.md` first. This runbook is the operational half; that document is the spec and
the trust model.

## 1. Pre-flight state, re-verified 2026-09-01

Every line below was executed on this tree, not carried over from a prior session's notes.

| check | command | result |
|---|---|---|
| artifact integrity | `sha256sum ceremony-launch-p14/*` | all three match the `README.md` table |
| opening parameters vs the CURRENT circuit | `verify-transcript sapling-phase1-p14.srs.bin ceremony-transcript-p14.bin --selfcheck` | `TRANSCRIPT VALID` + `KEYS WORK` |
| coordinator reproducibility | `coordinator/verify-build.sh` | `REPRODUCIBLE BUILD VERIFIED`, `ce34f578…` |
| publication scrub | `scripts/publish-scrub.sh` | `PASS`, leaks 0, needs-review 0 |
| circuit stability | `git log --since=<srs-gen> -- circuit/` | only `tests/violation_matrix.rs`, a comment |

The install-and-initialize sequence in section 4 was then rehearsed end to end against a clean local
replica, using the real payloads rather than the reduced ones:

| step | result |
|---|---|
| install published wasm, compare module hash | `0xce34f578…` == `BUILD-HASH.txt` |
| `configure` (power 14, the section-2 hashes) | `ok`, authority recorded |
| `upload_initial_chunk` transfer, 2,948,360 B in 2 chunks of ≤1.5 MB | both `chunk accepted` |
| `upload_initial_chunk` deposit, 168,200 B in 1 chunk | `chunk accepted` |
| `finish_init` | `initialized; genesis challenge set` |
| `get_transcript_summary` | `power = 14`, `srs_sha256 = 94f26895…`, `count = 0`, `genesis == running` |
| `get_current_params_meta` | `transfer_len = 2_948_360`, `deposit_len = 168_200` |

This is the first execution of the real-size chunked upload and of `finish_init`'s length check
against real payloads. The PocketIC battery in `coordinator/battery/` deliberately uses tiny delta
parameters and so has never covered either. 1.5 MB chunks are comfortable; `finish_init` accepted
the reassembled lengths on the first attempt.

A real contribution was then driven through the shipped browser client
(`demo-frontend/contributor-client/`) against that live coordinator, and the resulting transcript was
pulled back off the chain and handed to the independent verifier:

| step | result |
|---|---|
| client connect / `join_queue` / `begin_contribution` | queue position 1, staging open |
| download current parameters | 2,948,360 B + 168,200 B |
| `transform_contribution` in the wasm sandbox | secret sampled, applied, discarded in-tab |
| upload + `submit_contribution` | `contribution 1 accepted` (23.6 s for the whole click) |
| reassemble transcript from on-chain queries | `initial parameters match the SRS-derived ones` |
| `verify-transcript --selfcheck` over it | `TRANSCRIPT VALID`, `honest contributions : 1`, `KEYS WORK` |

The transfer vk moved from the opening `08e15807…` to `fe010c6e…` and the deposit vk from
`5c6cfc31…` to `e2dc0e4c…`, which is the section-2 check that the contribution actually took effect.
The two `fixed` hashes are unchanged, as they must be — they are circuit-fixed, not delta-dependent.

This closes the last untested path. On-chain acceptance is structural only, so a browser contribution
was never previously known to be *sound*; it now is, end to end, by the verifier that shares no code
with the coordinator.

### A launch step the browser run surfaced

`demo-frontend/contributor-client/index.html` ships with the coordinator canister id as an EMPTY
field the contributor types in, and the host defaulted to `http://127.0.0.1:4945` — a local address
that matches neither mainnet nor this repository's own local network (41403). Two consequences for a
public ceremony, the second of which matters:

1. Every contributor has to be told the host, and the shipped default is wrong for all of them.
2. **An id the contributor pastes is an id an attacker can substitute.** A ceremony page that asks
   the participant to supply the coordinator address invites a look-alike page, or a wrong id posted
   in a chat, sending contributions to a canister nobody audited. The published page should carry the
   real coordinator canister id and the mainnet host baked in, with the id also printed in
   `docs/CEREMONY.md` so a contributor can cross-check the page against the spec rather than trusting
   whichever copy they landed on.

This is a one-line change once the coordinator id exists, but it cannot be made before the deploy, so
it belongs in the launch sequence between section 3 and announcing the ceremony. It is written here
rather than changed now because guessing an id would bake in a wrong one.

The last row of the pre-flight table is the one that retired the two previous ceremonies. The opening parameters are valid
only while `circuit/common` is unchanged; the only post-generation commit touching `circuit/` changed
a comment inside a test, so the parameters still stand. **Re-run that git check immediately before
launching** — if any non-test circuit source has moved since, these parameters are stale and the
extraction must be redone rather than launched from.

## 1a. Launch record — executed 2026-09-01

The ceremony is LIVE. Everything below is what actually ran, read back off the chain rather than
copied from the commands that were issued.

```
coordinator        osqjo-zyaaa-aaaad-agxua-cai   module ce34f578… , NO CONTROLLERS
contributor page   ovrp2-uaaaa-aaaad-agxuq-cai   https://ovrp2-uaaaa-aaaad-agxuq-cai.icp0.io
authority          4jzjr-ob6oo-sb3ew-eeaxp-444x7-sdf33-allxe-owics-g5k2v-52jrv-fae
window             1788283220000000000 .. 1789492820000000000   (14 days, opened immediately)
turn timeout       1800000000000 ns (30 min)
```

Funding: 3.12560699 ICP → 5.626 TC at 18,035 XDR-permyriad/ICP. Coordinator 4 TC at creation
(3.478 TC after install), contributor page 1.2 TC, 0.441 TC left liquid in the cycles ledger.

Order of operations, and why: the coordinator was **created empty and left without a module** while
its id was published and baked into the page. `configure` makes its first caller the authority
permanently, so a module that is live but unconfigured is a public race for the ceremony; an empty
canister has nothing to claim. Install, hash-check and `configure` then ran back-to-back.

| gate | result |
|---|---|
| `verify-transcript --selfcheck` re-run on this tree | `TRANSCRIPT VALID`, `KEYS WORK`, all hashes match section 2 |
| circuit stability since SRS extraction (09:26) | holds — the only later commits, `9398de6` and `057c624`, touch `tests/` only |
| deployed module hash vs `BUILD-HASH.txt` | `ce34f578…` == `ce34f578…`, checked before `configure` |
| `configure` / 3 × `upload_initial_chunk` / `finish_init` | all `ok`; `initialized; genesis challenge set` |
| on-chain state | power 14, srs `94f26895…`, lengths 2,948,360 / 168,200, genesis == running, count 0 |
| opening parameters pulled BACK off the chain | byte-identical to the verified artifacts, both circuits |
| blackhole | controllers empty; a management call now refused `IC0542` |
| published page → live coordinator | reachable under the page's own CSP, reports the correct state |

Two defects were found and fixed during launch, both invisible on a local replica:

1. **Sign-in did not exist.** `app.js` took `getIdentity()` without ever calling `login()`. On
   mainnet every contributor would have been the anonymous principal `2vxsx-fae` — one shared
   identity, so the second `join_queue` is refused as a duplicate, the `staging.who != caller`
   guard never trips, and the transcript records one contributor for the whole ceremony, erasing
   the participant count that section 3 of `docs/CEREMONY.md` rests on. Now a real Internet
   Identity sign-in, mandatory off localhost, with an anonymous-principal refusal behind it.
2. **The CSP blocked the transform.** dfx's "standard" security policy ships `script-src 'self'`,
   and WebAssembly compilation counts as script evaluation. Measured against the live canister:
   `CompileError … 'unsafe-eval' is not an allowed source of script`. Overridden with
   `'wasm-unsafe-eval'`, which permits WebAssembly and not `eval()`. Re-measured: compile OK.

Measured capacity, from five real browser contributions against a local replica carrying the same
published wasm and the real payloads:

```
memory   202,012,006 B at init -> 269,120,870 -> 336,229,734 -> 336,229,734 -> 336,229,734 -> 336,229,734
cycles   ~15.1 B per contribution, consistent across all five
```

Heap steps in 64 MiB increments as the working set expands and then **plateaus** — the growth is not
per-contribution. Amortized growth is the ~3.12 MB of retained deltas per contribution, so the 3 GiB
wasm memory limit is roughly 900 contributions away, and 3.478 TC covers the window with a wide
margin. (Two data points would have read as a hard 44-contributor ceiling; five do not.)

Consequences of the blackhole, stated plainly because they are permanent: the canister's cycle
balance and status can no longer be read by anyone, and `wasm_memory_limit` can no longer be
raised. Cycles can still be deposited by anyone, and every ceremony method is gated on the
authority principal rather than on controllership, so `submit_beacon` and finalize are unaffected.
The published wasm carries no `candid:service` metadata, so tools cannot introspect the interface
from the canister; `coordinator/coordinator.did` in this repository is the published interface.

### The beacon (settled 2026-09-15, before the window closed)

**Named in `BEACON.md`:** the ICP ledger block with the smallest index whose timestamp is at or
after 2026-09-16 12:00:00 UTC, folded in as `icp-ledger-block:<index>:<sha256>`. The original
intent was a named future Bitcoin block height; it was replaced by an ICP-native source, and by a
timestamp rather than an index so that a burst in the ledger's block rate could not pull the beacon
block ahead of the close. `icp-beacon.py` resolves and verifies it.

## 2. Values `configure` takes

These are not free choices. They are read off the verifier's own output over the artifacts in this
directory, and a deployed coordinator carrying different values is serving different parameters.

```
power                = 14
srs_sha256           = 94f268950305fd23b50fa77dec3d540e2742d3472d7416160cce627566ae39e8
transfer_fixed_hash  = fb5f120a18a0318cd9d49ac413f64cae27312b9d55a8b36240e53aa2cae2e9ad
deposit_fixed_hash   = fdc73e08de8a562262c94464a3ea739bc452c1ac120b78a885ab5aaf6f1e0cbd
```

`start_time`, `end_time` and `turn_timeout` are the ceremony window and are an operator decision
(section 5). `configure` rejects `end_time <= start_time` and a non-positive `turn_timeout`, and runs
a G2 generator self-check before it accepts anything.

The opening verifying keys these parameters produce, for comparison after finalize:

```
transfer vk SHA-256  = 08e15807338263653a5e3ed96fa5c5d71df03d67863f4ff784b4ef278f8dd720
deposit  vk SHA-256  = 5c6cfc31de04ab1c1b07aa5c596d8deaf1cc4ca940e3ed04a0f6a7dc30ff2d83
```

These are the **pre-contribution** keys. The production keys are different by construction — they
come only from contributions plus the beacon finalize. If the finished ceremony reproduces these
hashes, no contribution took effect and the result must be rejected.

## 3. Install the coordinator — do NOT use `dfx deploy`

🔴 `dfx.json` declares `coordinator` as `type: motoko`, so `dfx deploy coordinator` **rebuilds from
source** and installs whatever wasm that build produces. The entire trust story of this coordinator is
that the deployed module hash equals the published `BUILD-HASH.txt`, and a rebuild under any
unpinned toolchain silently breaks that equality while reporting success.

Install the published artifact explicitly:

```
dfx canister create coordinator --network ic
dfx canister install coordinator --network ic \
    --mode install \
    --wasm coordinator/coordinator.wasm
```

Then prove the deployed module is the published one, before configuring:

```
dfx canister info coordinator --network ic     # Module hash must read ce34f578fa583f9ff785f3a9c235d801b7fd36dde50e1db985c7e6cefc6fe616
```

If that hash differs, stop. Do not configure a coordinator whose binary cannot be reproduced.

## 4. Configure, upload, initialize

`configure` has no authority argument: **the first principal to call it becomes the authority
permanently.** There is no transfer, no recovery, and no second chance. Confirm the calling identity
before this call, not after.

```
# 1. becomes authority + sets the window
dfx canister call coordinator configure '(14 : nat32, blob "...", blob "...", blob "...", <start> : int, <end> : int, <timeout> : int)' --network ic

# 2. upload the opening parameters (authority only, after configure, before finish_init)
#    payloads come from: ceremony-cli emit-initial ceremony-transcript-p14.bin <outdir>
#      transfer_initial.wire  2,948,360 B  -> 2 chunks (chunks are appended in call order)
#      deposit_initial.wire     168,200 B  -> 1 chunk
#    the binding limit is the IC ingress message size, not the canister. Both 1.5 MB and 1.8 MB
#    chunks were accepted against a live replica; 1.8 MB is the size the browser contributor client
#    uses (`demo-frontend/contributor-client/app.js`, CHUNK), so that path is covered too.
dfx canister call coordinator upload_initial_chunk '(variant { transfer }, blob "...")' --network ic
dfx canister call coordinator upload_initial_chunk '(variant { transfer }, blob "...")' --network ic
dfx canister call coordinator upload_initial_chunk '(variant { deposit  }, blob "...")' --network ic

# 3. freeze the initial parameters and compute the genesis challenge
dfx canister call coordinator finish_init --network ic
```

`finish_init` re-checks the uploaded byte counts against the lengths implied by the h/l shape and
refuses on a mismatch, so a dropped or duplicated chunk fails here rather than corrupting the
ceremony. The wire format is a 296-byte header plus 96 bytes per point; both payloads satisfy this
exactly at transfer h/l = 16383/14326 and deposit h/l = 1023/726.

Query `get_ceremony_info` and confirm `configured = true`, `init_done = true`, `power = 14`, and that
`srs_sha256` matches section 2 before announcing the ceremony to anyone.

## 5. Decisions that must be made before contributions open

These are governance choices, not engineering ones, and each is irreversible or publicly binding.
**All were decided at launch except the beacon, settled 2026-09-15; see section 1a and `BEACON.md`.**

1. **Authority identity.** Permanent, per section 4. Settled: `4jzjr-ob6oo-…`, this box's `default`
   identity. Note what that means — it is a plaintext `identity.pem` on a shared build host, not a
   securely-stored key, and dfx only accepts it against mainnet under
   `DFX_WARNING=-mainnet_plaintext_identity`. Whoever holds that file can finalize the ceremony
   with a beacon of their choosing. It cannot rewrite the transcript (the canister is blackholed)
   and it cannot recover toxic waste from an honest contributor, so this is a
   ceremony-integrity risk, not a soundness break. Protect the file accordingly.
2. **The beacon.** `docs/CEREMONY.md` §2 requires a public random beacon folded in as the final step.
   Its source must be *specified publicly before the window closes* — a named future Bitcoin block
   height, a named drand round, or as chosen here a named future ICP ledger timestamp — or it
   provides no unpredictability. Choosing it afterward defeats its only purpose. Settled: see
   `BEACON.md`.
3. **The window.** `start_time`, `end_time`, `turn_timeout`. `turn_timeout` is what reclaims a slot
   from a participant who joins the queue and then disappears; too long and one absent contributor
   stalls the queue.
4. **Contributor client hosting.** `demo-frontend/contributor-client/` is the only client that can
   reach a deployed coordinator; the Rust CLI carries no agent and physically cannot contribute. Its
   wasm is prebuilt at `pkg/ceremony_contributor_wasm_bg.wasm`. `dfx.json` declares no asset
   canister, so a host for this page is required.
5. **Participant set.** Security is 1-of-N honest. The count and independence of contributors is the
   whole assurance argument.

## 6. Do not upgrade the coordinator mid-ceremony

`coordinator/src/Main.mo` compiles with an M0206 migration warning: the `staging` field is consumed by
the migration expression without being reproduced, so it is reinitialized on upgrade. An upgrade
while a contributor holds an open staging slot discards their in-flight upload. The transcript itself
is unaffected, but the contributor's turn is lost. Treat the coordinator as immutable for the
duration of the window.

## 6a. Finalize

The Rust CLI carries no IC agent, so the beacon step reaches the coordinator through
`finalize.py` in this directory (python3 + ic-py; the authority identity is dfx's `default`):

```
python3 ceremony-launch-p14/icp-beacon.py resolve 2026-09-16T12:00:00Z     # after T; prints the beacon string
python3 ceremony-launch-p14/finalize.py run 'icp-ledger-block:<index>:<hex>' <workdir>
```

`run` exports the transcript from the coordinator (every blob checked against the hash the
coordinator recorded for it), assembles and verifies it, applies the beacon step locally with
`ceremony-cli finalize`, verifies again, serializes that step with `ceremony-cli emit-contribution`,
and only then talks to the coordinator: it refuses unless the caller is the authority, the window
has closed or the queue is empty, the coordinator's contribution count equals the index of the
emitted step, and `icp-beacon.py verify` accepts the beacon string. It then calls
`begin_beacon_staging`, uploads both circuits in chunks under the ingress limit, and calls
`submit_beacon` with the exact beacon bytes; on any refusal it aborts the staging slot. After the
call it re-exports the finalized transcript from the coordinator, runs `verify-transcript
--selfcheck` on it, and requires the from-chain verifying-key hashes to equal the local ones. The
transcript it writes as `<workdir>/final.transcript.bin` is the one to publish.

The state before finalize was exported and verified on 2026-09-15 (25 contributions,
`TRANSCRIPT VALID`, 25 honest, `finalized (beacon) : false`), and the whole procedure was
rehearsed the same day on a local replica running the published module (see `BEACON.md`).

## 7. After finalize

The keys are not trustworthy because the coordinator accepted them. On-chain acceptance is structural
only — the proof-of-knowledge subgroup and pairing checks, and the full cross-point consistency
check, run off-chain and nowhere else.

```
verify-transcript sapling-phase1-p14.srs.bin <published-transcript.bin> --selfcheck
```

This must print `TRANSCRIPT VALID`, `KEYS WORK`, `finalized (beacon) : true`, and a non-zero honest
contribution count. The deployed ledger's verifying keys must equal the transfer and deposit vk
hashes it reports. Until that verifier accepts the full published transcript, the keys carry no
value-bearing assurance.

## 8. Note on `PHASE1-PIN.md`

`README.md` in this directory lists, as a remaining requirement, that `PHASE1-PIN.md` gain the
power-14 extraction record. No such file has ever existed in this repository's history. The Phase-1
pin for the live set is recorded in `PROVENANCE-p14.json` (upstream URL, response-file SHA-256,
extracted-SRS SHA-256, source and target power, attestation set) and restated in `README.md` §
"Provenance". That requirement is satisfied by those two files; there is no missing document.

Menese DeFi Team
