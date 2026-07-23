# Read-path specification: cost model, view tags, and the detection stream

The client read path is how a wallet recovers its balance from the ledger's PUBLIC block log with
no recipient index — detection is Ω(N) by privacy design, so the engineering surface is the
constants (bytes and operations per note) and the range (which notes can possibly be yours), never
the asymptotic. This document states the wire cost (measured, not assumed), the envelope formats,
the detection-stream endpoint and its bound, and the boundaries at scale. Companion:
`docs/PIR-V2-SPEC.md` (private matched-note retrieval); numbers here are the authoritative
reference for `demo-frontend/src/wallet.js` (client) and `src/Main.mo` (ledger `detection_stream`).

## The problem it replaces (measured, at exact file:line)

- `readNotes` fetched the whole log in ONE `icrc3_get_blocks([{start:0, length:total}])` call
  (old `wallet.js:88-91`). The ledger caps a response at **512 blocks TOTAL across all ranges**
  (`src/Main.mo:1573` `MAX_BLOCKS_PER_CALL`, enforced at `:1583` `break ranges`), so past 512 notes
  the wallet silently scanned a truncated log — a live correctness bug in balance discovery AND, via
  `leavesInOrder`→`indexOf` (`wallet.js:167,219`), in spend-proof witness construction.
- The envelope carried NO view tag: `ephPk(32)||nonce(24)||box` (`wallet.js:27`); `scanNotes` ran a
  full X25519 `nacl.box.open` trial-decrypt on every record.
- Nothing persisted between sessions (no cursor, no birthday, no cache): every open re-downloaded
  and re-scanned from genesis.
- Spent-ness was probed with a per-owned-note `is_nullifier_spent` point query — leaking which and
  how many notes a session owns.

## A0 — bytes per note on the wire (measured on PocketIC)

`tests/ReadPathProbe.mo` + `soak/src/bin/probe_readpath_cost.rs` append realistic frontend-shaped
blocks through the REAL `NoteCodec`/`ICRC3` codec and measure the marginal candid-encoded size of an
`icrc3_get_blocks`-shaped response:

| shape | wire bytes / note | notes |
|---|---|---|
| shield block | **588 B** | 0 nullifiers; 32-B ephemeral_key; ~235-B envelope; commitment/anchor/root 32 B each; ICRC-3 map overhead |
| transfer output block | **679 B** | + 2 × 32-B nullifiers and their array framing |

This corrects the plan's "~500 B/note naive" estimate. Extrapolated full-log download:

| N | shield-only full log (588 B/note) | detection stream (48 B/note) |
|---|---|---|
| 1 M | ~588 MB | ~48 MB |
| 100 M | ~58.8 GB | ~4.8 GB |

## Envelope formats

Two wire layouts, both opaque to the chain (the ledger stores the envelope as bytes):

```
legacy : ephPk(32) || nonce(24) || box
tagged : ephPk(32) || tag(8)    || nonce(24) || box
```

`tag = H("picp-note-viewtag/v1" || shared)[0..8]`, where `shared = nacl.box.before(ephPk, encSk)` is
the X25519→HSalsa20 shared key and `H` is SHA-512 (`nacl.hash`) truncated to 8 bytes. The ECDH is
derived exactly ONCE and reused by the tag check and the box open (`nacl.box.open.after`). WRITING
the tagged layout is gated by the single flag `VIEW_TAG_ENABLED` (`config.js`); unset ⇒
byte-identical legacy envelopes (`nacl.box` = before+after). The READ path auto-detects both layouts
unconditionally: it tries the tagged interpretation, and Poly1305 authentication
(`nacl.box.open.after` → null on failure) is the arbiter — a wrong-format parse cannot authenticate
to wrong plaintext, so the try-tagged-then-legacy order is always correct.

## detection_stream endpoint (measured bound)

`detection_stream(start, count) : query -> blob` (`src/Main.mo`) returns densely packed 48-byte
entries `(note_position : 8B big-endian) || note_ciphertext[0..40]` — the envelope's ephemeral
X25519 key (32 B) plus its 8-byte view tag (tagged) or first 8 nonce bytes (legacy). Additive and
read-only; same 512-block total cap as `icrc3_get_blocks`.

| quantity | measured (PocketIC, ReadPathProbe) |
|---|---|
| wire bytes / note | **48.00 B** (target ≤ 48) |
| bandwidth win vs full shield block | **12.2×** |
| instructions / note (block decode + per-note SHA-256 checksum + 40-B slice) | **417,869** |
| allocation / note | 23,816 B |
| a 512-note call | 213,948,928 instr = **23.4× under** the 5×10⁹ query budget (≥4× headroom) |

"Slices without parsing" is a WIRE claim (40 payload bytes out vs a full ~588-B block); reaching
`note_ciphertext` still costs a `NoteCodec.decode` + the per-note checksum — measured, not assumed.

## Read-path design and cost model

| phase | what it does | cost per open |
|---|---|---|
| **P1 pagination + cursor** | `readNotes` issues N page-aligned SINGLE-range 512-block fetches (concurrent); total pinned once; a scan cursor turns "full rescan" into "new-notes-only" | fetch only [cursor, tip] |
| **P2 birthday** | scan [birthday, tip]; a note before the wallet existed cannot be its own; birthday-less restore = full history | no pre-birthday fetch |
| **P3 view tags + detection** | stream 48 B/note, one ECDH + tag compare per note, full-fetch only matched 512-aligned pages; below a format cutover, full-open (never miss) | detection: 48 B + 1 ECDH/note; retrieval: matched pages only |
| **P4 encrypted cache** | notes+cursor+birthday sealed (nacl.secretbox) under the vetKey session key, bound to canister-id+host+`note_root_after` anchor; throwaway accounts write nothing | re-open fetches only [cursor, tip] |

Spent-ness is computed LOCALLY from the log's `nullifiers` fields (the union of all blocks'
nullifiers equals the canister spent set — `Main.mo:526,1907-1914,2147-2154`), removing the
per-owned-note `is_nullifier_spent` deanonymization channel.

## The format cutover (a correction to the plan text)

The plan's "gated by length/format detection" is unsound: the envelope LENGTH cannot separate legacy
from tagged (the JSON payload carries a variable-length decimal `v`, so legacy = 226+len(v) and
tagged = 234+len(v) overlap), and the first 8 bytes after ephPk are indistinguishable (tag vs nonce).
The only zero-false-negative rule on a mixed log is a **format-activation position** (Zcash NU5
view-tag-at-activation-height): below the cutover full-open, at/above trust the tag. `VIEW_TAG_CUTOVER`
defaults to `null` ⇒ full-open every note (**never-miss safe default**). A concrete cutover is the
recorded log length at the official frontend's flip **plus a straggler margin** (an in-flight
old-format transfer can land just above the flip); a cutover set too LOW silently misses legacy notes
in match-free pages above it — hence the safe default is mandatory and the concrete value must come
from the deploy record, never a guess.

## What is claimed / not claimed (privacy)

- **Claimed:** the block-fetch transcript is page-aligned and never isolates an owned position — two
  wallets with different keys produce byte-identical fetch transcripts on the same ledger
  (keyless-observer, B-P5); zero nullifier point-queries; nothing plaintext at rest; a
  validly-sealed-but-stale cache (rewind/fork/wrong-ledger) is discarded, never a wrong balance.
- **Not claimed (documented residuals, closed by PIR / OMR):**
  1. **Page-set leak** — matched-note retrieval fetches whole 512-aligned pages (full-page
     camouflage), which hides the intra-page position but not WHICH pages a wallet fetches. PIR
     replaces the single `retrieveMatchedPage` seam with a private single-record fetch.
  2. **Birthday age** — a birthday scan's fetch start reveals the wallet is at least that old.
  3. **The one heavy residual case** — birthday-less full-history restore (~4.8 GB detection stream +
     ~N ECDH at 100 M). Detection here is Ω(N) by privacy design and stays Ω(N); what was open was
     whether that honest linear scan is *operationally* affordable. It now is — see
     "Birthday-less restore at scale" below (certified mirror distribution + a parallel client
     scanner). This is an OPERATIONAL closure of the linear scan, not sublinear detection: the
     sublinear leg (on-chain homomorphic detection) remains PARKED per the measured OMR go/no-go,
     and FMD is EXCLUDED by design on transparent-execution infrastructure.

## Boundaries at scale (stated openly)

1. **Detection is Ω(N).** Privacy forbids a recipient index, so someone scans every note. The
   detection stream makes the constant 48 B + 1 ECDH/note (12× under full blocks); it does not and
   cannot make detection sublinear without added machinery (OMR, probe-gated).
2. **Query calls are unmetered on the IC** (same caveat as PIR-V2-SPEC §V2.8 stated boundaries): a cheap
   caller can force the full `detection_stream`/`icrc3_get_blocks` scan work. Production must bound
   this (metered windows, dedicated replicas); for the valueless demo it is accepted and documented.

## Birthday-less restore at scale (residual #3, closed operationally)

A wallet with no birthday must scan the full detection stream from genesis. Detection stays Ω(N)
— privacy forbids a recipient index — so closure means making the honest linear scan cheap in
bytes, in compute, and in trust. Two pieces do that; neither changes consensus or ledger state.

**Certified mirror distribution of the stream.** The detection stream is public, immutable,
target-independent data, so any untrusted mirror or CDN can serve it — provided the client can
verify what it received. A per-append SHA-256 chain over the exact 48-B entries
(`c_{i+1} = SHA256(c_i ‖ pos_i ‖ ciphertext_i[0..40])`) publishes a boundary digest every 4,096
notes; those boundaries are the leaves of a Merkle tree whose root is folded into the ledger's
certified tree (the `detect_stream` anchor). A client verifies each 4,096-note segment
independently — two O(log) Merkle boundary proofs against the certified root, then a chain
recompute across the segment — and rejects any bit-flip, truncation, reorder, or splice **before**
that segment's entries touch the owned set. Serving is untrusted; the chain certifies. The anchor
is additive and default-off: with it disabled the ledger's certified state is byte-for-byte what
it was before the feature existed.

**Parallel client scanner.** The per-note work — one X25519 ECDH plus one view-tag compare (the
tag saves the trial decryption, not the ECDH) — parallelizes across cores. A streaming,
resumable, worker-pool scanner partitions the stream into segments, verifies-then-scans each, and
unions matched pages; it never holds more than one segment per worker in memory and checkpoints a
cursor that always lags the durably-recorded matches (crash-safe, no double-count, no gap). The
recovered owned-note set is byte-identical to a single-threaded reference scan — zero false
negatives across the complete 100-million-record acceptance corpus and all published test
variants is an absolute gate — and the compute kernel is isolated behind a pure
`(ephemeral_key, secret) → shared` boundary so a native or WebGPU implementation drops in without
changing the recognition logic. Before any mirror traffic, the client re-derives the certified
leaf `SHA256(root ‖ c_tip ‖ note_count)` from its (root, tip, count) triple and rejects a
mismatch — the three values MUST come from ONE certificate, so no cross-certificate mix (root
from one snapshot, count from another) can drive a scan. Inside a verified segment, entry
positions are additionally checked for exact continuity and 53-bit-safe parsing before use.

**Anchor persistence and maintenance (ledger side).** The anchor's state is deliberately tiny
and log-derived: the 32-B running chain, one 32-B leaf per complete 4,096-note segment
(24,415 leaves ≈ 0.78 MB at 10⁸ notes), the cached root, and two counters. The root is
maintained by an incremental Merkle frontier — O(log B) hashing per boundary, ≤ ⌈log₂ B⌉
cached nodes (11 at 10⁸-note scale), never a full-tree recompute on the append path. The
frontier itself is transient and rebuilt from the persisted boundary list at every upgrade
(O(B) hashing over the boundary COUNT only — a sub-percent slice of the committed
2-billion-instruction postupgrade bound, measured in the soak's upgrade drill), so the stable
memory layout is unchanged by the feature. The background chunked audit re-derives the entire
anchor from the note log on every pass — every boundary leaf, the chain tip, both counters,
and the root — and any mismatch fail-closes the ledger with a `detect-chain:*` code; because
the anchor is a pure function of the note log, an admin `detect_chain_rebuild` reconstructs it
from scratch in bounded chunks and swaps it in atomically, which a re-run audit then re-proves.

**Measured (this reference box, 24 cores).** Verified wire cost is 48 B/note (4.8 GB at 100 M),
served from a mirror at ordinary CDN speeds and verified once; page verification adds ~0.2% to the
scan. The scanner scales near-linearly — 6.9× on 8 workers — and recovers a full 100-million-note
birthday-less history, verified end-to-end, in **about 6.5 minutes** of 8-worker compute, versus the
hundreds of days an on-chain homomorphic scan would take. Peak memory stays under 1 GB (the 4.8 GB
stream is never materialized), and zero owned notes are missed. This is an operational closure of
the linear scan; it does not make detection sublinear, and the sublinear route stays parked pending
a construction whose cost is operationally sane on transparent-execution infrastructure.
