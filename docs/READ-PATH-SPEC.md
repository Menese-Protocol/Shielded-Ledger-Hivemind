# Read-path specification: cost model, view tags, and the detection stream

The client read path is how a wallet recovers its balance from the ledger's PUBLIC block log with
no recipient index — detection is Ω(N) by privacy design, so the engineering surface is the
constants (bytes and operations per note) and the range (which notes can possibly be yours), never
the asymptotic. This document states the wire cost (measured, not assumed), the envelope formats,
the detection-stream endpoint and its bound, and the boundaries at scale. Companion:
`docs/PIR-SPEC.md` (private matched-note retrieval); numbers here are the authoritative
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
     ~N ECDH at 100 M, parallelizable). This single case is the OMR justification;
     `detection_stream` and the OMR clue (block-format change) are independent and
     coexist. FMD is EXCLUDED by design on transparent-execution infrastructure.

## Boundaries at scale (stated openly)

1. **Detection is Ω(N).** Privacy forbids a recipient index, so someone scans every note. The
   detection stream makes the constant 48 B + 1 ECDH/note (12× under full blocks); it does not and
   cannot make detection sublinear without added machinery (OMR, probe-gated).
2. **Query calls are unmetered on the IC** (same caveat as PIR-SPEC §Known boundaries): a cheap
   caller can force the full `detection_stream`/`icrc3_get_blocks` scan work. Production must bound
   this (metered windows, dedicated replicas); for the valueless demo it is accepted and documented.
