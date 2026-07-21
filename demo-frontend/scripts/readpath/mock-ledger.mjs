// Node test-rig ledger for the read-path battery (Menese DeFi Team).
//
// A faithful in-memory mirror of the shielded ledger's READ surface, with a request log so the
// battery can assert exactly what a wallet fetched. Transport is mocked ONLY at the actor boundary;
// all envelope crypto in the battery is REAL nacl.box. Every method that the battery touches is
// modelled byte-for-byte against src/Main.mo so the harness fails on the real bug (it reproduces the live
// 512-block truncation, not a softened version of it).
//
// Ground-truth references (src/Main.mo):
//   * icrc3_get_blocks — MAX_BLOCKS_PER_CALL = 512, cap is TOTAL across all ranges in one call,
//     `break ranges` exits the whole loop (Main.mo:1570-1591).
//   * status().log_length = noteCount() (Main.mo:1400); note_root exposed for cache anchoring.
//   * is_nullifier_spent — membership in the spent set (Main.mo:1555); the spent set equals the
//     union of every appended block's `nullifiers` field (addNullifier rides with appendBlock).
//   * detection_stream(start,count) — additive query added by this workstream: packed
//     (position 8B BE || note_ciphertext[0..40]) per note, same 512 total cap.

const MAX_BLOCKS_PER_CALL = 512;

// A stored note record. `ciphertext` is a Uint8Array (the real envelope bytes); `nullifiers` is an
// array of Uint8Array (the spends revealed by the tx that created this block).
function toBlobField(u8) {
  // readNotes does `new Uint8Array(map.X.Blob)`, so Blob must be array-like of byte values.
  return { Blob: Array.from(u8) };
}

function blockValue(rec) {
  // Only the fields readNotes reads (wallet.js:93-100), in a candid-Map shape:
  // block.Map is [ [key, valueVariant], ... ].
  return {
    Map: [
      ["btype", { Text: "zknote1" }],
      ["note_position", { Nat: BigInt(rec.position) }],
      ["commitment", toBlobField(rec.commitment)],
      ["origin", { Text: rec.origin }],
      ["ephemeral_key", toBlobField(rec.ephemeralKey)],
      ["note_ciphertext", toBlobField(rec.ciphertext)],
      ["nullifiers", { Array: rec.nullifiers.map((n) => toBlobField(n)) }],
      ["note_root_after", toBlobField(rec.noteRootAfter)],
    ],
  };
}

// Incremental note_root chain: root_after(i) = SHA-256(root_after(i-1) || commitment(i)). Any
// rewind/fork/reorder below a cursor changes the root there, so a wallet can bind a cache to the
// per-block note_root_after (D8).
async function chainRoot(prev, commitment) {
  const buf = new Uint8Array(64);
  buf.set(prev, 0);
  buf.set(commitment, 32);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", buf));
}

const eqBytes = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

export class MockLedger {
  // canisterId/host let the battery test D8 cache binding across ledger identity.
  constructor({ canisterId = "nf7le-bqaaa-aaaau-ag26q-cai", host = "https://icp-api.io" } = {}) {
    this.records = [];
    this.canisterId = canisterId;
    this.host = host;
    this.requestLog = [];
    this._noteRoot = new Uint8Array(32);
    // The actor surface the wallet talks to (actors.ledger.*).
    this.ledger = {
      status: async () => this._status(),
      icrc3_get_blocks: async (args) => this._getBlocks(args),
      is_nullifier_spent: async (nf) => this._isSpent(nf),
      detection_stream: async (start, count) => this._detectionStream(start, count),
    };
  }

  // ---- corpus mutation (test setup only; not part of the wallet-facing surface) ----
  async append(rec) {
    const prev = this.records.length ? this.records[this.records.length - 1].noteRootAfter : new Uint8Array(32);
    const noteRootAfter = await chainRoot(prev, rec.commitment);
    this.records.push({
      position: this.records.length,
      commitment: rec.commitment,
      origin: rec.origin,
      ephemeralKey: rec.ephemeralKey ?? new Uint8Array(32),
      ciphertext: rec.ciphertext,
      nullifiers: rec.nullifiers ?? [],
      noteRootAfter,
    });
    this._noteRoot = noteRootAfter;
  }

  // Rewind to `length` notes (models a canister reinstall / rollback for D8).
  async rewind(length) {
    this.records = this.records.slice(0, length);
    this._noteRoot = this.records.length ? this.records[this.records.length - 1].noteRootAfter : new Uint8Array(32);
  }

  resetLog() {
    this.requestLog = [];
  }

  // ---- wallet-facing read surface (byte-faithful to Main.mo) ----
  _status() {
    this.requestLog.push({ method: "status" });
    return {
      log_length: BigInt(this.records.length),
      note_count: BigInt(this.records.length),
      note_root: Array.from(this._noteRoot),
    };
  }

  _getBlocks(args) {
    // Record the exact ranges requested (for page-accounting + privacy assertions), plus the log
    // length AT REQUEST TIME so the isolation oracle can distinguish a legitimate last partial
    // page from a truncated-length fetch even after the log grows.
    const ranges = args.map((r) => ({ start: Number(r.start), length: Number(r.length) }));
    this.requestLog.push({ method: "icrc3_get_blocks", ranges, n: this.records.length });
    const blocks = [];
    let emitted = 0;
    const n = this.records.length;
    outer: for (const r of ranges) {
      if (r.start < n) {
        const end = Math.min(r.start + r.length, n);
        for (let i = r.start; i < end; i++) {
          if (emitted >= MAX_BLOCKS_PER_CALL) break outer; // TOTAL cap across ranges (Main.mo:1583)
          blocks.push({ id: BigInt(i), block: blockValue(this.records[i]) });
          emitted++;
        }
      }
    }
    return { blocks, log_length: BigInt(n), archived_blocks: [] };
  }

  _isSpent(nf) {
    const needle = nf instanceof Uint8Array ? nf : new Uint8Array(nf);
    this.requestLog.push({ method: "is_nullifier_spent", nf: Array.from(needle) });
    for (const rec of this.records) {
      for (const stored of rec.nullifiers) {
        if (eqBytes(stored, needle)) return true;
      }
    }
    return false;
  }

  _detectionStream(start, count) {
    const s = Number(start);
    const c = Number(count);
    this.requestLog.push({ method: "detection_stream", start: s, count: c });
    const n = this.records.length;
    const end = Math.min(s + Math.min(c, MAX_BLOCKS_PER_CALL), n);
    const out = [];
    for (let i = s; i < end; i++) {
      // position 8B big-endian — division/modulo (NOT `>>`, whose 32-bit semantics corrupt the high
      // bytes); mirrors Main.mo detection_stream `(i / (256 ** k)) % 256`.
      for (let k = 7; k >= 0; k--) out.push(Math.floor(i / 256 ** k) % 256);
      const ct = this.records[i].ciphertext;
      for (let j = 0; j < 40; j++) out.push(ct[j] ?? 0); // ephPk(32)||tag-or-nonce(8)
    }
    return new Uint8Array(out);
  }

  // ---- helpers for the battery's oracles ----
  get noteRoot() {
    return this._noteRoot;
  }

  // Count the block fetches in the request log that could isolate a position — the B-P5 privacy
  // assertion. A fetch is non-isolating ONLY if it is a single 512-aligned range that is either a
  // FULL page (length == 512) or the true last partial page at request time (start + length ==
  // log_length, which reveals only the public tip). A truncated-length page fetch like
  // {start: 512, length: 128} pinpoints position start+length to the byte and is flagged even
  // though it is page-aligned.
  positionIsolatingFetches() {
    return this.requestLog.filter((e) => {
      if (e.method !== "icrc3_get_blocks") return false;
      if (e.ranges.length !== 1) return true;
      const r = e.ranges[0];
      if (r.start % MAX_BLOCKS_PER_CALL !== 0 || r.length > MAX_BLOCKS_PER_CALL) return true;
      return r.length !== MAX_BLOCKS_PER_CALL && r.start + r.length !== e.n;
    });
  }

  // Any block fetch whose single range covers positions strictly below `birthday` (B-P2).
  fetchesBelow(birthday) {
    return this.requestLog.filter(
      (e) => e.method === "icrc3_get_blocks" && e.ranges.some((r) => r.start < birthday)
    );
  }
}

export { MAX_BLOCKS_PER_CALL };
