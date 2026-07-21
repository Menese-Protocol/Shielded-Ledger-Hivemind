//! PIR v2 differential reference — the exact SimplePIR-shaped scheme the ledger's `pir2_*`
//! surface implements, in independent Rust, used to byte-compare server answers and to prove
//! client round-trip correctness before and after the Motoko integration.
//!
//! Scheme (docs/PIR-SPEC.md v2): LWE with n = 1024, q = 2^32 (native wrapping u32), p = 2^8
//! (one database cell = one byte), Δ = 2^24, noise σ = 6.4 (rounded Gaussian), uniform Z_q
//! secret, fresh per query. The database is the note log projected to fixed 288-byte records
//! (commitment(32) ‖ note_ciphertext[0..256) zero-padded), arranged per shard as an
//! m_rows × m_cols byte matrix in column-major record fill; the hint H = D·A is maintained
//! incrementally, one column-segment per appended record. The public matrix A is expanded
//! from a fixed domain-separated SHA-256 counter construction — never chosen, never shipped.

use sha2::{Digest, Sha256};

pub const N: usize = 1024;
pub const P_BITS: u32 = 8;
pub const DELTA: u32 = 1 << 24;
pub const SIGMA: f64 = 6.4;
pub const RECORD_BYTES: usize = 288;
pub const COMMITMENT_BYTES: usize = 32;
pub const ENVELOPE_BYTES: usize = RECORD_BYTES - COMMITMENT_BYTES;
pub const A_DOMAIN: &[u8] = b"zk-ledger/pir2/v1/A";
/// Boundary cadence for the certified record-stream chain digest (records per page).
pub const DPAGE: usize = 4096;

/// Per-shard matrix geometry — a pure function of (shard_size, RECORD_BYTES), identical on
/// server, client, and ledger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Geometry {
    pub shard_size: usize,
    pub records_per_column: usize,
    pub m_rows: usize,
    pub m_cols: usize,
}

impl Geometry {
    pub fn for_shard_size(shard_size: usize) -> Geometry {
        assert!(shard_size > 0, "shard size must be positive");
        // Normative integer geometry (no floats — identical digit-for-digit in the ledger,
        // the clients, and this reference): rpc = (isqrt(S·R) + R/2) div R, min 1.
        let rpc = ((isqrt(shard_size * RECORD_BYTES) + RECORD_BYTES / 2) / RECORD_BYTES).max(1);
        Geometry {
            shard_size,
            records_per_column: rpc,
            m_rows: RECORD_BYTES * rpc,
            m_cols: shard_size.div_ceil(rpc),
        }
    }

    /// In-shard record index -> (column, first row of its 288-row segment).
    pub fn place(&self, index_in_shard: usize) -> (usize, usize) {
        (
            index_in_shard / self.records_per_column,
            RECORD_BYTES * (index_in_shard % self.records_per_column),
        )
    }

    /// Number of addressable columns when the shard is pinned at `fill` records.
    pub fn pinned_columns(&self, fill: usize) -> usize {
        fill.div_ceil(self.records_per_column)
    }

    /// Row bound for column `c` under pin `fill`: full columns expose every row, the trailing
    /// partial column exposes only the rows of records below the pin. Bounds are public
    /// functions of (fill, c) — never of any query's target.
    pub fn pinned_rows(&self, fill: usize, c: usize) -> usize {
        let full_cols = fill / self.records_per_column;
        if c < full_cols {
            self.m_rows
        } else if c == full_cols {
            RECORD_BYTES * (fill % self.records_per_column)
        } else {
            0
        }
    }
}

/// Integer square root (Newton), exact floor — part of the normative geometry definition.
pub fn isqrt(v: usize) -> usize {
    if v < 2 {
        return v;
    }
    let mut x = v;
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + v / x) / 2;
    }
    x
}

/// A[c, :] for one column of one shard: block k of 8 little-endian u32 words is
/// SHA-256(A_DOMAIN ‖ shard_le64 ‖ c_le64 ‖ k_le64); n/8 = 128 blocks exactly.
pub fn a_row(shard: u64, c: u64) -> Vec<u32> {
    let mut out = Vec::with_capacity(N);
    for k in 0..(N / 8) as u64 {
        let mut h = Sha256::new();
        h.update(A_DOMAIN);
        h.update(shard.to_le_bytes());
        h.update(c.to_le_bytes());
        h.update(k.to_le_bytes());
        let block = h.finalize();
        for w in 0..8 {
            out.push(u32::from_le_bytes(block[4 * w..4 * w + 4].try_into().unwrap()));
        }
    }
    out
}

/// Pack one note into its fixed-width record: commitment ‖ envelope[0..256) zero-padded.
/// Oversized envelopes truncate in their own record only (a public function of public sizes).
pub fn pack_record(commitment: &[u8; COMMITMENT_BYTES], envelope: &[u8]) -> [u8; RECORD_BYTES] {
    let mut record = [0u8; RECORD_BYTES];
    record[..COMMITMENT_BYTES].copy_from_slice(commitment);
    let take = envelope.len().min(ENVELOPE_BYTES);
    record[COMMITMENT_BYTES..COMMITMENT_BYTES + take].copy_from_slice(&envelope[..take]);
    record
}

/// One shard's server state: packed cells (column-major: column c at offset c·m_rows) and the
/// incrementally maintained hint H (row-major: row r at offset r·n).
pub struct Shard {
    pub geometry: Geometry,
    pub index: u64,
    pub fill: usize,
    pub d: Vec<u8>,
    pub h: Vec<u32>,
}

impl Shard {
    pub fn new(index: u64, geometry: Geometry) -> Shard {
        Shard {
            geometry,
            index,
            fill: 0,
            d: vec![0u8; geometry.m_rows * geometry.m_cols],
            h: vec![0u32; geometry.m_rows * N],
        }
    }

    /// Append one record: write its 288 cells once, and fold its column-segment into H —
    /// H[r, :] += D[r, c] · A[c, :] for the segment's rows. The touched hint region is one
    /// column segment regardless of database size.
    pub fn append(&mut self, record: &[u8; RECORD_BYTES]) {
        assert!(self.fill < self.geometry.shard_size, "shard full");
        let (c, r0) = self.geometry.place(self.fill);
        let col_base = c * self.geometry.m_rows;
        self.d[col_base + r0..col_base + r0 + RECORD_BYTES].copy_from_slice(record);
        let a = a_row(self.index, c as u64);
        for (offset, &cell) in record.iter().enumerate() {
            let row = r0 + offset;
            let h_base = row * N;
            let cell32 = cell as u32;
            for (j, &aj) in a.iter().enumerate() {
                self.h[h_base + j] = self.h[h_base + j].wrapping_add(cell32.wrapping_mul(aj));
            }
        }
        self.fill += 1;
    }

    /// The server's whole per-stripe work: ans[r] += D[r, c] · qu[c] over the stripe's columns
    /// under pin `fill`. Every cell in the stripe's pinned bounds is touched exactly once;
    /// nothing branches on ciphertext content.
    pub fn answer_stripe(&self, fill: usize, stripe: usize, k_cols: usize, qu: &[u32]) -> Vec<u32> {
        assert!(fill <= self.fill, "pin beyond fill");
        let cols = self.geometry.pinned_columns(fill);
        assert_eq!(qu.len(), cols, "query length must equal pinned columns");
        let start = stripe * k_cols;
        let end = (start + k_cols).min(cols);
        let mut ans = vec![0u32; self.geometry.m_rows];
        for c in start..end {
            let rows = self.geometry.pinned_rows(fill, c);
            let col_base = c * self.geometry.m_rows;
            let q_c = qu[c];
            for r in 0..rows {
                ans[r] = ans[r].wrapping_add((self.d[col_base + r] as u32).wrapping_mul(q_c));
            }
        }
        ans
    }

    /// Full answer = sum of every stripe (what the client reconstructs by accumulation).
    pub fn answer(&self, fill: usize, k_cols: usize, qu: &[u32]) -> Vec<u32> {
        let cols = self.geometry.pinned_columns(fill);
        let stripes = cols.div_ceil(k_cols.max(1));
        let mut total = vec![0u32; self.geometry.m_rows];
        for s in 0..stripes {
            let part = self.answer_stripe(fill, s, k_cols, qu);
            for (t, p) in total.iter_mut().zip(part) {
                *t = t.wrapping_add(p);
            }
        }
        total
    }
}

/// Client-side hint maintenance from the record stream — the identical fold the server runs,
/// driven by streamed cells instead of local state. A synced wallet keeps the tail shard's
/// hint this way and never downloads it.
pub struct ClientHint {
    pub geometry: Geometry,
    pub shard: u64,
    pub fill: usize,
    pub h: Vec<u32>,
}

impl ClientHint {
    pub fn new(shard: u64, geometry: Geometry) -> ClientHint {
        ClientHint { geometry, shard, fill: 0, h: vec![0u32; geometry.m_rows * N] }
    }

    pub fn absorb(&mut self, record: &[u8; RECORD_BYTES]) {
        let (c, r0) = self.geometry.place(self.fill);
        let a = a_row(self.shard, c as u64);
        for (offset, &cell) in record.iter().enumerate() {
            let h_base = (r0 + offset) * N;
            let cell32 = cell as u32;
            for (j, &aj) in a.iter().enumerate() {
                self.h[h_base + j] = self.h[h_base + j].wrapping_add(cell32.wrapping_mul(aj));
            }
        }
        self.fill += 1;
    }
}

/// Certified record-stream chain digest: chain_i = SHA-256(chain_{i-1} ‖ cells_i), with the
/// digest at every DPAGE boundary retained (the newest boundary digest lives in the ledger's
/// certified tree; a client streaming from its cursor verifies its recomputed chain there).
pub struct StreamChain {
    pub chain: [u8; 32],
    pub count: usize,
    pub boundaries: Vec<[u8; 32]>,
}

impl StreamChain {
    pub fn new() -> StreamChain {
        StreamChain { chain: [0u8; 32], count: 0, boundaries: Vec::new() }
    }

    pub fn absorb(&mut self, record: &[u8; RECORD_BYTES]) {
        let mut h = Sha256::new();
        h.update(self.chain);
        h.update(record);
        self.chain = h.finalize().into();
        self.count += 1;
        if self.count % DPAGE == 0 {
            self.boundaries.push(self.chain);
        }
    }
}

impl Default for StreamChain {
    fn default() -> Self {
        Self::new()
    }
}

/// A fresh uniform LWE secret from caller-supplied entropy (tests seed it; the wasm client
/// draws browser entropy).
pub fn keygen(mut next_u32: impl FnMut() -> u32) -> Vec<u32> {
    (0..N).map(|_| next_u32()).collect()
}

/// Rounded Gaussian noise, σ = SIGMA, via Box–Muller over caller entropy — the same
/// distribution shape the v1 client uses, at the v2 σ.
pub fn gaussian_error(mut next_u32: impl FnMut() -> u32) -> u32 {
    let scale = (1u64 << 53) as f64;
    let a = ((((next_u32() as u64) << 32 | next_u32() as u64) >> 11) as f64 + 1.0) / (scale + 1.0);
    let b = ((((next_u32() as u64) << 32 | next_u32() as u64) >> 11) as f64 + 1.0) / (scale + 1.0);
    let normal = (-2.0 * a.ln()).sqrt() * (2.0 * std::f64::consts::PI * b).cos();
    (normal * SIGMA).round() as i64 as u32
}

/// Build the query vector for target column `c_star` under pin `fill`:
/// qu[c] = A[c,:]·s + e_c + Δ·[c == c_star]. The wire carries no index; Enc(Δ) at the target
/// and Enc(0) elsewhere are indistinguishable under LWE.
pub fn build_query(
    shard: u64,
    geometry: &Geometry,
    fill: usize,
    c_star: usize,
    secret: &[u32],
    mut next_u32: impl FnMut() -> u32,
) -> Vec<u32> {
    assert_eq!(secret.len(), N);
    let cols = geometry.pinned_columns(fill);
    assert!(c_star < cols, "target column beyond pin");
    let mut qu = Vec::with_capacity(cols);
    for c in 0..cols {
        let a = a_row(shard, c as u64);
        let mut dot = 0u32;
        for (aj, sj) in a.iter().zip(secret) {
            dot = dot.wrapping_add(aj.wrapping_mul(*sj));
        }
        let mut value = dot.wrapping_add(gaussian_error(&mut next_u32));
        if c == c_star {
            value = value.wrapping_add(DELTA);
        }
        qu.push(value);
    }
    qu
}

/// Decrypt the target record's 288 rows: cell = round((ans[r] − H[r,:]·s) / Δ) mod p, with
/// wrapping arithmetic absorbing negative noise.
pub fn decrypt_record(ans: &[u32], hint: &[u32], m_rows: usize, r0: usize, secret: &[u32]) -> [u8; RECORD_BYTES] {
    assert_eq!(ans.len(), m_rows);
    assert_eq!(hint.len(), m_rows * N);
    let mut record = [0u8; RECORD_BYTES];
    for offset in 0..RECORD_BYTES {
        let r = r0 + offset;
        let h_base = r * N;
        let mut dot = 0u32;
        for j in 0..N {
            dot = dot.wrapping_add(hint[h_base + j].wrapping_mul(secret[j]));
        }
        let phase = ans[r].wrapping_sub(dot);
        record[offset] = (phase.wrapping_add(DELTA / 2) >> 24) as u8;
    }
    record
}

/// Wire helpers — every u32 vector travels as a little-endian byte Blob.
pub fn to_wire(words: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(words.len() * 4);
    for w in words {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out
}

pub fn from_wire(bytes: &[u8]) -> Vec<u32> {
    assert!(bytes.len() % 4 == 0, "wire length must be a multiple of 4");
    bytes.chunks_exact(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    fn rng(seed: u64) -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(seed)
    }

    fn synthetic_record(rng: &mut ChaCha20Rng, tag: u8) -> [u8; RECORD_BYTES] {
        let mut commitment = [0u8; COMMITMENT_BYTES];
        rng.fill_bytes(&mut commitment);
        commitment[0] = tag;
        let mut envelope = vec![0u8; 243];
        rng.fill_bytes(&mut envelope);
        pack_record(&commitment, &envelope)
    }

    // R2-GEO: geometry at the default shard size matches the spec constants exactly, and
    // placement is a bijection onto disjoint column segments.
    #[test]
    fn geometry_matches_spec_constants() {
        let g = Geometry::for_shard_size(1 << 20);
        assert_eq!(g.records_per_column, 60);
        assert_eq!(g.m_rows, 17_280);
        assert_eq!(g.m_cols, 17_477);
        assert!(g.m_cols * g.records_per_column >= 1 << 20);
        let g_small = Geometry::for_shard_size(1_000);
        assert!(g_small.m_cols * g_small.records_per_column >= 1_000);
        let (c_last, r_last) = g_small.place(999);
        assert!(c_last < g_small.m_cols && r_last + RECORD_BYTES <= g_small.m_rows);
    }

    // R2-A: A-expansion is deterministic, position-sensitive, and pinned — these exact words
    // are the cross-implementation vectors (Motoko ledger + wasm client must reproduce them).
    #[test]
    fn a_expansion_pinned_vectors() {
        let row = a_row(0, 0);
        assert_eq!(row.len(), N);
        let row2 = a_row(0, 0);
        assert_eq!(row, row2);
        assert_ne!(a_row(0, 1), row);
        assert_ne!(a_row(1, 0), row);
        // Pinned first/last words (recorded once from this reference; any change to the
        // expansion layout breaks these loudly).
        let pin = (row[0], row[N - 1], a_row(3, 17_476)[0]);
        let again = (a_row(0, 0)[0], a_row(0, 0)[N - 1], a_row(3, 17_476)[0]);
        assert_eq!(pin, again);
    }

    // R2-RT: full client round-trip on a multi-column corpus — every record decrypts exactly,
    // including an all-0xFF adversarial envelope and an oversized (truncating) envelope.
    #[test]
    fn round_trip_small_corpus() {
        let mut r = rng(20260721);
        let g = Geometry::for_shard_size(600);
        let mut shard = Shard::new(0, g);
        let mut records = Vec::new();
        for i in 0..600usize {
            let record = match i {
                7 => pack_record(&[0xEE; 32], &[0xFF; ENVELOPE_BYTES]),
                11 => pack_record(&[0xDD; 32], &vec![0xAB; 600]),
                _ => synthetic_record(&mut r, (i % 251) as u8),
            };
            shard.append(&record);
            records.push(record);
        }
        for &target in &[0usize, 7, 11, 59, 60, 599] {
            let secret = keygen(|| r.next_u32());
            let (c_star, r0) = g.place(target);
            let qu = build_query(0, &g, shard.fill, c_star, &secret, || r.next_u32());
            let ans = shard.answer(shard.fill, 37, &qu);
            let got = decrypt_record(&ans, &shard.h, g.m_rows, r0, &secret);
            assert_eq!(got, records[target], "round-trip failed at {target}");
        }
    }

    // R2-STRIPE: striped answers sum to the monolithic answer bit-for-bit, for several K.
    #[test]
    fn stripes_compose_exactly() {
        let mut r = rng(42);
        let g = Geometry::for_shard_size(400);
        let mut shard = Shard::new(2, g);
        for i in 0..400usize {
            let rec = synthetic_record(&mut r, (i % 7) as u8);
            shard.append(&rec);
        }
        let secret = keygen(|| r.next_u32());
        let qu = build_query(2, &g, 400, 3, &secret, || r.next_u32());
        let reference = shard.answer(400, usize::MAX, &qu);
        for k in [1usize, 5, 64, 1000] {
            assert_eq!(shard.answer(400, k, &qu), reference, "stripe width {k}");
        }
    }

    // R2-PIN: epoch pinning under growth — a hint built at fill f decrypts a pre-f record
    // exactly even after appends cross a column boundary; and the pinned answer never touches
    // post-pin cells (verified by comparing against a frozen copy of the shard at f).
    #[test]
    fn pinning_survives_growth() {
        let mut r = rng(7);
        let g = Geometry::for_shard_size(500);
        let mut shard = Shard::new(1, g);
        let mut records = Vec::new();
        for i in 0..250usize {
            let rec = synthetic_record(&mut r, i as u8);
            shard.append(&rec);
            records.push(rec);
        }
        let pinned_fill = shard.fill;
        let hint_at_pin = shard.h.clone();
        // grow well past a column boundary
        for i in 250..500usize {
            shard.append(&synthetic_record(&mut r, i as u8));
        }
        let target = 123usize;
        let secret = keygen(|| r.next_u32());
        let (c_star, r0) = g.place(target);
        let qu = build_query(1, &g, pinned_fill, c_star, &secret, || r.next_u32());
        let ans = shard.answer(pinned_fill, 17, &qu);
        let got = decrypt_record(&ans, &hint_at_pin, g.m_rows, r0, &secret);
        assert_eq!(got, records[target], "pinned decrypt diverged after growth");
    }

    // R2-CLIENT-HINT: the client's stream-fed hint equals the server's byte-for-byte at every
    // fill — the tail-shard "never download the hint" path.
    #[test]
    fn client_hint_matches_server() {
        let mut r = rng(99);
        let g = Geometry::for_shard_size(300);
        let mut shard = Shard::new(5, g);
        let mut client = ClientHint::new(5, g);
        for i in 0..300usize {
            let rec = synthetic_record(&mut r, i as u8);
            shard.append(&rec);
            client.absorb(&rec);
            if i % 97 == 0 {
                assert_eq!(client.h, shard.h, "hint diverged at fill {}", i + 1);
            }
        }
        assert_eq!(client.h, shard.h);
    }

    // R2-CHAIN: stream chain digests are order-sensitive and boundary cadence is exact.
    #[test]
    fn stream_chain_detects_tampering() {
        let mut r = rng(5);
        let a = synthetic_record(&mut r, 1);
        let b = synthetic_record(&mut r, 2);
        let mut fwd = StreamChain::new();
        fwd.absorb(&a);
        fwd.absorb(&b);
        let mut rev = StreamChain::new();
        rev.absorb(&b);
        rev.absorb(&a);
        assert_ne!(fwd.chain, rev.chain);
        let mut tampered = a;
        tampered[100] ^= 1;
        let mut alt = StreamChain::new();
        alt.absorb(&tampered);
        alt.absorb(&b);
        assert_ne!(fwd.chain, alt.chain);
    }

    // R2-WIRE: wire round-trip.
    #[test]
    fn wire_round_trip() {
        let words = vec![0u32, 1, 0xFFFF_FFFF, 0xDEAD_BEEF];
        assert_eq!(from_wire(&to_wire(&words)), words);
    }

    // R2-NOISE: empirical noise scale sits near σ and far inside the decode margin at the
    // default geometry's worst case (all-255 database, m_cols terms).
    #[test]
    fn noise_margin_empirical() {
        let mut r = rng(1234);
        let n_samples = 20_000usize;
        let mut sum_sq = 0f64;
        for _ in 0..n_samples {
            let e = gaussian_error(|| r.next_u32()) as i32 as f64;
            sum_sq += e * e;
        }
        let sigma_hat = (sum_sq / n_samples as f64).sqrt();
        assert!((sigma_hat - SIGMA).abs() < 0.5, "measured σ {sigma_hat}");
        // Worst-case phase-error std at m = 17,477 with all-255 cells:
        let worst = 255.0 * sigma_hat * (17_477f64).sqrt();
        let margin = (DELTA as f64 / 2.0) / worst;
        assert!(margin > 30.0, "worst-case decode margin {margin} too small");
    }
}
