//! Deterministic cross-implementation battery core.
//!
//! THE SHARED STREAM SPEC (implemented independently in Rust here, in Motoko in
//! `fortress/motoko/ArithDiff.mo`, and in Python in the §4 reference model; digest
//! agreement is only meaningful because each side implements this spec from this text,
//! not from each other's code):
//!
//! - Per-class PRNG: splitmix64. The initial state is the first 8 bytes (big-endian u64)
//!   of SHA-256(ASCII(class_tag) || be64(seed)).
//! - splitmix64 step: state +%= 0x9E3779B97F4A7C15; z = state;
//!   z = (z ^ (z >> 30)) *% 0xBF58476D1CE4E5B9; z = (z ^ (z >> 27)) *% 0x94D049BB133111EB;
//!   output z ^ (z >> 31). (All 64-bit wrapping.)
//! - A raw 512-bit draw is 8 successive words w0..w7, w0 most significant:
//!   n = Σ w_j · 2^(64·(7−j)).
//! - A field-stream draw for modulus m is `raw mod m` — EXCEPT that callers that test
//!   unreduced-input tolerance keep the raw value (the Motoko L1/L2 layers accept any Nat).
//!   Class definitions below state which form they use.
//! - Per case i (0-based): operands are drawn in order (a, then b when the op is binary),
//!   then edge injection OVERRIDES drawn values (stream position is not affected):
//!   if i % 17 == 0 then a := EDGES[(i/17) % |EDGES|];
//!   if i % 19 == 0 (binary ops only) then b := EDGES[(i/19) % |EDGES|].
//!   EDGES(Fp) = [0, 1, 2, P−1, P, P+1, 2P−1]; EDGES(Fr) analogous with R.
//! - Transcript fold (the differential detector, not a security boundary): a polynomial
//!   hash over the class's result integers, in case order:
//!   acc := 0; per result x: acc := (acc · B + x) mod M
//!   with M = 2^255 − 19 and B = 2^128 + 51. Encodings of non-integer results are
//!   defined per class; `invOpt = null` folds the sentinel INV_NONE = 7777777777777777777.
//! - Output line per class: `CLASS <tag> N=<n> DIGEST=<lowercase hex of acc>` and a final
//!   `SEED <seed>` line. The comparing harness diffs the full sorted line sets.

use num_bigint::BigUint;
use sha2::{Digest, Sha256};

pub mod curvepair;
pub mod tower;

pub struct SplitMix64 {
    pub state: u64,
}

impl SplitMix64 {
    pub fn for_class(tag: &str, seed: u64) -> Self {
        let mut h = Sha256::new();
        h.update(tag.as_bytes());
        h.update(seed.to_be_bytes());
        let d = h.finalize();
        SplitMix64 {
            state: u64::from_be_bytes(d[0..8].try_into().unwrap()),
        }
    }

    pub fn next(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }

    /// 512-bit raw draw, w0 most significant.
    pub fn raw512(&mut self) -> BigUint {
        let mut n = BigUint::from(0u8);
        for _ in 0..8 {
            n = (n << 64) + BigUint::from(self.next());
        }
        n
    }
}

pub const INV_NONE: u64 = 7777777777777777777;

pub struct Fold {
    acc: BigUint,
    m: BigUint,
    b: BigUint,
}

impl Default for Fold {
    fn default() -> Self {
        Self::new()
    }
}

impl Fold {
    pub fn new() -> Self {
        let m = (BigUint::from(1u8) << 255) - BigUint::from(19u8);
        let b = (BigUint::from(1u8) << 128) + BigUint::from(51u8);
        Fold {
            acc: BigUint::from(0u8),
            m,
            b,
        }
    }

    pub fn put(&mut self, x: &BigUint) {
        self.acc = (&self.acc * &self.b + x) % &self.m;
    }

    pub fn put_u64(&mut self, x: u64) {
        self.put(&BigUint::from(x));
    }

    pub fn hex(&self) -> String {
        format!("{:x}", self.acc)
    }
}

/// Edge list for a modulus m: [0, 1, 2, m−1, m, m+1, 2m−1].
pub fn edges(m: &BigUint) -> Vec<BigUint> {
    vec![
        BigUint::from(0u8),
        BigUint::from(1u8),
        BigUint::from(2u8),
        m - 1u8,
        m.clone(),
        m + 1u8,
        m * 2u8 - 1u8,
    ]
}

/// TOWER DRAW SPEC (additional; implemented symmetrically in fortress/motoko/TowerDiff.mo):
/// - A tower element draw of k coefficients (k = 2, 6, 12; tower-lexicographic order:
///   Fp6 = (c0.c0, c0.c1, c1.c0, c1.c1, c2.c0, c2.c1); Fp12 = (c0 : Fp6, c1 : Fp6) flattened)
///   draws each coefficient as `raw512() mod P` (canonical).
/// - Each class keeps an element counter e (0-based, incremented per element drawn; a binary
///   case draws a at e, then b at e+1).
/// - Edge injection: if e % 17 == 0, coefficient j is OVERRIDDEN with
///   EDGE_CANON[(e/17 + j) % 4], EDGE_CANON = [0, 1, 2, P−1]. The stream advances regardless.
/// - Fold: one `put` per coefficient of the result, in the same tower-lexicographic order;
///   an `invOpt = null` result folds a single INV_NONE.
/// - Montgomery-layer classes convert the SAME drawn normal-form element in and out of
///   Montgomery form inside the Motoko harness; the oracle computes the plain math.
pub fn edge_canon(m: &BigUint) -> Vec<BigUint> {
    vec![
        BigUint::from(0u8),
        BigUint::from(1u8),
        BigUint::from(2u8),
        m - 1u8,
    ]
}

/// Draws one k-coefficient tower element per the spec; returns canonical coefficients.
pub fn draw_tower(
    rng: &mut SplitMix64,
    e: &mut u64,
    k: usize,
    m: &BigUint,
    ec: &[BigUint],
) -> Vec<BigUint> {
    let mut coeffs: Vec<BigUint> = (0..k).map(|_| rng.raw512() % m).collect();
    if *e % 17 == 0 {
        for (j, c) in coeffs.iter_mut().enumerate() {
            *c = ec[((*e / 17) as usize + j) % ec.len()].clone();
        }
    }
    *e += 1;
    coeffs
}
