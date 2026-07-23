//! arkworks/blst side of the curve, pairing, and wire-decode differential classes.
//!
//! CURVE DRAW SPEC (implemented symmetrically in fortress/motoko/CurveDiff.mo and
//! PairingDiff.mo):
//! - Point pools: POOL_G1[k] = [s_k]G1, POOL_G2[k] = [t_k]G2 for k in 0..64, where s_k /
//!   t_k are successive raw512() draws (UNREDUCED) from the class streams "pool.g1" /
//!   "pool.g2". Scalar multiplication is by the literal integer (both sides), so
//!   reduction never has to agree.
//! - Chain classes: cur starts at pool[0]; per case, one word w = next():
//!   op = w & 1 (0 = cur := cur + pool[(w >> 1) % 64], 1 = cur := dbl(cur)).
//!   The affine of cur is folded every FOLD_EVERY cases and after the last case
//!   (fold: infinity → put PT_INF; else put x then y; G2 folds x.c0, x.c1, y.c0, y.c1).
//! - Scalar-mul classes: per case, k = raw512() (unreduced), idx = next() % 64;
//!   fold affine([k]pool[idx]).
//! - Subgroup classes: case i even → pool[next() % 64] (expected in subgroup);
//!   case i odd → deterministic off-subgroup on-curve point: repeat { x = raw512() mod p }
//!   until x³ + 4 (G1; x³ + 4(1+u) for G2 over Fp2) is a square; y := the LARGER root
//!   (same rule as the wire sort bit: G1 y > (p−1)/2; G2 lexicographic (c1, then c0)).
//!   Fold the boolean subgroup verdict (1/0).
//! - On-curve classes: case i with i % 10 == 0 → pool point (true); otherwise
//!   x = raw512() mod p, y = raw512() mod p (overwhelmingly false). Fold the boolean.
//! - vkx class: per case k = 1 + (next() % 8) inputs; indices ic_0..ic_k = next() % 64
//!   each; inputs = k raw512() draws reduced mod r (the Motoko vkX takes canonical Fr
//!   Nats from parseInputs in production). Fold affine(ic[0] + Σ inputs[i]·ic[i+1]).
//! - PT_INF fold sentinel = 12648430.
//!
//! DECODE classes ("dec.*"): oracle = blst (independent C implementation of the same
//! ZCash wire format the Motoko decoder implements; arkworks' own compressed format
//! differs and is NOT used here). Variant per case: v = next() % 8:
//!   0,1 → compress(pool[next() % 64]); 2 → canonical infinity encoding;
//!   3 → compress(pool point) with sort bit flipped (valid; decodes to −P);
//!   4 → compress(pool point) with compression bit cleared (reject);
//!   5 → compress(pool point) with x replaced by p + (next() % 4) (reject, non-canonical);
//!   6,7 → random bytes with compression bit forced on, infinity bit cleared (accept iff
//!         the x is canonical and on-curve — deterministic both sides).
//! Fold: reject → put 0; accept → put 1 then the affine coords (PT_INF for infinity).
//! "dec.frle": 32 LE bytes; v = next() % 8: 0..4 random; 5 → r (reject); 6 → r−1 with
//! probe: bytes of r−1; 7 → 2^256−1 (reject). Fold verdict + accepted value.

use crate::{Fold, SplitMix64};
use ark_bls12_381::{Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField};
use num_bigint::BigUint;

pub const PT_INF: u64 = 12648430;

fn big_fq(x: Fq) -> BigUint {
    x.into_bigint().into()
}

fn p_mod() -> BigUint {
    BigUint::from_bytes_be(&Fq::MODULUS.to_bytes_be())
}
fn r_mod() -> BigUint {
    BigUint::from_bytes_be(&Fr::MODULUS.to_bytes_be())
}

fn mul_big(p: &G1Projective, k: &BigUint) -> G1Projective {
    let bits: Vec<bool> = (0..k.bits()).map(|i| k.bit(i)).collect();
    let mut acc = G1Projective::default(); // identity
    for b in bits.iter().rev() {
        acc.double_in_place();
        if *b {
            acc += p;
        }
    }
    acc
}
fn mul_big2(p: &G2Projective, k: &BigUint) -> G2Projective {
    let bits: Vec<bool> = (0..k.bits()).map(|i| k.bit(i)).collect();
    let mut acc = G2Projective::default();
    for b in bits.iter().rev() {
        acc.double_in_place();
        if *b {
            acc += p;
        }
    }
    acc
}

pub fn pool_g1(seed: u64) -> Vec<G1Projective> {
    let mut rng = SplitMix64::for_class("pool.g1", seed);
    let g = G1Projective::generator();
    (0..64).map(|_| mul_big(&g, &rng.raw512())).collect()
}
pub fn pool_g2(seed: u64) -> Vec<G2Projective> {
    let mut rng = SplitMix64::for_class("pool.g2", seed);
    let g = G2Projective::generator();
    (0..64).map(|_| mul_big2(&g, &rng.raw512())).collect()
}

fn fold_g1(f: &mut Fold, p: &G1Projective) {
    let a = p.into_affine();
    if a.is_zero() {
        f.put_u64(PT_INF);
    } else {
        f.put(&big_fq(a.x));
        f.put(&big_fq(a.y));
    }
}
fn fold_g2(f: &mut Fold, p: &G2Projective) {
    let a = p.into_affine();
    if a.is_zero() {
        f.put_u64(PT_INF);
    } else {
        f.put(&big_fq(a.x.c0));
        f.put(&big_fq(a.x.c1));
        f.put(&big_fq(a.y.c0));
        f.put(&big_fq(a.y.c1));
    }
}

/// Deterministic off-subgroup on-curve G1 point per the spec.
fn off_subgroup_g1(rng: &mut SplitMix64, p: &BigUint) -> (BigUint, BigUint) {
    loop {
        let x = rng.raw512() % p;
        let rhs = (x.modpow(&BigUint::from(3u8), p) + 4u8) % p;
        // sqrt via a^((p+1)/4), p ≡ 3 mod 4
        let cand = rhs.modpow(&((p + 1u8) >> 2), p);
        if (&cand * &cand) % p == rhs {
            let other = p - &cand;
            let y = if cand > (p - 1u8) >> 1 { cand } else { other };
            return (x, y);
        }
    }
}

/// Deterministic off-subgroup on-curve G2 point: x drawn as (c0, c1); rhs = x³ + 4(1+u);
/// root via ark Fq2::sqrt normalized to the LARGER root (lexicographic c1 then c0).
fn off_subgroup_g2(rng: &mut SplitMix64, p: &BigUint) -> G2Affine {
    loop {
        let c0 = Fq::from(rng.raw512() % p);
        let c1 = Fq::from(rng.raw512() % p);
        let x = Fq2::new(c0, c1);
        let four = Fq2::new(Fq::from(4u8), Fq::from(4u8));
        let rhs = x * x * x + four;
        if let Some(y0) = rhs.sqrt() {
            let y1 = -y0;
            let y = if fq2_larger(&y0, &y1) { y0 } else { y1 };
            return G2Affine::new_unchecked(x, y);
        }
    }
}

fn fq2_larger(a: &Fq2, b: &Fq2) -> bool {
    // lexicographic: compare c1 first, then c0 (the wire sort-bit convention)
    let (a1, b1): (BigUint, BigUint) = (a.c1.into_bigint().into(), b.c1.into_bigint().into());
    if a1 != b1 {
        return a1 > b1;
    }
    let (a0, b0): (BigUint, BigUint) = (a.c0.into_bigint().into(), b.c0.into_bigint().into());
    a0 > b0
}

pub fn run_curve(seed: u64, div: u64) -> Vec<String> {
    let p = p_mod();
    let r = r_mod();
    let g1 = pool_g1(seed);
    let g2 = pool_g2(seed);
    let n = |base: u64| (base / div).max(1);
    let mut lines = Vec::new();

    // chain classes
    for (tag, nn, fold_every) in [("c1.chain", n(10_000), 1_000u64), ("c1.chainfast", n(200_000), 10_000)] {
        let mut rng = SplitMix64::for_class(tag, seed);
        let mut fold = Fold::new();
        let mut cur = g1[0];
        for i in 1..=nn {
            let w = rng.next();
            if w & 1 == 0 {
                cur += &g1[((w >> 1) % 64) as usize];
            } else {
                cur.double_in_place();
            }
            if i % fold_every == 0 || i == nn {
                fold_g1(&mut fold, &cur);
            }
        }
        lines.push(format!("CLASS {tag} N={nn} DIGEST={}", fold.hex()));
    }
    for (tag, nn, fold_every) in [("c2.chain", n(5_000), 500u64), ("c2.chainfast", n(100_000), 5_000)] {
        let mut rng = SplitMix64::for_class(tag, seed);
        let mut fold = Fold::new();
        let mut cur = g2[0];
        for i in 1..=nn {
            let w = rng.next();
            if w & 1 == 0 {
                cur += &g2[((w >> 1) % 64) as usize];
            } else {
                cur.double_in_place();
            }
            if i % fold_every == 0 || i == nn {
                fold_g2(&mut fold, &cur);
            }
        }
        lines.push(format!("CLASS {tag} N={nn} DIGEST={}", fold.hex()));
    }

    // scalar-mul classes (both the L2/Jacobian tag and the tiny L1 tag share the oracle
    // math; the Motoko side computes them through the two different layers)
    for (tag, nn, is_g2) in [
        ("c1.mul", n(2_000), false),
        ("c1.mull1", n(100), false),
        ("c2.mul", n(1_000), true),
    ] {
        let mut rng = SplitMix64::for_class(tag, seed);
        let mut fold = Fold::new();
        for _ in 0..nn {
            let k = rng.raw512();
            let idx = (rng.next() % 64) as usize;
            if is_g2 {
                fold_g2(&mut fold, &mul_big2(&g2[idx], &k));
            } else {
                fold_g1(&mut fold, &mul_big(&g1[idx], &k));
            }
        }
        lines.push(format!("CLASS {tag} N={nn} DIGEST={}", fold.hex()));
    }

    // subgroup classes
    for (tag, nn, is_g2) in [
        ("c1.subgrp", n(1_000), false),
        ("c1.subgrpl1", n(100), false),
        ("c2.subgrp", n(500), true),
        ("c2.subgrpl1", n(50), true),
    ] {
        let mut rng = SplitMix64::for_class(tag, seed);
        let mut fold = Fold::new();
        for i in 0..nn {
            let verdict = if i % 2 == 0 {
                let idx = (rng.next() % 64) as usize;
                if is_g2 {
                    g2[idx]
                        .into_affine()
                        .is_in_correct_subgroup_assuming_on_curve()
                } else {
                    g1[idx]
                        .into_affine()
                        .is_in_correct_subgroup_assuming_on_curve()
                }
            } else if is_g2 {
                off_subgroup_g2(&mut rng, &p).is_in_correct_subgroup_assuming_on_curve()
            } else {
                let (x, y) = off_subgroup_g1(&mut rng, &p);
                G1Affine::new_unchecked(Fq::from(x), Fq::from(y))
                    .is_in_correct_subgroup_assuming_on_curve()
            };
            fold.put_u64(if verdict { 1 } else { 0 });
        }
        lines.push(format!("CLASS {tag} N={nn} DIGEST={}", fold.hex()));
    }

    // on-curve classes
    for (tag, nn, is_g2) in [("c1.oncurve", n(100_000), false), ("c2.oncurve", n(50_000), true)] {
        let mut rng = SplitMix64::for_class(tag, seed);
        let mut fold = Fold::new();
        for i in 0..nn {
            let verdict = if i % 10 == 0 {
                let idx = (rng.next() % 64) as usize;
                true && {
                    if is_g2 {
                        g2[idx].into_affine().is_on_curve()
                    } else {
                        g1[idx].into_affine().is_on_curve()
                    }
                }
            } else if is_g2 {
                let x = Fq2::new(Fq::from(rng.raw512() % &p), Fq::from(rng.raw512() % &p));
                let y = Fq2::new(Fq::from(rng.raw512() % &p), Fq::from(rng.raw512() % &p));
                G2Affine::new_unchecked(x, y).is_on_curve()
            } else {
                let x = Fq::from(rng.raw512() % &p);
                let y = Fq::from(rng.raw512() % &p);
                G1Affine::new_unchecked(x, y).is_on_curve()
            };
            fold.put_u64(if verdict { 1 } else { 0 });
        }
        lines.push(format!("CLASS {tag} N={nn} DIGEST={}", fold.hex()));
    }

    // vkx MSM
    {
        let tag = "c1.vkx";
        let nn = n(500);
        let mut rng = SplitMix64::for_class(tag, seed);
        let mut fold = Fold::new();
        for _ in 0..nn {
            let k = (1 + rng.next() % 8) as usize;
            let ic: Vec<G1Projective> =
                (0..=k).map(|_| g1[(rng.next() % 64) as usize]).collect();
            let inputs: Vec<BigUint> = (0..k).map(|_| rng.raw512() % &r).collect();
            let mut acc = ic[0];
            for i in 0..k {
                acc += mul_big(&ic[i + 1], &inputs[i]);
            }
            fold_g1(&mut fold, &acc);
        }
        lines.push(format!("CLASS {tag} N={nn} DIGEST={}", fold.hex()));
    }

    lines
}

// ---------------- pairing classes ----------------

pub fn run_pairing(seed: u64, div: u64) -> Vec<String> {
    use ark_ec::pairing::Pairing;
    let g1 = pool_g1(seed);
    let g2 = pool_g2(seed);
    let n = |base: u64| (base / div).max(1);
    let mut lines = Vec::new();

    let fold_fq12 = |f: &mut Fold, x: ark_bls12_381::Fq12| {
        for c6 in [x.c0, x.c1] {
            for c2 in [c6.c0, c6.c1, c6.c2] {
                f.put(&big_fq(c2.c0));
                f.put(&big_fq(c2.c1));
            }
        }
    };

    // pm.miller: the projective prepared path folds the RAW Miller value (byte-equal to
    // arkworks'). pm.millermont: the affine PairingMont variant computes a
    // final-exp-EQUIVALENT raw value (probed: differs raw, equal after final exp), so
    // that class folds the final-exponentiated value instead.
    {
        let tag = "pm.miller";
        let nn = n(500);
        let mut rng = SplitMix64::for_class(tag, seed);
        let mut fold = Fold::new();
        for _ in 0..nn {
            let a = g1[(rng.next() % 64) as usize].into_affine();
            let b = g2[(rng.next() % 64) as usize].into_affine();
            let m = ark_bls12_381::Bls12_381::miller_loop(a, b);
            fold_fq12(&mut fold, m.0);
        }
        lines.push(format!("CLASS {tag} N={nn} DIGEST={}", fold.hex()));
    }
    {
        let tag = "pm.millermont";
        let nn = n(100);
        let mut rng = SplitMix64::for_class(tag, seed);
        let mut fold = Fold::new();
        for _ in 0..nn {
            let a = g1[(rng.next() % 64) as usize].into_affine();
            let b = g2[(rng.next() % 64) as usize].into_affine();
            let m = ark_bls12_381::Bls12_381::miller_loop(a, b);
            let f = ark_bls12_381::Bls12_381::final_exponentiation(m).expect("nonzero");
            fold_fq12(&mut fold, f.0);
        }
        lines.push(format!("CLASS {tag} N={nn} DIGEST={}", fold.hex()));
    }

    // pfe.finalexp on Miller outputs of pool pairs
    {
        let tag = "pfe.finalexp";
        let nn = n(200);
        let mut rng = SplitMix64::for_class(tag, seed);
        let mut fold = Fold::new();
        for _ in 0..nn {
            let a = g1[(rng.next() % 64) as usize].into_affine();
            let b = g2[(rng.next() % 64) as usize].into_affine();
            let m = ark_bls12_381::Bls12_381::miller_loop(a, b);
            let f = ark_bls12_381::Bls12_381::final_exponentiation(m).expect("nonzero");
            fold_fq12(&mut fold, f.0);
        }
        lines.push(format!("CLASS {tag} N={nn} DIGEST={}", fold.hex()));
    }

    // full pairing
    {
        let tag = "pm.pair";
        let nn = n(300);
        let mut rng = SplitMix64::for_class(tag, seed);
        let mut fold = Fold::new();
        for _ in 0..nn {
            let a = g1[(rng.next() % 64) as usize].into_affine();
            let b = g2[(rng.next() % 64) as usize].into_affine();
            let e = ark_bls12_381::Bls12_381::pairing(a, b);
            fold_fq12(&mut fold, e.0);
        }
        lines.push(format!("CLASS {tag} N={nn} DIGEST={}", fold.hex()));
    }

    // interleaved multi-Miller over 2..4 pairs
    {
        let tag = "gm.multi";
        let nn = n(200);
        let mut rng = SplitMix64::for_class(tag, seed);
        let mut fold = Fold::new();
        for _ in 0..nn {
            let k = (2 + rng.next() % 3) as usize;
            let aa: Vec<G1Affine> = (0..k)
                .map(|_| g1[(rng.next() % 64) as usize].into_affine())
                .collect();
            let bb: Vec<G2Affine> = (0..k)
                .map(|_| g2[(rng.next() % 64) as usize].into_affine())
                .collect();
            let m = ark_bls12_381::Bls12_381::multi_miller_loop(aa, bb);
            fold_fq12(&mut fold, m.0);
        }
        lines.push(format!("CLASS {tag} N={nn} DIGEST={}", fold.hex()));
    }

    lines
}

// ---------------- wire-decode classes (blst oracle) ----------------

fn compress_g1(p: &G1Projective) -> [u8; 48] {
    let a = p.into_affine();
    let mut out = [0u8; 48];
    if a.is_zero() {
        out[0] = 0xc0;
        return out;
    }
    let x: BigUint = a.x.into_bigint().into();
    let xb = x.to_bytes_be();
    out[48 - xb.len()..].copy_from_slice(&xb);
    out[0] |= 0x80;
    let y: BigUint = a.y.into_bigint().into();
    let pm = p_mod();
    if y > (&pm - 1u8) >> 1 {
        out[0] |= 0x20;
    }
    out
}

fn compress_g2(p: &G2Projective) -> [u8; 96] {
    let a = p.into_affine();
    let mut out = [0u8; 96];
    if a.is_zero() {
        out[0] = 0xc0;
        return out;
    }
    // ZCash order: x.c1 first, then x.c0
    let c1: BigUint = a.x.c1.into_bigint().into();
    let c0: BigUint = a.x.c0.into_bigint().into();
    let c1b = c1.to_bytes_be();
    let c0b = c0.to_bytes_be();
    out[48 - c1b.len()..48].copy_from_slice(&c1b);
    out[96 - c0b.len()..].copy_from_slice(&c0b);
    out[0] |= 0x80;
    let neg = -a.y;
    if fq2_larger(&a.y, &neg) {
        out[0] |= 0x20;
    }
    out
}

fn blst_decode_g1(bytes: &[u8; 48]) -> Option<Option<(BigUint, BigUint)>> {
    // Some(None) = accepted infinity; Some(Some((x,y))) = accepted point; None = reject.
    unsafe {
        let mut aff = blst::blst_p1_affine::default();
        if blst::blst_p1_uncompress(&mut aff, bytes.as_ptr()) != blst::BLST_ERROR::BLST_SUCCESS {
            return None;
        }
        if blst::blst_p1_affine_is_inf(&aff) {
            return Some(None);
        }
        let mut xb = [0u8; 48];
        let mut yb = [0u8; 48];
        blst::blst_bendian_from_fp(xb.as_mut_ptr(), &aff.x);
        blst::blst_bendian_from_fp(yb.as_mut_ptr(), &aff.y);
        Some(Some((
            BigUint::from_bytes_be(&xb),
            BigUint::from_bytes_be(&yb),
        )))
    }
}

#[allow(clippy::type_complexity)]
fn blst_decode_g2(bytes: &[u8; 96]) -> Option<Option<(BigUint, BigUint, BigUint, BigUint)>> {
    unsafe {
        let mut aff = blst::blst_p2_affine::default();
        if blst::blst_p2_uncompress(&mut aff, bytes.as_ptr()) != blst::BLST_ERROR::BLST_SUCCESS {
            return None;
        }
        if blst::blst_p2_affine_is_inf(&aff) {
            return Some(None);
        }
        let mut b = [[0u8; 48]; 4];
        blst::blst_bendian_from_fp(b[0].as_mut_ptr(), &aff.x.fp[0]);
        blst::blst_bendian_from_fp(b[1].as_mut_ptr(), &aff.x.fp[1]);
        blst::blst_bendian_from_fp(b[2].as_mut_ptr(), &aff.y.fp[0]);
        blst::blst_bendian_from_fp(b[3].as_mut_ptr(), &aff.y.fp[1]);
        Some(Some((
            BigUint::from_bytes_be(&b[0]),
            BigUint::from_bytes_be(&b[1]),
            BigUint::from_bytes_be(&b[2]),
            BigUint::from_bytes_be(&b[3]),
        )))
    }
}

pub fn run_decode(seed: u64, div: u64) -> Vec<String> {
    let p = p_mod();
    let r = r_mod();
    let g1 = pool_g1(seed);
    let g2 = pool_g2(seed);
    let n = |base: u64| (base / div).max(1);
    let mut lines = Vec::new();

    // dec.g1
    {
        let tag = "dec.g1";
        let nn = n(20_000);
        let mut rng = SplitMix64::for_class(tag, seed);
        let mut fold = Fold::new();
        for _ in 0..nn {
            let v = rng.next() % 8;
            let mut bytes: [u8; 48] = match v {
                0 | 1 => compress_g1(&g1[(rng.next() % 64) as usize]),
                2 => {
                    let mut b = [0u8; 48];
                    b[0] = 0xc0;
                    b
                }
                3 => {
                    let mut b = compress_g1(&g1[(rng.next() % 64) as usize]);
                    b[0] ^= 0x20;
                    b
                }
                4 => {
                    let mut b = compress_g1(&g1[(rng.next() % 64) as usize]);
                    b[0] &= 0x7f;
                    b
                }
                5 => {
                    let xb = ((&p) + (rng.next() % 4)).to_bytes_be();
                    let mut b = [0u8; 48];
                    b[48 - xb.len()..].copy_from_slice(&xb);
                    b[0] |= 0x80;
                    b
                }
                _ => {
                    let mut b = [0u8; 48];
                    for chunk in 0..6 {
                        b[chunk * 8..chunk * 8 + 8].copy_from_slice(&rng.next().to_be_bytes());
                    }
                    b[0] |= 0x80;
                    b[0] &= !0x40;
                    b
                }
            };
            // (defensive: fixed-size array, no-op line keeps mutability warnings away)
            bytes[0] |= 0;
            match blst_decode_g1(&bytes) {
                None => fold.put_u64(0),
                Some(None) => {
                    fold.put_u64(1);
                    fold.put_u64(PT_INF);
                }
                Some(Some((x, y))) => {
                    fold.put_u64(1);
                    fold.put(&x);
                    fold.put(&y);
                }
            }
        }
        lines.push(format!("CLASS {tag} N={nn} DIGEST={}", fold.hex()));
    }

    // dec.g2
    {
        let tag = "dec.g2";
        let nn = n(5_000);
        let mut rng = SplitMix64::for_class(tag, seed);
        let mut fold = Fold::new();
        for _ in 0..nn {
            let v = rng.next() % 8;
            let bytes: [u8; 96] = match v {
                0 | 1 => compress_g2(&g2[(rng.next() % 64) as usize]),
                2 => {
                    let mut b = [0u8; 96];
                    b[0] = 0xc0;
                    b
                }
                3 => {
                    let mut b = compress_g2(&g2[(rng.next() % 64) as usize]);
                    b[0] ^= 0x20;
                    b
                }
                4 => {
                    let mut b = compress_g2(&g2[(rng.next() % 64) as usize]);
                    b[0] &= 0x7f;
                    b
                }
                5 => {
                    let mut b = compress_g2(&g2[(rng.next() % 64) as usize]);
                    let xb = ((&p) + (rng.next() % 4)).to_bytes_be();
                    for i in 0..48 {
                        b[i] = 0;
                    }
                    b[48 - xb.len().min(48)..48].copy_from_slice(&xb[..xb.len().min(48)]);
                    b[0] |= 0x80;
                    b
                }
                _ => {
                    let mut b = [0u8; 96];
                    for chunk in 0..12 {
                        b[chunk * 8..chunk * 8 + 8].copy_from_slice(&rng.next().to_be_bytes());
                    }
                    b[0] |= 0x80;
                    b[0] &= !0x40;
                    b
                }
            };
            match blst_decode_g2(&bytes) {
                None => fold.put_u64(0),
                Some(None) => {
                    fold.put_u64(1);
                    fold.put_u64(PT_INF);
                }
                Some(Some((x0, x1, y0, y1))) => {
                    fold.put_u64(1);
                    fold.put(&x0);
                    fold.put(&x1);
                    fold.put(&y0);
                    fold.put(&y1);
                }
            }
        }
        lines.push(format!("CLASS {tag} N={nn} DIGEST={}", fold.hex()));
    }

    // dec.frle — 32-byte little-endian Fr parse; valid iff value < r.
    {
        let tag = "dec.frle";
        let nn = n(250_000);
        let mut rng = SplitMix64::for_class(tag, seed);
        let mut fold = Fold::new();
        for _ in 0..nn {
            let v = rng.next() % 8;
            let val: BigUint = match v {
                0..=4 => {
                    // 256-bit random (≈ 55% of draws are ≥ r — a real accept/reject mix)
                    let mut x = BigUint::from(0u8);
                    for _ in 0..4 {
                        x = (x << 64) + BigUint::from(rng.next());
                    }
                    x
                }
                5 => r.clone(),
                6 => &r - 1u8,
                _ => (BigUint::from(1u8) << 256) - 1u8,
            };
            let mut le = [0u8; 32];
            let vb = val.to_bytes_le();
            le[..vb.len().min(32)].copy_from_slice(&vb[..vb.len().min(32)]);
            let accepted = unsafe {
                let mut s = blst::blst_scalar::default();
                blst::blst_scalar_from_lendian(&mut s, le.as_ptr());
                blst::blst_scalar_fr_check(&s)
            };
            if accepted {
                fold.put_u64(1);
                fold.put(&val);
            } else {
                fold.put_u64(0);
            }
        }
        lines.push(format!("CLASS {tag} N={nn} DIGEST={}", fold.hex()));
    }

    lines
}
