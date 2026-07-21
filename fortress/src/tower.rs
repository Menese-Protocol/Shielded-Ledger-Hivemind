//! arkworks side of the tower-layer differential classes (Fp2/Fp6/Fp12, Frobenius,
//! cyclotomic ops). Tower conventions: Fq2 = Fq[u]/(u²+1), Fq6 = Fq2[v]/(v³−(u+1)),
//! Fq12 = Fq6[w]/(w²−v) — the same tower the Motoko layers implement (proven aligned by
//! the existing multi-Miller byte-diff battery).

use crate::{draw_tower, edge_canon, Fold, SplitMix64, INV_NONE};
use ark_bls12_381::{Fq, Fq12, Fq2, Fq6};
use ark_ff::{Field, PrimeField};
use num_bigint::BigUint;

fn fq(n: &BigUint) -> Fq {
    Fq::from(n.clone())
}
fn big(x: Fq) -> BigUint {
    x.into_bigint().into()
}

fn fq2(c: &[BigUint]) -> Fq2 {
    Fq2::new(fq(&c[0]), fq(&c[1]))
}
fn fq6(c: &[BigUint]) -> Fq6 {
    Fq6::new(fq2(&c[0..2]), fq2(&c[2..4]), fq2(&c[4..6]))
}
fn fq12(c: &[BigUint]) -> Fq12 {
    Fq12::new(fq6(&c[0..6]), fq6(&c[6..12]))
}

fn fold2(f: &mut Fold, x: Fq2) {
    f.put(&big(x.c0));
    f.put(&big(x.c1));
}
fn fold6(f: &mut Fold, x: Fq6) {
    fold2(f, x.c0);
    fold2(f, x.c1);
    fold2(f, x.c2);
}
fn fold12(f: &mut Fold, x: Fq12) {
    fold6(f, x.c0);
    fold6(f, x.c1);
}

/// f^((p^6−1)(p^2+1)) — the easy part; lands in the cyclotomic subgroup.
fn easy_part(f: Fq12) -> Fq12 {
    let mut y = f;
    y.frobenius_map_in_place(6);
    let y = y * f.inverse().expect("nonzero fp12 draw");
    let mut z = y;
    z.frobenius_map_in_place(2);
    z * y
}

const X_ABS: u64 = 0xd201000000010000;

struct Ctx {
    seed: u64,
    p: BigUint,
    lines: Vec<String>,
}

impl Ctx {
    fn class<F>(&mut self, tag: &str, n: u64, k: usize, binary: bool, mut op: F)
    where
        F: FnMut(&[BigUint], &[BigUint], &mut Fold),
    {
        let mut rng = SplitMix64::for_class(tag, self.seed);
        let ec = edge_canon(&self.p);
        let mut fold = Fold::new();
        let mut e: u64 = 0;
        for _ in 0..n {
            let a = draw_tower(&mut rng, &mut e, k, &self.p, &ec);
            let b = if binary {
                draw_tower(&mut rng, &mut e, k, &self.p, &ec)
            } else {
                Vec::new()
            };
            op(&a, &b, &mut fold);
        }
        self.lines
            .push(format!("CLASS {tag} N={n} DIGEST={}", fold.hex()));
    }
}

pub fn run(seed: u64, div: u64) -> Vec<String> {
    let p: BigUint = BigUint::from_bytes_be(&ark_ff::BigInteger::to_bytes_be(&Fq::MODULUS));
    let mut ctx = Ctx {
        seed,
        p,
        lines: Vec::new(),
    };
    let n = |base: u64| (base / div).max(1);

    // ---- L1 Tower.mo classes (plain math oracle; Motoko computes through Tower.mo) ----
    ctx.class("t2.mul", n(100_000), 2, true, |a, b, f| fold2(f, fq2(a) * fq2(b)));
    ctx.class("t2.sqr", n(100_000), 2, false, |a, _b, f| fold2(f, fq2(a).square()));
    ctx.class("t2.inv", n(20_000), 2, false, |a, _b, f| match fq2(a).inverse() {
        Some(z) => fold2(f, z),
        None => f.put_u64(INV_NONE),
    });
    ctx.class("t2.nonres", n(100_000), 2, false, |a, _b, f| {
        // multiply by (1 + u), the Fp6 nonresidue
        fold2(f, fq2(a) * Fq2::new(Fq::from(1u8), Fq::from(1u8)));
    });
    ctx.class("t2.conj", n(100_000), 2, false, |a, _b, f| {
        let mut z = fq2(a);
        z.conjugate_in_place();
        fold2(f, z);
    });
    ctx.class("t6.mul", n(50_000), 6, true, |a, b, f| fold6(f, fq6(a) * fq6(b)));
    ctx.class("t6.inv", n(10_000), 6, false, |a, _b, f| match fq6(a).inverse() {
        Some(z) => fold6(f, z),
        None => f.put_u64(INV_NONE),
    });
    ctx.class("t6.mulv", n(50_000), 6, false, |a, _b, f| {
        // multiply by v: (c0, c1, c2) -> (nonres*c2, c0, c1)
        let x = fq6(a);
        let nr = Fq2::new(Fq::from(1u8), Fq::from(1u8));
        fold6(f, Fq6::new(x.c2 * nr, x.c0, x.c1));
    });
    ctx.class("t12.mul", n(20_000), 12, true, |a, b, f| fold12(f, fq12(a) * fq12(b)));
    ctx.class("t12.sqr", n(20_000), 12, false, |a, _b, f| fold12(f, fq12(a).square()));
    ctx.class("t12.inv", n(5_000), 12, false, |a, _b, f| match fq12(a).inverse() {
        Some(z) => fold12(f, z),
        None => f.put_u64(INV_NONE),
    });
    ctx.class("t12.conj", n(20_000), 12, false, |a, _b, f| {
        let mut z = fq12(a);
        z.conjugate_in_place();
        fold12(f, z);
    });
    // L1 Frobenius is the LITERAL x^(p^i) (grotesquely slow by design) — tiny committed N.
    // Power cycles 1..=11 by case order; the Motoko side mirrors this exact rule.
    {
        let tag = "t12.frob";
        let nn = n(50);
        let mut rng = SplitMix64::for_class(tag, seed);
        let ec = edge_canon(&ctx.p);
        let mut fold = Fold::new();
        let mut e: u64 = 0;
        for i in 0..nn {
            let a = draw_tower(&mut rng, &mut e, 12, &ctx.p, &ec);
            let power = (i % 11 + 1) as usize; // cycles 1..=11
            let mut z = fq12(&a);
            z.frobenius_map_in_place(power);
            fold12(&mut fold, z);
        }
        ctx.lines
            .push(format!("CLASS {tag} N={nn} DIGEST={}", fold.hex()));
    }

    // ---- L2 TowerMont.mo / PairingFinalExp.mo classes ----
    ctx.class("tm2.mul", n(100_000), 2, true, |a, b, f| fold2(f, fq2(a) * fq2(b)));
    ctx.class("tm2.sqrfast", n(100_000), 2, false, |a, _b, f| fold2(f, fq2(a).square()));
    ctx.class("tm2.inv", n(20_000), 2, false, |a, _b, f| match fq2(a).inverse() {
        Some(z) => fold2(f, z),
        None => f.put_u64(INV_NONE),
    });
    ctx.class("tm12.mul", n(20_000), 12, true, |a, b, f| fold12(f, fq12(a) * fq12(b)));
    ctx.class("tm12.sqrfast", n(20_000), 12, false, |a, _b, f| {
        fold12(f, fq12(a).square())
    });
    ctx.class("tm12.inv", n(5_000), 12, false, |a, _b, f| match fq12(a).inverse() {
        Some(z) => fold12(f, z),
        None => f.put_u64(INV_NONE),
    });
    // sparse mul_by_014: the operand has coefficients only at tower positions 0, 1, 4 —
    // b = Fq6::new(b0, b1, 0) + w·Fq6::new(0, b4, 0). Drawn as one k=12 element (a) then
    // one k=6 element (b0, b1, b4) in the same stream.
    {
        let tag = "tm12.by014";
        let nn = n(20_000);
        let mut rng = SplitMix64::for_class(tag, seed);
        let ec = edge_canon(&ctx.p);
        let mut fold = Fold::new();
        let mut e: u64 = 0;
        for _ in 0..nn {
            let a = draw_tower(&mut rng, &mut e, 12, &ctx.p, &ec);
            let s = draw_tower(&mut rng, &mut e, 6, &ctx.p, &ec); // b0, b1, b4 as three Fq2
        let b0 = fq2(&s[0..2]);
            let b1 = fq2(&s[2..4]);
            let b4 = fq2(&s[4..6]);
            let sparse = Fq12::new(
                Fq6::new(b0, b1, Fq2::new(Fq::from(0u8), Fq::from(0u8))),
                Fq6::new(
                    Fq2::new(Fq::from(0u8), Fq::from(0u8)),
                    b4,
                    Fq2::new(Fq::from(0u8), Fq::from(0u8)),
                ),
            );
            fold12(&mut fold, fq12(&a) * sparse);
        }
        ctx.lines
            .push(format!("CLASS {tag} N={nn} DIGEST={}", fold.hex()));
    }
    // pfe.frob: the fast table-based Frobenius (production final-exp path); power cycles 0..=11.
    {
        let tag = "pfe.frob";
        let nn = n(20_000);
        let mut rng = SplitMix64::for_class(tag, seed);
        let ec = edge_canon(&ctx.p);
        let mut fold = Fold::new();
        let mut e: u64 = 0;
        for i in 0..nn {
            let a = draw_tower(&mut rng, &mut e, 12, &ctx.p, &ec);
            let power = (i % 12) as usize; // includes 0 (identity)
            let mut z = fq12(&a);
            z.frobenius_map_in_place(power);
            fold12(&mut fold, z);
        }
        ctx.lines
            .push(format!("CLASS {tag} N={nn} DIGEST={}", fold.hex()));
    }
    // pfe.cycsqr / pfe.expbyx: inputs mapped through the easy part (cyclotomic subgroup).
    ctx.class("pfe.cycsqr", n(5_000), 12, false, |a, _b, f| {
        let z = easy_part(fq12(a));
        fold12(f, z.square()); // cyclotomic square == generic square on the subgroup
    });
    ctx.class("pfe.expbyx", n(100), 12, false, |a, _b, f| {
        let z = easy_part(fq12(a));
        // Motoko expByX computes z^(−X_ABS) (NAF, conjugation as cyclotomic inverse).
        let zx = z.pow([X_ABS]);
        fold12(f, zx.inverse().expect("cyclotomic element invertible"));
    });

    ctx.lines
}
