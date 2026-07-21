//! arkworks side of the per-op arithmetic differential (field layers).
//!
//! Emits one `CLASS <tag> N=<n> DIGEST=<hex>` line per op class, computed with arkworks
//! field arithmetic over the shared deterministic stream (spec in fortress/src/lib.rs).
//! The Motoko side (fortress/motoko/ArithDiff.mo) emits the same lines from the same
//! spec through the production L1/L2 modules; the harness diffs the two line sets.
//!
//! Usage: arith_oracle --seed <u64> [--div <n>]
//!   --div divides every committed N (calibration runs); the emitted N is the divided one,
//!   so a calibration digest never masquerades as a full-scale digest.

use ark_bls12_381::{Fq, Fr};
use ark_ff::{Field, PrimeField};
use fortress::{edges, Fold, SplitMix64, INV_NONE};
use num_bigint::BigUint;

fn modulus_fq() -> BigUint {
    BigUint::from_bytes_be(&ark_ff::BigInteger::to_bytes_be(&Fq::MODULUS))
}
fn modulus_fr() -> BigUint {
    BigUint::from_bytes_be(&ark_ff::BigInteger::to_bytes_be(&Fr::MODULUS))
}

fn fq_of(n: &BigUint, p: &BigUint) -> Fq {
    Fq::from(n % p)
}
fn fr_of(n: &BigUint, r: &BigUint) -> Fr {
    Fr::from(n % r)
}
fn big_of_fq(x: Fq) -> BigUint {
    x.into_bigint().into()
}
fn big_of_fr(x: Fr) -> BigUint {
    x.into_bigint().into()
}

/// Runs one binary/unary Fp-or-Fr class: draws per the spec, injects edges, applies `op`,
/// folds the result integers.
fn run_class<FOp>(tag: &str, seed: u64, n: u64, draw_b: bool, m: &BigUint, mut op: FOp) -> String
where
    FOp: FnMut(&BigUint, &BigUint, &mut Fold),
{
    let mut rng = SplitMix64::for_class(tag, seed);
    let ed = edges(m);
    let mut fold = Fold::new();
    for i in 0..n {
        let mut a = rng.raw512();
        let mut b = BigUint::from(0u8);
        if draw_b {
            b = rng.raw512();
        }
        if i % 17 == 0 {
            a = ed[((i / 17) as usize) % ed.len()].clone();
        }
        if draw_b && i % 19 == 0 {
            b = ed[((i / 19) as usize) % ed.len()].clone();
        }
        op(&a, &b, &mut fold);
    }
    format!("CLASS {tag} N={n} DIGEST={}", fold.hex())
}

fn main() {
    let mut seed: u64 = 20260721;
    let mut div: u64 = 1;
    let mut suite = String::from("all");
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--seed" => {
                seed = args[i + 1].parse().expect("seed");
                i += 2;
            }
            "--div" => {
                div = args[i + 1].parse().expect("div");
                i += 2;
            }
            "--suite" => {
                suite = args[i + 1].clone();
                i += 2;
            }
            other => panic!("unknown arg {other}"),
        }
    }
    assert!(div >= 1);
    if suite == "tower" || suite == "all" {
        for l in fortress::tower::run(seed, div) {
            println!("{l}");
        }
        if suite == "tower" {
            println!("SEED {seed}");
            return;
        }
    }
    if suite == "curve" || suite == "all" {
        for l in fortress::curvepair::run_curve(seed, div) {
            println!("{l}");
        }
        if suite == "curve" {
            println!("SEED {seed}");
            return;
        }
    }
    if suite == "pairing" || suite == "all" {
        for l in fortress::curvepair::run_pairing(seed, div) {
            println!("{l}");
        }
        if suite == "pairing" {
            println!("SEED {seed}");
            return;
        }
    }
    if suite == "decode" || suite == "all" {
        for l in fortress::curvepair::run_decode(seed, div) {
            println!("{l}");
        }
        if suite == "decode" {
            println!("SEED {seed}");
            return;
        }
    }
    let p = modulus_fq();
    let r = modulus_fr();

    let n_big = 1_000_000 / div;
    let n_inv = 100_000 / div;
    let n_rt = 500_000 / div;

    let mut lines: Vec<String> = Vec::new();

    // ---- L1 semantics (arkworks is the oracle; L1 and L2 produce identical values,
    // so the same oracle digests serve both `fp1.*` and `fpm.*` tags; the Motoko side
    // computes fp1.* through Fp.mo and fpm.* through FpMont.mo, so a divergence in
    // EITHER layer separates from the oracle and from the sibling layer's line.)
    for (layer, m, is_fr) in [("fp1", &p, false), ("fpm", &p, false), ("fr", &r, true)] {
        let tag_of = |op: &str| format!("{layer}.{op}");
        for op in ["add", "sub", "mul", "sqr"] {
            let tag = tag_of(op);
            let draw_b = op != "sqr";
            let opname = op.to_string();
            let line = run_class(&tag, seed, n_big, draw_b, m, |a, b, fold| {
                if is_fr {
                    let (x, y) = (fr_of(a, m), fr_of(b, m));
                    let z = match opname.as_str() {
                        "add" => x + y,
                        "sub" => x - y,
                        "mul" => x * y,
                        "sqr" => x.square(),
                        _ => unreachable!(),
                    };
                    fold.put(&big_of_fr(z));
                } else {
                    let (x, y) = (fq_of(a, m), fq_of(b, m));
                    let z = match opname.as_str() {
                        "add" => x + y,
                        "sub" => x - y,
                        "mul" => x * y,
                        "sqr" => x.square(),
                        _ => unreachable!(),
                    };
                    fold.put(&big_of_fq(z));
                }
            });
            lines.push(line);
        }
        // inv
        let tag = tag_of("inv");
        let line = run_class(&tag, seed, n_inv, false, m, |a, _b, fold| {
            if is_fr {
                match fr_of(a, m).inverse() {
                    Some(z) => fold.put(&big_of_fr(z)),
                    None => fold.put_u64(INV_NONE),
                }
            } else {
                match fq_of(a, m).inverse() {
                    Some(z) => fold.put(&big_of_fq(z)),
                    None => fold.put_u64(INV_NONE),
                }
            }
        });
        lines.push(line);
    }

    // fpm.roundtrip: Motoko computes montMul(toMont(a), 1); the mathematical value is a mod p.
    lines.push(run_class("fpm.roundtrip", seed, n_rt, false, &p, |a, _b, fold| {
        fold.put(&(a % &p));
    }));

    for l in &lines {
        println!("{l}");
    }
    println!("SEED {seed}");
}
