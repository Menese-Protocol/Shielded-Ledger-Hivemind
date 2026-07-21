//! Differential oracle for the in-canister Poseidon Merkle frontier.
//!
//! Dumps the EXACT Poseidon constants and input→output vectors of the reference
//! implementation the ledger's tree oracle runs (`vendor/tree_common` built with
//! `--features bls12-381`, arkworks `ark-crypto-primitives` 0.5.0). Every vector is
//! produced by the REAL arkworks code path — the raw permutation vectors are obtained
//! by constructing a `PoseidonSponge` at an arbitrary state and letting the genuine
//! `permute()` run (triggered by `squeeze_native_field_elements`), then reading the
//! public `state` back. No re-implemented crypto is used to generate expectations.
//!
//! Subcommands:
//!   constants            → Motoko module with ARK (65×3) + MDS (3×3) + modulus
//!   vectors <seed> <name>→ Motoko fixture module with perm/hashN/compress/zeros/
//!                          sequential-frontier/synthetic-frontier vectors
//!   summary <seed>       → digest counts + a few spot values (for the evidence log)
//!
//! Menese DeFi Team.

use ark_bls12_381::Fr as F;
use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
use ark_crypto_primitives::sponge::{
    CryptographicSponge, DuplexSpongeMode, FieldBasedCryptographicSponge,
};
use ark_ff::{BigInteger, PrimeField, Zero};
use common::{
    f_to_hex, hash_n, merkle_compress, poseidon_config, zero_hashes, DenseTree, IncrementalTree,
    PoseidonCfg, TREE_DEPTH,
};

fn dec(x: &F) -> String {
    x.into_bigint().to_string()
}

/// splitmix64 — deterministic input generation (no external RNG dependency).
struct SplitMix(u64);
impl SplitMix {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }
    fn field(&mut self) -> F {
        let mut bytes = [0u8; 32];
        for chunk in bytes.chunks_mut(8) {
            chunk.copy_from_slice(&self.next().to_le_bytes());
        }
        F::from_le_bytes_mod_order(&bytes)
    }
}

/// Run the REAL arkworks permutation once on an arbitrary state:
/// state layout is [capacity | rate] = [s0, s1, s2] with capacity = 1, rate = 2.
/// `squeeze_native_field_elements` in Absorbing mode performs exactly one `permute()`
/// then copies out of the rate section; the mutated public `state` is the full output.
fn permute(cfg: &PoseidonCfg<F>, s: [F; 3]) -> [F; 3] {
    let mut sponge = PoseidonSponge::<F> {
        parameters: cfg.clone(),
        state: s.to_vec(),
        mode: DuplexSpongeMode::Absorbing {
            next_absorb_index: cfg.rate,
        },
    };
    let out = sponge.squeeze_native_field_elements(1);
    assert_eq!(out[0], sponge.state[cfg.capacity], "squeeze/state layout drift");
    [sponge.state[0], sponge.state[1], sponge.state[2]]
}

fn edge_values() -> Vec<F> {
    vec![
        F::zero(),
        F::from(1u64),
        F::from(2u64),
        -F::from(1u64), // P-1
        -F::from(2u64), // P-2
        F::from(u64::MAX),
        F::from(u64::MAX) + F::from(1u64), // 2^64
    ]
}

/// In-binary cross-checks tying every exposed vector family to a second independent
/// arkworks path. Panics (exit != 0) on any disagreement.
fn self_check(cfg: &PoseidonCfg<F>, seed: u64) {
    // 1. permute() extraction agrees with the sponge on compress inputs:
    //    merkle_compress(l, r) must equal permute([0, l, r])[1].
    let mut rng = SplitMix(seed ^ 0xc0ffee);
    for _ in 0..200 {
        let (l, r) = (rng.field(), rng.field());
        let via_perm = permute(cfg, [F::zero(), l, r])[1];
        assert_eq!(via_perm, merkle_compress(cfg, l, r), "perm vs compress");
    }
    // 2. hash_n on 3..6 inputs equals a chain of raw permutes (verifies the duplex
    //    absorb schedule AND that the capacity element survives extraction).
    for k in 3..=6usize {
        for _ in 0..50 {
            let inputs: Vec<F> = (0..k).map(|_| rng.field()).collect();
            let mut state = [F::zero(); 3];
            let mut idx = 0usize;
            for x in &inputs {
                if idx == cfg.rate {
                    state = permute(cfg, state);
                    idx = 0;
                }
                state[cfg.capacity + idx] += x;
                idx += 1;
            }
            state = permute(cfg, state);
            assert_eq!(state[1], hash_n(cfg, &inputs), "duplex chain vs hash_n k={k}");
        }
    }
    // 3. IncrementalTree agrees with DenseTree (two independent tree recomputations).
    let mut tree = IncrementalTree::new(cfg);
    let mut leaves = Vec::new();
    for i in 0..300u64 {
        let leaf = rng.field();
        leaves.push(leaf);
        let inc_root = tree.append(cfg, leaf);
        if matches!(i, 0 | 1 | 2 | 4 | 15 | 63 | 128 | 299) {
            let dense = DenseTree { leaves: leaves.clone() };
            assert_eq!(inc_root, dense.root(cfg), "incremental vs dense at {i}");
        }
    }
    // 4. Montgomery-repr assumption: arkworks Fr internal repr = a·2^256 mod r.
    //    F::one() must equal R mod r, independently derived in python from r alone.
    assert_eq!(
        mont_limbs32(&F::from(1u64)),
        [0xfffffffe, 0x00000001, 0x00034802, 0x5884b7fa, 0xecbc4ff5, 0x998c4fef, 0xacc5056f, 0x1824b159],
        "arkworks internal repr is not a*2^256 mod r"
    );
    eprintln!("[self-check] all internal cross-checks green (seed {seed:#x})");
}

/// Montgomery-form limbs of a field element as 8 little-endian 32-bit words.
/// arkworks' internal representation of Fr IS a·R mod r with R = 2^256 — the same R
/// as the ledger's 8×32 CIOS — so the raw `BigInt` limbs are emitted directly.
fn mont_limbs32(x: &F) -> [u32; 8] {
    let raw: [u64; 4] = x.0 .0;
    let mut out = [0u32; 8];
    for (i, limb) in raw.iter().enumerate() {
        out[2 * i] = (*limb & 0xffff_ffff) as u32;
        out[2 * i + 1] = (*limb >> 32) as u32;
    }
    out
}

fn nat32_list(v: &[u32]) -> String {
    v.iter().map(|x| format!("0x{x:08x}")).collect::<Vec<_>>().join(", ")
}

fn emit_constants(cfg: &PoseidonCfg<F>) {
    println!("/// GENERATED by frontier_oracle `constants` — DO NOT EDIT BY HAND.");
    println!("/// Poseidon over BLS12-381 Fr: t = 3 (rate 2, capacity 1), 8 full + 57 partial");
    println!("/// rounds, alpha = 5. Constants from arkworks ark-crypto-primitives 0.5.0");
    println!("/// `find_poseidon_ark_and_mds::<Fr>(255, 2, 8, 57, 0)` (Grain LFSR), the exact");
    println!("/// parameter set of `vendor/tree_common::poseidon_config()` — the reference the");
    println!("/// tree oracle and the circuits run. Menese DeFi Team.");
    println!("module {{");
    println!("  /// ARK[round][lane], 65 rounds x width 3, decimal canonical representation.");
    println!("  public let ARK : [[Nat]] = [");
    for row in &cfg.ark {
        println!(
            "    [{}],",
            row.iter().map(dec).collect::<Vec<_>>().join(", ")
        );
    }
    println!("  ];");
    println!("  /// MDS[i][j], 3 x 3.");
    println!("  public let MDS : [[Nat]] = [");
    for row in &cfg.mds {
        println!(
            "    [{}],",
            row.iter().map(dec).collect::<Vec<_>>().join(", ")
        );
    }
    println!("  ];");
    println!("  /// ARK in Montgomery form (a·2^256 mod r), flat 8×32-bit LE limbs:");
    println!("  /// ARK_MONT[(round*3 + lane)*8 ..+8]. Raw arkworks internal repr — the");
    println!("  /// exact operand form of the ledger's FrFlat CIOS (R = 2^256 on both sides).");
    println!("  public let ARK_MONT : [Nat32] = [");
    for row in &cfg.ark {
        for x in row {
            println!("    {},", nat32_list(&mont_limbs32(x)));
        }
    }
    println!("  ];");
    println!("  /// MDS in Montgomery form, flat limbs: MDS_MONT[(i*3 + j)*8 ..+8].");
    println!("  public let MDS_MONT : [Nat32] = [");
    for row in &cfg.mds {
        for x in row {
            println!("    {},", nat32_list(&mont_limbs32(x)));
        }
    }
    println!("  ];");
    println!("}}");
}

fn nat_list(v: &[F]) -> String {
    v.iter().map(dec).collect::<Vec<_>>().join(", ")
}

fn emit_vectors(cfg: &PoseidonCfg<F>, seed: u64, name: &str) {
    let mut rng = SplitMix(seed);
    println!("/// GENERATED by frontier_oracle `vectors {seed:#x} {name}` — DO NOT EDIT.");
    println!("/// Every expected output produced by arkworks 0.5.0 via vendor/tree_common");
    println!("/// (--features bls12-381). Menese DeFi Team.");
    println!("module {{");

    // ---- raw permutation vectors ----
    let mut perm_inputs: Vec<[F; 3]> = Vec::new();
    let e = edge_values();
    perm_inputs.push([F::zero(), F::zero(), F::zero()]);
    perm_inputs.push([e[3], e[3], e[3]]);
    perm_inputs.push([F::zero(), F::from(1u64), F::from(2u64)]);
    for _ in 0..250 {
        perm_inputs.push([rng.field(), rng.field(), rng.field()]);
    }
    println!("  /// (in0, in1, in2, out0, out1, out2) — one full 65-round permutation.");
    println!("  public let perm : [(Nat, Nat, Nat, Nat, Nat, Nat)] = [");
    for s in &perm_inputs {
        let o = permute(cfg, *s);
        println!(
            "    ({}, {}, {}, {}, {}, {}),",
            dec(&s[0]), dec(&s[1]), dec(&s[2]), dec(&o[0]), dec(&o[1]), dec(&o[2])
        );
    }
    println!("  ];");

    // ---- sponge hash_n vectors, k = 1..6 ----
    println!("  /// (inputs, expected hash_n output) — arkworks PoseidonSponge absorb/squeeze.");
    println!("  public let hashN : [([Nat], Nat)] = [");
    for k in 1..=6usize {
        // edge-only vector: first k edge values
        let edge_in: Vec<F> = e.iter().take(k).cloned().collect();
        println!("    ([{}], {}),", nat_list(&edge_in), dec(&hash_n(cfg, &edge_in)));
        for _ in 0..12 {
            let inputs: Vec<F> = (0..k).map(|_| rng.field()).collect();
            println!("    ([{}], {}),", nat_list(&inputs), dec(&hash_n(cfg, &inputs)));
        }
    }
    println!("  ];");

    // ---- merkle_compress vectors ----
    let mut pairs: Vec<(F, F)> = Vec::new();
    for a in &e {
        for b in &e {
            pairs.push((*a, *b));
        }
    }
    for _ in 0..350 {
        pairs.push((rng.field(), rng.field()));
    }
    println!("  /// (l, r, merkle_compress(l, r)).");
    println!("  public let compress : [(Nat, Nat, Nat)] = [");
    for (l, r) in &pairs {
        println!("    ({}, {}, {}),", dec(l), dec(r), dec(&merkle_compress(cfg, *l, *r)));
    }
    println!("  ];");

    // ---- zero hashes ----
    let zeros = zero_hashes(cfg);
    println!("  /// zeros[0..32]: zeros[0] = 0, zeros[i+1] = compress(zeros[i], zeros[i]).");
    println!("  public let zeros : [Nat] = [{}];", nat_list(&zeros));
    println!(
        "  public let zerosHex : [Text] = [{}];",
        zeros.iter().map(|z| format!("\"{}\"", f_to_hex(z))).collect::<Vec<_>>().join(", ")
    );

    // ---- sequential frontier: 400 appends from the empty tree ----
    let mut tree = IncrementalTree::new(cfg);
    let mut leaves: Vec<F> = Vec::new();
    let mut roots: Vec<F> = Vec::new();
    let mut dense_checks: Vec<(usize, F)> = Vec::new();
    for i in 0..400usize {
        let leaf = if i < e.len() { e[i] } else { rng.field() };
        leaves.push(leaf);
        roots.push(tree.append(cfg, leaf));
        if matches!(i, 0 | 1 | 2 | 3 | 15 | 99 | 399) {
            let dense = DenseTree { leaves: leaves.clone() };
            let d = dense.root(cfg);
            assert_eq!(d, roots[i], "dense cross-check at {i}");
            dense_checks.push((i + 1, d));
        }
    }
    println!("  /// leaf i appended to the empty tree in order; seqRoots[i] = root after.");
    println!("  public let seqLeaves : [Nat] = [{}];", nat_list(&leaves));
    println!("  public let seqRoots : [Nat] = [{}];", nat_list(&roots));
    println!(
        "  public let seqRootsHex : [Text] = [{}];",
        roots.iter().map(|r| format!("\"{}\"", f_to_hex(r))).collect::<Vec<_>>().join(", ")
    );
    println!("  /// (leafCount, root) recomputed independently by DenseTree.");
    println!("  public let denseCheck : [(Nat, Nat)] = [");
    for (n, root) in &dense_checks {
        println!("    ({}, {}),", n, dec(root));
    }
    println!("  ];");

    // ---- synthetic frontiers: arbitrary filled/next_index, 1 or 2 appends ----
    // Exercises every left/right branch pattern of the 32-level walk, including the
    // near-full indices a sequential run can never reach.
    let max_index = (1u64 << TREE_DEPTH) - 1;
    let mut synth_indices: Vec<u64> = vec![
        0, 1, 2, 3, 0x5555_5555, 0xAAAA_AAAA / 2 * 2, 0x7FFF_FFFF, 0x8000_0000,
        max_index - 2, max_index - 1,
    ];
    for _ in 0..38 {
        synth_indices.push(rng.next() % (max_index - 1));
    }
    println!("  /// (filledIn[32], nextIndexIn, leaves[1|2], filledOut[32], nextIndexOut,");
    println!("  ///  rootOut, rootOutHex) — appends on an arbitrary frontier state, exactly");
    println!("  /// the oracle's `append(state, leaves)` semantics.");
    println!("  public let synth : [([Nat], Nat, [Nat], [Nat], Nat, Nat, Text)] = [");
    for (i, next_index) in synth_indices.iter().enumerate() {
        let filled: Vec<F> = (0..TREE_DEPTH).map(|_| rng.field()).collect();
        let n_leaves = if i % 2 == 0 { 2 } else { 1 };
        let leaves: Vec<F> = (0..n_leaves).map(|_| rng.field()).collect();
        let mut t = IncrementalTree {
            filled: filled.clone(),
            zeros: zeros.clone(),
            next_index: *next_index,
            root: F::zero(),
        };
        let mut root = F::zero();
        for leaf in &leaves {
            root = t.append(cfg, *leaf);
        }
        println!(
            "    ([{}], {}, [{}], [{}], {}, {}, \"{}\"),",
            nat_list(&filled),
            next_index,
            nat_list(&leaves),
            nat_list(&t.filled),
            t.next_index,
            dec(&root),
            f_to_hex(&root)
        );
    }
    println!("  ];");
    println!("}}");
}

fn emit_summary(cfg: &PoseidonCfg<F>, seed: u64) {
    let zeros = zero_hashes(cfg);
    println!("modulus_dec={}", F::MODULUS);
    println!("modulus_bits={}", F::MODULUS_BIT_SIZE);
    println!("full_rounds={} partial_rounds={} alpha={} rate={} capacity={}",
        cfg.full_rounds, cfg.partial_rounds, cfg.alpha, cfg.rate, cfg.capacity);
    println!("ark_rows={} mds_rows={}", cfg.ark.len(), cfg.mds.len());
    println!("ark[0][0]={}", dec(&cfg.ark[0][0]));
    println!("mds[0][0]={}", dec(&cfg.mds[0][0]));
    println!("zeros[1]={}", dec(&zeros[1]));
    println!("zeros[32]={}", dec(&zeros[32]));
    println!("zeros[32]_hex={}", f_to_hex(&zeros[32]));
    println!("compress(1,2)={}", dec(&merkle_compress(cfg, F::from(1u64), F::from(2u64))));
    let mut rng = SplitMix(seed);
    let (a, b) = (rng.field(), rng.field());
    println!("first_seeded_pair=({}, {})", dec(&a), dec(&b));
    println!("compress(first_seeded_pair)={}", dec(&merkle_compress(cfg, a, b)));
}

fn main() {
    let cfg = poseidon_config();
    let args: Vec<String> = std::env::args().collect();
    let usage = "usage: frontier-oracle <constants | vectors <seed> <name> | summary <seed>>";
    match args.get(1).map(String::as_str) {
        Some("constants") => {
            self_check(&cfg, 0xE9);
            emit_constants(&cfg);
        }
        Some("vectors") => {
            let seed = u64::from_str_radix(
                args.get(2).expect(usage).trim_start_matches("0x"), 16,
            ).expect("seed must be hex");
            let name = args.get(3).expect(usage);
            self_check(&cfg, seed);
            emit_vectors(&cfg, seed, name);
        }
        Some("summary") => {
            let seed = u64::from_str_radix(
                args.get(2).expect(usage).trim_start_matches("0x"), 16,
            ).expect("seed must be hex");
            self_check(&cfg, seed);
            emit_summary(&cfg, seed);
        }
        _ => {
            eprintln!("{usage}");
            std::process::exit(2);
        }
    }
}
