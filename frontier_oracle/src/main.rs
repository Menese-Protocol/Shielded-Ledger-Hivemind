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
//! TWO POSEIDON INSTANCES, and keeping them apart is the whole game:
//!   * the NOTE instance, t = 3 (rate 2, capacity 1) — pk / nf / cm, via `hash_n`;
//!   * the TREE instance, t = 6 (rate 5, capacity 1) — one permutation absorbs a whole
//!     5-ary row with the domain tag in the capacity.
//! They are separate `PoseidonConfig` values with different round constants and a
//! different MDS, so a note image and a tree node cannot collide by construction. In
//! Rust the `TreeCfg` newtype makes handing one to the other's function a compile
//! error; this oracle emits both tables so the Motoko port can be held to the same line.
//!
//! Subcommands:
//!   constants            → Motoko module with both instances' ARK/MDS (canonical + Montgomery)
//!   vectors <seed> <name>→ Motoko fixture module with perm/permTree/hashN/compress/zeros/
//!                          sequential-frontier/synthetic-frontier vectors
//!   summary <seed>       → digest counts + a few spot values (for the evidence log)
//!
//! Menese DeFi Team.

use ark_bls12_381::Fr as F;
use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
use ark_crypto_primitives::sponge::{DuplexSpongeMode, FieldBasedCryptographicSponge};
use ark_ff::{BigInteger, PrimeField, Zero};
use common::{
    f_to_hex, hash_n, merkle_compress, poseidon_config, poseidon_config_tree, zero_hashes,
    DenseTree, IncrementalTree, PoseidonCfg, TreeCfg, TAG_MERGE, TREE_ARITY, TREE_CAPACITY,
    TREE_LEVELS,
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

/// Run the REAL arkworks permutation once on an arbitrary state of ANY width.
///
/// State layout is [capacity | rate], capacity = 1 for both instances, so the width is
/// 3 for the note instance and 6 for the tree instance. `squeeze_native_field_elements`
/// in Absorbing mode performs exactly one `permute()` then copies out of the rate
/// section; the mutated public `state` is the full output.
///
/// Width is taken from the state slice rather than a const generic ON PURPOSE: passing a
/// width-3 state with the tree config (or the reverse) must be caught, and the assertion
/// below against `cfg.rate + cfg.capacity` is what catches it. A const generic would have
/// let the caller name a width the config does not have.
fn permute_state(cfg: &PoseidonCfg<F>, s: &[F]) -> Vec<F> {
    assert_eq!(
        s.len(),
        cfg.rate + cfg.capacity,
        "state width does not match this Poseidon instance (rate {} + capacity {})",
        cfg.rate,
        cfg.capacity
    );
    let mut sponge = PoseidonSponge::<F> {
        parameters: cfg.clone(),
        state: s.to_vec(),
        mode: DuplexSpongeMode::Absorbing {
            next_absorb_index: cfg.rate,
        },
    };
    let out = sponge.squeeze_native_field_elements(1);
    assert_eq!(out[0], sponge.state[cfg.capacity], "squeeze/state layout drift");
    sponge.state.clone()
}

fn edge_values() -> Vec<F> {
    vec![
        F::zero(),
        F::from(1u64),
        F::from(2u64),
        -F::from(1u64), // p-1, i.e. -1 reduced mod the field modulus
        -F::from(2u64), // p-2
        F::from(u64::MAX),
        F::from(u64::MAX) + F::from(1u64), // 2^64
    ]
}

/// Edge-heavy 5-ary rows: every edge value repeated across the whole row, then every edge
/// value alone in each of the ARITY slots with zeros elsewhere. The second family is what
/// catches a lane-indexing error — a row that is all-identical looks correct under almost
/// any permutation of the slots, so it cannot detect one on its own.
fn edge_rows() -> Vec<[F; TREE_ARITY]> {
    let e = edge_values();
    let mut rows = Vec::new();
    for v in &e {
        rows.push([*v; TREE_ARITY]);
    }
    for v in &e {
        for slot in 0..TREE_ARITY {
            let mut row = [F::zero(); TREE_ARITY];
            row[slot] = *v;
            rows.push(row);
        }
    }
    rows
}

/// In-binary cross-checks tying every exposed vector family to a second independent
/// arkworks path. Panics (exit != 0) on any disagreement.
fn self_check(cfg: &PoseidonCfg<F>, cfg_tree: &TreeCfg, seed: u64) {
    // 0. The two instances must genuinely differ. The domain-separation argument for
    //    "a note image cannot collide with a tree node" rests on different round
    //    constants and a different MDS, not only on the tag — so assert it rather than
    //    assume it. A refactor that accidentally derived both from the same rate would
    //    otherwise pass every other check in this file.
    assert_eq!(cfg.rate, 2, "note instance must be rate 2");
    assert_eq!(cfg_tree.0.rate, TREE_ARITY, "tree instance rate must equal the arity");
    assert_ne!(cfg.ark[0][0], cfg_tree.0.ark[0][0], "instances share round constants");
    assert_ne!(cfg.mds[0][0], cfg_tree.0.mds[0][0], "instances share an MDS");

    // 1. permute() extraction agrees with the sponge on compress inputs:
    //    merkle_compress initialises the CAPACITY lane with TAG_MERGE and absorbs exactly
    //    the ARITY children, so the state entering the single permutation is
    //    [TAG_MERGE, c0..c4] and rate lane 0 is squeezed out. Verified here against a
    //    raw-permute path independent of the merkle_compress definition — this check is
    //    what catches a capacity/rate mix-up, so it must be written from the schedule and
    //    never by calling the thing under test.
    let mut rng = SplitMix(seed ^ 0xc0ffee);
    for _ in 0..200 {
        let row: [F; TREE_ARITY] = core::array::from_fn(|_| rng.field());
        let mut state = vec![F::from(TAG_MERGE)];
        state.extend_from_slice(&row);
        let via_perm = permute_state(&cfg_tree.0, &state)[cfg_tree.0.capacity];
        assert_eq!(via_perm, merkle_compress(cfg_tree, &row), "perm vs compress");
    }
    // 2. hash_n on 3..6 inputs equals a chain of raw permutes (verifies the duplex
    //    absorb schedule AND that the capacity element survives extraction).
    for k in 3..=6usize {
        for _ in 0..50 {
            let inputs: Vec<F> = (0..k).map(|_| rng.field()).collect();
            let mut state = vec![F::zero(); cfg.rate + cfg.capacity];
            let mut idx = 0usize;
            for x in &inputs {
                if idx == cfg.rate {
                    state = permute_state(cfg, &state);
                    idx = 0;
                }
                state[cfg.capacity + idx] += x;
                idx += 1;
            }
            state = permute_state(cfg, &state);
            assert_eq!(state[1], hash_n(cfg, &inputs), "duplex chain vs hash_n k={k}");
        }
    }
    // 3. IncrementalTree agrees with DenseTree (two independent tree recomputations).
    let mut tree = IncrementalTree::new(cfg_tree);
    let mut leaves = Vec::new();
    for i in 0..300u64 {
        let leaf = rng.field();
        leaves.push(leaf);
        let inc_root = tree.append(cfg_tree, leaf);
        if matches!(i, 0 | 1 | 2 | 4 | 15 | 63 | 128 | 299) {
            let dense = DenseTree { leaves: leaves.clone() };
            assert_eq!(inc_root, dense.root(cfg_tree), "incremental vs dense at {i}");
        }
    }
    // 3b. A path opens against the root it came from. This is the property the circuit's
    //     membership constraints enforce, checked natively: rebuilding upward through the
    //     returned rows, substituting the walked node at its stated position, must land on
    //     the dense root. It is what catches a row/position off-by-one that check 3 cannot
    //     see, because check 3 never opens anything.
    let dense = DenseTree { leaves: leaves.clone() };
    let dense_root = dense.root(cfg_tree);
    for &idx in &[0usize, 1, 4, 5, 24, 125, 299] {
        let (rows, positions) = dense.path(cfg_tree, idx);
        assert_eq!(rows.len(), TREE_LEVELS, "path row count");
        assert_eq!(positions.len(), TREE_LEVELS, "path position count");
        let mut cur = leaves[idx];
        for (row, pos) in rows.iter().zip(&positions) {
            assert!(*pos < TREE_ARITY, "position out of range");
            assert_eq!(row[*pos], cur, "walked node is not at its stated position");
            cur = merkle_compress(cfg_tree, row);
        }
        assert_eq!(cur, dense_root, "path does not open to the root at leaf {idx}");
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

/// Emit one instance's four tables. `prefix` names the instance (NOTE / TREE) and `width`
/// is the sponge width t, which is also the ARK row length and the MDS dimension — it is
/// printed into the index arithmetic in the doc comments so the Motoko side cannot guess
/// the stride wrong.
fn emit_instance_tables(cfg: &PoseidonCfg<F>, prefix: &str, width: usize) {
    println!(
        "  /// ARK_{prefix}[round][lane], {} rounds x width {width}, decimal canonical.",
        cfg.ark.len()
    );
    println!("  public let ARK_{prefix} : [[Nat]] = [");
    for row in &cfg.ark {
        println!("    [{}],", row.iter().map(dec).collect::<Vec<_>>().join(", "));
    }
    println!("  ];");
    println!("  /// MDS_{prefix}[i][j], {width} x {width}.");
    println!("  public let MDS_{prefix} : [[Nat]] = [");
    for row in &cfg.mds {
        println!("    [{}],", row.iter().map(dec).collect::<Vec<_>>().join(", "));
    }
    println!("  ];");
    println!("  /// ARK_{prefix} in Montgomery form (a·2^256 mod r), flat 8×32-bit LE limbs:");
    println!("  /// ARK_{prefix}_MONT[(round*{width} + lane)*8 ..+8]. Raw arkworks internal repr —");
    println!("  /// the exact operand form of the ledger's FrFlat CIOS (R = 2^256 on both sides).");
    println!("  public let ARK_{prefix}_MONT : [Nat32] = [");
    for row in &cfg.ark {
        for x in row {
            println!("    {},", nat32_list(&mont_limbs32(x)));
        }
    }
    println!("  ];");
    println!("  /// MDS_{prefix} in Montgomery form, flat limbs: MDS_{prefix}_MONT[(i*{width} + j)*8 ..+8].");
    println!("  public let MDS_{prefix}_MONT : [Nat32] = [");
    for row in &cfg.mds {
        for x in row {
            println!("    {},", nat32_list(&mont_limbs32(x)));
        }
    }
    println!("  ];");
}

fn emit_constants(cfg: &PoseidonCfg<F>, cfg_tree: &TreeCfg) {
    println!("/// GENERATED by frontier_oracle `constants` — DO NOT EDIT BY HAND.");
    println!("/// Poseidon over BLS12-381 Fr, TWO instances, both 8 full + 57 partial rounds,");
    println!("/// alpha = 5, from arkworks ark-crypto-primitives 0.5.0 (Grain LFSR):");
    println!("///");
    println!("///   NOTE  t = 3 (rate 2, capacity 1) — `find_poseidon_ark_and_mds::<Fr>(255, 2, 8, 57, 0)`");
    println!("///         the pk / nf / cm images, via `hashN`.");
    println!("///   TREE  t = 6 (rate {TREE_ARITY}, capacity 1) — `find_poseidon_ark_and_mds::<Fr>(255, {TREE_ARITY}, 8, 57, 0)`");
    println!("///         one permutation per {TREE_ARITY}-ary Merkle row, domain tag in the capacity.");
    println!("///");
    println!("/// The two sets are DIFFERENT round constants and a DIFFERENT MDS. That — not the");
    println!("/// domain tag alone — is why a note image and a tree node cannot collide. Never");
    println!("/// feed one instance's tables to the other's permutation; the widths differ, so the");
    println!("/// stride arithmetic above is the only thing standing between you and a silent");
    println!("/// wrong tree. Mirrors `poseidon_config()` / `poseidon_config_tree()` in");
    println!("/// `vendor/tree_common`. Menese DeFi Team.");
    println!("module {{");
    emit_instance_tables(cfg, "NOTE", cfg.rate + cfg.capacity);
    emit_instance_tables(&cfg_tree.0, "TREE", cfg_tree.0.rate + cfg_tree.0.capacity);
    println!("}}");
}

fn nat_list(v: &[F]) -> String {
    v.iter().map(dec).collect::<Vec<_>>().join(", ")
}

/// A frontier's `filled` flattened row-major: index `lvl * TREE_ARITY + j`. This is the
/// wire shape too (`tree_oracle`'s `TreeState.filled`), so the Motoko side, the oracle
/// canister and these fixtures all index it identically.
fn flat_filled(filled: &[[F; TREE_ARITY]]) -> Vec<F> {
    filled.iter().flat_map(|row| row.iter().copied()).collect()
}

fn emit_vectors(cfg: &PoseidonCfg<F>, cfg_tree: &TreeCfg, seed: u64, name: &str) {
    let mut rng = SplitMix(seed);
    println!("/// GENERATED by frontier_oracle `vectors {seed:#x} {name}` — DO NOT EDIT.");
    println!("/// Every expected output produced by arkworks 0.5.0 via vendor/tree_common");
    println!("/// (--features bls12-381). Menese DeFi Team.");
    println!("module {{");

    // ---- raw permutation vectors, NOTE instance (t = 3) ----
    let e = edge_values();
    let mut perm_inputs: Vec<[F; 3]> = Vec::new();
    perm_inputs.push([F::zero(), F::zero(), F::zero()]);
    perm_inputs.push([e[3], e[3], e[3]]);
    perm_inputs.push([F::zero(), F::from(1u64), F::from(2u64)]);
    for _ in 0..250 {
        perm_inputs.push([rng.field(), rng.field(), rng.field()]);
    }
    println!("  /// NOTE instance (t=3): (in0..in2, out0..out2) — one full 65-round permutation.");
    println!("  public let perm : [(Nat, Nat, Nat, Nat, Nat, Nat)] = [");
    for s in &perm_inputs {
        let o = permute_state(cfg, s);
        println!(
            "    ({}, {}, {}, {}, {}, {}),",
            dec(&s[0]), dec(&s[1]), dec(&s[2]), dec(&o[0]), dec(&o[1]), dec(&o[2])
        );
    }
    println!("  ];");

    // ---- raw permutation vectors, TREE instance (t = 6) ----
    // The Motoko width-6 permutation is verified against these BEFORE anything that uses
    // it (compress, zeros, append) is trusted — bottom of the tower first.
    let width = cfg_tree.0.rate + cfg_tree.0.capacity;
    let mut perm_tree_inputs: Vec<Vec<F>> = Vec::new();
    perm_tree_inputs.push(vec![F::zero(); width]);
    perm_tree_inputs.push(vec![e[3]; width]);
    perm_tree_inputs.push((0..width).map(|i| F::from(i as u64)).collect());
    // One edge value alone in each lane: catches a lane-indexing error that an
    // all-identical state cannot.
    for v in &e {
        for lane in 0..width {
            let mut s = vec![F::zero(); width];
            s[lane] = *v;
            perm_tree_inputs.push(s);
        }
    }
    for _ in 0..200 {
        perm_tree_inputs.push((0..width).map(|_| rng.field()).collect());
    }
    println!("  /// TREE instance (t=6): (inputs[6], outputs[6]) — one full 65-round permutation.");
    println!("  public let permTree : [([Nat], [Nat])] = [");
    for s in &perm_tree_inputs {
        let o = permute_state(&cfg_tree.0, s);
        println!("    ([{}], [{}]),", nat_list(s), nat_list(&o));
    }
    println!("  ];");

    // ---- sponge hash_n vectors, NOTE instance, k = 1..6 ----
    println!("  /// (inputs, expected hash_n output) — arkworks PoseidonSponge absorb/squeeze.");
    println!("  public let hashN : [([Nat], Nat)] = [");
    for k in 1..=6usize {
        let edge_in: Vec<F> = e.iter().take(k).cloned().collect();
        println!("    ([{}], {}),", nat_list(&edge_in), dec(&hash_n(cfg, &edge_in)));
        for _ in 0..12 {
            let inputs: Vec<F> = (0..k).map(|_| rng.field()).collect();
            println!("    ([{}], {}),", nat_list(&inputs), dec(&hash_n(cfg, &inputs)));
        }
    }
    println!("  ];");

    // ---- merkle_compress vectors: ARITY children in, one node out ----
    let mut rows: Vec<[F; TREE_ARITY]> = edge_rows();
    for _ in 0..350 {
        rows.push(core::array::from_fn(|_| rng.field()));
    }
    println!("  /// (children[{TREE_ARITY}], merkle_compress(children)).");
    println!("  public let compress : [([Nat], Nat)] = [");
    for row in &rows {
        println!("    ([{}], {}),", nat_list(row), dec(&merkle_compress(cfg_tree, row)));
    }
    println!("  ];");

    // ---- zero hashes ----
    let zeros = zero_hashes(cfg_tree);
    println!("  /// zeros[0..{TREE_LEVELS}]: zeros[0] = 0, zeros[i+1] = compress([zeros[i]; {TREE_ARITY}]).");
    println!("  public let zeros : [Nat] = [{}];", nat_list(&zeros));
    println!(
        "  public let zerosHex : [Text] = [{}];",
        zeros.iter().map(|z| format!("\"{}\"", f_to_hex(z))).collect::<Vec<_>>().join(", ")
    );

    // ---- sequential frontier: 400 appends from the empty tree ----
    let mut tree = IncrementalTree::new(cfg_tree);
    let mut leaves: Vec<F> = Vec::new();
    let mut roots: Vec<F> = Vec::new();
    let mut dense_checks: Vec<(usize, F)> = Vec::new();
    for i in 0..400usize {
        let leaf = if i < e.len() { e[i] } else { rng.field() };
        leaves.push(leaf);
        roots.push(tree.append(cfg_tree, leaf));
        if matches!(i, 0 | 1 | 2 | 3 | 15 | 99 | 399) {
            let dense = DenseTree { leaves: leaves.clone() };
            let d = dense.root(cfg_tree);
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
    // Exercises every slot pattern of the 14-level walk, including the near-full indices
    // a sequential run can never reach. `filled` is flattened row-major, 14*5 = 70 entries.
    let max_index = TREE_CAPACITY - 1;
    let mut synth_indices: Vec<u64> = vec![
        0, 1, 2, 3, 4, 5, 24, 0x5555_5555, 0x7FFF_FFFF, 0x8000_0000,
        max_index - 2, max_index - 1,
    ];
    for _ in 0..38 {
        synth_indices.push(rng.next() % (max_index - 1));
    }
    println!("  /// (filledIn[{}], nextIndexIn, leaves[1|2], filledOut[{}], nextIndexOut,",
        TREE_LEVELS * TREE_ARITY, TREE_LEVELS * TREE_ARITY);
    println!("  ///  rootOut, rootOutHex) — appends on an arbitrary frontier state, exactly");
    println!("  /// the oracle's `append(state, leaves)` semantics. `filled` is row-major:");
    println!("  /// index lvl*{TREE_ARITY} + j.");
    println!("  public let synth : [([Nat], Nat, [Nat], [Nat], Nat, Nat, Text)] = [");
    for (i, next_index) in synth_indices.iter().enumerate() {
        let filled: Vec<[F; TREE_ARITY]> = (0..TREE_LEVELS)
            .map(|_| core::array::from_fn(|_| rng.field()))
            .collect();
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
            root = t.append(cfg_tree, *leaf);
        }
        println!(
            "    ([{}], {}, [{}], [{}], {}, {}, \"{}\"),",
            nat_list(&flat_filled(&filled)),
            next_index,
            nat_list(&leaves),
            nat_list(&flat_filled(&t.filled)),
            t.next_index,
            dec(&root),
            f_to_hex(&root)
        );
    }
    println!("  ];");
    println!("}}");
}

fn emit_summary(cfg: &PoseidonCfg<F>, cfg_tree: &TreeCfg, seed: u64) {
    let zeros = zero_hashes(cfg_tree);
    println!("modulus_dec={}", F::MODULUS);
    println!("modulus_bits={}", F::MODULUS_BIT_SIZE);
    println!("arity={TREE_ARITY} levels={TREE_LEVELS} capacity={TREE_CAPACITY}");
    println!("note: full_rounds={} partial_rounds={} alpha={} rate={} capacity={}",
        cfg.full_rounds, cfg.partial_rounds, cfg.alpha, cfg.rate, cfg.capacity);
    println!("tree: full_rounds={} partial_rounds={} alpha={} rate={} capacity={}",
        cfg_tree.0.full_rounds, cfg_tree.0.partial_rounds, cfg_tree.0.alpha,
        cfg_tree.0.rate, cfg_tree.0.capacity);
    println!("note ark_rows={} mds_rows={}", cfg.ark.len(), cfg.mds.len());
    println!("tree ark_rows={} mds_rows={}", cfg_tree.0.ark.len(), cfg_tree.0.mds.len());
    println!("note ark[0][0]={}", dec(&cfg.ark[0][0]));
    println!("tree ark[0][0]={}", dec(&cfg_tree.0.ark[0][0]));
    println!("note mds[0][0]={}", dec(&cfg.mds[0][0]));
    println!("tree mds[0][0]={}", dec(&cfg_tree.0.mds[0][0]));
    println!("zeros[1]={}", dec(&zeros[1]));
    println!("zeros[{TREE_LEVELS}]={}", dec(&zeros[TREE_LEVELS]));
    println!("zeros[{TREE_LEVELS}]_hex={}", f_to_hex(&zeros[TREE_LEVELS]));
    let ones: [F; TREE_ARITY] = core::array::from_fn(|i| F::from(i as u64 + 1));
    println!("compress(1..{TREE_ARITY})={}", dec(&merkle_compress(cfg_tree, &ones)));
    let mut rng = SplitMix(seed);
    let row: [F; TREE_ARITY] = core::array::from_fn(|_| rng.field());
    println!("first_seeded_row=({})", nat_list(&row));
    println!("compress(first_seeded_row)={}", dec(&merkle_compress(cfg_tree, &row)));
}

/// Canonicality classification, arkworks as the source of truth.
///
/// `f_from_hex` is `Fr::deserialize_compressed`, which rejects any encoding at or above the
/// modulus. It is the EXACT field the circuits and the verifier use, so this is a differential
/// against the real thing rather than against a second reading of the spec.
///
/// Byte order is little-endian on both sides, and that is pinned here rather than assumed:
/// arkworks serialises least-significant-first, and `PoseidonTree.hexToNat` multiplies the first
/// byte read by `shift = 1`. `p_minus_one_le` and `p_be` are the asymmetric pair — the same
/// number in the two orders, classified differently — so a flip on either side fails loudly.
///
/// `--red` disables the modulus check and accepts anything that is 32 well-formed bytes. The
/// differential MUST fail under it; a red run that still agrees means the battery has no teeth.
fn emit_canonical(red: bool) {
    let modulus_le: Vec<u8> = F::MODULUS.to_bytes_le();
    let hex_of = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();

    let mut p_minus_1 = modulus_le.clone();
    p_minus_1[0] -= 1; // the modulus ends in ...01, so this cannot borrow
    let mut p_plus_1 = modulus_le.clone();
    p_plus_1[0] += 1;
    let mut p_be = modulus_le.clone();
    p_be.reverse();

    let mut one = [0u8; 32];
    one[0] = 1;

    let corpus: Vec<(&str, String)> = vec![
        ("zero", hex_of(&[0u8; 32])),
        ("one", hex_of(&one)),
        ("p_minus_one_le", hex_of(&p_minus_1)),
        ("p_le", hex_of(&modulus_le)),
        ("p_plus_one_le", hex_of(&p_plus_1)),
        ("all_ff", hex_of(&[0xffu8; 32])),
        ("p_be", hex_of(&p_be)),
        ("random_canonical", f_to_hex(&SplitMix(0xCA11).field())),
        ("short", "00".to_string()),
        ("odd_nibbles", "0".repeat(63)),
    ];

    println!("# canonicality corpus — arkworks ark_bls12_381::Fr, little-endian");
    println!("# red={red}");
    println!("modulus_dec={}", F::MODULUS);
    let (mut acc, mut rej) = (0usize, 0usize);
    for (name, hexval) in &corpus {
        let canonical = if red {
            // RED: shape only — 32 well-formed bytes, no modulus check at all.
            hexval.len() == 64 && hexval.chars().all(|c| c.is_ascii_hexdigit())
        } else {
            common::f_from_hex(hexval).is_some()
        };
        if canonical { acc += 1 } else { rej += 1 }
        println!("{name} {hexval} {}", if canonical { "CANONICAL" } else { "NON-CANONICAL" });
    }
    println!("census accepted={acc} rejected={rej}");
    if acc == 0 || rej == 0 {
        eprintln!("VACUOUS CORPUS: need at least one of each (accepted={acc} rejected={rej})");
        std::process::exit(3);
    }
}

/// Native cost of one permutation of each instance, and of a whole append.
///
/// This exists because the arity trade-off runs in OPPOSITE directions on the two sides,
/// and only the circuit side had ever been measured. In-circuit the MDS matrix-vector
/// product is free — it is a linear combination, and R1CS charges nothing for those — so
/// a level costs only its S-boxes (8t + R_P of them). NATIVELY the MDS is t^2 field
/// multiplications and dominates everything, so widening the sponge makes each level
/// dramatically more expensive while the level count only falls logarithmically.
///
/// The ledger runs the native side on every append. Measure, do not assume.
fn emit_bench(cfg: &PoseidonCfg<F>, cfg_tree: &TreeCfg) {
    use std::time::Instant;
    let mut rng = SplitMix(0xBE0C);

    // Per-permutation: one note permutation vs one tree permutation.
    let note_state: Vec<F> = (0..cfg.rate + cfg.capacity).map(|_| rng.field()).collect();
    let tree_state: Vec<F> = (0..cfg_tree.0.rate + cfg_tree.0.capacity).map(|_| rng.field()).collect();
    const N: u32 = 20_000;
    let t0 = Instant::now();
    for _ in 0..N { std::hint::black_box(permute_state(cfg, &note_state)); }
    let note_ns = t0.elapsed().as_nanos() as f64 / N as f64;
    let t0 = Instant::now();
    for _ in 0..N { std::hint::black_box(permute_state(&cfg_tree.0, &tree_state)); }
    let tree_ns = t0.elapsed().as_nanos() as f64 / N as f64;

    // Analytic multiplication counts: 65 rounds of a dense t*t MDS, plus 3 mults per
    // S-box (x^5 = two squarings and a multiply).
    let mults = |t: usize, rp: usize, rf: usize| 65 * t * t + 3 * (rf * t + rp);
    let m_note = mults(cfg.rate + cfg.capacity, cfg.partial_rounds, cfg.full_rounds);
    let m_tree = mults(cfg_tree.0.rate + cfg_tree.0.capacity, cfg_tree.0.partial_rounds, cfg_tree.0.full_rounds);

    println!("per-permutation  note(t={}) {:.0} ns   tree(t={}) {:.0} ns   ratio {:.2}x",
        cfg.rate + cfg.capacity, note_ns, cfg_tree.0.rate + cfg_tree.0.capacity, tree_ns, tree_ns / note_ns);
    println!("analytic mults   note {m_note}   tree {m_tree}   ratio {:.2}x", m_tree as f64 / m_note as f64);

    // Whole append: 2-ary needed 32 levels, this tree needs TREE_LEVELS.
    let binary_levels = 32usize;
    println!("append (native)  2-ary {} perms x {:.0} ns = {:.1} us",
        binary_levels, note_ns, binary_levels as f64 * note_ns / 1000.0);
    println!("append (native)  {}-ary {} perms x {:.0} ns = {:.1} us   => {:.2}x vs 2-ary",
        TREE_ARITY, TREE_LEVELS, tree_ns, TREE_LEVELS as f64 * tree_ns / 1000.0,
        (TREE_LEVELS as f64 * tree_ns) / (binary_levels as f64 * note_ns));

    // In-circuit, for contrast: S-boxes only.
    let sboxes = |t: usize, rp: usize, rf: usize| rf * t + rp;
    let s_note = sboxes(3, cfg.partial_rounds, cfg.full_rounds);
    let s_tree = sboxes(cfg_tree.0.rate + cfg_tree.0.capacity, cfg_tree.0.partial_rounds, cfg_tree.0.full_rounds);
    println!("in-circuit       2-ary {} sbox x {} lvl = {}   {}-ary {} sbox x {} lvl = {}   => {:.2}x WIN",
        s_note, binary_levels, s_note * binary_levels,
        TREE_ARITY, s_tree, TREE_LEVELS, s_tree * TREE_LEVELS,
        (s_note * binary_levels) as f64 / (s_tree * TREE_LEVELS) as f64);
}

fn main() {
    let cfg = poseidon_config();
    let cfg_tree = poseidon_config_tree();
    let args: Vec<String> = std::env::args().collect();
    let usage = "usage: frontier-oracle <constants | vectors <seed> <name> | summary <seed> | bench | canonical [--red]>";
    match args.get(1).map(String::as_str) {
        Some("constants") => {
            self_check(&cfg, &cfg_tree, 0xE9);
            emit_constants(&cfg, &cfg_tree);
        }
        Some("vectors") => {
            let seed = u64::from_str_radix(
                args.get(2).expect(usage).trim_start_matches("0x"), 16,
            ).expect("seed must be hex");
            let name = args.get(3).expect(usage);
            self_check(&cfg, &cfg_tree, seed);
            emit_vectors(&cfg, &cfg_tree, seed, name);
        }
        Some("bench") => {
            emit_bench(&cfg, &cfg_tree);
        }
        Some("canonical") => {
            emit_canonical(args.get(2).map(String::as_str) == Some("--red"));
        }
        Some("summary") => {
            let seed = u64::from_str_radix(
                args.get(2).expect(usage).trim_start_matches("0x"), 16,
            ).expect("seed must be hex");
            self_check(&cfg, &cfg_tree, seed);
            emit_summary(&cfg, &cfg_tree, seed);
        }
        _ => {
            eprintln!("{usage}");
            std::process::exit(2);
        }
    }
}
