//! Shared crypto for the shielded-pool prototype: Poseidon parameters, note/nullifier
//! derivations, the incremental commitment tree, and the R1CS circuits (transfer + deposit).
//!
//! Clean-room, shaped after the published designs it cites:
//! - note commitment + nullifier + anchor model: Zcash protocol spec (Sapling/Orchard, §3.2, §4.16)
//! - rho-chaining (output note's rho := nullifier of an input note in the same transfer):
//!   Orchard's Faerie-Gold defence (Zcash spec §4.7.3)
//! - incremental tree with cached filled subtrees: Tornado Cash MerkleTreeWithHistory shape
//!   (re-derived here from the description; Tornado's code is GPL-3.0 and none of it is used)
//! - conservation-in-one-circuit with fixed arity + 64-bit range checks: Aztec join-split shape.
//!
//! Domain separation: every note-level hash absorbs a leading tag (1=pk, 2=nf, 3=cm) and Merkle
//! inner nodes absorb their own leading tag (4=merge), so a node hash lives in a distinct domain
//! from every note-level image AND from a bare 2-input hash. Leaves are already hash images and the
//! tree depth is fixed, so a node value could never be opened as a note commitment even without the
//! tag (that would need a Poseidon preimage); the merge tag makes the separation structural rather
//! than a consequence of arity, matching the explicit personalization used by production designs.

// Curve selection: default BN254 (the original PoC fixtures); `--features bls12-381` re-instantiates
// the IDENTICAL circuits over the BLS12-381 scalar field — the curve of the measured Motoko
// verifier (G10-E). One source of truth for the circuit logic; only the field alias moves.
// Poseidon: alpha=5 is a permutation over BOTH fields (gcd(5, r−1) = 1 for each), and the
// Grain-LFSR constants below regenerate from the selected field's modulus.
#[cfg(feature = "bls12-381")]
pub type ScalarField = ark_bls12_381::Fr;
#[cfg(not(feature = "bls12-381"))]
pub type ScalarField = ark_bn254::Fr;
type F = ScalarField;
use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar,
    poseidon::{
        constraints::PoseidonSpongeVar, find_poseidon_ark_and_mds, PoseidonConfig, PoseidonSponge,
    },
    CryptographicSponge,
};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar,
    boolean::Boolean,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

pub use ark_crypto_primitives::sponge::poseidon::PoseidonConfig as PoseidonCfg;

/// Merkle arity. A 4-ary tree reaches the 2^32 leaf capacity in 16 levels instead of 32, and a
/// level costs one width-5 permutation instead of one width-3 permutation.
///
/// THE TRADE RUNS IN OPPOSITE DIRECTIONS ON THE TWO SIDES, and only one of them had been
/// measured when the arity was first raised. In-circuit the MDS matrix-vector product is a
/// linear combination, which R1CS charges nothing for, so a level costs only its S-boxes
/// (`R_F*t + R_P`) and widening is close to free: 32 levels x 81 = 2,592 S-boxes at t=3
/// against 16 x 97 = 1,552 at t=5, a 1.67x win. NATIVELY the MDS is t^2 field multiplications
/// and dominates everything: 65*t^2 + 3*(R_F*t + R_P) is 828 mults at t=3 and 1,916 at t=5, so
/// an append goes 32 x 828 = 26,496 to 16 x 1,916 = 30,656 — a 1.16x LOSS. The ledger runs the
/// native side on every append, so that loss is real and is the price of the circuit win.
///
/// Arity 4 rather than 5 because 5 is worse on both counts that matter: it costs 37,170 native
/// mults (1.40x) for only 1,470 in-circuit S-boxes (1.76x), i.e. it buys ~5% more circuit win
/// for ~21% more on-chain work, and both land in the same 2^14 QAP domain, so the keyset — the
/// headline cold-start number — is identical either way. Measured with `frontier-oracle bench`.
pub const TREE_ARITY: usize = 4;
/// 4^16 = 2^32 EXACTLY, so 16 levels cover the addressable leaf space with nothing wasted and
/// the walk is `idx >> 2` / `idx & 3` rather than a divide. The ledger caps `next_index` at
/// 2^32 because a leaf index is a 32-bit wire value; here the tree shape agrees with that cap
/// instead of overshooting it.
pub const TREE_LEVELS: usize = 16;
/// Addressable leaves. Unchanged by the arity switch — this is a wire/interface constant, not a
/// tree-shape one, and nothing about the 4-ary layout is allowed to move it.
pub const TREE_CAPACITY: u64 = 1 << 32;

/// The tree shape must cover EXACTLY the addressable capacity — a COMPILE-TIME check, not a
/// test, because getting it wrong is not a failing assertion somewhere: it is either leaves the
/// ledger can index but the tree cannot hold (`<`, silent truncation of the top of the index
/// space) or levels that can never be reached (`>`, wasted work on every single append). At
/// arity 4 the equality is exact; any future arity change that does not also fix TREE_LEVELS
/// stops the build here rather than shipping.
const _: () = assert!(
    (TREE_ARITY as u64).pow(TREE_LEVELS as u32) == TREE_CAPACITY,
    "TREE_ARITY ^ TREE_LEVELS must equal TREE_CAPACITY exactly"
);
pub const TAG_PK: u64 = 1;
pub const TAG_NF: u64 = 2;
pub const TAG_CM: u64 = 3;
/// Domain tag carried in the sponge CAPACITY by the 2-to-1 Merkle compression, so an inner-node
/// image lives in a domain distinct from pk/nf/cm and from a bare 2-input hash.
///
/// It used to be absorbed as a leading RATE element, which separated the domain just as well but
/// cost an entire extra permutation on every Merkle level: the sponge has rate 2, so `[tag, l, r]`
/// is three absorbs = two permutations where a level needs one. Merkle paths were 86.6% of the
/// circuit, so that one wasted permutation was most of a transfer proof. Carried in the capacity
/// the tag is free: it never occupies a rate slot, and it still enters every round of the
/// permutation, which is what domain separation actually requires.
pub const TAG_MERGE: u64 = 4;

/// Poseidon over BN254 Fr: rate 2, capacity 1, 8 full + 57 partial rounds, alpha = 5.
/// Same parameter shape as the verifier-lab measurement so per-hash costs are comparable.
/// Constants derived with arkworks' Grain-LFSR routine (the Poseidon paper's method).
///
/// This is the NOTE instance — pk, nf and cm. The Merkle tree uses `poseidon_config_tree`.
pub fn poseidon_config() -> PoseidonConfig<F> {
    let (ark, mds) = find_poseidon_ark_and_mds::<F>(F::MODULUS_BIT_SIZE as u64, 2, 8, 57, 0);
    PoseidonConfig::new(8, 57, 5, mds, ark, 2, 1)
}

/// The TREE instance: width 5 (rate 4, capacity 1), so one permutation absorbs a whole 4-ary row
/// with the domain tag in the capacity.
///
/// `R_F = 8, R_P = 57` is NOT copied from the paper's table — it is what this repository's own
/// `scripts/poseidon-round-margin.py` derives for t=5 at the 128-bit target: the strict minimum
/// R_P at R_F = 8 is 50, so the shipped 57 carries a +7 partial-round margin — the SAME margin
/// the deployed t=3 instance carries, over both BLS12-381 Fr and BN254 Fr.
///
/// That script checks BOTH shipped instances on every run. It used to hardcode `t = 3` at module
/// level, so the tree width could only be checked by editing the script by hand — the very
/// "documented provenance nobody re-derives" failure the script exists to prevent, reproduced
/// inside the script itself. Fixed 2026-08-27; a future widening cannot silently skip its own
/// security argument.
///
/// Deriving both instances from the same Grain-LFSR routine at the same security target is what
/// keeps the two hashes independent: different widths produce different round constants and a
/// different MDS, so a note commitment and a tree node cannot collide by construction, quite
/// apart from the domain tag.
pub fn poseidon_config_tree() -> TreeCfg {
    let (ark, mds) = find_poseidon_ark_and_mds::<F>(F::MODULUS_BIT_SIZE as u64, TREE_ARITY, 8, 57, 0);
    TreeCfg(PoseidonConfig::new(8, 57, 5, mds, ark, TREE_ARITY, 1))
}

/// The tree instance, wrapped so it CANNOT be confused with the note instance at a call site.
///
/// Both instances are `PoseidonConfig<F>`. Before this newtype existed, handing the note config
/// to `DenseTree::root` compiled cleanly and silently computed a different tree — the anchor came
/// out wrong and the only symptom was an honest witness failing to satisfy the circuit, with
/// nothing pointing at the cause. That is exactly the class of mistake that must be impossible
/// rather than merely tested for, because the compiling-but-wrong version of it is a consensus
/// fork: the ledger and the prover would disagree about what the tree is.
#[derive(Clone, Debug)]
pub struct TreeCfg(pub PoseidonConfig<F>);

// ---------- native hashing ----------

pub fn hash_n(cfg: &PoseidonConfig<F>, inputs: &[F]) -> F {
    let mut sponge = PoseidonSponge::<F>::new(cfg);
    for x in inputs {
        sponge.absorb(x);
    }
    sponge.squeeze_field_elements(1)[0]
}

pub fn derive_pk(cfg: &PoseidonConfig<F>, nk: F) -> F {
    hash_n(cfg, &[F::from(TAG_PK), nk])
}
pub fn derive_nf(cfg: &PoseidonConfig<F>, nk: F, rho: F) -> F {
    hash_n(cfg, &[F::from(TAG_NF), nk, rho])
}
pub fn note_commitment(cfg: &PoseidonConfig<F>, v: u64, pk: F, rho: F, rcm: F) -> F {
    hash_n(cfg, &[F::from(TAG_CM), F::from(v), pk, rho, rcm])
}
/// 5-to-1 Merkle compression: the sponge is initialised with `TAG_MERGE` in the capacity lane and
/// then absorbs exactly the five children, so the state entering the single permutation is
/// `[TAG_MERGE, c0, c1, c2, c3, c4]` and lane 0 of the rate is squeezed out.
///
/// arkworks lays the state out capacity-first (`absorb_internal` writes at
/// `state[capacity + i]`) and permutes only when the rate section fills. At rate 5 the five
/// children fill it exactly, so a whole 5-ary row costs ONE permutation — the same count a
/// 2-ary row costs at rate 2, over less than half as many levels. That is where the arity win
/// comes from, and it is why this does not route through `hash_n`: `hash_n` can express neither
/// a non-zero IV nor the wider instance.
///
/// MUST stay in lockstep with `merkle_compress_gadget`, `PoseidonTree.merkleCompress` and the
/// frontier oracle. Changing one alone does not fail loudly — it silently computes a different
/// root, and every proof stops verifying against the anchor.
pub fn merkle_compress(cfg_tree: &TreeCfg, children: &[F; TREE_ARITY]) -> F {
    let mut sponge = PoseidonSponge::<F>::new(&cfg_tree.0);
    sponge.state[0] = F::from(TAG_MERGE);
    for c in children {
        sponge.absorb(c);
    }
    sponge.squeeze_field_elements(1)[0]
}

// ---------- the note ----------

#[derive(Clone, Copy, Debug)]
pub struct Note {
    pub v: u64,
    pub nk: F, // spender's nullifier key (secret); address pk = H(1, nk)
    pub rho: F,
    pub rcm: F,
}

impl Note {
    pub fn pk(&self, cfg: &PoseidonConfig<F>) -> F {
        derive_pk(cfg, self.nk)
    }
    pub fn cm(&self, cfg: &PoseidonConfig<F>) -> F {
        note_commitment(cfg, self.v, self.pk(cfg), self.rho, self.rcm)
    }
    pub fn nf(&self, cfg: &PoseidonConfig<F>) -> F {
        derive_nf(cfg, self.nk, self.rho)
    }
}

// ---------- incremental Merkle tree (append-only, O(depth) state) ----------

/// Cached zero-subtree hashes: zeros[0] = 0 (empty leaf), zeros[i+1] = H(zeros[i] x ARITY).
pub fn zero_hashes(cfg_tree: &TreeCfg) -> Vec<F> {
    let mut z = vec![F::from(0u64)];
    for i in 0..TREE_LEVELS {
        z.push(merkle_compress(cfg_tree, &[z[i]; TREE_ARITY]));
    }
    z
}

/// Append-only incremental tree. Root recomputed per append with one hash call per level.
///
/// The frontier caches ARITY-1 left siblings per level instead of one: at level `lvl` the node
/// under construction already has `idx % ARITY` completed children, and the rest of the row is
/// the empty-subtree hash for that level.
pub struct IncrementalTree {
    /// filled[lvl][j] = the j-th child already fixed at level `lvl`. Entries at or after the
    /// current position are stale and must never be read — `append` only reads j < pos.
    pub filled: Vec<[F; TREE_ARITY]>,
    pub zeros: Vec<F>,
    pub next_index: u64,
    pub root: F,
}

impl IncrementalTree {
    pub fn new(cfg_tree: &TreeCfg) -> Self {
        let zeros = zero_hashes(cfg_tree);
        IncrementalTree {
            filled: (0..TREE_LEVELS).map(|lvl| [zeros[lvl]; TREE_ARITY]).collect(),
            root: zeros[TREE_LEVELS],
            zeros,
            next_index: 0,
        }
    }

    /// Returns the new root. Panics when full (2^32 leaves — unreachable in the prototype).
    pub fn append(&mut self, cfg_tree: &TreeCfg, leaf: F) -> F {
        assert!(self.next_index < TREE_CAPACITY, "tree full");
        let mut idx = self.next_index;
        let mut cur = leaf;
        for lvl in 0..TREE_LEVELS {
            let pos = (idx % TREE_ARITY as u64) as usize;
            self.filled[lvl][pos] = cur;
            // Children before `pos` are already fixed; `pos` is the node we just carried up;
            // everything after it is still empty at this level.
            let mut row = [self.zeros[lvl]; TREE_ARITY];
            row[..=pos].copy_from_slice(&self.filled[lvl][..=pos]);
            cur = merkle_compress(cfg_tree, &row);
            idx /= TREE_ARITY as u64;
        }
        self.next_index += 1;
        self.root = cur;
        cur
    }
}

/// Native full recomputation over a small explicit leaf set — used by `gen` to build witness
/// paths and to cross-check `IncrementalTree` roots (two independent implementations must agree).
pub struct DenseTree {
    pub leaves: Vec<F>,
}

impl DenseTree {
    pub fn root(&self, cfg_tree: &TreeCfg) -> F {
        let zeros = zero_hashes(cfg_tree);
        let mut level: Vec<F> = self.leaves.clone();
        for lvl in 0..TREE_LEVELS {
            let mut next = Vec::with_capacity(level.len().div_ceil(TREE_ARITY));
            for i in 0..level.len().div_ceil(TREE_ARITY) {
                let mut row = [zeros[lvl]; TREE_ARITY];
                for (j, slot) in row.iter_mut().enumerate() {
                    if let Some(v) = level.get(TREE_ARITY * i + j) {
                        *slot = *v;
                    }
                }
                next.push(merkle_compress(cfg_tree, &row));
            }
            if next.is_empty() {
                next.push(merkle_compress(cfg_tree, &[zeros[lvl]; TREE_ARITY]));
            }
            level = next;
        }
        level[0]
    }

    /// The authentication path for leaf `index`, as one FULL ROW PER LEVEL plus the
    /// position the walked node occupies in that row.
    ///
    /// Returning the whole row (including the walked node itself) rather than ARITY-1 siblings is
    /// deliberate: in-circuit the row is what gets hashed, and the membership statement is then
    /// "the node I carried up equals row[pos]", enforced by a one-hot inner product. The
    /// alternative — ARITY-1 siblings plus an index — would force the circuit to rotate the
    /// siblings into position, which costs constraints and is easy to get subtly wrong. This is
    /// the shape `incrementalquintree` uses for the same reason.
    pub fn path(
        &self,
        cfg_tree: &TreeCfg,
        index: usize,
    ) -> (Vec<[F; TREE_ARITY]>, Vec<usize>) {
        let zeros = zero_hashes(cfg_tree);
        let mut rows = Vec::with_capacity(TREE_LEVELS);
        let mut positions = Vec::with_capacity(TREE_LEVELS);
        let mut level: Vec<F> = self.leaves.clone();
        let mut idx = index;
        for lvl in 0..TREE_LEVELS {
            let pos = idx % TREE_ARITY;
            let base = idx - pos;
            let mut row = [zeros[lvl]; TREE_ARITY];
            for (j, slot) in row.iter_mut().enumerate() {
                if let Some(v) = level.get(base + j) {
                    *slot = *v;
                }
            }
            rows.push(row);
            positions.push(pos);

            let mut next = Vec::with_capacity(level.len().div_ceil(TREE_ARITY));
            for i in 0..level.len().div_ceil(TREE_ARITY) {
                let mut r = [zeros[lvl]; TREE_ARITY];
                for (j, slot) in r.iter_mut().enumerate() {
                    if let Some(v) = level.get(TREE_ARITY * i + j) {
                        *slot = *v;
                    }
                }
                next.push(merkle_compress(cfg_tree, &r));
            }
            if next.is_empty() {
                next.push(merkle_compress(cfg_tree, &[zeros[lvl]; TREE_ARITY]));
            }
            level = next;
            idx /= TREE_ARITY;
        }
        (rows, positions)
    }
}

// ---------- circuit gadget helpers ----------

fn hash_n_gadget(
    cs: ConstraintSystemRef<F>,
    cfg: &PoseidonConfig<F>,
    inputs: &[FpVar<F>],
) -> Result<FpVar<F>, SynthesisError> {
    let mut sponge = PoseidonSpongeVar::<F>::new(cs, cfg);
    for x in inputs {
        sponge.absorb(x)?;
    }
    Ok(sponge.squeeze_field_elements(1)?[0].clone())
}

/// Enforce v ∈ [0, 2^64): allocate 64 bit-witnesses and enforce the recomposition equals v.
/// Bit assignments come from the LOW 64 BITS of the claimed field value — so a witness value
/// ≥ 2^64 (e.g. the field-wrap "negative" mint) can never satisfy the recomposition equality.
fn enforce_u64_range(
    cs: ConstraintSystemRef<F>,
    v: &FpVar<F>,
    v_val: Option<F>,
) -> Result<(), SynthesisError> {
    let low64: Option<u64> = v_val.map(|f| f.into_bigint().as_ref()[0]);
    let mut acc = FpVar::<F>::zero();
    let mut pow = F::from(1u64);
    for i in 0..64 {
        let bit = Boolean::new_witness(cs.clone(), || {
            low64
                .map(|v| (v >> i) & 1 == 1)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        acc += FpVar::from(bit) * pow;
        pow += pow;
    }
    acc.enforce_equal(v)
}

/// In-circuit twin of `merkle_compress`: capacity carries `TAG_MERGE`, the rate absorbs exactly
/// the five children, one permutation. The capacity assignment is a CONSTANT, so it allocates no
/// witness and adds no constraint — the entire cost of domain separation is zero.
fn merkle_compress_gadget(
    cs: ConstraintSystemRef<F>,
    cfg_tree: &TreeCfg,
    row: &[FpVar<F>; TREE_ARITY],
) -> Result<FpVar<F>, SynthesisError> {
    let mut sponge = PoseidonSpongeVar::<F>::new(cs, &cfg_tree.0);
    sponge.state[0] = FpVar::constant(F::from(TAG_MERGE));
    for c in row {
        sponge.absorb(c)?;
    }
    Ok(sponge.squeeze_field_elements(1)?[0].clone())
}

/// Fold a 5-ary Merkle path.
///
/// Per level the prover witnesses the full row of ARITY children and a one-hot selector saying
/// which slot the node carried up from below occupies. Two things are enforced, and BOTH are
/// load-bearing:
///
///   1. the selector is one-hot — each entry boolean AND the entries summing to exactly one;
///   2. the inner product `sum_j sel_j * row_j` equals the node carried up.
///
/// Drop (1) and the statement collapses: a prover could choose selector entries summing to one
/// out of non-boolean field values and open the inner product to a value that appears NOWHERE in
/// the row, proving membership of a note that is not in the tree. Booleanity alone is not enough
/// either — an all-zero selector would make the inner product zero and (2) would then merely
/// assert the carried node is zero, which is exactly what an empty leaf hashes from. The pair is
/// the statement; neither half is decoration. `row05_merkle_path_enforcement` and the
/// under-constrained detector are what hold this honest.
fn merkle_root_gadget(
    cs: ConstraintSystemRef<F>,
    cfg_tree: &TreeCfg,
    leaf: &FpVar<F>,
    rows: &[Vec<FpVar<F>>],
    selectors: &[Vec<Boolean<F>>],
) -> Result<FpVar<F>, SynthesisError> {
    let mut cur = leaf.clone();
    for (row, sel) in rows.iter().zip(selectors) {
        debug_assert_eq!(row.len(), TREE_ARITY);
        debug_assert_eq!(sel.len(), TREE_ARITY);

        // (1) one-hot: every entry is already a Boolean witness (booleanity enforced at
        // allocation); require exactly one of them set.
        let mut sum = FpVar::<F>::zero();
        for s in sel {
            sum += FpVar::from(s.clone());
        }
        sum.enforce_equal(&FpVar::one())?;

        // (2) the node carried up from below must be the selected entry of this row.
        let mut selected = FpVar::<F>::zero();
        for (s, c) in sel.iter().zip(row) {
            selected += FpVar::from(s.clone()) * c;
        }
        selected.enforce_equal(&cur)?;

        let fixed: [FpVar<F>; TREE_ARITY] = core::array::from_fn(|j| row[j].clone());
        cur = merkle_compress_gadget(cs.clone(), cfg_tree, &fixed)?;
    }
    Ok(cur)
}

// ---------- the transfer circuit (2-in / 2-out, unified transfer+withdraw) ----------

/// Statement (public inputs, in allocation order):
///   anchor, nf_1, nf_2, cm_out_1, cm_out_2, fee, v_pub_out, recipient_binding
/// Witness: for each input note (v, nk, rho, rcm, merkle path); for each output (v', pk', rcm').
/// Constraints (hardened statement, `legacy_statement = false`):
///   fee/v_pub_out ranges: fee ∈ [0,2^64) and v_pub_out ∈ [0,2^64) — the two public
///                      conservation terms are range-bound IN-CIRCUIT, not at the interface.
///   for each input i:  pk_i = H(1,nk_i);  cm_i = H(3,v_i,pk_i,rho_i,rcm_i);
///                      MerklePath(cm_i) == anchor;  nf_i == H(2,nk_i,rho_i);  v_i ∈ [0,2^64)
///   input distinctness: nf_1 != nf_2 — the same note cannot occupy both input slots, so the
///                      rho-chaining below is self-sufficient (distinct nf ⇒ distinct output
///                      rho) without relying on any external duplicate-nullifier check.
///   for each output j: cm_out_j == H(3,v'_j,pk'_j,rho'_j,rcm'_j) with rho'_j := nf_j
///                      (Orchard-style uniqueness chaining);  v'_j ∈ [0,2^64)
///   recipient binding: a private mirror is constrained equal to the public recipient field, so
///                      a proof cannot be replayed with a different public ICRC recipient.
///   conservation:      v_1 + v_2 == v'_1 + v'_2 + fee + v_pub_out   (exact over Z because ALL
///                      FOUR value terms — input values, output values, fee, and v_pub_out — are
///                      range-bound: 4·2^64 ≪ p ≈ 2^254 — S1 is meaningless without S3)
///
/// `legacy_statement = true` reproduces the PRE-HARDENING statement byte-for-byte: no
/// fee/v_pub_out range gadgets and no input-distinctness constraint. In that statement those
/// three properties hold only end-to-end (the ledger builds fee/v_pub_out from candid `Nat64`
/// and rejects duplicate nullifiers per transaction); the circuit alone accepts a field-wrapped
/// fee/v_pub_out or a doubled input note. The two statements have DISTINCT verifying keys and
/// proofs do not cross-verify; the frozen `vectors-bls` fixtures and any verifying key rotated
/// in before the hardened statement belong to the legacy statement.
///
/// `enforce_range` exists ONLY so `gen` can demonstrate natively that removing S3 lets the
/// field-wrap mint attack through. Deployment-eligible verifying keys are generated with
/// `enforce_range = true`; a proof against the no-range variant has a different vk and cannot
/// be accepted by the canister. In the hardened statement the flag gates all four range
/// gadgets (note values AND fee/v_pub_out); the distinctness constraint is not gated.
#[derive(Clone)]
pub struct TransferCircuit {
    pub cfg: PoseidonConfig<F>,
    pub enforce_range: bool,
    /// Statement selector: `false` (the default built by `blank`) = the hardened conservation
    /// statement; `true` (`blank_legacy`) = the byte-identical pre-hardening statement. See the
    /// struct docs above for exactly which constraints the flag controls.
    pub legacy_statement: bool,
    // public
    pub anchor: Option<F>,
    pub nf: [Option<F>; 2],
    pub cm_out: [Option<F>; 2],
    pub fee: Option<u64>,
    pub v_pub_out: Option<u64>,
    pub recipient_binding: Option<F>,
    // witness: inputs
    pub in_v: [Option<u64>; 2],
    pub in_nk: [Option<F>; 2],
    pub in_rho: [Option<F>; 2],
    pub in_rcm: [Option<F>; 2],
    /// One full ARITY-wide row per level (the walked node included), as returned by
    /// `DenseTree::path`. Replaces the pre-5-ary `in_siblings`.
    pub in_rows: [Vec<[F; TREE_ARITY]>; 2],
    /// The walked node's slot in each row, 0..ARITY. Witnessed in-circuit as a one-hot selector.
    /// Replaces the pre-5-ary `in_bits`.
    pub in_pos: [Vec<usize>; 2],
    // witness: outputs (raw field values so witness-level attacks are expressible in tests;
    // honest provers always use F::from(u64))
    pub out_v: [Option<F>; 2],
    pub out_pk: [Option<F>; 2],
    pub out_rcm: [Option<F>; 2],
}

impl TransferCircuit {
    /// Blank circuit for the HARDENED statement (the canonical statement going forward).
    pub fn blank(cfg: &PoseidonConfig<F>) -> Self {
        TransferCircuit {
            cfg: cfg.clone(),
            enforce_range: true,
            legacy_statement: false,
            anchor: None,
            nf: [None; 2],
            cm_out: [None; 2],
            fee: None,
            v_pub_out: None,
            recipient_binding: None,
            in_v: [None; 2],
            in_nk: [None; 2],
            in_rho: [None; 2],
            in_rcm: [None; 2],
            in_rows: [
                vec![[F::from(0u64); TREE_ARITY]; TREE_LEVELS],
                vec![[F::from(0u64); TREE_ARITY]; TREE_LEVELS],
            ],
            in_pos: [vec![0usize; TREE_LEVELS], vec![0usize; TREE_LEVELS]],
            out_v: [None::<F>; 2],
            out_pk: [None; 2],
            out_rcm: [None; 2],
        }
    }

    /// Blank circuit for the LEGACY (pre-hardening) statement — the statement of the frozen
    /// `vectors-bls` fixtures and of any verifying key generated before the hardening. Kept so
    /// the legacy setup remains byte-for-byte reproducible until every deployment has rotated
    /// to the hardened statement's verifying key.
    pub fn blank_legacy(cfg: &PoseidonConfig<F>) -> Self {
        TransferCircuit { legacy_statement: true, ..Self::blank(cfg) }
    }

    /// The public-input vector in the exact order the circuit allocates them.
    pub fn public_inputs(&self) -> Vec<F> {
        vec![
            self.anchor.unwrap(),
            self.nf[0].unwrap(),
            self.nf[1].unwrap(),
            self.cm_out[0].unwrap(),
            self.cm_out[1].unwrap(),
            F::from(self.fee.unwrap()),
            F::from(self.v_pub_out.unwrap()),
            self.recipient_binding.unwrap(),
        ]
    }
}

fn opt<T: Copy>(o: Option<T>) -> Result<T, SynthesisError> {
    o.ok_or(SynthesisError::AssignmentMissing)
}

impl ConstraintSynthesizer<F> for TransferCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let cfg = &self.cfg;
        // The tree runs on the WIDER instance (rate 5) so a 5-ary row is one permutation. Derived
        // once per synthesis rather than carried in the struct, so no caller has to thread a
        // second config through and no caller can pass a mismatched pair.
        let cfg_tree = poseidon_config_tree();

        // public inputs (allocation order = public_inputs() order)
        let anchor = FpVar::new_input(cs.clone(), || opt(self.anchor))?;
        let nf_pub = [
            FpVar::new_input(cs.clone(), || opt(self.nf[0]))?,
            FpVar::new_input(cs.clone(), || opt(self.nf[1]))?,
        ];
        let cm_out_pub = [
            FpVar::new_input(cs.clone(), || opt(self.cm_out[0]))?,
            FpVar::new_input(cs.clone(), || opt(self.cm_out[1]))?,
        ];
        let fee = FpVar::new_input(cs.clone(), || opt(self.fee).map(F::from))?;
        let v_pub_out = FpVar::new_input(cs.clone(), || opt(self.v_pub_out).map(F::from))?;
        let recipient_binding = FpVar::new_input(cs.clone(), || opt(self.recipient_binding))?;
        // `recipient_binding` is a public input the statement does not otherwise reference. The
        // witness below is allocated from the SAME value and then compared to it, so the equality
        // holds for every assignment -- a prover controls both slots and would fill them alike.
        //
        // IT IS NOT WHAT BINDS THE RECIPIENT, and reading it as such is the error this comment
        // exists to prevent. Groth16 binds every instance variable regardless of whether the
        // circuit mentions it: ark-groth16's QAP reduction gives each one its own Lagrange
        // coefficient at a domain position past the constraint count (`r1cs_to_qap.rs`, hence
        // `domain_size = num_constraints + num_instance_variables`). Deleting these two lines
        // leaves `recipient_binding_is_bound_at_the_verifier` passing -- measured, not assumed.
        //
        // What it DOES do is keep the input inside the developer constraint system, so the
        // under-constrained coverage property holds. Deleting it costs one constraint and one
        // witness and fails `transfer_circuit_is_fully_constrained` with "1 public inputs are not
        // effectively constrained". That is the reason to keep it, and the only one.
        let recipient_binding_witness =
            FpVar::new_witness(cs.clone(), || opt(self.recipient_binding))?;
        recipient_binding_witness.enforce_equal(&recipient_binding)?;

        // Hardened statement: range-bind the two PUBLIC conservation terms in-circuit, under the
        // same flag that gates the note-value ranges. Without these two gadgets a field-wrapped
        // fee or v_pub_out (a canonical element r−k) satisfies the conservation equality below
        // while outputs exceed inputs by k — over-issuance the circuit alone would accept.
        if !self.legacy_statement && self.enforce_range {
            enforce_u64_range(cs.clone(), &fee, self.fee.map(F::from))?;
            enforce_u64_range(cs.clone(), &v_pub_out, self.v_pub_out.map(F::from))?;
        }

        let mut in_value_sum = FpVar::<F>::zero();
        let mut nf_vars: Vec<FpVar<F>> = Vec::with_capacity(2);

        for i in 0..2 {
            let v = FpVar::new_witness(cs.clone(), || opt(self.in_v[i]).map(F::from))?;
            let nk = FpVar::new_witness(cs.clone(), || opt(self.in_nk[i]))?;
            let rho = FpVar::new_witness(cs.clone(), || opt(self.in_rho[i]))?;
            let rcm = FpVar::new_witness(cs.clone(), || opt(self.in_rcm[i]))?;

            let rows: Vec<Vec<FpVar<F>>> = self.in_rows[i]
                .iter()
                .map(|row| {
                    row.iter()
                        .map(|s| FpVar::new_witness(cs.clone(), || Ok(*s)))
                        .collect::<Result<Vec<_>, _>>()
                })
                .collect::<Result<_, _>>()?;
            // The selector is witnessed one-hot from the position. `Boolean::new_witness` enforces
            // booleanity per entry; `merkle_root_gadget` enforces that exactly one is set. A
            // malicious prover choosing a different assignment is constrained by both, not by the
            // honest derivation here.
            let selectors: Vec<Vec<Boolean<F>>> = self.in_pos[i]
                .iter()
                .map(|pos| {
                    (0..TREE_ARITY)
                        .map(|j| Boolean::new_witness(cs.clone(), || Ok(j == *pos)))
                        .collect::<Result<Vec<_>, _>>()
                })
                .collect::<Result<_, _>>()?;

            let tag_pk = FpVar::constant(F::from(TAG_PK));
            let tag_nf = FpVar::constant(F::from(TAG_NF));
            let tag_cm = FpVar::constant(F::from(TAG_CM));

            let pk = hash_n_gadget(cs.clone(), cfg, &[tag_pk, nk.clone()])?;
            let cm = hash_n_gadget(cs.clone(), cfg, &[tag_cm, v.clone(), pk, rho.clone(), rcm])?;
            let root = merkle_root_gadget(cs.clone(), &cfg_tree, &cm, &rows, &selectors)?;
            root.enforce_equal(&anchor)?;

            let nf = hash_n_gadget(cs.clone(), cfg, &[tag_nf, nk, rho])?;
            nf.enforce_equal(&nf_pub[i])?;
            nf_vars.push(nf);

            if self.enforce_range {
                enforce_u64_range(cs.clone(), &v, self.in_v[i].map(F::from))?;
            }
            in_value_sum += v;
        }

        // Hardened statement: the two input notes must be DISTINCT (nf_1 != nf_2). Loading the
        // same note into both slots would double its value in the sum and give both outputs the
        // same chained rho (the exact Faerie-Gold collision the chaining prevents). Not gated by
        // `enforce_range`: distinctness is part of the statement, not a demonstration hook.
        // (For equal nullifiers `enforce_not_equal` has no satisfying assignment — synthesis of
        // the difference's inverse fails — so no proof can be produced.)
        if !self.legacy_statement {
            nf_vars[0].enforce_not_equal(&nf_vars[1])?;
        }

        let mut out_value_sum = FpVar::<F>::zero();
        for j in 0..2 {
            let v = FpVar::new_witness(cs.clone(), || opt(self.out_v[j]))?;
            let pk = FpVar::new_witness(cs.clone(), || opt(self.out_pk[j]))?;
            let rcm = FpVar::new_witness(cs.clone(), || opt(self.out_rcm[j]))?;

            // rho of output j is the nullifier of input j — Faerie-Gold defence. Within one
            // transfer the two chained rhos are distinct by the in-circuit nf_1 != nf_2
            // constraint (hardened statement); across transfers nullifiers are globally unique
            // (the ledger rejects repeats).
            let rho_out = nf_vars[j].clone();

            let tag_cm = FpVar::constant(F::from(TAG_CM));
            let cm = hash_n_gadget(cs.clone(), cfg, &[tag_cm, v.clone(), pk, rho_out, rcm])?;
            cm.enforce_equal(&cm_out_pub[j])?;

            if self.enforce_range {
                enforce_u64_range(cs.clone(), &v, self.out_v[j])?;
            }
            out_value_sum += v;
        }

        // conservation
        in_value_sum.enforce_equal(&(out_value_sum + fee + v_pub_out))
    }
}

// ---------- the deposit circuit ----------

/// Statement: public (cm, v_pub); witness (pk, rho, rcm); cm == H(3, v_pub, pk, rho, rcm).
///
/// INTERFACE OBLIGATION (audit F3) — read this before integrating a new caller. There is NO
/// in-circuit range constraint on `v_pub`: the proof alone does not stop a deposit from
/// committing a note whose value wraps the field. Deposit soundness rests on two obligations
/// the VERIFIER'S CALLER must uphold:
///
///   1. `v_pub` must be built from a 64-bit integer. The ledger does this by typing the
///      candid argument `Nat64` and embedding it with `nat64Field` (src/Main.mo `shield`),
///      so a public input >= 2^64 is unrepresentable at the interface.
///   2. The transparent leg must bound the real amount: the ledger moves exactly `v_pub`
///      ICRC-2 tokens into custody before the note finalizes, so an inflated claim has to be
///      paid for, not merely proven.
///
/// Any integration that feeds this statement a `v_pub` from a wider type, or verifies a
/// deposit without the paid transparent leg, reopens the F1(b)-class over-issuance for
/// deposits. The ledger-side seam is marked CONSENSUS-CRITICAL and pinned by
/// scripts/consensus-seam-guard.sh. (If a hardened deposit statement is ever cut, add the
/// in-circuit u64 range gadget on `v_pub` for symmetry with the hardened transfer statement.)
#[derive(Clone)]
pub struct DepositCircuit {
    pub cfg: PoseidonConfig<F>,
    pub cm: Option<F>,
    pub v_pub: Option<u64>,
    pub pk: Option<F>,
    pub rho: Option<F>,
    pub rcm: Option<F>,
}

impl DepositCircuit {
    pub fn blank(cfg: &PoseidonConfig<F>) -> Self {
        DepositCircuit {
            cfg: cfg.clone(),
            cm: None,
            v_pub: None,
            pk: None,
            rho: None,
            rcm: None,
        }
    }
    pub fn public_inputs(&self) -> Vec<F> {
        vec![self.cm.unwrap(), F::from(self.v_pub.unwrap())]
    }
}

impl ConstraintSynthesizer<F> for DepositCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let cfg = &self.cfg;
        let cm_pub = FpVar::new_input(cs.clone(), || opt(self.cm))?;
        let v_pub = FpVar::new_input(cs.clone(), || opt(self.v_pub).map(F::from))?;
        let pk = FpVar::new_witness(cs.clone(), || opt(self.pk))?;
        let rho = FpVar::new_witness(cs.clone(), || opt(self.rho))?;
        let rcm = FpVar::new_witness(cs.clone(), || opt(self.rcm))?;
        let tag_cm = FpVar::constant(F::from(TAG_CM));
        let cm = hash_n_gadget(cs.clone(), cfg, &[tag_cm, v_pub, pk, rho, rcm])?;
        cm.enforce_equal(&cm_pub)
    }
}

// ---------- serialization helpers (canister ⇄ vectors) ----------

pub fn f_to_hex(x: &F) -> String {
    let mut b = Vec::new();
    use ark_serialize::CanonicalSerialize;
    x.serialize_compressed(&mut b).unwrap();
    hex::encode_via(&b)
}

// tiny local hex to avoid pulling the hex crate into no-std paths
mod hex {
    pub fn encode_via(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
    pub fn decode_via(s: &str) -> Option<Vec<u8>> {
        if s.len() % 2 != 0 {
            return None;
        }
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok())
            .collect()
    }
}

pub fn f_from_hex(s: &str) -> Option<F> {
    use ark_serialize::CanonicalDeserialize;
    let b = hex::decode_via(s)?;
    F::deserialize_compressed(&b[..]).ok()
}

/// Field element to decimal string (for logging / cross-checks).
pub fn f_to_dec(x: &F) -> String {
    x.into_bigint().to_string()
}
