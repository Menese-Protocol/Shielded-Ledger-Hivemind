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
//! Domain separation: every note-level hash absorbs a leading tag (1=pk, 2=nf, 3=cm) so a
//! commitment can never collide with a nullifier or an address image. Merkle inner nodes use
//! bare 2-to-1 compression (leaves are already hash images; an inner-node value cannot be
//! opened as a note commitment without a Poseidon preimage).

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
    select::CondSelectGadget,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

pub use ark_crypto_primitives::sponge::poseidon::PoseidonConfig as PoseidonCfg;

pub const TREE_DEPTH: usize = 32;
pub const TAG_PK: u64 = 1;
pub const TAG_NF: u64 = 2;
pub const TAG_CM: u64 = 3;

/// Poseidon over BN254 Fr: rate 2, capacity 1, 8 full + 57 partial rounds, alpha = 5.
/// Same parameter shape as the verifier-lab measurement so per-hash costs are comparable.
/// Constants derived with arkworks' Grain-LFSR routine (the Poseidon paper's method).
pub fn poseidon_config() -> PoseidonConfig<F> {
    let (ark, mds) = find_poseidon_ark_and_mds::<F>(F::MODULUS_BIT_SIZE as u64, 2, 8, 57, 0);
    PoseidonConfig::new(8, 57, 5, mds, ark, 2, 1)
}

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
pub fn merkle_compress(cfg: &PoseidonConfig<F>, l: F, r: F) -> F {
    hash_n(cfg, &[l, r])
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

/// Cached zero-subtree hashes: zeros[0] = 0 (empty leaf), zeros[i+1] = H(zeros[i], zeros[i]).
pub fn zero_hashes(cfg: &PoseidonConfig<F>) -> Vec<F> {
    let mut z = vec![F::from(0u64)];
    for i in 0..TREE_DEPTH {
        z.push(merkle_compress(cfg, z[i], z[i]));
    }
    z
}

/// Append-only incremental tree. Root recomputed per append with depth hash calls.
pub struct IncrementalTree {
    pub filled: Vec<F>, // filled[i] = left sibling cached at level i
    pub zeros: Vec<F>,
    pub next_index: u64,
    pub root: F,
}

impl IncrementalTree {
    pub fn new(cfg: &PoseidonConfig<F>) -> Self {
        let zeros = zero_hashes(cfg);
        IncrementalTree {
            filled: zeros[..TREE_DEPTH].to_vec(),
            root: zeros[TREE_DEPTH],
            zeros,
            next_index: 0,
        }
    }

    /// Returns the new root. Panics when full (2^32 leaves — unreachable in the prototype).
    pub fn append(&mut self, cfg: &PoseidonConfig<F>, leaf: F) -> F {
        assert!(self.next_index < (1u64 << TREE_DEPTH), "tree full");
        let mut idx = self.next_index;
        let mut cur = leaf;
        for lvl in 0..TREE_DEPTH {
            if idx % 2 == 0 {
                self.filled[lvl] = cur;
                cur = merkle_compress(cfg, cur, self.zeros[lvl]);
            } else {
                cur = merkle_compress(cfg, self.filled[lvl], cur);
            }
            idx /= 2;
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
    pub fn root(&self, cfg: &PoseidonConfig<F>) -> F {
        let zeros = zero_hashes(cfg);
        let mut level: Vec<F> = self.leaves.clone();
        for lvl in 0..TREE_DEPTH {
            let mut next = Vec::with_capacity((level.len() + 1) / 2);
            for i in 0..level.len().div_ceil(2) {
                let l = level[2 * i];
                let r = if 2 * i + 1 < level.len() {
                    level[2 * i + 1]
                } else {
                    zeros[lvl]
                };
                next.push(merkle_compress(cfg, l, r));
            }
            if next.is_empty() {
                next.push(merkle_compress(cfg, zeros[lvl], zeros[lvl]));
            }
            level = next;
        }
        level[0]
    }

    /// (siblings, position bits little-endian from leaf) for leaf `index`.
    pub fn path(&self, cfg: &PoseidonConfig<F>, index: usize) -> (Vec<F>, Vec<bool>) {
        let zeros = zero_hashes(cfg);
        let mut siblings = Vec::with_capacity(TREE_DEPTH);
        let mut bits = Vec::with_capacity(TREE_DEPTH);
        let mut level: Vec<F> = self.leaves.clone();
        let mut idx = index;
        for lvl in 0..TREE_DEPTH {
            let sib_idx = idx ^ 1;
            let sib = if sib_idx < level.len() {
                level[sib_idx]
            } else {
                zeros[lvl]
            };
            siblings.push(sib);
            bits.push(idx % 2 == 1); // true => current node is the RIGHT child
            let mut next = Vec::with_capacity((level.len() + 1) / 2);
            for i in 0..level.len().div_ceil(2) {
                let l = level[2 * i];
                let r = if 2 * i + 1 < level.len() {
                    level[2 * i + 1]
                } else {
                    zeros[lvl]
                };
                next.push(merkle_compress(cfg, l, r));
            }
            if next.is_empty() {
                next.push(merkle_compress(cfg, zeros[lvl], zeros[lvl]));
            }
            level = next;
            idx /= 2;
        }
        (siblings, bits)
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

/// Fold a Merkle path: cur starts at the leaf; bit=true means cur is the right child.
fn merkle_root_gadget(
    cs: ConstraintSystemRef<F>,
    cfg: &PoseidonConfig<F>,
    leaf: &FpVar<F>,
    siblings: &[FpVar<F>],
    bits: &[Boolean<F>],
) -> Result<FpVar<F>, SynthesisError> {
    let mut cur = leaf.clone();
    for (sib, bit) in siblings.iter().zip(bits) {
        let l = FpVar::conditionally_select(bit, sib, &cur)?;
        let r = FpVar::conditionally_select(bit, &cur, sib)?;
        cur = hash_n_gadget(cs.clone(), cfg, &[l, r])?;
    }
    Ok(cur)
}

// ---------- the transfer circuit (2-in / 2-out, unified transfer+withdraw) ----------

/// Statement (public inputs, in allocation order):
///   anchor, nf_1, nf_2, cm_out_1, cm_out_2, fee, v_pub_out, recipient_binding
/// Witness: for each input note (v, nk, rho, rcm, merkle path); for each output (v', pk', rcm').
/// Constraints:
///   for each input i:  pk_i = H(1,nk_i);  cm_i = H(3,v_i,pk_i,rho_i,rcm_i);
///                      MerklePath(cm_i) == anchor;  nf_i == H(2,nk_i,rho_i);  v_i ∈ [0,2^64)
///   for each output j: cm_out_j == H(3,v'_j,pk'_j,rho'_j,rcm'_j) with rho'_j := nf_j
///                      (Orchard-style uniqueness chaining);  v'_j ∈ [0,2^64)
///   recipient binding: a private mirror is constrained equal to the public recipient field, so
///                      a proof cannot be replayed with a different public ICRC recipient.
///   conservation:      v_1 + v_2 == v'_1 + v'_2 + fee + v_pub_out   (exact over Z because every
///                      term is range-bound: 2·2^64 ≪ p ≈ 2^254 — S1 is meaningless without S3)
///
/// `enforce_range` exists ONLY so `gen` can demonstrate natively that removing S3 lets the
/// field-wrap mint attack through. The deployed verifying key is generated with
/// `enforce_range = true`; a proof against the no-range variant has a different vk and cannot
/// be accepted by the canister.
#[derive(Clone)]
pub struct TransferCircuit {
    pub cfg: PoseidonConfig<F>,
    pub enforce_range: bool,
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
    pub in_siblings: [Vec<F>; 2],
    pub in_bits: [Vec<bool>; 2],
    // witness: outputs (raw field values so witness-level attacks are expressible in tests;
    // honest provers always use F::from(u64))
    pub out_v: [Option<F>; 2],
    pub out_pk: [Option<F>; 2],
    pub out_rcm: [Option<F>; 2],
}

impl TransferCircuit {
    pub fn blank(cfg: &PoseidonConfig<F>) -> Self {
        TransferCircuit {
            cfg: cfg.clone(),
            enforce_range: true,
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
            in_siblings: [
                vec![F::from(0u64); TREE_DEPTH],
                vec![F::from(0u64); TREE_DEPTH],
            ],
            in_bits: [vec![false; TREE_DEPTH], vec![false; TREE_DEPTH]],
            out_v: [None::<F>; 2],
            out_pk: [None; 2],
            out_rcm: [None; 2],
        }
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
        let recipient_binding_witness =
            FpVar::new_witness(cs.clone(), || opt(self.recipient_binding))?;
        recipient_binding_witness.enforce_equal(&recipient_binding)?;

        let mut in_value_sum = FpVar::<F>::zero();
        let mut nf_vars: Vec<FpVar<F>> = Vec::with_capacity(2);

        for i in 0..2 {
            let v = FpVar::new_witness(cs.clone(), || opt(self.in_v[i]).map(F::from))?;
            let nk = FpVar::new_witness(cs.clone(), || opt(self.in_nk[i]))?;
            let rho = FpVar::new_witness(cs.clone(), || opt(self.in_rho[i]))?;
            let rcm = FpVar::new_witness(cs.clone(), || opt(self.in_rcm[i]))?;

            let siblings: Vec<FpVar<F>> = self.in_siblings[i]
                .iter()
                .map(|s| FpVar::new_witness(cs.clone(), || Ok(*s)))
                .collect::<Result<_, _>>()?;
            let bits: Vec<Boolean<F>> = self.in_bits[i]
                .iter()
                .map(|b| Boolean::new_witness(cs.clone(), || Ok(*b)))
                .collect::<Result<_, _>>()?;

            let tag_pk = FpVar::constant(F::from(TAG_PK));
            let tag_nf = FpVar::constant(F::from(TAG_NF));
            let tag_cm = FpVar::constant(F::from(TAG_CM));

            let pk = hash_n_gadget(cs.clone(), cfg, &[tag_pk, nk.clone()])?;
            let cm = hash_n_gadget(cs.clone(), cfg, &[tag_cm, v.clone(), pk, rho.clone(), rcm])?;
            let root = merkle_root_gadget(cs.clone(), cfg, &cm, &siblings, &bits)?;
            root.enforce_equal(&anchor)?;

            let nf = hash_n_gadget(cs.clone(), cfg, &[tag_nf, nk, rho])?;
            nf.enforce_equal(&nf_pub[i])?;
            nf_vars.push(nf);

            if self.enforce_range {
                enforce_u64_range(cs.clone(), &v, self.in_v[i].map(F::from))?;
            }
            in_value_sum += v;
        }

        let mut out_value_sum = FpVar::<F>::zero();
        for j in 0..2 {
            let v = FpVar::new_witness(cs.clone(), || opt(self.out_v[j]))?;
            let pk = FpVar::new_witness(cs.clone(), || opt(self.out_pk[j]))?;
            let rcm = FpVar::new_witness(cs.clone(), || opt(self.out_rcm[j]))?;

            // rho of output j is the nullifier of input j — unique because nullifiers are
            // globally unique (the canister rejects repeats). Faerie-Gold defence.
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
/// v_pub arrives as a u64 through candid, so its range is enforced by the interface type.
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
