//! Circuit semantic-completeness audit — twelve properties, each with an adversarial-witness
//! UNSAT battery (proven against the SHIPPED circuit) and a mutation-kill test (the SAME witness
//! flips SAT against a faithful test-local mirror with exactly one mapped constraint removed).
//!
//! Discipline (mission `for-team/MISSION-circuit-semantic-audit.md`, plan §WS-2):
//!   * The shipped `common::TransferCircuit` / `common::DepositCircuit` are NEVER modified.
//!   * Every UNSAT proof runs against the SHIPPED circuit — no drift risk on the property claim.
//!   * The mirror below is a byte-faithful transcription of `lib.rs::generate_constraints` gated
//!     by per-constraint knockout switches; it is used ONLY to prove a constraint is load-bearing.
//!   * `mirror_is_faithful_to_shipped_circuit` proves mirror(ko=none) ≡ shipped over the whole
//!     witness battery (honest + every adversarial witness), anchoring the mirror to the original.
//!
//! Two proofs per row: the UNSAT result AND the mutation-kill SAT flip.

use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar,
    poseidon::{constraints::PoseidonSpongeVar, PoseidonConfig},
};
use ark_ff::{BigInteger, One, PrimeField, UniformRand};
use ark_r1cs_std::{
    alloc::AllocVar,
    boolean::Boolean,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    select::CondSelectGadget,
};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
};
use ark_std::rand::{rngs::StdRng, RngCore, SeedableRng};
use common::{
    derive_nf, derive_pk, note_commitment, poseidon_config, DenseTree, DepositCircuit, Note,
    PoseidonCfg, ScalarField as F, TransferCircuit, TAG_CM, TAG_NF, TAG_PK,
};

// ---------------------------------------------------------------------------
// Local re-implementation of the three PRIVATE gadgets in lib.rs (221-271).
// Byte-faithful; anchored by `mirror_is_faithful_to_shipped_circuit`.
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Per-constraint knockout switches. `KnockOut::none()` reproduces the shipped
// circuit exactly (range on, nothing dropped, no proposed hardening).
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct KnockOut {
    drop_recipient: bool,        // row 7  — lib.rs:381
    drop_pk_binding: bool,       // row 4  — lib.rs:405 (pk becomes a free witness)
    drop_merkle: bool,           // row 5/9 — lib.rs:408
    drop_nullifier: bool,        // row 3  — lib.rs:411
    drop_rho_chain: bool,        // row 6  — lib.rs:428 (rho_out becomes a free witness)
    drop_output_commitment: bool,// row 6/10 — lib.rs:432
    drop_conservation: bool,     // row 1/8/11 — lib.rs:441
    range_inputs: bool,          // row 2  — lib.rs:414-416 (mirrors enforce_range for inputs)
    range_outputs: bool,         // row 2/10 — lib.rs:434-436
    // PROPOSED defense-in-depth (NOT in the shipped circuit): in-circuit range on fee/v_pub_out
    // and input-note distinctness. See for-team/PROPOSAL-circuit-indepth-conservation-hardening.md.
    range_fee: bool,             // row 11 hardening
    range_v_pub_out: bool,       // row 8 hardening
    harden_distinctness: bool,   // input-distinctness hardening: nf[0] != nf[1]
}

impl KnockOut {
    fn none() -> Self {
        KnockOut {
            drop_recipient: false,
            drop_pk_binding: false,
            drop_merkle: false,
            drop_nullifier: false,
            drop_rho_chain: false,
            drop_output_commitment: false,
            drop_conservation: false,
            range_inputs: true,
            range_outputs: true,
            range_fee: false,
            range_v_pub_out: false,
            harden_distinctness: false,
        }
    }
}

/// Faithful mirror of `TransferCircuit`. Same public-input allocation order, same witness order,
/// same gadgets — plus knockout switches and value overrides for the "free witness" knockouts.
#[derive(Clone)]
struct MirrorTransfer {
    inner: TransferCircuit,
    ko: KnockOut,
    // value assigned to the free pk witness when `drop_pk_binding` (else ignored)
    in_pk_override: [Option<F>; 2],
    // value assigned to the free rho_out witness when `drop_rho_chain` (else ignored)
    out_rho_override: [Option<F>; 2],
    // value assigned to the recipient-binding WITNESS mirror (the shipped struct hardwires it to
    // the public field, so a differing witness can only be expressed here). None ⇒ = public input.
    recipient_witness_override: Option<F>,
    // RAW-FIELD overrides. The shipped struct types fee/v_pub_out/in_v as u64 (matching the
    // canister's Nat64), so a field-wrapped value for those terms is expressible ONLY against the
    // compiled R1CS — exactly the raw assignment a malicious prover injects. When set, the mirror
    // feeds this raw F instead of F::from(u64). The anchor test proves the mirror's CONSTRAINTS are
    // identical to shipped on the u64 domain; these overrides only change the injected value.
    fee_field_override: Option<F>,
    v_pub_out_field_override: Option<F>,
    in_v_field_override: [Option<F>; 2],
}

impl MirrorTransfer {
    fn new(inner: TransferCircuit, ko: KnockOut) -> Self {
        MirrorTransfer {
            inner,
            ko,
            in_pk_override: [None; 2],
            out_rho_override: [None; 2],
            recipient_witness_override: None,
            fee_field_override: None,
            v_pub_out_field_override: None,
            in_v_field_override: [None; 2],
        }
    }
}

fn opt<T: Copy>(o: Option<T>) -> Result<T, SynthesisError> {
    o.ok_or(SynthesisError::AssignmentMissing)
}

impl ConstraintSynthesizer<F> for MirrorTransfer {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let cfg = &self.inner.cfg;
        let ko = self.ko;

        let anchor = FpVar::new_input(cs.clone(), || opt(self.inner.anchor))?;
        let nf_pub = [
            FpVar::new_input(cs.clone(), || opt(self.inner.nf[0]))?,
            FpVar::new_input(cs.clone(), || opt(self.inner.nf[1]))?,
        ];
        let cm_out_pub = [
            FpVar::new_input(cs.clone(), || opt(self.inner.cm_out[0]))?,
            FpVar::new_input(cs.clone(), || opt(self.inner.cm_out[1]))?,
        ];
        let fee = FpVar::new_input(cs.clone(), || {
            self.fee_field_override
                .map(Ok)
                .unwrap_or_else(|| opt(self.inner.fee).map(F::from))
        })?;
        let v_pub_out = FpVar::new_input(cs.clone(), || {
            self.v_pub_out_field_override
                .map(Ok)
                .unwrap_or_else(|| opt(self.inner.v_pub_out).map(F::from))
        })?;
        let recipient_binding =
            FpVar::new_input(cs.clone(), || opt(self.inner.recipient_binding))?;
        let recipient_binding_witness = FpVar::new_witness(cs.clone(), || {
            opt(self
                .recipient_witness_override
                .or(self.inner.recipient_binding))
        })?;
        if !ko.drop_recipient {
            recipient_binding_witness.enforce_equal(&recipient_binding)?;
        }

        // Proposed hardening (absent from the shipped circuit).
        let fee_val = self
            .fee_field_override
            .or_else(|| self.inner.fee.map(F::from));
        let v_pub_out_val = self
            .v_pub_out_field_override
            .or_else(|| self.inner.v_pub_out.map(F::from));
        if ko.range_fee {
            enforce_u64_range(cs.clone(), &fee, fee_val)?;
        }
        if ko.range_v_pub_out {
            enforce_u64_range(cs.clone(), &v_pub_out, v_pub_out_val)?;
        }

        let mut in_value_sum = FpVar::<F>::zero();
        let mut nf_vars: Vec<FpVar<F>> = Vec::with_capacity(2);

        for i in 0..2 {
            let in_v_val = self.in_v_field_override[i].or_else(|| self.inner.in_v[i].map(F::from));
            let v = FpVar::new_witness(cs.clone(), || opt(in_v_val))?;
            let nk = FpVar::new_witness(cs.clone(), || opt(self.inner.in_nk[i]))?;
            let rho = FpVar::new_witness(cs.clone(), || opt(self.inner.in_rho[i]))?;
            let rcm = FpVar::new_witness(cs.clone(), || opt(self.inner.in_rcm[i]))?;

            let siblings: Vec<FpVar<F>> = self.inner.in_siblings[i]
                .iter()
                .map(|s| FpVar::new_witness(cs.clone(), || Ok(*s)))
                .collect::<Result<_, _>>()?;
            let bits: Vec<Boolean<F>> = self.inner.in_bits[i]
                .iter()
                .map(|b| Boolean::new_witness(cs.clone(), || Ok(*b)))
                .collect::<Result<_, _>>()?;

            let tag_pk = FpVar::constant(F::from(TAG_PK));
            let tag_nf = FpVar::constant(F::from(TAG_NF));
            let tag_cm = FpVar::constant(F::from(TAG_CM));

            // row 4: pk binding. Knockout ⇒ pk is a free witness (assigned the override value)
            // instead of being constrained equal to H(1, nk).
            let pk = if ko.drop_pk_binding {
                FpVar::new_witness(cs.clone(), || opt(self.in_pk_override[i]))?
            } else {
                hash_n_gadget(cs.clone(), cfg, &[tag_pk, nk.clone()])?
            };
            let cm = hash_n_gadget(cs.clone(), cfg, &[tag_cm, v.clone(), pk, rho.clone(), rcm])?;
            let root = merkle_root_gadget(cs.clone(), cfg, &cm, &siblings, &bits)?;
            if !ko.drop_merkle {
                root.enforce_equal(&anchor)?;
            }

            let nf = hash_n_gadget(cs.clone(), cfg, &[tag_nf, nk, rho])?;
            if !ko.drop_nullifier {
                nf.enforce_equal(&nf_pub[i])?;
            }
            nf_vars.push(nf);

            if ko.range_inputs {
                enforce_u64_range(cs.clone(), &v, in_v_val)?;
            }
            in_value_sum += v;
        }

        // PROPOSED input-note distinctness (absent from the shipped circuit).
        if ko.harden_distinctness {
            nf_vars[0].enforce_not_equal(&nf_vars[1])?;
        }

        let mut out_value_sum = FpVar::<F>::zero();
        for j in 0..2 {
            let v = FpVar::new_witness(cs.clone(), || opt(self.inner.out_v[j]))?;
            let pk = FpVar::new_witness(cs.clone(), || opt(self.inner.out_pk[j]))?;
            let rcm = FpVar::new_witness(cs.clone(), || opt(self.inner.out_rcm[j]))?;

            // row 6: Faerie-Gold rho-chaining. Knockout ⇒ rho_out is a free witness.
            let rho_out = if ko.drop_rho_chain {
                FpVar::new_witness(cs.clone(), || opt(self.out_rho_override[j]))?
            } else {
                nf_vars[j].clone()
            };

            let tag_cm = FpVar::constant(F::from(TAG_CM));
            let cm = hash_n_gadget(cs.clone(), cfg, &[tag_cm, v.clone(), pk, rho_out, rcm])?;
            if !ko.drop_output_commitment {
                cm.enforce_equal(&cm_out_pub[j])?;
            }

            if ko.range_outputs {
                enforce_u64_range(cs.clone(), &v, self.inner.out_v[j])?;
            }
            out_value_sum += v;
        }

        if !ko.drop_conservation {
            in_value_sum.enforce_equal(&(out_value_sum + fee + v_pub_out))?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Satisfiability harness
// ---------------------------------------------------------------------------

/// Is the SHIPPED transfer circuit satisfied by this witness?
fn shipped_satisfied(circuit: &TransferCircuit) -> bool {
    let cs = ConstraintSystem::<F>::new_ref();
    circuit.clone().generate_constraints(cs.clone()).unwrap();
    cs.is_satisfied().unwrap()
}

/// Is the MIRROR satisfied under the given knockout?
fn mirror_satisfied(m: MirrorTransfer) -> bool {
    let cs = ConstraintSystem::<F>::new_ref();
    m.generate_constraints(cs.clone()).unwrap();
    cs.is_satisfied().unwrap()
}

/// Does the MIRROR REJECT this witness? A rejection is either an unsatisfied constraint OR a
/// synthesis error — the latter is how ark_r1cs_std's `enforce_not_equal` signals infeasibility
/// when the two operands are equal (it cannot compute the inverse of their zero difference), i.e.
/// no prover could produce a witness assignment / a valid proof. Both are genuine rejections.
fn mirror_rejects(m: MirrorTransfer) -> bool {
    let cs = ConstraintSystem::<F>::new_ref();
    match m.generate_constraints(cs.clone()) {
        Err(_) => true,
        Ok(()) => !cs.is_satisfied().unwrap(),
    }
}

fn assert_shipped_unsat(circuit: &TransferCircuit, why: &str) {
    assert!(
        !shipped_satisfied(circuit),
        "SHIPPED circuit unexpectedly SATISFIED an adversarial witness ({why})"
    );
}

fn assert_shipped_sat(circuit: &TransferCircuit, why: &str) {
    assert!(
        shipped_satisfied(circuit),
        "SHIPPED circuit unexpectedly REJECTED an honest witness ({why})"
    );
}

/// The kill flip, checked per-witness so the teeth are airtight:
///   (1) the SAME witness (with the same value overrides) against the faithful mirror with NOTHING
///       removed must be REJECTED — this is per-witness faithfulness to the shipped circuit;
///   (2) once the mapped constraint is knocked out, that SAME witness becomes SATISFIED.
/// (1)+(2) together prove the knocked-out constraint — and only it — was load-bearing.
fn assert_kill_flip(m: MirrorTransfer, row: &str) {
    let mut baseline = m.clone();
    baseline.ko = KnockOut::none();
    assert!(
        mirror_rejects(baseline),
        "{row}: mirror(ko=none) unexpectedly ACCEPTED the adversarial witness — the witness does \
         not actually violate the mapped constraint (battery bug), investigate."
    );
    assert!(
        mirror_satisfied(m),
        "MUTATION-KILL FAILED for {row}: witness stayed UNSAT after removing the mapped \
         constraint — the battery has no teeth (or the constraint is redundant). Investigate."
    );
}

// ---------------------------------------------------------------------------
// Honest-witness builder (self-contained; real notes at non-trivial tree positions so both
// left and right Merkle branches are exercised).
// ---------------------------------------------------------------------------

struct Built {
    circuit: TransferCircuit,
    owner_nk: F,
    // native openings kept for adversarial edits
    in_rho: [F; 2],
    out_pk: [F; 2],
    out_rcm: [F; 2],
    nullifiers: [F; 2],
}

fn build_honest(
    rng: &mut StdRng,
    cfg: &PoseidonCfg<F>,
    in_values: [u64; 2],
    fee: u64,
    public_out: u64,
    first_output: u64,
) -> Built {
    let total = u128::from(in_values[0]) + u128::from(in_values[1]);
    let consumed = u128::from(fee) + u128::from(public_out) + u128::from(first_output);
    assert!(consumed <= total, "test setup: outputs exceed inputs");
    let second_output = u64::try_from(total - consumed).unwrap();

    let owner_nk = F::rand(rng);
    let recipient_nk = F::rand(rng);
    let inputs = [
        Note { v: in_values[0], nk: owner_nk, rho: F::rand(rng), rcm: F::rand(rng) },
        Note { v: in_values[1], nk: owner_nk, rho: F::rand(rng), rcm: F::rand(rng) },
    ];

    let mut filler = || Note { v: 1, nk: F::rand(rng), rho: F::rand(rng), rcm: F::rand(rng) };
    let leaves = vec![
        filler().cm(cfg),
        inputs[0].cm(cfg),
        filler().cm(cfg),
        filler().cm(cfg),
        inputs[1].cm(cfg),
        filler().cm(cfg),
    ];
    let tree = DenseTree { leaves };
    let anchor = tree.root(cfg);
    let (siblings_1, bits_1) = tree.path(cfg, 1);
    let (siblings_2, bits_2) = tree.path(cfg, 4);
    let nullifiers = [inputs[0].nf(cfg), inputs[1].nf(cfg)];
    let out_pk = [derive_pk(cfg, recipient_nk), derive_pk(cfg, owner_nk)];
    let out_rcm = [F::rand(rng), F::rand(rng)];
    let output_values = [first_output, second_output];
    let cm_out = [
        note_commitment(cfg, output_values[0], out_pk[0], nullifiers[0], out_rcm[0]),
        note_commitment(cfg, output_values[1], out_pk[1], nullifiers[1], out_rcm[1]),
    ];

    let circuit = TransferCircuit {
        cfg: cfg.clone(),
        enforce_range: true,
        anchor: Some(anchor),
        nf: [Some(nullifiers[0]), Some(nullifiers[1])],
        cm_out: [Some(cm_out[0]), Some(cm_out[1])],
        fee: Some(fee),
        v_pub_out: Some(public_out),
        recipient_binding: Some(F::rand(rng)),
        in_v: [Some(inputs[0].v), Some(inputs[1].v)],
        in_nk: [Some(inputs[0].nk), Some(inputs[1].nk)],
        in_rho: [Some(inputs[0].rho), Some(inputs[1].rho)],
        in_rcm: [Some(inputs[0].rcm), Some(inputs[1].rcm)],
        in_siblings: [siblings_1, siblings_2],
        in_bits: [bits_1, bits_2],
        out_v: [Some(F::from(output_values[0])), Some(F::from(output_values[1]))],
        out_pk: [Some(out_pk[0]), Some(out_pk[1])],
        out_rcm: [Some(out_rcm[0]), Some(out_rcm[1])],
    };

    Built {
        circuit,
        owner_nk,
        in_rho: [inputs[0].rho, inputs[1].rho],
        out_pk,
        out_rcm,
        nullifiers,
    }
}

/// Recompute an output commitment for an edited (value, pk, rho, rcm) so a witness edit stays
/// internally consistent with the public cm it claims.
fn cm(cfg: &PoseidonCfg<F>, v: F, pk: F, rho: F, rcm: F) -> F {
    common::hash_n(cfg, &[F::from(TAG_CM), v, pk, rho, rcm])
}

// ===========================================================================
// FAITHFULNESS ANCHOR — mirror(ko=none) ≡ shipped, over honest + adversarial witnesses.
// ===========================================================================

#[test]
fn mirror_is_faithful_to_shipped_circuit() {
    let cfg = poseidon_config();
    let mut rng = StdRng::from_seed([0x11; 32]);

    // A spread of honest cases + deliberately-broken cases; the mirror with NO knockouts must
    // agree with the shipped circuit's verdict on EVERY one, or the mirror is not faithful.
    for case in 0..24 {
        let a = 10_000 + rng.next_u64() % 1_000_000;
        let b = 10_000 + rng.next_u64() % 1_000_000;
        let total = a + b;
        let fee = rng.next_u64() % (total / 8 + 1);
        let public_out = rng.next_u64() % ((total - fee) / 3 + 1);
        let first = rng.next_u64() % (total - fee - public_out + 1);
        let mut built = build_honest(&mut rng, &cfg, [a, b], fee, public_out, first);

        // Perturb some cases into UNSAT territory so faithfulness is checked on BOTH verdicts.
        match case % 4 {
            1 => {
                // break conservation
                let bumped = built.circuit.out_v[0].unwrap() + F::one();
                built.circuit.out_v[0] = Some(bumped);
                built.circuit.cm_out[0] = Some(cm(
                    &cfg,
                    bumped,
                    built.out_pk[0],
                    built.nullifiers[0],
                    built.out_rcm[0],
                ));
            }
            2 => {
                // break a nullifier
                built.circuit.nf[0] = Some(built.circuit.nf[0].unwrap() + F::one());
            }
            3 => {
                // break a Merkle path bit
                built.circuit.in_bits[0][3] = !built.circuit.in_bits[0][3];
            }
            _ => {}
        }

        let shipped = shipped_satisfied(&built.circuit);
        let mirror = mirror_satisfied(MirrorTransfer::new(built.circuit.clone(), KnockOut::none()));
        assert_eq!(
            shipped, mirror,
            "mirror(ko=none) disagreed with shipped circuit on case {case} \
             (shipped={shipped}, mirror={mirror}) — mirror is not faithful"
        );
    }
}

// ===========================================================================
// Deposit-circuit mirror (row 6/10 kill for the deposit path)
// ===========================================================================

#[derive(Clone)]
struct MirrorDeposit {
    inner: DepositCircuit,
    drop_commitment: bool, // lib.rs:485
}

impl ConstraintSynthesizer<F> for MirrorDeposit {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let cfg = &self.inner.cfg;
        let cm_pub = FpVar::new_input(cs.clone(), || opt(self.inner.cm))?;
        let v_pub = FpVar::new_input(cs.clone(), || opt(self.inner.v_pub).map(F::from))?;
        let pk = FpVar::new_witness(cs.clone(), || opt(self.inner.pk))?;
        let rho = FpVar::new_witness(cs.clone(), || opt(self.inner.rho))?;
        let rcm = FpVar::new_witness(cs.clone(), || opt(self.inner.rcm))?;
        let tag_cm = FpVar::constant(F::from(TAG_CM));
        let cm = hash_n_gadget(cs.clone(), cfg, &[tag_cm, v_pub, pk, rho, rcm])?;
        if !self.drop_commitment {
            cm.enforce_equal(&cm_pub)?;
        }
        Ok(())
    }
}

fn deposit_satisfied(c: &DepositCircuit) -> bool {
    let cs = ConstraintSystem::<F>::new_ref();
    c.clone().generate_constraints(cs.clone()).unwrap();
    cs.is_satisfied().unwrap()
}
fn mirror_deposit_satisfied(m: MirrorDeposit) -> bool {
    let cs = ConstraintSystem::<F>::new_ref();
    m.generate_constraints(cs.clone()).unwrap();
    cs.is_satisfied().unwrap()
}

// ===========================================================================
// ROW 1 — Value conservation (lib.rs:441). Kill: drop_conservation.
// ===========================================================================
#[test]
fn row01_value_conservation() {
    let cfg = poseidon_config();
    for seed in [0x01u8, 0x02] {
        let mut rng = StdRng::from_seed([seed; 32]);
        let built = build_honest(&mut rng, &cfg, [500_000, 300_000], 20, 1_000, 250_000);
        assert_shipped_sat(&built.circuit, "row1 honest");

        // Adversarial: output 0 worth one more unit, with a matching commitment so ONLY the
        // conservation equality (441) is violated — outputs now exceed inputs by 1.
        let mut adv = built.circuit.clone();
        let bumped = adv.out_v[0].unwrap() + F::one();
        adv.out_v[0] = Some(bumped);
        adv.cm_out[0] = Some(cm(
            &cfg, bumped, built.out_pk[0], built.nullifiers[0], built.out_rcm[0],
        ));
        assert_shipped_unsat(&adv, "row1 outputs exceed inputs by 1");

        let ko = KnockOut { drop_conservation: true, ..KnockOut::none() };
        assert_kill_flip(MirrorTransfer::new(adv, ko), "row1 conservation (441)");
    }
}

// ===========================================================================
// ROW 2 — Range constraints (enforce_u64_range, lib.rs:236-254; calls 414/434).
// Kill: shipped enforce_range=false, and mirror range_outputs / range_inputs off.
// ===========================================================================
#[test]
fn row02_range_constraints_field_wrap_mint() {
    let cfg = poseidon_config();
    for seed in [0x21u8, 0x22] {
        let mut rng = StdRng::from_seed([seed; 32]);
        let built = build_honest(&mut rng, &cfg, [70, 30], 5, 0, 55); // honest out = [55, 40]
        assert_shipped_sat(&built.circuit, "row2 honest");

        // Field-wrap mint on OUTPUTS (out_v is a raw field in the shipped struct): -1 + 96 + 5 == 100
        // in the field, but -1 hides p-1 while a spendable 96-note is minted.
        let neg = -F::one();
        let mut adv = built.circuit.clone();
        adv.out_v = [Some(neg), Some(F::from(96u64))];
        adv.cm_out = [
            Some(cm(&cfg, neg, built.out_pk[0], built.nullifiers[0], built.out_rcm[0])),
            Some(cm(&cfg, F::from(96u64), built.out_pk[1], built.nullifiers[1], built.out_rcm[1])),
        ];
        assert_shipped_unsat(&adv, "row2 output field-wrap mint (enforce_range=true)");

        // Built-in kill via the shipped enforce_range hook.
        let mut vuln = adv.clone();
        vuln.enforce_range = false;
        assert_shipped_sat(&vuln, "row2 KILL: enforce_range=false accepts the mint");

        // Mirror kill isolating the OUTPUT range invocation (lib.rs:434-436).
        let ko = KnockOut { range_outputs: false, ..KnockOut::none() };
        assert_kill_flip(MirrorTransfer::new(adv, ko), "row2 output range (434)");
    }

    // INPUT range invocation (lib.rs:414-416) isolated: a note whose committed value is 2^64
    // (just past u64) sits in the tree; outputs are in-range and conserve. The shipped struct types
    // in_v as u64 so this is expressed against the faithful mirror via in_v_field_override.
    let mut rng = StdRng::from_seed([0x2f; 32]);
    let over = F::from(u64::MAX) + F::one(); // 2^64
    let owner_nk = F::rand(&mut rng);
    let rho0 = F::rand(&mut rng);
    let rcm0 = F::rand(&mut rng);
    let pk0 = derive_pk(&cfg, owner_nk);
    let leaf0 = cm(&cfg, over, pk0, rho0, rcm0);
    let n1 = Note { v: 10, nk: owner_nk, rho: F::rand(&mut rng), rcm: F::rand(&mut rng) };
    let mut filler = || Note { v: 1, nk: F::rand(&mut rng), rho: F::rand(&mut rng), rcm: F::rand(&mut rng) };
    let leaves = vec![filler().cm(&cfg), leaf0, filler().cm(&cfg), filler().cm(&cfg), n1.cm(&cfg), filler().cm(&cfg)];
    let tree = DenseTree { leaves };
    let anchor = tree.root(&cfg);
    let (s1, b1) = tree.path(&cfg, 1);
    let (s2, b2) = tree.path(&cfg, 4);
    let nf0 = derive_nf(&cfg, owner_nk, rho0);
    let nf1 = n1.nf(&cfg);
    // in_sum = 2^64 + 10; outputs both in-range: (2^64-1) + 11.
    let out_pk0 = derive_pk(&cfg, F::rand(&mut rng));
    let out_pk1 = derive_pk(&cfg, owner_nk);
    let out_rcm0 = F::rand(&mut rng);
    let out_rcm1 = F::rand(&mut rng);
    let outv0 = F::from(u64::MAX);
    let outv1 = F::from(11u64);
    let base = TransferCircuit {
        cfg: cfg.clone(),
        enforce_range: true,
        anchor: Some(anchor),
        nf: [Some(nf0), Some(nf1)],
        cm_out: [
            Some(cm(&cfg, outv0, out_pk0, nf0, out_rcm0)),
            Some(cm(&cfg, outv1, out_pk1, nf1, out_rcm1)),
        ],
        fee: Some(0),
        v_pub_out: Some(0),
        recipient_binding: Some(F::rand(&mut rng)),
        in_v: [Some(0), Some(10)], // idx0 overridden to `over` on the mirror
        in_nk: [Some(owner_nk), Some(owner_nk)],
        in_rho: [Some(rho0), Some(n1.rho)],
        in_rcm: [Some(rcm0), Some(n1.rcm)],
        in_siblings: [s1, s2],
        in_bits: [b1, b2],
        out_v: [Some(outv0), Some(outv1)],
        out_pk: [Some(out_pk0), Some(out_pk1)],
        out_rcm: [Some(out_rcm0), Some(out_rcm1)],
    };
    let mut on = MirrorTransfer::new(base.clone(), KnockOut::none());
    on.in_v_field_override[0] = Some(over);
    assert!(!mirror_satisfied(on), "row2 input range (414): 2^64 input rejected");
    let mut off = MirrorTransfer::new(base, KnockOut { range_inputs: false, ..KnockOut::none() });
    off.in_v_field_override[0] = Some(over);
    assert!(mirror_satisfied(off), "row2 KILL input range (414): 2^64 input accepted when dropped");
}

// ===========================================================================
// ROW 3 — Nullifier derivation (lib.rs:410-411). Kill: drop_nullifier.
// ===========================================================================
#[test]
fn row03_nullifier_derivation() {
    let cfg = poseidon_config();
    for seed in [0x31u8, 0x32] {
        let mut rng = StdRng::from_seed([seed; 32]);
        let built = build_honest(&mut rng, &cfg, [40_000, 60_000], 7, 500, 30_000);
        assert_shipped_sat(&built.circuit, "row3 honest");

        // Public nullifier disagrees with H(2,nk,rho) — only line 411 fails.
        let mut adv = built.circuit.clone();
        adv.nf[0] = Some(adv.nf[0].unwrap() + F::one());
        assert_shipped_unsat(&adv, "row3 nf_pub != H(2,nk,rho)");

        let ko = KnockOut { drop_nullifier: true, ..KnockOut::none() };
        assert_kill_flip(MirrorTransfer::new(adv, ko), "row3 nullifier binding (411)");
    }
}

// ===========================================================================
// ROW 4 — Note ownership: pk = H(1,nk) feeding cm (lib.rs:405). Kill: drop_pk_binding.
// A party who knows a note's opening but NOT the owner's nk tries to spend it with their own
// key (minting a valid distinct nullifier). Shipped rejects (wrong pk => wrong cm => not in tree).
// ===========================================================================
#[test]
fn row04_note_ownership() {
    let cfg = poseidon_config();
    for seed in [0x41u8, 0x42] {
        let mut rng = StdRng::from_seed([seed; 32]);
        let built = build_honest(&mut rng, &cfg, [100_000, 100_000], 3, 0, 90_000);
        assert_shipped_sat(&built.circuit, "row4 honest");

        // Attacker uses a DIFFERENT nullifier key for input 0 (the real owner is `built.owner_nk`).
        let attacker_nk = F::rand(&mut rng);
        let mut adv = built.circuit.clone();
        adv.in_nk[0] = Some(attacker_nk);
        // The attacker's nullifier for this note (so line 411 passes on its own).
        adv.nf[0] = Some(derive_nf(&cfg, attacker_nk, built.in_rho[0]));
        // Output 0 rho chains to the (now attacker) nullifier — keep the output commitment consistent.
        adv.cm_out[0] = Some(cm(
            &cfg,
            adv.out_v[0].unwrap(),
            built.out_pk[0],
            adv.nf[0].unwrap(),
            built.out_rcm[0],
        ));
        // Shipped: pk = H(1, attacker_nk) != owner pk => input cm != tree leaf => Merkle fails.
        assert_shipped_unsat(&adv, "row4 spend-without-owning (wrong nk)");

        // Kill: free the pk from nk (assign the REAL owner pk) so the note commitment matches the
        // tree; input 1 keeps its honest owner pk. Now the note is spent by a non-owner => SAT.
        let ko = KnockOut { drop_pk_binding: true, ..KnockOut::none() };
        let mut m = MirrorTransfer::new(adv, ko);
        m.in_pk_override[0] = Some(derive_pk(&cfg, built.owner_nk));
        m.in_pk_override[1] = Some(derive_pk(&cfg, built.owner_nk));
        assert_kill_flip(m, "row4 pk=H(1,nk) ownership binding (405)");
    }
}

// ===========================================================================
// ROW 5 — Merkle path enforcement (lib.rs:407-408). Kill: drop_merkle.
// ===========================================================================
#[test]
fn row05_merkle_path_enforcement() {
    let cfg = poseidon_config();
    for (seed, level) in [(0x51u8, 0usize), (0x52u8, 7usize)] {
        let mut rng = StdRng::from_seed([seed; 32]);
        let built = build_honest(&mut rng, &cfg, [10_000, 20_000], 1, 0, 15_000);
        assert_shipped_sat(&built.circuit, "row5 honest");

        // Flip one position bit on input 0's path => folds to a different root != anchor.
        let mut adv = built.circuit.clone();
        adv.in_bits[0][level] = !adv.in_bits[0][level];
        assert_shipped_unsat(&adv, "row5 tampered path bit");

        let ko = KnockOut { drop_merkle: true, ..KnockOut::none() };
        assert_kill_flip(MirrorTransfer::new(adv, ko), "row5 root==anchor (408)");

        // Also: a fabricated anchor is rejected, and dropping merkle accepts it.
        let mut adv2 = built.circuit.clone();
        adv2.anchor = Some(adv2.anchor.unwrap() + F::one());
        assert_shipped_unsat(&adv2, "row5 fabricated anchor");
        let ko2 = KnockOut { drop_merkle: true, ..KnockOut::none() };
        assert_kill_flip(MirrorTransfer::new(adv2, ko2), "row5 fabricated anchor (408)");
    }
}

// ===========================================================================
// ROW 6 — Output commitment formation (lib.rs:431-432) AND rho-chaining (lib.rs:428).
// Kills: drop_output_commitment; drop_rho_chain.
// ===========================================================================
#[test]
fn row06_output_commitment_and_rho_chaining() {
    let cfg = poseidon_config();
    for seed in [0x61u8, 0x62] {
        let mut rng = StdRng::from_seed([seed; 32]);
        let built = build_honest(&mut rng, &cfg, [80_000, 40_000], 4, 200, 70_000);
        assert_shipped_sat(&built.circuit, "row6 honest");

        // (A) commitment binding: public cm_out disagrees with H(3,...) => line 432 fails.
        let mut adv_cm = built.circuit.clone();
        adv_cm.cm_out[0] = Some(adv_cm.cm_out[0].unwrap() + F::one());
        assert_shipped_unsat(&adv_cm, "row6A cm_out != H(3,v,pk,rho_out,rcm)");
        let ko = KnockOut { drop_output_commitment: true, ..KnockOut::none() };
        assert_kill_flip(MirrorTransfer::new(adv_cm, ko), "row6A output commitment (432)");

        // (B) Faerie-Gold rho-chaining: output 0 commits to a rho OTHER than nf_0. Shipped forces
        // rho_out = nf_0, so the computed cm != the claimed cm => UNSAT.
        let rogue_rho = built.nullifiers[0] + F::from(0xB00Bu64);
        let mut adv_rho = built.circuit.clone();
        adv_rho.cm_out[0] = Some(cm(
            &cfg,
            adv_rho.out_v[0].unwrap(),
            built.out_pk[0],
            rogue_rho,
            built.out_rcm[0],
        ));
        assert_shipped_unsat(&adv_rho, "row6B output rho != nullifier chain");
        // Kill: free rho_out and assign the rogue rho => cm matches => SAT.
        let ko_rho = KnockOut { drop_rho_chain: true, ..KnockOut::none() };
        let mut m = MirrorTransfer::new(adv_rho, ko_rho);
        m.out_rho_override[0] = Some(rogue_rho);
        m.out_rho_override[1] = Some(built.nullifiers[1]);
        assert_kill_flip(m, "row6B rho_out = nf chaining (428)");
    }
}

// ===========================================================================
// ROW 7 — Recipient binding (lib.rs:381). The shipped struct hardwires the witness mirror to the
// public field, so a differing witness is expressible only against the faithful mirror (proven
// == shipped by the anchor test). Complementary proof-level binding: the existing
// security_properties test mutates public-input position 7 and shows Groth16 rejects it.
// Kill: drop_recipient.
// ===========================================================================
#[test]
fn row07_recipient_binding() {
    let cfg = poseidon_config();
    for seed in [0x71u8, 0x72] {
        let mut rng = StdRng::from_seed([seed; 32]);
        let built = build_honest(&mut rng, &cfg, [55_000, 45_000], 2, 100, 40_000);

        // Witness mirror disagrees with the public recipient field: line 381 present => UNSAT.
        let mut m_on = MirrorTransfer::new(built.circuit.clone(), KnockOut::none());
        m_on.recipient_witness_override = Some(built.circuit.recipient_binding.unwrap() + F::one());
        assert!(
            !mirror_satisfied(m_on),
            "row7 recipient witness != public rejected (381 present)"
        );

        // Kill: drop line 381 => recipient_binding referenced by zero constraints => the differing
        // witness is accepted (recipient malleable).
        let mut m_off =
            MirrorTransfer::new(built.circuit.clone(), KnockOut { drop_recipient: true, ..KnockOut::none() });
        m_off.recipient_witness_override = Some(built.circuit.recipient_binding.unwrap() + F::one());
        assert!(
            mirror_satisfied(m_off),
            "row7 KILL: dropping 381 unbinds the recipient"
        );
    }
}

// ===========================================================================
// ROW 8 — Public withdrawal treatment (v_pub_out). The circuit has NO range gadget on v_pub_out;
// its [0,2^64) bound is at the interface (candid Nat64 + nat64Field, Main.mo:1130/2106). The
// shipped struct types v_pub_out as u64 so the field-wrap witness is expressible only against the
// compiled R1CS (via the faithful mirror). GAP: mirror accepts a wrapped v_pub_out that mints;
// FIX (proposal): mirror with range_v_pub_out on rejects it.
// ===========================================================================
#[test]
fn row08_public_withdrawal_field_wrap_gap_and_fix() {
    let cfg = poseidon_config();
    for seed in [0x81u8, 0x82] {
        let mut rng = StdRng::from_seed([seed; 32]);
        // Honest base: in = [200_000, 0], out = [100_000, 100_000], fee 0, v_pub_out 0.
        let built = build_honest(&mut rng, &cfg, [200_000, 0], 0, 0, 100_000);
        // Adversarial: bump output 0 by 50_000 (mint), balanced by v_pub_out = -50_000 (field wrap).
        let mut adv = built.circuit.clone();
        let bumped = adv.out_v[0].unwrap() + F::from(50_000u64);
        adv.out_v[0] = Some(bumped);
        adv.cm_out[0] = Some(cm(&cfg, bumped, built.out_pk[0], built.nullifiers[0], built.out_rcm[0]));
        let wrapped = -F::from(50_000u64); // r - 50_000, canonical, NOT a u64

        // GAP: faithful mirror (ko=none) with the raw wrapped v_pub_out => SATISFIED (over-mint).
        let mut gap = MirrorTransfer::new(adv.clone(), KnockOut::none());
        gap.v_pub_out_field_override = Some(wrapped);
        assert!(
            mirror_satisfied(gap),
            "row8 GAP: shipped R1CS accepts a field-wrapped v_pub_out (mint of 50k)"
        );

        // FIX: the proposed in-circuit range on v_pub_out rejects the wrapped value.
        let mut fix = MirrorTransfer::new(adv, KnockOut { range_v_pub_out: true, ..KnockOut::none() });
        fix.v_pub_out_field_override = Some(wrapped);
        assert!(
            !mirror_satisfied(fix),
            "row8 FIX: in-circuit range on v_pub_out rejects the wrap"
        );
    }
}

// ===========================================================================
// ROW 9 — Dummy-input behavior. There is NO dummy slot: fixed 2-in arity, no is_dummy flag, no
// conditional on any input (lib.rs:386-418). A dummy/fabricated input (not a real tree member) is
// rejected by the Merkle membership constraint (408). Kill: drop_merkle. Padding is via zero-value
// REAL notes (row 10).
// ===========================================================================
#[test]
fn row09_no_dummy_input_slot() {
    let cfg = poseidon_config();
    for seed in [0x91u8, 0x92] {
        let mut rng = StdRng::from_seed([seed; 32]);
        let built = build_honest(&mut rng, &cfg, [12_000, 8_000], 0, 0, 10_000);
        assert_shipped_sat(&built.circuit, "row9 honest");

        // "Dummy" input 0: change its opening so its commitment is NOT the tree leaf (a note that
        // was never appended). nf is unaffected (depends on nk,rho), so ONLY Merkle fails.
        let mut adv = built.circuit.clone();
        adv.in_rcm[0] = Some(F::rand(&mut rng));
        assert_shipped_unsat(&adv, "row9 fabricated/dummy input not in tree");

        let ko = KnockOut { drop_merkle: true, ..KnockOut::none() };
        assert_kill_flip(MirrorTransfer::new(adv, ko), "row9 membership is mandatory (408)");
    }
}

// ===========================================================================
// ROW 10 — Zero-value notes. v=0 passes range and still commits; a zero in the value sum cannot be
// paired with a commitment to a nonzero value (the commitment binds the value). Kill:
// drop_output_commitment.
// ===========================================================================
#[test]
fn row10_zero_value_notes() {
    let cfg = poseidon_config();
    // Honest zero-value OUTPUT note (out = [0, 100_000]).
    let mut rng = StdRng::from_seed([0xa0; 32]);
    let built_out = build_honest(&mut rng, &cfg, [100_000, 0], 0, 0, 0);
    assert_shipped_sat(&built_out.circuit, "row10 honest zero-value output");
    assert!(
        built_out.circuit.out_v[0] == Some(F::from(0u64)),
        "row10 setup: output 0 is zero-valued"
    );

    // Honest zero-value INPUT note (input 0 has v=0, genuinely in the tree).
    let mut rng = StdRng::from_seed([0xa1; 32]);
    let built_in = build_honest(&mut rng, &cfg, [0, 100_000], 0, 0, 60_000);
    assert_shipped_sat(&built_in.circuit, "row10 honest zero-value input");

    // Adversarial: output 0 carries 0 in the conservation sum but its public commitment encodes 5.
    // Conservation still holds (0 + 100_000); ONLY the commitment (432) fails.
    let mut adv = built_out.circuit.clone();
    adv.cm_out[0] = Some(cm(
        &cfg, F::from(5u64), built_out.out_pk[0], built_out.nullifiers[0], built_out.out_rcm[0],
    ));
    assert_shipped_unsat(&adv, "row10 zero in sum but commitment to 5");
    let ko = KnockOut { drop_output_commitment: true, ..KnockOut::none() };
    assert_kill_flip(MirrorTransfer::new(adv, ko), "row10 commitment binds value (432)");
}

// ===========================================================================
// ROW 11 — Fee accounting. Same shape as row 8: no in-circuit range on `fee`; [0,2^64) bound is at
// the interface (candid Nat64 + nat64Field, Main.mo:1130/2105). GAP + FIX via the faithful mirror.
// ===========================================================================
#[test]
fn row11_fee_field_wrap_gap_and_fix() {
    let cfg = poseidon_config();
    for seed in [0xb1u8, 0xb2] {
        let mut rng = StdRng::from_seed([seed; 32]);
        let built = build_honest(&mut rng, &cfg, [200_000, 0], 0, 0, 100_000);
        let mut adv = built.circuit.clone();
        let bumped = adv.out_v[0].unwrap() + F::from(50_000u64);
        adv.out_v[0] = Some(bumped);
        adv.cm_out[0] = Some(cm(&cfg, bumped, built.out_pk[0], built.nullifiers[0], built.out_rcm[0]));
        let wrapped = -F::from(50_000u64); // r - 50_000, a canonical field element, not a u64

        let mut gap = MirrorTransfer::new(adv.clone(), KnockOut::none());
        gap.fee_field_override = Some(wrapped);
        assert!(
            mirror_satisfied(gap),
            "row11 GAP: shipped R1CS accepts a field-wrapped fee (mint of 50k)"
        );

        let mut fix = MirrorTransfer::new(adv, KnockOut { range_fee: true, ..KnockOut::none() });
        fix.fee_field_override = Some(wrapped);
        assert!(
            !mirror_satisfied(fix),
            "row11 FIX: in-circuit range on fee rejects the wrap"
        );
    }
}

// ===========================================================================
// ROW 12 — Field-reduction / non-canonical encoding ambiguity. NOT an R1CS constraint: rejected at
// the ledger canonical-decode (Groth16Wire.mo:72 -> Fr.mo:19, `x < P`). Rust mirror: f_from_hex /
// deserialize_compressed enforces `< modulus` (lib.rs:513). Teeth: a canonical encoding round-trips;
// a non-canonical one (== modulus) is REJECTED; and a REDUCING decode would alias it to 0 — the
// two-openings ambiguity the rejection prevents.
// ===========================================================================
#[test]
fn row12_field_reduction_ambiguity() {
    let k = F::from(12_345u64);
    let hex_k = common::f_to_hex(&k);
    assert_eq!(common::f_from_hex(&hex_k), Some(k), "row12 canonical encoding accepted");

    // 32-byte LE encoding of the modulus r itself (>= r => non-canonical).
    let modulus = <F as PrimeField>::MODULUS;
    let mut bytes = modulus.to_bytes_le();
    assert!(bytes.len() <= 32, "row12 modulus fits in 32 bytes");
    bytes.resize(32, 0);
    let hex_noncanon: String = bytes.iter().map(|x| format!("{x:02x}")).collect();
    assert_eq!(
        common::f_from_hex(&hex_noncanon),
        None,
        "row12 non-canonical (== modulus) encoding REJECTED at decode"
    );

    // KILL reasoning made concrete: a reducing decode maps the SAME bytes to 0 (r mod r), colliding
    // with the canonical zero encoding — two openings of one public input. The rejecting decode is
    // what removes the ambiguity.
    let reduced = F::from_le_bytes_mod_order(&bytes);
    assert_eq!(
        reduced,
        F::from(0u64),
        "row12 a REDUCING decode would alias modulus-bytes to 0 (the ambiguity rejection prevents)"
    );
}

// ===========================================================================
// DEPOSIT circuit — commitment binding (lib.rs:485), zero-value + max-value (rows 6/10/2-by-type).
// Kill: MirrorDeposit drop_commitment.
// ===========================================================================
#[test]
fn deposit_commitment_formation_and_edges() {
    let cfg = poseidon_config();
    let mut rng = StdRng::from_seed([0xde; 32]);
    for value in [0u64, 1, 10_000, u32::MAX as u64, u64::MAX] {
        let pk = derive_pk(&cfg, F::rand(&mut rng));
        let rho = F::rand(&mut rng);
        let rcm = F::rand(&mut rng);
        let cmv = note_commitment(&cfg, value, pk, rho, rcm);
        let honest = DepositCircuit {
            cfg: cfg.clone(),
            cm: Some(cmv),
            v_pub: Some(value),
            pk: Some(pk),
            rho: Some(rho),
            rcm: Some(rcm),
        };
        assert!(deposit_satisfied(&honest), "deposit honest v={value}");

        // Adversarial: claimed public commitment != H(3, v_pub, pk, rho, rcm) => line 485 fails.
        let mut adv = honest.clone();
        adv.cm = Some(cmv + F::one());
        assert!(!deposit_satisfied(&adv), "deposit wrong cm UNSAT v={value}");

        // Kill: drop the commitment binding => SAT.
        assert!(
            mirror_deposit_satisfied(MirrorDeposit { inner: adv, drop_commitment: true }),
            "deposit KILL commitment binding (485) v={value}"
        );
    }
}

// ===========================================================================
// EXTRA finding (verify-loop pass 2) — no in-circuit input-note distinctness. The shipped circuit
// accepts the SAME note in both input slots (value doubling); closed end-to-end at the canister
// (nullifier_1 == nullifier_2 rejected, Main.mo:2087-2088). Proposed fix (harden_distinctness):
// nf[0] != nf[1] rejects it in-circuit.
// ===========================================================================
#[test]
fn extra_input_note_distinctness_gap_and_fix() {
    let cfg = poseidon_config();
    let mut rng = StdRng::from_seed([0xdd; 32]);

    let owner_nk = F::rand(&mut rng);
    let note = Note { v: 100_000, nk: owner_nk, rho: F::rand(&mut rng), rcm: F::rand(&mut rng) };
    let mut filler = || Note { v: 1, nk: F::rand(&mut rng), rho: F::rand(&mut rng), rcm: F::rand(&mut rng) };
    let leaves = vec![filler().cm(&cfg), note.cm(&cfg), filler().cm(&cfg), filler().cm(&cfg)];
    let tree = DenseTree { leaves };
    let anchor = tree.root(&cfg);
    let (s, b) = tree.path(&cfg, 1);
    let nf = note.nf(&cfg);

    // Both inputs are the SAME note; in_value_sum = 200_000 (doubled). Outputs distinct, sum 200_000.
    let out_pk0 = derive_pk(&cfg, F::rand(&mut rng));
    let out_pk1 = derive_pk(&cfg, owner_nk);
    let out_rcm0 = F::rand(&mut rng);
    let out_rcm1 = F::rand(&mut rng);
    let ov0 = F::from(120_000u64);
    let ov1 = F::from(80_000u64);
    let doubled = TransferCircuit {
        cfg: cfg.clone(),
        enforce_range: true,
        anchor: Some(anchor),
        nf: [Some(nf), Some(nf)],
        cm_out: [
            Some(cm(&cfg, ov0, out_pk0, nf, out_rcm0)),
            Some(cm(&cfg, ov1, out_pk1, nf, out_rcm1)),
        ],
        fee: Some(0),
        v_pub_out: Some(0),
        recipient_binding: Some(F::rand(&mut rng)),
        in_v: [Some(note.v), Some(note.v)],
        in_nk: [Some(owner_nk), Some(owner_nk)],
        in_rho: [Some(note.rho), Some(note.rho)],
        in_rcm: [Some(note.rcm), Some(note.rcm)],
        in_siblings: [s.clone(), s],
        in_bits: [b.clone(), b],
        out_v: [Some(ov0), Some(ov1)],
        out_pk: [Some(out_pk0), Some(out_pk1)],
        out_rcm: [Some(out_rcm0), Some(out_rcm1)],
    };
    // GAP: the shipped circuit is SATISFIED by the same-note-twice witness.
    assert_shipped_sat(&doubled, "distinctness GAP: same note in both input slots doubles value");

    // FIX: the proposed nf[0] != nf[1] constraint rejects it (as a synthesis infeasibility).
    let fix = MirrorTransfer::new(doubled, KnockOut { harden_distinctness: true, ..KnockOut::none() });
    assert!(
        mirror_rejects(fix),
        "distinctness FIX: in-circuit nf[0] != nf[1] rejects the doubled note"
    );

    // The proposed constraint does NOT break an honest transfer (two distinct input notes).
    let mut rng2 = StdRng::from_seed([0xdc; 32]);
    let honest = build_honest(&mut rng2, &cfg, [70_000, 30_000], 5, 0, 60_000);
    let honest_hardened =
        MirrorTransfer::new(honest.circuit, KnockOut { harden_distinctness: true, ..KnockOut::none() });
    assert!(
        mirror_satisfied(honest_hardened),
        "distinctness FIX: honest distinct-nullifier transfer still satisfies the hardened circuit"
    );
}
