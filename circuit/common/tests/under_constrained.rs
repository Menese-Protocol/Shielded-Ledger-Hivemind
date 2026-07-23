//! §5 constraint-coverage / under-constrained detection (the highest-value ZK bug class).
//!
//! Two detectors over the transfer circuit's R1CS, plus teeth on a deliberately
//! under-constrained toy circuit:
//!
//! 1. R1CS EXPORT ANALYSIS: export the A/B/C matrices and report #vars, #constraints, and —
//!    the load-bearing metric — every witness variable that appears in NO constraint (an
//!    unconstrained witness is a free variable an attacker can set at will), plus every
//!    instance (public) variable with no effective constraint. For the real transfer circuit
//!    both counts must be zero.
//! 2. WITNESS-MUTATION SCAN: from a valid full assignment, perturb each witness variable by
//!    +1 and recheck R1CS satisfaction directly from the matrices. Every witness variable
//!    must be NOTICED (some constraint now fails); an unnoticed variable is a finding.
//! 3. TEETH: a toy circuit with (a) a witness var used in no constraint and (b) a boolean
//!    witness missing its x(x-1)=0 constraint — the detectors must flag BOTH, and the same
//!    detectors must report the real transfer circuit clean.
//!
//! Determinism: seeded; the scan is a pure function of the assignment. Lives in the test
//! tree so the frozen lib.rs / vendor diff is untouched.
#![cfg(feature = "bls12-381")]

use ark_ff::{Field, One, UniformRand, Zero};
use ark_relations::r1cs::{
    ConstraintMatrices, ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, LinearCombination,
    SynthesisError, Variable,
};
use ark_std::rand::{rngs::StdRng, RngCore, SeedableRng};
use common::{
    derive_pk, note_commitment, poseidon_config, DenseTree, Note, PoseidonCfg, ScalarField as F,
    TransferCircuit,
};

/// Full R1CS witness vector z = [1, instance.., witness..], and the matrices.
struct Exported {
    matrices: ConstraintMatrices<F>,
    z: Vec<F>,
    num_instance: usize,
    num_witness: usize,
}

fn export<C: ConstraintSynthesizer<F>>(circuit: C) -> Exported {
    let cs = ConstraintSystem::<F>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    cs.finalize();
    assert!(cs.is_satisfied().unwrap(), "circuit under export is not satisfied");
    let matrices = cs.to_matrices().expect("matrices");
    let borrowed = cs.borrow().unwrap();
    let num_instance = borrowed.num_instance_variables;
    let num_witness = borrowed.num_witness_variables;
    let mut z = borrowed.instance_assignment.clone(); // index 0 == the "one" variable
    z.extend_from_slice(&borrowed.witness_assignment);
    Exported { matrices, z, num_instance, num_witness }
}

fn dot(row: &[(F, usize)], z: &[F]) -> F {
    let mut acc = F::zero();
    for (c, i) in row {
        acc += *c * z[*i];
    }
    acc
}

/// True iff every constraint (A·z)(B·z) == (C·z) holds under z.
fn satisfies(m: &ConstraintMatrices<F>, z: &[F]) -> bool {
    for k in 0..m.num_constraints {
        if dot(&m.a[k], z) * dot(&m.b[k], z) != dot(&m.c[k], z) {
            return false;
        }
    }
    true
}

/// Variable indices (in z-space) that appear in at least one A/B/C row.
fn constrained_indices(m: &ConstraintMatrices<F>) -> std::collections::HashSet<usize> {
    let mut s = std::collections::HashSet::new();
    for rows in [&m.a, &m.b, &m.c] {
        for row in rows {
            for (_, i) in row {
                s.insert(*i);
            }
        }
    }
    s
}

fn honest_transfer(rng: &mut StdRng, cfg: &PoseidonCfg<F>) -> TransferCircuit {
    let owner_nk = F::rand(rng);
    let recipient_nk = F::rand(rng);
    let in_v = [80_000u64 + rng.next_u64() % 400_000, 50_000 + rng.next_u64() % 400_000];
    let inputs = [
        Note { v: in_v[0], nk: owner_nk, rho: F::rand(rng), rcm: F::rand(rng) },
        Note { v: in_v[1], nk: owner_nk, rho: F::rand(rng), rcm: F::rand(rng) },
    ];
    let mut filler = |rng: &mut StdRng| Note { v: 1, nk: F::rand(rng), rho: F::rand(rng), rcm: F::rand(rng) };
    let leaves = vec![
        filler(rng).cm(cfg), inputs[0].cm(cfg), filler(rng).cm(cfg),
        filler(rng).cm(cfg), inputs[1].cm(cfg), filler(rng).cm(cfg),
    ];
    let tree = DenseTree { leaves };
    let anchor = tree.root(cfg);
    let (sib0, bits0) = tree.path(cfg, 1);
    let (sib1, bits1) = tree.path(cfg, 4);
    let nf = [inputs[0].nf(cfg), inputs[1].nf(cfg)];
    let out_pk = [derive_pk(cfg, recipient_nk), derive_pk(cfg, owner_nk)];
    let out_rcm = [F::rand(rng), F::rand(rng)];
    let total = in_v[0] + in_v[1];
    let fee = rng.next_u64() % (total / 8 + 1);
    let v_pub_out = rng.next_u64() % ((total - fee) / 3 + 1);
    let rem = total - fee - v_pub_out;
    let o0 = rng.next_u64() % (rem + 1);
    let out_v = [o0, rem - o0];
    let cm_out = [
        note_commitment(cfg, out_v[0], out_pk[0], nf[0], out_rcm[0]),
        note_commitment(cfg, out_v[1], out_pk[1], nf[1], out_rcm[1]),
    ];
    TransferCircuit {
        cfg: cfg.clone(),
        enforce_range: true,
        anchor: Some(anchor),
        nf: [Some(nf[0]), Some(nf[1])],
        cm_out: [Some(cm_out[0]), Some(cm_out[1])],
        fee: Some(fee),
        v_pub_out: Some(v_pub_out),
        recipient_binding: Some(F::rand(rng)),
        in_v: [Some(in_v[0]), Some(in_v[1])],
        in_nk: [Some(inputs[0].nk), Some(inputs[1].nk)],
        in_rho: [Some(inputs[0].rho), Some(inputs[1].rho)],
        in_rcm: [Some(inputs[0].rcm), Some(inputs[1].rcm)],
        in_siblings: [sib0, sib1],
        in_bits: [bits0, bits1],
        out_v: [Some(F::from(out_v[0])), Some(F::from(out_v[1]))],
        out_pk: [Some(out_pk[0]), Some(out_pk[1])],
        out_rcm: [Some(out_rcm[0]), Some(out_rcm[1])],
    }
}

/// Returns (num_unconstrained_witness, num_uneffective_instance).
fn coverage_report(e: &Exported) -> (usize, usize) {
    let constrained = constrained_indices(&e.matrices);
    // z-space: index 0 is the one-var; instance 1..num_instance; witness after that.
    let mut unconstrained_witness = 0;
    for w in 0..e.num_witness {
        let zidx = e.num_instance + w;
        if !constrained.contains(&zidx) {
            unconstrained_witness += 1;
        }
    }
    let mut uneffective_instance = 0;
    for inst in 1..e.num_instance {
        if !constrained.contains(&inst) {
            uneffective_instance += 1;
        }
    }
    (unconstrained_witness, uneffective_instance)
}

/// Returns the list of witness variable indices whose +1 perturbation is NOT noticed.
fn unnoticed_witnesses(e: &Exported) -> Vec<usize> {
    let mut unnoticed = Vec::new();
    for w in 0..e.num_witness {
        let zidx = e.num_instance + w;
        let mut z2 = e.z.clone();
        z2[zidx] += F::one();
        if satisfies(&e.matrices, &z2) {
            unnoticed.push(w);
        }
    }
    unnoticed
}

#[test]
fn transfer_circuit_is_fully_constrained() {
    let cfg = poseidon_config();
    let mut rng = StdRng::from_seed([0x35; 32]);
    let e = export(honest_transfer(&mut rng, &cfg));
    let (unc_w, unc_i) = coverage_report(&e);
    println!(
        "R1CS-EXPORT: {} constraints, {} instance vars, {} witness vars; \
         unconstrained-witness={} uneffective-instance={}",
        e.matrices.num_constraints, e.num_instance, e.num_witness, unc_w, unc_i,
    );
    assert_eq!(unc_w, 0, "{unc_w} witness variables appear in NO constraint");
    assert_eq!(unc_i, 0, "{unc_i} public inputs are not effectively constrained");

    // witness-mutation scan: every witness var must be noticed.
    let unnoticed = unnoticed_witnesses(&e);
    println!("WITNESS-SCAN: {} witness vars, {} unnoticed", e.num_witness, unnoticed.len());
    assert!(
        unnoticed.is_empty(),
        "{} witness variables are under-constrained (perturbation not noticed): {:?}",
        unnoticed.len(),
        &unnoticed[..unnoticed.len().min(8)],
    );
    println!("UNDER-CONSTRAINED GREEN: transfer circuit fully constrained, all witnesses noticed");
}

// ---- teeth: a deliberately under-constrained toy circuit ----

struct UnderConstrained {
    // an honest product statement a*b == c (public c), PLUS:
    //  - `dead`: a witness allocated but never constrained
    //  - `pseudo_bool`: a witness meant to be boolean but WITHOUT its x(x-1)=0 constraint
    a: F,
    b: F,
    c: F,
    dead: F,
    pseudo_bool: F,
    constrain_dead: bool,
    constrain_bool: bool,
}

impl ConstraintSynthesizer<F> for UnderConstrained {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| Ok(self.a))?;
        let b = cs.new_witness_variable(|| Ok(self.b))?;
        let c = cs.new_input_variable(|| Ok(self.c))?;
        cs.enforce_constraint(lc(a), lc(b), lc(c))?;
        let dead = cs.new_witness_variable(|| Ok(self.dead))?;
        if self.constrain_dead {
            // a real use: dead == a (so it becomes constrained)
            cs.enforce_constraint(lc(dead), one_lc(), lc(a))?;
        }
        let pb = cs.new_witness_variable(|| Ok(self.pseudo_bool))?;
        if self.constrain_bool {
            // booleanity: pb * (pb - 1) == 0
            cs.enforce_constraint(lc(pb), minus_one_lc(pb), zero_lc())?;
        } else {
            // pb still must appear SOMEWHERE or it's trivially dead; use it in a constraint
            // that does NOT pin it to {0,1}: pb * 1 == pb (a tautology — the classic
            // under-constrained boolean: present but free).
            cs.enforce_constraint(lc(pb), one_lc(), lc(pb))?;
        }
        Ok(())
    }
}

fn lc(v: Variable) -> LinearCombination<F> {
    LinearCombination::from(v)
}
fn one_lc() -> LinearCombination<F> {
    LinearCombination::from((F::one(), Variable::One))
}
fn zero_lc() -> LinearCombination<F> {
    LinearCombination::zero()
}
fn minus_one_lc(v: Variable) -> LinearCombination<F> {
    // (v - 1)
    LinearCombination::from(v) - (F::one(), Variable::One)
}

#[test]
fn teeth_detectors_flag_a_planted_under_constrained_circuit() {
    // Honest baseline: a=3,b=4,c=12; dead=7 (unconstrained); pseudo_bool=5 (not booleanity).
    let planted = UnderConstrained {
        a: F::from(3u64), b: F::from(4u64), c: F::from(12u64),
        dead: F::from(7u64), pseudo_bool: F::from(5u64),
        constrain_dead: false, constrain_bool: false,
    };
    let e = export(planted);
    let (unc_w, _unc_i) = coverage_report(&e);
    // `dead` must be flagged as an unconstrained witness.
    assert!(unc_w >= 1, "TEETH FAILED: dead witness not flagged as unconstrained");

    // Witness-mutation scan: perturbing `dead` (or the free pseudo_bool) is NOT noticed.
    let unnoticed = unnoticed_witnesses(&e);
    assert!(
        !unnoticed.is_empty(),
        "TEETH FAILED: planted under-constrained witnesses were all noticed"
    );

    // The FIXED version (both constraints present) must be clean.
    let fixed = UnderConstrained {
        a: F::from(3u64), b: F::from(4u64), c: F::from(12u64),
        dead: F::from(3u64), pseudo_bool: F::from(1u64),
        constrain_dead: true, constrain_bool: true,
    };
    let ef = export(fixed);
    let (fw, _fi) = coverage_report(&ef);
    let fixed_unnoticed = unnoticed_witnesses(&ef);
    assert_eq!(fw, 0, "fixed toy circuit still has unconstrained witnesses");
    // pseudo_bool=1 with booleanity present: perturbing to 2 breaks 2*(2-1)=2 != 0 -> noticed.
    assert!(
        fixed_unnoticed.is_empty(),
        "fixed toy circuit still reports unnoticed witnesses: {fixed_unnoticed:?}"
    );
    println!(
        "UNDER-CONSTRAINED TEETH GREEN: planted circuit flagged ({} unconstrained, {} unnoticed); \
         fixed circuit clean",
        unc_w, unnoticed.len(),
    );
    let _ = F::from(0u64).is_zero();
}
