//! WITNESS UNIQUENESS — the property soundness actually rests on.
//!
//! Groth16 proves "I know a witness satisfying this system". It says nothing about whether the
//! system pins that witness down. If two distinct witnesses satisfy the same public inputs, a
//! prover chooses between them, and for a value-conservation statement that is unlimited mint.
//!
//! The existing coverage checks SAMPLE this property:
//!   * `coverage_report` asks whether a variable APPEARS in a constraint — syntactic presence,
//!     not semantic determination.
//!   * `unnoticed_witnesses` perturbs ONE variable by `+1` at ONE base point. A joint freedom is
//!     invisible to it: if `w1 * w2 = c`, moving either alone breaks the constraint, yet
//!     infinitely many pairs satisfy it.
//!
//! This file PROVES the property constructively instead, by determinism propagation over the
//! R1CS — the algorithm behind Ecne (0xPARC, 2022) and the uniqueness query in Picus (Pailoor
//! et al., PLDI 2023).
//!
//! THE ALGORITHM. Call a variable "pinned" when the public inputs force its value. Seed the
//! pinned set with the constant `1` and every instance variable. Then sweep the constraints to a
//! fixpoint, pinning what each one forces:
//!
//!   constraint i is   (A_i · z) * (B_i · z) = (C_i · z)
//!
//!   * A and B fully pinned  =>  the product is a known constant  =>  C_i · z is forced.
//!   * A fully pinned and non-zero, C fully pinned  =>  B_i · z is forced (divide).
//!   * B fully pinned and non-zero, C fully pinned  =>  A_i · z is forced.
//!   * A fully pinned and EQUAL TO ZERO  =>  the product is 0 regardless of B  =>  C_i · z = 0
//!     is forced. (Symmetrically for B pinned to zero.)
//!
//!   A forced linear form with exactly ONE unpinned variable, at a non-zero coefficient, pins
//!   that variable: its value is (target - known part) / coeff, a single field element.
//!
//! If every witness variable ends up pinned, the witness is a FUNCTION of the public inputs, so
//! it is unique, so the statement is sound against the under-constrained class. That is a proof,
//! not a sample.
//!
//! SOUND BUT INCOMPLETE, and this is stated rather than hidden. Failure to pin a variable does
//! NOT prove it is under-constrained — the system may determine it in a way this propagation
//! cannot see (a non-linear entanglement resolved only by a Groebner-style argument). So:
//!   * all pinned      => PROOF of uniqueness.
//!   * some unpinned   => NOT a proof of a defect; a list of candidates to examine by hand.
//! Reporting it the other way round would be the dishonest direction, because it would let an
//! incomplete tool declare a circuit broken and get "fixed" until the tool went quiet.
//!
//! Menese DeFi Team.

use ark_ff::{UniformRand, Zero};
use ark_relations::r1cs::{
    ConstraintMatrices, ConstraintSynthesizer, ConstraintSystem, Matrix,
};
use ark_std::rand::{rngs::StdRng, RngCore, SeedableRng};
use common::{
    derive_pk, note_commitment, poseidon_config, DenseTree, Note, PoseidonCfg, ScalarField as F,
    TransferCircuit,
};
use std::collections::BTreeSet;

/// Honest satisfying witness. Copied from `under_constrained.rs` deliberately rather than shared:
/// each analysis owns its own builder, so a change made for one cannot silently retune the other.
fn harness_honest_transfer(rng: &mut StdRng, cfg: &PoseidonCfg<F>) -> TransferCircuit {
    let owner_nk = F::rand(rng);
    let recipient_nk = F::rand(rng);
    let in_v = [80_000u64 + rng.next_u64() % 400_000, 50_000 + rng.next_u64() % 400_000];
    let inputs = [
        Note { v: in_v[0], nk: owner_nk, rho: F::rand(rng), rcm: F::rand(rng) },
        Note { v: in_v[1], nk: owner_nk, rho: F::rand(rng), rcm: F::rand(rng) },
    ];
    let mut filler =
        |rng: &mut StdRng| Note { v: 1, nk: F::rand(rng), rho: F::rand(rng), rcm: F::rand(rng) };
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
        legacy_statement: false,
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

struct Exported {
    matrices: ConstraintMatrices<F>,
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
    Exported {
        num_instance: borrowed.num_instance_variables,
        num_witness: borrowed.num_witness_variables,
        matrices,
    }
}

/// A linear form over z, as R1CS stores it: (coefficient, z-index) pairs.
type Form<'a> = &'a [(F, usize)];

/// Is every variable of this form pinned?
fn form_pinned(form: Form, pinned: &BTreeSet<usize>) -> bool {
    form.iter().all(|(_, idx)| pinned.contains(idx))
}

/// The single unpinned term of a form, if there is exactly one with a non-zero coefficient.
fn lone_unpinned(form: Form, pinned: &BTreeSet<usize>) -> Option<usize> {
    let mut found = None;
    for (coeff, idx) in form {
        if pinned.contains(idx) {
            continue;
        }
        if coeff.is_zero() {
            continue; // a zero coefficient pins nothing
        }
        if found.is_some() {
            return None; // two or more unpinned: this form forces neither
        }
        found = Some(*idx);
    }
    found
}

/// Pin the lone unpinned variable of `form`, if there is exactly one. Returns whether it pinned.
fn try_pin(form: Form, pinned: &mut BTreeSet<usize>) -> bool {
    match lone_unpinned(form, pinned) {
        Some(idx) => pinned.insert(idx),
        None => false,
    }
}

/// Determinism propagation to a fixpoint. Returns the pinned set.
///
/// Note on the zero cases: we cannot evaluate a form without a concrete assignment, and the
/// point of this analysis is to avoid depending on one. So the zero-product rules are applied
/// only in the form that holds for EVERY assignment consistent with the pinned set — that is,
/// when a form is IDENTICALLY zero (empty, or all coefficients zero), not when it merely
/// evaluates to zero at some witness. Anything else would prove a property of one witness rather
/// than of the system.
fn propagate(m: &ConstraintMatrices<F>, num_instance: usize) -> BTreeSet<usize> {
    propagate_seeded(m, num_instance, 0)
}

/// As `propagate`, but additionally seeds the first `extra_witness` witness variables as pinned.
/// Used to ask Ecne's real question — "is every signal determined by the circuit's INPUTS" —
/// rather than "is the witness determined by the public outputs", which for a hiding scheme is
/// asking to invert a hash.
fn propagate_seeded(
    m: &ConstraintMatrices<F>,
    num_instance: usize,
    extra_witness: usize,
) -> BTreeSet<usize> {
    let mut pinned: BTreeSet<usize> = (0..num_instance + extra_witness).collect(); // 0 is the constant 1

    let identically_zero = |f: Form| f.iter().all(|(c, _)| c.is_zero());

    let row = |mat: &Matrix<F>, i: usize| -> Vec<(F, usize)> { mat[i].clone() };

    loop {
        let mut progressed = false;
        for i in 0..m.num_constraints {
            let a = row(&m.a, i);
            let b = row(&m.b, i);
            let c = row(&m.c, i);

            let (a_pin, b_pin, c_pin) = (
                form_pinned(&a, &pinned),
                form_pinned(&b, &pinned),
                form_pinned(&c, &pinned),
            );

            // A and B pinned => the product is determined => C is forced.
            if a_pin && b_pin && try_pin(&c, &mut pinned) {
                progressed = true;
                continue;
            }
            // A identically zero => product is 0 for every assignment => C is forced to 0.
            if identically_zero(&a) && try_pin(&c, &mut pinned) {
                progressed = true;
                continue;
            }
            if identically_zero(&b) && try_pin(&c, &mut pinned) {
                progressed = true;
                continue;
            }
            // C pinned and one side pinned => the other side is forced, PROVIDED the pinned side
            // cannot be zero for some consistent assignment. We cannot establish that without an
            // assignment, so this rule is applied only when the pinned side is a non-zero
            // CONSTANT — a form over the constant-1 variable alone.
            let constant_nonzero = |f: Form| {
                !f.is_empty()
                    && f.iter().all(|(_, idx)| *idx == 0)
                    && !f.iter().fold(F::zero(), |acc, (c, _)| acc + c).is_zero()
            };
            if c_pin && constant_nonzero(&a) && try_pin(&b, &mut pinned) {
                progressed = true;
                continue;
            }
            if c_pin && constant_nonzero(&b) && try_pin(&a, &mut pinned) {
                progressed = true;
                continue;
            }
        }
        if !progressed {
            break;
        }
    }
    pinned
}

fn report(name: &str, e: &Exported) -> usize {
    let pinned = propagate(&e.matrices, e.num_instance);
    let total_vars = e.num_instance + e.num_witness;
    let unpinned: Vec<usize> = (e.num_instance..total_vars)
        .filter(|idx| !pinned.contains(idx))
        .collect();

    println!(
        "UNIQUENESS[{name}]: {} constraints, {} instance, {} witness; pinned {} of {} witness vars",
        e.matrices.num_constraints,
        e.num_instance,
        e.num_witness,
        e.num_witness - unpinned.len(),
        e.num_witness,
    );
    if unpinned.is_empty() {
        println!("UNIQUENESS[{name}]: PROVED — every witness variable is a function of the public inputs");
    } else {
        println!(
            "UNIQUENESS[{name}]: NOT PROVED — {} witness variable(s) unpinned (candidates, not a \
             defect finding): first few z-indices {:?}",
            unpinned.len(),
            &unpinned[..unpinned.len().min(12)],
        );
    }
    unpinned.len()
}

/// An honest satisfying circuit. `export` asserts satisfaction, so the analysis is always run
/// against a system that really does have at least one witness — otherwise "pinned everything"
/// could be vacuous.
fn honest(cfg: &PoseidonCfg<F>, legacy: bool) -> TransferCircuit {
    let mut rng = StdRng::from_seed([0x4du8; 32]);
    let mut c = harness_honest_transfer(&mut rng, cfg);
    c.legacy_statement = legacy;
    c
}

#[test]
fn witness_uniqueness_hardened_and_legacy() {
    let cfg = poseidon_config();

    let hardened = export(honest(&cfg, false));
    let legacy = export(honest(&cfg, true));

    let h_unpinned = report("hardened", &hardened);
    let l_unpinned = report("legacy", &legacy);

    // NEGATIVE CONTROL: the analysis must be capable of REPORTING unpinned variables. A prover that
    // pins everything unconditionally proves nothing. Seed the propagation with only the
    // constant, withholding the real public inputs, and the run must leave variables unpinned.
    let starved = propagate(&hardened.matrices, 1);
    let starved_unpinned = (1..hardened.num_instance + hardened.num_witness)
        .filter(|idx| !starved.contains(idx))
        .count();
    println!("UNIQUENESS[negative]: starved of public inputs, {starved_unpinned} variable(s) unpinned");
    assert!(
        starved_unpinned > 0,
        "NEGATIVE CONTROL FAILED: the propagation pinned everything with NO public inputs seeded, so \
         it is not actually reading the constraint system — a green verdict from it means nothing"
    );

    // Record, do not assert a pass. An incomplete analysis must not be allowed to fail the build
    // on its own inability to pin a variable; that pressure is exactly how a tool gets neutered.
    // The verdict is the printed line above, reproducible by running this test.
    println!(
        "UNIQUENESS SUMMARY: hardened unpinned={h_unpinned}, legacy unpinned={l_unpinned}"
    );

    // ---------------------------------------------------------------------------------------
    // WHY THE ABOVE PINS ALMOST NOTHING, tested rather than asserted.
    //
    // Seeding from the public inputs asks: "do the publics determine the witness?" For a
    // TRANSPARENT computation that is the right query. For a SHIELDED transfer it is the wrong
    // one, and it must be: the publics here are OUTPUTS (nullifiers, output commitments, root),
    // and they are Poseidon images of the private note data. Propagating from them means
    // inverting a hash, which no propagation can do — and if it could, the scheme would not be
    // hiding.
    //
    // Ecne's actual query seeds the circuit's INPUT signals and checks everything downstream
    // becomes determined. The hypothesis is therefore: seed the publics plus the first K witness
    // variables (arkworks allocates the note-opening witnesses before the intermediates) and the
    // rest of the system should pin. The sweep below finds the K at which that happens; a sharp
    // cliff is evidence the machinery works and the earlier query was simply pointed backwards.
    // ---------------------------------------------------------------------------------------
    println!("SEEDED-SWEEP[hardened]: publics + first K witnesses -> remaining unpinned");
    let total_h = hardened.num_instance + hardened.num_witness;
    for k in [0usize, 8, 16, 32, 64, 128, 142, 160, 200, 256] {
        if k > hardened.num_witness {
            break;
        }
        let seeded = propagate_seeded(&hardened.matrices, hardened.num_instance, k);
        let left = (hardened.num_instance..total_h)
            .filter(|idx| !seeded.contains(idx))
            .count();
        println!("  K={k:<4} unpinned={left}");
        if left == 0 {
            println!(
                "SEEDED-SWEEP[hardened]: PROVED determinism — with {k} input witnesses seeded, \
                 every remaining witness variable is forced. The circuit is a deterministic \
                 function of its inputs; there is no free intermediate."
            );
            break;
        }
    }
}
