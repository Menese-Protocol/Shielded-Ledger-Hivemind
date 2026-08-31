//! F7 setup-guard battery: the emit path's guard (the same functions `gen`'s `main.rs` calls
//! on the exact instances it hands to `Groth16::circuit_specific_setup`) must REFUSE every
//! wrong-flagged or non-blank setup instance and ACCEPT exactly the two reviewed statements.
//!
//! The headline case is the F7 footgun itself: a hand-built `enforce_range = false` transfer
//! instance — the shape whose verifying key would silently accept the field-wrap mint — is
//! REFUSED.

use ark_crypto_primitives::sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig};
use ark_ff::PrimeField;
use common::{poseidon_config, DepositCircuit, ScalarField as F, TransferCircuit};
use gen::{assert_deposit_setup_eligible, assert_transfer_setup_eligible};

#[test]
fn hardened_blank_is_eligible() {
    let cfg = poseidon_config();
    assert_transfer_setup_eligible(&TransferCircuit::blank(&cfg))
        .expect("blank() (hardened statement) must be setup-eligible");
}

#[test]
fn legacy_blank_is_eligible() {
    let cfg = poseidon_config();
    assert_transfer_setup_eligible(&TransferCircuit::blank_legacy(&cfg))
        .expect("blank_legacy() must remain setup-eligible (provenance regeneration)");
}

#[test]
fn enforce_range_false_setup_is_refused() {
    let cfg = poseidon_config();
    // The F7 footgun: identical to blank() except the flag that removes the range gadgets.
    let mut c = TransferCircuit::blank(&cfg);
    c.enforce_range = false;
    let err = assert_transfer_setup_eligible(&c)
        .expect_err("an enforce_range=false setup instance MUST be refused");
    assert!(
        err.contains("enforce_range=false"),
        "refusal must name the flag; got: {err}"
    );

    // The legacy-side variant of the same footgun is refused identically.
    let mut c = TransferCircuit::blank_legacy(&cfg);
    c.enforce_range = false;
    assert_transfer_setup_eligible(&c)
        .expect_err("a legacy enforce_range=false setup instance MUST be refused");
}

#[test]
fn populated_transfer_instance_is_refused() {
    let cfg = poseidon_config();
    let mut c = TransferCircuit::blank(&cfg);
    c.fee = Some(5);
    let err = assert_transfer_setup_eligible(&c)
        .expect_err("a setup instance carrying assignments MUST be refused");
    assert!(err.contains("assignments"), "refusal must say why; got: {err}");

    let mut c = TransferCircuit::blank(&cfg);
    // Input 0, level 0, slot 0 of the 4-ary Merkle path. `in_rows` replaced the binary-tree
    // `in_siblings`; the guard at gen/src/lib.rs:83 reads `in_rows`, so this still trips it.
    c.in_rows[0][0][0] = F::from(1u64);
    assert_transfer_setup_eligible(&c)
        .expect_err("a setup instance with a non-blank Merkle path slot MUST be refused");
}

#[test]
fn non_canonical_poseidon_config_is_refused() {
    // Same field, one partial round fewer: a different (unreviewed) R1CS shape.
    let (ark, mds) = find_poseidon_ark_and_mds::<F>(F::MODULUS_BIT_SIZE as u64, 2, 8, 56, 0);
    let wrong_cfg = PoseidonConfig::new(8, 56, 5, mds, ark, 2, 1);
    let err = assert_transfer_setup_eligible(&TransferCircuit::blank(&wrong_cfg))
        .expect_err("a setup instance over a non-canonical Poseidon config MUST be refused");
    assert!(err.contains("Poseidon"), "refusal must name the config; got: {err}");
}

#[test]
fn deposit_blank_is_eligible_and_populated_is_refused() {
    let cfg = poseidon_config();
    assert_deposit_setup_eligible(&DepositCircuit::blank(&cfg))
        .expect("DepositCircuit::blank() must be setup-eligible");

    let mut c = DepositCircuit::blank(&cfg);
    c.v_pub = Some(1);
    assert_deposit_setup_eligible(&c)
        .expect_err("a populated deposit setup instance MUST be refused");
}
