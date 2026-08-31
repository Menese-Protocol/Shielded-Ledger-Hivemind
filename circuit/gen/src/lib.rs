//! F7 setup guard — the emit-path refusal that makes a wrong-flagged Groth16 setup impossible.
//!
//! `enforce_range` and `legacy_statement` are struct fields that change the R1CS shape, so a
//! verifying key is bound to their values at setup time. `blank()`/`blank_legacy()` hardcode
//! `enforce_range = true`; a setup accidentally taken from an `enforce_range = false` instance
//! would silently produce an UNSOUND verifying key (the generator's own A2a control shows the
//! no-range circuit accepting the field-wrap mint). These checks run on the exact circuit
//! instance handed to `Groth16::circuit_specific_setup` in `main.rs`, BEFORE any key material
//! is derived or written — not in a test-only helper. They read the instance and touch no RNG,
//! so guarded runs emit byte-identical keys to pre-guard runs.
//!
//! A setup instance is eligible only if it is one of the two reviewed statements, i.e. exactly
//! the shape `TransferCircuit::blank()` / `TransferCircuit::blank_legacy()` (or
//! `DepositCircuit::blank()`) constructs: `enforce_range = true`, the canonical Poseidon
//! configuration, and NO witness or public assignment (a setup must never see witness data).

use common::{poseidon_config, DepositCircuit, PoseidonCfg, ScalarField as F, TransferCircuit, TREE_LEVELS};

/// The one Poseidon configuration the reviewed statements are defined over. A setup from a
/// different configuration would be a different (unreviewed) R1CS with a different, unsound-by
/// -default verifying key, so it is refused like any other shape change.
fn assert_canonical_poseidon_cfg(cfg: &PoseidonCfg<F>, which: &str) -> Result<(), String> {
    let canonical = poseidon_config();
    if cfg.full_rounds != canonical.full_rounds
        || cfg.partial_rounds != canonical.partial_rounds
        || cfg.alpha != canonical.alpha
        || cfg.rate != canonical.rate
        || cfg.capacity != canonical.capacity
        || cfg.ark != canonical.ark
        || cfg.mds != canonical.mds
    {
        return Err(format!(
            "{which} setup instance carries a non-canonical Poseidon configuration \
             (expected R_F={}, R_P={}, alpha={}, rate={}, capacity={} with the Grain-LFSR \
             constants of the reviewed statement); refusing to derive keys from an unreviewed \
             R1CS shape",
            canonical.full_rounds,
            canonical.partial_rounds,
            canonical.alpha,
            canonical.rate,
            canonical.capacity,
        ));
    }
    Ok(())
}

/// Refuse any transfer setup instance that is not byte-for-byte the shape of
/// `TransferCircuit::blank()` or `TransferCircuit::blank_legacy()`.
pub fn assert_transfer_setup_eligible(c: &TransferCircuit) -> Result<(), String> {
    if !c.enforce_range {
        return Err(
            "transfer setup instance has enforce_range=false: its R1CS omits the value/fee/\
             v_pub_out range gadgets, and a verifying key derived from it would accept the \
             field-wrap mint (the generator's A2a control demonstrates exactly that). \
             Deployable setups come ONLY from TransferCircuit::blank() or blank_legacy()"
                .to_string(),
        );
    }
    assert_canonical_poseidon_cfg(&c.cfg, "transfer")?;

    let assigned = c.anchor.is_some()
        || c.nf.iter().any(Option::is_some)
        || c.cm_out.iter().any(Option::is_some)
        || c.fee.is_some()
        || c.v_pub_out.is_some()
        || c.recipient_binding.is_some()
        || c.in_v.iter().any(Option::is_some)
        || c.in_nk.iter().any(Option::is_some)
        || c.in_rho.iter().any(Option::is_some)
        || c.in_rcm.iter().any(Option::is_some)
        || c.out_v.iter().any(Option::is_some)
        || c.out_pk.iter().any(Option::is_some)
        || c.out_rcm.iter().any(Option::is_some);
    if assigned {
        return Err(
            "transfer setup instance carries witness/public assignments; a setup must be run \
             from the blank statement shape (TransferCircuit::blank()/blank_legacy()), never \
             from a populated instance"
                .to_string(),
        );
    }

    let blank_paths = c.in_rows.iter().all(|rows| {
        rows.len() == TREE_LEVELS && rows.iter().all(|row| row.iter().all(|x| *x == F::from(0u64)))
    }) && c
        .in_pos
        .iter()
        .all(|pos| pos.len() == TREE_LEVELS && pos.iter().all(|p| *p == 0));
    if !blank_paths {
        return Err(
            "transfer setup instance's Merkle path slots differ from the blank shape \
             (TREE_LEVELS zero-filled ARITY-wide rows / zero positions); refusing a setup \
             from a non-blank instance"
                .to_string(),
        );
    }
    // `legacy_statement` may be either value: blank() (hardened) and blank_legacy() are the
    // two reviewed statements, and both keep every constraint the statement defines.
    Ok(())
}

/// Refuse any deposit setup instance that is not the shape of `DepositCircuit::blank()`.
pub fn assert_deposit_setup_eligible(c: &DepositCircuit) -> Result<(), String> {
    assert_canonical_poseidon_cfg(&c.cfg, "deposit")?;
    if c.cm.is_some() || c.v_pub.is_some() || c.pk.is_some() || c.rho.is_some() || c.rcm.is_some()
    {
        return Err(
            "deposit setup instance carries witness/public assignments; a setup must be run \
             from DepositCircuit::blank(), never from a populated instance"
                .to_string(),
        );
    }
    Ok(())
}
