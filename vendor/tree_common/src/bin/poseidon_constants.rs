//! Prints the Poseidon round constants and MDS matrix that arkworks generates for the field this
//! crate is compiled against, so they can be compared BYTE FOR BYTE with src/PoseidonConstants.mo.
//!
//! Why this exists: PoseidonTree.mo cites `find_poseidon_ark_and_mds::<Fr>(255, 2, 8, 57, 0)` as the
//! provenance of its tables, and that citation was true but UNCHECKED -- nothing regenerated the
//! constants and compared them. A documented provenance nobody re-derives is the same
//! claim-stronger-than-evidence shape this repository has been removing elsewhere: if the tables
//! were ever edited, or generated with a different parameter set, every security argument that
//! rests on "this is Poseidon" would be resting on nothing.
//!
//! Build with the SAME feature the Motoko port targets, or the comparison is meaningless because
//! the constants are derived from the field modulus:
//!     cargo run --offline --features bls12-381 --bin poseidon_constants
//!
//! Output is deterministic: one decimal value per line, ARK in round-major order (row by row),
//! then MDS in row-major order, each section preceded by a header naming its dimensions.

use ark_crypto_primitives::sponge::poseidon::find_poseidon_ark_and_mds;
use ark_ff::PrimeField;

#[cfg(feature = "bls12-381")]
type F = ark_bls12_381::Fr;
#[cfg(not(feature = "bls12-381"))]
type F = ark_bn254::Fr;

fn main() {
    // Exactly the call PoseidonTree.mo documents. MODULUS_BIT_SIZE is 255 for BLS12-381 Fr and 254
    // for BN254 Fr, which is why the feature must match the port's field.
    let (ark, mds) = find_poseidon_ark_and_mds::<F>(F::MODULUS_BIT_SIZE as u64, 2, 8, 57, 0);

    println!("# field-modulus-bits {}", F::MODULUS_BIT_SIZE);
    println!("# ark {} {}", ark.len(), ark.first().map(|r| r.len()).unwrap_or(0));
    for row in &ark {
        for v in row {
            println!("{}", v.into_bigint());
        }
    }
    println!("# mds {} {}", mds.len(), mds.first().map(|r| r.len()).unwrap_or(0));
    for row in &mds {
        for v in row {
            println!("{}", v.into_bigint());
        }
    }
}
