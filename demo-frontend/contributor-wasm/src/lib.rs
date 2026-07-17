//! Browser contributor client for the Phase-2 trusted-setup ceremony (Deliverable D2).
//!
//! APPLY-AND-DESTROY, ENTIRELY IN THE WASM SANDBOX. The secret delta increment is sampled from
//! WebCrypto entropy inside `transform_contribution`, used to re-randomize the downloaded public
//! parameters and to build the proof of knowledge, and then DROPPED when the function returns.
//! The ONLY values that cross the wasm boundary back to JavaScript are the transformed PUBLIC
//! parameters and the PUBLIC proof of knowledge. There is no export, field, or return value that
//! carries the secret, so no network call the page later makes can carry it either. This is the
//! Bowe-Gabizon-Miers 2017 "the secret never leaves the browser" property, enforced by construction.
//!
//! The math is not reimplemented here: it calls the exact `ceremony` core the standalone verifier
//! and the coordinator canister check against, so there is one implementation of the contribution.

use ceremony::contribute::{contribute, sample_secret};
use ceremony::transcript::{delta_from_wire, delta_to_wire, g1_be, g2_be, Pok};
use rand::SeedableRng;
use serde::Serialize;
use wasm_bindgen::prelude::*;

fn err(m: impl core::fmt::Display) -> JsValue {
    JsValue::from_str(&m.to_string())
}

/// A fresh CSPRNG stream seeded from WebCrypto. `getrandom` with the "js" feature calls
/// crypto.getRandomValues; the seed and the stream never leave this module.
fn browser_rng() -> rand_chacha::ChaCha20Rng {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).expect("browser entropy (crypto.getRandomValues) unavailable");
    rand_chacha::ChaCha20Rng::from_seed(seed)
}

#[derive(Serialize)]
struct PokOut {
    s_g1: String,
    s_delta_g1: String,
    r_delta_g2: String,
}
impl PokOut {
    fn of(p: &Pok) -> Self {
        PokOut {
            s_g1: hex::encode(g1_be(&p.s_g1)),
            s_delta_g1: hex::encode(g1_be(&p.s_delta_g1)),
            r_delta_g2: hex::encode(g2_be(&p.r_delta_g2)),
        }
    }
}

#[derive(Serialize)]
struct ContributionOut {
    transfer_delta: String, // hex of the wire delta blob to upload
    transfer_pok: PokOut,
    deposit_delta: String,
    deposit_pok: PokOut,
}

/// Transform the current parameters of BOTH circuits with fresh browser-sampled secrets and produce
/// the proofs of knowledge, all in-sandbox. Inputs are the current wire delta blobs downloaded from
/// the coordinator and the running challenge. Returns a JSON string with the public results to
/// upload. The secrets are local to this call and are dropped before it returns.
#[wasm_bindgen]
pub fn transform_contribution(
    current_transfer_wire: &[u8],
    current_deposit_wire: &[u8],
    prev_challenge: &[u8],
) -> Result<String, JsValue> {
    if prev_challenge.len() != 32 {
        return Err(err("prev_challenge must be 32 bytes"));
    }
    let mut chal = [0u8; 32];
    chal.copy_from_slice(prev_challenge);

    let cur_transfer = delta_from_wire(current_transfer_wire).map_err(err)?;
    let cur_deposit = delta_from_wire(current_deposit_wire).map_err(err)?;

    let mut rng = browser_rng();

    // ---- SECRETS LIVE ONLY IN THIS SCOPE ----
    let transfer_secret = sample_secret(&mut rng);
    let (new_transfer, transfer_pok) =
        contribute(&chal, &cur_transfer, transfer_secret, &mut rng).map_err(err)?;
    // transfer_secret is not stored, returned, or logged; it is dropped at end of scope.

    let deposit_secret = sample_secret(&mut rng);
    let (new_deposit, deposit_pok) =
        contribute(&chal, &cur_deposit, deposit_secret, &mut rng).map_err(err)?;
    // deposit_secret likewise dropped.
    // ---- from here on only PUBLIC data exists ----

    let out = ContributionOut {
        transfer_delta: hex::encode(delta_to_wire(&new_transfer)),
        transfer_pok: PokOut::of(&transfer_pok),
        deposit_delta: hex::encode(delta_to_wire(&new_deposit)),
        deposit_pok: PokOut::of(&deposit_pok),
    };
    serde_json::to_string(&out).map_err(err)
}

/// Convenience for the UI: a fresh random 32-byte hex string (e.g. an anti-CSRF nonce). Uses the
/// same browser entropy. Never used for the contribution secret path.
#[wasm_bindgen]
pub fn random_nonce_hex() -> String {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).expect("browser entropy unavailable");
    hex::encode(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ceremony::transcript::{delta_params_hash, DeltaParams};
    use ark_bls12_381::{G1Affine, G2Affine};
    use ark_ec::AffineRepr;

    // The returned bytes are exactly the public transform + PoK, and re-parse as valid public
    // parameters. (There is no code path that emits the secret; this exercises the happy path and
    // confirms the output is well-formed public data.)
    #[test]
    fn transform_produces_valid_public_output() {
        let cur = DeltaParams {
            delta_g1: G1Affine::generator(),
            delta_g2: G2Affine::generator(),
            h_query: vec![G1Affine::generator()],
            l_query: vec![G1Affine::generator()],
        };
        let wire = delta_to_wire(&cur);
        let out = transform_contribution(&wire, &wire, &[7u8; 32]).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        let new_wire = hex::decode(v["transfer_delta"].as_str().unwrap()).unwrap();
        // re-parses as valid public params, and differs from the input (a real contribution happened)
        let parsed = delta_from_wire(&new_wire).unwrap();
        assert_ne!(delta_params_hash(&parsed), delta_params_hash(&cur));
    }
}
