//! Client-side crypto for the shielded-pool demo — Menese DeFi Team.
//!
//! Everything privacy-critical happens HERE, in the browser:
//!   - note secrets (nk, rho, rcm) from browser entropy;
//!   - commitment / nullifier / address derivation (the same Poseidon the circuit uses);
//!   - the note tree rebuilt CLIENT-SIDE from the public commitment log (commitments are
//!     public by design — that is the honest part the node provider also sees);
//!   - Groth16 proving (BLS12-381) against the pool circuits, with the proving key's embedded
//!     vk asserted equal to the ledger's configured vk before any proof is produced;
//!   - the LWE PIR client: key generation, selector encryption, response decryption.
//!
//! Wire conventions match the ledger exactly: field elements travel as 32-byte
//! LITTLE-endian canonical Fr hex (ark serialize_compressed), proofs as compressed
//! arkworks Groth16 bytes.

use ark_bls12_381::{Bls12_381, Fr as F};
use ark_ff::{PrimeField, UniformRand, Zero};
use ark_groth16::{Groth16, ProvingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use common::*;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

// ---------------------------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------------------------

fn err(msg: &str) -> JsValue {
    JsValue::from_str(msg)
}

fn f_from_wire(hex: &str) -> Result<F, JsValue> {
    f_from_hex(hex).ok_or_else(|| err("bad field hex"))
}

fn rng() -> ark_std::rand::rngs::StdRng {
    // Browser entropy via getrandom(js) seeds a CSPRNG stream for field sampling.
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).expect("browser entropy unavailable");
    <ark_std::rand::rngs::StdRng as ark_std::rand::SeedableRng>::from_seed(seed)
}

fn compressed_hex<T: CanonicalSerialize>(x: &T) -> String {
    let mut b = Vec::new();
    x.serialize_compressed(&mut b).unwrap();
    b.iter().map(|c| format!("{c:02x}")).collect()
}

// ---------------------------------------------------------------------------------------------
// note primitives
// ---------------------------------------------------------------------------------------------

/// A fresh uniformly-random scalar from browser entropy, in ledger wire form.
#[wasm_bindgen]
pub fn random_field() -> String {
    f_to_hex(&F::rand(&mut rng()))
}

/// Reduce deterministic key material (for example a vetKey-derived 64-byte secret) into the
/// BLS12-381 scalar field used by the shielded account. The reduction is deterministic and the
/// raw seed never crosses the wasm boundary except for this call.
#[wasm_bindgen]
pub fn field_from_seed(seed: &[u8]) -> Result<String, JsValue> {
    if seed.len() < 32 {
        return Err(err("seed must contain at least 32 bytes"));
    }
    let field = F::from_le_bytes_mod_order(seed);
    if field.is_zero() {
        return Err(err("derived zero field element"));
    }
    Ok(f_to_hex(&field))
}

/// Shielded address pk = H(1, nk).
#[wasm_bindgen]
pub fn shielded_address(nk_hex: &str) -> Result<String, JsValue> {
    let cfg = poseidon_config();
    Ok(f_to_hex(&derive_pk(&cfg, f_from_wire(nk_hex)?)))
}

/// Note commitment cm = H(3, v, pk, rho, rcm).
#[wasm_bindgen]
pub fn note_commitment_hex(v: u64, pk_hex: &str, rho_hex: &str, rcm_hex: &str) -> Result<String, JsValue> {
    let cfg = poseidon_config();
    Ok(f_to_hex(&note_commitment(
        &cfg, v, f_from_wire(pk_hex)?, f_from_wire(rho_hex)?, f_from_wire(rcm_hex)?,
    )))
}

/// Nullifier nf = H(2, nk, rho).
#[wasm_bindgen]
pub fn note_nullifier_hex(nk_hex: &str, rho_hex: &str) -> Result<String, JsValue> {
    let cfg = poseidon_config();
    Ok(f_to_hex(&derive_nf(&cfg, f_from_wire(nk_hex)?, f_from_wire(rho_hex)?)))
}

/// Root of the note tree rebuilt from the PUBLIC commitment log.
#[wasm_bindgen]
pub fn tree_root(leaves_json: &str) -> Result<String, JsValue> {
    let leaves: Vec<String> = serde_json::from_str(leaves_json).map_err(|_| err("bad leaves json"))?;
    let cfg = poseidon_config();
    let leaves: Vec<F> = leaves
        .iter()
        .map(|h| f_from_hex(h).ok_or_else(|| err("bad leaf hex")))
        .collect::<Result<_, _>>()?;
    Ok(f_to_hex(&DenseTree { leaves }.root(&cfg)))
}

// ---------------------------------------------------------------------------------------------
// proving keys
// ---------------------------------------------------------------------------------------------

fn load_pk(bytes: &[u8]) -> Result<ProvingKey<Bls12_381>, JsValue> {
    // Static local asset: unchecked deserialization is deliberate (checked would subgroup-test
    // ~50k points). Integrity is enforced by `assert_pk_matches_vk` against the ledger's
    // configured vk, and every proof is verified by the ledger's own verifier anyway.
    ProvingKey::<Bls12_381>::deserialize_uncompressed_unchecked(bytes)
        .map_err(|_| err("proving key failed to parse"))
}

/// The lineage check: the proving key's embedded vk must BYTE-match the vk the ledger was
/// configured with (compressed hex). Call once at load; refuse to prove if it fails.
#[wasm_bindgen]
pub fn assert_pk_matches_vk(pk_bytes: &[u8], ledger_vk_hex: &str) -> Result<bool, JsValue> {
    let pk = load_pk(pk_bytes)?;
    Ok(compressed_hex(&pk.vk) == ledger_vk_hex.to_lowercase())
}

// ---------------------------------------------------------------------------------------------
// transfer statement inference
// ---------------------------------------------------------------------------------------------

/// Finalized witness count of the given transfer statement, synthesized once in setup mode —
/// the exact mode Groth16 setup uses, so the count matches key generation.
fn transfer_witness_count(cfg: &PoseidonCfg<F>, legacy_statement: bool) -> Result<usize, &'static str> {
    use ark_relations::r1cs::{ConstraintSystem, OptimizationGoal, SynthesisMode};
    let circuit = if legacy_statement {
        TransferCircuit::blank_legacy(cfg)
    } else {
        TransferCircuit::blank(cfg)
    };
    let cs = ConstraintSystem::<F>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Setup);
    ark_relations::r1cs::ConstraintSynthesizer::generate_constraints(circuit, cs.clone())
        .map_err(|_| "transfer statement synthesis failed")?;
    cs.finalize();
    Ok(cs.num_witness_variables())
}

/// Infer which transfer statement a supplied proving key was set up for. A Groth16 proving
/// key carries exactly one `l_query` element per witness variable, and the two statements
/// have distinct witness counts (pinned by the circuit crate's `statement_dims` test), so the
/// length identifies the statement. Returns `legacy_statement` for `TransferCircuit`; errors
/// if the key matches neither statement (wrong key entirely — refuse to prove).
fn transfer_statement_of_pk_core(
    cfg: &PoseidonCfg<F>,
    pk: &ProvingKey<Bls12_381>,
) -> Result<bool, &'static str> {
    let l = pk.l_query.len();
    if l == transfer_witness_count(cfg, false)? {
        return Ok(false);
    }
    if l == transfer_witness_count(cfg, true)? {
        return Ok(true);
    }
    Err("proving key matches neither the hardened nor the legacy transfer statement")
}

fn transfer_statement_of_pk(
    cfg: &PoseidonCfg<F>,
    pk: &ProvingKey<Bls12_381>,
) -> Result<bool, JsValue> {
    transfer_statement_of_pk_core(cfg, pk).map_err(err)
}

#[cfg(test)]
mod statement_inference_tests {
    use super::*;
    use ark_snark::SNARK;
    use ark_std::rand::rngs::StdRng;
    use ark_std::rand::SeedableRng;

    /// The wallet-side inference must identify a legacy and a hardened proving key correctly
    /// and refuse a key that matches neither statement (here: the DEPOSIT circuit's key).
    #[test]
    fn infers_statement_from_proving_key() {
        let cfg = poseidon_config();
        let mut rng = StdRng::seed_from_u64(42);
        let (legacy_pk, _) = Groth16::<Bls12_381>::circuit_specific_setup(
            TransferCircuit::blank_legacy(&cfg),
            &mut rng,
        )
        .unwrap();
        let (hardened_pk, _) =
            Groth16::<Bls12_381>::circuit_specific_setup(TransferCircuit::blank(&cfg), &mut rng)
                .unwrap();
        let (deposit_pk, _) =
            Groth16::<Bls12_381>::circuit_specific_setup(DepositCircuit::blank(&cfg), &mut rng)
                .unwrap();
        assert_eq!(transfer_statement_of_pk_core(&cfg, &legacy_pk), Ok(true));
        assert_eq!(transfer_statement_of_pk_core(&cfg, &hardened_pk), Ok(false));
        assert!(transfer_statement_of_pk_core(&cfg, &deposit_pk).is_err());
    }
}

// ---------------------------------------------------------------------------------------------
// deposit (shield) proving
// ---------------------------------------------------------------------------------------------

#[derive(Serialize)]
struct DepositResult {
    proof_hex: String,
    cm_hex: String,
}

/// Prove knowledge of the opening of `cm` for public value `v`: the shield statement.
#[wasm_bindgen]
pub fn prove_deposit(
    pk_bytes: &[u8], v: u64, pk_hex: &str, rho_hex: &str, rcm_hex: &str,
) -> Result<String, JsValue> {
    let cfg = poseidon_config();
    let pk_owner = f_from_wire(pk_hex)?;
    let rho = f_from_wire(rho_hex)?;
    let rcm = f_from_wire(rcm_hex)?;
    let cm = note_commitment(&cfg, v, pk_owner, rho, rcm);
    let circuit = DepositCircuit {
        cfg: cfg.clone(),
        cm: Some(cm),
        v_pub: Some(v),
        pk: Some(pk_owner),
        rho: Some(rho),
        rcm: Some(rcm),
    };
    let publics = circuit.public_inputs();
    let key = load_pk(pk_bytes)?;
    let proof = Groth16::<Bls12_381>::prove(&key, circuit, &mut rng())
        .map_err(|_| err("deposit proof failed"))?;
    // Never hand the UI a proof the vk would reject: self-verify before returning.
    if !Groth16::<Bls12_381>::verify(&key.vk, &publics, &proof).map_err(|_| err("verify errored"))? {
        return Err(err("deposit self-verification failed"));
    }
    Ok(serde_json::to_string(&DepositResult {
        proof_hex: compressed_hex(&proof),
        cm_hex: f_to_hex(&cm),
    })
    .unwrap())
}

// ---------------------------------------------------------------------------------------------
// transfer proving
// ---------------------------------------------------------------------------------------------

#[derive(Deserialize)]
struct InNote {
    v: u64,
    nk: String,
    rho: String,
    rcm: String,
    /// position of this note's commitment in the public log
    index: usize,
}

#[derive(Deserialize)]
struct OutNote {
    v: u64,
    pk: String,
    rcm: String,
}

#[derive(Deserialize)]
struct TransferWitness {
    /// the full public commitment log, in order (rebuilt by the client from public blocks)
    leaves: Vec<String>,
    in1: InNote,
    in2: InNote,
    out1: OutNote,
    out2: OutNote,
    fee: u64,
    v_pub_out: u64,
    /// Zero for a private transfer; hash-to-field of the exact public ICRC account for unshield.
    recipient_binding: String,
}

#[derive(Serialize)]
struct TransferResult {
    proof_hex: String,
    anchor_hex: String,
    nf1_hex: String,
    nf2_hex: String,
    cm_out1_hex: String,
    cm_out2_hex: String,
    /// rho of each output note (the input nullifier it chains to) — the RECIPIENT needs this
    /// plus (v, rcm) to spend; it travels inside the encrypted note payload.
    out1_rho_hex: String,
    out2_rho_hex: String,
}

/// Prove a 2-in/2-out private transfer. Conservation, ranges, membership, and nullifier
/// correctness are all enforced by the circuit; this only assembles the witness.
#[wasm_bindgen]
pub fn prove_transfer(pk_bytes: &[u8], witness_json: &str) -> Result<String, JsValue> {
    let w: TransferWitness = serde_json::from_str(witness_json).map_err(|_| err("bad witness json"))?;
    let cfg = poseidon_config();
    let leaves: Vec<F> = w
        .leaves
        .iter()
        .map(|h| f_from_hex(h).ok_or_else(|| err("bad leaf hex")))
        .collect::<Result<_, _>>()?;
    let tree = DenseTree { leaves };
    let anchor = tree.root(&cfg);

    let parse_in = |n: &InNote| -> Result<(Note, Vec<F>, Vec<bool>), JsValue> {
        let note = Note {
            v: n.v,
            nk: f_from_wire(&n.nk)?,
            rho: f_from_wire(&n.rho)?,
            rcm: f_from_wire(&n.rcm)?,
        };
        let cm = note.cm(&cfg);
        if n.index >= tree.leaves.len() || tree.leaves[n.index] != cm {
            return Err(err("input note commitment not found at claimed index"));
        }
        let (sib, bits) = tree.path(&cfg, n.index);
        Ok((note, sib, bits))
    };
    let (in1, sib1, bits1) = parse_in(&w.in1)?;
    let (in2, sib2, bits2) = parse_in(&w.in2)?;
    let nf1 = in1.nf(&cfg);
    let nf2 = in2.nf(&cfg);

    // Output rho chains to the input nullifiers (Orchard-style uniqueness).
    let out1_pk = f_from_wire(&w.out1.pk)?;
    let out2_pk = f_from_wire(&w.out2.pk)?;
    let out1_rcm = f_from_wire(&w.out1.rcm)?;
    let out2_rcm = f_from_wire(&w.out2.rcm)?;
    let cm_out1 = note_commitment(&cfg, w.out1.v, out1_pk, nf1, out1_rcm);
    let cm_out2 = note_commitment(&cfg, w.out2.v, out2_pk, nf2, out2_rcm);

    // The witness must be assembled for the SAME statement the supplied proving key was set up
    // for — the wallet keeps working across a verifying-key rotation without an API change.
    let key = load_pk(pk_bytes)?;
    let legacy_statement = transfer_statement_of_pk(&cfg, &key)?;

    let circuit = TransferCircuit {
        cfg: cfg.clone(),
        enforce_range: true,
        legacy_statement,
        anchor: Some(anchor),
        nf: [Some(nf1), Some(nf2)],
        cm_out: [Some(cm_out1), Some(cm_out2)],
        fee: Some(w.fee),
        v_pub_out: Some(w.v_pub_out),
        recipient_binding: Some(f_from_wire(&w.recipient_binding)?),
        in_v: [Some(in1.v), Some(in2.v)],
        in_nk: [Some(in1.nk), Some(in2.nk)],
        in_rho: [Some(in1.rho), Some(in2.rho)],
        in_rcm: [Some(in1.rcm), Some(in2.rcm)],
        in_siblings: [sib1, sib2],
        in_bits: [bits1, bits2],
        out_v: [Some(F::from(w.out1.v)), Some(F::from(w.out2.v))],
        out_pk: [Some(out1_pk), Some(out2_pk)],
        out_rcm: [Some(out1_rcm), Some(out2_rcm)],
    };
    let publics = circuit.public_inputs();
    let proof = Groth16::<Bls12_381>::prove(&key, circuit, &mut rng())
        .map_err(|_| err("transfer proof failed (witness does not satisfy the circuit?)"))?;
    if !Groth16::<Bls12_381>::verify(&key.vk, &publics, &proof).map_err(|_| err("verify errored"))? {
        return Err(err("transfer self-verification failed"));
    }
    Ok(serde_json::to_string(&TransferResult {
        proof_hex: compressed_hex(&proof),
        anchor_hex: f_to_hex(&anchor),
        nf1_hex: f_to_hex(&nf1),
        nf2_hex: f_to_hex(&nf2),
        cm_out1_hex: f_to_hex(&cm_out1),
        cm_out2_hex: f_to_hex(&cm_out2),
        out1_rho_hex: f_to_hex(&nf1),
        out2_rho_hex: f_to_hex(&nf2),
    })
    .unwrap())
}

// ---------------------------------------------------------------------------------------------
// LWE PIR client (dimension 630, q = 2^64, Δ = 2^63) — the exact scheme the ledger's
// uniform-scan pir_query_lwe endpoint answers.
// ---------------------------------------------------------------------------------------------

const PIR_DIMENSION: usize = 630;
const PIR_DELTA: u64 = 1 << 63;
const PIR_ROUNDING: u64 = 1 << 62;
const PIR_NOISE_SIGMA: f64 = (1u64 << 49) as f64;
const PIR_OUTPUT_BITS: usize = 256;

// u64 travels as STRINGS in JSON: JavaScript numbers lose precision above 2^53, and every
// coefficient here is a full 64-bit value. The frontend feeds them to candid as bigints.
#[derive(Serialize, Deserialize)]
pub struct PirCiphertextWire {
    pub a: Vec<String>,
    pub b: String,
}

pub struct PirCiphertext {
    pub a: Vec<u64>,
    pub b: u64,
}

impl PirCiphertext {
    fn to_wire(&self) -> PirCiphertextWire {
        PirCiphertextWire { a: self.a.iter().map(|v| v.to_string()).collect(), b: self.b.to_string() }
    }
    fn from_wire(w: &PirCiphertextWire) -> Option<PirCiphertext> {
        let a: Option<Vec<u64>> = w.a.iter().map(|s| s.parse().ok()).collect();
        Some(PirCiphertext { a: a?, b: w.b.parse().ok()? })
    }
}

fn pir_random_u64() -> u64 {
    let mut b = [0u8; 8];
    getrandom::getrandom(&mut b).expect("browser entropy unavailable");
    u64::from_le_bytes(b)
}

fn pir_gaussian_error() -> u64 {
    // Box–Muller over browser entropy; matches the reference client's noise distribution.
    let scale = (1u64 << 53) as f64;
    let u1 = ((pir_random_u64() >> 11) as f64 + 1.0) / (scale + 1.0);
    let u2 = ((pir_random_u64() >> 11) as f64 + 1.0) / (scale + 1.0);
    let normal = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
    (normal * PIR_NOISE_SIGMA).round() as i64 as u64
}

/// Fresh binary LWE secret key.
#[wasm_bindgen]
pub fn pir_keygen() -> String {
    let bits: Vec<u8> = (0..PIR_DIMENSION).map(|_| (pir_random_u64() & 1) as u8).collect();
    serde_json::to_string(&bits).unwrap()
}

fn pir_encrypt_bit(secret: &[u8], bit: u64) -> PirCiphertext {
    let a: Vec<u64> = (0..PIR_DIMENSION).map(|_| pir_random_u64()).collect();
    let dot: u64 = a
        .iter()
        .zip(secret)
        .filter(|(_, s)| **s == 1)
        .map(|(v, _)| *v)
        .fold(0u64, |acc, v| acc.wrapping_add(v));
    PirCiphertext {
        a,
        b: dot.wrapping_add(bit.wrapping_mul(PIR_DELTA)).wrapping_add(pir_gaussian_error()),
    }
}

/// One encrypted selector per record: Enc(1) at the target index, Enc(0) everywhere else.
/// Under LWE the two are computationally indistinguishable — the wire carries NO index.
#[wasm_bindgen]
pub fn pir_selectors(secret_json: &str, target_index: usize, record_count: usize) -> Result<String, JsValue> {
    let secret: Vec<u8> = serde_json::from_str(secret_json).map_err(|_| err("bad secret"))?;
    if secret.len() != PIR_DIMENSION {
        return Err(err("bad secret dimension"));
    }
    if target_index >= record_count {
        return Err(err("target out of range"));
    }
    let selectors: Vec<PirCiphertextWire> = (0..record_count)
        .map(|i| pir_encrypt_bit(&secret, u64::from(i == target_index)).to_wire())
        .collect();
    Ok(serde_json::to_string(&selectors).unwrap())
}

fn pir_decrypt_bit(secret: &[u8], ct: &PirCiphertext) -> u8 {
    let dot: u64 = ct
        .a
        .iter()
        .zip(secret)
        .filter(|(_, s)| **s == 1)
        .map(|(v, _)| *v)
        .fold(0u64, |acc, v| acc.wrapping_add(v));
    let phase = ct.b.wrapping_sub(dot);
    ((phase.wrapping_add(PIR_ROUNDING)) >> 63) as u8 & 1
}

/// Decrypt the 256-ciphertext response into the 32-byte record (MSB-first bit order).
#[wasm_bindgen]
pub fn pir_decrypt(secret_json: &str, response_json: &str) -> Result<String, JsValue> {
    let secret: Vec<u8> = serde_json::from_str(secret_json).map_err(|_| err("bad secret"))?;
    let wires: Vec<PirCiphertextWire> = serde_json::from_str(response_json).map_err(|_| err("bad response"))?;
    if wires.len() != PIR_OUTPUT_BITS {
        return Err(err("bad response length"));
    }
    let mut out = [0u8; 32];
    for (i, w) in wires.iter().enumerate() {
        let ct = PirCiphertext::from_wire(w).ok_or_else(|| err("bad response u64"))?;
        out[i / 8] |= pir_decrypt_bit(&secret, &ct) << (7 - i % 8);
    }
    Ok(out.iter().map(|c| format!("{c:02x}")).collect())
}

// ---------------------------------------------------------------------------------------------
// self-contained feasibility bench (kept as a regression probe)
// ---------------------------------------------------------------------------------------------

#[wasm_bindgen(inline_js = "export function js_sys_now() { return Date.now(); }")]
extern "C" {
    fn js_sys_now() -> f64;
}

/// End-to-end in-wasm bench: setup + prove + verify one honest transfer. JSON of stage timings.
#[wasm_bindgen]
pub fn spike_transfer_prove() -> String {
    let cfg = poseidon_config();
    let mut r = <ark_std::rand::rngs::StdRng as ark_std::rand::SeedableRng>::from_seed([7u8; 32]);
    let alice_nk = F::rand(&mut r);
    let bob_nk = F::rand(&mut r);
    let bob_pk = derive_pk(&cfg, bob_nk);
    let alice_pk = derive_pk(&cfg, alice_nk);
    let n1 = Note { v: 70, nk: alice_nk, rho: F::rand(&mut r), rcm: F::rand(&mut r) };
    let n2 = Note { v: 30, nk: alice_nk, rho: F::rand(&mut r), rcm: F::rand(&mut r) };
    let dense = DenseTree { leaves: vec![n1.cm(&cfg), n2.cm(&cfg)] };
    let anchor = dense.root(&cfg);
    let (sib1, bits1) = dense.path(&cfg, 0);
    let (sib2, bits2) = dense.path(&cfg, 1);
    let nf1 = n1.nf(&cfg);
    let nf2 = n2.nf(&cfg);
    let out1 = Note { v: 55, nk: bob_nk, rho: nf1, rcm: F::rand(&mut r) };
    let out2 = Note { v: 40, nk: alice_nk, rho: nf2, rcm: F::rand(&mut r) };
    let circuit = TransferCircuit {
        cfg: cfg.clone(),
        enforce_range: true,
        legacy_statement: false, // self-consistent bench: hardened setup two lines below
        anchor: Some(anchor),
        nf: [Some(nf1), Some(nf2)],
        cm_out: [Some(out1.cm(&cfg)), Some(out2.cm(&cfg))],
        fee: Some(5),
        v_pub_out: Some(0),
        recipient_binding: Some(F::from(0)),
        in_v: [Some(n1.v), Some(n2.v)],
        in_nk: [Some(n1.nk), Some(n2.nk)],
        in_rho: [Some(n1.rho), Some(n2.rho)],
        in_rcm: [Some(n1.rcm), Some(n2.rcm)],
        in_siblings: [sib1, sib2],
        in_bits: [bits1, bits2],
        out_v: [Some(F::from(out1.v)), Some(F::from(out2.v))],
        out_pk: [Some(bob_pk), Some(alice_pk)],
        out_rcm: [Some(out1.rcm), Some(out2.rcm)],
    };
    let t0 = js_sys_now();
    let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(TransferCircuit::blank(&cfg), &mut r).unwrap();
    let t1 = js_sys_now();
    let publics = circuit.public_inputs();
    let proof = Groth16::<Bls12_381>::prove(&pk, circuit, &mut r).unwrap();
    let t2 = js_sys_now();
    let ok = Groth16::<Bls12_381>::verify(&vk, &publics, &proof).unwrap();
    let t3 = js_sys_now();
    format!(
        "{{\"setup_ms\":{},\"prove_ms\":{},\"verify_ms\":{},\"verified\":{}}}",
        t1 - t0, t2 - t1, t3 - t2, ok
    )
}
