//! Public transcript types for the Phase-2 ceremony, and the Fiat-Shamir hashing the whole
//! protocol is bound to. Nothing here holds a secret: a `DeltaParams` is public parameters, a
//! `Pok` is a public proof of knowledge, and the challenge chain is public.
//!
//! Hashing convention (identical in Rust and in the Motoko canister, so both can recompute the
//! same challenges with only SHA-256): `hash_to_fr(input)` reduces a 64-byte digest
//! `SHA256(0x00 || input) || SHA256(0x01 || input)` into the BLS12-381 scalar field. Two SHA-256
//! blocks give a ~512-bit digest whose reduction mod r is statistically uniform.

use ark_bls12_381::{Fq, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use sha2::{Digest, Sha256};

/// The delta-dependent subset of a circuit's Phase-2 parameters. This is exactly what changes from
/// one contribution to the next; the alpha/beta/gamma_abc/A/B queries are fixed by Phase-1 and live
/// in `FixedParams`.
#[derive(Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct DeltaParams {
    pub delta_g1: G1Affine,     // [delta]_1
    pub delta_g2: G2Affine,     // [delta]_2
    pub h_query: Vec<G1Affine>, // [ t(tau) tau^i / delta ]_1
    pub l_query: Vec<G1Affine>, // [ (beta A_j + alpha B_j + C_j)(tau) / delta ]_1, witness wires
}

/// The circuit-fixed subset of the Phase-2 parameters, computed once at ceremony init from the SRS.
/// Never changes; a verifier holds one copy and refuses any transcript that mutates it.
#[derive(Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct FixedParams {
    pub alpha_g1: G1Affine,
    pub beta_g1: G1Affine,
    pub beta_g2: G2Affine,
    pub gamma_g2: G2Affine,          // = G2 generator (gamma = 1)
    pub gamma_abc_g1: Vec<G1Affine>, // public-wire IC terms (gamma = 1)
    pub a_query: Vec<G1Affine>,
    pub b_g1_query: Vec<G1Affine>,
    pub b_g2_query: Vec<G2Affine>,
    pub num_instance: u32,
}

/// A contribution's public proof of knowledge of its delta increment `s`.
/// `delta_after` is `DeltaParams::delta_g1`, so it is not duplicated here.
#[derive(Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Pok {
    pub s_g1: G1Affine,        // s * G1
    pub s_delta_g1: G1Affine,  // s * delta * G1
    pub r_delta_g2: G2Affine,  // delta * r_g2, where r_g2 = c * G2 and c = challenge scalar
}

/// One contributor's step for one circuit: the resulting delta params and the PoK tying them to the
/// previous delta by a secret the contributor knew and (in an honest run) destroyed.
#[derive(Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct CircuitContribution {
    pub delta: DeltaParams,
    pub pok: Pok,
}

/// A full contribution covers both ceremony circuits (transfer + deposit) with independent secrets.
#[derive(Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Contribution {
    /// Opaque contributor identity (the IC principal bytes the canister recorded). Empty for the
    /// beacon-finalize step, which has no principal.
    pub contributor: Vec<u8>,
    /// Unix-nanos timestamp the canister stamped. 0 in a pure off-chain transcript.
    pub timestamp: u64,
    pub transfer: CircuitContribution,
    pub deposit: CircuitContribution,
    /// True only for the final beacon step, whose secret is the public beacon hash.
    pub is_beacon: bool,
    /// The beacon bytes (empty unless is_beacon).
    pub beacon: Vec<u8>,
}

/// The complete public transcript: the fixed params of both circuits, the initial delta params, and
/// the ordered list of contributions. A verifier replays it from the initial params.
#[derive(Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Transcript {
    pub power: u32,
    /// SHA-256 of the Phase-1 SRS this ceremony specialized (its published identity).
    pub srs_sha256: Vec<u8>,
    pub transfer_fixed: FixedParams,
    pub deposit_fixed: FixedParams,
    pub transfer_initial: DeltaParams,
    pub deposit_initial: DeltaParams,
    pub contributions: Vec<Contribution>,
    /// Set once finalized (after the beacon step).
    pub finalized: bool,
}

// ------------------------------------------------------------------------------------------------
// Fiat-Shamir hashing
// ------------------------------------------------------------------------------------------------

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// SHA-256 of the canonical compressed serialization of any transcript object.
pub fn hash_obj<T: CanonicalSerialize>(x: &T) -> [u8; 32] {
    let mut bytes = Vec::new();
    x.serialize_compressed(&mut bytes).unwrap();
    sha256(&[&bytes])
}

/// hash_to_fr(input) = reduce( SHA256(0x00||input) || SHA256(0x01||input) ) into Fr.
/// Reproducible with SHA-256 alone in Motoko.
pub fn hash_to_fr(input: &[u8]) -> Fr {
    let a = sha256(&[&[0u8], input]);
    let b = sha256(&[&[1u8], input]);
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&a);
    wide[32..].copy_from_slice(&b);
    Fr::from_le_bytes_mod_order(&wide)
}

// --- Motoko-reproducible point encodings: uncompressed, big-endian coordinates, 48 bytes per Fq.
fn fq_be(x: &Fq) -> [u8; 48] {
    let v = x.into_bigint().to_bytes_be();
    let mut out = [0u8; 48];
    out[48 - v.len()..].copy_from_slice(&v);
    out
}

/// G1 as 96 bytes: x(48 BE) || y(48 BE). Panics on the identity (never a valid ceremony point).
pub fn g1_be(p: &G1Affine) -> [u8; 96] {
    let (x, y) = p.xy().expect("identity G1 in hashing");
    let mut out = [0u8; 96];
    out[..48].copy_from_slice(&fq_be(&x));
    out[48..].copy_from_slice(&fq_be(&y));
    out
}

/// G2 as 192 bytes: x.c0 || x.c1 || y.c0 || y.c1, each 48 BE.
pub fn g2_be(p: &G2Affine) -> [u8; 192] {
    let (x, y) = p.xy().expect("identity G2 in hashing");
    let mut out = [0u8; 192];
    out[0..48].copy_from_slice(&fq_be(&x.c0));
    out[48..96].copy_from_slice(&fq_be(&x.c1));
    out[96..144].copy_from_slice(&fq_be(&y.c0));
    out[144..192].copy_from_slice(&fq_be(&y.c1));
    out
}

/// The PoK's three points serialized for the challenge chain.
pub fn pok_bytes(pok: &Pok) -> Vec<u8> {
    let mut v = Vec::with_capacity(96 + 96 + 192);
    v.extend_from_slice(&g1_be(&pok.s_g1));
    v.extend_from_slice(&g1_be(&pok.s_delta_g1));
    v.extend_from_slice(&g2_be(&pok.r_delta_g2));
    v
}

/// SHA-256 of a delta-params object over the exact byte layout the canister streams during upload:
///   delta_g1(96) || delta_g2(192) || u32be(h_len) || h[i](96)... || u32be(l_len) || l[i](96)...
/// Computed identically by the canister (streaming), the client, and the standalone verifier.
pub fn delta_params_hash(d: &DeltaParams) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(g1_be(&d.delta_g1));
    h.update(g2_be(&d.delta_g2));
    h.update((d.h_query.len() as u32).to_be_bytes());
    for p in &d.h_query {
        h.update(g1_be(p));
    }
    h.update((d.l_query.len() as u32).to_be_bytes());
    for p in &d.l_query {
        h.update(g1_be(p));
    }
    h.finalize().into()
}

/// Serialize a delta-params object to the exact wire/on-chain byte layout (what the canister
/// streams and hashes, and what `delta_params_hash` digests):
///   delta_g1(96) || delta_g2(192) || u32be(h_len) || h[i](96)... || u32be(l_len) || l[i](96)...
pub fn delta_to_wire(d: &DeltaParams) -> Vec<u8> {
    let mut v = Vec::with_capacity(288 + 8 + (d.h_query.len() + d.l_query.len()) * 96);
    v.extend_from_slice(&g1_be(&d.delta_g1));
    v.extend_from_slice(&g2_be(&d.delta_g2));
    v.extend_from_slice(&(d.h_query.len() as u32).to_be_bytes());
    for p in &d.h_query {
        v.extend_from_slice(&g1_be(p));
    }
    v.extend_from_slice(&(d.l_query.len() as u32).to_be_bytes());
    for p in &d.l_query {
        v.extend_from_slice(&g1_be(p));
    }
    v
}

fn g1_from_be(b: &[u8]) -> Result<G1Affine, String> {
    let x = Fq::from_be_bytes_mod_order(&b[..48]);
    let y = Fq::from_be_bytes_mod_order(&b[48..96]);
    let p = G1Affine::new_unchecked(x, y);
    if !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve() || p.is_zero() {
        return Err("invalid G1 in wire delta".into());
    }
    Ok(p)
}
fn g2_from_be(b: &[u8]) -> Result<G2Affine, String> {
    use ark_bls12_381::Fq2;
    let x = Fq2::new(Fq::from_be_bytes_mod_order(&b[..48]), Fq::from_be_bytes_mod_order(&b[48..96]));
    let y = Fq2::new(Fq::from_be_bytes_mod_order(&b[96..144]), Fq::from_be_bytes_mod_order(&b[144..192]));
    let p = G2Affine::new_unchecked(x, y);
    if !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve() || p.is_zero() {
        return Err("invalid G2 in wire delta".into());
    }
    Ok(p)
}

/// Parse a delta-params object from the wire layout. Validates every point (on curve, in subgroup,
/// non-identity) — this is the full point validation the off-chain side always performs.
pub fn delta_from_wire(bytes: &[u8]) -> Result<DeltaParams, String> {
    if bytes.len() < 296 {
        return Err("wire delta too short".into());
    }
    let delta_g1 = g1_from_be(&bytes[0..96])?;
    let delta_g2 = g2_from_be(&bytes[96..288])?;
    let h_len = u32::from_be_bytes(bytes[288..292].try_into().unwrap()) as usize;
    let l_off = 292 + h_len * 96;
    if bytes.len() < l_off + 4 {
        return Err("wire delta truncated in h block".into());
    }
    let mut h_query = Vec::with_capacity(h_len);
    for i in 0..h_len {
        h_query.push(g1_from_be(&bytes[292 + i * 96..292 + i * 96 + 96])?);
    }
    let l_len = u32::from_be_bytes(bytes[l_off..l_off + 4].try_into().unwrap()) as usize;
    let l_start = l_off + 4;
    if bytes.len() != l_start + l_len * 96 {
        return Err("wire delta length mismatch".into());
    }
    let mut l_query = Vec::with_capacity(l_len);
    for i in 0..l_len {
        l_query.push(g1_from_be(&bytes[l_start + i * 96..l_start + i * 96 + 96])?);
    }
    Ok(DeltaParams { delta_g1, delta_g2, h_query, l_query })
}

/// SHA-256 identity of the circuit-fixed params. The canister stores this as a 32-byte constant at
/// init; the standalone verifier recomputes it from the SRS-derived fixed params and checks it.
pub fn fixed_params_hash(f: &FixedParams) -> [u8; 32] {
    hash_obj(f)
}

/// The per-contribution PoK challenge scalar `c`:
///   c = hash_to_fr( prev_challenge || g1be(s_g1) || g1be(s_delta_g1) || g1be(delta_after_g1) )
/// binding the PoK to the running transcript so contributions cannot be reordered or replayed.
pub fn pok_challenge(
    prev_challenge: &[u8; 32],
    s_g1: &G1Affine,
    s_delta_g1: &G1Affine,
    delta_after_g1: &G1Affine,
) -> Fr {
    let mut pre = Vec::with_capacity(32 + 96 * 3);
    pre.extend_from_slice(prev_challenge);
    pre.extend_from_slice(&g1_be(s_g1));
    pre.extend_from_slice(&g1_be(s_delta_g1));
    pre.extend_from_slice(&g1_be(delta_after_g1));
    hash_to_fr(&pre)
}

/// Advance the running challenge after a full contribution is accepted, over compact fields the
/// canister already has (32-byte per-circuit delta hashes + the small PoK bytes), never the 2.5 MB
/// of query points:
///   next = SHA256( prev || is_beacon || contributor || transfer_pok || deposit_pok
///                  || transfer_delta_hash || deposit_delta_hash || beacon )
pub fn advance_challenge(prev_challenge: &[u8; 32], c: &Contribution) -> [u8; 32] {
    let th = delta_params_hash(&c.transfer.delta);
    let dh = delta_params_hash(&c.deposit.delta);
    let mut h = Sha256::new();
    h.update(prev_challenge);
    h.update([u8::from(c.is_beacon)]);
    h.update((c.contributor.len() as u32).to_be_bytes());
    h.update(&c.contributor);
    h.update(pok_bytes(&c.transfer.pok));
    h.update(pok_bytes(&c.deposit.pok));
    h.update(th);
    h.update(dh);
    h.update((c.beacon.len() as u32).to_be_bytes());
    h.update(&c.beacon);
    h.finalize().into()
}

/// The genesis challenge:
///   SHA256( TAG || u32be(power) || srs_sha256 || tf_hash || df_hash || ti_delta_hash || di_delta_hash )
pub fn genesis_challenge(
    power: u32,
    srs_sha256: &[u8],
    transfer_fixed: &FixedParams,
    deposit_fixed: &FixedParams,
    transfer_initial: &DeltaParams,
    deposit_initial: &DeltaParams,
) -> [u8; 32] {
    let tag = b"shielded-ledger-phase2-ceremony-v1";
    let mut h = Sha256::new();
    h.update(tag);
    h.update(power.to_be_bytes());
    h.update(srs_sha256);
    h.update(fixed_params_hash(transfer_fixed));
    h.update(fixed_params_hash(deposit_fixed));
    h.update(delta_params_hash(transfer_initial));
    h.update(delta_params_hash(deposit_initial));
    h.finalize().into()
}
