//! Phase-1 structured reference string (powers of tau) for BLS12-381 Groth16.
//!
//! This is the universal, circuit-independent object that Phase-2 specializes. Its contents are
//! exactly what a Groth16-shaped powers-of-tau ceremony (Bowe-Gabizon-Miers Phase-1, the Zcash
//! Sapling MPC, snarkjs `powersOfTau`) publishes after accumulation:
//!
//!   tau_g1[i]        = [tau^i]_1          for i in 0 ..= 2n-2   (length 2n-1)
//!   tau_g2[i]        = [tau^i]_2          for i in 0 ..= n-1    (length n)
//!   alpha_tau_g1[i]  = [alpha * tau^i]_1  for i in 0 ..= n-1    (length n)
//!   beta_tau_g1[i]   = [beta  * tau^i]_1  for i in 0 ..= n-1    (length n)
//!   beta_g2          = [beta]_2
//!
//! where n = 2^power is the largest QAP domain any specialized circuit needs. For the
//! shielded-ledger circuits n = 2^15 (transfer QAP domain; deposit's 2^10 domain is a sub-domain).
//!
//! PROVENANCE. In production this SRS is the extracted first 2^power powers of an inherited,
//! reviewed BLS12-381 Phase-1 (the Zcash Sapling Powers of Tau); its
//! accumulated secret (tau, alpha, beta) is UNKNOWN to everyone. `structure_check` below verifies,
//! by pairings alone and WITHOUT knowing the secret, that the bytes are a well-formed powers of
//! tau; that is the same test applied to the production extractor's output.
//!
//! For the local battery and the valueless demo, `generate_test_tier` samples (tau, alpha, beta)
//! from a CSPRNG and builds a structurally identical SRS whose secret is known ONLY so the initial
//! Phase-2 parameters can be cross-checked against a direct oracle. It carries the same
//! not-real-value provenance the repo already uses for `os-csprng-single-party` keys, and is never
//! eligible for a real-value keyset.

use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{One, UniformRand};
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, SerializationError, Valid, Validate,
};
use rand::RngCore;
use std::io::{Read, Write};

/// The provenance label carried alongside the SRS bytes, mirroring the repo's key tiers.
///
/// ark-serialize 0.5's derive does not support enums, so the codec is a single tag byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SrsProvenance {
    /// Sampled locally from a CSPRNG with a KNOWN accumulated secret. Structurally real; used only
    /// for the battery and the valueless demo. Never real-value eligible.
    TestTierKnownSecret,
    /// Extracted from an inherited, reviewed multi-party Phase-1 whose secret is unknown to all.
    /// The only tier eligible to seed a real-value ceremony.
    InheritedReviewedPhase1,
}

impl SrsProvenance {
    fn tag(self) -> u8 {
        match self {
            SrsProvenance::TestTierKnownSecret => 0,
            SrsProvenance::InheritedReviewedPhase1 => 1,
        }
    }
    fn from_tag(t: u8) -> Result<Self, SerializationError> {
        match t {
            0 => Ok(SrsProvenance::TestTierKnownSecret),
            1 => Ok(SrsProvenance::InheritedReviewedPhase1),
            _ => Err(SerializationError::InvalidData),
        }
    }
}

impl CanonicalSerialize for SrsProvenance {
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        _compress: Compress,
    ) -> Result<(), SerializationError> {
        Ok(writer.write_all(&[self.tag()])?)
    }
    fn serialized_size(&self, _compress: Compress) -> usize {
        1
    }
}

impl Valid for SrsProvenance {
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}

impl CanonicalDeserialize for SrsProvenance {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        _compress: Compress,
        _validate: Validate,
    ) -> Result<Self, SerializationError> {
        let mut b = [0u8; 1];
        reader.read_exact(&mut b)?;
        SrsProvenance::from_tag(b[0])
    }
}

/// A Groth16-shaped powers of tau of a given `power` (n = 2^power).
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Phase1Srs {
    pub power: u32,
    pub provenance: SrsProvenance,
    pub tau_g1: Vec<G1Affine>,       // length 2n-1
    pub tau_g2: Vec<G2Affine>,       // length n
    pub alpha_tau_g1: Vec<G1Affine>, // length n
    pub beta_tau_g1: Vec<G1Affine>,  // length n
    pub beta_g2: G2Affine,
}

impl Phase1Srs {
    /// n = 2^power, the largest QAP domain this SRS can specialize.
    pub fn n(&self) -> usize {
        1usize << self.power
    }

    /// Build a structurally real powers of tau with a KNOWN secret. Test tier only.
    ///
    /// This is not a stub: every power is a genuine scalar multiple on the real BLS12-381 curve,
    /// so Phase-2 exercises the identical math it will run over the inherited SRS. Only the
    /// provenance label (and the fact that the secret is known here) differs.
    pub fn generate_test_tier<R: RngCore>(power: u32, rng: &mut R) -> Self {
        let n = 1usize << power;
        let tau = Fr::rand(rng);
        let alpha = Fr::rand(rng);
        let beta = Fr::rand(rng);
        Self::from_secret(power, tau, alpha, beta, SrsProvenance::TestTierKnownSecret, n)
    }

    /// Construct the SRS from an explicit secret. Exposed so the params oracle can rebuild the
    /// exact same SRS deterministically and so tests can pin values.
    pub fn from_secret(
        power: u32,
        tau: Fr,
        alpha: Fr,
        beta: Fr,
        provenance: SrsProvenance,
        n: usize,
    ) -> Self {
        let g1 = G1Projective::generator();
        let g2 = G2Projective::generator();

        // Powers of tau as field elements first (cheap), then a single scalar-mul per power.
        let mut tau_pows = Vec::with_capacity(2 * n - 1);
        let mut acc = Fr::one();
        for _ in 0..(2 * n - 1) {
            tau_pows.push(acc);
            acc *= tau;
        }

        let tau_g1: Vec<G1Affine> =
            G1Projective::normalize_batch(&tau_pows.iter().map(|t| g1 * t).collect::<Vec<_>>());
        let tau_g2: Vec<G2Affine> =
            G2Projective::normalize_batch(&tau_pows[..n].iter().map(|t| g2 * t).collect::<Vec<_>>());
        let alpha_tau_g1: Vec<G1Affine> = G1Projective::normalize_batch(
            &tau_pows[..n].iter().map(|t| g1 * (alpha * t)).collect::<Vec<_>>(),
        );
        let beta_tau_g1: Vec<G1Affine> = G1Projective::normalize_batch(
            &tau_pows[..n].iter().map(|t| g1 * (beta * t)).collect::<Vec<_>>(),
        );
        let beta_g2 = (g2 * beta).into_affine();

        Phase1Srs { power, provenance, tau_g1, tau_g2, alpha_tau_g1, beta_tau_g1, beta_g2 }
    }

    /// Verify, by pairings alone and WITHOUT the secret, that the bytes are a well-formed powers of
    /// tau: the G1 tau chain is geometric with the same ratio the G2 chain encodes, and alpha/beta
    /// are consistent across the two groups. This is exactly the acceptance test the production
    /// extractor's output must pass. Returns Err with the first inconsistency found.
    ///
    /// `sample_indices` keeps the check O(1) pairings instead of O(n): a random handful of indices
    /// plus the structural endpoints. For an exhaustive check pass every index.
    pub fn structure_check(&self, sample_indices: &[usize]) -> Result<(), String> {
        let n = self.n();
        if self.tau_g1.len() != 2 * n - 1 {
            return Err(format!("tau_g1 len {} != 2n-1 {}", self.tau_g1.len(), 2 * n - 1));
        }
        if self.tau_g2.len() != n || self.alpha_tau_g1.len() != n || self.beta_tau_g1.len() != n {
            return Err("tau_g2/alpha_tau_g1/beta_tau_g1 must have length n".into());
        }
        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();

        // tau_g1[0] and tau_g2[0] must be the generators (tau^0 = 1).
        if self.tau_g1[0] != g1 || self.tau_g2[0] != g2 {
            return Err("tau_*[0] is not the group generator".into());
        }
        // Non-degenerate: tau_g2[1] != g2 (tau != 1), else the SRS is trivial/insecure.
        if self.tau_g2[1] == g2 {
            return Err("tau == 1 (degenerate SRS)".into());
        }

        let tau_g2_1 = self.tau_g2[1];
        // The G1 tau chain has ratio tau, matching the G2 chain: e(tau_g1[i], g2) == e(tau_g1[i-1], tau_g2[1]).
        for &i in sample_indices {
            if i == 0 || i >= self.tau_g1.len() {
                continue;
            }
            let lhs = Bls12_381::pairing(self.tau_g1[i], g2);
            let rhs = Bls12_381::pairing(self.tau_g1[i - 1], tau_g2_1);
            if lhs != rhs {
                return Err(format!("tau_g1 chain broken at index {i}"));
            }
            // Cross-group: tau_g1[i] and tau_g2[i] encode the same tau^i (for i < n).
            if i < n {
                let lhs = Bls12_381::pairing(self.tau_g1[i], g2);
                let rhs = Bls12_381::pairing(g1, self.tau_g2[i]);
                if lhs != rhs {
                    return Err(format!("tau_g1/tau_g2 disagree at index {i}"));
                }
            }
        }

        // alpha and beta chains: alpha_tau_g1[i] = alpha * tau^i, tied to tau_g2[i].
        let alpha_g1 = self.alpha_tau_g1[0];
        let beta_g1 = self.beta_tau_g1[0];
        for &i in sample_indices {
            if i == 0 || i >= n {
                continue;
            }
            if Bls12_381::pairing(self.alpha_tau_g1[i], g2) != Bls12_381::pairing(alpha_g1, self.tau_g2[i])
            {
                return Err(format!("alpha_tau_g1 chain broken at index {i}"));
            }
            if Bls12_381::pairing(self.beta_tau_g1[i], g2) != Bls12_381::pairing(beta_g1, self.tau_g2[i])
            {
                return Err(format!("beta_tau_g1 chain broken at index {i}"));
            }
        }
        // beta consistency between G1 and G2.
        if Bls12_381::pairing(beta_g1, g2) != Bls12_381::pairing(g1, self.beta_g2) {
            return Err("beta_g1 and beta_g2 disagree".into());
        }
        Ok(())
    }

    /// SHA-256 of the canonical compressed serialization: the SRS identity published in the spec.
    pub fn sha256_hex(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut bytes = Vec::new();
        self.serialize_compressed(&mut bytes).unwrap();
        hex::encode(Sha256::digest(&bytes))
    }
}
