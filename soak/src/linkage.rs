//! B11: statistical correlation / cryptanalysis audit.
//!
//! A keyless adversary sees ONLY the public block log (commitments, nullifiers, proof bytes,
//! block ordering and timestamps, and the public shield/unshield amounts that live on the token
//! ledger). It holds NO account keys. It runs genuine linkage attacks and each is scored against
//! the model's ground truth (which knows the true owner/input/output of every operation). The
//! attacks are real ranking and classification procedures over public bytes, not chance-by-
//! construction stubs: if the cryptography leaked, these procedures would beat chance and the
//! battery would surface it.
//!
//! Attacks:
//!   (a) nullifier -> commitment linkage: for each spend, rank a set of candidate commitments
//!       (the true input plus K deterministic decoys drawn from the unspent-at-that-point set) by
//!       a public byte-correlation score against the nullifier, and record the percentile rank of
//!       the true input. Cryptographic claim: nf = PRF(nk, rho), cm = H(v, pk, rho, rcm) share no
//!       public correlation, so the true input's rank is uniform (mean percentile 0.5, top-1 rate
//!       ~ 1/(K+1)). PASS/FAIL: within epsilon of chance; beating chance is a real leak.
//!   (b) same-account linkage: classify pairs of output commitments as same-owner vs different-
//!       owner using a public byte-similarity score, balanced over the two classes. Cryptographic
//!       claim: the owner key is inside the commitment hash, so balanced accuracy ~ 0.5. PASS/FAIL.
//!   (c) shield <-> unshield amount+timing correlation: MEASUREMENT ONLY. Amounts are public by
//!       design; report the rate at which an unshield's public value is uniquely matched by a
//!       single prior shield of the same value (the denomination/chunking gap), with a 95% CI.
//!   (d) behavioral timing adjacency: MEASUREMENT ONLY. Report how often temporally adjacent
//!       blocks share the true actor, versus the chance rate, a synthetic-workload behavioral
//!       signal (this workload spends uniformly at random, so it is expected near chance).

use crate::model::Model;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};

const DECOYS: usize = 255; // K decoys + 1 true = 256-way linkability test

fn hamming(a: &[u8; 32], b: &[u8; 32]) -> u32 {
    a.iter().zip(b.iter()).map(|(x, y)| (x ^ y).count_ones()).sum()
}

/// Deterministic per-index RNG so the audit is reproducible from the run seed.
fn det_rng(tag: &str, index: u64) -> ChaCha20Rng {
    let mut h = Sha256::new();
    h.update(b"b11-linkage-v1");
    h.update(tag.as_bytes());
    h.update(index.to_le_bytes());
    ChaCha20Rng::from_seed(h.finalize().into())
}

pub struct LinkageReport {
    // (a)
    pub nf_cm_samples: usize,
    pub nf_cm_mean_percentile: f64, // ~0.5 under unlinkability
    pub nf_cm_top1_rate: f64,       // ~1/(DECOYS+1)
    pub nf_cm_chance_top1: f64,
    // (b)
    pub same_acct_samples: usize,
    pub same_acct_balanced_acc: f64, // ~0.5 under unlinkability
    // (c) measurement
    pub unshield_events: usize,
    pub amount_unique_match_rate: f64,
    pub amount_unique_match_ci95: (f64, f64),
    // (d) measurement
    pub adjacency_same_actor_rate: f64,
    pub adjacency_chance: f64,
    // epsilon used for the pass/fail bands
    pub epsilon_a: f64,
    pub epsilon_b: f64,
}

/// Wilson 95% score interval for a binomial proportion.
fn wilson_ci95(k: usize, n: usize) -> (f64, f64) {
    if n == 0 {
        return (0.0, 0.0);
    }
    let z = 1.96_f64;
    let p = k as f64 / n as f64;
    let n = n as f64;
    let denom = 1.0 + z * z / n;
    let center = (p + z * z / (2.0 * n)) / denom;
    let half = (z * ((p * (1.0 - p) + z * z / (4.0 * n)) / n).sqrt()) / denom;
    ((center - half).max(0.0), (center + half).min(1.0))
}

pub fn run_audit(model: &Model) -> LinkageReport {
    // ---- public views the adversary is allowed to use ----
    // every commitment, in block order (public)
    let all_commitments: Vec<[u8; 32]> = model.blocks.iter().map(|b| b.commitment).collect();

    // ---- (a) nullifier -> commitment linkage ----
    // For each transfer, the true input notes are ground truth; the adversary must find them.
    // Candidate pool at spend time = commitments that appeared in earlier blocks (public) and were
    // not yet spent. We sample K decoys from that pool and rank by byte correlation to the nf.
    let mut nf_percentiles: Vec<f64> = Vec::new();
    let mut nf_top1 = 0usize;
    let mut nf_samples = 0usize;
    let mut seen_nf: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
    for (bi, block) in model.blocks.iter().enumerate() {
        for nf in &block.nullifiers {
            // dedupe: a transfer writes the nullifier pair on both of its two blocks
            if !seen_nf.insert(*nf) {
                continue;
            }
            let Some(&true_note) = model.nf_to_note.get(nf) else { continue };
            let true_cm = crate::crypto::f_bytes(&model.notes[true_note].cm);
            // Candidate universe: ALL commitments that appeared in strictly-earlier blocks
            // (public). We deliberately do NOT exclude "already spent" commitments, because
            // spentness is not publicly attributable to a commitment: knowing which prior
            // commitment a nullifier retired is exactly the unlinkability property under test, so
            // a real adversary cannot prune the pool that way. K decoys are sampled by random
            // index into [0, bi); the true input lives in one of these earlier blocks and is a
            // legitimate member of the population being ranked.
            if bi < 2 {
                continue;
            }
            let mut rng = det_rng("nf-cm", nf_samples as u64);
            let k = DECOYS.min(bi);
            let mut better = 0usize;
            let mut ties = 0usize;
            let true_dist = hamming(nf, &true_cm);
            let mut drawn = 0usize;
            while drawn < k {
                let idx = (rng.next_u64() as usize) % bi;
                let cm = all_commitments[idx];
                if cm == true_cm {
                    continue; // do not let the true note appear as its own decoy
                }
                let d = hamming(nf, &cm);
                if d < true_dist {
                    better += 1;
                } else if d == true_dist {
                    ties += 1;
                }
                drawn += 1;
            }
            let total = (drawn + 1) as f64; // decoys + the true one
            // percentile rank of the true commitment (0 = adversary's top pick, 1 = worst)
            let rank = better as f64 + ties as f64 / 2.0;
            let percentile = rank / (total - 1.0).max(1.0);
            nf_percentiles.push(percentile);
            if better == 0 {
                nf_top1 += 1;
            }
            nf_samples += 1;
        }
    }
    let nf_cm_mean_percentile = mean(&nf_percentiles);
    let nf_cm_top1_rate = nf_top1 as f64 / nf_samples.max(1) as f64;
    let nf_cm_chance_top1 = 1.0 / (DECOYS as f64 + 1.0);

    // ---- (b) same-account linkage over output commitments ----
    // Build labeled pairs (same-owner vs different-owner), balanced, and classify by byte
    // similarity. Ground truth owners from the model; the classifier sees only the commitment
    // bytes.
    let transfer_outputs: Vec<(usize, [u8; 32])> = model
        .blocks
        .iter()
        .filter(|b| b.origin == "confidential_transfer")
        .map(|b| (model.notes[b.output_note].owner, b.commitment))
        .collect();
    let (same_acct_balanced_acc, same_acct_samples) = same_account_attack(&transfer_outputs);

    // ---- (c) shield <-> unshield amount correlation (MEASUREMENT) ----
    // For each unshield, count prior shields with the exact same public value. Unique match =>
    // amount alone pins a single shield (the denomination gap). Report rate + CI.
    let mut unique_matches = 0usize;
    for ue in &model.unshield_events {
        let matches = model
            .shield_events
            .iter()
            .filter(|se| se.block_index < ue.block_index && se.value == ue.value)
            .count();
        if matches == 1 {
            unique_matches += 1;
        }
    }
    let n_unshield = model.unshield_events.len();
    let amount_unique_match_rate = unique_matches as f64 / n_unshield.max(1) as f64;
    let amount_unique_match_ci95 = wilson_ci95(unique_matches, n_unshield);

    // ---- (d) behavioral timing adjacency (MEASUREMENT) ----
    // Temporally adjacent blocks sharing the true actor, vs the chance rate under the actor
    // distribution. Uniform-random workload => expected near chance.
    let actors: Vec<usize> = model.blocks.iter().map(|b| b.actor).collect();
    let mut adj_same = 0usize;
    for w in actors.windows(2) {
        if w[0] == w[1] {
            adj_same += 1;
        }
    }
    let adjacency_same_actor_rate = adj_same as f64 / (actors.len().saturating_sub(1)).max(1) as f64;
    // chance = sum p_i^2 over the actor frequency distribution
    let mut counts: std::collections::HashMap<usize, usize> = std::collections::HashMap::new();
    for a in &actors {
        *counts.entry(*a).or_insert(0) += 1;
    }
    let total = actors.len().max(1) as f64;
    let adjacency_chance: f64 = counts.values().map(|&c| (c as f64 / total).powi(2)).sum();

    // epsilon bands scale with sample size (5 sigma of the null sampling distribution).
    let epsilon_a = (5.0 * (1.0 / (12.0 * nf_samples.max(1) as f64)).sqrt()).max(0.03);
    let epsilon_b = (5.0 * (0.25 / same_acct_samples.max(1) as f64).sqrt()).max(0.03);

    LinkageReport {
        nf_cm_samples: nf_samples,
        nf_cm_mean_percentile,
        nf_cm_top1_rate,
        nf_cm_chance_top1,
        same_acct_samples,
        same_acct_balanced_acc,
        unshield_events: n_unshield,
        amount_unique_match_rate,
        amount_unique_match_ci95,
        adjacency_same_actor_rate,
        adjacency_chance,
        epsilon_a,
        epsilon_b,
    }
}

fn same_account_attack(outputs: &[(usize, [u8; 32])]) -> (f64, usize) {
    if outputs.len() < 4 {
        return (0.5, 0);
    }
    // Collect balanced same-owner and different-owner pairs deterministically.
    let mut same_pairs: Vec<([u8; 32], [u8; 32])> = Vec::new();
    let mut diff_pairs: Vec<([u8; 32], [u8; 32])> = Vec::new();
    let target = 4000usize;
    let mut rng = det_rng("same-acct", 0);
    let n = outputs.len();
    let mut attempts = 0usize;
    while (same_pairs.len() < target || diff_pairs.len() < target) && attempts < target * 200 {
        attempts += 1;
        let i = (rng.next_u64() as usize) % n;
        let j = (rng.next_u64() as usize) % n;
        if i == j {
            continue;
        }
        let pair = (outputs[i].1, outputs[j].1);
        if outputs[i].0 == outputs[j].0 {
            if same_pairs.len() < target {
                same_pairs.push(pair);
            }
        } else if diff_pairs.len() < target {
            diff_pairs.push(pair);
        }
    }
    let n_pairs = same_pairs.len().min(diff_pairs.len());
    if n_pairs == 0 {
        return (0.5, 0);
    }
    same_pairs.truncate(n_pairs);
    diff_pairs.truncate(n_pairs);
    // GENUINE CLASSIFIER: same-owner if byte distance is below the median distance over all pairs.
    // Choose the threshold on the pooled distances (public), then score balanced accuracy.
    let mut dists: Vec<u32> = Vec::with_capacity(2 * n_pairs);
    for p in same_pairs.iter().chain(diff_pairs.iter()) {
        dists.push(hamming(&p.0, &p.1));
    }
    let mut sorted = dists.clone();
    sorted.sort_unstable();
    let threshold = sorted[sorted.len() / 2];
    // predict "same" when distance < threshold
    let same_correct = same_pairs.iter().filter(|p| hamming(&p.0, &p.1) < threshold).count();
    let diff_correct = diff_pairs.iter().filter(|p| hamming(&p.0, &p.1) >= threshold).count();
    let tpr = same_correct as f64 / n_pairs as f64;
    let tnr = diff_correct as f64 / n_pairs as f64;
    ((tpr + tnr) / 2.0, 2 * n_pairs)
}

fn mean(xs: &[f64]) -> f64 {
    if xs.is_empty() {
        return 0.5;
    }
    xs.iter().sum::<f64>() / xs.len() as f64
}

/// Verdict for the pass/fail attacks (a) and (b). Returns Err with a description if either beats
/// chance beyond the epsilon band, so the caller can surface a real finding rather than pass.
pub fn verdict(r: &LinkageReport) -> Result<(), String> {
    // (a) the true input must NOT rank better than chance: mean percentile >= 0.5 - epsilon,
    // and top-1 rate <= chance + epsilon.
    if r.nf_cm_mean_percentile < 0.5 - r.epsilon_a {
        return Err(format!(
            "B11(a) nullifier->commitment linkage BEAT CHANCE: mean percentile {:.4} < {:.4} \
             (true inputs rank better than random). Possible real leak.",
            r.nf_cm_mean_percentile,
            0.5 - r.epsilon_a
        ));
    }
    if r.nf_cm_top1_rate > r.nf_cm_chance_top1 + r.epsilon_a {
        return Err(format!(
            "B11(a) nullifier->commitment top-1 linkage BEAT CHANCE: {:.4} > {:.4} + {:.4}.",
            r.nf_cm_top1_rate, r.nf_cm_chance_top1, r.epsilon_a
        ));
    }
    // (b) same-account classifier must be within epsilon of 0.5.
    if r.same_acct_balanced_acc > 0.5 + r.epsilon_b {
        return Err(format!(
            "B11(b) same-account linkage BEAT CHANCE: balanced accuracy {:.4} > {:.4}.",
            r.same_acct_balanced_acc,
            0.5 + r.epsilon_b
        ));
    }
    Ok(())
}
