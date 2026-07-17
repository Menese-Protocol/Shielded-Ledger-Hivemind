//! Native proving throughput, measured before the harness runs. Reports single-core
//! deposit and transfer proof latency and all-core proofs/second, so the full-tier wall-clock can
//! be projected. Uses the real circuits and the regenerated keyset.

use crate::keys::Keyset;
use ark_bls12_381::{Bls12_381, Fr as F};
use ark_ff::UniformRand;
use ark_groth16::Groth16;
use ark_snark::SNARK;
use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;
use common::{
    derive_pk, poseidon_config, DenseTree, DepositCircuit, Note, PoseidonCfg, TransferCircuit,
};
use rayon::prelude::*;
use std::time::Instant;

fn sample_transfer_circuit(cfg: &PoseidonCfg<F>, seed: u64) -> TransferCircuit {
    let mut r = StdRng::seed_from_u64(seed);
    let alice_nk = F::rand(&mut r);
    let bob_nk = F::rand(&mut r);
    let bob_pk = derive_pk(cfg, bob_nk);
    let alice_pk = derive_pk(cfg, alice_nk);
    let n1 = Note { v: 70, nk: alice_nk, rho: F::rand(&mut r), rcm: F::rand(&mut r) };
    let n2 = Note { v: 30, nk: alice_nk, rho: F::rand(&mut r), rcm: F::rand(&mut r) };
    let dense = DenseTree { leaves: vec![n1.cm(cfg), n2.cm(cfg)] };
    let anchor = dense.root(cfg);
    let (sib1, bits1) = dense.path(cfg, 0);
    let (sib2, bits2) = dense.path(cfg, 1);
    let nf1 = n1.nf(cfg);
    let nf2 = n2.nf(cfg);
    let out1 = Note { v: 55, nk: bob_nk, rho: nf1, rcm: F::rand(&mut r) };
    let out2 = Note { v: 40, nk: alice_nk, rho: nf2, rcm: F::rand(&mut r) };
    TransferCircuit {
        cfg: cfg.clone(),
        enforce_range: true,
        anchor: Some(anchor),
        nf: [Some(nf1), Some(nf2)],
        cm_out: [Some(out1.cm(cfg)), Some(out2.cm(cfg))],
        fee: Some(5),
        v_pub_out: Some(0),
        recipient_binding: Some(F::from(0u64)),
        in_v: [Some(n1.v), Some(n2.v)],
        in_nk: [Some(n1.nk), Some(n2.nk)],
        in_rho: [Some(n1.rho), Some(n2.rho)],
        in_rcm: [Some(n1.rcm), Some(n2.rcm)],
        in_siblings: [sib1, sib2],
        in_bits: [bits1, bits2],
        out_v: [Some(F::from(out1.v)), Some(F::from(out2.v))],
        out_pk: [Some(bob_pk), Some(alice_pk)],
        out_rcm: [Some(out1.rcm), Some(out2.rcm)],
    }
}

fn sample_deposit_circuit(cfg: &PoseidonCfg<F>, seed: u64) -> DepositCircuit {
    let mut r = StdRng::seed_from_u64(seed);
    let nk = F::rand(&mut r);
    let pk = derive_pk(cfg, nk);
    let rho = F::rand(&mut r);
    let rcm = F::rand(&mut r);
    let note = Note { v: 1234, nk, rho, rcm };
    DepositCircuit { cfg: cfg.clone(), cm: Some(note.cm(cfg)), v_pub: Some(1234), pk: Some(pk), rho: Some(rho), rcm: Some(rcm) }
}

pub struct BenchReport {
    pub deposit_single_ms: f64,
    pub transfer_single_ms: f64,
    pub deposit_allcore_per_s: f64,
    pub transfer_allcore_per_s: f64,
    pub cores: usize,
}

pub fn run(keys: &Keyset, allcore_batch: usize) -> BenchReport {
    let cfg = poseidon_config();
    let cores = rayon::current_num_threads();

    // single-core latency (median of a few)
    let mut d_ms = Vec::new();
    let mut t_ms = Vec::new();
    for i in 0..5u64 {
        let dc = sample_deposit_circuit(&cfg, 1000 + i);
        let mut r = StdRng::seed_from_u64(7);
        let t0 = Instant::now();
        let _ = Groth16::<Bls12_381>::prove(&keys.deposit_pk, dc, &mut r).unwrap();
        d_ms.push(t0.elapsed().as_secs_f64() * 1000.0);

        let tc = sample_transfer_circuit(&cfg, 2000 + i);
        let mut r = StdRng::seed_from_u64(7);
        let t0 = Instant::now();
        let _ = Groth16::<Bls12_381>::prove(&keys.transfer_pk, tc, &mut r).unwrap();
        t_ms.push(t0.elapsed().as_secs_f64() * 1000.0);
    }
    d_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    t_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let deposit_single_ms = d_ms[d_ms.len() / 2];
    let transfer_single_ms = t_ms[t_ms.len() / 2];

    // all-core throughput: `allcore_batch` independent proofs spread across the rayon pool.
    let dcs: Vec<DepositCircuit> = (0..allcore_batch as u64).map(|i| sample_deposit_circuit(&cfg, 3000 + i)).collect();
    let t0 = Instant::now();
    dcs.into_par_iter().for_each(|dc| {
        let mut r = StdRng::seed_from_u64(7);
        let _ = Groth16::<Bls12_381>::prove(&keys.deposit_pk, dc, &mut r).unwrap();
    });
    let deposit_allcore_per_s = allcore_batch as f64 / t0.elapsed().as_secs_f64();

    let tcs: Vec<TransferCircuit> = (0..allcore_batch as u64).map(|i| sample_transfer_circuit(&cfg, 4000 + i)).collect();
    let t0 = Instant::now();
    tcs.into_par_iter().for_each(|tc| {
        let mut r = StdRng::seed_from_u64(7);
        let _ = Groth16::<Bls12_381>::prove(&keys.transfer_pk, tc, &mut r).unwrap();
    });
    let transfer_allcore_per_s = allcore_batch as f64 / t0.elapsed().as_secs_f64();

    BenchReport {
        deposit_single_ms,
        transfer_single_ms,
        deposit_allcore_per_s,
        transfer_allcore_per_s,
        cores,
    }
}
