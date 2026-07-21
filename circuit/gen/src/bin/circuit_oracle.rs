//! Production-side dump for §4 (circuit soundness vs independent reference model).
//!
//! This binary IS the production witness generator: it uses `common` (the shipped circuit
//! crate) to emit, for a seeded batch of transactions, the exact values a correct circuit
//! enforces — Poseidon parameters, per-note pk/nf/cm, tree roots, and the 8-element
//! transfer public-input vector. The INDEPENDENT Python model (fortress/refmodel/model.py)
//! reimplements Poseidon (Grain-LFSR + Cauchy MDS + sponge) and the circuit semantics from
//! the spec, WITHOUT importing any production helper, and must reproduce every value.
//!
//! Output: JSON on stdout. Usage: circuit_oracle --seed <u64> --count <n>

use ark_bls12_381::Fr as F;
use ark_ff::{PrimeField, UniformRand};
use ark_std::rand::{rngs::StdRng, RngCore, SeedableRng};
use common::{
    derive_nf, derive_pk, note_commitment, poseidon_config, DenseTree, Note, TAG_CM, TAG_NF,
    TAG_PK,
};

fn dec(x: &F) -> String {
    x.into_bigint().to_string()
}

fn main() {
    let mut seed: u64 = 20260721;
    let mut count: u64 = 200;
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--seed" => {
                seed = args[i + 1].parse().unwrap();
                i += 2;
            }
            "--count" => {
                count = args[i + 1].parse().unwrap();
                i += 2;
            }
            o => panic!("unknown arg {o}"),
        }
    }

    let cfg = poseidon_config();

    // ---- dump Poseidon parameters (decimal) ----
    let modulus_str = F::MODULUS.to_string();
    print!("{{\"modulus\":\"{modulus_str}\",");
    print!("\"tags\":{{\"pk\":{TAG_PK},\"nf\":{TAG_NF},\"cm\":{TAG_CM}}},");
    print!("\"full_rounds\":{},\"partial_rounds\":{},\"alpha\":{},\"rate\":{},\"capacity\":{},",
        cfg.full_rounds, cfg.partial_rounds, cfg.alpha, cfg.rate, cfg.capacity);
    print!("\"ark\":[");
    for (ri, row) in cfg.ark.iter().enumerate() {
        if ri > 0 {
            print!(",");
        }
        print!("[");
        for (ci, x) in row.iter().enumerate() {
            if ci > 0 {
                print!(",");
            }
            print!("\"{}\"", dec(x));
        }
        print!("]");
    }
    print!("],\"mds\":[");
    for (ri, row) in cfg.mds.iter().enumerate() {
        if ri > 0 {
            print!(",");
        }
        print!("[");
        for (ci, x) in row.iter().enumerate() {
            if ci > 0 {
                print!(",");
            }
            print!("\"{}\"", dec(x));
        }
        print!("]");
    }
    print!("],");

    // ---- hash test vectors: hash_n over 1..5 inputs, seeded ----
    let mut rng = StdRng::seed_from_u64(seed);
    print!("\"hash_vectors\":[");
    for h in 0..40u64 {
        if h > 0 {
            print!(",");
        }
        let arity = (h % 5 + 1) as usize;
        let inputs: Vec<F> = (0..arity).map(|_| F::rand(&mut rng)).collect();
        let out = common::hash_n(&cfg, &inputs);
        print!("{{\"in\":[");
        for (k, x) in inputs.iter().enumerate() {
            if k > 0 {
                print!(",");
            }
            print!("\"{}\"", dec(x));
        }
        print!("],\"out\":\"{}\"}}", dec(&out));
    }
    print!("],");

    // ---- transfer witness expected values ----
    // A transfer draws two owned input notes placed in a small dense tree of unrelated
    // commitments, two outputs (recipient + change), and computes the public-input vector
    // exactly as TransferCircuit.public_inputs() does.
    print!("\"transfers\":[");
    for t in 0..count {
        if t > 0 {
            print!(",");
        }
        let owner_nk = F::rand(&mut rng);
        let recipient_nk = F::rand(&mut rng);
        let in0 = Note {
            v: 10_000 + rng.next_u64() % 1_000_000,
            nk: owner_nk,
            rho: F::rand(&mut rng),
            rcm: F::rand(&mut rng),
        };
        let in1 = Note {
            v: 10_000 + rng.next_u64() % 1_000_000,
            nk: owner_nk,
            rho: F::rand(&mut rng),
            rcm: F::rand(&mut rng),
        };
        let mut filler = |rng: &mut StdRng| Note {
            v: 1,
            nk: F::rand(rng),
            rho: F::rand(rng),
            rcm: F::rand(rng),
        };
        let leaves = vec![
            filler(&mut rng).cm(&cfg),
            in0.cm(&cfg),
            filler(&mut rng).cm(&cfg),
            filler(&mut rng).cm(&cfg),
            in1.cm(&cfg),
            filler(&mut rng).cm(&cfg),
        ];
        let tree = DenseTree { leaves };
        let anchor = tree.root(&cfg);
        let nf0 = in0.nf(&cfg);
        let nf1 = in1.nf(&cfg);
        let total = in0.v + in1.v;
        let fee = rng.next_u64() % (total / 8 + 1);
        let v_pub_out = rng.next_u64() % ((total - fee) / 3 + 1);
        let remaining = total - fee - v_pub_out;
        let out0_v = rng.next_u64() % (remaining + 1);
        let out1_v = remaining - out0_v;
        let out_pk0 = derive_pk(&cfg, recipient_nk);
        let out_pk1 = derive_pk(&cfg, owner_nk);
        let rcm0 = F::rand(&mut rng);
        let rcm1 = F::rand(&mut rng);
        // rho of output j = nf_j (Orchard chaining)
        let cm_out0 = note_commitment(&cfg, out0_v, out_pk0, nf0, rcm0);
        let cm_out1 = note_commitment(&cfg, out1_v, out_pk1, nf1, rcm1);
        let recipient_binding = F::rand(&mut rng);

        print!("{{\"owner_nk\":\"{}\",\"recip_nk\":\"{}\",", dec(&owner_nk), dec(&recipient_nk));
        print!("\"in0\":{{\"v\":{},\"rho\":\"{}\",\"rcm\":\"{}\"}},", in0.v, dec(&in0.rho), dec(&in0.rcm));
        print!("\"in1\":{{\"v\":{},\"rho\":\"{}\",\"rcm\":\"{}\"}},", in1.v, dec(&in1.rho), dec(&in1.rcm));
        print!("\"out0\":{{\"v\":{},\"pk\":\"{}\",\"rcm\":\"{}\"}},", out0_v, dec(&out_pk0), dec(&rcm0));
        print!("\"out1\":{{\"v\":{},\"pk\":\"{}\",\"rcm\":\"{}\"}},", out1_v, dec(&out_pk1), dec(&rcm1));
        print!("\"fee\":{fee},\"v_pub_out\":{v_pub_out},\"recipient_binding\":\"{}\",", dec(&recipient_binding));
        // leaf commitments so the model can rebuild the same tree
        print!("\"leaves\":[");
        for (k, l) in tree.leaves.iter().enumerate() {
            if k > 0 {
                print!(",");
            }
            print!("\"{}\"", dec(l));
        }
        print!("],\"in0_index\":1,\"in1_index\":4,");
        // expected values (the load-bearing outputs)
        print!("\"expect\":{{\"pk0\":\"{}\",\"pk1\":\"{}\",", dec(&in0.pk(&cfg)), dec(&in1.pk(&cfg)));
        print!("\"cm_in0\":\"{}\",\"cm_in1\":\"{}\",", dec(&in0.cm(&cfg)), dec(&in1.cm(&cfg)));
        print!("\"anchor\":\"{}\",\"nf0\":\"{}\",\"nf1\":\"{}\",", dec(&anchor), dec(&nf0), dec(&nf1));
        print!("\"cm_out0\":\"{}\",\"cm_out1\":\"{}\",", dec(&cm_out0), dec(&cm_out1));
        // public-input vector (allocation order)
        print!("\"public_inputs\":[\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"]}}}}",
            dec(&anchor), dec(&nf0), dec(&nf1), dec(&cm_out0), dec(&cm_out1),
            dec(&F::from(fee)), dec(&F::from(v_pub_out)), dec(&recipient_binding));
    }
    println!("]}}");
    let _ = (TAG_NF, derive_nf); // referenced by the model spec; nf uses derive_nf semantics
}
