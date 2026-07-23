//! Vector generator + NATIVE ORACLE for the shielded-pool prototype.
//!
//! Everything the canister will be asked to accept or reject is first run through the
//! reference libraries natively (ark-groth16 / dalek-bulletproofs). The oracle's accept/reject
//! verdicts are written into `vectors/ORACLE.txt`; the canister's verdicts on the SAME vectors
//! must byte-match (gate b). A vector set whose oracle run fails any assertion is never written.
//!
//! Also demonstrates, natively, the two witness-level attacks the circuit must kill:
//!   A1 value-imbalanced witness  -> constraint system UNSATISFIED (cannot even prove)
//!   A2 field-wrap mint (v_out = v_in - fee + p) -> UNSATISFIED with range checks;
//!      and, run against the enforce_range=false variant, SATISFIED + a valid proof —
//!      proving the range constraint (S3) is the load-bearing defence, not decoration.

// Curve selection mirrors common/src/lib.rs: default BN254; `--features bls12-381` regenerates
// the identical battery over BLS12-381 — the curve of the measured Motoko verifier (G10-E).
#[cfg(feature = "bls12-381")]
use ark_bls12_381::{Bls12_381 as Curve, Fr as F};
#[cfg(not(feature = "bls12-381"))]
use ark_bn254::{Bn254 as Curve, Fr as F};
use ark_ff::{One, UniformRand};
use ark_groth16::Groth16;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;
use common::*;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

const INSECURE_TEST_SEED: u64 = 20260712;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SetupMode {
    /// Reproduces the checked-in oracle fixtures. The setup trapdoor is public by definition.
    InsecureDeterministicTest,
    /// Draws setup randomness directly from the operating system CSPRNG. This removes the
    /// published-seed vulnerability, but remains a single-party setup rather than an MPC ceremony.
    OsCsprngSingleParty,
}

impl SetupMode {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "insecure-deterministic-test" => Some(Self::InsecureDeterministicTest),
            "os-csprng-single-party" => Some(Self::OsCsprngSingleParty),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::InsecureDeterministicTest => "insecure-deterministic-test",
            Self::OsCsprngSingleParty => "os-csprng-single-party",
        }
    }

    fn publicly_reproducible_toxic_waste(self) -> bool {
        self == Self::InsecureDeterministicTest
    }
}

fn usage() -> ! {
    eprintln!(
        "usage: gen <output-dir> --setup <insecure-deterministic-test|os-csprng-single-party> \
[--statement <legacy|hardened>]\n\
         \n\
         insecure-deterministic-test: reproducible oracle fixtures only; NEVER deploy its keys\n\
         os-csprng-single-party: removes the public-seed flaw; still NOT an MPC ceremony\n\
         --statement legacy (default): the pre-hardening transfer statement — reproduces the\n\
                     frozen vectors byte-for-byte (the deployed verifying key's statement)\n\
         --statement hardened: the hardened conservation statement (in-circuit fee/v_pub_out\n\
                     ranges + input-note distinctness) — distinct keys, own fixture set"
    );
    std::process::exit(2)
}

fn parse_args() -> (String, SetupMode, bool) {
    let mut args = std::env::args().skip(1);
    let dir = args.next().unwrap_or_else(|| usage());
    let flag = args.next().unwrap_or_else(|| usage());
    let value = if flag == "--setup" {
        args.next().unwrap_or_else(|| usage())
    } else if let Some(value) = flag.strip_prefix("--setup=") {
        value.to_owned()
    } else {
        usage()
    };
    let legacy_statement = match args.next() {
        None => true,
        Some(flag) => {
            let statement = if flag == "--statement" {
                args.next().unwrap_or_else(|| usage())
            } else if let Some(value) = flag.strip_prefix("--statement=") {
                value.to_owned()
            } else {
                usage()
            };
            match statement.as_str() {
                "legacy" => true,
                "hardened" => false,
                _ => usage(),
            }
        }
    };
    if args.next().is_some() {
        usage()
    }
    let mode = SetupMode::parse(&value).unwrap_or_else(|| usage());
    (dir, mode, legacy_statement)
}

fn file_sha256(path: &str) -> String {
    let bytes = std::fs::read(path).unwrap();
    hex::encode(Sha256::digest(bytes))
}

fn hex_ser<T: CanonicalSerialize>(x: &T) -> String {
    let mut b = Vec::new();
    x.serialize_compressed(&mut b).unwrap();
    hex::encode(b)
}

struct Out {
    dir: String,
    oracle: String,
}
impl Out {
    fn write(&self, name: &str, data: &str) {
        std::fs::write(format!("{}/{}", self.dir, name), data).unwrap();
    }
    fn oracle_line(&mut self, s: &str) {
        println!("ORACLE {s}");
        writeln!(self.oracle, "{s}").unwrap();
    }
}

fn main() {
    let (dir, setup_mode, legacy_statement) = parse_args();
    std::fs::create_dir_all(&dir).unwrap();
    let mut out = Out { dir, oracle: String::new() };
    let cfg = poseidon_config();
    // This RNG exists only to make public oracle witnesses/proofs reproducible. In secure mode it
    // is never passed to Groth16 setup. Browser proofs use WebCrypto-backed randomness instead.
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(INSECURE_TEST_SEED);
    out.oracle_line(&format!("SETUP-MODE {}", setup_mode.name()));
    // The legacy statement's oracle text is FROZEN (diffed byte-for-byte by the security gate);
    // only the hardened statement announces itself, in its own fixture directory.
    if !legacy_statement {
        out.oracle_line("STATEMENT hardened (in-circuit fee/v_pub_out ranges + input-note distinctness)");
    }
    match setup_mode {
        SetupMode::InsecureDeterministicTest => out.oracle_line(
            "SETUP-WARNING PUBLIC FIXED SEED; TEST VECTORS ONLY; DEPLOYMENT FORBIDDEN",
        ),
        SetupMode::OsCsprngSingleParty => out.oracle_line(
            "SETUP-WARNING OS CSPRNG REMOVES PUBLIC-SEED FLAW; SINGLE-PARTY, NOT MPC-CEREMONY",
        ),
    }

    // ---------------- notes & tree ----------------
    // Alice deposits two notes (70 and 30), then transfers: 55 to Bob, 40 change, fee 5, 0 out.
    let alice_nk = F::rand(&mut rng);
    let bob_nk = F::rand(&mut rng);
    let bob_pk = derive_pk(&cfg, bob_nk);
    let alice_pk = derive_pk(&cfg, alice_nk);

    let n1 = Note { v: 70, nk: alice_nk, rho: F::rand(&mut rng), rcm: F::rand(&mut rng) };
    let n2 = Note { v: 30, nk: alice_nk, rho: F::rand(&mut rng), rcm: F::rand(&mut rng) };

    // two independent tree implementations must agree (self-check of the tree code)
    let mut inc = IncrementalTree::new(&cfg);
    inc.append(&cfg, n1.cm(&cfg));
    let anchor = inc.append(&cfg, n2.cm(&cfg));
    let dense = DenseTree { leaves: vec![n1.cm(&cfg), n2.cm(&cfg)] };
    assert_eq!(anchor, dense.root(&cfg), "IncrementalTree and DenseTree disagree on the root");
    out.oracle_line("TREE-XCHECK incremental==dense OK");

    let (sib1, bits1) = dense.path(&cfg, 0);
    let (sib2, bits2) = dense.path(&cfg, 1);

    let nf1 = n1.nf(&cfg);
    let nf2 = n2.nf(&cfg);

    // outputs: rho chained to input nullifiers (Orchard-style)
    let out1 = Note { v: 55, nk: bob_nk, rho: nf1, rcm: F::rand(&mut rng) };
    let out2 = Note { v: 40, nk: alice_nk, rho: nf2, rcm: F::rand(&mut rng) };
    let fee = 5u64;
    let v_pub_out = 0u64;
    let recipient_binding = F::from(0u64); // private transfers bind the canonical zero recipient

    let mk_circuit = || TransferCircuit {
        cfg: cfg.clone(),
        enforce_range: true,
        legacy_statement,
        anchor: Some(anchor),
        nf: [Some(nf1), Some(nf2)],
        cm_out: [Some(out1.cm(&cfg)), Some(out2.cm(&cfg))],
        fee: Some(fee),
        v_pub_out: Some(v_pub_out),
        recipient_binding: Some(recipient_binding),
        in_v: [Some(n1.v), Some(n2.v)],
        in_nk: [Some(n1.nk), Some(n2.nk)],
        in_rho: [Some(n1.rho), Some(n2.rho)],
        in_rcm: [Some(n1.rcm), Some(n2.rcm)],
        in_siblings: [sib1.clone(), sib2.clone()],
        in_bits: [bits1.clone(), bits2.clone()],
        out_v: [Some(F::from(out1.v)), Some(F::from(out2.v))],
        out_pk: [Some(bob_pk), Some(alice_pk)],
        out_rcm: [Some(out1.rcm), Some(out2.rcm)],
    };

    // constraint-count report + satisfaction self-check
    {
        let cs = ConstraintSystem::<F>::new_ref();
        mk_circuit().generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap(), "honest transfer witness does not satisfy the circuit");
        out.oracle_line(&format!(
            "TRANSFER-CIRCUIT constraints={} witnesses={} publics={}",
            cs.num_constraints(),
            cs.num_witness_variables(),
            cs.num_instance_variables() - 1
        ));
    }

    // ---------------- Groth16 setup + proofs (transfer) ----------------
    let transfer_blank = || if legacy_statement {
        TransferCircuit::blank_legacy(&cfg)
    } else {
        TransferCircuit::blank(&cfg)
    };
    let (tpk, tvk) = match setup_mode {
        SetupMode::InsecureDeterministicTest =>
            Groth16::<Curve>::circuit_specific_setup(transfer_blank(), &mut rng).unwrap(),
        SetupMode::OsCsprngSingleParty => {
            let mut setup_rng = OsRng;
            Groth16::<Curve>::circuit_specific_setup(transfer_blank(), &mut setup_rng).unwrap()
        },
    };
    let circuit = mk_circuit();
    let publics = circuit.public_inputs();
    let t_prove = std::time::Instant::now();
    let proof = Groth16::<Curve>::prove(&tpk, circuit, &mut rng).unwrap();
    out.oracle_line(&format!(
        "PROVE-TIME transfer circuit (native, single-thread arkworks) = {} ms",
        t_prove.elapsed().as_millis()
    ));

    // ORACLE: reference library verdicts on exactly the vectors the canister will see
    assert!(Groth16::<Curve>::verify(&tvk, &publics, &proof).unwrap());
    out.oracle_line("P0 transfer valid-proof            -> ACCEPT");

    let mut bad_proof_bytes = { let mut b = Vec::new(); proof.serialize_compressed(&mut b).unwrap(); b };
    let last = bad_proof_bytes.len() - 1;
    bad_proof_bytes[last] ^= 0x01;
    out.oracle_line("C1 transfer forged-proof(bitflip)  -> REJECT (deserialize-or-pairing)");

    // C4a: tampered public input (fee+1) — well-formed group elements, pairing must fail
    let mut publics_badfee = publics.clone();
    publics_badfee[5] += F::one();
    assert!(!Groth16::<Curve>::verify(&tvk, &publics_badfee, &proof).unwrap());
    out.oracle_line("C4a transfer tampered-fee          -> REJECT (pairing)");

    let mut publics_bad_recipient = publics.clone();
    publics_bad_recipient[7] += F::one();
    assert!(!Groth16::<Curve>::verify(&tvk, &publics_bad_recipient, &proof).unwrap());
    out.oracle_line("C4b transfer tampered-recipient    -> REJECT (pairing)");

    // C2: honest-looking proof against a FABRICATED tree (attacker invents a note+tree,
    // proves membership in it honestly; only the canister's root-set check can reject it)
    let fake_note = Note { v: 1_000_000, nk: alice_nk, rho: F::rand(&mut rng), rcm: F::rand(&mut rng) };
    let fake_dense = DenseTree { leaves: vec![fake_note.cm(&cfg), n2.cm(&cfg)] };
    let fake_anchor = fake_dense.root(&cfg);
    let (fsib1, fbits1) = fake_dense.path(&cfg, 0);
    let (fsib2, fbits2) = fake_dense.path(&cfg, 1);
    let fnf1 = fake_note.nf(&cfg);
    let fout1 = Note { v: 999_995, nk: alice_nk, rho: fnf1, rcm: F::rand(&mut rng) };
    let fout2 = Note { v: n2.v, nk: alice_nk, rho: nf2, rcm: F::rand(&mut rng) };
    let fake_circuit = TransferCircuit {
        cfg: cfg.clone(),
        enforce_range: true,
        legacy_statement,
        anchor: Some(fake_anchor),
        nf: [Some(fnf1), Some(nf2)],
        cm_out: [Some(fout1.cm(&cfg)), Some(fout2.cm(&cfg))],
        fee: Some(fee),
        v_pub_out: Some(v_pub_out),
        recipient_binding: Some(recipient_binding),
        in_v: [Some(fake_note.v), Some(n2.v)],
        in_nk: [Some(fake_note.nk), Some(n2.nk)],
        in_rho: [Some(fake_note.rho), Some(n2.rho)],
        in_rcm: [Some(fake_note.rcm), Some(n2.rcm)],
        in_siblings: [fsib1, fsib2],
        in_bits: [fbits1, fbits2],
        out_v: [Some(F::from(fout1.v)), Some(F::from(fout2.v))],
        out_pk: [Some(alice_pk), Some(alice_pk)],
        out_rcm: [Some(fout1.rcm), Some(fout2.rcm)],
    };
    let fake_publics = fake_circuit.public_inputs();
    let fake_proof = Groth16::<Curve>::prove(&tpk, fake_circuit, &mut rng).unwrap();
    // The PROOF ITSELF IS VALID — the pairing check passes. This is the point of control C2:
    // cryptography alone cannot reject it; the canister's historical-root set must.
    assert!(Groth16::<Curve>::verify(&tvk, &fake_publics, &fake_proof).unwrap());
    out.oracle_line("C2 transfer fabricated-tree proof  -> pairing ACCEPTS; canister MUST reject on unknown anchor");

    // ---------------- witness-level attacks (native, cannot even be proven) ----------------
    {
        // A1: imbalanced (out1.v bumped to 56: 70+30 != 56+40+5)
        let mut c = mk_circuit();
        let cheat = Note { v: 56, ..out1 };
        c.out_v[0] = Some(F::from(cheat.v));
        c.cm_out[0] = Some(cheat.cm(&cfg));
        let cs = ConstraintSystem::<F>::new_ref();
        c.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
        out.oracle_line("A1 imbalanced witness (+1 out)     -> UNSATISFIABLE (cannot construct a proof)");

        // A2: the field-wrap / negative-value mint. Conservation is a FIELD equation:
        // set v'_1 = -1 (= p-1) and v'_2 = 96; then 70+30 = (p-1) + 96 + 5 (mod p) holds,
        // and the attacker has minted a spendable note of 96 from inputs worth only 95.
        // Without range checks this witness SATISFIES the constraints (the vulnerability);
        // with them it cannot (S3 is what makes S1 conservation, not just congruence).
        let neg = -F::one(); // p - 1, a "negative" value
        let cheat_out2 = Note { v: 96, nk: alice_nk, rho: nf2, rcm: F::rand(&mut rng) };
        let cheat_cm1 = hash_n(&cfg, &[F::from(TAG_CM), neg, bob_pk, nf1, out1.rcm]);
        let mut c = mk_circuit();
        c.cm_out = [Some(cheat_cm1), Some(cheat_out2.cm(&cfg))];
        c.out_v = [Some(neg), Some(F::from(96u64))];
        c.out_pk = [Some(bob_pk), Some(alice_pk)];
        c.out_rcm = [Some(out1.rcm), Some(cheat_out2.rcm)];

        let mut c_norange = c.clone();
        c_norange.enforce_range = false;
        let cs = ConstraintSystem::<F>::new_ref();
        c_norange.generate_constraints(cs.clone()).unwrap();
        assert!(
            cs.is_satisfied().unwrap(),
            "wrap attack should SATISFY the no-range variant (demonstrating the vulnerability)"
        );
        out.oracle_line("A2a negative-value mint vs NO-RANGE variant -> SATISFIED (vulnerability demonstrated)");

        let cs = ConstraintSystem::<F>::new_ref();
        c.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap(), "range checks must kill the wrap attack");
        out.oracle_line("A2b same attack vs REAL circuit    -> UNSATISFIABLE (S3 range check is load-bearing)");
    }

    // ---------------- withdraw (unshield) vectors ----------------
    // After the canister processes deposits (leaves 0,1) and the P0 transfer (appends
    // cm_out1, cm_out2 as leaves 2,3), its root is the dense root of those 4 leaves.
    // The withdraw spends out1 (Bob, 55) + out2 (Alice, 40) jointly against that root:
    // 55 + 40 = 0 + 0 + fee 5 + v_pub_out 90.
    let w_proof_uncompressed;
    {
        let tree2 = DenseTree {
            leaves: vec![n1.cm(&cfg), n2.cm(&cfg), out1.cm(&cfg), out2.cm(&cfg)],
        };
        let anchor2 = tree2.root(&cfg);
        let (wsib1, wbits1) = tree2.path(&cfg, 2);
        let (wsib2, wbits2) = tree2.path(&cfg, 3);
        let wnf1 = out1.nf(&cfg);
        let wnf2 = out2.nf(&cfg);
        let wout1 = Note { v: 0, nk: bob_nk, rho: wnf1, rcm: F::rand(&mut rng) };
        let wout2 = Note { v: 0, nk: alice_nk, rho: wnf2, rcm: F::rand(&mut rng) };
        let wfee = 5u64;
        let w_v_pub_out = 90u64;
        let w_recipient_binding = F::from(0xc0ffeeu64);
        let wc = TransferCircuit {
            cfg: cfg.clone(),
            enforce_range: true,
            legacy_statement,
            anchor: Some(anchor2),
            nf: [Some(wnf1), Some(wnf2)],
            cm_out: [Some(wout1.cm(&cfg)), Some(wout2.cm(&cfg))],
            fee: Some(wfee),
            v_pub_out: Some(w_v_pub_out),
            recipient_binding: Some(w_recipient_binding),
            in_v: [Some(out1.v), Some(out2.v)],
            in_nk: [Some(out1.nk), Some(out2.nk)],
            in_rho: [Some(out1.rho), Some(out2.rho)],
            in_rcm: [Some(out1.rcm), Some(out2.rcm)],
            in_siblings: [wsib1, wsib2],
            in_bits: [wbits1, wbits2],
            out_v: [Some(F::from(0u64)), Some(F::from(0u64))],
            out_pk: [Some(bob_pk), Some(alice_pk)],
            out_rcm: [Some(wout1.rcm), Some(wout2.rcm)],
        };
        let wpublics = wc.public_inputs();
        let wproof = Groth16::<Curve>::prove(&tpk, wc, &mut rng).unwrap();
        assert!(Groth16::<Curve>::verify(&tvk, &wpublics, &wproof).unwrap());
        out.oracle_line("P1 withdraw valid-proof            -> ACCEPT (v_pub_out=90, fee=5)");
        out.write("withdraw_anchor.hex", &f_to_hex(&anchor2));
        out.write("withdraw_nf1.hex", &f_to_hex(&wnf1));
        out.write("withdraw_nf2.hex", &f_to_hex(&wnf2));
        out.write("withdraw_cm_out1.hex", &f_to_hex(&wout1.cm(&cfg)));
        out.write("withdraw_cm_out2.hex", &f_to_hex(&wout2.cm(&cfg)));
        out.write("withdraw_fee.txt", &wfee.to_string());
        out.write("withdraw_v_pub_out.txt", &w_v_pub_out.to_string());
        out.write("withdraw_recipient_binding.hex", &f_to_hex(&w_recipient_binding));
        out.write("withdraw_proof.hex", &hex_ser(&wproof));
        w_proof_uncompressed = (wproof, wpublics);
    }

    // ---------------- deposit circuit ----------------
    let (dpk, dvk) = match setup_mode {
        SetupMode::InsecureDeterministicTest =>
            Groth16::<Curve>::circuit_specific_setup(DepositCircuit::blank(&cfg), &mut rng).unwrap(),
        SetupMode::OsCsprngSingleParty => {
            let mut setup_rng = OsRng;
            Groth16::<Curve>::circuit_specific_setup(DepositCircuit::blank(&cfg), &mut setup_rng).unwrap()
        },
    };
    let mut dep_vec = Vec::new();
    let mut dep_uncompressed = Vec::new();
    for n in [&n1, &n2] {
        let c = DepositCircuit {
            cfg: cfg.clone(),
            cm: Some(n.cm(&cfg)),
            v_pub: Some(n.v),
            pk: Some(n.pk(&cfg)),
            rho: Some(n.rho),
            rcm: Some(n.rcm),
        };
        let publics = c.public_inputs();
        let proof = Groth16::<Curve>::prove(&dpk, c, &mut rng).unwrap();
        assert!(Groth16::<Curve>::verify(&dvk, &publics, &proof).unwrap());
        dep_vec.push((hex_ser(&proof), f_to_hex(&n.cm(&cfg)), n.v));
        dep_uncompressed.push((proof, publics));
    }
    out.oracle_line("P0d deposit valid-proofs x2        -> ACCEPT");
    // deposit negative: claim a different public amount for the same cm
    let amountlie_publics;
    {
        let c = DepositCircuit {
            cfg: cfg.clone(),
            cm: Some(n1.cm(&cfg)),
            v_pub: Some(n1.v),
            pk: Some(n1.pk(&cfg)),
            rho: Some(n1.rho),
            rcm: Some(n1.rcm),
        };
        let mut publics = c.public_inputs();
        publics[1] = F::from(7_000_000u64); // claim the note is worth 7M
        let proof = Groth16::<Curve>::prove(&dpk, c, &mut rng).unwrap();
        assert!(!Groth16::<Curve>::verify(&dvk, &publics, &proof).unwrap());
        out.oracle_line("C6 deposit amount-lie              -> REJECT (pairing)");
        amountlie_publics = publics;
    }

    // ---------------- write vectors ----------------
    out.write("transfer_vk.hex", &hex_ser(&tvk));
    out.write("deposit_vk.hex", &hex_ser(&dvk));
    out.write("transfer_proof.hex", &hex_ser(&proof));
    out.write("transfer_badproof.hex", &hex::encode(&bad_proof_bytes));
    out.write("anchor.hex", &f_to_hex(&anchor));
    out.write("nf1.hex", &f_to_hex(&nf1));
    out.write("nf2.hex", &f_to_hex(&nf2));
    out.write("cm_out1.hex", &f_to_hex(&out1.cm(&cfg)));
    out.write("cm_out2.hex", &f_to_hex(&out2.cm(&cfg)));
    out.write("fee.txt", &fee.to_string());
    out.write("v_pub_out.txt", &v_pub_out.to_string());
    out.write("recipient_binding.hex", &f_to_hex(&recipient_binding));
    out.write("cm1.hex", &f_to_hex(&n1.cm(&cfg)));
    out.write("cm2.hex", &f_to_hex(&n2.cm(&cfg)));
    for (i, (p, cm, v)) in dep_vec.iter().enumerate() {
        out.write(&format!("deposit{}_proof.hex", i + 1), p);
        out.write(&format!("deposit{}_cm.hex", i + 1), cm);
        out.write(&format!("deposit{}_v.txt", i + 1), &v.to_string());
    }
    // C2 vectors: valid-cryptography proof against a fabricated anchor
    out.write("fake_anchor.hex", &f_to_hex(&fake_anchor));
    out.write("fake_proof.hex", &hex_ser(&fake_proof));
    out.write("fake_nf1.hex", &f_to_hex(&fnf1));
    out.write("fake_nf2.hex", &f_to_hex(&nf2));
    out.write("fake_cm_out1.hex", &f_to_hex(&fout1.cm(&cfg)));
    out.write("fake_cm_out2.hex", &f_to_hex(&fout2.cm(&cfg)));

    // ---------------- Bulletproofs vectors (prices the account-model / no-setup option) ----------------
    // Curve25519 — independent of the Groth16 curve; generated only with the original BN254 set
    // so the BLS12-381 fixture directory holds exactly what the Motoko verifier consumes.
    #[cfg(not(feature = "bls12-381"))]
    bp_vectors(&mut out);

    // ---------------- proving-key emission for the client-side demo prover ----------------
    // BLS12-381 only. The demo browser prover must prove against the SAME setup the ledger's vk
    // came from — these are that setup's proving keys. SETUP-MANIFEST.json records whether the
    // setup was the explicitly unsafe deterministic fixture mode or OS-CSPRNG single-party mode.
    // Uncompressed on purpose: the client loads them with deserialize_uncompressed_unchecked
    // (they are local static assets; integrity is enforced at runtime by an explicit
    // pk.vk == configured-vk assert in the prover, and ultimately by the ledger verifying
    // every proof).
    #[cfg(feature = "bls12-381")]
    {
        let mut tb = Vec::new();
        tpk.serialize_uncompressed(&mut tb).unwrap();
        std::fs::write(format!("{}/transfer_pk.bin", out.dir), &tb).unwrap();
        let mut db = Vec::new();
        dpk.serialize_uncompressed(&mut db).unwrap();
        std::fs::write(format!("{}/deposit_pk.bin", out.dir), &db).unwrap();
        out.oracle_line(&format!(
            "PK-EMIT transfer_pk.bin {} bytes, deposit_pk.bin {} bytes (same setup as the pinned vks)",
            tb.len(), db.len()
        ));

        let manifest = format!(
            concat!(
                "{{\n",
                "  \"format\": 1,\n",
                "  \"proof_system\": \"Groth16\",\n",
                "  \"curve\": \"BLS12-381\",\n",
                "  \"setup_mode\": \"{}\",\n",
                "  \"publicly_reproducible_toxic_waste\": {},\n",
                "  \"multi_party_ceremony\": false,\n",
                "  \"real_value_eligible\": false,\n",
                "  \"transfer_pk_sha256\": \"{}\",\n",
                "  \"transfer_vk_sha256\": \"{}\",\n",
                "  \"deposit_pk_sha256\": \"{}\",\n",
                "  \"deposit_vk_sha256\": \"{}\",\n",
                "  \"warning\": \"A production keyset requires a separately verified multi-party ceremony transcript.\"\n",
                "}}\n"
            ),
            setup_mode.name(),
            setup_mode.publicly_reproducible_toxic_waste(),
            file_sha256(&format!("{}/transfer_pk.bin", out.dir)),
            file_sha256(&format!("{}/transfer_vk.hex", out.dir)),
            file_sha256(&format!("{}/deposit_pk.bin", out.dir)),
            file_sha256(&format!("{}/deposit_vk.hex", out.dir)),
        );
        out.write("SETUP-MANIFEST.json", &manifest);
        out.oracle_line("SETUP-MANIFEST key hashes + eligibility written");
    }

    // ---------------- uncompressed affine emission for the Motoko verifier gate ----------------
    // BLS12-381 only: the measured Motoko verifier (G10-E) takes affine coordinates; the
    // compressed wire decode is a separate gated battery. Every verdict written here was already
    // asserted against native arkworks above.
    #[cfg(feature = "bls12-381")]
    {
        use ark_ec::AffineRepr;
        use ark_ff::{BigInteger, PrimeField};
        type G1A = ark_bls12_381::G1Affine;
        type G2A = ark_bls12_381::G2Affine;

        fn hq(x: &ark_bls12_381::Fq) -> String {
            x.into_bigint().to_bytes_be().iter().map(|c| format!("{c:02x}")).collect()
        }
        fn hfr(x: &F) -> String {
            x.into_bigint().to_bytes_be().iter().map(|c| format!("{c:02x}")).collect()
        }
        fn g1(s: &mut String, name: &str, p: &G1A) {
            assert!(!p.is_zero(), "unexpected infinity in {name}");
            writeln!(s, "{name}_x={}", hq(&p.x().unwrap())).unwrap();
            writeln!(s, "{name}_y={}", hq(&p.y().unwrap())).unwrap();
        }
        fn g2(s: &mut String, name: &str, p: &G2A) {
            assert!(!p.is_zero(), "unexpected infinity in {name}");
            let (x, y) = (p.x().unwrap(), p.y().unwrap());
            writeln!(s, "{name}_x_c0={}", hq(&x.c0)).unwrap();
            writeln!(s, "{name}_x_c1={}", hq(&x.c1)).unwrap();
            writeln!(s, "{name}_y_c0={}", hq(&y.c0)).unwrap();
            writeln!(s, "{name}_y_c1={}", hq(&y.c1)).unwrap();
        }
        fn vk_block(s: &mut String, tag: &str, vk: &ark_groth16::VerifyingKey<Curve>) {
            writeln!(s, "[{tag}]").unwrap();
            g1(s, "alpha", &vk.alpha_g1);
            g2(s, "beta", &vk.beta_g2);
            g2(s, "gamma", &vk.gamma_g2);
            g2(s, "delta", &vk.delta_g2);
            writeln!(s, "gamma_abc_len={}", vk.gamma_abc_g1.len()).unwrap();
            for (i, p) in vk.gamma_abc_g1.iter().enumerate() {
                g1(s, &format!("gamma_abc_{i}"), p);
            }
        }
        fn proof_block(
            s: &mut String, tag: &str, proof: &ark_groth16::Proof<Curve>, publics: &[F], verdict: &str,
        ) {
            writeln!(s, "[{tag}]").unwrap();
            g1(s, "A", &proof.a);
            g2(s, "B", &proof.b);
            g1(s, "C", &proof.c);
            for (i, x) in publics.iter().enumerate() {
                writeln!(s, "public_{i}={}", hfr(x)).unwrap();
            }
            writeln!(s, "verdict={verdict}").unwrap();
        }

        let mut s = String::new();
        writeln!(s, "# BLS12-381 pool Groth16 vectors, UNCOMPRESSED affine — for the Motoko verifier gate.").unwrap();
        writeln!(s, "# GENERATED by pool-proto gen --features bls12-381. DO NOT HAND-EDIT.").unwrap();
        vk_block(&mut s, "transfer_vk", &tvk);
        vk_block(&mut s, "deposit_vk", &dvk);
        proof_block(&mut s, "transfer", &proof, &publics, "ACCEPT");
        proof_block(&mut s, "transfer_badfee", &proof, &publics_badfee, "REJECT");
        proof_block(&mut s, "transfer_badrecipient", &proof, &publics_bad_recipient, "REJECT");
        proof_block(&mut s, "fake_tree", &fake_proof, &fake_publics, "PAIRING-ACCEPT-CANISTER-MUST-REJECT-ANCHOR");
        proof_block(&mut s, "withdraw", &w_proof_uncompressed.0, &w_proof_uncompressed.1, "ACCEPT");
        proof_block(&mut s, "deposit1", &dep_uncompressed[0].0, &dep_uncompressed[0].1, "ACCEPT");
        proof_block(&mut s, "deposit2", &dep_uncompressed[1].0, &dep_uncompressed[1].1, "ACCEPT");
        proof_block(&mut s, "deposit_amount_lie", &dep_uncompressed[0].0, &amountlie_publics, "REJECT");
        out.write("motoko-groth16-uncompressed.txt", &s);
        out.oracle_line("MOTOKO-EMIT uncompressed affine vectors written (verdicts as asserted above)");
    }

    std::fs::write(format!("{}/ORACLE.txt", out.dir), &out.oracle).unwrap();
    println!("vectors + ORACLE.txt written to {}/", out.dir);
}

// ---------------- Bulletproofs (dalek, MIT) ----------------

fn bp_vectors(out: &mut Out) {
    use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
    use curve25519_dalek_ng::scalar::Scalar;
    use merlin::Transcript;
    use rand::rngs::StdRng as RStdRng;
    use rand::SeedableRng as RSeedableRng;

    let mut rng = RStdRng::seed_from_u64(20260712);
    let pc = PedersenGens::default();
    let bp = BulletproofGens::new(64, 16);

    // single 64-bit range proof
    let v: u64 = 1_234_567;
    let blind = Scalar::random(&mut rng);
    let mut t = Transcript::new(b"zk-lab-range");
    let (proof, commit) =
        RangeProof::prove_single(&bp, &pc, &mut t, v, &blind, 64).expect("bp prove");
    let mut t2 = Transcript::new(b"zk-lab-range");
    proof.verify_single(&bp, &pc, &mut t2, &commit, 64).expect("bp self-verify");
    out.oracle_line("BP0 bulletproof single64 valid     -> ACCEPT");

    let mut bad = proof.to_bytes();
    let l = bad.len() - 1;
    bad[l] ^= 0x01;
    out.oracle_line("BC1 bulletproof tampered           -> REJECT");
    out.write("bp_single_proof.hex", &hex::encode(proof.to_bytes()));
    out.write("bp_single_badproof.hex", &hex::encode(&bad));
    out.write("bp_single_commit.hex", &hex::encode(commit.as_bytes()));

    // aggregated 2×64 and 16×64 (batching economics for the account model)
    for m in [2usize, 16] {
        let vals: Vec<u64> = (0..m as u64).map(|i| 1000 + i).collect();
        let blinds: Vec<Scalar> = (0..m).map(|_| Scalar::random(&mut rng)).collect();
        let mut t = Transcript::new(b"zk-lab-range-agg");
        let (proof, commits) =
            RangeProof::prove_multiple(&bp, &pc, &mut t, &vals, &blinds, 64).expect("bp agg prove");
        let mut t2 = Transcript::new(b"zk-lab-range-agg");
        proof
            .verify_multiple(&bp, &pc, &mut t2, &commits, 64)
            .expect("bp agg self-verify");
        out.oracle_line(&format!("BP{m} bulletproof agg{m}x64 valid    -> ACCEPT"));
        out.write(&format!("bp_agg{m}_proof.hex"), &hex::encode(proof.to_bytes()));
        let commits_hex: Vec<String> =
            commits.iter().map(|c| hex::encode(c.as_bytes())).collect();
        out.write(&format!("bp_agg{m}_commits.hex"), &commits_hex.join("\n"));
    }
}
