//! Shared infrastructure for the fortress PocketIC gates (§1 taxonomy, §6 metamorphic, and
//! the §9/§10 harness reuse): the ZCash wire encoding all three verifiers consume, the
//! arkworks and blst native verdicts, a valid-transfer generator, and the production Motoko
//! verifier harness on PocketIC (compile + install + call, with optional single-limb bug
//! injection for teeth). Test/oracle only — never linked into the shipped ledger.

use ark_bls12_381::{Bls12_381, Fq, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, RngCore, SeedableRng};
use common::{derive_pk, note_commitment, poseidon_config, DenseTree, Note, PoseidonCfg};
use pocket_ic::PocketIcBuilder;
use std::path::{Path, PathBuf};
use std::process::Command;

pub fn u64_le(bytes: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap())
}

pub fn ark_g1(bytes: &[u8]) -> Option<G1Affine> {
    if bytes.len() != 48 {
        return None;
    }
    G1Affine::deserialize_compressed(bytes).ok()
}
pub fn ark_g2(bytes: &[u8]) -> Option<G2Affine> {
    if bytes.len() != 96 {
        return None;
    }
    G2Affine::deserialize_compressed(bytes).ok()
}

/// arkworks verdict on the ZCash wire triple: true = ACCEPT.
pub fn ark_verdict(vk_bytes: &[u8], proof_bytes: &[u8], input_bytes: &[u8]) -> bool {
    if vk_bytes.len() < 344 {
        return false;
    }
    let alpha = match ark_g1(&vk_bytes[0..48]) { Some(p) => p, None => return false };
    let beta = match ark_g2(&vk_bytes[48..144]) { Some(p) => p, None => return false };
    let gamma = match ark_g2(&vk_bytes[144..240]) { Some(p) => p, None => return false };
    let delta = match ark_g2(&vk_bytes[240..336]) { Some(p) => p, None => return false };
    let len = u64_le(vk_bytes, 336) as usize;
    if len < 1 || len > 1024 || vk_bytes.len() != 344 + 48 * len {
        return false;
    }
    let mut ic = Vec::with_capacity(len);
    for i in 0..len {
        match ark_g1(&vk_bytes[344 + 48 * i..344 + 48 * (i + 1)]) {
            Some(p) => ic.push(p),
            None => return false,
        }
    }
    let vk = VerifyingKey::<Bls12_381> { alpha_g1: alpha, beta_g2: beta, gamma_g2: gamma, delta_g2: delta, gamma_abc_g1: ic };
    if proof_bytes.len() != 192 {
        return false;
    }
    let a = match ark_g1(&proof_bytes[0..48]) { Some(p) => p, None => return false };
    let b = match ark_g2(&proof_bytes[48..144]) { Some(p) => p, None => return false };
    let c = match ark_g1(&proof_bytes[144..192]) { Some(p) => p, None => return false };
    let proof = Proof::<Bls12_381> { a, b, c };
    if input_bytes.len() < 8 {
        return false;
    }
    let count = u64_le(input_bytes, 0) as usize;
    if input_bytes.len() != 8 + 32 * count {
        return false;
    }
    let mut inputs = Vec::with_capacity(count);
    for i in 0..count {
        match Fr::deserialize_compressed(&input_bytes[8 + 32 * i..8 + 32 * (i + 1)]) {
            Ok(f) => inputs.push(f),
            Err(_) => return false,
        }
    }
    Groth16::<Bls12_381>::verify(&vk, &inputs, &proof).unwrap_or(false)
}

/// blst verdict on the wire triple: true = ACCEPT.
pub fn blst_verdict(vk_bytes: &[u8], proof_bytes: &[u8], input_bytes: &[u8]) -> bool {
    let vk = match cross_oracle::parse_vk(vk_bytes) { Ok(v) => v, Err(_) => return false };
    if input_bytes.len() < 8 {
        return false;
    }
    let count = u64_le(input_bytes, 0) as usize;
    if input_bytes.len() != 8 + 32 * count {
        return false;
    }
    let refs: Vec<&[u8]> = (0..count).map(|i| &input_bytes[8 + 32 * i..8 + 32 * (i + 1)]).collect();
    cross_oracle::verify(&vk, proof_bytes, &refs) == cross_oracle::Verdict::Accept
}

// ---- ark -> wire ----

pub fn compress_g1(p: &G1Affine) -> [u8; 48] {
    let mut out = [0u8; 48];
    if p.is_zero() {
        out[0] = 0xc0;
        return out;
    }
    let x: num_bigint::BigUint = p.x().unwrap().into_bigint().into();
    let xb = x.to_bytes_be();
    out[48 - xb.len()..].copy_from_slice(&xb);
    out[0] |= 0x80;
    let y: num_bigint::BigUint = p.y().unwrap().into_bigint().into();
    let pm: num_bigint::BigUint = Fq::MODULUS.into();
    if y > (&pm - 1u8) / 2u8 {
        out[0] |= 0x20;
    }
    out
}

pub fn compress_g2(p: &G2Affine) -> [u8; 96] {
    let mut out = [0u8; 96];
    if p.is_zero() {
        out[0] = 0xc0;
        return out;
    }
    let x = p.x().unwrap();
    let c1: num_bigint::BigUint = x.c1.into_bigint().into();
    let c0: num_bigint::BigUint = x.c0.into_bigint().into();
    let c1b = c1.to_bytes_be();
    let c0b = c0.to_bytes_be();
    out[48 - c1b.len()..48].copy_from_slice(&c1b);
    out[96 - c0b.len()..].copy_from_slice(&c0b);
    out[0] |= 0x80;
    let y = p.y().unwrap();
    let neg = -y;
    let larger = {
        let (a1, b1): (num_bigint::BigUint, num_bigint::BigUint) = (y.c1.into_bigint().into(), neg.c1.into_bigint().into());
        if a1 != b1 { a1 > b1 } else {
            let (a0, b0): (num_bigint::BigUint, num_bigint::BigUint) = (y.c0.into_bigint().into(), neg.c0.into_bigint().into());
            a0 > b0
        }
    };
    if larger {
        out[0] |= 0x20;
    }
    out
}

pub fn fr_le(f: &Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    let b = f.into_bigint().to_bytes_le();
    out[..b.len().min(32)].copy_from_slice(&b[..b.len().min(32)]);
    out
}

pub fn vk_to_wire(vk: &VerifyingKey<Bls12_381>) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&compress_g1(&vk.alpha_g1));
    b.extend_from_slice(&compress_g2(&vk.beta_g2));
    b.extend_from_slice(&compress_g2(&vk.gamma_g2));
    b.extend_from_slice(&compress_g2(&vk.delta_g2));
    b.extend_from_slice(&(vk.gamma_abc_g1.len() as u64).to_le_bytes());
    for p in &vk.gamma_abc_g1 {
        b.extend_from_slice(&compress_g1(p));
    }
    b
}

pub fn proof_to_wire(proof: &Proof<Bls12_381>) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&compress_g1(&proof.a));
    b.extend_from_slice(&compress_g2(&proof.b));
    b.extend_from_slice(&compress_g1(&proof.c));
    b
}

pub fn inputs_to_wire(inputs: &[Fr]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&(inputs.len() as u64).to_le_bytes());
    for f in inputs {
        b.extend_from_slice(&fr_le(f));
    }
    b
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ---- valid-transfer generation ----

/// A prepared valid transfer: proving key, verifying key, circuit, proof, public inputs.
pub struct ValidTransfer {
    pub pk: ProvingKey<Bls12_381>,
    pub vk: VerifyingKey<Bls12_381>,
    pub circuit: common::TransferCircuit,
    pub proof: Proof<Bls12_381>,
    pub public: Vec<Fr>,
}

pub fn build_transfer(rng: &mut StdRng, cfg: &PoseidonCfg<Fr>) -> common::TransferCircuit {
    let owner_nk = Fr::rand(rng);
    let recipient_nk = Fr::rand(rng);
    let in_v = [90_000u64 + rng.next_u64() % 500_000, 40_000 + rng.next_u64() % 500_000];
    let inputs = [
        Note { v: in_v[0], nk: owner_nk, rho: Fr::rand(rng), rcm: Fr::rand(rng) },
        Note { v: in_v[1], nk: owner_nk, rho: Fr::rand(rng), rcm: Fr::rand(rng) },
    ];
    let mut filler = |rng: &mut StdRng| Note { v: 1, nk: Fr::rand(rng), rho: Fr::rand(rng), rcm: Fr::rand(rng) };
    let leaves = vec![
        filler(rng).cm(cfg), inputs[0].cm(cfg), filler(rng).cm(cfg),
        filler(rng).cm(cfg), inputs[1].cm(cfg), filler(rng).cm(cfg),
    ];
    let tree = DenseTree { leaves };
    let anchor = tree.root(cfg);
    let (sib0, bits0) = tree.path(cfg, 1);
    let (sib1, bits1) = tree.path(cfg, 4);
    let nf = [inputs[0].nf(cfg), inputs[1].nf(cfg)];
    let out_pk = [derive_pk(cfg, recipient_nk), derive_pk(cfg, owner_nk)];
    let out_rcm = [Fr::rand(rng), Fr::rand(rng)];
    let total = in_v[0] + in_v[1];
    let fee = rng.next_u64() % (total / 8 + 1);
    let v_pub_out = rng.next_u64() % ((total - fee) / 3 + 1);
    let rem = total - fee - v_pub_out;
    let o0 = rng.next_u64() % (rem + 1);
    let out_v = [o0, rem - o0];
    let cm_out = [
        note_commitment(cfg, out_v[0], out_pk[0], nf[0], out_rcm[0]),
        note_commitment(cfg, out_v[1], out_pk[1], nf[1], out_rcm[1]),
    ];
    common::TransferCircuit {
        cfg: cfg.clone(),
        enforce_range: true,
        anchor: Some(anchor),
        nf: [Some(nf[0]), Some(nf[1])],
        cm_out: [Some(cm_out[0]), Some(cm_out[1])],
        fee: Some(fee),
        v_pub_out: Some(v_pub_out),
        recipient_binding: Some(Fr::rand(rng)),
        in_v: [Some(in_v[0]), Some(in_v[1])],
        in_nk: [Some(inputs[0].nk), Some(inputs[1].nk)],
        in_rho: [Some(inputs[0].rho), Some(inputs[1].rho)],
        in_rcm: [Some(inputs[0].rcm), Some(inputs[1].rcm)],
        in_siblings: [sib0, sib1],
        in_bits: [bits0, bits1],
        out_v: [Some(Fr::from(out_v[0])), Some(Fr::from(out_v[1]))],
        out_pk: [Some(out_pk[0]), Some(out_pk[1])],
        out_rcm: [Some(out_rcm[0]), Some(out_rcm[1])],
    }
}

/// One deterministic proving/verifying key for the transfer circuit (seed 0xc3), reused
/// across cases so re-proofs share the vk (§6 needs pk to re-randomize proofs).
pub fn transfer_keys() -> (ProvingKey<Bls12_381>, VerifyingKey<Bls12_381>) {
    let cfg = poseidon_config();
    let mut setup_rng = StdRng::from_seed([0xc3; 32]);
    Groth16::<Bls12_381>::circuit_specific_setup(common::TransferCircuit::blank(&cfg), &mut setup_rng).unwrap()
}

pub fn valid_transfer(seed: [u8; 32]) -> ValidTransfer {
    let cfg = poseidon_config();
    let (pk, vk) = transfer_keys();
    let mut rng = StdRng::from_seed(seed);
    let circuit = build_transfer(&mut rng, &cfg);
    let public = circuit.public_inputs();
    let proof = Groth16::<Bls12_381>::prove(&pk, circuit.clone(), &mut rng).unwrap();
    assert!(Groth16::<Bls12_381>::verify(&vk, &public, &proof).unwrap(), "valid transfer must verify");
    ValidTransfer { pk, vk, circuit, proof, public }
}

/// A valid DEPOSIT (shield) proof + its vk/inputs — the shield verify op class. Different
/// deposit secrets (pk/rho/rcm/value) give the same public shape (cm, v_pub) with different
/// values, so §10 can measure the shield-verify instruction class the same way as transfers.
pub fn valid_deposit(seed: [u8; 32]) -> ValidTransfer2 {
    let cfg = poseidon_config();
    let mut setup_rng = StdRng::from_seed([0xd0; 32]);
    let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(common::DepositCircuit::blank(&cfg), &mut setup_rng).unwrap();
    let mut rng = StdRng::from_seed(seed);
    let value = 1 + rng.next_u64() % 1_000_000;
    let owner_pk = derive_pk(&cfg, Fr::rand(&mut rng));
    let rho = Fr::rand(&mut rng);
    let rcm = Fr::rand(&mut rng);
    let cm = note_commitment(&cfg, value, owner_pk, rho, rcm);
    let circuit = common::DepositCircuit { cfg: cfg.clone(), cm: Some(cm), v_pub: Some(value), pk: Some(owner_pk), rho: Some(rho), rcm: Some(rcm) };
    let public = circuit.public_inputs();
    let proof = Groth16::<Bls12_381>::prove(&pk, circuit, &mut rng).unwrap();
    assert!(Groth16::<Bls12_381>::verify(&vk, &public, &proof).unwrap(), "valid deposit must verify");
    ValidTransfer2 { vk, proof, public }
}

/// Minimal (vk, proof, public) triple — deposit has no proving key reuse need in §10.
pub struct ValidTransfer2 {
    pub vk: VerifyingKey<Bls12_381>,
    pub proof: Proof<Bls12_381>,
    pub public: Vec<Fr>,
}

/// A second, unrelated valid vk (independent setup) — the "wrong vk" case.
pub fn wrong_vk() -> VerifyingKey<Bls12_381> {
    let cfg = poseidon_config();
    let mut setup_rng = StdRng::from_seed([0x77; 32]);
    let (_pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(common::TransferCircuit::blank(&cfg), &mut setup_rng).unwrap();
    vk
}

// ---- PocketIC production-verifier harness ----

/// Compile the harness canister. `mutate = Some((module, from, to))` plants a single-limb bug
/// in a STAGED copy of the production groth16 modules (the shipped tree is never touched).
pub fn build_harness_wasm(repo_root: &Path, mutate: Option<(&str, &str, &str)>) -> Vec<u8> {
    let stage = std::env::temp_dir().join(format!("fortress_harness_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&stage);
    std::fs::create_dir_all(stage.join("groth16")).unwrap();
    for entry in std::fs::read_dir(repo_root.join("src/groth16")).unwrap() {
        let p = entry.unwrap().path();
        if p.extension().map(|e| e == "mo").unwrap_or(false) {
            std::fs::copy(&p, stage.join("groth16").join(p.file_name().unwrap())).unwrap();
        }
    }
    std::fs::copy(repo_root.join("fortress/harness/Verifier.mo"), stage.join("Verifier.mo")).unwrap();
    if let Some((rel_path, from, to)) = mutate {
        // rel_path is stage-relative, e.g. "groth16/FpMont.mo" or "Verifier.mo".
        let mp = stage.join(rel_path);
        let src = std::fs::read_to_string(&mp).unwrap();
        let mutated = src.replacen(from, to, 1);
        assert_ne!(src, mutated, "planted mutation did not change {rel_path}");
        std::fs::write(&mp, mutated).unwrap();
    }
    let moc = std::env::var("SOAK_MOC").unwrap_or_else(|_| "/opt/moc-1.4.1/moc".into());
    let sources = String::from_utf8(Command::new("mops").arg("sources").current_dir(repo_root).output().unwrap().stdout).unwrap();
    let src_args: Vec<String> = sources.split_whitespace().map(String::from).collect();
    let out = stage.join("verifier.wasm");
    let status = Command::new(&moc).args(&src_args).arg("-c").arg(stage.join("Verifier.mo")).arg("-o").arg(&out).current_dir(repo_root).status().unwrap();
    assert!(status.success(), "harness moc compile failed");
    let wasm = std::fs::read(&out).unwrap();
    let _ = std::fs::remove_dir_all(&stage);
    wasm
}

pub struct Harness {
    pub server: crate::pic_env::ManagedServer,
    pub pic: pocket_ic::PocketIc,
    pub canister: candid::Principal,
}

impl Harness {
    pub fn new(wasm: &[u8]) -> Self {
        let server_bin = crate::pic_env::resolve_pocket_ic_server();
        let server = crate::pic_env::spawn_server(&server_bin);
        let pic = PocketIcBuilder::new().with_server_url(server.url.clone()).with_application_subnet().build();
        let canister = pic.create_canister();
        pic.add_cycles(canister, 100_000_000_000_000);
        pic.install_canister(canister, wasm.to_vec(), candid::encode_args(()).unwrap(), None);
        Harness { server, pic, canister }
    }

    pub fn reinstall(&self, wasm: &[u8]) {
        self.pic.reinstall_canister(self.canister, wasm.to_vec(), candid::encode_args(()).unwrap(), None).expect("reinstall harness");
    }

    /// Motoko verdict: true = ACCEPT.
    pub fn verdict(&self, vk: &[u8], proof: &[u8], inputs: &[u8]) -> bool {
        let args = candid::encode_args((hex(vk), hex(proof), hex(inputs))).unwrap();
        let raw = self.pic.update_call(self.canister, candid::Principal::anonymous(), "verify_oneshot", args).expect("verify_oneshot call");
        let verdict: String = candid::decode_one(&raw).expect("decode verdict");
        verdict == "ACCEPT"
    }

    /// §10: production verify plus the instructions it consumed. (verdict==ACCEPT, count).
    pub fn verdict_counted(&self, vk: &[u8], proof: &[u8], inputs: &[u8]) -> (bool, u64) {
        let args = candid::encode_args((hex(vk), hex(proof), hex(inputs))).unwrap();
        let raw = self.pic.update_call(self.canister, candid::Principal::anonymous(), "verify_counted", args).expect("verify_counted call");
        let (verdict, count): (String, u64) = candid::decode_args(&raw).expect("decode counted verdict");
        (verdict == "ACCEPT", count)
    }
}

/// Clean teardown: PocketIC's instance-delete on Drop is flaky (IncompleteMessage) and can
/// panic AFTER a gate has passed. Skip the pic Drop and kill the server child explicitly.
pub fn shutdown(h: Harness) {
    let Harness { server, pic, .. } = h;
    std::mem::forget(pic);
    drop(server);
}

pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}
