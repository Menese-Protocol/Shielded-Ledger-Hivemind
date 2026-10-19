//! Verifying-key freeze battery — teeth-first, on PocketIC.
//!
//! Until frozen, the administrator can replace the verifying keys (rotate_verifying_keys_v2),
//! and keys of the administrator's choosing would accept forged proofs. freeze_verifying_keys is
//! a one-way latch: after it, rotation is refused for good, the anchor as it stood at the freeze
//! is certified under "vk_frozen", and the keys can change only through a code upgrade by the
//! controller. Proven against the REAL ledger wasm with real proofs.
//!
//! Checks:
//!   F1 off by default: not frozen, no vk_frozen leaf in the certified tree, rotation works
//!   F2 authority: a non-administrator cannot freeze; a wrong expected anchor is refused; neither
//!      leaves the keys frozen
//!   F3 freeze: the administrator freezes the exact current anchor; rotation is then refused with
//!      keys and epoch unchanged; a second freeze is refused; honest transfers still go through
//!   F4 certified: right after the freeze, the certificate (verified against the PocketIC root key)
//!      carries zk/vk_frozen equal to the anchor and to zk/vk
//!   F5 upgrade: the freeze survives an upgrade; rotation is still refused; the leaf is still
//!      certified; the ledger is not guarded (its post-upgrade self-check passed)
//!
//! RED expectations (each a patched copy of src/Main.mo; the shipped tree is never modified):
//!   A rotation ignores the freeze ⇒ F3, F5   B freeze not admin-gated ⇒ F2
//!   C expected anchor ignored ⇒ F2           D latch transient ⇒ F5
//!   E frozen leaf not certified ⇒ F4         F freeze does not refresh the certificate ⇒ F4

use ark_ff::UniformRand;
use candid::Principal;
use ic_cbor::{CertificateToCbor, HashTreeToCbor};
use ic_certificate_verification::VerifyCertificate;
use ic_certification::{Certificate, HashTree, LookupResult};
use soak::candid_types as ct;
use soak::crypto::f_bytes;
use soak::model::AccountKeys;
use soak::{keys, pic_env, prover};
use std::path::{Path, PathBuf};

type F = common::ScalarField;

const FUND: u128 = 2_000_000_000;
const NOTE: u64 = 100_000_000;
const SEED: u64 = 20261016;
const MAX_CERTIFICATE_OFFSET_NS: u128 = 300_000_000_000;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

#[derive(candid::CandidType, serde::Deserialize, Debug, Clone)]
struct VkAnchor {
    transfer_vk_hex: String,
    deposit_vk_hex: String,
    digest: serde_bytes::ByteBuf,
    epoch: u64,
    certified: bool,
    frozen: bool,
}

impl VkAnchor {
    /// The 40-byte certified `vk` leaf: digest ‖ epoch (8B BE).
    fn leaf(&self) -> Vec<u8> {
        let mut out = self.digest.to_vec();
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out
    }
}

struct NoteRec {
    acct: usize,
    v: u64,
    rho: F,
    rcm: F,
    spent: bool,
}

struct Harness {
    env: pic_env::Env,
    keyset: keys::Keyset,
    cfg: common::PoseidonCfg<F>,
    cfg_tree: common::TreeCfg,
    accounts: Vec<AccountKeys>,
    leaves: Vec<F>,
    notes: Vec<NoteRec>,
    op: u64,
}

impl Harness {
    fn new(wasms: &pic_env::BuiltWasms, keyset: keys::Keyset, tag: &str) -> Self {
        let cfg = common::poseidon_config();
        let accounts = soak::model::derive_accounts(SEED, 3, &cfg);
        let state_dir = std::env::temp_dir().join(format!("vk_freeze_battery_{}_{}", std::process::id(), tag));
        let _ = std::fs::remove_dir_all(&state_dir);
        std::fs::create_dir_all(&state_dir).unwrap();
        let env = pic_env::setup(wasms, &keyset.transfer_vk_hex, &keyset.deposit_vk_hex, &state_dir);
        let principals: Vec<Principal> = accounts.iter().map(|a| a.principal).collect();
        pic_env::fund_accounts(&env, &principals, FUND, FUND);
        Harness { env, keyset, cfg, cfg_tree: common::poseidon_config_tree(), accounts, leaves: Vec::new(), notes: Vec::new(), op: 0 }
    }

    fn admin(&self) -> Principal {
        self.env.admin
    }

    fn prepare_shield(&mut self, acct: usize, v: u64) -> (ct::DepositArgs, F, F) {
        self.op += 1;
        let mut prng = prover::op_rng(SEED, self.op, "vk-freeze-shield-plan");
        let rho = F::rand(&mut prng);
        let rcm = F::rand(&mut prng);
        let mut prepared =
            prover::prepare_shield(&self.cfg, &self.keyset.deposit_pk, &self.accounts[acct], v, rho, rcm, SEED, self.op);
        prepared.args.created_at_time = self.env.time_ns();
        (prepared.args, rho, rcm)
    }

    fn send_shield(&mut self, acct: usize, args: ct::DepositArgs) -> ct::MutationResult {
        self.env.update(self.env.ledger, self.accounts[acct].principal, "shield", (args,)).expect("shield call")
    }

    fn shield(&mut self, acct: usize, v: u64) -> ct::MutationResult {
        let (args, rho, rcm) = self.prepare_shield(acct, v);
        let m = self.send_shield(acct, args);
        if m.outcome == "ACCEPT" {
            self.leaves.push(common::note_commitment(&self.cfg, v, self.accounts[acct].pk, rho, rcm));
            self.notes.push(NoteRec { acct, v, rho, rcm, spent: false });
        }
        m
    }

    /// Two unspent notes of `acct`, shielding fresh ones as needed.
    fn two_notes(&mut self, acct: usize) -> (usize, usize) {
        let mut free: Vec<usize> = (0..self.notes.len()).filter(|&k| self.notes[k].acct == acct && !self.notes[k].spent).collect();
        while free.len() < 2 {
            let m = self.shield(acct, NOTE);
            assert_eq!(m.outcome, "ACCEPT", "shield for notes said {}", m.outcome);
            free.push(self.notes.len() - 1);
        }
        (free[0], free[1])
    }

    /// A private transfer from `acct` spending two of its notes, half to account 1, change back.
    fn prepare_transfer(&mut self, acct: usize) -> (prover::PreparedTransfer, usize, usize) {
        let (i, j) = self.two_notes(acct);
        self.op += 1;
        let plan = |note: usize| -> prover::TransferPlanInput {
            let n = &self.notes[note];
            prover::TransferPlanInput { note_index: note, leaf_index: note as u64, v: n.v, nk: self.accounts[n.acct].nk, rho: n.rho, rcm: n.rcm }
        };
        let tree = common::DenseTree { leaves: self.leaves.clone() };
        let anchor = tree.root(&self.cfg_tree);
        let mut prng = prover::op_rng(SEED, self.op, "vk-freeze-transfer-plan");
        let crypto = prover::TransferCrypto {
            anchor,
            path1: tree.path(&self.cfg_tree, i),
            path2: tree.path(&self.cfg_tree, j),
            out_rcm1: F::rand(&mut prng),
            out_rcm2: F::rand(&mut prng),
        };
        let total = self.notes[i].v + self.notes[j].v;
        let first = total / 2;
        let (in1, in2) = (plan(i), plan(j));
        let p = prover::prepare_transfer(
            &self.cfg,
            &self.keyset.transfer_pk,
            self.keyset.legacy_statement,
            &crypto,
            (&in1, &in2),
            (&self.accounts[1], &self.accounts[acct]),
            (first, total - first),
            0,
            0,
            [0u8; 32],
            None,
            None,
            SEED,
            self.op,
        );
        (p, i, j)
    }

    fn send_transfer(&mut self, who: Principal, args: ct::TransferArgs) -> ct::MutationResult {
        self.env.update(self.env.ledger, who, "confidential_transfer", (args,)).expect("confidential_transfer call")
    }

    /// An honest private transfer; its notes are recorded only when accepted.
    fn honest_transfer(&mut self) -> ct::MutationResult {
        let (p, i, j) = self.prepare_transfer(0);
        let m = self.send_transfer(self.accounts[0].principal, p.args.clone());
        if m.outcome == "ACCEPT" {
            self.notes[i].spent = true;
            self.notes[j].spent = true;
            for (owner, v, rho, rcm) in p.outs.iter() {
                self.leaves.push(common::note_commitment(&self.cfg, *v, self.accounts[*owner].pk, *rho, *rcm));
                self.notes.push(NoteRec { acct: *owner, v: *v, rho: *rho, rcm: *rcm, spent: false });
            }
            let tree = common::DenseTree { leaves: self.leaves.clone() };
            let root = f_bytes(&tree.root(&self.cfg_tree)).to_vec();
            assert_eq!(self.env.ledger_status().note_root.as_ref(), root.as_slice(), "battery mirror diverged");
        }
        m
    }

    fn upgrade(&self) {
        self.env
            .pic()
            .upgrade_eop_canister(self.env.ledger, self.env.ledger_wasm.clone(), candid::encode_args(()).unwrap(), Some(self.admin()))
            .unwrap_or_else(|e| panic!("upgrade failed: {e:?}"));
    }
}

impl Harness {
    fn anchor(&self) -> VkAnchor {
        self.env.query(self.env.ledger, "verifying_key_anchor", ()).expect("verifying_key_anchor")
    }

    fn freeze_as(&self, who: Principal, expected: Vec<u8>) -> Result<Vec<u8>, String> {
        let r: ct::MotokoResult<serde_bytes::ByteBuf> = self
            .env
            .update(self.env.ledger, who, "freeze_verifying_keys", (serde_bytes::ByteBuf::from(expected),))
            .map_err(|e| format!("freeze call: {e}"))?;
        r.into_result().map(|b| b.to_vec())
    }

    /// Rotate to the SAME keys: a real rotation (epoch + 1) that needs no second keyset.
    fn rotate_same(&self) -> Result<(), String> {
        let a = self.anchor();
        let r: ct::MotokoResult<ct::LedgerStatus> = self
            .env
            .update(
                self.env.ledger,
                self.admin(),
                "rotate_verifying_keys_v2",
                (a.transfer_vk_hex.clone(), a.deposit_vk_hex.clone(), a.transfer_vk_hex.clone(), a.deposit_vk_hex.clone()),
            )
            .map_err(|e| format!("rotate call: {e}"))?;
        r.into_result().map(|_| ())
    }

    /// zk/vk and zk/vk_frozen from the tip certificate, after verifying the certificate against the
    /// PocketIC root key and binding the witness to certified_data. None = label absent.
    fn certified_vk_leaves(&self) -> Result<(Vec<u8>, Option<Vec<u8>>), String> {
        let tip: Option<ct::DataCertificate> =
            self.env.query(self.env.ledger, "icrc3_get_tip_certificate", ()).map_err(|e| format!("tip certificate: {e}"))?;
        let tip = tip.ok_or("no tip certificate (empty ledger)")?;
        let root_key = self.env.pic().root_key().ok_or("PocketIC root key")?;
        let certificate = Certificate::from_cbor(&tip.certificate[..]).map_err(|e| e.to_string())?;
        let now_ns = self.env.time_ns() as u128;
        certificate
            .verify(self.env.ledger.as_slice(), &root_key, &now_ns, &MAX_CERTIFICATE_OFFSET_NS)
            .map_err(|e| format!("certificate verification: {e}"))?;
        let certified_data = match certificate.tree.lookup_path([
            "canister".as_bytes(),
            self.env.ledger.as_slice(),
            "certified_data".as_bytes(),
        ]) {
            LookupResult::Found(value) => value.to_vec(),
            other => return Err(format!("certified_data lookup: {other:?}")),
        };
        let tree = HashTree::from_cbor(&tip.hash_tree[..]).map_err(|e| e.to_string())?;
        if tree.digest().as_slice() != certified_data.as_slice() {
            return Err("witness digest is not the certified_data value".into());
        }
        let vk = match tree.lookup_path([b"zk".as_slice(), b"vk".as_slice()]) {
            LookupResult::Found(v) => v.to_vec(),
            other => return Err(format!("zk/vk lookup: {other:?}")),
        };
        let frozen = match tree.lookup_path([b"zk".as_slice(), b"vk_frozen".as_slice()]) {
            LookupResult::Found(v) => Some(v.to_vec()),
            LookupResult::Absent => None,
            other => return Err(format!("zk/vk_frozen lookup: {other:?}")),
        };
        Ok((vk, frozen))
    }
}

fn harness(w: &pic_env::BuiltWasms, ks: keys::Keyset, tag: &str) -> Harness {
    let mut h = Harness::new(w, ks, tag);
    // one accepted shield so the ledger has a tip certificate
    let m = h.shield(0, NOTE);
    assert_eq!(m.outcome, "ACCEPT", "{tag}: setup shield said {}", m.outcome);
    h
}

fn f1_default(w: &pic_env::BuiltWasms, ks: keys::Keyset) -> Result<(), String> {
    let h = harness(w, ks, "f1");
    let a = h.anchor();
    if a.frozen {
        return Err("f1 RED: a fresh ledger reports frozen".into());
    }
    let (vk, frozen) = h.certified_vk_leaves()?;
    if frozen.is_some() || vk != a.leaf() {
        return Err(format!("f1 RED: unfrozen tree carries vk_frozen={} / vk matches anchor={}", frozen.is_some(), vk == a.leaf()));
    }
    h.rotate_same().map_err(|e| format!("f1 RED: rotation before any freeze refused: {e}"))?;
    if h.anchor().epoch != a.epoch + 1 {
        return Err("f1 RED: rotation did not bump the epoch".into());
    }
    println!("[F1] PASS off by default: not frozen, no vk_frozen leaf, rotation works (epoch {} -> {})", a.epoch, a.epoch + 1);
    Ok(())
}

fn f2_authority(w: &pic_env::BuiltWasms, ks: keys::Keyset) -> Result<(), String> {
    let h = harness(w, ks, "f2");
    let a = h.anchor();
    let outsider = h.accounts[1].principal;
    match h.freeze_as(outsider, a.leaf()) {
        Err(e) if e == "REJECT:not-administrator" => {}
        other => return Err(format!("f2 RED: a non-administrator's freeze said {other:?}")),
    }
    let mut wrong = a.leaf();
    wrong[0] ^= 1;
    match h.freeze_as(h.admin(), wrong) {
        Err(e) if e == "REJECT:vk-anchor-precondition" => {}
        other => return Err(format!("f2 RED: a freeze with a wrong anchor said {other:?}")),
    }
    let mut stale = a.leaf();
    stale[39] ^= 1; // right digest, wrong epoch
    match h.freeze_as(h.admin(), stale) {
        Err(e) if e == "REJECT:vk-anchor-precondition" => {}
        other => return Err(format!("f2 RED: a freeze with a stale epoch said {other:?}")),
    }
    if h.anchor().frozen {
        return Err("f2 RED: refused freezes left the keys frozen".into());
    }
    println!("[F2] PASS authority: outsider refused, wrong digest and stale epoch refused, still unfrozen");
    Ok(())
}

fn f3_freeze(w: &pic_env::BuiltWasms, ks: keys::Keyset) -> Result<(), String> {
    let mut h = harness(w, ks, "f3");
    let a = h.anchor();
    let got = h.freeze_as(h.admin(), a.leaf()).map_err(|e| format!("f3: freeze refused: {e}"))?;
    if got != a.leaf() || !h.anchor().frozen {
        return Err("f3 RED: freeze did not take".into());
    }
    match h.rotate_same() {
        Err(e) if e == "REJECT:vk-frozen" => {}
        other => return Err(format!("f3 RED: rotation after the freeze said {other:?}")),
    }
    let b = h.anchor();
    if b.epoch != a.epoch || b.transfer_vk_hex != a.transfer_vk_hex || b.deposit_vk_hex != a.deposit_vk_hex {
        return Err("f3 RED: keys or epoch moved after the freeze".into());
    }
    match h.freeze_as(h.admin(), a.leaf()) {
        Err(e) if e == "REJECT:vk-frozen" => {}
        other => return Err(format!("f3 RED: a second freeze said {other:?}")),
    }
    let m = h.honest_transfer();
    if m.outcome != "ACCEPT" {
        return Err(format!("f3 RED: honest transfer after the freeze said {}", m.outcome));
    }
    println!("[F3] PASS freeze: rotation refused (keys, epoch unchanged), second freeze refused, honest transfer accepted");
    Ok(())
}

fn f4_certified(w: &pic_env::BuiltWasms, ks: keys::Keyset) -> Result<(), String> {
    let h = harness(w, ks, "f4");
    let a = h.anchor();
    h.freeze_as(h.admin(), a.leaf()).map_err(|e| format!("f4: freeze refused: {e}"))?;
    // no mutation between the freeze and the read: the freeze itself must refresh certified_data
    let (vk, frozen) = h.certified_vk_leaves()?;
    match frozen {
        Some(f) if f == a.leaf() && vk == a.leaf() => {}
        other => return Err(format!("f4 RED: certified vk_frozen={:?} vk_matches={}", other.map(hex::encode), vk == a.leaf())),
    }
    println!("[F4] PASS certified: verified certificate carries zk/vk_frozen == zk/vk == the frozen anchor");
    Ok(())
}

fn f5_upgrade(w: &pic_env::BuiltWasms, ks: keys::Keyset) -> Result<(), String> {
    let mut h = harness(w, ks, "f5");
    let a = h.anchor();
    h.freeze_as(h.admin(), a.leaf()).map_err(|e| format!("f5: freeze refused: {e}"))?;
    // whatever the latch does, try a rotation before the upgrade; a working latch refuses it,
    // a broken one changes the anchor and the post-upgrade self-check must then guard the ledger
    let _ = h.rotate_same();
    h.upgrade();
    let b = h.anchor();
    if !b.frozen || b.leaf() != a.leaf() {
        return Err(format!("f5 RED: after upgrade frozen={} anchor_unchanged={}", b.frozen, b.leaf() == a.leaf()));
    }
    match h.rotate_same() {
        Err(e) if e == "REJECT:vk-frozen" => {}
        other => return Err(format!("f5 RED: rotation after the upgrade said {other:?}")),
    }
    let (vk, frozen) = h.certified_vk_leaves()?;
    if frozen.as_deref() != Some(a.leaf().as_slice()) || vk != a.leaf() {
        return Err("f5 RED: vk_frozen not certified after the upgrade".into());
    }
    let m = h.honest_transfer();
    if m.outcome != "ACCEPT" {
        return Err(format!("f5 RED: honest transfer after the upgrade said {} (ledger guarded?)", m.outcome));
    }
    println!("[F5] PASS upgrade: freeze kept, rotation refused, leaf certified, ledger healthy");
    Ok(())
}

// ---------------------------------------------------------------------------

fn build_ledger(root: &Path, tag: &str, patches: &[(&str, &str)]) -> Vec<u8> {
    let stage = std::env::temp_dir().join(format!("vk_freeze_variant_{}_{}", std::process::id(), tag));
    let _ = std::fs::remove_dir_all(&stage);
    pic_env::copy_dir_recursive(&root.join("src"), &stage.join("src"));
    let main_path = stage.join("src/Main.mo");
    let mut source = std::fs::read_to_string(&main_path).expect("read Main.mo");
    for (from, to) in patches {
        assert_eq!(source.matches(from).count(), 1, "variant {tag}: patch anchor must occur exactly once:\n{from}");
        source = source.replace(from, to);
    }
    std::fs::write(&main_path, source).expect("write patched Main.mo");
    let out = stage.join("zk_ledger_variant.wasm");
    let sources_raw = String::from_utf8(
        std::process::Command::new("/usr/bin/mops").arg("sources").current_dir(root).output().expect("mops").stdout,
    )
    .unwrap();
    let source_args: Vec<String> = sources_raw.split_whitespace().map(String::from).collect();
    let status = std::process::Command::new("/opt/moc-1.4.1/moc")
        .args(&source_args)
        .arg("-c")
        .arg(main_path.to_str().unwrap())
        .arg("-o")
        .arg(&out)
        .current_dir(root)
        .status()
        .expect("moc spawn");
    assert!(status.success(), "variant {tag} compile failed");
    std::fs::read(&out).expect("read variant wasm")
}

type Check = (&'static str, fn(&pic_env::BuiltWasms, keys::Keyset) -> Result<(), String>);

fn main() {
    let root = repo_root();
    let manifest = std::fs::read_to_string(root.join("fixtures/pool-vectors-bls12-381-hardened/SETUP-MANIFEST.json")).unwrap();
    println!("[battery] regenerating the hardened-statement test keyset...");
    let keyset = keys::regenerate_and_verify(&manifest, false).expect("keyset");
    println!("[battery] building wasms (ledger + token + tree oracle)...");
    let base = pic_env::build_wasms(&root, &root.join("soak/target/wasms"));
    println!("[battery] shipped ledger sha256 {}", base.ledger_sha256);

    let checks: Vec<Check> = vec![
        ("F1", f1_default),
        ("F2", f2_authority),
        ("F3", f3_freeze),
        ("F4", f4_certified),
        ("F5", f5_upgrade),
    ];

    println!("\n==== TEETH: planted defects must turn the checks RED ====");
    let variants: Vec<(&str, Vec<(&str, &str)>, Vec<&str>)> = vec![
        (
            "A:rotation-ignores-freeze",
            vec![(
                "    if (vk_frozen_anchor != null) return #err(\"REJECT:vk-frozen\");\n    if (pending_shield != null or pending_unshield != null) return #err(\"REJECT:pending-token-mutation\");\n    if (transfer_vk_hex != expectedOldTransferVkHex)",
                "    // PLANTED DEFECT A\n    if (pending_shield != null or pending_unshield != null) return #err(\"REJECT:pending-token-mutation\");\n    if (transfer_vk_hex != expectedOldTransferVkHex)",
            )],
            vec!["F3", "F5"],
        ),
        (
            "B:freeze-not-admin-gated",
            vec![(
                "    if (not isAdministrator(caller)) return #err(\"REJECT:not-administrator\");\n    if (not configured()) return #err(\"REJECT:unconfigured\");\n    if (vk_frozen_anchor != null) return #err(\"REJECT:vk-frozen\");\n    let anchor",
                "    // PLANTED DEFECT B\n    if (not configured()) return #err(\"REJECT:unconfigured\");\n    if (vk_frozen_anchor != null) return #err(\"REJECT:vk-frozen\");\n    let anchor",
            )],
            vec!["F2"],
        ),
        (
            "C:expected-anchor-ignored",
            vec![("    if (anchor != expectedAnchor) return #err(\"REJECT:vk-anchor-precondition\");\n", "    // PLANTED DEFECT C\n")],
            vec!["F2"],
        ),
        (
            "D:transient-latch",
            vec![("  var vk_frozen_anchor : ?Blob = null;", "  transient var vk_frozen_anchor : ?Blob = null; // PLANTED DEFECT D")],
            vec!["F5"],
        ),
        (
            "E:frozen-leaf-not-certified",
            vec![("      vk_frozen = vk_frozen_anchor;", "      vk_frozen = null; // PLANTED DEFECT E")],
            vec!["F4"],
        ),
        (
            "F:freeze-skips-certification",
            vec![("    vk_frozen_anchor := ?anchor;\n    refreshCertification();\n", "    vk_frozen_anchor := ?anchor; // PLANTED DEFECT F\n")],
            vec!["F4"],
        ),
    ];

    let mut teeth = 0u32;
    let mut wanted = 0u32;
    for (vname, patches, red_checks) in &variants {
        let tag = vname.split(':').next().unwrap();
        let vw = pic_env::BuiltWasms { ledger: build_ledger(&root, tag, patches), ..base.clone() };
        for want_red in red_checks {
            wanted += 1;
            let (_, f) = checks.iter().find(|(n, _)| n == want_red).unwrap();
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(&vw, keyset.clone())));
            let red = match outcome {
                Ok(Err(reason)) => {
                    println!("[TEETH {vname}/{want_red}] RED as required: {reason}");
                    true
                }
                Ok(Ok(())) => false,
                Err(_) => {
                    println!("[TEETH {vname}/{want_red}] RED as required (hard panic)");
                    true
                }
            };
            assert!(red, "TEETH FAILED: {want_red} stayed GREEN on planted defect {vname}");
            teeth += 1;
        }
    }
    println!("==== TEETH: {teeth}/{wanted} planted-defect reds confirmed ====");

    println!("\n==== SHIPPED WASM: all checks must be GREEN ====");
    let mut green = 0u32;
    for (name, f) in &checks {
        f(&base, keyset.clone()).unwrap_or_else(|e| panic!("{name} FAILED on the shipped wasm: {e}"));
        green += 1;
    }
    println!("\nVK FREEZE BATTERY COMPLETE: {green}/{} green on shipped, {teeth}/{wanted} planted reds", checks.len());
    println!("VK-FREEZE-BATTERY: PASS");
}
