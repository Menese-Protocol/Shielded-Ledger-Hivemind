//! Standalone Phase-2 transcript verifier (Deliverable D4).
//!
//! Runnable by anyone. Given the published Phase-1 SRS and a ceremony transcript, it re-derives the
//! initial parameters from the SRS and the compiled-in circuits, replays every contribution through
//! the proof-of-knowledge check AND the full delta-division-consistency check, verifies the beacon
//! finalize, and confirms the final keys prove and verify real proofs. It shares no code with the
//! coordinator canister's on-chain acceptance path (that path is Motoko and only runs the cheap PoK
//! check; this runs the full off-chain check independently).
//!
//! Usage:
//!   verify-transcript <srs.bin> <transcript.bin> [--selfcheck]
//!
//! Exit code 0 and "TRANSCRIPT VALID" on success; nonzero and the first inconsistency otherwise.

use ark_serialize::CanonicalDeserialize;
use ceremony::session::{selfcheck_keys_work, verify_full_transcript};
use ceremony::srs::Phase1Srs;
use ceremony::transcript::Transcript;
use std::process::exit;

fn read<T: CanonicalDeserialize>(path: &str) -> T {
    let bytes = std::fs::read(path).unwrap_or_else(|e| {
        eprintln!("cannot read {path}: {e}");
        exit(2);
    });
    T::deserialize_compressed(&bytes[..]).unwrap_or_else(|e| {
        eprintln!("cannot parse {path}: {e:?}");
        exit(2);
    })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: verify-transcript <srs.bin> <transcript.bin> [--selfcheck]");
        exit(2);
    }
    let selfcheck = args.iter().any(|a| a == "--selfcheck");

    eprintln!("reading SRS from {} ...", args[1]);
    let srs: Phase1Srs = read(&args[1]);
    eprintln!("reading transcript from {} ...", args[2]);
    let transcript: Transcript = read(&args[2]);

    eprintln!(
        "SRS: power {} ({} G1 tau powers), provenance {:?}",
        srs.power,
        srs.tau_g1.len(),
        srs.provenance
    );
    eprintln!("SRS SHA-256: {}", srs.sha256_hex());
    eprintln!("transcript: {} contributions, finalized={}", transcript.contributions.len(), transcript.finalized);

    match verify_full_transcript(&srs, &transcript) {
        Ok((final_keys, report)) => {
            println!("TRANSCRIPT VALID");
            println!("  honest contributions : {}", report.honest_contributions);
            println!("  finalized (beacon)   : {}", report.finalized);
            println!("  transfer vk SHA-256  : {}", report.transfer_vk_sha256);
            println!("  deposit  vk SHA-256  : {}", report.deposit_vk_sha256);
            if selfcheck {
                eprint!("running key self-check (prove+verify real transfer & deposit) ... ");
                match selfcheck_keys_work(&final_keys) {
                    Ok(()) => println!("KEYS WORK (real transfer + deposit proofs verify)"),
                    Err(e) => {
                        println!("KEY SELF-CHECK FAILED: {e}");
                        exit(1);
                    }
                }
            }
            exit(0);
        }
        Err(e) => {
            println!("TRANSCRIPT INVALID: {e}");
            exit(1);
        }
    }
}
