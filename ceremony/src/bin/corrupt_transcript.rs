//! Produce a DELIBERATELY INVALID transcript, so the transcript verifier can be shown rejecting.
//!
//! A verifier that has never rejected anything is an untested verifier. `verify-transcript` had no
//! caller at all, so nothing had ever established that it CAN reject — and a green run of a
//! verifier that cannot fail is worth nothing. This binary manufactures the two corruptions the
//! ceremony's acceptance criteria name, each targeting a different property:
//!
//!   flip-h-query   replaces one point in one circuit's `h_query` with a DIFFERENT VALID CURVE
//!                  POINT. It must still deserialize, so the rejection comes from the
//!                  delta-division-consistency check rather than from a parse error — otherwise the
//!                  red leg would pass for the wrong reason and prove nothing about verification.
//!
//!   reorder        swaps two adjacent contributions. Every field stays individually well-formed;
//!                  what breaks is the CHALLENGE CHAIN, which is the whole reason the chain exists.
//!                  This is the case the Sapling/PPoT inclusion check is built around.
//!
//! Both are test-only artifacts. Nothing in the product or the coordinator consumes this binary,
//! and it writes only to the output path it is given.
//!
//! Usage: corrupt-transcript <in.transcript.bin> <out.transcript.bin> <flip-h-query|reorder>

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ceremony::transcript::Transcript;
use std::process::exit;

fn die(message: &str) -> ! {
    eprintln!("corrupt-transcript: {message}");
    exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        die("usage: corrupt-transcript <in.bin> <out.bin> <flip-h-query|reorder>");
    }
    let bytes = std::fs::read(&args[1]).unwrap_or_else(|e| die(&format!("cannot read {}: {e}", args[1])));
    let mut transcript = Transcript::deserialize_compressed(&bytes[..])
        .unwrap_or_else(|e| die(&format!("cannot parse {}: {e:?}", args[1])));

    match args[3].as_str() {
        "flip-h-query" => {
            let c = transcript
                .contributions
                .first_mut()
                .unwrap_or_else(|| die("transcript has no contributions to corrupt"));
            let h = &mut c.transfer.delta.h_query;
            if h.is_empty() {
                die("transfer h_query is empty; nothing to flip");
            }
            let before = h[0];
            // Doubling stays on the curve and in the right subgroup, so the encoding remains
            // canonical and deserialization still succeeds. A random byte flip would usually
            // produce an unparseable point and the verifier would reject at the wrong layer.
            let after = (h[0] + h[0]).into();
            if before == after {
                die("h_query[0] is the identity; doubling would not change it");
            }
            h[0] = after;
            eprintln!("corrupt-transcript: flipped transfer h_query[0] of contribution 0 to a different valid point");
        }
        "reorder" => {
            if transcript.contributions.len() < 2 {
                die("reorder needs at least 2 contributions; re-run the ceremony with n >= 2");
            }
            transcript.contributions.swap(0, 1);
            eprintln!("corrupt-transcript: swapped contributions 0 and 1; every field is still individually well-formed");
        }
        other => die(&format!("unknown mode {other}")),
    }

    let mut out = Vec::new();
    transcript
        .serialize_compressed(&mut out)
        .unwrap_or_else(|e| die(&format!("cannot serialize: {e:?}")));
    std::fs::write(&args[2], &out).unwrap_or_else(|e| die(&format!("cannot write {}: {e}", args[2])));
    eprintln!("corrupt-transcript: wrote {} ({} bytes)", args[2], out.len());
}
