/// Differential gate for field-element canonicality: `src/PoseidonTree.parseFieldElement`
/// against the arkworks oracle (`frontier_oracle canonical`, ark_bls12_381::Fr
/// `deserialize_compressed`). Runs as a WASI program (moc -wasi-system-api, wasmtime).
///
/// The corpus and the oracle's verdict for each entry are GENERATED into
/// `CanonicalityVectors.mo` by `scripts/canonicality-battery.sh`. Nothing here is
/// hand-transcribed, so a divergence cannot be papered over by editing an expectation.
///
/// Traps on the FIRST disagreement with the entry name, the hex, and both verdicts.
/// Menese DeFi Team.

import Prim "mo:⛔";
import Runtime "mo:core/Runtime";
import Nat "mo:core/Nat";
import P "../src/PoseidonTree";
import V "CanonicalityVectors";

var checked : Nat = 0;
var agreedCanonical : Nat = 0;
var agreedNonCanonical : Nat = 0;

func verdict(b : Bool) : Text { if (b) "CANONICAL" else "NON-CANONICAL" };

for (entry in V.corpus.vals()) {
  let (name, hex, oracleCanonical) = entry;
  let motokoCanonical = switch (P.parseFieldElement(hex)) {
    case (?_) true;
    case null false;
  };
  if (motokoCanonical != oracleCanonical) {
    Runtime.trap(
      "CANONICALITY DIVERGENCE at `" # name # "`"
      # "  hex=" # hex
      # "  oracle=" # verdict(oracleCanonical)
      # "  motoko=" # verdict(motokoCanonical)
    );
  };
  checked += 1;
  if (oracleCanonical) { agreedCanonical += 1 } else { agreedNonCanonical += 1 };
};

// C-2: the corpus must not be vacuous. A run where every entry falls on one side proves
// nothing — two implementations that both answered "yes" to everything would pass it.
if (agreedCanonical == 0 or agreedNonCanonical == 0) {
  Runtime.trap(
    "VACUOUS CORPUS: accepted=" # Nat.toText(agreedCanonical)
    # " rejected=" # Nat.toText(agreedNonCanonical) # " -- need at least one of each"
  );
};

Prim.debugPrint(
  "PASS CanonicalityDifferential: " # Nat.toText(checked) # " entries, "
  # Nat.toText(agreedCanonical) # " canonical / " # Nat.toText(agreedNonCanonical)
  # " non-canonical, arkworks and Motoko agree on every one"
);
