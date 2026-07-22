/// §1 three-verifier gate — the Motoko side.
///
/// A minimal PocketIC harness canister that exposes the PRODUCTION Groth16 verifier on the
/// exact shipped code path: `Groth16Wire.tryVerify` parses+prepares the verifying key and
/// verifies through the L3 flat backend (`verifyPreparedCached` -> `verifyWithFlat`) — the
/// same path `src/Main.mo` uses per proof. The §1 driver installs this wasm, feeds it the
/// full mutation taxonomy, and asserts Motoko == arkworks == blst on every case. Update call
/// (verification exceeds the query instruction budget). No state; pure over its arguments.
import Prim "mo:⛔";
import Groth16Wire "groth16/Groth16Wire";

persistent actor {
  public func verify_oneshot(vkHex : Text, proofHex : Text, inputsHex : Text) : async Text {
    Groth16Wire.tryVerify(vkHex, proofHex, inputsHex);
  };

  /// §10 side-channel probe: the production verify plus the exact instruction count it
  /// consumed. Two proofs of the SAME public shape but DIFFERENT private values must produce
  /// the same instruction-count class here — a secret-dependent branch would show as a
  /// different count.
  public func verify_counted(vkHex : Text, proofHex : Text, inputsHex : Text) : async (Text, Nat64) {
    let start = Prim.performanceCounter(0);
    let v = Groth16Wire.tryVerify(vkHex, proofHex, inputsHex);
    let stop = Prim.performanceCounter(0);
    (v, stop - start);
  };
};
