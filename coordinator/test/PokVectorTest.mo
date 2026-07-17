// Cross-language PoK oracle test: a real Rust-produced contribution (emit-pok-vector) must be
// ACCEPTED by the Motoko on-chain verifier, and a tampered copy REJECTED.
//   moc $(mops sources) -r coordinator/test/PokVectorTest.mo   (exit 0 = pass)
import PokVerify "../src/PokVerify";
import GW "../../src/groth16/Groth16Wire";
import Wire "../src/Wire";
import Runtime "mo:core/Runtime";
import Array "mo:core/Array";
import Debug "mo:core/Debug";

func bytes(t : Text) : [Nat8] {
  switch (GW.hexToBytes(t)) { case (?b) b; case (null) { Runtime.trap("bad hex") } };
};
let prev = bytes("7068617365322d706f6b766563746f722d707265762d6368616c6c656e676521");
let oldG1 = Wire.g1FromBE(bytes("17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1"), 0);
let newG1 = Wire.g1FromBE(bytes("083fee8d83d31af2cafa17d26621355ab333c8e34f58abf3570aa3dc8e5acc5dabd27ae9910fc66f263810e25aca0d5b0508918bb16fc5c4b6820266af5facfceec4e0e041be50289f5492872fe1ba4729b06b6c519ac07ccdf18a1b672f7cdb"), 0);
let newG2 = Wire.g2FromBE(bytes("02ce23b7488e0817549aaa0ce0e8bbf9eb38450db0b4561beb21c48e684d322b36af74a055a76e625a8f78f6ceb794000b25e24724c3cd9edc2aea867915fd17a199109001809c2a7c0b6a836affcbba6402565959986b2b7b9186dc22b973e4096f3ce7665e403da46197ce741df68922ad3464fa92724032137208ab2514262063930d9271e21cd6b42f5bd7bef937189a522ec95ea604abfc0e89e2624604748781072dc49165ba4eafa280858bcb43eaa83810cf3a9d8c3a59703166931b"), 0);
let sG1 = Wire.g1FromBE(bytes("117a7e6e31f8eec60cb91848e94fe9276e72814c1fcbc07204ef385512834f50dffc659e0b2892d81820819a38be880c038d29bf32d9b80070b36ac80fed87d09ed21a98a4fcfc76dfb77a3862220dc5398b2bf893f48e7880ca69100ff8fd6c"), 0);
let sDeltaG1 = Wire.g1FromBE(bytes("1549dc6e16d00d4b702ef38d7a3e13e062b7b570ef088eab5adf9ae5009147a43dac00267d5a2dba4df7edfa01055ae40ba0ca8efbc79aeaa553d8a0aea35edbd65347e9297188b3ff7363719d7c0882496fa51a027a00de4a683a68b3561fe7"), 0);
let rDeltaBytes = bytes("18b03196a1424c06020feed63ce846d33f7aa26ebc67ee8b603e58cd02b9e37825ed535bed41e0942e77993880de3392100550c7a9ba776d4247a980cb24368eefd91388d67ed7a2428b3728f45be8119007c6c7dd1af1efcbd2676a538ddb4e0bc10299b145c8305b6546077be17ac34c6abc5131ee146767a6abbfbe7c93acf445b19af409e5873000414187e99b621684950ffae1aa635599ef50c9797ef08c60bec4544805e5bf4e16f1a5e3126b5c5c7625f8655bc75b21d247d9fea7f5");
let rDeltaG2 = Wire.g2FromBE(rDeltaBytes, 0);

assert PokVerify.selfCheckGenerator();

let good = PokVerify.verifyPok(prev, oldG1, { deltaG1 = newG1; deltaG2 = newG2 }, { sG1; sDeltaG1; rDeltaG2 });
switch (good) { case (#ok) { Debug.print("GENUINE ACCEPTED") }; case (#err(e)) { Runtime.trap("GENUINE REJECTED: " # e) } };

let n = rDeltaBytes.size();
let tamperedBytes = Array.tabulate<Nat8>(n, func(i) { if (i == n - 1) { rDeltaBytes[i] ^ 1 } else { rDeltaBytes[i] } });
let tamperedG2 = Wire.g2FromBE(tamperedBytes, 0);
let bad = PokVerify.verifyPok(prev, oldG1, { deltaG1 = newG1; deltaG2 = newG2 }, { sG1; sDeltaG1; rDeltaG2 = tamperedG2 });
switch (bad) { case (#ok) { Runtime.trap("TAMPERED ACCEPTED") }; case (#err(e)) { Debug.print("TAMPERED (off-curve) REJECTED: " # e) } };

// A VALID but WRONG r_delta_g2 (substitute new_delta_g2, an on-curve subgroup point) must fail the
// pairing check itself, not just curve validation.
let wrong = PokVerify.verifyPok(prev, oldG1, { deltaG1 = newG1; deltaG2 = newG2 }, { sG1; sDeltaG1; rDeltaG2 = newG2 });
switch (wrong) { case (#ok) { Runtime.trap("WRONG-VALID-POINT ACCEPTED") }; case (#err(e)) { Debug.print("WRONG-VALID-POINT REJECTED: " # e) } };

// The identity contribution (delta unchanged) must be rejected.
let ident = PokVerify.verifyPok(prev, oldG1, { deltaG1 = oldG1; deltaG2 = newG2 }, { sG1; sDeltaG1; rDeltaG2 });
switch (ident) { case (#ok) { Runtime.trap("IDENTITY ACCEPTED") }; case (#err(e)) { Debug.print("IDENTITY REJECTED: " # e) } };

Debug.print("PoK cross-language oracle test PASSED");
