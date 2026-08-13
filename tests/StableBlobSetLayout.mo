/// Layout-2 unit checks for StableBlobSet — no replica required.
/// Run: $(dfx cache show)/moc $(mops sources) -r tests/StableBlobSetLayout.mo
///
/// Covers the layout invariants that the cached-hash change must not break: a fresh set uses the
/// wide slot, membership survives every doubling, a duplicate put is still reported as a
/// duplicate (addNullifier traps on that answer, so a regression here would admit a double
/// spend), and the digest is a pure function of set CONTENT rather than of the slot layout.
import Blob "mo:core/Blob";
import Nat "mo:core/Nat";
import Nat8 "mo:core/Nat8";
import Nat64 "mo:core/Nat64";
import Sha256 "mo:sha2/Sha256";
import Debug "mo:core/Debug";
import S "../src/StableBlobSet";

func key(i : Nat) : Blob {
  Sha256.fromBlob(#sha256, Blob.fromArray([Nat8.fromNat(i % 256), Nat8.fromNat((i / 256) % 256), Nat8.fromNat((i / 65536) % 256)]))
};

var pass = 0;
var fail = 0;
func check(name : Text, cond : Bool) {
  if (cond) { pass += 1; Debug.print("  PASS  " # name) }
  else { fail += 1; Debug.print("  FAIL  " # name) }
};

let set = S.newState();
S.ensureInit(set);

check("a fresh set uses the 41-byte slot", S.activeStride(set) == 41);

// Insert enough to force several doublings (16 -> 32 -> ... ), each of which rehashes.
let N = 600;
var i = 0;
while (i < N) { ignore S.put(set, key(i)); i += 1 };

check("entry_count matches the inserts", S.size(set) == N);
check("still the 41-byte slot after many grows", S.activeStride(set) == 41);

// Every committed key readable, no control falsely present.
var missing = 0;
i := 0;
while (i < N) { if (not S.contains(set, key(i))) missing += 1; i += 1 };
var ghosts = 0;
i := 0;
while (i < N) { if (S.contains(set, key(1_000_000 + i))) ghosts += 1; i += 1 };
check("every committed key is readable after the grows", missing == 0);
check("no key that was never inserted is reported present", ghosts == 0);

// A duplicate must answer #ok(false) and must not move the count.
let before = S.size(set);
let dup = switch (S.put(set, key(7))) { case (#ok(false)) true; case _ false };
check("a duplicate put answers ok(false)", dup);
check("a duplicate put does not change entry_count", S.size(set) == before);

// The digest must depend on content, not on the slot stride: same keys inserted in a different
// order must give the same digest.
let other = S.newState();
S.ensureInit(other);
i := N;
while (i > 0) { i -= 1; ignore S.put(other, key(i)) };
check("digest is order-independent and layout-independent", S.digest(other) == S.digest(set));

check("validate() accepts the layout-2 set", switch (S.validate(set)) { case (#ok(_)) true; case (#err(_)) false });

Debug.print("=== RESULT: " # Nat.toText(pass) # " passed, " # Nat.toText(fail) # " failed ===");
assert fail == 0;
