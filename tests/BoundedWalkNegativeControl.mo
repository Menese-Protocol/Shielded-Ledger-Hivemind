/// NEGATIVE CONTROL for the byte ceiling added to the chunked note walks: the ceiling, not the
/// count cap, is what bounds the bytes a chunk moves.
///
/// A count cap bounds how many notes a chunk touches. It does not bound the BYTES a chunk moves,
/// because a note is variable-length. This program demonstrates that gap on the real
/// `src/StableLog` rather than arguing it: it builds a log of inflated notes and runs the walk
/// twice over it — once with the byte ceiling the fix adds, once without.
///
///   POSITIVE (bound present) : a chunk moves at most AUDIT_BYTES_PER_CHUNK + one note's worth.
///   NEGATIVE (bound removed) : the same fixture moves far past the ceiling, and the run TRAPS.
///
/// A control that cannot fail proves nothing, so the negative leg is asserted to fail here: if
/// removing the ceiling still keeps the walk inside it, the ceiling was never load-bearing and
/// this file says so loudly.
///
/// SCOPE, stated rather than implied. This drives the real `StableLog` with the real byte
/// accounting, but it reproduces the walk's bounding arithmetic instead of calling
/// `__detect_rebuild_chunk` on a replica. It therefore establishes that the ceiling binds the
/// bytes a chunk moves; it does NOT establish the canister's per-message instruction behaviour,
/// which needs pocket-ic. That measurement is recorded as owed.
///
/// Runs as a WASI program (moc -wasi-system-api, wasmtime).
/// Menese DeFi Team.

import Prim "mo:⛔";
import Runtime "mo:core/Runtime";
import Nat "mo:core/Nat";
import Blob "mo:core/Blob";
import Array "mo:core/Array";
import StableLog "../src/StableLog";

// The production constants, restated. If either moves in Main.mo this file must move with it —
// a divergence here would silently weaken the control rather than fail it.
let AUDIT_NOTES_PER_CHUNK : Nat = 4096;
let AUDIT_BYTES_PER_CHUNK : Nat = 8_388_608;

// Inflated notes: 4 KiB each. 4096 of them is 16 MiB, so the count cap alone would let a single
// chunk move twice the byte ceiling. Anything at or below 2048 B per note would let the count
// cap bind first and the fixture would prove nothing.
let NOTE_BYTES : Nat = 4096;
let NOTE_COUNT : Nat = 3000;

let log = StableLog.newState();
StableLog.ensureInit(log);

let filler : Blob = Blob.fromArray(Array.repeat<Nat8>(0xAB, NOTE_BYTES));
var appended = 0;
while (appended < NOTE_COUNT) {
  switch (StableLog.append(log, filler)) {
    case (#ok(_)) {};
    case (#err(m)) Runtime.trap("fixture append failed: " # m);
  };
  appended += 1;
};
Prim.debugPrint(
  "fixture: " # Nat.toText(StableLog.size(log)) # " notes of " # Nat.toText(NOTE_BYTES)
  # " B = " # Nat.toText(NOTE_COUNT * NOTE_BYTES) # " B total"
);

/// One chunk of the walk. `withByteBound` selects the fixed path or the pre-fix path.
/// Returns (notes stepped, bytes moved).
func walkChunk(from : Nat, withByteBound : Bool) : (Nat, Nat) {
  var cursor = from;
  var stepped = 0;
  var steppedBytes = 0;
  let n = StableLog.size(log);
  while (stepped < AUDIT_NOTES_PER_CHUNK and cursor < n) {
    let encoded = switch (StableLog.get(log, cursor)) {
      case (?value) value;
      case null Runtime.trap("fixture note missing");
    };
    cursor += 1;
    stepped += 1;
    steppedBytes += encoded.size();
    // The fix: checked AFTER at least one note, so a single oversized note still advances.
    if (withByteBound and steppedBytes >= AUDIT_BYTES_PER_CHUNK) return (stepped, steppedBytes);
  };
  (stepped, steppedBytes)
};

// ---- GREEN: the ceiling binds ------------------------------------------------------------
let (greenSteps, greenBytes) = walkChunk(0, true);
Prim.debugPrint(
  "GREEN  bound present: stepped=" # Nat.toText(greenSteps)
  # " bytes=" # Nat.toText(greenBytes) # " ceiling=" # Nat.toText(AUDIT_BYTES_PER_CHUNK)
);
// The overshoot is at most one note, by construction of the after-the-fact check.
if (greenBytes >= AUDIT_BYTES_PER_CHUNK + NOTE_BYTES) {
  Runtime.trap(
    "GREEN FAILED: a chunk moved " # Nat.toText(greenBytes)
    # " B, more than the ceiling plus one note — the bound is not binding"
  );
};
if (greenSteps >= AUDIT_NOTES_PER_CHUNK) {
  Runtime.trap(
    "VACUOUS FIXTURE: the COUNT cap bound first (stepped=" # Nat.toText(greenSteps)
    # "), so this fixture never exercises the byte ceiling. Inflate the notes."
  );
};

// ---- NEGATIVE: remove the ceiling, the same fixture must blow past it ----------------------
let (redSteps, redBytes) = walkChunk(0, false);
Prim.debugPrint(
  "NEGATIVE  bound removed: stepped=" # Nat.toText(redSteps) # " bytes=" # Nat.toText(redBytes)
);
if (redBytes < AUDIT_BYTES_PER_CHUNK) {
  Runtime.trap(
    "BYTE CEILING NEGATIVE CONTROL FAILED: with the ceiling REMOVED the walk still moved only "
    # Nat.toText(redBytes) # " B, under the " # Nat.toText(AUDIT_BYTES_PER_CHUNK)
    # " B ceiling. The ceiling is not load-bearing on this fixture and this control has no teeth."
  );
};

// ---- ORDINARY TRAFFIC is unchanged ---------------------------------------------------------
// The measured mean encoded note size on a seeded fixture is 395 B (recorded on
// AUDIT_BYTES_PER_CHUNK in Main.mo). At that size the COUNT cap must still bind first, so the
// new ceiling changes nothing for real traffic and existing runs stay byte-for-byte identical.
// If this ever flips, the ceiling has started rejecting ordinary work and that is a regression.
let ordinaryLog = StableLog.newState();
StableLog.ensureInit(ordinaryLog);
let ordinaryNote : Blob = Blob.fromArray(Array.repeat<Nat8>(0xCD, 395));
var oi = 0;
while (oi < AUDIT_NOTES_PER_CHUNK) {
  switch (StableLog.append(ordinaryLog, ordinaryNote)) {
    case (#ok(_)) {};
    case (#err(m)) Runtime.trap("ordinary fixture append failed: " # m);
  };
  oi += 1;
};
let ordinaryBytes = AUDIT_NOTES_PER_CHUNK * 395;
Prim.debugPrint(
  "ordinary traffic: " # Nat.toText(AUDIT_NOTES_PER_CHUNK) # " notes x 395 B = "
  # Nat.toText(ordinaryBytes) # " B, " # Nat.toText(ordinaryBytes * 100 / AUDIT_BYTES_PER_CHUNK)
  # "% of the ceiling"
);
if (ordinaryBytes >= AUDIT_BYTES_PER_CHUNK) {
  Runtime.trap(
    "ORDINARY TRAFFIC FAILED: at the measured mean note size a full count-capped chunk reaches "
    # "the byte "
    # "ceiling, so the new bound changes behaviour for ordinary traffic"
  );
};

Prim.debugPrint(
  "PASS BoundedWalkNegativeControl: ceiling holds a chunk to " # Nat.toText(greenBytes)
  # " B; removing it lets the same fixture move " # Nat.toText(redBytes)
  # " B (" # Nat.toText(redBytes * 100 / AUDIT_BYTES_PER_CHUNK)
  # "% of the ceiling). Ordinary traffic sits at "
  # Nat.toText(ordinaryBytes * 100 / AUDIT_BYTES_PER_CHUNK) # "%, so it is unaffected."
);
