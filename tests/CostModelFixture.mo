/// D-1 STEP 1 — checkNote cost model. Test-only actor, never the shipped ledger wasm.
///
/// Wraps the PRODUCTION NoteAudit.checkNote between two performanceCounter(0) reads — the
/// measure_vk_prepare / measure_hex_decode precedent. A cost model fitted to a copy of the walk
/// would measure the copy, so nothing here reimplements any part of it: the checker is
/// NoteAudit.Checker(), the frame comes from NoteCodec.encode, and the sets are StableBlobSet.
///
/// WHY THIS IS ITS OWN ACTOR, and not another entry on ScaleFixture.
/// scripts/build-layout1-fixture.sh regenerates ScaleFixture.mo against the FROZEN layout-1
/// StableBlobSet (tests/layout1/StableBlobSet.mo) with exactly one line changed, and that frozen
/// module predates option (b): it has no migrationActive, no advanceMigration and no
/// activeCapacity. Any set-window measurement therefore cannot live in ScaleFixture without
/// breaking the layout-1 build. Kept separate, the cost model perturbs neither that generator nor
/// the 26 scripts that build scale_fixture.
///
/// The measured question. The instruction guard at Main.mo:1463 is reached only while
/// steppedBytes < AUDIT_BYTES_PER_CHUNK (:646) and stepped < AUDIT_NOTES_PER_CHUNK (:634), so
/// whether it can fire at the shipped 20e9 (:655) is the arithmetic question
/// 4096*F + 8388608*k >= 20e9 for per-note cost F and per-byte cost k. The surface has four axes
/// and this fixture drives all four: note size, nullifier count (each nullifier is one more
/// StableBlobSet.contains at NoteAudit.mo:407), the referenceCheck fallback, and whether the
/// consulted set is mid-migration -- contains probes BOTH tables during a window
/// (StableBlobSet.mo:595-598).

import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Nat64 "mo:core/Nat64";
import Nat8 "mo:core/Nat8";
import Prim "mo:⛔";
import Sha256 "mo:sha2/Sha256";
import NoteAudit "../src/NoteAudit";
import NoteCodec "../src/NoteCodec";
import StableBlobSet "../src/StableBlobSet";

persistent actor CostModelFixture {
  public type Result<T> = { #ok : T; #err : Text };

  transient var d1_roots : ?StableBlobSet.State = null;
  transient var d1_nulls : ?StableBlobSet.State = null;
  transient let d1_checker = NoteAudit.Checker();

  // Same generators ScaleFixture uses, so the synthetic values are drawn the same way.
  func deterministicBlob(tag : Nat8, index : Nat, size : Nat) : Blob {
    let seed = Blob.fromArray(Array.tabulate<Nat8>(9, func(i) {
      if (i == 0) tag else Nat8.fromNat((index / (256 ** (i - 1))) % 256)
    }));
    let base = Sha256.fromBlob(#sha256, seed);
    if (size == 32) return base;
    let bytes = Blob.toArray(base);
    Blob.fromArray(Array.tabulate<Nat8>(size, func(i) { bytes[i % 32] }))
  };

  /// Byte 31 zeroed: canonical by construction, matching ScaleFixture's generator.
  func canonicalBlob(tag : Nat8, index : Nat) : Blob {
    let bytes = Blob.toArray(deterministicBlob(tag, index, 32));
    Blob.fromArray(Array.tabulate<Nat8>(32, func(i) { if (i == 31) 0 else bytes[i] }))
  };

  func d1RootKey() : Blob { canonicalBlob(91, 0) };
  func d1NullKey(index : Nat) : Blob { canonicalBlob(92, index) };
  func d1FillerKey(index : Nat) : Blob { canonicalBlob(93, index) };

  /// Build the measurement sets. `filler` keys drive table capacity. When `leave_window_open` the
  /// fill stops the moment a grow opens a migration window AT OR ABOVE `min_capacity` and does not
  /// put again -- contains never advances the cursor (StableBlobSet.mo:601-606), so the window
  /// stays open for the whole measurement. Otherwise both sets are drained to quiescence.
  ///
  /// min_capacity matters because the cost a window adds is bounded by the OLD table's capacity:
  /// stopping at the first window leaves a 128-slot old table, which is not the degraded regime at
  /// all. Sweeping it is how the per-probe cost is shown to scale, or shown not to.
  /// Returns (nulls_window_open, roots_window_open, nulls_size, nulls_active_capacity).
  public func measure_prepare_sets(filler : Nat, leave_window_open : Bool, min_capacity : Nat) : async Result<(Bool, Bool, Nat, Nat)> {
    let roots = StableBlobSet.newState();
    let nulls = StableBlobSet.newState();
    StableBlobSet.ensureInit(roots);
    StableBlobSet.ensureInit(nulls);

    // The keys the measured note references MUST be present, or checkNote returns early on
    // "missing-historical-root" / "missing-nullifier" and the number is the cost of an early
    // return rather than of the walk -- a measurement this audit has been caught by before.
    switch (StableBlobSet.put(roots, d1RootKey())) { case (#err(m)) return #err(m); case (#ok(_)) {} };
    var i : Nat = 0;
    while (i < 32) {
      switch (StableBlobSet.put(nulls, d1NullKey(i))) { case (#err(m)) return #err(m); case (#ok(_)) {} };
      i += 1;
    };

    i := 0;
    label fill while (i < filler) {
      switch (StableBlobSet.put(nulls, d1FillerKey(i))) { case (#err(m)) return #err(m); case (#ok(_)) {} };
      switch (StableBlobSet.put(roots, d1FillerKey(i))) { case (#err(m)) return #err(m); case (#ok(_)) {} };
      i += 1;
      if (
        leave_window_open and StableBlobSet.migrationActive(nulls)
        and Nat64.toNat(StableBlobSet.activeCapacity(nulls)) >= min_capacity
      ) break fill;
    };

    if (not leave_window_open) {
      while (StableBlobSet.migrationActive(nulls)) ignore StableBlobSet.advanceMigration(nulls, 1_048_576);
      while (StableBlobSet.migrationActive(roots)) ignore StableBlobSet.advanceMigration(roots, 1_048_576);
    };

    d1_roots := ?roots;
    d1_nulls := ?nulls;
    #ok((
      StableBlobSet.migrationActive(nulls),
      StableBlobSet.migrationActive(roots),
      StableBlobSet.size(nulls),
      Nat64.toNat(StableBlobSet.activeCapacity(nulls)),
    ))
  };

  /// One measured call of the PRODUCTION checkNote against the prepared sets.
  ///
  /// `anomalous` flips one byte of the frame's stored checksum. That is size-preserving, so the
  /// anomalous branch differs from the clean branch in COST only and never in bytes. It drives the
  /// referenceCheck fallback (NoteAudit.mo:299-302).
  ///
  /// Returns (instructions, encoded_bytes, outcome). The outcome string is returned so a truncated
  /// walk cannot be read as a full one: a clean call must report "ok".
  public func measure_check_note(ct_bytes : Nat, nulls : Nat, anomalous : Bool) : async Result<(Nat64, Nat, Text)> {
    let roots = switch (d1_roots) { case (?s) s; case null return #err("measure: call measure_prepare_sets first") };
    let nullset = switch (d1_nulls) { case (?s) s; case null return #err("measure: call measure_prepare_sets first") };
    if (nulls > 32) return #err("measure: nulls exceeds the 32 prepared keys");

    let block : NoteCodec.ShieldedNoteBlock = {
      btype = "zknote1";
      phash = null;
      encoding_version = 1;
      note_position = 0;
      commitment = canonicalBlob(1, 0);
      ephemeral_key = deterministicBlob(4, 0, 16);
      note_ciphertext = deterministicBlob(5, 0, ct_bytes);
      nullifiers = Array.tabulate<Blob>(nulls, func(j) { d1NullKey(j) });
      anchor_before = d1RootKey();
      note_root_after = d1RootKey();
      timestamp = Nat64.fromNat(1_784_246_400_000_000_000);
      origin = #shield;
    };
    let clean = switch (NoteCodec.encode(block)) {
      case (#ok(value)) value;
      case (#err(message)) return #err(message);
    };
    let encoded = if (not anomalous) clean else {
      let bytes = Blob.toArray(clean);
      Blob.fromArray(Array.tabulate<Nat8>(bytes.size(), func(j) { if (j == 16) bytes[j] ^ 0xFF else bytes[j] }))
    };

    // Warm the reused scratch buffer so a first-call ensureScratch growth is not attributed to the
    // measured call. The ledger reuses one Checker across a walk for the same reason.
    ignore d1_checker.checkNote(encoded, 0, null, roots, nullset);

    let c0 = Prim.performanceCounter(0);
    let outcome = d1_checker.checkNote(encoded, 0, null, roots, nullset);
    let c1 = Prim.performanceCounter(0);

    #ok((c1 - c0, encoded.size(), switch (outcome) { case (#ok(_)) "ok"; case (#err(message)) message }))
  };
}
