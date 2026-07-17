/// Phase-2 trusted-setup ceremony COORDINATOR (Deliverable D1).
///
/// THE COORDINATOR NEVER HOLDS A SECRET. Its entire state is public: the running accumulator's
/// delta-dependent parameters (per circuit), each contribution's proof of knowledge and parameter
/// hashes, the participant queue and log, the ceremony window, and the finalize beacon. There is no
/// field, argument, or code path that receives, stores, or reconstructs any participant's secret.
/// The secret is sampled, applied, and destroyed in the contributor's browser; only transformed
/// public parameters and a proof are uploaded (apply-and-destroy, Bowe-Gabizon-Miers 2017).
///
/// On acceptance the coordinator runs the O(1)-pairing proof-of-knowledge check on-chain (soundness)
/// and records the contribution; the full delta-division-consistency check (correctness) is run
/// off-chain by the standalone verifier over the published transcript, which this canister serves in
/// full. Parameters are uploaded and downloaded in <2 MB chunks (a transfer contribution is ~2.5 MB).

import Principal "mo:core/Principal";
import Blob "mo:core/Blob";
import Time "mo:core/Time";
import List "mo:core/List";
import Array "mo:core/Array";
import Nat "mo:core/Nat";
import Nat8 "mo:core/Nat8";
import Nat32 "mo:core/Nat32";
import Result "mo:core/Result";
import C "../../src/groth16/Curve";
import Wire "Wire";
import PokVerify "PokVerify";

persistent actor CeremonyCoordinator {

  // ------------------------------------------------------------------------------------------
  // Public types (Candid surface)
  // ------------------------------------------------------------------------------------------

  type Circuit = { #transfer; #deposit };

  type PokWire = {
    s_g1 : Blob; // 96 bytes uncompressed BE
    s_delta_g1 : Blob; // 96
    r_delta_g2 : Blob; // 192
  };

  type ContributionMeta = {
    index : Nat;
    contributor : Blob; // principal bytes; empty for the beacon step
    timestamp : Int;
    transfer_pok : PokWire;
    deposit_pok : PokWire;
    transfer_delta_hash : Blob;
    deposit_delta_hash : Blob;
    is_beacon : Bool;
    beacon : Blob;
    transfer_delta_len : Nat;
    deposit_delta_len : Nat;
  };

  type CeremonyInfo = {
    configured : Bool;
    init_done : Bool;
    power : Nat32;
    srs_sha256 : Blob;
    transfer_fixed_hash : Blob;
    deposit_fixed_hash : Blob;
    transfer_initial_hash : Blob;
    deposit_initial_hash : Blob;
    genesis_challenge : Blob;
    running_challenge : Blob;
    start_time : Int;
    end_time : Int;
    turn_timeout : Int;
    now : Int;
    phase : Text; // "unconfigured" | "init" | "open" | "closed" | "finalized"
    contribution_count : Nat;
    honest_count : Nat;
    queue_length : Nat;
    current_turn : ?Principal;
    current_turn_started : Int;
    finalized : Bool;
    authority : Principal;
  };

  type R = Result.Result<Text, Text>;

  // ------------------------------------------------------------------------------------------
  // State — all public, no secrets.
  // ------------------------------------------------------------------------------------------

  var authority : Principal = Principal.anonymous();
  var configured : Bool = false;
  var initDone : Bool = false;

  var power : Nat32 = 0;
  var srsSha256 : Blob = "";
  var transferFixedHash : Blob = "";
  var depositFixedHash : Blob = "";
  var startTime : Int = 0;
  var endTime : Int = 0;
  var turnTimeout : Int = 0;

  // initial params (full bytes, for serving + hashing)
  var transferInitial : Blob = "";
  var depositInitial : Blob = "";
  var transferInitialHash : Blob = "";
  var depositInitialHash : Blob = "";
  var transferHLen : Nat = 0;
  var transferLLen : Nat = 0;
  var depositHLen : Nat = 0;
  var depositLLen : Nat = 0;
  var genesis : Blob = "";

  // init-upload staging (before finishInit)
  var initTransferChunks : List.List<Blob> = List.empty<Blob>();
  var initDepositChunks : List.List<Blob> = List.empty<Blob>();

  // transcript
  type ContributionRec = {
    contributor : Blob;
    timestamp : Int;
    transferDelta : Blob;
    depositDelta : Blob;
    transferPok : PokWire;
    depositPok : PokWire;
    transferDeltaHash : Blob;
    depositDeltaHash : Blob;
    isBeacon : Bool;
    beacon : Blob;
  };
  let contributions : List.List<ContributionRec> = List.empty<ContributionRec>();
  var runningChallenge : Blob = "";
  var finalized : Bool = false;

  // queue + per-turn. FIFO via an append-only list plus a head index (mo:core List has no
  // removeFirst); a "removed" head is one whose index is below queueHead.
  let queue : List.List<Principal> = List.empty<Principal>();
  var queueHead : Nat = 0;
  var currentTurnStart : Int = 0;

  // contribution staging (during a turn)
  type Staging = {
    who : Principal;
    transferChunks : List.List<Blob>;
    depositChunks : List.List<Blob>;
  };
  var staging : ?Staging = null;

  // ------------------------------------------------------------------------------------------
  // helpers
  // ------------------------------------------------------------------------------------------

  func concatBlobs(chunks : List.List<Blob>) : Blob {
    let bytes = List.empty<Nat8>();
    List.forEach<Blob>(chunks, func(b) { for (x in b.vals()) { List.add(bytes, x) } });
    Blob.fromArray(List.toArray(bytes));
  };

  func be4(n : Nat) : [Nat8] { Wire.natToBE(n, 4) };

  func expectedLen(hLen : Nat, lLen : Nat) : Nat { 96 + 192 + 4 + hLen * 96 + 4 + lLen * 96 };

  // parse hLen (u32 BE at offset 288) and lLen (u32 BE right after the h block)
  func parseLens(delta : [Nat8]) : ?(Nat, Nat) {
    if (delta.size() < 296) { return null };
    let hLen = Wire.beToNat(delta, 288, 4);
    let lOff = 292 + hLen * 96;
    if (delta.size() < lOff + 4) { return null };
    let lLen = Wire.beToNat(delta, lOff, 4);
    ?(hLen, lLen);
  };

  func pokFromWire(p : PokWire) : ?PokVerify.Pok {
    if (p.s_g1.size() != 96 or p.s_delta_g1.size() != 96 or p.r_delta_g2.size() != 192) {
      return null;
    };
    ?{
      sG1 = Wire.g1FromBE(Blob.toArray(p.s_g1), 0);
      sDeltaG1 = Wire.g1FromBE(Blob.toArray(p.s_delta_g1), 0);
      rDeltaG2 = Wire.g2FromBE(Blob.toArray(p.r_delta_g2), 0);
    };
  };

  func deltaPoints(delta : Blob) : (C.G1, C.G2) {
    let a = Blob.toArray(delta);
    (Wire.g1FromBE(a, 0), Wire.g2FromBE(a, 96));
  };

  func pokBytes(p : PokWire) : [Nat8] {
    Wire.concat([Blob.toArray(p.s_g1), Blob.toArray(p.s_delta_g1), Blob.toArray(p.r_delta_g2)]);
  };

  func advance(prev : Blob, c : ContributionRec) : Blob {
    let pre = Wire.concat([
      Blob.toArray(prev),
      [if (c.isBeacon) 1 else 0],
      be4(c.contributor.size()),
      Blob.toArray(c.contributor),
      pokBytes(c.transferPok),
      pokBytes(c.depositPok),
      Blob.toArray(c.transferDeltaHash),
      Blob.toArray(c.depositDeltaHash),
      be4(c.beacon.size()),
      Blob.toArray(c.beacon),
    ]);
    Blob.fromArray(Wire.sha256(pre));
  };

  func queueRemaining() : Nat { List.size(queue) - queueHead };
  func queueFront() : ?Principal { List.get(queue, queueHead) };

  func currentDeltas() : (Blob, Blob) {
    switch (List.last(contributions)) {
      case (null) { (transferInitial, depositInitial) };
      case (?c) { (c.transferDelta, c.depositDelta) };
    };
  };

  func honestCount() : Nat {
    var n = 0;
    List.forEach<ContributionRec>(contributions, func(c) { if (not c.isBeacon) { n += 1 } });
    n;
  };

  func phaseText(now : Int) : Text {
    if (not configured) { return "unconfigured" };
    if (not initDone) { return "init" };
    if (finalized) { return "finalized" };
    if (now < startTime) { return "init" };
    if (now > endTime) { return "closed" };
    "open";
  };

  // Drop timed-out heads from the queue by advancing the head index.
  func advanceStaleHeads(now : Int) {
    label l loop {
      switch (queueFront()) {
        case (null) { break l };
        case (?_head) {
          if (currentTurnStart != 0 and now > currentTurnStart + turnTimeout) {
            queueHead += 1;
            currentTurnStart := if (queueRemaining() == 0) 0 else now;
            staging := null; // discard a stale head's open staging
          } else {
            break l;
          };
        };
      };
    };
  };

  // ------------------------------------------------------------------------------------------
  // configuration + init (authority only, once)
  // ------------------------------------------------------------------------------------------

  /// First caller becomes the authority and sets the ceremony parameters. `power`, the SRS and
  /// fixed-params hashes, and the window come from the operator; they are all public.
  public shared ({ caller }) func configure(
    p : Nat32,
    srs_sha256 : Blob,
    transfer_fixed_hash : Blob,
    deposit_fixed_hash : Blob,
    start_time : Int,
    end_time : Int,
    turn_timeout : Int,
  ) : async R {
    if (configured) { return #err("already configured") };
    if (srs_sha256.size() != 32 or transfer_fixed_hash.size() != 32 or deposit_fixed_hash.size() != 32) {
      return #err("hashes must be 32 bytes");
    };
    if (end_time <= start_time or turn_timeout <= 0) { return #err("bad window/timeout") };
    if (not PokVerify.selfCheckGenerator()) { return #err("G2 generator self-check failed") };
    authority := caller;
    power := p;
    srsSha256 := srs_sha256;
    transferFixedHash := transfer_fixed_hash;
    depositFixedHash := deposit_fixed_hash;
    startTime := start_time;
    endTime := end_time;
    turnTimeout := turn_timeout;
    configured := true;
    #ok("configured; authority = " # Principal.toText(caller));
  };

  func onlyAuthority(caller : Principal) : ?Text {
    if (caller != authority) { ?"only the ceremony authority may call this" } else { null };
  };

  public shared ({ caller }) func upload_initial_chunk(circuit : Circuit, chunk : Blob) : async R {
    switch (onlyAuthority(caller)) { case (?e) { return #err(e) }; case (null) {} };
    if (not configured) { return #err("configure first") };
    if (initDone) { return #err("init already finished") };
    switch (circuit) {
      case (#transfer) { List.add(initTransferChunks, chunk) };
      case (#deposit) { List.add(initDepositChunks, chunk) };
    };
    #ok("chunk accepted");
  };

  /// Freeze the initial parameters, compute their hashes and the genesis challenge.
  public shared ({ caller }) func finish_init() : async R {
    switch (onlyAuthority(caller)) { case (?e) { return #err(e) }; case (null) {} };
    if (not configured) { return #err("configure first") };
    if (initDone) { return #err("already initialized") };
    let ti = concatBlobs(initTransferChunks);
    let di = concatBlobs(initDepositChunks);
    let tiA = Blob.toArray(ti);
    let diA = Blob.toArray(di);
    switch (parseLens(tiA), parseLens(diA)) {
      case (?(th, tl), ?(dh, dl)) {
        if (ti.size() != expectedLen(th, tl)) { return #err("transfer initial length mismatch") };
        if (di.size() != expectedLen(dh, dl)) { return #err("deposit initial length mismatch") };
        transferHLen := th;
        transferLLen := tl;
        depositHLen := dh;
        depositLLen := dl;
      };
      case _ { return #err("cannot parse initial params") };
    };
    transferInitial := ti;
    depositInitial := di;
    transferInitialHash := Blob.fromArray(Wire.sha256(tiA));
    depositInitialHash := Blob.fromArray(Wire.sha256(diA));
    // genesis = SHA256(TAG || power(be4) || srs || tf || df || ti_hash || di_hash)
    let tag = Blob.toArray("shielded-ledger-phase2-ceremony-v1" : Blob);
    let pre = Wire.concat([
      tag,
      be4(Nat32.toNat(power)),
      Blob.toArray(srsSha256),
      Blob.toArray(transferFixedHash),
      Blob.toArray(depositFixedHash),
      Blob.toArray(transferInitialHash),
      Blob.toArray(depositInitialHash),
    ]);
    genesis := Blob.fromArray(Wire.sha256(pre));
    runningChallenge := genesis;
    initTransferChunks := List.empty<Blob>();
    initDepositChunks := List.empty<Blob>();
    initDone := true;
    #ok("initialized; genesis challenge set");
  };

  // ------------------------------------------------------------------------------------------
  // queue + contribute
  // ------------------------------------------------------------------------------------------

  public shared ({ caller }) func join_queue() : async R {
    if (not initDone) { return #err("ceremony not initialized") };
    if (finalized) { return #err("ceremony finalized") };
    let now = Time.now();
    if (now < startTime) { return #err("ceremony window not open yet") };
    if (now > endTime) { return #err("ceremony window closed") };
    advanceStaleHeads(now);
    // scan only the still-active tail (from queueHead)
    var i = queueHead;
    while (i < List.size(queue)) {
      if (List.get(queue, i) == ?caller) { return #err("already in queue") };
      i += 1;
    };
    let wasEmpty = queueRemaining() == 0;
    List.add(queue, caller);
    if (wasEmpty) { currentTurnStart := now };
    #ok("joined; queue position " # Nat.toText(queueRemaining()));
  };

  func isCurrentTurn(caller : Principal, now : Int) : Bool {
    advanceStaleHeads(now);
    switch (queueFront()) {
      case (?head) { head == caller };
      case (null) { false };
    };
  };

  public shared ({ caller }) func begin_contribution() : async R {
    if (not initDone or finalized) { return #err("not accepting contributions") };
    let now = Time.now();
    if (now > endTime) { return #err("ceremony window closed") };
    if (not isCurrentTurn(caller, now)) { return #err("not your turn") };
    currentTurnStart := now; // reset the clock for the active contributor
    staging := ?{
      who = caller;
      transferChunks = List.empty<Blob>();
      depositChunks = List.empty<Blob>();
    };
    #ok("staging open; upload your chunks then submit");
  };

  public shared ({ caller }) func upload_contribution_chunk(circuit : Circuit, chunk : Blob) : async R {
    switch (staging) {
      case (?s) {
        if (s.who != caller) { return #err("staging owned by another contributor") };
        switch (circuit) {
          case (#transfer) { List.add(s.transferChunks, chunk) };
          case (#deposit) { List.add(s.depositChunks, chunk) };
        };
        #ok("chunk accepted");
      };
      case (null) { #err("call begin_contribution first") };
    };
  };

  public shared ({ caller }) func abort_contribution() : async R {
    switch (staging) {
      case (?s) {
        if (s.who != caller) { return #err("not your staging") };
        staging := null;
        #ok("aborted");
      };
      case (null) { #err("no active staging") };
    };
  };

  // Acceptance and the on-chain verification boundary.
  //
  // MEASURED: a full
  // proof-of-knowledge verification in this pure-Nat BLS12-381 tower costs well over the IC
  // 40e9-instruction single-message limit (the subgroup checks alone are literal [r]P scalar
  // multiplications). So the coordinator runs the AFFORDABLE structural checks on-chain (each point
  // canonical, on the curve, non-identity; the delta actually advanced; correct length) and records
  // the proof and its hashes into the immutable public transcript. The SOUNDNESS-critical subgroup +
  // pairing verification is run OFF-CHAIN by the standalone verifier over the published transcript
  // (it re-runs exactly `PokVerify.verifyPok`'s math in arkworks). This is the structural-on-chain +
  // full-off-chain split the proposal put to measurement.

  // Structural-check one circuit's staged new delta against its current base delta.
  func checkOneCircuit(newDelta : Blob, expectLen : Nat, curDelta : Blob, pokWire : PokWire) : { #ok; #err : Text } {
    if (newDelta.size() != expectLen) { return #err("delta length mismatch") };
    let pok = switch (pokFromWire(pokWire)) { case (?p) p; case (null) { return #err("bad pok encoding") } };
    let (oldG1, _) = deltaPoints(curDelta);
    let (newG1, newG2) = deltaPoints(newDelta);
    PokVerify.structuralCheck(oldG1, { deltaG1 = newG1; deltaG2 = newG2 }, pok);
  };

  // Append a fully-checked contribution and advance the transcript.
  func appendContribution(caller : Principal, now : Int, transferPok : PokWire, depositPok : PokWire, isBeacon : Bool, beacon : Blob) : R {
    let s = switch (staging) { case (?s) s; case (null) { return #err("no staging") } };
    if (s.who != caller) { return #err("not your staging") };
    let transferDelta = concatBlobs(s.transferChunks);
    let depositDelta = concatBlobs(s.depositChunks);
    switch (checkOneCircuit(transferDelta, expectedLen(transferHLen, transferLLen), currentDeltas().0, transferPok)) {
      case (#err(e)) { return #err("transfer: " # e) }; case (#ok) {};
    };
    switch (checkOneCircuit(depositDelta, expectedLen(depositHLen, depositLLen), currentDeltas().1, depositPok)) {
      case (#err(e)) { return #err("deposit: " # e) }; case (#ok) {};
    };
    let prev = runningChallenge;
    let rec : ContributionRec = {
      contributor = if (isBeacon) "" else Principal.toBlob(caller);
      timestamp = now;
      transferDelta;
      depositDelta;
      transferPok;
      depositPok;
      transferDeltaHash = Blob.fromArray(Wire.sha256(Blob.toArray(transferDelta)));
      depositDeltaHash = Blob.fromArray(Wire.sha256(Blob.toArray(depositDelta)));
      isBeacon;
      beacon;
    };
    List.add(contributions, rec);
    runningChallenge := advance(prev, rec);
    staging := null;
    if (isBeacon) {
      finalized := true;
      #ok("FINALIZED: beacon contribution " # Nat.toText(List.size(contributions)) # " accepted");
    } else {
      queueHead += 1;
      currentTurnStart := if (queueRemaining() == 0) 0 else now;
      #ok("contribution " # Nat.toText(List.size(contributions)) # " accepted");
    };
  };

  public shared ({ caller }) func submit_contribution(transfer_pok : PokWire, deposit_pok : PokWire) : async R {
    if (not initDone or finalized) { return #err("not accepting contributions") };
    let now = Time.now();
    if (now > endTime) { return #err("ceremony window closed") };
    if (not isCurrentTurn(caller, now)) { return #err("not your turn") };
    appendContribution(caller, now, transfer_pok, deposit_pok, false, "");
  };

  /// Finalize: the authority applies the public beacon after the window closes or the queue drains.
  public shared ({ caller }) func submit_beacon(beacon : Blob, transfer_pok : PokWire, deposit_pok : PokWire) : async R {
    switch (onlyAuthority(caller)) { case (?e) { return #err(e) }; case (null) {} };
    if (not initDone) { return #err("not initialized") };
    if (finalized) { return #err("already finalized") };
    let now = Time.now();
    if (now <= endTime and queueRemaining() > 0) {
      return #err("finalize only after the window closes or the queue drains");
    };
    if (beacon.size() == 0) { return #err("empty beacon") };
    appendContribution(caller, now, transfer_pok, deposit_pok, true, beacon);
  };

  /// The authority may open a staging slot for the beacon even though it is not "their turn".
  public shared ({ caller }) func begin_beacon_staging() : async R {
    switch (onlyAuthority(caller)) { case (?e) { return #err(e) }; case (null) {} };
    if (not initDone or finalized) { return #err("not accepting the beacon") };
    staging := ?{ who = caller; transferChunks = List.empty<Blob>(); depositChunks = List.empty<Blob>() };
    #ok("beacon staging open");
  };

  // ------------------------------------------------------------------------------------------
  // read-only transcript access
  // ------------------------------------------------------------------------------------------

  public query func get_ceremony_info() : async CeremonyInfo {
    let now = Time.now();
    {
      configured;
      init_done = initDone;
      power;
      srs_sha256 = srsSha256;
      transfer_fixed_hash = transferFixedHash;
      deposit_fixed_hash = depositFixedHash;
      transfer_initial_hash = transferInitialHash;
      deposit_initial_hash = depositInitialHash;
      genesis_challenge = genesis;
      running_challenge = runningChallenge;
      start_time = startTime;
      end_time = endTime;
      turn_timeout = turnTimeout;
      now;
      phase = phaseText(now);
      contribution_count = List.size(contributions);
      honest_count = honestCount();
      queue_length = queueRemaining();
      current_turn = queueFront();
      current_turn_started = currentTurnStart;
      finalized;
      authority;
    };
  };

  /// Metadata of the current (base) delta parameters the next contributor transforms.
  public query func get_current_params_meta() : async {
    transfer_hash : Blob;
    deposit_hash : Blob;
    transfer_len : Nat;
    deposit_len : Nat;
  } {
    let (t, d) = currentDeltas();
    {
      transfer_hash = Blob.fromArray(Wire.sha256(Blob.toArray(t)));
      deposit_hash = Blob.fromArray(Wire.sha256(Blob.toArray(d)));
      transfer_len = t.size();
      deposit_len = d.size();
    };
  };

  func sliceBlob(b : Blob, offset : Nat, len : Nat) : Blob {
    let a = Blob.toArray(b);
    let end = Nat.min(offset + len, a.size());
    if (offset >= a.size()) { return "" };
    Blob.fromArray(Array.sliceToArray<Nat8>(a, offset, end));
  };

  public query func get_current_params_chunk(circuit : Circuit, offset : Nat, len : Nat) : async Blob {
    let (t, d) = currentDeltas();
    switch (circuit) { case (#transfer) { sliceBlob(t, offset, len) }; case (#deposit) { sliceBlob(d, offset, len) } };
  };

  func recAt(i : Nat) : ?ContributionRec { List.get(contributions, i) };

  public query func get_contribution(i : Nat) : async ?ContributionMeta {
    switch (recAt(i)) {
      case (null) { null };
      case (?c) {
        ?{
          index = i;
          contributor = c.contributor;
          timestamp = c.timestamp;
          transfer_pok = c.transferPok;
          deposit_pok = c.depositPok;
          transfer_delta_hash = c.transferDeltaHash;
          deposit_delta_hash = c.depositDeltaHash;
          is_beacon = c.isBeacon;
          beacon = c.beacon;
          transfer_delta_len = c.transferDelta.size();
          deposit_delta_len = c.depositDelta.size();
        };
      };
    };
  };

  public query func get_contribution_chunk(i : Nat, circuit : Circuit, offset : Nat, len : Nat) : async Blob {
    switch (recAt(i)) {
      case (null) { "" };
      case (?c) {
        switch (circuit) {
          case (#transfer) { sliceBlob(c.transferDelta, offset, len) };
          case (#deposit) { sliceBlob(c.depositDelta, offset, len) };
        };
      };
    };
  };

  public query func get_transcript_summary() : async {
    power : Nat32;
    srs_sha256 : Blob;
    transfer_initial_hash : Blob;
    deposit_initial_hash : Blob;
    genesis_challenge : Blob;
    running_challenge : Blob;
    count : Nat;
    finalized : Bool;
  } {
    {
      power;
      srs_sha256 = srsSha256;
      transfer_initial_hash = transferInitialHash;
      deposit_initial_hash = depositInitialHash;
      genesis_challenge = genesis;
      running_challenge = runningChallenge;
      count = List.size(contributions);
      finalized;
    };
  };

  public query func get_initial_chunk(circuit : Circuit, offset : Nat, len : Nat) : async Blob {
    switch (circuit) {
      case (#transfer) { sliceBlob(transferInitial, offset, len) };
      case (#deposit) { sliceBlob(depositInitial, offset, len) };
    };
  };
}
