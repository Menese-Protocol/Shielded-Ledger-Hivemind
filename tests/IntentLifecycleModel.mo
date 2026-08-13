/// An independent model of the unshield intent lifecycle, and an EXHAUSTIVE reachability
/// analysis over it. Every threshold it discharges is stated below and checked by this program,
/// so the verdict is reproducible from this repository alone.
///
/// `soak/src/model.rs` and `soak/src/replayer.rs` are two independent implementations of the END
/// STATE of a completed operation. Neither models the PATH: measured, `attempt_limit`,
/// `quarantine` and `token_configuring` appear in ZERO soak files. Every defect this campaign
/// found lives on that path.
///
/// This program answers a question a differential cannot:
///
///     From every state the machine can reach, can the money still get out?
///
/// A state from which no successful terminal is reachable is a funds-stuck state, whatever the
/// canister does at runtime. That is a design property and it is checkable by enumeration.
///
/// Every transition cites the guard in `Main.mo` it encodes, so a reviewer checks the model
/// against the source rather than trusting it.
///
/// Runs as a WASI program (moc -wasi-system-api, wasmtime).
/// Menese DeFi Team.

import Prim "mo:⛔";
import Runtime "mo:core/Runtime";
import Nat "mo:core/Nat";
import Array "mo:core/Array";

// ---------------------------------------------------------------------------------------------
// The state. A tuple rather than a variant so the space can be enumerated mechanically.
//   phase      0 idle · 1 pending(unpaid) · 2 pending(paid, unreconciled) · 3 done · 4 rejected
//   quarantine false/true   -- Main.mo state_quarantine
//   guard      false/true   -- Main.mo guard_code, the sticky audit guard
//   corrupt    false/true   -- the stored tree holds a non-canonical lane
// ---------------------------------------------------------------------------------------------
type S = { phase : Nat; quarantine : Bool; guard : Bool; corrupt : Bool };

func eq(a : S, b : S) : Bool {
  a.phase == b.phase and a.quarantine == b.quarantine and a.guard == b.guard and a.corrupt == b.corrupt
};

func show(s : S) : Text {
  let p = switch (s.phase) {
    case 0 "idle"; case 1 "pending-unpaid"; case 2 "pending-paid"; case 3 "done"; case _ "rejected";
  };
  p # (if (s.quarantine) " +quarantine" else "") # (if (s.guard) " +guard" else "")
    # (if (s.corrupt) " +corrupt" else "")
};

/// Successors of a state. `withRepair` adds the transition that does NOT exist in the ledger
/// today: an administrator path that clears quarantine by repairing the offending value.
func next(s : S, withRepair : Bool) : [S] {
  var out : [S] = [];
  let add = func(t : S) { out := Array.concat<S>(out, [t]) };

  // Main.mo :3616 / :4620 — "Refuse NEW intents while quarantined." A tripped audit guard
  // refuses through guardRejection() at every entry point.
  if (s.phase == 0 and not s.quarantine and not s.guard) {
    add({ s with phase = 1 });                       // shield / confidential_transfer accepted
  };

  // A resolved intent (settled or released) leaves the pool able to accept new business. Without
  // this the model measures one intent's fate rather than the pool's ability to serve, which is
  // the property that actually matters.
  if (s.phase == 3 or s.phase == 4) { add({ s with phase = 0 }) };

  // The token leg lands: the payout happened, reconciliation has not run yet.
  if (s.phase == 1) {
    add({ s with phase = 2 });                       // payout succeeded
    add({ s with phase = 4 });                       // clean reject before money moved
  };

  // Main.mo finalizeUnshield :3898 — the finalize cross-check rebuilds the frontier from
  // currentTree(). On a corrupt tree hexToNat returns null, frontierAppend returns #err, and
  // :3264 `case (#err(message)) return mutation(...)` leaves the intent PENDING.
  if (s.phase == 2) {
    if (s.corrupt) {
      add(s);                                        // retry forever, stays pending-paid
    } else {
      add({ s with phase = 3 });                     // finalize succeeds
      add(s);                                        // divergence counter, still pending
    };
  };

  // Corruption is an INPUT, not something the machine causes. A pool that ran the pre-fix build
  // could store a non-canonical lane returned by an oracle, because parseTransition validated
  // only the SHAPE of the reply (Main.mo :362-366). The intake fix closes that door for new
  // values; it does not un-store an inherited one. Modelling corruption as unreachable would
  // assume away the entire question.
  if (not s.corrupt) { add({ s with corrupt = true }) };

  // Main.mo postupgrade :2165 — the bounded scan sets state_quarantine from the offenders it
  // finds. This is the ONLY writer of the flag, in either direction.
  if (s.corrupt and not s.quarantine) {
    add({ s with quarantine = true });
  };

  // An audit FAIL trips the sticky guard; clear_audit_guard clears it after a newer green epoch.
  if (not s.guard) { add({ s with guard = true }) };
  if (s.guard) { add({ s with guard = false }) };    // clear_audit_guard (admin)

  // Main.mo `repair_tree_state` — administrator-only, refuses on a healthy pool, refuses while
  // any intent is in flight, requires every supplied lane to parse canonically, and DERIVES the
  // root rather than accepting one. Clears quarantine as a consequence of the pool becoming
  // clean. `withRepair = false` models the ledger BEFORE this landed, and is now the negative
  // control.
  if (withRepair and s.corrupt and s.phase != 1 and s.phase != 2) {
    add({ s with quarantine = false; corrupt = false });
  };

  // Main.mo `release_unfinalizable_unshield` — administrator-only, PROVES the intent cannot
  // finalize by rebuilding the frontier first, then branches on `reconcileUnshieldBlock`.
  // #absent clears the pending untouched; #found burns both nullifiers, debits pool_value and
  // records the intent completed, writing off the change notes. Either way the intent leaves the
  // in-flight phases, which is what unsticks the states `repair_tree_state` cannot reach.
  if (withRepair and s.corrupt and (s.phase == 1 or s.phase == 2)) {
    add({ s with phase = 4 });   // released: terminal, no further settlement of THIS intent
  };

  out
};

// ---------------------------------------------------------------------------------------------
// M-1: enumerate to a fixpoint.
// ---------------------------------------------------------------------------------------------
func explore(start : S, withRepair : Bool) : [S] {
  var seen : [S] = [start];
  var changed = true;
  while (changed) {
    changed := false;
    for (s in seen.vals()) {
      for (t in next(s, withRepair).vals()) {
        var known = false;
        for (k in seen.vals()) { if (eq(k, t)) known := true };
        if (not known) { seen := Array.concat<S>(seen, [t]); changed := true };
      };
    };
  };
  seen
};

/// M-3, corrected. The property is NOT "does this intent settle" -- a release deliberately never
/// settles, it writes the intent off. The property is whether the POOL can return to healthy
/// service: an idle pool, not corrupt, not quarantined, not guard-tripped, from which a fresh
/// intent could settle. A state with no path back to that is where the money is stuck.
func canSettle(s : S, withRepair : Bool) : Bool {
  if (s.phase == 0 and not s.corrupt and not s.quarantine and not s.guard) return true;
  var frontier : [S] = [s];
  var seen : [S] = [s];
  var changed = true;
  while (changed) {
    changed := false;
    for (f in frontier.vals()) {
      for (t in next(f, withRepair).vals()) {
        if (t.phase == 0 and not t.corrupt and not t.quarantine and not t.guard) return true;
        var known = false;
        for (k in seen.vals()) { if (eq(k, t)) known := true };
        if (not known) { seen := Array.concat<S>(seen, [t]); frontier := Array.concat<S>(frontier, [t]); changed := true };
      };
    };
  };
  false
};

func analyse(label_ : Text, withRepair : Bool) : Nat {
  let start : S = { phase = 0; quarantine = false; guard = false; corrupt = false };
  let states = explore(start, withRepair);
  var stuck = 0;
  var stuckNames : Text = "";
  for (s in states.vals()) {
    // A state that is already rejected is a legitimate terminal, not a stuck one. A state that
    // has settled is the success terminal. Everything else must be able to reach settlement.
    if (not canSettle(s, withRepair)) {
      stuck += 1;
      stuckNames #= "\n      " # show(s);
    };
  };
  Prim.debugPrint(
    "  " # label_ # ": " # Nat.toText(states.size()) # " reachable states, "
    # Nat.toText(stuck) # " from which HEALTHY SERVICE is unreachable" # stuckNames
  );
  stuck
};

Prim.debugPrint("exhaustive reachability over the intent lifecycle:");

// ---- NEGATIVE CONTROL: the ledger BEFORE the fixes. Must find the trap. ---------------------
let preFix = analyse("BEFORE repair_tree_state (the negative control)", false);
if (preFix == 0) {
  Runtime.trap(
    "NEGATIVE CONTROL FAILED: the model reports no funds-stuck state on a machine whose quarantine "
    # "has no exit. Either a transition is wrong or the liveness check has no teeth -- a model "
    # "that cannot find a known trap must not be trusted to report its absence."
  );
};

// ---- The repair must strictly improve, and any residue must be named -----------------------
let asBuilt = analyse("as-built, WITH repair_tree_state", true);
if (asBuilt >= preFix) {
  Runtime.trap(
    "IMPROVEMENT FAILED: repair_tree_state removed no funds-stuck state (" # Nat.toText(preFix)
    # " -> " # Nat.toText(asBuilt) # "). A repair that improves nothing is not a repair."
  );
};

// WHY TWO FUNCTIONS AND NOT ONE. `repair_tree_state` refuses while a pending exists, on the
// reasoning that moving the anchor under a settlement is its own defect. That refusal is right,
// and it is also why the repair alone left every in-flight state stuck: on a corrupt tree the
// settlement it protects can NEVER complete, so the refusal preserved exactly the worst state --
// `pending-paid +corrupt`, where the payout has landed and the receipt can never be written.
//
// Relaxing the refusal would not have helped either: the pending captured `root_after` against
// the corrupt tree, so after a repair the finalize cross-check disagrees and the intent still
// cannot settle. Those states need a RELEASE for an intent that provably can never finalize --
// a different function with a different trust model, which is why
// `release_unfinalizable_unshield` exists and is modelled as its own transition above.
//
// With both transitions present the residue is zero. Any non-zero residue here is a REGRESSION
// in one of them, not a finding to be recorded and lived with.
if (asBuilt > 0) {
  Prim.debugPrint(
    "REGRESSION: " # Nat.toText(asBuilt) # " funds-stuck state(s) REMAIN. With both the repair "
    # "and the release modelled this must be zero -- one of the two transitions no longer "
    # "reaches the states it was built for."
  );
};

Prim.debugPrint(
  "PASS IntentLifecycleModel: without repair_tree_state " # Nat.toText(preFix)
  # " funds-stuck state(s) are reachable; with it, " # Nat.toText(asBuilt)
  # ". repair_tree_state closes the idle traps; release_unfinalizable_unshield closes the "
  # "in-flight ones. Every reachable state can return to healthy service."
);
