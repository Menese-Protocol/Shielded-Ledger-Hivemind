/// NEGATIVE CONTROL for `release_unfinalizable_unshield`'s accounting: the nullifier burn and
/// the `pool_value` debit each hold their own invariant, and neither carries the other.
///
/// The release burns two nullifiers and debits `pool_value` on the `#found` branch. Both are
/// load-bearing and for DIFFERENT reasons, and neither is obvious from reading the function:
///
///   * the burn stops a DOUBLE-SPEND. Nullifiers are recorded only in `finalizeUnshield`, so a
///     paid-but-unfinalized intent still has spendable input notes. Release without burning and
///     the user keeps the payout AND the notes.
///   * the debit preserves SOLVENCY. The money left the token ledger; if `pool_value` keeps
///     claiming it, the pool asserts custody of value it does not hold.
///
/// This enumerates the release's accounting over every combination of (payout happened?, burn
/// performed?, debit performed?) and checks both invariants, so each guard is shown to be the
/// thing that holds its own invariant rather than being carried by the other.
///
/// SCOPE, stated rather than implied. This checks the ACCOUNTING RULE the function implements.
/// It does not exercise the canister: the reconciliation branch is chosen here rather than read
/// from a token ledger, so `#error`-handling and the post-await re-read are not covered. Those
/// need a replica and are recorded as owed.
///
/// Runs as a WASI program (moc -wasi-system-api, wasmtime).
/// Menese DeFi Team.

import Prim "mo:⛔";
import Runtime "mo:core/Runtime";
import Nat "mo:core/Nat";

/// The pool's books and the world, after a release.
///   claimed   — what `pool_value` still asserts the pool holds
///   left      — what actually left the token ledger
///   spendable — whether the input notes can still be spent (nullifiers NOT burned)
type Books = { claimed : Nat; left : Nat; spendable : Bool };

let START : Nat = 1_000;
let DEBIT : Nat = 250;

/// The release's accounting, parameterised so each guard can be knocked out independently.
func release(payoutFound : Bool, doBurn : Bool, doDebit : Bool) : Books {
  var claimed = START;
  var left = 0;
  var spendable = true;
  if (payoutFound) {
    left := DEBIT;                                   // the money is gone from the token ledger
    if (doDebit) { claimed -= DEBIT };               // Main.mo: pool_value -= pending.pool_debit
    if (doBurn) { spendable := false };              // Main.mo: addNullifier x2
  };
  { claimed; left; spendable }
};

/// DOUBLE-SPEND: the payout happened AND the input notes are still spendable.
func doubleSpend(b : Books) : Bool { b.left > 0 and b.spendable };

/// INSOLVENT: the pool claims more than it can still hold after what left.
func insolvent(b : Books) : Bool { b.claimed > START - b.left };

// ---- GREEN: the release as implemented, both branches -----------------------------------------
let absent = release(false, false, false);
if (doubleSpend(absent)) { Runtime.trap("GREEN FAILED: #absent branch reports a double-spend") };
if (insolvent(absent)) { Runtime.trap("GREEN FAILED: #absent branch reports insolvency") };
if (not absent.spendable) {
  Runtime.trap("GREEN FAILED: #absent burned nullifiers -- no money moved, the notes must stay spendable");
};
Prim.debugPrint("GREEN #absent : nothing burned, nothing debited, notes stay spendable -- correct");

let found = release(true, true, true);
if (doubleSpend(found)) { Runtime.trap("GREEN FAILED: #found branch leaves a double-spend") };
if (insolvent(found)) { Runtime.trap("GREEN FAILED: #found branch leaves the pool insolvent") };
Prim.debugPrint(
  "GREEN #found  : claimed " # Nat.toText(found.claimed) # ", left " # Nat.toText(found.left)
  # ", notes burned -- no double-spend, solvent"
);

// ---- NEGATIVE 1: drop the burn. Must produce a double-spend. ---------------------------------
let noBurn = release(true, false, true);
if (not doubleSpend(noBurn)) {
  Runtime.trap(
    "ACCOUNTING NEGATIVE CONTROL FAILED: removing the nullifier burn did NOT produce a "
    # "double-spend, so the "
    # "burn is not what prevents one and this control has no teeth"
  );
};
Prim.debugPrint("NEGATIVE 1 : burn removed -> payout left AND notes still spendable = DOUBLE-SPEND, as required");

// ---- NEGATIVE 2: drop the debit. Must produce insolvency. ------------------------------------
let noDebit = release(true, true, false);
if (not insolvent(noDebit)) {
  Runtime.trap(
    "ACCOUNTING NEGATIVE CONTROL FAILED: removing the pool_value debit did NOT produce "
    # "insolvency, so the "
    # "debit is not what preserves it"
  );
};
Prim.debugPrint(
  "NEGATIVE 2 : debit removed -> pool claims " # Nat.toText(noDebit.claimed) # " but only "
  # Nat.toText(START - noDebit.left) # " remains = INSOLVENT, as required"
);

// ---- The two guards are INDEPENDENT: neither covers for the other -----------------------------
if (insolvent(noBurn)) {
  Runtime.trap("the burn knockout also broke solvency -- the two invariants are not separated");
};
if (doubleSpend(noDebit)) {
  Runtime.trap("the debit knockout also produced a double-spend -- the two invariants are not separated");
};
Prim.debugPrint("SEPARATION: each knockout breaks its OWN invariant and only its own");

Prim.debugPrint(
  "PASS ReleaseSolvencyNegativeControl: the accounting is separated -- the burn prevents "
  # "the double-spend, the debit preserves solvency, and neither carries the other"
);
