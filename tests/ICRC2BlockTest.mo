import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Debug "mo:core/Debug";
import Nat64 "mo:core/Nat64";
import Principal "mo:core/Principal";
import Runtime "mo:core/Runtime";
import ICRC2 "../src/ICRC2";
import ICRC2Block "../src/ICRC2Block";
import ICRC1Block "../src/ICRC1Block";
import ICRC3 "../src/ICRC3";
import Ckbtc "CkbtcBlockVectors";

let spender = Principal.fromText("aaaaa-aa");
let owner = Principal.fromText("2vxsx-fae");
let subaccount = Blob.fromArray([
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
]);
let memo = Blob.fromArray([
  9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
  9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
]);
let badMemo = Blob.fromArray([
  8, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
  9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
]);
let args : ICRC2.TransferFromArgs = {
  spender_subaccount = null;
  from = { owner; subaccount = ?subaccount };
  to = { owner = spender; subaccount = null };
  amount = 70;
  fee = ?10_000;
  memo = ?memo;
  created_at_time = ?1_700_000_000_000_000_000;
};

func account(account : ICRC2.Account) : ICRC3.Value {
  switch (account.subaccount) {
    case (?sub) #Array([#Blob(Principal.toBlob(account.owner)), #Blob(sub)]);
    case null #Array([#Blob(Principal.toBlob(account.owner))]);
  }
};

func block(memoValue : Blob, fromValue : ICRC3.Value, includeUserTime : Bool) : ICRC3.Value {
  let txBase : [(Text, ICRC3.Value)] = [
    ("amt", #Nat(70)),
    ("from", fromValue),
    ("to", account(args.to)),
    ("spender", account({ owner = spender; subaccount = null })),
    ("fee", #Nat(10_000)),
    ("memo", #Blob(memoValue)),
  ];
  let tx = if (includeUserTime) {
    [
      txBase[0], txBase[1], txBase[2], txBase[3], txBase[4], txBase[5],
      ("ts", #Nat(1_700_000_000_000_000_000)),
    ]
  } else { txBase };
  #Map([
    ("btype", #Text("2xfer")),
    ("ts", #Nat(1_700_000_000_000_000_111)),
    ("tx", #Map(tx)),
  ])
};

let canonical = block(memo, account(args.from), true);
assert ICRC2Block.matchesTransferFrom(canonical, args, spender);
assert not ICRC2Block.matchesTransferFrom(block(badMemo, account(args.from), true), args, spender);
assert not ICRC2Block.matchesTransferFrom(block(memo, #Map([("owner", #Blob(Principal.toBlob(owner)))]), true), args, spender);
assert not ICRC2Block.matchesTransferFrom(block(memo, account(args.from), false), args, spender);

let payoutArgs : ICRC2.TransferArg = {
  from_subaccount = ?subaccount;
  to = { owner; subaccount = null };
  amount = 70;
  fee = ?10_000;
  memo = ?memo;
  created_at_time = ?1_700_000_000_000_000_000;
};

func payoutBlock(
  memoValue : Blob,
  fromValue : ICRC3.Value,
  toValue : ICRC3.Value,
  includeUserTime : Bool,
) : ICRC3.Value {
  let txBase : [(Text, ICRC3.Value)] = [
    ("amt", #Nat(70)),
    ("from", fromValue),
    ("to", toValue),
    ("fee", #Nat(10_000)),
    ("memo", #Blob(memoValue)),
  ];
  let tx = if (includeUserTime) {
    [txBase[0], txBase[1], txBase[2], txBase[3], txBase[4],
      ("ts", #Nat(1_700_000_000_000_000_000))]
  } else { txBase };
  #Map([
    ("btype", #Text("1xfer")),
    ("ts", #Nat(1_700_000_000_000_000_111)),
    ("tx", #Map(tx)),
  ])
};

let payoutFrom = account({ owner = spender; subaccount = ?subaccount });
let canonicalPayout = payoutBlock(memo, payoutFrom, account(payoutArgs.to), true);
assert ICRC1Block.matchesTransfer(canonicalPayout, payoutArgs, spender);
assert not ICRC1Block.matchesTransfer(
  payoutBlock(badMemo, payoutFrom, account(payoutArgs.to), true), payoutArgs, spender
);
assert not ICRC1Block.matchesTransfer(
  payoutBlock(memo, account({ owner = spender; subaccount = null }), account(payoutArgs.to), true),
  payoutArgs,
  spender,
);
assert not ICRC1Block.matchesTransfer(
  payoutBlock(memo, payoutFrom, account({ owner = spender; subaccount = null }), true),
  payoutArgs,
  spender,
);
assert not ICRC1Block.matchesTransfer(
  payoutBlock(memo, payoutFrom, account(payoutArgs.to), false), payoutArgs, spender
);
let duplicateFeePayout = #Map([
  ("btype", #Text("1xfer")),
  ("tx", #Map([
    ("amt", #Nat(70)),
    ("from", payoutFrom),
    ("to", account(payoutArgs.to)),
    ("fee", #Nat(10_000)),
    ("fee", #Nat(10_000)),
    ("memo", #Blob(memo)),
    ("ts", #Nat(1_700_000_000_000_000_000)),
  ])),
]);
assert not ICRC1Block.matchesTransfer(duplicateFeePayout, payoutArgs, spender);

Debug.print("G4-TYPED-BLOCK-MATCH PASS");

// ---- Legacy ICRC-1/2 blocks, as the live ckBTC ledger writes them (real blocks, CkbtcBlockVectors).
// Before Oct-31 both matchers began with `btype == "1xfer"/"2xfer"`, so every one of these returned
// false and a ckBTC payout or shield could never be recovered from its block.
func hasBtype(b : ICRC3.Value) : Bool {
  switch (b) {
    case (#Map(entries)) { for ((k, _) in entries.vals()) { if (k == "btype") return true }; false };
    case _ false;
  }
};
assert not hasBtype(Ckbtc.xfer_txfee_memo_ts);
assert not hasBtype(Ckbtc.xfer_topfee);
assert not hasBtype(Ckbtc.xfer_spender_txfee_memo);

func outerOf(b : ICRC3.Value) : [(Text, ICRC3.Value)] { switch (b) { case (#Map(e)) e; case _ [] } };
func txOf(b : ICRC3.Value) : [(Text, ICRC3.Value)] {
  for ((k, v) in outerOf(b).vals()) { if (k == "tx") switch (v) { case (#Map(e)) return e; case _ {} } };
  []
};
func field(entries : [(Text, ICRC3.Value)], name : Text) : ICRC3.Value {
  for ((k, v) in entries.vals()) { if (k == name) return v };
  Runtime.trap("vector has no " # name)
};
func bytes(v : ICRC3.Value) : Blob { switch (v) { case (#Blob(b)) b; case _ Runtime.trap("not a blob") } };
func acct(v : ICRC3.Value) : ICRC2.Account {
  switch (v) {
    case (#Array(parts)) {
      let owner = Principal.fromBlob(bytes(parts[0]));
      if (parts.size() == 1) ({ owner; subaccount = null })
      else if (parts.size() == 2) ({ owner; subaccount = ?bytes(parts[1]) })
      else Runtime.trap("not an account")
    };
    case _ Runtime.trap("not an account");
  }
};
func nat(v : ICRC3.Value) : Nat { switch (v) { case (#Nat(n)) n; case _ Runtime.trap("not a nat") } };
// Rebuild a block with `tx` or outer entries changed, keeping everything else as the ledger wrote it.
func withTx(b : ICRC3.Value, f : [(Text, ICRC3.Value)] -> [(Text, ICRC3.Value)]) : ICRC3.Value {
  #Map(Array.map<(Text, ICRC3.Value), (Text, ICRC3.Value)>(outerOf(b), func((k, v)) {
    if (k == "tx") (k, #Map(f(txOf(b)))) else (k, v)
  }))
};
func setTx(entries : [(Text, ICRC3.Value)], name : Text, value : ICRC3.Value) : [(Text, ICRC3.Value)] {
  let kept = Array.filter<(Text, ICRC3.Value)>(entries, func((k, _)) { k != name });
  Array.concat(kept, [(name, value)])
};
func dropTx(entries : [(Text, ICRC3.Value)], name : Text) : [(Text, ICRC3.Value)] {
  Array.filter<(Text, ICRC3.Value)>(entries, func((k, _)) { k != name })
};
func addOuter(b : ICRC3.Value, name : Text, value : ICRC3.Value) : ICRC3.Value {
  #Map(Array.concat(outerOf(b), [(name, value)]))
};

// Block 4791982: a plain transfer with the caller's fee, memo and created_at_time in `tx`. This is
// exactly the shape of a pool payout, so the payout matcher must accept it for the call that made it.
let realPayoutTx = txOf(Ckbtc.xfer_txfee_memo_ts);
let realPayoutFrom = acct(field(realPayoutTx, "from"));
let realPayoutArgs : ICRC2.TransferArg = {
  from_subaccount = realPayoutFrom.subaccount;
  to = acct(field(realPayoutTx, "to"));
  amount = nat(field(realPayoutTx, "amt"));
  fee = ?nat(field(realPayoutTx, "fee"));
  memo = ?bytes(field(realPayoutTx, "memo"));
  created_at_time = ?Nat64.fromNat(nat(field(realPayoutTx, "ts")));
};
assert ICRC1Block.matchesTransfer(Ckbtc.xfer_txfee_memo_ts, realPayoutArgs, realPayoutFrom.owner);
// Each field the call fixed must match.
assert not ICRC1Block.matchesTransfer(Ckbtc.xfer_txfee_memo_ts, { realPayoutArgs with amount = 99_991 }, realPayoutFrom.owner);
assert not ICRC1Block.matchesTransfer(Ckbtc.xfer_txfee_memo_ts, { realPayoutArgs with fee = ?11 }, realPayoutFrom.owner);
assert not ICRC1Block.matchesTransfer(Ckbtc.xfer_txfee_memo_ts, { realPayoutArgs with memo = ?memo }, realPayoutFrom.owner);
assert not ICRC1Block.matchesTransfer(Ckbtc.xfer_txfee_memo_ts, { realPayoutArgs with created_at_time = ?1_793_448_473_531_000_001 }, realPayoutFrom.owner);
assert not ICRC1Block.matchesTransfer(Ckbtc.xfer_txfee_memo_ts, { realPayoutArgs with from_subaccount = null }, realPayoutFrom.owner);
assert not ICRC1Block.matchesTransfer(Ckbtc.xfer_txfee_memo_ts, { realPayoutArgs with to = { owner = spender; subaccount = null } }, realPayoutFrom.owner);
assert not ICRC1Block.matchesTransfer(Ckbtc.xfer_txfee_memo_ts, realPayoutArgs, spender);
// The schema must be the one named: another op, a second op, a block-level fee, a spender, or a
// typed btype for the other operation are all refused.
assert not ICRC1Block.matchesTransfer(withTx(Ckbtc.xfer_txfee_memo_ts, func(t) = setTx(t, "op", #Text("approve"))), realPayoutArgs, realPayoutFrom.owner);
assert not ICRC1Block.matchesTransfer(withTx(Ckbtc.xfer_txfee_memo_ts, func(t) = Array.concat(t, [("op", #Text("xfer"))])), realPayoutArgs, realPayoutFrom.owner);
assert not ICRC1Block.matchesTransfer(withTx(Ckbtc.xfer_txfee_memo_ts, func(t) = dropTx(t, "op")), realPayoutArgs, realPayoutFrom.owner);
assert not ICRC1Block.matchesTransfer(addOuter(Ckbtc.xfer_txfee_memo_ts, "fee", #Nat(10)), realPayoutArgs, realPayoutFrom.owner);
assert not ICRC1Block.matchesTransfer(withTx(Ckbtc.xfer_txfee_memo_ts, func(t) = setTx(t, "spender", field(t, "from"))), realPayoutArgs, realPayoutFrom.owner);
assert not ICRC1Block.matchesTransfer(addOuter(Ckbtc.xfer_txfee_memo_ts, "btype", #Text("2xfer")), realPayoutArgs, realPayoutFrom.owner);
// A typed `1xfer` btype on the same content is the other allowed schema and is accepted.
assert ICRC1Block.matchesTransfer(addOuter(Ckbtc.xfer_txfee_memo_ts, "btype", #Text("1xfer")), realPayoutArgs, realPayoutFrom.owner);
// A transfer is not a transfer_from.
assert not ICRC2Block.matchesTransferFrom(Ckbtc.xfer_txfee_memo_ts, {
  spender_subaccount = null; from = realPayoutFrom; to = realPayoutArgs.to; amount = realPayoutArgs.amount;
  fee = realPayoutArgs.fee; memo = realPayoutArgs.memo; created_at_time = realPayoutArgs.created_at_time;
}, realPayoutFrom.owner);

// Block 4792004: the caller named no fee, so the ledger put the effective fee at block level and none
// in `tx`. The pool always names its fee, so this is never a pool block, whatever the caller claims.
let topFeeTx = txOf(Ckbtc.xfer_topfee);
let topFeeFrom = acct(field(topFeeTx, "from"));
let topFeeArgs : ICRC2.TransferArg = {
  from_subaccount = topFeeFrom.subaccount;
  to = acct(field(topFeeTx, "to"));
  amount = nat(field(topFeeTx, "amt"));
  fee = ?10;
  memo = ?bytes(field(topFeeTx, "memo"));
  created_at_time = ?Nat64.fromNat(nat(field(topFeeTx, "ts")));
};
assert not ICRC1Block.matchesTransfer(Ckbtc.xfer_topfee, topFeeArgs, topFeeFrom.owner);
// With the fee moved into `tx` (the shape when the caller sets it) the same block matches, which
// shows the refusal above is the block-level fee and nothing else.
let topFeeMoved = withTx(
  #Map(Array.filter<(Text, ICRC3.Value)>(outerOf(Ckbtc.xfer_topfee), func((k, _)) { k != "fee" })),
  func(t) = setTx(t, "fee", #Nat(10)),
);
assert ICRC1Block.matchesTransfer(topFeeMoved, topFeeArgs, topFeeFrom.owner);

// Block 4792012: a transfer_from with a spender, the caller's fee and memo, and no created_at_time.
// The pool always sets created_at_time, so the real block is refused; with `tx.ts` added it is the
// shape of a pool shield and is accepted.
let shieldTx = txOf(Ckbtc.xfer_spender_txfee_memo);
let shieldSpender = acct(field(shieldTx, "spender"));
let realShieldArgs : ICRC2.TransferFromArgs = {
  spender_subaccount = shieldSpender.subaccount;
  from = acct(field(shieldTx, "from"));
  to = acct(field(shieldTx, "to"));
  amount = nat(field(shieldTx, "amt"));
  fee = ?nat(field(shieldTx, "fee"));
  memo = ?bytes(field(shieldTx, "memo"));
  created_at_time = ?1_793_449_356_000_000_000;
};
assert not ICRC2Block.matchesTransferFrom(Ckbtc.xfer_spender_txfee_memo, realShieldArgs, shieldSpender.owner);
let shieldWithTs = withTx(Ckbtc.xfer_spender_txfee_memo, func(t) = setTx(t, "ts", #Nat(1_793_449_356_000_000_000)));
assert ICRC2Block.matchesTransferFrom(shieldWithTs, realShieldArgs, shieldSpender.owner);
assert not ICRC2Block.matchesTransferFrom(shieldWithTs, { realShieldArgs with amount = 130_001 }, shieldSpender.owner);
assert not ICRC2Block.matchesTransferFrom(shieldWithTs, { realShieldArgs with fee = ?11 }, shieldSpender.owner);
assert not ICRC2Block.matchesTransferFrom(shieldWithTs, { realShieldArgs with memo = ?memo }, shieldSpender.owner);
assert not ICRC2Block.matchesTransferFrom(shieldWithTs, { realShieldArgs with from = { owner; subaccount = null } }, shieldSpender.owner);
assert not ICRC2Block.matchesTransferFrom(shieldWithTs, realShieldArgs, spender);
assert not ICRC2Block.matchesTransferFrom(withTx(shieldWithTs, func(t) = dropTx(t, "spender")), realShieldArgs, shieldSpender.owner);
assert not ICRC2Block.matchesTransferFrom(withTx(shieldWithTs, func(t) = setTx(t, "op", #Text("burn"))), realShieldArgs, shieldSpender.owner);
assert not ICRC2Block.matchesTransferFrom(addOuter(shieldWithTs, "fee", #Nat(10)), realShieldArgs, shieldSpender.owner);
assert not ICRC2Block.matchesTransferFrom(addOuter(shieldWithTs, "btype", #Text("1xfer")), realShieldArgs, shieldSpender.owner);
assert ICRC2Block.matchesTransferFrom(addOuter(shieldWithTs, "btype", #Text("2xfer")), realShieldArgs, shieldSpender.owner);
// A transfer_from is not a payout.
assert not ICRC1Block.matchesTransfer(shieldWithTs, {
  from_subaccount = realShieldArgs.from.subaccount; to = realShieldArgs.to; amount = realShieldArgs.amount;
  fee = realShieldArgs.fee; memo = realShieldArgs.memo; created_at_time = realShieldArgs.created_at_time;
}, realShieldArgs.from.owner);

func netAfterFee(gross : Nat, fee : Nat) : ?Nat {
  if (gross <= fee) null else ?(gross - fee)
};
assert netAfterFee(20_000, 10_000) == ?10_000;
assert netAfterFee(10_000, 10_000) == null;
assert netAfterFee(0, 10_000) == null;

Debug.print("G4-BLOCK-MATCH PASS");
Debug.print("G4-DIRECT-BLOCK-MATCH PASS");
Debug.print("G4-FEE-ARITHMETIC PASS");
Debug.print("G4-LEGACY-CKBTC-BLOCK-MATCH PASS");
