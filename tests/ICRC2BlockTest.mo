import Blob "mo:core/Blob";
import Debug "mo:core/Debug";
import Principal "mo:core/Principal";
import ICRC2 "../src/ICRC2";
import ICRC2Block "../src/ICRC2Block";
import ICRC1Block "../src/ICRC1Block";
import ICRC3 "../src/ICRC3";

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

func netAfterFee(gross : Nat, fee : Nat) : ?Nat {
  if (gross <= fee) null else ?(gross - fee)
};
assert netAfterFee(20_000, 10_000) == ?10_000;
assert netAfterFee(10_000, 10_000) == null;
assert netAfterFee(0, 10_000) == null;

Debug.print("G4-BLOCK-MATCH PASS");
Debug.print("G4-DIRECT-BLOCK-MATCH PASS");
Debug.print("G4-FEE-ARITHMETIC PASS");
