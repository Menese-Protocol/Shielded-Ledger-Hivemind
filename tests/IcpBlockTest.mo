// IcpBlock: the NNS ICP ledger's legacy blocks matched against what the pool sent.
// Run: moc -r $(mops sources) tests/IcpBlockTest.mo
//
// K1   account identifier known answer (anonymous principal, default subaccount)
// TF   transfer_from: the exact block matches; every single-field change is refused
// T    transfer: the exact block matches; every single-field change is refused
import Blob "mo:core/Blob";
import Debug "mo:core/Debug";
import Nat8 "mo:core/Nat8";
import Runtime "mo:core/Runtime";
import Principal "mo:core/Principal";
import Text "mo:core/Text";
import ICRC2 "../src/ICRC2";
import IcpBlock "../src/IcpBlock";
import NnsBlock "../src/NnsBlock";

func bytes(n : Nat8) : Blob {
  Blob.fromArray([n, n, n, n, n, n, n, n, n, n, n, n, n, n, n, n, n, n, n, n, n, n, n, n, n, n, n, n, n, n, n, n])
};
func hex(b : Blob) : Text {
  let d = [ '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' ];
  var out = "";
  for (x in b.vals()) {
    out #= Text.fromChar(d[Nat8.toNat(x) / 16]) # Text.fromChar(d[Nat8.toNat(x) % 16]);
  };
  out
};

var checks = 0;
func expect(name : Text, ok : Bool) {
  if (not ok) Runtime.trap("FAIL " # name);
  checks += 1;
};

// K1: the anonymous principal's default account identifier, as the ICP ledger documents it
let anonymous = Principal.fromText("2vxsx-fae");
expect("K1 account id", hex(Principal.toLedgerAccount(anonymous, null)) == "1c7a48ba6a562aa9eaa2481a9049cdf0433b9738c992d698c31d8abf89cadc79");

let pool = Principal.fromText("uzt4z-lp777-77774-qaabq-cai");
let user = Principal.fromText("zn6e5-pxkig-6iniy-kvvgm-jh2js-npsh3-facqb-wgdno-hsyqs-cuax2-4ae");
let poolSub = bytes(7);
let intent = bytes(9);
let time : Nat64 = 1_784_246_400_000_000_123;
let id = func(p : Principal, s : ?Blob) : Blob { Principal.toLedgerAccount(p, s) };

let tfArgs : ICRC2.TransferFromArgs = {
  spender_subaccount = null;
  from = { owner = user; subaccount = null };
  to = { owner = pool; subaccount = ?poolSub };
  amount = 300_000_000;
  fee = ?10_000;
  memo = ?intent;
  created_at_time = ?time;
};
func tfBlock(
  op : ?NnsBlock.Operation,
  memo : ?Blob,
  created : Nat64,
) : NnsBlock.Block {
  { parent_hash = null; timestamp = { timestamp_nanos = created + 5 };
    transaction = { memo = 0; icrc1_memo = memo; operation = op; created_at_time = { timestamp_nanos = created } } }
};
func transferOp(from : Blob, to : Blob, amount : Nat64, fee : Nat64, spender : ?Blob) : ?NnsBlock.Operation {
  ?#Transfer({ from; to; amount = { e8s = amount }; fee = { e8s = fee }; spender })
};
let goodFrom = id(user, null);
let goodTo = id(pool, ?poolSub);
let goodSpender = id(pool, null);

expect("TF exact", IcpBlock.matchesTransferFrom(tfBlock(transferOp(goodFrom, goodTo, 300_000_000, 10_000, ?goodSpender), ?intent, time), tfArgs, pool));
expect("TF spender other", not IcpBlock.matchesTransferFrom(tfBlock(transferOp(goodFrom, goodTo, 300_000_000, 10_000, ?id(user, null)), ?intent, time), tfArgs, pool));
expect("TF spender absent", not IcpBlock.matchesTransferFrom(tfBlock(transferOp(goodFrom, goodTo, 300_000_000, 10_000, null), ?intent, time), tfArgs, pool));
expect("TF from other", not IcpBlock.matchesTransferFrom(tfBlock(transferOp(id(user, ?bytes(1)), goodTo, 300_000_000, 10_000, ?goodSpender), ?intent, time), tfArgs, pool));
expect("TF to other subaccount", not IcpBlock.matchesTransferFrom(tfBlock(transferOp(goodFrom, id(pool, null), 300_000_000, 10_000, ?goodSpender), ?intent, time), tfArgs, pool));
expect("TF amount", not IcpBlock.matchesTransferFrom(tfBlock(transferOp(goodFrom, goodTo, 300_000_001, 10_000, ?goodSpender), ?intent, time), tfArgs, pool));
expect("TF fee", not IcpBlock.matchesTransferFrom(tfBlock(transferOp(goodFrom, goodTo, 300_000_000, 20_000, ?goodSpender), ?intent, time), tfArgs, pool));
expect("TF memo other", not IcpBlock.matchesTransferFrom(tfBlock(transferOp(goodFrom, goodTo, 300_000_000, 10_000, ?goodSpender), ?bytes(8), time), tfArgs, pool));
expect("TF memo absent", not IcpBlock.matchesTransferFrom(tfBlock(transferOp(goodFrom, goodTo, 300_000_000, 10_000, ?goodSpender), null, time), tfArgs, pool));
expect("TF created_at_time", not IcpBlock.matchesTransferFrom(tfBlock(transferOp(goodFrom, goodTo, 300_000_000, 10_000, ?goodSpender), ?intent, time + 1), tfArgs, pool));
expect("TF not a transfer", not IcpBlock.matchesTransferFrom(tfBlock(?#Mint({ to = goodTo; amount = { e8s = 300_000_000 } }), ?intent, time), tfArgs, pool));
expect("TF no operation", not IcpBlock.matchesTransferFrom(tfBlock(null, ?intent, time), tfArgs, pool));
expect("TF args without fee", not IcpBlock.matchesTransferFrom(tfBlock(transferOp(goodFrom, goodTo, 300_000_000, 10_000, ?goodSpender), ?intent, time), { tfArgs with fee = null }, pool));
expect("TF args without time", not IcpBlock.matchesTransferFrom(tfBlock(transferOp(goodFrom, goodTo, 300_000_000, 10_000, ?goodSpender), ?intent, time), { tfArgs with created_at_time = null }, pool));
expect("TF amount beyond u64", not IcpBlock.matchesTransferFrom(tfBlock(transferOp(goodFrom, goodTo, 300_000_000, 10_000, ?goodSpender), ?intent, time), { tfArgs with amount = 300_000_000 + 0x1_0000_0000_0000_0000 }, pool));

let tArgs : ICRC2.TransferArg = {
  from_subaccount = ?poolSub;
  to = { owner = user; subaccount = null };
  amount = 50_000_000;
  fee = ?10_000;
  memo = ?intent;
  created_at_time = ?time;
};
let tFrom = id(pool, ?poolSub);
let tTo = id(user, null);
expect("T exact", IcpBlock.matchesTransfer(tfBlock(transferOp(tFrom, tTo, 50_000_000, 10_000, null), ?intent, time), tArgs, pool));
expect("T with spender", not IcpBlock.matchesTransfer(tfBlock(transferOp(tFrom, tTo, 50_000_000, 10_000, ?goodSpender), ?intent, time), tArgs, pool));
expect("T from default subaccount", not IcpBlock.matchesTransfer(tfBlock(transferOp(id(pool, null), tTo, 50_000_000, 10_000, null), ?intent, time), tArgs, pool));
expect("T to other", not IcpBlock.matchesTransfer(tfBlock(transferOp(tFrom, id(anonymous, null), 50_000_000, 10_000, null), ?intent, time), tArgs, pool));
expect("T amount", not IcpBlock.matchesTransfer(tfBlock(transferOp(tFrom, tTo, 49_999_999, 10_000, null), ?intent, time), tArgs, pool));
expect("T fee", not IcpBlock.matchesTransfer(tfBlock(transferOp(tFrom, tTo, 50_000_000, 0, null), ?intent, time), tArgs, pool));
expect("T memo", not IcpBlock.matchesTransfer(tfBlock(transferOp(tFrom, tTo, 50_000_000, 10_000, null), ?bytes(8), time), tArgs, pool));
expect("T time", not IcpBlock.matchesTransfer(tfBlock(transferOp(tFrom, tTo, 50_000_000, 10_000, null), ?intent, time - 1), tArgs, pool));

Debug.print("ICP BLOCK MATCHER: " # debug_show (checks) # " checks PASS");
