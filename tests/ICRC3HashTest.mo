import Blob "mo:core/Blob";
import Debug "mo:core/Debug";
import Nat8 "mo:core/Nat8";
import Text "mo:core/Text";
import Sha256 "mo:sha2/Sha256";
import ICRC3 "../src/ICRC3";

func nibble(value : Nat) : Text {
  switch (value) {
    case 0 "0"; case 1 "1"; case 2 "2"; case 3 "3";
    case 4 "4"; case 5 "5"; case 6 "6"; case 7 "7";
    case 8 "8"; case 9 "9"; case 10 "a"; case 11 "b";
    case 12 "c"; case 13 "d"; case 14 "e"; case _ "f";
  }
};

func hex(value : Blob) : Text {
  var output = "";
  for (byte in value.vals()) {
    let n = Nat8.toNat(byte);
    output #= nibble(n / 16) # nibble(n % 16);
  };
  output
};

let official : [(ICRC3.Value, Text)] = [
  (#Nat(42), "684888c0ebb17f374298b65ee2807526c066094c701bcc7ebbe1c1095f494fc1"),
  (#Int(-42), "de5a6f78116eca62d7fc5ce159d23ae6b889b365a1739ad2cf36f925a140d0cc"),
  (#Text("Hello, World!"), "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"),
  (#Blob("\01\02\03\04"), "9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a"),
  (
    #Array([#Nat(3), #Text("foo"), #Blob("\05\06")]),
    "514a04011caa503990d446b7dec5d79e19c221ae607fb08b2848c67734d468d6",
  ),
  (
    #Map([
      ("from", #Blob("\00\ab\cd\ef\00\12\34\00\56\78\9a\00\bc\de\f0\00\01\23\45\67\89\00\ab\cd\ef\01")),
      ("to", #Blob("\00\ab\0d\ef\00\12\34\00\56\78\9a\00\bc\de\f0\00\01\23\45\67\89\00\ab\cd\ef\01")),
      ("amount", #Nat(42)),
      ("created_at", #Nat(1_699_218_263)),
      ("memo", #Nat(0)),
    ]),
    "c56ece650e1de4269c5bdeff7875949e3e2033f85b2d193c2ff4f7f78bdcfc75",
  ),
];

for ((value, expected) in official.vals()) {
  assert hex(ICRC3.hashValue(value)) == expected;
};

// Named G1-HASH negative control: the altered input cannot satisfy the frozen Nat-42 digest.
assert hex(ICRC3.hashValue(#Nat(43))) != official[0].1;

// Auditor regression: icrc-ledger-types 0.1.13 incorrectly uses unsigned LEB for some positive
// Ints. The spec-correct Motoko implementation must never reproduce its positive/negative collisions.
let signedBoundaryVectors : [(Int, Text)] = [
  (64, "e9aff84fdb699ca706c0a1fed47bb095cb25e3c95aa5d1c5d216ff2cfbcd4998"),
  (-64, "c3641f8544d7c02f3580b07c0f9887f0c6a27ff5ab1d4a3e29caf197cfc299ae"),
  (127, "ea5dbf9596d187e9500f23e9a680109475341cf4e81f7e043f7d97152c10772f"),
  (-1, "620bfdaa346b088fb49998d92f19a7eaf6bfc2fb0aee015753966da1028cb731"),
  (8_192, "db64f065746b0d0010a4d6242786938eb46616ec2de56b3a1f46e8d31976df1c"),
  (-8_192, "607b306244cab5c6e8670d7525e1af04304b5d2c3a8a1ad791cb01de20e22117"),
];
for ((value, expected) in signedBoundaryVectors.vals()) {
  assert hex(ICRC3.hashValue(#Int(value))) == expected;
};
assert ICRC3.hashValue(#Int(64)) != ICRC3.hashValue(#Int(-64));
assert ICRC3.hashValue(#Int(127)) != ICRC3.hashValue(#Int(-1));
assert ICRC3.hashValue(#Int(8_192)) != ICRC3.hashValue(#Int(-8_192));

let forward : ICRC3.Value = #Map([
  ("alpha", #Nat(1)),
  ("beta", #Text("two")),
]);
let reverse : ICRC3.Value = #Map([
  ("beta", #Text("two")),
  ("alpha", #Nat(1)),
]);
assert ICRC3.hashValue(forward) == ICRC3.hashValue(reverse);

func orderSensitive(entries : [(Text, ICRC3.Value)]) : Blob {
  let digest = Sha256.Digest(#sha256);
  for ((key, value) in entries.vals()) {
    digest.writeBlob(Sha256.fromBlob(#sha256, Text.encodeUtf8(key)));
    digest.writeBlob(ICRC3.hashValue(value));
  };
  digest.sum()
};

switch (forward, reverse) {
  case (#Map(a), #Map(b)) {
    // Named G1-MAP mutant: failing to sort by key hash is observably order-dependent.
    assert orderSensitive(a) != orderSensitive(b);
  };
  case _ assert false;
};

Debug.print("G1-HASH PASS (6/6 official vectors; Nat43 negative observed)");
Debug.print("G1-MAP PASS (order-independent; order-sensitive mutant rejected)");
Debug.print("G1-INT-GUARD PASS (6 signed boundaries; 3 upstream collision pairs separated)");
