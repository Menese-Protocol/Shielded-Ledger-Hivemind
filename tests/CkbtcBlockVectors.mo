/// Real blocks read anonymously from the live ckBTC ledger mxzaz-hqaaa-aaaar-qaada-cai on 2026-10-31
/// (module 354dd6ec…6d8a = dfinity/ic cf41372e, ledger-suite-icrc-2026-03-09), via icrc3_get_blocks.
/// The legacy ICRC-1/2 schema: no btype, tx.op, fee in tx when the caller set it, else at block level.
import ICRC3 "../src/ICRC3";

module {
  /// block 4791982
  public let xfer_txfee_memo_ts : ICRC3.Value = #Map([
    ("fee_col_block", #Nat(39493)),
    ("phash", #Blob("\09\1b\aa\74\81\9a\b7\a0\38\61\6c\f3\de\fd\30\ce\25\65\e9\f2\52\7d\59\62\1f\38\7c\91\f0\a8\3d\24")),
    ("ts", #Nat(1793448478431997493)),
    ("tx", #Map([
      ("amt", #Nat(99990)),
      ("fee", #Nat(10)),
      ("from", #Array([#Blob("\00\00\00\00\00\41\2a\87\01\01"), #Blob("\5f\32\80\e9\97\42\2e\b9\16\d8\3c\a0\f4\2f\b5\dd\2b\14\c0\bf\18\75\82\c9\f1\22\bd\7a\11\2f\77\0a")])),
      ("memo", #Blob("\74\66\76\71\8a\b1\72\b2\ed\34\98\dd\ec\14\61\1e")),
      ("op", #Text("xfer")),
      ("to", #Array([#Blob("\5b\66\61\3e\bf\cf\93\52\16\93\ad\8a\09\5a\36\14\d2\37\af\52\80\5d\01\e2\b7\e5\fe\1a\02")])),
      ("ts", #Nat(1793448473531000000)),
    ])),
  ]);
  /// block 4792004
  public let xfer_topfee : ICRC3.Value = #Map([
    ("fee", #Nat(10)),
    ("fee_col_block", #Nat(39493)),
    ("phash", #Blob("\e8\bc\5e\fa\cd\9c\b1\a6\39\47\0a\b3\48\86\b0\db\d4\f4\c1\a3\70\73\2b\ab\4b\94\2a\37\42\9d\42\5d")),
    ("ts", #Nat(1793449225912414016)),
    ("tx", #Map([
      ("amt", #Nat(114000)),
      ("from", #Array([#Blob("\e6\29\3d\20\17\dd\04\4d\08\54\9f\5f\48\a3\64\ba\dd\2e\39\ad\57\ae\44\f6\ac\16\1d\20\02")])),
      ("memo", #Blob("\65\78\63\68\61\6e\67\65\3a\32\34\35\34\32")),
      ("op", #Text("xfer")),
      ("to", #Array([#Blob("\c3\e9\4f\4f\0d\e3\f7\13\cd\f7\42\bf\d9\28\54\1a\1d\1b\b0\21\fe\cb\3e\3a\7f\58\78\d3\02")])),
      ("ts", #Nat(1793449214527000000)),
    ])),
  ]);
  /// block 4792012
  public let xfer_spender_txfee_memo : ICRC3.Value = #Map([
    ("fee_col_block", #Nat(39493)),
    ("phash", #Blob("\b3\f8\08\17\b9\74\31\44\63\ce\10\b4\65\6e\d7\8d\db\d3\3b\0b\fe\6b\24\88\83\ce\d3\2f\57\5d\a5\8b")),
    ("ts", #Nat(1793449356582614074)),
    ("tx", #Map([
      ("amt", #Nat(130000)),
      ("fee", #Nat(10)),
      ("from", #Array([#Blob("\62\41\67\6b\23\7e\42\98\e2\12\13\36\d6\08\8b\a7\84\7a\87\da\35\e8\35\54\98\90\43\fe\02")])),
      ("memo", #Blob("\00\00\00\00\00\0a\60\c9")),
      ("op", #Text("xfer")),
      ("spender", #Array([#Blob("\00\00\00\00\00\d0\0e\7f\01\01")])),
      ("to", #Array([#Blob("\00\00\00\00\00\d0\0e\7f\01\01")])),
    ])),
  ]);
}
