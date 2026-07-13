/// Local-only ICP ledger fixture for Gate 4 atomic-shield falsification.
///
/// It uses ICP's e8s denomination and implements the NNS ledger's ICRC-1/2 plus legacy
/// `query_blocks`/archive surface. A test-only generic ICRC-3 view remains for the pre-existing
/// capability probes; Gate 4 consumes the separately certified NNS adapter instead.
/// The conformant mode records full identities only after success. The bounded mutant deliberately
/// reproduces the read-only ICRC-ME defect: timestamp-only identity recorded before preconditions.

import Array "mo:core/Array";
import Blob "mo:core/Blob";
import CertifiedData "mo:core/CertifiedData";
import Int "mo:core/Int";
import List "mo:core/List";
import Nat "mo:core/Nat";
import Nat64 "mo:core/Nat64";
import Nat8 "mo:core/Nat8";
import Principal "mo:core/Principal";
import Text "mo:core/Text";
import Time "mo:core/Time";
import ICRC2 "../src/ICRC2";
import ICRC3 "../src/ICRC3";
import NnsBlock "../src/NnsBlock";

persistent actor IcpLedgerFixture {
  public type DedupMode = { #conformant; #timestamp_only_preinsert };
  public type MetadataValue = { #Nat : Nat; #Int : Int; #Text : Text; #Blob : Blob };
  public type TransferArg = {
    from_subaccount : ?Blob;
    to : ICRC2.Account;
    amount : Nat;
    fee : ?Nat;
    memo : ?Blob;
    created_at_time : ?Nat64;
  };
  public type TransferError = {
    #BadFee : { expected_fee : Nat };
    #BadBurn : { min_burn_amount : Nat };
    #InsufficientFunds : { balance : Nat };
    #TooOld;
    #CreatedInFuture : { ledger_time : Nat64 };
    #Duplicate : { duplicate_of : Nat };
    #TemporarilyUnavailable;
    #GenericError : { error_code : Nat; message : Text };
  };
  public type TransferResult = { #Ok : Nat; #Err : TransferError };
  public type GetArchivesArgs = { from : ?Principal };
  public type ArchiveInfo = { canister_id : Principal; start : Nat; end : Nat };
  public type DataCertificate = { certificate : Blob; hash_tree : Blob };
  public type Archives = { archives : [{ canister_id : Principal }] };
  public type TipOfChainRes = { certification : ?Blob; tip_index : Nat64 };
  type BalanceEntry = { account : ICRC2.Account; balance : Nat };
  type AllowanceEntry = {
    from : ICRC2.Account;
    spender : ICRC2.Account;
    allowance : Nat;
    expires_at : ?Nat64;
  };
  type TransferIdentity = {
    caller : Principal;
    args : ICRC2.TransferFromArgs;
    block_index : Nat;
  };
  type DirectTransferIdentity = {
    caller : Principal;
    args : TransferArg;
    block_index : Nat;
  };
  type ApproveIdentity = {
    caller : Principal;
    args : ICRC2.ApproveArgs;
    block_index : Nat;
  };
  type ArchivedBlocks = { args : [ICRC2.GetBlocksArgs]; callback : GetBlocksCallback };
  type FullGetBlocksResult = {
    log_length : Nat;
    blocks : [ICRC2.Block];
    archived_blocks : [ArchivedBlocks];
  };
  type GetBlocksCallback = shared query ([ICRC2.GetBlocksArgs]) -> async FullGetBlocksResult;
  type ArchiveActor = actor {
    get_blocks : shared query NnsBlock.GetBlocksArgs -> async NnsBlock.GetBlocksResult;
    get_encoded_blocks : shared query NnsBlock.GetBlocksArgs -> async NnsBlock.GetEncodedBlocksResult;
  };

  let NAME = "Internet Computer";
  let SYMBOL = "ICP";
  let WINDOW_NS : Nat = 86_400_000_000_000;
  let DRIFT_NS : Nat = 60_000_000_000;

  var balances : [BalanceEntry] = [];
  var allowances : [AllowanceEntry] = [];
  var blocks : [ICRC3.Value] = [];
  var legacy_blocks : [NnsBlock.Block] = [];
  var encoded_blocks : [Blob] = [];
  var created_at_presence : [Bool] = [];
  var fee_e8s : Nat = 10_000;
  var decimals : Nat8 = 8;
  var archive_id : ?Principal = null;
  var archived_count : Nat = 0;
  var transfers : [TransferIdentity] = [];
  var direct_transfers : [DirectTransferIdentity] = [];
  var approvals : [ApproveIdentity] = [];
  var poisoned_timestamps : [(Nat64, Nat)] = [];
  var dedup_mode : DedupMode = #conformant;
  // Test-only simulated elapsed time, added to the wall clock. Lets a test age a created_at_time
  // past WINDOW_NS to reproduce a post-transaction-window recovery without waiting 24h.
  var time_offset_ns : Nat = 0;

  func now() : Nat64 { Nat64.fromNat(Int.abs(Time.now()) + time_offset_ns) };

  func balanceOf(account : ICRC2.Account) : Nat {
    for (entry in balances.vals()) {
      if (ICRC2.accountsEqual(entry.account, account)) return entry.balance;
    };
    0
  };

  func setBalance(account : ICRC2.Account, amount : Nat) {
    let next = List.empty<BalanceEntry>();
    var found = false;
    for (entry in balances.vals()) {
      if (ICRC2.accountsEqual(entry.account, account)) {
        List.add(next, { account; balance = amount });
        found := true;
      } else { List.add(next, entry) };
    };
    if (not found) List.add(next, { account; balance = amount });
    balances := List.toArray(next);
  };

  func totalSupply() : Nat {
    var total = 0;
    for (entry in balances.vals()) { total += entry.balance };
    total
  };

  func allowanceOf(from : ICRC2.Account, spender : ICRC2.Account) : ICRC2.Allowance {
    for (entry in allowances.vals()) {
      if (ICRC2.accountsEqual(entry.from, from) and ICRC2.accountsEqual(entry.spender, spender)) {
        switch (entry.expires_at) {
          case (?expiry) { if (expiry <= now()) return { allowance = 0; expires_at = null } };
          case null {};
        };
        return { allowance = entry.allowance; expires_at = entry.expires_at };
      };
    };
    { allowance = 0; expires_at = null }
  };

  func setAllowance(from : ICRC2.Account, spender : ICRC2.Account, amount : Nat, expiry : ?Nat64) {
    let next = List.empty<AllowanceEntry>();
    var found = false;
    for (entry in allowances.vals()) {
      if (ICRC2.accountsEqual(entry.from, from) and ICRC2.accountsEqual(entry.spender, spender)) {
        List.add(next, { from; spender; allowance = amount; expires_at = expiry });
        found := true;
      } else { List.add(next, entry) };
    };
    if (not found) List.add(next, { from; spender; allowance = amount; expires_at = expiry });
    allowances := List.toArray(next);
  };

  func accountValue(account : ICRC2.Account) : ICRC3.Value {
    switch (account.subaccount) {
      case (?subaccount) #Array([#Blob(Principal.toBlob(account.owner)), #Blob(subaccount)]);
      case null #Array([#Blob(Principal.toBlob(account.owner))]);
    }
  };

  func refreshCertification() {
    if (encoded_blocks.size() == 0) {
      CertifiedData.set(Blob.fromArray(Array.repeat<Nat8>(0, 32)))
    } else {
      CertifiedData.set(NnsBlock.hashEncoded(encoded_blocks[encoded_blocks.size() - 1]))
    }
  };

  func appendBlock(
    blockType : Text,
    tx : [(Text, ICRC3.Value)],
    effectiveFee : Nat,
    feeWasExplicit : Bool,
    legacyOperation : NnsBlock.Operation,
    memo : ?Blob,
    createdAtTime : ?Nat64,
  ) : Nat {
    let blockTime = now();
    let outer = List.empty<(Text, ICRC3.Value)>();
    List.add(outer, ("btype", #Text(blockType)));
    if (not feeWasExplicit) List.add(outer, ("fee", #Nat(effectiveFee)));
    if (blocks.size() > 0) List.add(outer, ("phash", #Blob(ICRC3.hashValue(blocks[blocks.size() - 1]))));
    List.add(outer, ("ts", #Nat(Nat64.toNat(blockTime))));
    List.add(outer, ("tx", #Map(tx)));
    let block = #Map(List.toArray(outer));
    let index = blocks.size();
    blocks := Array.tabulate<ICRC3.Value>(index + 1, func(i) { if (i == index) block else blocks[i] });
    let parentHash = if (encoded_blocks.size() == 0) null else {
      ?NnsBlock.hashEncoded(encoded_blocks[encoded_blocks.size() - 1])
    };
    let legacy : NnsBlock.Block = {
      parent_hash = parentHash;
      transaction = {
        memo = 0;
        icrc1_memo = memo;
        operation = ?legacyOperation;
        created_at_time = {
          timestamp_nanos = switch (createdAtTime) { case (?value) value; case null blockTime }
        };
      };
      timestamp = { timestamp_nanos = blockTime };
    };
    let encoded = NnsBlock.encode(legacy, createdAtTime != null);
    legacy_blocks := Array.tabulate<NnsBlock.Block>(index + 1, func(i) {
      if (i == index) legacy else legacy_blocks[i]
    });
    encoded_blocks := Array.tabulate<Blob>(index + 1, func(i) {
      if (i == index) encoded else encoded_blocks[i]
    });
    created_at_presence := Array.tabulate<Bool>(index + 1, func(i) {
      if (i == index) createdAtTime != null else created_at_presence[i]
    });
    refreshCertification();
    index
  };

  func validateTime(timestamp : ?Nat64) : { #ok; #tooOld; #future : Nat64 } {
    switch (timestamp) {
      case null #ok;
      case (?value) {
        let current = Nat64.toNat(now());
        let supplied = Nat64.toNat(value);
        if (supplied + WINDOW_NS < current) return #tooOld;
        if (supplied > current + DRIFT_NS) return #future(Nat64.fromNat(current));
        #ok
      };
    }
  };

  func transferDuplicate(caller : Principal, args : ICRC2.TransferFromArgs) : ?Nat {
    if (args.created_at_time == null) return null;
    switch (dedup_mode) {
      case (#conformant) {
        for (entry in transfers.vals()) {
          if (Principal.equal(entry.caller, caller) and ICRC2.transferArgsEqual(entry.args, args)) {
            return ?entry.block_index;
          };
        };
        null
      };
      case (#timestamp_only_preinsert) {
        let timestamp = switch (args.created_at_time) { case (?value) value; case null return null };
        for ((seen, index) in poisoned_timestamps.vals()) {
          if (seen == timestamp) return ?index;
        };
        poisoned_timestamps := Array.tabulate<(Nat64, Nat)>(poisoned_timestamps.size() + 1, func(i) {
          if (i == poisoned_timestamps.size()) (timestamp, blocks.size()) else poisoned_timestamps[i]
        });
        null
      };
    }
  };

  func directTransferArgsEqual(left : TransferArg, right : TransferArg) : Bool {
    ICRC2.optionalBlobEqual(left.from_subaccount, right.from_subaccount) and
    ICRC2.accountsEqual(left.to, right.to) and left.amount == right.amount and
    ICRC2.optionalNatEqual(left.fee, right.fee) and ICRC2.optionalBlobEqual(left.memo, right.memo) and
    ICRC2.optionalNat64Equal(left.created_at_time, right.created_at_time)
  };

  func directTransferDuplicate(caller : Principal, args : TransferArg) : ?Nat {
    if (args.created_at_time == null) return null;
    for (entry in direct_transfers.vals()) {
      if (Principal.equal(entry.caller, caller) and directTransferArgsEqual(entry.args, args)) {
        return ?entry.block_index;
      };
    };
    null
  };

  public query func icrc1_name() : async Text { NAME };
  public query func icrc1_symbol() : async Text { SYMBOL };
  public query func icrc1_decimals() : async Nat8 { decimals };
  public query func icrc1_fee() : async Nat { fee_e8s };
  public query func icrc1_metadata() : async [(Text, MetadataValue)] {
    [
      ("icrc1:name", #Text(NAME)),
      ("icrc1:symbol", #Text(SYMBOL)),
      ("icrc1:decimals", #Nat(Nat8.toNat(decimals))),
      ("icrc1:fee", #Nat(fee_e8s)),
    ]
  };
  public query func icrc1_total_supply() : async Nat { totalSupply() };
  public query func icrc1_minting_account() : async ?ICRC2.Account { null };
  public query func icrc1_balance_of(account : ICRC2.Account) : async Nat { balanceOf(account) };
  public query func icrc1_supported_standards() : async [{ name : Text; url : Text }] {
    [
      { name = "ICRC-1"; url = "https://github.com/dfinity/ICRC-1/tree/main/standards/ICRC-1" },
      { name = "ICRC-2"; url = "https://github.com/dfinity/ICRC-1/tree/main/standards/ICRC-2" },
    ]
  };

  public shared ({ caller }) func icrc1_transfer(args : TransferArg) : async TransferResult {
    switch (validateTime(args.created_at_time)) {
      case (#tooOld) return #Err(#TooOld);
      case (#future(value)) return #Err(#CreatedInFuture({ ledger_time = value }));
      case (#ok) {};
    };
    switch (directTransferDuplicate(caller, args)) {
      case (?index) return #Err(#Duplicate({ duplicate_of = index }));
      case null {};
    };
    let fee = switch (args.fee) {
      case (?value) {
        if (value != fee_e8s) return #Err(#BadFee({ expected_fee = fee_e8s }));
        value
      };
      case null fee_e8s;
    };
    let from : ICRC2.Account = { owner = caller; subaccount = args.from_subaccount };
    let gross = args.amount + fee;
    let balance = balanceOf(from);
    if (balance < gross) return #Err(#InsufficientFunds({ balance }));
    setBalance(from, balance - gross);
    setBalance(args.to, balanceOf(args.to) + args.amount);
    let tx = List.empty<(Text, ICRC3.Value)>();
    List.add(tx, ("amt", #Nat(args.amount)));
    List.add(tx, ("from", accountValue(from)));
    List.add(tx, ("to", accountValue(args.to)));
    switch (args.fee) { case (?value) List.add(tx, ("fee", #Nat(value))); case null {} };
    switch (args.memo) { case (?value) List.add(tx, ("memo", #Blob(value))); case null {} };
    switch (args.created_at_time) {
      case (?value) List.add(tx, ("ts", #Nat(Nat64.toNat(value))));
      case null {};
    };
    let index = appendBlock(
      "1xfer",
      List.toArray(tx),
      fee,
      args.fee != null,
      #Transfer({
        from = NnsBlock.accountIdentifier(from.owner, from.subaccount);
        to = NnsBlock.accountIdentifier(args.to.owner, args.to.subaccount);
        amount = { e8s = Nat64.fromNat(args.amount) };
        fee = { e8s = Nat64.fromNat(fee) };
        spender = null;
      }),
      args.memo,
      args.created_at_time,
    );
    direct_transfers := Array.tabulate<DirectTransferIdentity>(direct_transfers.size() + 1, func(i) {
      if (i == direct_transfers.size()) ({ caller; args; block_index = index }) else direct_transfers[i]
    });
    #Ok(index)
  };

  public query func icrc2_allowance(args : ICRC2.AllowanceArgs) : async ICRC2.Allowance {
    allowanceOf(args.account, args.spender)
  };
  public query func icrc3_supported_block_types() : async [{ block_type : Text; url : Text }] {
    [
      { block_type = "1xfer"; url = "https://github.com/dfinity/ICRC-1/tree/main/standards/ICRC-3" },
      { block_type = "2approve"; url = "https://github.com/dfinity/ICRC-1/tree/main/standards/ICRC-3" },
      { block_type = "2xfer"; url = "https://github.com/dfinity/ICRC-1/tree/main/standards/ICRC-3" },
    ]
  };

  public shared ({ caller }) func icrc2_approve(args : ICRC2.ApproveArgs) : async ICRC2.ApproveResult {
    switch (validateTime(args.created_at_time)) {
      case (#tooOld) return #Err(#TooOld);
      case (#future(value)) return #Err(#CreatedInFuture({ ledger_time = value }));
      case (#ok) {};
    };
    if (args.created_at_time != null) {
      for (entry in approvals.vals()) {
        if (Principal.equal(entry.caller, caller) and entry.args == args) {
          return #Err(#Duplicate({ duplicate_of = entry.block_index }));
        };
      };
    };
    let fee = switch (args.fee) {
      case (?value) {
        if (value != fee_e8s) return #Err(#BadFee({ expected_fee = fee_e8s }));
        value
      };
      case null fee_e8s;
    };
    let from = { owner = caller; subaccount = args.from_subaccount };
    if (ICRC2.accountsEqual(from, args.spender)) {
      return #Err(#GenericError({ error_code = 2; message = "self-approval not allowed" }));
    };
    let current = allowanceOf(from, args.spender);
    switch (args.expected_allowance) {
      case (?expected) {
        if (current.allowance != expected) {
          return #Err(#AllowanceChanged({ current_allowance = current.allowance }));
        };
      };
      case null {};
    };
    switch (args.expires_at) {
      case (?expiry) { if (expiry <= now()) return #Err(#Expired({ ledger_time = now() })) };
      case null {};
    };
    let balance = balanceOf(from);
    if (balance < fee) return #Err(#InsufficientFunds({ balance }));
    setBalance(from, balance - fee);
    setAllowance(from, args.spender, args.amount, args.expires_at);
    let tx = List.empty<(Text, ICRC3.Value)>();
    List.add(tx, ("amt", #Nat(args.amount)));
    List.add(tx, ("from", accountValue(from)));
    List.add(tx, ("spender", accountValue(args.spender)));
    switch (args.fee) { case (?value) List.add(tx, ("fee", #Nat(value))); case null {} };
    switch (args.memo) { case (?value) List.add(tx, ("memo", #Blob(value))); case null {} };
    switch (args.created_at_time) {
      case (?value) List.add(tx, ("ts", #Nat(Nat64.toNat(value))));
      case null {};
    };
    switch (args.expected_allowance) {
      case (?value) List.add(tx, ("expected_allowance", #Nat(value)));
      case null {};
    };
    switch (args.expires_at) {
      case (?value) List.add(tx, ("expires_at", #Nat(Nat64.toNat(value))));
      case null {};
    };
    let index = appendBlock(
      "2approve",
      List.toArray(tx),
      fee,
      args.fee != null,
      #Approve({
        from = NnsBlock.accountIdentifier(from.owner, from.subaccount);
        spender = NnsBlock.accountIdentifier(args.spender.owner, args.spender.subaccount);
        allowance_e8s = args.amount;
        allowance = { e8s = Nat64.fromNat(args.amount) };
        fee = { e8s = Nat64.fromNat(fee) };
        expires_at = switch (args.expires_at) {
          case (?value) ?{ timestamp_nanos = value };
          case null null;
        };
        expected_allowance = switch (args.expected_allowance) {
          case (?value) ?{ e8s = Nat64.fromNat(value) };
          case null null;
        };
      }),
      args.memo,
      args.created_at_time,
    );
    approvals := Array.tabulate<ApproveIdentity>(approvals.size() + 1, func(i) {
      if (i == approvals.size()) ({ caller = caller; args = args; block_index = index }) else approvals[i]
    });
    #Ok(index)
  };

  public shared ({ caller }) func icrc2_transfer_from(args : ICRC2.TransferFromArgs) : async ICRC2.TransferFromResult {
    switch (validateTime(args.created_at_time)) {
      case (#tooOld) return #Err(#TooOld);
      case (#future(value)) return #Err(#CreatedInFuture({ ledger_time = value }));
      case (#ok) {};
    };
    switch (transferDuplicate(caller, args)) {
      case (?index) return #Err(#Duplicate({ duplicate_of = index }));
      case null {};
    };
    let fee = switch (args.fee) {
      case (?value) {
        if (value != fee_e8s) return #Err(#BadFee({ expected_fee = fee_e8s }));
        value
      };
      case null fee_e8s;
    };
    let spender = { owner = caller; subaccount = args.spender_subaccount };
    let gross = args.amount + fee;
    let currentAllowance = allowanceOf(args.from, spender);
    if (not ICRC2.accountsEqual(args.from, spender) and currentAllowance.allowance < gross) {
      return #Err(#InsufficientAllowance({ allowance = currentAllowance.allowance }));
    };
    let balance = balanceOf(args.from);
    if (balance < gross) return #Err(#InsufficientFunds({ balance }));

    setBalance(args.from, balance - gross);
    setBalance(args.to, balanceOf(args.to) + args.amount);
    if (not ICRC2.accountsEqual(args.from, spender)) {
      setAllowance(args.from, spender, currentAllowance.allowance - gross, currentAllowance.expires_at);
    };
    let tx = List.empty<(Text, ICRC3.Value)>();
    List.add(tx, ("amt", #Nat(args.amount)));
    List.add(tx, ("from", accountValue(args.from)));
    List.add(tx, ("to", accountValue(args.to)));
    List.add(tx, ("spender", accountValue(spender)));
    switch (args.fee) { case (?value) List.add(tx, ("fee", #Nat(value))); case null {} };
    switch (args.memo) { case (?value) List.add(tx, ("memo", #Blob(value))); case null {} };
    switch (args.created_at_time) {
      case (?value) List.add(tx, ("ts", #Nat(Nat64.toNat(value))));
      case null {};
    };
    let index = appendBlock(
      "2xfer",
      List.toArray(tx),
      fee,
      args.fee != null,
      #Transfer({
        from = NnsBlock.accountIdentifier(args.from.owner, args.from.subaccount);
        to = NnsBlock.accountIdentifier(args.to.owner, args.to.subaccount);
        amount = { e8s = Nat64.fromNat(args.amount) };
        fee = { e8s = Nat64.fromNat(fee) };
        spender = ?NnsBlock.accountIdentifier(spender.owner, spender.subaccount);
      }),
      args.memo,
      args.created_at_time,
    );
    if (dedup_mode == #conformant) {
      transfers := Array.tabulate<TransferIdentity>(transfers.size() + 1, func(i) {
        if (i == transfers.size()) ({ caller = caller; args = args; block_index = index }) else transfers[i]
      });
    };
    #Ok(index)
  };

  func archiveActor(id : Principal) : ArchiveActor { actor (Principal.toText(id)) };

  func requestedBounds(args : NnsBlock.GetBlocksArgs) : (Nat, Nat) {
    let start = Nat64.toNat(args.start);
    let requestedEnd = start + Nat64.toNat(args.length);
    (start, Nat.min(legacy_blocks.size(), requestedEnd))
  };

  /// Exact legacy NNS history endpoint. The certificate authenticates the SHA-256 hash of the
  /// protobuf-encoded tip block, never the test-only generic ICRC-3 view above.
  public query func query_blocks(args : NnsBlock.GetBlocksArgs) : async NnsBlock.QueryBlocksResponse {
    let (start, end) = requestedBounds(args);
    let localStart = Nat.max(start, archived_count);
    let local = if (localStart >= end) [] else {
      Array.tabulate<NnsBlock.Block>(end - localStart, func(i) { legacy_blocks[localStart + i] })
    };
    let archivedEnd = Nat.min(end, archived_count);
    let archived = if (start >= archivedEnd) [] else {
      switch (archive_id) {
        case (?id) [{
          start = Nat64.fromNat(start);
          length = Nat64.fromNat(archivedEnd - start);
          callback = archiveActor(id).get_blocks;
        }];
        case null [];
      }
    };
    {
      chain_length = Nat64.fromNat(legacy_blocks.size());
      certificate = CertifiedData.getCertificate();
      blocks = local;
      first_block_index = Nat64.fromNat(localStart);
      archived_blocks = archived;
    }
  };

  public query func query_encoded_blocks(
    args : NnsBlock.GetBlocksArgs
  ) : async NnsBlock.QueryEncodedBlocksResponse {
    let (start, end) = requestedBounds(args);
    let localStart = Nat.max(start, archived_count);
    let local = if (localStart >= end) [] else {
      Array.tabulate<Blob>(end - localStart, func(i) { encoded_blocks[localStart + i] })
    };
    let archivedEnd = Nat.min(end, archived_count);
    let archived = if (start >= archivedEnd) [] else {
      switch (archive_id) {
        case (?id) [{
          start = Nat64.fromNat(start);
          length = Nat64.fromNat(archivedEnd - start);
          callback = archiveActor(id).get_encoded_blocks;
        }];
        case null [];
      }
    };
    {
      chain_length = Nat64.fromNat(encoded_blocks.size());
      certificate = CertifiedData.getCertificate();
      blocks = local;
      first_block_index = Nat64.fromNat(localStart);
      archived_blocks = archived;
    }
  };

  public query func archives() : async Archives {
    switch (archive_id) {
      case (?id) ({ archives = [{ canister_id = id }] });
      case null ({ archives = [] });
    }
  };

  public query func tip_of_chain() : async TipOfChainRes {
    {
      certification = CertifiedData.getCertificate();
      tip_index = if (encoded_blocks.size() == 0) 0 else Nat64.fromNat(encoded_blocks.size() - 1);
    }
  };

  public query func icrc3_get_blocks(ranges : [ICRC2.GetBlocksArgs]) : async FullGetBlocksResult {
    let result = List.empty<ICRC2.Block>();
    for (range in ranges.vals()) {
      let end = Nat.min(blocks.size(), range.start + range.length);
      var index = range.start;
      while (index < end) {
        List.add(result, { id = index; block = blocks[index] });
        index += 1;
      };
    };
    { blocks = List.toArray(result); log_length = blocks.size(); archived_blocks = [] }
  };

  public query func icrc3_get_archives(_args : GetArchivesArgs) : async [ArchiveInfo] { [] };

  system func postupgrade() { refreshCertification() };

  /// Test-only controls. They are deliberately isolated in this fixture and are never imported by
  /// the shielded ledger canister.
  public shared func test_set_balance(account : ICRC2.Account, amount : Nat) : async () {
    setBalance(account, amount)
  };
  public shared func test_set_allowance(from : ICRC2.Account, spender : ICRC2.Account, amount : Nat) : async () {
    setAllowance(from, spender, amount, null)
  };
  public shared func test_set_dedup_mode(mode : DedupMode) : async () { dedup_mode := mode };
  public query func test_mode() : async DedupMode { dedup_mode };
  public shared func test_set_fee(value : Nat) : async () { fee_e8s := value };
  public shared func test_set_decimals(value : Nat8) : async () { decimals := value };
  public shared func test_set_archive(id : ?Principal, count : Nat) : async () {
    assert count <= legacy_blocks.size();
    if (count > 0) assert id != null;
    archive_id := id;
    archived_count := count;
  };
  public query func test_created_at_presence() : async [Bool] { created_at_presence };
  public query func test_encoded_blocks() : async [Blob] { encoded_blocks };
  /// Advance the fixture's clock by `ns` nanoseconds (simulates transaction-window passage so a
  /// resume after the window can be tested without a real 24h wait).
  public shared func test_advance_time(ns : Nat) : async () { time_offset_ns += ns };
}
