/// MockSnsBinding.mo: one test canister that answers as an SNS root (list_sns_canisters), as
/// NNS SNS-W (list_deployed_snses) and acts as SNS governance (call: a generic function's
/// execution, which reaches the ledger as a call from this canister). The protocol-fee battery
/// uses it to prove how the ledger's administrator binds to SNS governance.
import Error "mo:core/Error";
import IC "mo:core/InternetComputer";

persistent actor class MockSnsBinding() {
  type Answer = { root : ?Principal; governance : ?Principal; ledger : ?Principal; dapps : [Principal] };
  type Deployed = { root_canister_id : ?Principal; governance_canister_id : ?Principal; ledger_canister_id : ?Principal };

  var answer : ?Answer = null;
  var deployed : [Deployed] = [];

  public func setAnswer(a : ?Answer) : async () { answer := a };
  public func setDeployed(d : [Deployed]) : async () { deployed := d };

  public func list_sns_canisters(_ : {}) : async {
    root : ?Principal; governance : ?Principal; ledger : ?Principal; swap : ?Principal; index : ?Principal;
    dapps : [Principal]; archives : [Principal];
  } {
    switch (answer) {
      case (?a) { { root = a.root; governance = a.governance; ledger = a.ledger; swap = null; index = null; dapps = a.dapps; archives = [] } };
      case null throw Error.reject("TEST: not an SNS root");
    };
  };

  public query func list_deployed_snses(_ : {}) : async { instances : [Deployed] } { { instances = deployed } };

  public func call(target : Principal, method : Text, arg : Blob) : async Blob {
    await IC.call(target, method, arg);
  };
};
