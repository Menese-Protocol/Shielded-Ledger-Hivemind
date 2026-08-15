/// Sandbox ZK-ledger integration PoC.
///
/// Motoko owns the append-only opaque-note log, historical roots, nullifier set, certified root,
/// and PIR. Proof verdicts come from the IN-PROCESS Motoko Groth16 verifier over BLS12-381
/// (`src/groth16/`, vendored from `verifier-lab/`; oracle-gated against arkworks at every layer and
/// measured at 12.6B/10.1B instructions per verify, inside the 40B message budget). The verify
/// is no longer an inter-canister await, so no state-change window exists between the guards and
/// the verdict. Circuit-native Poseidon transitions still come from the stateless tree adapter.

import Array "mo:core/Array";
import Blob "mo:core/Blob";
import CertifiedData "mo:core/CertifiedData";
import Char "mo:core/Char";
import Error "mo:core/Error";
import Int "mo:core/Int";
import List "mo:core/List";
import Map "mo:core/Map";
import Nat "mo:core/Nat";
import Nat32 "mo:core/Nat32";
import Nat64 "mo:core/Nat64";
import Nat8 "mo:core/Nat8";
import Principal "mo:core/Principal";
// Unused by the shipped actor since the PIR hint-corruption hook moved to
// `scripts/test-hooks.frag.mo`, and RETAINED deliberately: the fragment is injected into the
// actor body by `scripts/build-test-wasm.sh` and cannot add its own imports, so the hook build
// needs this one here. Renaming it `_Region` to quiet M0194 would break that build.
import Region "mo:core/Region";
import Runtime "mo:core/Runtime";
import Sha256 "mo:sha2/Sha256";
import Text "mo:core/Text";
import Time "mo:core/Time";
import Timer "mo:core/Timer";
import Prim "mo:⛔";
import CertifiedTuple "CertifiedTuple";
import DetectChain "DetectChain";
import Groth16Multi "groth16/Groth16Multi";
import Groth16Wire "groth16/Groth16Wire";
import ICRC1Block "ICRC1Block";
import ICRC2 "ICRC2";
import ICRC2Block "ICRC2Block";
import ICRC3 "ICRC3";
import NoteAudit "NoteAudit";
import NoteCodec "NoteCodec";
import Pir2 "Pir2";
import PoseidonTree "PoseidonTree";
import StableBlobSet "StableBlobSet";
import StableLog "StableLog";

persistent actor ZkLedger {
  public type Result<T> = { #ok : T; #err : Text };

  public type MeteredVerify = {
    accepted : Bool;
    verify_instructions : Nat64;
    deserialize_instructions : Nat64;
  };
  public type TreeState = {
    filled : [Text];
    root : Text;
    next_index : Nat64;
  };
  public type TreeTransition = {
    state : ?TreeState;
    error : ?Text;
  };
  type TreeOracle = actor {
    empty : shared () -> async TreeTransition;
    append : shared (TreeState, [Text]) -> async TreeTransition;
  };
  type TransferLedger = actor {
    icrc1_transfer : shared ICRC2.TransferArg -> async ICRC2.TransferResult;
    icrc2_transfer_from : shared ICRC2.TransferFromArgs -> async ICRC2.TransferFromResult;
    icrc1_fee : shared query () -> async Nat;
    icrc1_decimals : shared query () -> async Nat8;
  };
  // The reply type MUST be the archive-aware one declared below. ICRC2.GetBlocksResult carries only
  // { log_length; blocks } — no archived_blocks — and Candid silently drops record fields the
  // receiver does not declare, so with that type the archived ranges never reach this canister at
  // all. Reading `page.blocks` and concluding absence was not an oversight in the scan loop; the
  // scan loop could not have seen an archive if it had tried.
  type HistoryAdapter = actor {
    icrc3_get_blocks : GetBlocksCallback;
  };

  public type NoteOrigin = NoteCodec.NoteOrigin;
  type ShieldedNoteBlock = NoteCodec.ShieldedNoteBlock;
  public type Block = { id : Nat; block : ICRC3.Value };
  public type GetBlocksArgs = { start : Nat; length : Nat };
  public type GetBlocksResult = {
    log_length : Nat;
    blocks : [Block];
    archived_blocks : [ArchivedBlocks];
  };
  public type GetBlocksCallback = shared query ([GetBlocksArgs]) -> async GetBlocksResult;
  public type ArchivedBlocks = { args : [GetBlocksArgs]; callback : GetBlocksCallback };
  public type GetArchivesArgs = { from : ?Principal };
  public type ArchiveInfo = { canister_id : Principal; start : Nat; end : Nat };

  public type DepositArgs = {
    value : Nat64;
    from_subaccount : ?Blob;
    created_at_time : Nat64;
    client_nonce : Blob;
    commitment : Blob;
    ephemeral_key : Blob;
    note_ciphertext : Blob;
    proof_hex : Text;
  };
  public type OutputRecord = {
    commitment : Blob;
    ephemeral_key : Blob;
    note_ciphertext : Blob;
  };
  public type CompactTarget = { #roots; #nullifiers; #shields; #unshields };
  var compact_instructions : Nat64 = 0;
  public type TransferArgs = {
    anchor : Blob;
    nullifier_1 : Blob;
    nullifier_2 : Blob;
    output_1 : OutputRecord;
    output_2 : OutputRecord;
    fee : Nat64;
    v_pub_out : Nat64;
    recipient : ?ICRC2.Account;
    created_at_time : ?Nat64;
    proof_hex : Text;
  };
  public type MutationResult = {
    outcome : Text;
    verifier_outcome : Text;
    note_root : Blob;
    note_count : Nat;
    nullifier_count : Nat;
    pool_value : Nat;
    epoch : Nat;
    // instructions executed in the current message slice when the response was built
    // (PostupgradeStats precedent) — the money-path cost telemetry the derived-index
    // decoupling battery asserts on (AC-D6: flag-on delta vs flag-off ≈ 0)
    instructions : Nat64;
  };

  public type LedgerStatus = {
    configured : Bool;
    /// Who holds the administrator role. Exposed so that WHO owns a pool is observable rather than
    /// inferable only by trying an admin-only call. How this value is set is documented at `configure`.
    administrator : ?Principal;
    note_root : Blob;
    note_count : Nat;
    log_length : Nat;
    nullifier_count : Nat;
    historical_root_count : Nat;
    pool_value : Nat;
    epoch : Nat;
    tree_state : ?TreeState;
    transfer_statement_version : Nat;
  };
  public type StorageStatus = {
    layout_version : Nat;
    note_entries : Nat;
    note_bytes : Nat;
    // Region CAPACITY, not bytes used. note_bytes is the data offset; this is what a grow moves,
    // and it is what makes 'the log grew before the payout rather than inside the commit'
    // observable from outside the canister.
    note_log_region_bytes : Nat;
    note_digest : Blob;
    root_entries : Nat;
    root_capacity : Nat;
    root_region_bytes : Nat;
    root_digest : Blob;
    nullifier_entries : Nat;
    nullifier_capacity : Nat;
    nullifier_region_bytes : Nat;
    nullifier_digest : Blob;
    completed_shield_entries : Nat;
    completed_shield_capacity : Nat;
    completed_shield_region_bytes : Nat;
    completed_shield_digest : Blob;
    completed_unshield_entries : Nat;
    completed_unshield_capacity : Nat;
    completed_unshield_region_bytes : Nat;
    completed_unshield_digest : Blob;
  };
  public type RtsStatus = {
    memory_size : Nat;
    heap_size : Nat;
    total_allocation : Nat;
    reclaimed : Nat;
    max_live_size : Nat;
  };
  public type PendingShield = {
    intent_id : Blob;
    caller : Principal;
    output : OutputRecord;
    value : Nat64;
    transfer_args : ICRC2.TransferFromArgs;
    anchor_before : Blob;
    root_after : Blob;
    next_tree : TreeState;
    base_epoch : Nat;
    verifier_outcome : Text;
    attempts : Nat;
    // Token-ledger log length captured BEFORE the token call. Recovery scans blocks from here for a
    // 2xfer carrying memo == intent_id, so it reconciles by idempotency key rather than by the
    // ICRC-2 dedup cache — which expires after the ledger's transaction window and, once expired,
    // would strand a trapped-after-transfer shield (money in pool, no note) permanently.
    ledger_tip_before : Nat;
  };
  public type PendingUnshield = {
    intent_id : Blob;
    caller : Principal;
    output_1 : OutputRecord;
    output_2 : OutputRecord;
    nullifier_1 : Blob;
    nullifier_2 : Blob;
    transfer_args : ICRC2.TransferArg;
    recipient_binding : Blob;
    public_value : Nat64;
    pool_debit : Nat;
    anchor_before : Blob;
    root_after : Blob;
    next_tree : TreeState;
    base_epoch : Nat;
    verifier_outcome : Text;
    attempts : Nat;
    ledger_tip_before : Nat;
  };
  public type PrepaidDepositArgs = {
    value : Nat64;
    from_subaccount : ?Blob;
    created_at_time : Nat64;
    client_nonce : Blob;
  };
  /// One in-flight prepaid-fee token movement (deposit into, or payout from, the fee
  /// subaccount). Stable, resumable through `resume_prepaid` with memo reconciliation from
  /// `ledger_tip_before` — the same dedup-window-independent recovery the shield leg uses.
  public type PendingPrepaid = {
    intent_id : Blob;
    caller : Principal;
    op : {
      // credit `value` to the caller's prepaid balance once the pull is observed
      #deposit : { value : Nat64; transfer_args : ICRC2.TransferFromArgs };
      // `reserved` was already debited from the source when the intent was created;
      // a deterministic token failure refunds it, finalization keeps it debited
      #withdraw : {
        reserved : Nat;
        source : { #balance; #revenue };
        transfer_args : ICRC2.TransferArg;
      };
    };
    ledger_tip_before : Nat;
    attempts : Nat;
  };
  public type PrepaidFeeStatus = {
    enabled : Bool;
    rate : Nat;
    total_prepaid : Nat;
    revenue : Nat;
    fee_account : ICRC2.Account;
    holders : Nat;
    pending : ?PendingPrepaid;
    completed_intents : Nat;
  };

  /// The publicly visible shape of an in-flight token intent.
  ///
  /// atomicity_status is an unauthenticated query, so it must not carry anything that links a
  /// shielded note to a transparent identity. The full PendingShield/PendingUnshield records do:
  /// `caller` is the spending principal, `transfer_args.to`/`.from` is the transparent account,
  /// and the nullifiers name the exact notes being consumed. Published together they defeat the
  /// unlinkability the pool exists to provide, to any anonymous caller, for the whole time an
  /// operation is in flight. Only the operational fields an outside observer needs in order to
  /// reason about atomicity are exposed here; the detail is admin-gated in pending_intent_detail.
  public type AtomicityPending = {
    intent_id : Blob;
    base_epoch : Nat;
    attempts : Nat;
    verifier_outcome : Text;
    ledger_tip_before : Nat;
  };

  public type AtomicityStatus = {
    token_configured : Bool;
    token_ledger : ?Principal;
    history_adapter : ?Principal;
    transparent_ledger_fee : Nat;
    transparent_ledger_decimals : Nat8;
    pool_account : ICRC2.Account;
    pending : ?AtomicityPending;
    pending_unshield : ?AtomicityPending;
    completed_intents : Nat;
    completed_intent_digest : Blob;
    completed_unshield_intents : Nat;
    completed_unshield_intent_digest : Blob;
    test_fault_armed : Bool;
  };
  public type CertifiedSnapshot = {
    last_block_index : ?Nat;
    last_block_hash : ?Blob;
    note_root : Blob;
    note_count : Nat;
    encoding_version : Nat;
    archive_manifest : Blob;
    certificate : ?Blob;
    hash_tree : Blob;
  };
  public type DataCertificate = { certificate : Blob; hash_tree : Blob };

  public type LweCiphertext = { a : [Nat64]; b : Nat64 };
  public type LwePirArgs = { selectors : [LweCiphertext] };
  public type LweQueryTrace = {
    records_scanned : Nat;
    selectors_received : Nat;
    lwe_dimension : Nat;
    output_bits : Nat;
    selector_decryptions : Nat;
    target_index_parameters : Nat;
    target_dependent_branches : Nat;
    instructions : Nat64;
  };
  public type LwePirResponse = {
    ciphertexts : [LweCiphertext];
    trace : LweQueryTrace;
    snapshot_root : Blob;
  };

  let ENCODING_VERSION : Nat = 1;
  let STABLE_LAYOUT_VERSION : Nat = 1;
  let LWE_DIMENSION : Nat = 630;
  let RECORD_BITS : Nat = 256;
  let BIT_SHIFTS : [Nat] = [7, 6, 5, 4, 3, 2, 1, 0];

  var configuring : Bool = false;
  var administrator : ?Principal = null;
  var verifier_id : ?Principal = null;
  var tree_oracle_id : ?Principal = null;
  var token_ledger_id : ?Principal = null;
  var history_adapter_id : ?Principal = null;
  var token_configuring : Bool = false;
  var transparent_ledger_fee : Nat = 0;
  var transparent_ledger_decimals : Nat8 = 0;
  var pool_subaccount : ?Blob = null;
  var transfer_vk_hex : Text = "";
  var deposit_vk_hex : Text = "";
  // Parsed + prepared ONCE at configure (subgroup-validated, fixed pairs precomputed) — the
  // per-proof path never re-validates the vk. Stable: survives upgrades with the hexes.
  // Monotonic keyset epoch. Bumped by configure and by every rotate_verifying_keys_v2, and
  // carried in the certified vk anchor so a client can detect a rotation it has not adopted.
  var vk_epoch : Nat64 = 0;
  var transfer_vk_prepared : ?Groth16Multi.PreparedVk = null;
  var deposit_vk_prepared : ?Groth16Multi.PreparedVk = null;
  // Flat-limb projection of the prepared vks: rebuilding it inline cost a measured
  // 18.7 MB of allocation per verify. TRANSIENT (wiped by upgrades, rebuilt lazily) and a pure
  // deterministic function of the PreparedVk. INVARIANT: every write to *_vk_prepared writes
  // the matching *_vk_flat in the same statement block (configure / rotate are the only sites).
  transient var transfer_vk_flat : ?Groth16Multi.FlatVk = null;
  transient var deposit_vk_flat : ?Groth16Multi.FlatVk = null;
  var tree_state : ?TreeState = null;
  // ==== in-canister Poseidon Merkle frontier (single switch, default OFF) ====
  // OFF: byte-identical legacy — the tree oracle's returned root is trusted (the
  // counterfeit-class exposure this flag closes). ON: the ledger computes every tree
  // transition itself (`PoseidonTree.mo`, differentially gated against arkworks); an
  // attached oracle is only a cross-check whose disagreement flips the sticky
  // fail-closed guard, and with the oracle detached (`set_tree_oracle(null)`) the
  // ledger stands alone. All-or-nothing: no per-path enable.
  /// DEFAULT ON. It shipped false, and the setter's own comment below says what that meant:
  /// "byte-identical legacy: oracle root trusted". With it off the ledger computes no transition of
  /// its own, frontierCrossCheck runs no check, and parseTransition validates only the SHAPE of the
  /// oracle's reply — so an oracle that returns a well-formed root of its own choosing has that root
  /// written into historical_roots and installed as note_root. The blast radius is counterfeit
  /// notes and pool drain.
  ///
  /// Changing this initialiser fixes FRESH pools only, because this is a stable variable and a
  /// deployed pool keeps its stored false. That is why the value path also refuses while it is off —
  /// see shield and confidential_transfer. The two together are the fix; either alone is not.
  var tree_frontier_enabled : Bool = true;

  /// QUARANTINE ON UPGRADE. A pool upgraded to the intake fix may ALREADY hold
  /// non-canonical values stored by a pre-fix build; Phase 1 closes the door, it does not clean the
  /// room. These record that condition. NOTHING here traps: `postupgrade` already carries two
  /// pre-existing traps, and a trap there ROLLS BACK THE UPGRADE, leaving the pool running the OLD
  /// broken code — so the fix could never reach the pool that needs it most. Quarantine REPORTS.
  var state_quarantine : Bool = false;
  var state_quarantine_values : [Text] = [];
  // zeroHashes() is a pure function of the gate-validated constants (275M instr once);
  // TRANSIENT: wiped by upgrades, rebuilt lazily — the FlatVk pattern.
  transient var zero_hashes_cache : ?[Nat] = null;
  var note_root : Blob = "";
  let historical_roots = StableBlobSet.newState();
  let spent_nullifiers = StableBlobSet.newState();
  let completed_shield_intents = StableBlobSet.newState();
  let completed_unshield_intents = StableBlobSet.newState();
  let note_log = StableLog.newState();

  // ==== PIR v2 query layer (default OFF; src/Pir2.mo) ====
  // Additive and gated: while `pir2_state.enabled` is false the append path carries no v2
  // code, no timer is armed, and every v2 endpoint rejects, so an unset deployment is
  // byte-identical to the pre-v2 ledger.
  //
  // DERIVED-INDEX DECOUPLING: the financial append is
  // authoritative and complete WITHOUT the PIR index; a background fold driver trails it
  // with the freshness cursor `pir2_state.record_count` (== the `indexed_upto` watermark —
  // ONE variable, never two). All fold work — initial backfill after `pir2_enable`,
  // steady-state catch-up, and repair refolds — runs through one awaited self-call chunk
  // (`__pir2_fold_chunk`, audit-tick pattern) driven by a 2s recurring watchdog plus a
  // chained fast path while behind. A trapping chunk is caught in the driver, recorded
  // (#degraded + last error), and retried with exponential backoff; the money path is
  // unaffected by construction. While the sticky audit guard is set the fold pauses
  // (fail-closed extends to derived state).
  let pir2_state = Pir2.newState();
  var pir2_backfilling : Bool = false;
  var pir2_backfill_cursor : Nat = 0;
  // Records per fold chunk — the per-record fold is ~198M instr (measured, n=1152), so a
  // chunk of 20 (~4.0e9 incl. decode overhead, measured 196M/record) stays under the 5e9 committed budget.
  let PIR2_BACKFILL_PER_TICK : Nat = 20;
  let PIR2_FOLD_FAILURE_LIMIT : Nat = 3;
  let PIR2_CHAIN_REPLAY_PER_CHUNK : Nat = 256;
  let PIR2_ZERO_BYTES_PER_CHUNK : Nat64 = 8_388_608;
  var pir2_fold_retries : Nat = 0;
  /// Consecutive DETERMINISTIC trap classifications. A trap recurs on every retry, so retrying
  /// it is unbounded work that can never succeed; a transient failure deserves the existing
  /// unbounded retry. The catch already distinguishes the two and then treated them identically.
  var pir2_fold_trap_streak : Nat = 0;
  /// Set when the streak hits PIR2_FOLD_FAILURE_LIMIT. Cleared by pir2_reindex, so stopping does
  /// not become the permanent latch A5 was filed for.
  var pir2_fold_terminal : Bool = false;
  var pir2_last_fold_error : ?Text = null;
  var pir2_fold_backoff_until : Nat64 = 0;
  var pir2_last_chunk_instructions : Nat64 = 0;
  // Repair state machine (stable — an upgrade mid-repair MUST resume, or a half-zeroed hint
  // region would be refolded over dirty bytes): chain replay from the DPAGE checkpoint up to
  // the reset point, then chunked zeroing of every affected shard's hint span, then the
  // normal catch-up refolds from the rewound cursor.
  var pir2_repair : ?Pir2Repair = null;
  transient var pir2_fold_inflight : Bool = false;
  transient var pir2_driver_armed : Bool = false;
  var last_block_hash : ?Blob = null;
  var pool_value : Nat = 0;
  var epoch : Nat = 0;
  var pending_shield : ?PendingShield = null;
  var pending_unshield : ?PendingUnshield = null;
  // ==== prepaid fee balance (single switch, default OFF) ====
  // OFF: byte-identical legacy — no prepaid state is read on any path, deposits reject, and
  // the transfer path carries zero fee logic. ON with rate 0: mechanism armed but free.
  // ON with rate > 0: every accepted confidential_transfer debits `rate` from the caller's
  // prepaid balance ATOMICALLY with acceptance — an internal state write with no token call
  // and no public block, so shielded transfers leave no per-transfer fee trail on the token
  // ledger (the deanonymization vector a visible per-transfer payment would create).
  // Custody for these balances lives in the DEDICATED fee subaccount below, never in the
  // pool account, so the pool solvency identity (custody == pool_value == Σ unspent notes)
  // is untouched. Fee-side identity: fee-account custody == total_prepaid + revenue
  // + (in-flight withdrawal reservation, while one is pending).
  var prepaid_fee_enabled : Bool = false;
  var prepaid_fee_rate : Nat = 0;
  // Σ of all balances in prepaid_fee_balances — maintained by credit/debit/refund so status
  // and solvency checks never walk the map.
  var prepaid_fee_total : Nat = 0;
  // debited fees, payable out by the administrator through prepaid_fee_collect
  var prepaid_fee_revenue : Nat = 0;
  let prepaid_fee_balances = Map.empty<Principal, Nat>();
  // completed prepaid intents (deposit AND withdraw/collect) for idempotent replay answers
  let completed_prepaid_intents = Map.empty<Blob, ()>();
  var pending_prepaid : ?PendingPrepaid = null;
  // Prepaid debit reserved by the CURRENT pending unshield (0 when none): the unshield fee is
  // debited when the pending intent is created — at finalize time the payout has already
  // happened and a failed debit could no longer reject the operation — and refunded iff the
  // token leg fails with a deterministic no-effect error (the only path that cancels the
  // intent). A separate stable var (not a PendingUnshield field) keeps the stable record
  // type backward-compatible.
  var pending_unshield_prepaid_debit : Nat = 0;

  /// The unshield commit's PREPARE output. A NEW TOP-LEVEL STABLE VARIABLE rather than a field of
  /// PendingUnshield, which would be an M0170 incompatible change and would make every deployed pool
  /// unupgradeable — the lesson StableBlobSet.State already taught this tree. The pattern is
  /// pending_unshield_prepaid_debit directly above: extra state for the pending unshield, carried
  /// alongside it rather than inside it.
  ///
  /// It is a CACHE, NOT AUTHORITY. Every field is recomputable from the pending intent; it names the
  /// intent it was built for; and a record that is absent or names a different intent is rebuilt
  /// rather than treated as an error. That is what makes a pool holding a live pending intent at the
  /// moment of upgrade a non-event: the intent's own shape is untouched, so there is nothing to
  /// migrate, and the first resume fills this in.
  public type PreparedUnshield = {
    intent_id : Blob;
    encoded_1 : Blob;
    encoded_2 : Blob;
    hash_1 : Blob;      // block 1's hash: becomes last_block_hash, and is block 2's phash
    hash_2 : Blob;      // block 2's hash
    position_1 : Nat;
  };
  var pending_unshield_prepared : ?PreparedUnshield = null;

  // An upgraded v1 deployment remains locked until the administrator rotates the transfer VK.
  // A fresh configure() installs the recipient-bound v2 statement immediately.
  var transfer_statement_version : Nat = 1;
  // ==== fault-injection state — ARMED FROM NOWHERE IN THIS BINARY ====
  //
  // The three arming entry points, and the one-way seal that used to gate them, are NOT in this
  // file. They live in `scripts/test-hooks.frag.mo` and exist only in the hook build produced by
  // `scripts/build-test-wasm.sh`, alongside the strictly more dangerous primitives that were
  // already handled that way (`test_force_double_credit`, `test_set_tree_root_hex`).
  //
  // Why the seal went with them. The seal was a PRESENT-TENSE assertion doing duty as a
  // PAST-TENSE guarantee: its status query told a reviewer the hooks cannot be used from now on,
  // and told them nothing about whether one had been used an hour earlier. No shipped state
  // could promote it, because nothing recorded an invocation. Build-time exclusion replaces that
  // unverifiable claim with one anyone can check without trusting the operator: the installed
  // module hash equals the hash of a binary whose source provably contains no arming code.
  // CWE-489 catalogues the mitigation at the Build/Distribution phase for exactly this reason.
  //
  // 🔴 WHAT REMAINS, STATED SO IT IS NOT MISREAD. The two flags below and their consumption sites
  // are still here, because the fragment is injected additively and cannot reach inside a product
  // function body to reinstate a check. In this binary nothing can set them: with the arming
  // entries absent, the only writer is a stable-state stager — `ScaleFixture.test_preset_fail_after_token`
  // writing the variable before a fixture-to-ledger upgrade, which is how the batteries arm it and
  // which no production pool has a path to. Absence of an ingress is what this change buys; it is
  // not the same as absence of the branch, and the two must not be conflated.
  /// RESERVED, never read, never written. This is the seal flag D-3 retired; the sealer, the
  /// status query and all three arming entries are gone, and nothing in this file consults it.
  ///
  /// It is kept DECLARED because deleting a stable variable under enhanced orthogonal persistence
  /// is not free, and the alternatives were measured rather than reasoned about. A migration
  /// expression that consumes it (`with migration = func(old : { test_hooks_sealed : Bool }) : {}`)
  /// upgrades a pre-D-3 pool correctly — and then refuses two upgrades this repository performs
  /// constantly, because dfx checks stable compatibility against the canister's DECLARED main:
  ///
  ///   fixture -> ledger staging   M0169 "the previous program version does not contain ..."
  ///   this build -> this build    M0169, same cause
  ///   pre-D-3 -> this build       Upgraded code   (the only arm it helps)
  ///
  /// Writing the consumed field `?Bool` so it tolerates absence passes the static check and then
  /// TRAPS at runtime (IC0503) on both arms, rolling the upgrade back — a loud refusal turned into
  /// a silent-looking failure, so it was rejected. Deleting the variable with no migration at all
  /// refuses every pre-D-3 baseline install, which is most of this repository's red legs.
  ///
  /// So the field is reserved rather than removed: one name, one meaning, never reused — the
  /// Protocol Buffers reserved-field discipline: reserve a retired name, never reuse it. What the
  /// D-3 change buys is the ARMING SURFACE, and that is gone from the interface, which
  /// `scripts/hook-exclusion-battery.sh` measures directly against the shipped candid and the
  /// running canister. Removing the declaration is an operator decision with the costs above, not
  /// a cleanup.
  var test_hooks_sealed : Bool = false;
  var test_fail_after_token_once : Bool = false;
  // While > 0, the PIR fold path traps. In the synchronous wiring the in-message rollback keeps
  // the counter armed (every transfer traps until disarmed) — the exact money-path coupling the
  // derived-index decoupling removes.
  var test_pir2_fold_trap_remaining : Nat = 0;
  let stable_layout_version : Nat = STABLE_LAYOUT_VERSION;

  // ==== background stable-state audit (postupgrade-scale fix) ====
  // The old postupgrade ran the full per-note walk in ONE message and hit the wasm64
  // 6 GiB cap at 51,411 notes (measured 3.0M instr + 180KB alloc per note). postupgrade
  // now performs O(1)/O(k) bounded checks and delegates the full walk to this
  // timer-driven audit: chunked, cursor in stable state, EXACTLY the old checks in the
  // old order with the old error strings (NoteAudit.referenceCheck is the contract; the
  // fast path falls back to it on any anomaly). A FAIL (or a deterministic trap inside
  // a chunk) flips the sticky fail-closed guard below.
  public type AuditState = { #running; #pass; #fail : { code : Text; index : Nat } };
  public type AuditPhase = {
    #log_index; #set_roots; #set_nullifiers; #set_shields; #set_unshields; #notes; #tail;
  };
  public type AuditStatus = {
    state : AuditState;
    phase : AuditPhase;
    cursor : Nat;
    total : Nat;
    audit_epoch : Nat;
    last_completed_at : ?Nat64;
    last_chunk_at : ?Nat64;
    chunk_retries : Nat;
    guard : ?Text;
    guard_epoch : Nat;
  };
  // #pass at genesis: the empty install state is vacuously valid (and the certified
  // audit leaf must hash identically on a never-upgraded instance and a post-upgrade
  // instance whose audit passed — e2e G2/G4 compare those tuples byte-for-byte).
  var audit_state : AuditState = #pass;
  var audit_phase : AuditPhase = #tail;
  var audit_cursor : Nat = 0;
  var audit_expected_parent : ?Blob = null;
  var audit_log_expected_offset : Nat64 = 16;
  var audit_log_captured_entries : Nat64 = 0;
  var audit_log_captured_offset : Nat64 = 0;
  var audit_set_captured_table : Nat64 = 0;
  var audit_set_captured_capacity : Nat64 = 0;
  var audit_set_captured_count : Nat64 = 0;
  var audit_set_captured_puts : Nat = 0;
  // The migration cursor at the start of a set's walk. A window spreads a set's entries across two
  // tables, and carrying one entry from the old table to the new one moves it from an index the walk
  // may already have passed to one it may already have passed — so a cursor that moves mid-walk can
  // double-count or miss, exactly as a racing insert can. It is captured and re-checked for the same
  // reason, and reuses the same restart machinery.
  var audit_set_captured_cursor : Nat64 = 0;
  var audit_set_observed : Nat64 = 0;
  var audit_set_restarts : Nat = 0;
  var audit_epoch : Nat = 0;
  var audit_last_completed_at : ?Nat64 = null;
  var audit_last_chunk_at : ?Nat64 = null;
  var audit_chunk_retries : Nat = 0;
  // Fail-closed guard: set by an audit FAIL, sticky across upgrades, cleared only by
  // clear_audit_guard (admin) after a NEWER audit epoch has re-run green.
  var guard_code : ?Text = null;
  var guard_epoch : Nat = 0;
  // NON-BLOCKING divergence signal for the finalize frontier cross-check. A finalize
  // frontier mismatch is corruption-only (unreachable in the honest case under the
  // `note_root == anchor_before` guard) and is deliberately NOT escalated to the sticky
  // `guard_code` — doing so would block the resume that converges the money, turning a
  // silent per-intent wedge into a funds-availability bug. Instead it is COUNTED here, so
  // the operator has an observable without the ledger fail-closing. Observable-only; never gates.
  var finalize_frontier_mismatch_count : Nat = 0;
  var finalize_frontier_mismatch_last : ?Blob = null;
  // put counters: exact-count contention detection for the chunked set walks
  var roots_put_counter : Nat = 0;
  var nullifiers_put_counter : Nat = 0;
  var shields_put_counter : Nat = 0;
  var unshields_put_counter : Nat = 0;
  // Incremental CHANGE-DETECTION digests (replace the O(n) region walks the old
  // StableLog.digest/StableBlobSet.digest performed inside storage_status /
  // atomicity_status): the log digest is a sha256 chain folded at append; each set
  // digest is the XOR of sha256(key) folded at first-insert. On a state migrated from a
  // pre-fix wasm they cover post-migration mutations only (documented; nothing asserts
  // on digests of migrated instances).
  var note_log_chain_digest : Blob = Blob.fromArray(Array.repeat<Nat8>(0, 32));
  // Certified detection-stream anchor (additive, default OFF). Flag off ⇒ no maintenance and the
  // certifiedTuple `detect_stream` label is absent ⇒ state hash byte-identical to 44692fc.
  // Genesis-only enable keeps the chain covering the FULL history without a backfill path.
  var detect_chain_enabled : Bool = false;
  let detect_chain_state : DetectChain.State = DetectChain.newState();
  // Incremental boundary-Merkle frontier (O(log B) per boundary; replaces the old O(B)
  // full-root recompute on the append path). TRANSIENT on purpose: the stable shape of
  // `detect_chain_state` is unchanged (stable-compatible by construction) and the frontier
  // is a pure function of the persisted boundary list — rebuilt here on install AND on
  // every upgrade at O(B) hashing over the boundary COUNT only (B ≤ 24,414 at 10^8 notes;
  // measured inside postupgrade_instructions, bounded by the soak's 2B-instruction gate).
  transient let detect_chain_frontier : DetectChain.Frontier = DetectChain.frontierFromBoundaries(detect_chain_state.boundaries);
  // Audit-side detect-chain recompute (flag-gated; small: one 32-B chain + ≤⌈log2 B⌉
  // frontier nodes). Walked alongside the #notes phase and compared to the live anchor
  // ONLY in the message where the cursor catches the live noteCount() — the same
  // atomic-tail discipline as audit_expected_parent == last_block_hash.
  var audit_detect_chain : Blob = Blob.fromArray(Array.repeat<Nat8>(0, 32));
  var audit_detect_covered : Nat = 0;
  let audit_detect_frontier : DetectChain.Frontier = DetectChain.emptyFrontier();
  // Detect-chain rebuild (admin recovery): the anchor is a pure function of the note log,
  // so a corrupted anchor is rebuilt from scratch by a chunked walk that swaps into the
  // live state atomically in the message that catches the live tail. Progress is stable;
  // postupgrade re-arms an in-flight rebuild (timers do not survive upgrades).
  var detect_rebuild_active : Bool = false;
  var detect_rebuild_error : ?Text = null;
  var detect_rebuild_cursor : Nat = 0;
  var detect_rebuild_chain : Blob = Blob.fromArray(Array.repeat<Nat8>(0, 32));
  var detect_rebuild_covered : Nat = 0;
  let detect_rebuild_boundaries : List.List<Blob> = List.empty<Blob>();
  let detect_rebuild_frontier : DetectChain.Frontier = DetectChain.emptyFrontier();
  var detect_rebuild_retries : Nat = 0;
  var roots_fold_digest : Blob = Blob.fromArray(Array.repeat<Nat8>(0, 32));
  var nullifiers_fold_digest : Blob = Blob.fromArray(Array.repeat<Nat8>(0, 32));
  var shields_fold_digest : Blob = Blob.fromArray(Array.repeat<Nat8>(0, 32));
  var unshields_fold_digest : Blob = Blob.fromArray(Array.repeat<Nat8>(0, 32));
  // postupgrade telemetry (T1: cost must stay ~flat vs note count)
  var postupgrade_instructions : Nat64 = 0;
  /// Instructions consumed by `configure` up to its first await. Same shape as
  /// `pir2_last_chunk_instructions` and `postupgrade_instructions`; the pre-await segment is the one
  /// that was carrying both vk preparations and 51.1% of the 40e9 budget.
  var configure_prepare_instructions : Nat64 = 0;
  var postupgrade_heap_before : Nat = 0;
  var postupgrade_heap_after : Nat = 0;
  transient let note_checker = NoteAudit.Checker();

  // chunk sizes from the Phase-2d measurement (≥4× instruction headroom against the
  // 40B DTS budget + a 256 MiB per-chunk allocation envelope): fast path 1.40M instr /
  // 35.3KB alloc per note → K=4096 ≈ 5.7B instr + 145 MiB; slot walk 386 instr/slot →
  // 4M slots ≈ 1.6B instr (the contended-restart path is reachable only above 4M slots
  // ≈ 2.8M entries — far beyond tier; it restarts then fails LOUD, never band-passes);
  // index walk 623 instr/entry → 1M entries ≈ 0.65B instr.
  let AUDIT_NOTES_PER_CHUNK : Nat = 4096;
  // Companion BYTE budget for the note walk. AUDIT_NOTES_PER_CHUNK bounds how many notes a
  // chunk visits; it does not bound the WORK, because the per-note cost is linear in the stored
  // note size (NoteAudit.checkNote copies the whole frame byte-at-a-time and SHA-256s the
  // payload) and note_ciphertext has no upper bound on ingress. The 4096 constant was sized
  // from a measurement on ordinary notes (see the note above: 1.40M instr / 35.3KB alloc each);
  // a window of inflated notes multiplies both figures without touching the count.
  //
  // 8 MiB is chosen so the count cap still binds first for ordinary traffic — measured mean
  // encoded note size on a seeded fixture is 395 B, so 4096 ordinary notes are ~1.6 MB, five
  // times under this ceiling and therefore byte-for-byte unchanged in behaviour — while an
  // abnormal window stops early instead of running to the instruction or allocation limit.
  let AUDIT_BYTES_PER_CHUNK : Nat = 8_388_608;
  /// Resumable exit. The byte/count caps above bound WORK; this bounds COST, which is what the
  /// 40e9 per-message limit actually charges. A chunk that reaches it exits with done=false and its
  /// cursor, so the next message resumes rather than restarting -- which is only expressible because
  /// the reply carries `resume_cursor`. Measured with Prim.performanceCounter(0), already used at
  /// :1642 for pir2_last_chunk_instructions. COMPILE-TIME CONSTANT: there is no env override in this
  /// canister (verified: zero Env/getenv references in this file), so raising the bound beyond reach
  /// requires a BUILD VARIANT, exactly as the optional-cursor variant did. An earlier version of
  /// this comment claimed env-overridable; that was false and is corrected here.
  let AUDIT_INSTRUCTIONS_PER_CHUNK : Nat64 = 20_000_000_000;
  let AUDIT_SLOTS_PER_CHUNK : Nat64 = 4_194_304;
  let AUDIT_INDEX_PER_CHUNK : Nat64 = 1_048_576;

  /// PRE-FLIGHT REFUSAL for `configure`. `configure` runs `Groth16Wire.parseAndPrepareVk` on each
  /// key IN-PROCESS with no way to exit — the two preparations carried 20,428,523,632 instructions
  /// = 51.1% of the 40e9 per-message limit. `MAX_VK_BYTES` (16_384) bounds decode-DoS but NOT
  /// preparation cost, so a vk between ~2.3 KB and 16 KB passes the size check yet cannot be
  /// prepared inside one message. There is no loop to exit, so a message must be able to REFUSE
  /// TO START, before touching any state.
  ///
  /// THE COST MODEL, MEASURED (not quoted). `tests/ScaleFixture.measure_vk_prepare` wraps the exact
  /// production `Groth16Wire.parseAndPrepareVk` behind `Prim.performanceCounter(0)`. Run 2026-08-10
  /// on the two production keys:
  ///   deposit  vk  976 hex chars ->  8_551_286_600 instr
  ///   transfer vk 1552 hex chars -> 11_877_237_032 instr   (sum 20.4e9, the figure quoted above)
  /// A line through those two points: cost(hexlen) ~= 2.916e9 + 5.774e6 * hexlen. The constants
  /// below round the intercept and slope UP so the estimate never UNDER-predicts a real preparation
  /// (an under-estimate would admit a budget-buster — the failure this guard exists to prevent).
  /// Only two production vk sizes exist in-tree, so this is a two-point line, not a characterised
  /// superlinear model; it is deliberately conservative rather than tight, exactly as `MAX_VK_BYTES`
  /// is. New keys are re-measured, not assumed.
  let VK_PREPARE_INSTR_INTERCEPT : Nat = 3_000_000_000;
  let VK_PREPARE_INSTR_PER_HEX_CHAR : Nat = 5_800_000;
  /// Refuse a preparation predicted to exceed this. 30e9 = 75% of the 40e9 message limit, reserving
  /// headroom for the rest of the configure message (the controller/oracle/parse/commit work that
  /// shares it). Both production keys (est. ~8.7e9 and ~12.0e9) clear it with wide margin; a vk above
  /// ~4_650 hex chars (~2.3 KB) is refused before `parseAndPrepareVk` charges for it.
  let VK_PREPARE_INSTR_CEILING : Nat = 30_000_000_000;
  func estimatedVkPrepareInstructions(vkHex : Text) : Nat {
    VK_PREPARE_INSTR_INTERCEPT + VK_PREPARE_INSTR_PER_HEX_CHAR * vkHex.size()
  };
  let AUDIT_CHUNK_FAILURE_LIMIT : Nat = 3;
  let AUDIT_SET_RESTART_LIMIT : Nat = 3;

  /// The audit driver re-arms immediately on every `done = false` return (`Timer.setTimer
  /// (#seconds 0, auditTick)`), so a chunk that returns without advancing spins forever, burning
  /// cycles and never completing. Enumerating the four return sites shows none does — but that
  /// result rests on these two constants rather than on structure: at `AUDIT_SLOTS_PER_CHUNK = 0`
  /// the set phase computes `end == from`, never advances the cursor, skips the completion branch
  /// and LIVELOCKS; at `AUDIT_SET_RESTART_LIMIT = 0` the contended-walk branch can never fail closed.
  /// Neither is caught by the type system and both are one edit away, so assert them where the
  /// canister cannot serve without passing: the actor body on install, and postupgrade on upgrade.
  func assertAuditProgressConstants() {
    if (AUDIT_SLOTS_PER_CHUNK == 0) {
      Runtime.trap("init:audit-slots-per-chunk-zero:set-phase-would-livelock");
    };
    if (AUDIT_SET_RESTART_LIMIT == 0) {
      Runtime.trap("init:audit-set-restart-limit-zero:contended-walk-would-never-fail-closed");
    };
  };
  assertAuditProgressConstants();

  StableBlobSet.ensureInit(historical_roots);
  StableBlobSet.ensureInit(spent_nullifiers);
  StableBlobSet.ensureInit(completed_shield_intents);
  StableBlobSet.ensureInit(completed_unshield_intents);
  StableLog.ensureInit(note_log);

  func noteCount() : Nat { StableLog.size(note_log) };
  func rootCount() : Nat { StableBlobSet.size(historical_roots) };
  func nullifierCount() : Nat { StableBlobSet.size(spent_nullifiers) };
  func completedShieldCount() : Nat { StableBlobSet.size(completed_shield_intents) };
  func completedUnshieldCount() : Nat { StableBlobSet.size(completed_unshield_intents) };

  func selfPrincipal() : Principal { Principal.fromActor(ZkLedger) };
  func poolAccount() : ICRC2.Account { { owner = selfPrincipal(); subaccount = pool_subaccount } };
  func tokenConfigured() : Bool { token_ledger_id != null and history_adapter_id != null };

  func isAdministrator(caller : Principal) : Bool {
    switch (administrator) { case (?value) Principal.equal(value, caller); case null false }
  };

  func tokenActor() : TransferLedger {
    switch (token_ledger_id) {
      case (?id) actor (Principal.toText(id));
      case null Runtime.trap("unconfigured token ledger");
    }
  };

  func historyActor() : HistoryAdapter {
    switch (history_adapter_id) {
      case (?id) actor (Principal.toText(id));
      case null Runtime.trap("unconfigured history adapter");
    }
  };

  func shieldIntentId(caller : Principal, args : DepositArgs) : Blob {
    let entries = List.empty<(Text, ICRC3.Value)>();
    List.add(entries, ("domain", #Text("zk-ledger/icrc2-shield/v1")));
    List.add(entries, ("caller", #Blob(Principal.toBlob(caller))));
    switch (args.from_subaccount) {
      case (?value) List.add(entries, ("from_subaccount", #Blob(value)));
      case null {};
    };
    List.add(entries, ("created_at_time", #Nat(Nat64.toNat(args.created_at_time))));
    List.add(entries, ("client_nonce", #Blob(args.client_nonce)));
    List.add(entries, ("value", #Nat(Nat64.toNat(args.value))));
    List.add(entries, ("commitment", #Blob(args.commitment)));
    List.add(entries, ("ephemeral_key", #Blob(args.ephemeral_key)));
    List.add(entries, ("note_ciphertext", #Blob(args.note_ciphertext)));
    switch (token_ledger_id) {
      case (?id) List.add(entries, ("token_ledger", #Blob(Principal.toBlob(id))));
      case null {};
    };
    List.add(entries, ("pool_owner", #Blob(Principal.toBlob(selfPrincipal()))));
    switch (pool_subaccount) {
      case (?value) List.add(entries, ("pool_subaccount", #Blob(value)));
      case null {};
    };
    ICRC3.hashValue(#Map(List.toArray(entries)))
  };

  func zeroField() : Blob { Blob.fromArray(Array.repeat<Nat8>(0, 32)) };

  /// Canonical recipient commitment used as the eighth Groth16 public input. Hashing includes
  /// the pool and token canisters, so a proof cannot be replayed into another pool or asset. The
  /// high byte is cleared because field wire encoding is little-endian and 31 bytes are safely
  /// below the BLS12-381 scalar modulus.
  func recipientBindingValue(recipient : ICRC2.Account) : Result<Blob> {
    switch (recipient.subaccount) {
      case (?value) { if (value.size() != 32) return #err("REJECT:recipient-subaccount-length") };
      case null {};
    };
    let token = switch (token_ledger_id) {
      case (?value) value;
      case null return #err("REJECT:token-unconfigured");
    };
    let entries = List.empty<(Text, ICRC3.Value)>();
    List.add(entries, ("domain", #Text("picp-unshield-recipient/v1")));
    List.add(entries, ("pool", #Blob(Principal.toBlob(selfPrincipal()))));
    List.add(entries, ("token", #Blob(Principal.toBlob(token))));
    List.add(entries, ("owner", #Blob(Principal.toBlob(recipient.owner))));
    switch (recipient.subaccount) {
      case (?value) List.add(entries, ("subaccount", #Blob(value)));
      case null {};
    };
    let digest = Blob.toArray(ICRC3.hashValue(#Map(List.toArray(entries))));
    if (digest.size() != 32) return #err("REJECT:recipient-binding-hash");
    let field = Prim.Array_init<Nat8>(32, 0);
    var i : Nat = 0;
    while (i < 31) {
      field[i] := digest[i];
      i += 1;
    };
    #ok(Blob.fromArray(Array.fromVarArray(field)))
  };

  /// `intent_id` is derived deterministically from caller, recipient_binding and the
  /// transfer fields, and `atomicity_status` published it unauthenticated. An observer who guesses a
  /// recipient can recompute `recipient_binding` (public and unsalted) and hence the whole
  /// intent_id, turning a status query into a confirm-the-recipient oracle.
  ///
  /// The internal intent_id is NOT changed: it is the ICRC-2 memo that reconciliation matches on
  /// (`transfer.memo != ?pending.intent_id`). Only the PUBLISHED handle is salted, so correlation by
  /// an outside guesser is broken while every internal identity is preserved.
  var intent_publish_salt : Blob = "";

  /// Seeded EXACTLY ONCE from the management canister's randomness, on an update path. Queries
  /// cannot seed it, so a query before the first seeding withholds the handle (publishedIntentId
  /// fails closed) -- which is why callers that create pendings seed it first (see the
  /// shield/unshield entry points).
  ///
  /// "Exactly once" is made true by the RE-TEST AFTER THE AWAIT, not by the guard before it. The
  /// first version tested `size() == 0` and then assigned across an await:
  ///
  ///     if (intent_publish_salt.size() == 0) { intent_publish_salt := await ic.raw_rand() };
  ///
  /// An await yields the message, so two concurrent shield / confidential_transfer calls could BOTH
  /// pass the guard and BOTH assign -- last write wins. No value leaked (every seed is
  /// unpredictable), but a re-seed silently changes EVERY published handle, so a reader who
  /// recorded one could no longer match it. Classic double-checked locking (Schmidt & Harrison,
  /// PLoP 1996), in the form the IC forces: state can change across an await, so post-await state
  /// must be RE-VALIDATED rather than assumed -- the same principle behind `configure`'s await-free state
  /// set and behind the finalize cross-check sitting above its commit boundary.
  ///
  /// NOT A SEEDING FLAG, deliberately. On the IC an await is a COMMIT POINT: state written before
  /// it is committed, and a trap afterwards rolls back only post-await changes. A `seeding := true`
  /// claimed before the await therefore LATCHES if the continuation traps, with no in-canister
  /// reset -- a sibling project carries exactly that bug today, where a configuring flag set before
  /// an await and cleared only in the continuations strands permanently and refuses every later
  /// configure. The double-checked form has no flag, so there is nothing to strand; its only cost
  /// is one discarded raw_rand in a genuine race, which is free.
  ///
  /// STRICTLY NARROWING: the re-test can only PREVENT a write, never cause one, so it introduces no
  /// state the old code could not reach. That is what makes it safe on a money-in path.
  func seedIntentPublishSalt() : async () {
    if (intent_publish_salt.size() == 0) {
      let ic : actor { raw_rand : () -> async Blob } = actor ("aaaaa-aa");
      let seed = await ic.raw_rand();
      // Re-test: first writer wins, a loser discards its seed.
      if (intent_publish_salt.size() == 0) { intent_publish_salt := seed };
    };
  };

  /// The handle as published. Unlinkable to the recipient without the salt.
  func publishedIntentId(id : Blob) : Blob {
    // Fail CLOSED. The first version returned `id` when the salt was empty, which published the raw
    // deterministic handle and left the oracle open — the before/after showed the published bytes
    // byte-identical to the unfixed build. A privacy control must never default to disclosure, so an
    // unseeded salt withholds the handle instead of revealing it.
    if (intent_publish_salt.size() == 0) return "";
    let d = Sha256.Digest(#sha256);
    d.writeBlob("zk-ledger/intent-id-publish/v1");
    d.writeBlob(intent_publish_salt);
    d.writeBlob(id);
    d.sum()
  };

  func unshieldIntentId(caller : Principal, args : TransferArgs, binding : Blob) : Blob {
    let entries = List.empty<(Text, ICRC3.Value)>();
    List.add(entries, ("domain", #Text("zk-ledger/icrc1-unshield/v1")));
    List.add(entries, ("caller", #Blob(Principal.toBlob(caller))));
    List.add(entries, ("anchor", #Blob(args.anchor)));
    List.add(entries, ("nullifier_1", #Blob(args.nullifier_1)));
    List.add(entries, ("nullifier_2", #Blob(args.nullifier_2)));
    List.add(entries, ("output_1", #Blob(args.output_1.commitment)));
    List.add(entries, ("output_2", #Blob(args.output_2.commitment)));
    List.add(entries, ("fee", #Nat(Nat64.toNat(args.fee))));
    List.add(entries, ("public_value", #Nat(Nat64.toNat(args.v_pub_out))));
    List.add(entries, ("recipient_binding", #Blob(binding)));
    switch (args.created_at_time) {
      case (?value) List.add(entries, ("created_at_time", #Nat(Nat64.toNat(value))));
      case null {};
    };
    ICRC3.hashValue(#Map(List.toArray(entries)))
  };

  func decodeBlockAt(index : Nat) : Result<ShieldedNoteBlock> {
    let encoded = switch (StableLog.get(note_log, index)) {
      case (?value) value;
      case null return #err("stable-state:missing-note");
    };
    switch (NoteCodec.decode(encoded)) {
      case (#ok(block)) #ok(block);
      case (#err(message)) #err(message);
    }
  };

  func blockAt(index : Nat) : ShieldedNoteBlock {
    switch (decodeBlockAt(index)) {
      case (#ok(block)) block;
      case (#err(message)) Runtime.trap(message);
    }
  };

  /// XOR-of-sha256 fold for the incremental set digests. Folded ONLY on a first insert
  /// (#ok(true)): addRoot tolerates re-adding an existing root, and an unconditional
  /// fold would XOR the key back OUT while set content is unchanged.
  func xorFold(acc : Blob, key : Blob) : Blob {
    let h = Blob.toArray(Sha256.fromBlob(#sha256, key));
    let a = Blob.toArray(acc);
    Blob.fromArray(Array.tabulate<Nat8>(32, func(i) { a[i] ^ h[i] }))
  };

  func addRoot(root : Blob) {
    switch (StableBlobSet.put(historical_roots, root)) {
      case (#ok(true)) {
        roots_put_counter += 1;
        roots_fold_digest := xorFold(roots_fold_digest, root);
      };
      case (#ok(false)) {};
      case (#err(message)) Runtime.trap(message);
    }
  };

  func addNullifier(nullifier : Blob) {
    switch (StableBlobSet.put(spent_nullifiers, nullifier)) {
      case (#ok(true)) {
        nullifiers_put_counter += 1;
        nullifiers_fold_digest := xorFold(nullifiers_fold_digest, nullifier);
      };
      case (#ok(false)) Runtime.trap("stable-state:duplicate-nullifier-commit");
      case (#err(message)) Runtime.trap(message);
    }
  };

  func archiveManifest() : Blob { ICRC3.hashValue(#Array([])) };

  /// The certified audit leaf: a PURE function of the audit verdict — state tag plus
  /// code/index iff failed. Cursor, epoch, totals, and timestamps are EXCLUDED so the
  /// tuple hashes identically on a never-upgraded instance (#pass at genesis) and after
  /// any green post-upgrade audit — e2e G2/G3/G4 compare those trees byte-for-byte.
  func auditLeafDigest() : Blob {
    let entries = List.empty<(Text, ICRC3.Value)>();
    switch (audit_state) {
      case (#running) List.add(entries, ("state", #Text("running")));
      case (#pass) List.add(entries, ("state", #Text("pass")));
      case (#fail(f)) {
        List.add(entries, ("state", #Text("fail")));
        List.add(entries, ("code", #Text(f.code)));
        List.add(entries, ("index", #Nat(f.index)));
      };
    };
    ICRC3.hashValue(#Map(List.toArray(entries)))
  };

  func certifiedTuple() : CertifiedTuple.Tuple {
    let index : ?Nat = switch (noteCount()) {
      case 0 null;
      case size ?Nat.sub(size, 1);
    };
    {
      last_block_index = index;
      last_block_hash;
      note_count = noteCount();
      note_root;
      encoding_version = ENCODING_VERSION;
      archive_manifest = archiveManifest();
      audit_digest = auditLeafDigest();
      pir2_boundary = pir2BoundaryLeaf();
      detect_stream = if (detect_chain_enabled) ?DetectChain.streamLeaf(detect_chain_state) else null;
      vk_anchor = vkAnchorLeaf();
    }
  };

  /// Certified anchor for the pir2 record stream: digest(32) ‖ covered-count(8B BE), present
  /// only when pir2 is enabled and a DPAGE boundary exists — the flag-off certified tree is
  /// byte-identical to the pre-pir2 one (spec §V2.5).
  /// sha256 over the domain tag and BOTH verifying keys, so a client binding to it cannot be
  /// fooled by swapping one key: the digest covers the pair.
  func vkDigest() : Blob {
    let hash = Sha256.Digest(#sha256);
    hash.writeBlob(Text.encodeUtf8("zk-ledger/vk-anchor/v1"));
    hash.writeBlob(Text.encodeUtf8(transfer_vk_hex));
    hash.writeBlob(Text.encodeUtf8(deposit_vk_hex));
    hash.sum()
  };

  /// Certified verifying-key anchor: digest(32) ‖ vk_epoch(8B BE). Present once the pool holds
  /// verifying keys; absent before that, so the unconfigured certified tree is unchanged.
  func vkAnchorLeaf() : ?Blob {
    if (transfer_vk_hex.size() == 0 or deposit_vk_hex.size() == 0) return null;
    let digest = Blob.toArray(vkDigest());
    let epoch64 = vk_epoch;
    ?Blob.fromArray(Array.tabulate<Nat8>(40, func(i) {
      if (i < 32) digest[i]
      else Nat8.fromNat(Nat64.toNat((epoch64 >> (8 * (7 - Nat64.fromNat(i - 32)))) & 0xff))
    }))
  };

  func pir2BoundaryLeaf() : ?Blob {
    if (not pir2_state.enabled) return null;
    switch (Pir2.latestBoundary(pir2_state)) {
      case (?(digest, covered)) {
        let bytes = List.empty<Nat8>();
        for (byte in digest.values()) List.add(bytes, byte);
        var k : Nat = 8;
        while (k > 0) { k -= 1; List.add(bytes, Nat8.fromNat((covered / (256 ** k)) % 256)) };
        ?Blob.fromArray(List.toArray(bytes))
      };
      case null null;
    }
  };

  func certifiedTree() : CertifiedTuple.HashTree { CertifiedTuple.build(certifiedTuple()) };

  func refreshCertification() {
    CertifiedData.set(CertifiedTuple.digest(certifiedTree()));
  };

  /// The old walk's post-note phases, verbatim (configured/unconfigured branch, pool
  /// subaccount, token admin, pending intents). Shared by the bounded postupgrade
  /// validation AND the audit's final phase — single source of the exact strings.
  func validateTailAndPendings() : Result<()> {
    if (configured()) {
      if (transfer_vk_hex.size() == 0 or deposit_vk_hex.size() == 0) {
        return #err("stable-state:empty-vk");
      };
      if (not fieldSized(note_root) or not StableBlobSet.contains(historical_roots, note_root)) {
        return #err("stable-state:current-root");
      };
      let state = currentTree();
      if (state.filled.size() != 32 or state.next_index != Nat64.fromNat(noteCount())) {
        return #err("stable-state:tree-position");
      };
      switch (hexToBlob(state.root)) {
        case (?root) { if (root != note_root) return #err("stable-state:tree-root") };
        case null return #err("stable-state:tree-root-hex");
      };
    } else {
      if (noteCount() != 0 or rootCount() != 0 or nullifierCount() != 0 or
          last_block_hash != null or pool_value != 0 or epoch != 0) {
        return #err("stable-state:unconfigured-nonempty");
      };
    };
    switch (pool_subaccount) {
      case (?value) { if (value.size() != 32) return #err("stable-state:pool-subaccount") };
      case null {};
    };
    if (tokenConfigured() and administrator == null) return #err("stable-state:token-admin");
    if (pending_shield != null and pending_unshield != null) {
      return #err("stable-state:multiple-pending-token-mutations");
    };
    switch (pending_shield) {
      case (?pending) {
        if (not tokenConfigured()) return #err("stable-state:pending-token-unconfigured");
        if (not fieldSized(pending.intent_id) or
            StableBlobSet.contains(completed_shield_intents, pending.intent_id)) {
          return #err("stable-state:pending-intent");
        };
        switch (validateOutput(pending.output)) {
          case (?_) return #err("stable-state:pending-output");
          case null {};
        };
        if (pending.base_epoch != epoch or pending.anchor_before != note_root) {
          return #err("stable-state:pending-epoch");
        };
        if (pending.next_tree.filled.size() != 32 or
            pending.next_tree.next_index != Nat64.fromNat(noteCount() + 1)) {
          return #err("stable-state:pending-tree-position");
        };
        switch (hexToBlob(pending.next_tree.root)) {
          case (?root) { if (root != pending.root_after) return #err("stable-state:pending-root") };
          case null return #err("stable-state:pending-root-hex");
        };
        let transfer = pending.transfer_args;
        if (not Principal.equal(transfer.from.owner, pending.caller) or
            transfer.spender_subaccount != null) {
          return #err("stable-state:pending-from");
        };
        if (not ICRC2.accountsEqual(transfer.to, poolAccount()) or
            transfer.amount != Nat64.toNat(pending.value) or transfer.fee != ?transparent_ledger_fee or
            transfer.created_at_time == null or transfer.memo != ?pending.intent_id) {
          return #err("stable-state:pending-transfer");
        };
      };
      case null {};
    };
    switch (pending_unshield) {
      case (?pending) {
        if (not tokenConfigured() or transfer_statement_version != 2) {
          return #err("stable-state:pending-unshield-configuration");
        };
        if (not fieldSized(pending.intent_id) or not fieldSized(pending.recipient_binding) or
            StableBlobSet.contains(completed_unshield_intents, pending.intent_id)) {
          return #err("stable-state:pending-unshield-intent");
        };
        switch (validateOutput(pending.output_1)) {
          case (?_) return #err("stable-state:pending-unshield-output-1");
          case null {};
        };
        switch (validateOutput(pending.output_2)) {
          case (?_) return #err("stable-state:pending-unshield-output-2");
          case null {};
        };
        if (pending.base_epoch != epoch or pending.anchor_before != note_root or
            not StableBlobSet.contains(historical_roots, pending.anchor_before)) {
          return #err("stable-state:pending-unshield-epoch");
        };
        if (pending.next_tree.filled.size() != 32 or
            pending.next_tree.next_index != Nat64.fromNat(noteCount() + 2)) {
          return #err("stable-state:pending-unshield-tree-position");
        };
        switch (hexToBlob(pending.next_tree.root)) {
          case (?root) { if (root != pending.root_after) return #err("stable-state:pending-unshield-root") };
          case null return #err("stable-state:pending-unshield-root-hex");
        };
        if (pending.nullifier_1 == pending.nullifier_2 or
            StableBlobSet.contains(spent_nullifiers, pending.nullifier_1) or
            StableBlobSet.contains(spent_nullifiers, pending.nullifier_2)) {
          return #err("stable-state:pending-unshield-nullifier");
        };
        let transfer = pending.transfer_args;
        if (transfer.from_subaccount != pool_subaccount or transfer.amount != Nat64.toNat(pending.public_value) or
            transfer.fee != ?transparent_ledger_fee or transfer.created_at_time == null or
            transfer.memo != ?pending.intent_id or not Principal.equal(transfer.to.owner, pending.caller)) {
          return #err("stable-state:pending-unshield-transfer");
        };
        if (pending.pool_debit != transfer.amount + transparent_ledger_fee or pending.pool_debit > pool_value) {
          return #err("stable-state:pending-unshield-pool-debit");
        };
        switch (recipientBindingValue(transfer.to)) {
          case (#ok(value)) { if (value != pending.recipient_binding) return #err("stable-state:pending-unshield-binding") };
          case (#err(_)) return #err("stable-state:pending-unshield-binding-invalid");
        };
      };
      case null {};
    };
    #ok(())
  };

  /// O(1)/O(k) postupgrade validation: layout version, structure HEADER
  /// checks (the O(n) walks moved into the audit), statement version, a decode of ONLY
  /// the last block (hash == last_block_hash, position == noteCount()-1), the old
  /// walk's configured/unconfigured/pool/pending phases (all O(1)), and finally the
  /// tail-root binding (a NEW check with a NEW code, ordered last so every state an old
  /// check can fault reports the OLD string first).
  func validateStableStateBounded() : Result<()> {
    if (stable_layout_version != STABLE_LAYOUT_VERSION) {
      return #err("stable-state:layout-version");
    };
    switch (StableLog.validateHeader(note_log)) {
      case (#err(message)) return #err(message);
      case (#ok(_)) {};
    };
    switch (StableBlobSet.validateHeader(historical_roots)) {
      case (#err(message)) return #err("roots:" # message);
      case (#ok(_)) {};
    };
    switch (StableBlobSet.validateHeader(spent_nullifiers)) {
      case (#err(message)) return #err("nullifiers:" # message);
      case (#ok(_)) {};
    };
    switch (StableBlobSet.validateHeader(completed_shield_intents)) {
      case (#err(message)) return #err("completed-shields:" # message);
      case (#ok(_)) {};
    };
    switch (StableBlobSet.validateHeader(completed_unshield_intents)) {
      case (#err(message)) return #err("completed-unshields:" # message);
      case (#ok(_)) {};
    };
    if (transfer_statement_version != 1 and transfer_statement_version != 2) {
      return #err("stable-state:transfer-statement-version");
    };
    var tail_block : ?ShieldedNoteBlock = null;
    if (noteCount() == 0) {
      if (last_block_hash != null) return #err("stable-state:last-block-hash");
    } else {
      let encoded = switch (StableLog.get(note_log, noteCount() - 1)) {
        case (?value) value;
        case null return #err("stable-state:missing-note");
      };
      let block = switch (NoteCodec.decode(encoded)) {
        case (#ok(value)) value;
        case (#err(message)) return #err(message);
      };
      if (?ICRC3.hashValue(NoteAudit.blockValue(block)) != last_block_hash) {
        return #err("stable-state:last-block-hash");
      };
      if (block.note_position != noteCount() - 1) return #err("stable-state:note-position");
      tail_block := ?block;
    };
    switch (validateTailAndPendings()) {
      case (#err(message)) return #err(message);
      case (#ok(_)) {};
    };
    switch (tail_block) {
      case (?block) {
        // strictly additional detection: the last appended block's root must BE the
        // current root (true by construction of every append path)
        if (block.note_root_after != note_root) return #err("stable-state:tail-root");
      };
      case null {};
    };
    #ok(())
  };

  // ==== audit state machine ====

  func nowNat64() : Nat64 { Nat64.fromNat(Int.abs(Time.now())) };

  /// The reply must carry WHERE to resume, as a REQUIRED field. A bare Bool says only THAT
  /// there is more to do, so a caller restarts the scan -- reintroducing both the unbounded per-note
  /// cost and the re-walk under a live entry_count. `?Nat64` is forbidden: null would let a caller resume
  /// from nothing and reproduce the defect while appearing repaired.
  type AuditChunkResult = { done : Bool; resume_cursor : Nat };

  func auditFail(code : Text, index : Nat) : AuditChunkResult {
    audit_state := #fail({ code; index });
    if (guard_code == null) {
      guard_code := ?code;
      guard_epoch := audit_epoch;
    };
    audit_last_completed_at := ?nowNat64();
    refreshCertification();
    { done = true; resume_cursor = audit_cursor }
  };

  func auditPass() : AuditChunkResult {
    audit_state := #pass;
    audit_last_completed_at := ?nowNat64();
    refreshCertification();
    { done = true; resume_cursor = audit_cursor }
  };

  /// Restart the audit from phase 0 and arm the tick chain. Called from postupgrade
  /// (every upgrade re-audits the whole state) and from restart_audit.
  func resetAudit<system>() {
    audit_epoch += 1;
    audit_state := #running;
    audit_phase := #log_index;
    audit_cursor := 0;
    audit_expected_parent := null;
    audit_log_expected_offset := StableLog.dataStartOffset();
    audit_log_captured_entries := 0;
    audit_log_captured_offset := 0;
    audit_set_restarts := 0;
    audit_chunk_retries := 0;
    ignore Timer.setTimer<system>(#seconds 0, auditTick);
    refreshCertification();
  };

  type AuditSelf = actor { __audit_chunk : shared () -> async AuditChunkResult };

  /// The tick: ONE awaited self-call per tick (trap isolation — a trap inside the chunk
  /// rolls the chunk back and rejects the call; the catch arm here commits). Nothing
  /// executes before the try (pass-3 A4). A racing upgrade ATTEMPT aborts an in-flight
  /// chunk with a transient reject (TX probe, Phase 2c), so a single failure only
  /// retries; AUDIT_CHUNK_FAILURE_LIMIT consecutive failures fail CLOSED with a code
  /// that distinguishes deterministic traps from exhausted transients.
  func auditTick() : async () {
    if (audit_state != #running) return;
    var done = false;
    try {
      let self : AuditSelf = actor (Principal.toText(selfPrincipal()));
      done := (await self.__audit_chunk()).done;
      audit_chunk_retries := 0;
    } catch (e) {
      audit_chunk_retries += 1;
      if (audit_chunk_retries >= AUDIT_CHUNK_FAILURE_LIMIT) {
        let code = switch (Error.code(e)) {
          case (#canister_error) "stable-state:audit-chunk-trap:" # Error.message(e);
          case (_) "audit:chunk-transient-exhausted:" # Error.message(e);
        };
        done := auditFail(code, audit_cursor).done;
      };
    };
    if (not done) {
      ignore Timer.setTimer<system>(#seconds 0, auditTick);
    };
  };

  func auditSetTarget(phase : AuditPhase) : ?(StableBlobSet.State, Text, Nat) {
    switch (phase) {
      case (#set_roots) ?(historical_roots, "roots:", roots_put_counter);
      case (#set_nullifiers) ?(spent_nullifiers, "nullifiers:", nullifiers_put_counter);
      case (#set_shields) ?(completed_shield_intents, "completed-shields:", shields_put_counter);
      case (#set_unshields) ?(completed_unshield_intents, "completed-unshields:", unshields_put_counter);
      case (_) null;
    }
  };

  func auditAdvancePhase() {
    audit_cursor := 0;
    audit_set_restarts := 0;
    audit_phase := switch (audit_phase) {
      case (#log_index) #set_roots;
      case (#set_roots) #set_nullifiers;
      case (#set_nullifiers) #set_shields;
      case (#set_shields) #set_unshields;
      case (#set_unshields) #notes;
      case (#notes) #tail;
      case (#tail) #tail;
    };
  };

  /// One audit chunk (self-call from auditTick; bounded work per message). Returns true
  /// when the audit reached a terminal state. Phases run in the OLD validateStableState
  /// order — layout+log header+index walk, the four set walks (header + slot count),
  /// statement version, the per-note walk, then the tail phases — producing the OLD
  /// error strings.
  public shared ({ caller }) func __audit_chunk() : async AuditChunkResult {
    if (not Principal.equal(caller, selfPrincipal())) Runtime.trap("audit-chunk:self-only");
    if (audit_state != #running) return { done = true; resume_cursor = audit_cursor };
    let chunk_c0 = Prim.performanceCounter(0);
    audit_last_chunk_at := ?nowNat64();
    switch (audit_phase) {
      case (#log_index) {
        if (audit_cursor == 0) {
          if (stable_layout_version != STABLE_LAYOUT_VERSION) {
            return auditFail("stable-state:layout-version", 0);
          };
          switch (StableLog.validateHeader(note_log)) {
            case (#err(message)) return auditFail(message, 0);
            case (#ok(_)) {};
          };
          audit_log_captured_entries := Nat64.fromNat(StableLog.size(note_log));
          audit_log_captured_offset := note_log.data_offset;
          audit_log_expected_offset := StableLog.dataStartOffset();
        };
        let from = Nat64.fromNat(audit_cursor);
        // The cost predicate is supplied HERE because Main.mo holds the chunk's start counter;
        // StableLog stays free of Prim. See V2-DESIGN.md.
        switch (StableLog.validateIndexRange(note_log, from, AUDIT_INDEX_PER_CHUNK, audit_log_expected_offset, audit_log_captured_entries, func() : Bool { Prim.performanceCounter(0) - chunk_c0 >= AUDIT_INSTRUCTIONS_PER_CHUNK })) {
          case (#err(message)) return auditFail(message, audit_cursor);
          case (#ok(walked)) {
            audit_log_expected_offset := walked.offset;
            // Advance to where the walk ACTUALLY stopped, not to where the clamp says it should
            // have. Under an early cost exit those differ, and recomputing would skip unwalked
            // entries -- silently, and in the direction that loses coverage.
            audit_cursor := Nat64.toNat(walked.stopped_at);
          };
        };
        if (Nat64.fromNat(audit_cursor) >= audit_log_captured_entries) {
          if (audit_log_expected_offset != audit_log_captured_offset) {
            return auditFail("stable-log:tail-offset", audit_cursor);
          };
          auditAdvancePhase();
        };
        { done = false; resume_cursor = audit_cursor }
      };
      case (#set_roots or #set_nullifiers or #set_shields or #set_unshields) {
        let (set, prefix, puts_now) = switch (auditSetTarget(audit_phase)) {
          case (?target) target;
          case null Runtime.trap("audit:phase-target");
        };
        if (audit_cursor == 0) {
          switch (StableBlobSet.validateHeader(set)) {
            case (#err(message)) return auditFail(prefix # message, 0);
            case (#ok(_)) {};
          };
          audit_set_captured_table := set.table_offset;
          // walkWidth, not capacity: during a migration window a set's entries live in BOTH tables,
          // and a walk of the old table alone counts entry_count minus everything carried across so
          // far — which would fail the observed-count check and FAIL-CLOSE THE LEDGER on a perfectly
          // healthy pool. countTagsRange spans both tables over this width.
          audit_set_captured_capacity := StableBlobSet.walkWidth(set);
          audit_set_captured_count := set.entry_count;
          audit_set_captured_puts := puts_now;
          audit_set_captured_cursor := StableBlobSet.migrationCursor(set);
          audit_set_observed := 0;
        };
        // a grow moved the table mid-walk: restart this set's walk (bounded, loud)
        if (set.table_offset != audit_set_captured_table or
            StableBlobSet.walkWidth(set) != audit_set_captured_capacity or
            StableBlobSet.migrationCursor(set) != audit_set_captured_cursor) {
          audit_set_restarts += 1;
          if (audit_set_restarts > AUDIT_SET_RESTART_LIMIT) {
            return auditFail("audit:set-walk-contended", audit_cursor);
          };
          audit_cursor := 0;
          // REG-1. A cost predicate stood here whose two branches returned the SAME value, so it
          // decided nothing while its comment claimed the arm was cost-bounded — a guard that reads
          // as a bound and implements none (CWE-561, dead code). Removed rather than repaired,
          // because there is nothing here for a predicate to bound: this arm restarts the walk and
          // YIELDS UNCONDITIONALLY on the next line. The chunk ends either way. A predicate can only
          // bite where a LOOP would otherwise keep running — the #notes arm's `while`, and the
          // #log_index arm, which threads one into StableLog.validateIndexRange because the loop is
          // in the callee (the caller-supplied-predicate pattern). Neither shape exists here.
          return { done = false; resume_cursor = audit_cursor };
        };
        let from = Nat64.fromNat(audit_cursor);
        switch (StableBlobSet.countTagsRange(set, audit_set_captured_table, audit_set_captured_capacity, from, AUDIT_SLOTS_PER_CHUNK)) {
          case (#err(message)) return auditFail(prefix # message, audit_cursor);
          case (#ok(observed)) {
            audit_set_observed += observed;
            let end = if (from + AUDIT_SLOTS_PER_CHUNK > audit_set_captured_capacity) audit_set_captured_capacity else from + AUDIT_SLOTS_PER_CHUNK;
            audit_cursor := Nat64.toNat(end);
          };
        };
        if (Nat64.fromNat(audit_cursor) >= audit_set_captured_capacity) {
          if (puts_now == audit_set_captured_puts) {
            // quiescent walk: EXACT equality, the old check verbatim
            if (audit_set_observed != audit_set_captured_count) {
              return auditFail(prefix # "stable-set:observed-count", audit_cursor);
            };
            auditAdvancePhase();
          } else {
            // racing inserts landed during a multi-chunk walk: restart, never band-pass
            audit_set_restarts += 1;
            if (audit_set_restarts > AUDIT_SET_RESTART_LIMIT) {
              return auditFail("audit:set-walk-contended", audit_cursor);
            };
            audit_cursor := 0;
          };
        };
        { done = false; resume_cursor = audit_cursor }
      };
      case (#notes) {
        if (audit_cursor == 0) {
          if (transfer_statement_version != 1 and transfer_statement_version != 2) {
            return auditFail("stable-state:transfer-statement-version", 0);
          };
          audit_expected_parent := null;
          audit_detect_chain := Blob.fromArray(Array.repeat<Nat8>(0, 32));
          audit_detect_covered := 0;
          List.clear(audit_detect_frontier.stack);
        };
        var stepped : Nat = 0;
        var steppedBytes : Nat = 0;
        while (stepped < AUDIT_NOTES_PER_CHUNK and audit_cursor < noteCount()) {
          let encoded = switch (StableLog.get(note_log, audit_cursor)) {
            case (?value) value;
            case null return auditFail("stable-state:missing-note", audit_cursor);
          };
          switch (note_checker.checkNote(encoded, audit_cursor, audit_expected_parent, historical_roots, spent_nullifiers)) {
            case (#err(message)) return auditFail(message, audit_cursor);
            case (#ok(hash)) audit_expected_parent := ?hash;
          };
          // detect-chain recompute (flag-gated): fold this note's detection entry; at a
          // DPAGE boundary the recomputed chain must BE the stored boundary leaf (catches
          // boundary-list corruption exactly — the cached root alone would not).
          if (detect_chain_enabled) {
            switch (NoteAudit.ciphertextPrefix(encoded, 40)) {
              case (?ct) {
                audit_detect_chain := DetectChain.fold(audit_detect_chain, DetectChain.entryBytes(audit_cursor, ct));
                if ((audit_cursor + 1) % DetectChain.DPAGE == 0) {
                  switch (List.get(detect_chain_state.boundaries, audit_detect_covered)) {
                    case (?stored) {
                      if (stored != audit_detect_chain) return auditFail("detect-chain:boundary-mismatch", audit_cursor);
                    };
                    case null return auditFail("detect-chain:boundary-count", audit_cursor);
                  };
                  DetectChain.frontierAppend(audit_detect_frontier, audit_detect_covered, audit_detect_chain);
                  audit_detect_covered += 1;
                };
              };
              case null return auditFail("detect-chain:ciphertext-extract", audit_cursor);
            };
          };
          audit_cursor += 1;
          stepped += 1;
          steppedBytes += encoded.size();
          // Checked AFTER at least one note has been processed, so a single note larger than
          // the whole budget still makes progress and the walk can never stall.
          if (steppedBytes >= AUDIT_BYTES_PER_CHUNK) return { done = false; resume_cursor = audit_cursor };
          // Bound COST as well as work. Exits with the cursor, so the next chunk resumes.
          if (Prim.performanceCounter(0) - chunk_c0 >= AUDIT_INSTRUCTIONS_PER_CHUNK) {
            return { done = false; resume_cursor = audit_cursor };
          };
        };
        // the tail comparison must be atomic with walk completion: run it in the SAME
        // message the cursor catches the live noteCount() in
        if (audit_cursor >= noteCount()) {
          if (audit_expected_parent != last_block_hash) {
            return auditFail("stable-state:last-block-hash", audit_cursor);
          };
          switch (detectChainAuditTail()) {
            case (?code) return auditFail(code, audit_cursor);
            case null {};
          };
          switch (validateTailAndPendings()) {
            case (#err(message)) return auditFail(message, audit_cursor);
            case (#ok(_)) {};
          };
          audit_phase := #tail;
          return auditPass();
        };
        { done = false; resume_cursor = audit_cursor }
      };
      case (#tail) {
        // reachable only if a terminal transition was interrupted; re-run the tail
        if (audit_expected_parent != last_block_hash and audit_cursor < noteCount()) {
          audit_phase := #notes;
          // REG-1, same dead-predicate shape as the set arm above and removed for the same reason:
          // this arm hands control back to #notes and yields on the next line, so no predicate can
          // bound anything here. The cost bound for the work this schedules lives where the loop
          // is — inside the #notes `while`.
          return { done = false; resume_cursor = audit_cursor };
        };
        switch (detectChainAuditTail()) {
          case (?code) return auditFail(code, audit_cursor);
          case null {};
        };
        switch (validateTailAndPendings()) {
          case (#err(message)) return auditFail(message, audit_cursor);
          case (#ok(_)) {};
        };
        auditPass()
      };
    }
  };

  /// Terminal detect-chain comparison (flag-gated): the walk-recomputed chain state vs
  /// the live anchor — count, chain tip, boundary count, and Merkle root, plus per-
  /// boundary equality already enforced inside the walk. Called ONLY in a message whose
  /// walk cursor has caught the live noteCount() (atomic-tail discipline).
  func detectChainAuditTail() : ?Text {
    if (not detect_chain_enabled) return null;
    if (audit_detect_chain != detect_chain_state.chain) return ?"detect-chain:tip-mismatch";
    if (audit_cursor != detect_chain_state.count) return ?"detect-chain:count-mismatch";
    if (audit_detect_covered != detect_chain_state.covered) return ?"detect-chain:covered-mismatch";
    if (List.size(detect_chain_state.boundaries) != audit_detect_covered) return ?"detect-chain:boundary-count";
    if (DetectChain.frontierRoot(audit_detect_frontier) != detect_chain_state.root) return ?"detect-chain:root-mismatch";
    null
  };

  func auditStatusValue() : AuditStatus {
    {
      state = audit_state;
      phase = audit_phase;
      cursor = audit_cursor;
      total = noteCount();
      audit_epoch;
      last_completed_at = audit_last_completed_at;
      last_chunk_at = audit_last_chunk_at;
      chunk_retries = audit_chunk_retries;
      guard = guard_code;
      guard_epoch;
    }
  };

  public query func audit_status() : async AuditStatus { auditStatusValue() };

  /// Restart the background audit (admin). Guard-EXEMPT by design: re-running the audit
  /// is the only path to clearing a tripped guard, and it mutates only audit state.
  public shared ({ caller }) func restart_audit() : async Result<AuditStatus> {
    if (not isAdministrator(caller)) return #err("REJECT:not-administrator");
    resetAudit<system>();
    #ok(auditStatusValue())
  };

  // ==== detect-chain rebuild (admin recovery; chunked, trap-isolated) ====
  // The anchor is a pure function of the note log, so recovery from a corrupted anchor is
  // a from-scratch chunked recompute that swaps into the live state ATOMICALLY in the
  // message that catches the live tail (appends landing mid-rebuild are covered: the walk
  // reads them from the log before it completes). Guard-EXEMPT like restart_audit: it is
  // a recovery path and mutates only detect-chain state.

  type RebuildSelf = actor { __detect_rebuild_chunk : shared () -> async Bool };

  func detectRebuildFail(code : Text) : Bool {
    detect_rebuild_error := ?code;
    detect_rebuild_active := false;
    true
  };

  func detectRebuildTick() : async () {
    if (not detect_rebuild_active) return;
    var done = false;
    try {
      let self : RebuildSelf = actor (Principal.toText(selfPrincipal()));
      done := await self.__detect_rebuild_chunk();
      detect_rebuild_retries := 0;
    } catch (e) {
      detect_rebuild_retries += 1;
      if (detect_rebuild_retries >= AUDIT_CHUNK_FAILURE_LIMIT) {
        done := detectRebuildFail("detect-rebuild:chunk-failed:" # Error.message(e));
      };
    };
    if (not done) ignore Timer.setTimer<system>(#seconds 0, detectRebuildTick);
  };

  public shared ({ caller }) func __detect_rebuild_chunk() : async Bool {
    if (not Principal.equal(caller, selfPrincipal())) Runtime.trap("detect-rebuild:self-only");
    if (not detect_rebuild_active) return true;
    // Same three bounds the audit note walk carries, for the same reasons. This path reads the
    // SAME variable-length notes through `StableLog.get`, so a count cap alone bounds how many
    // notes a chunk touches and says nothing about the bytes it moves or the instructions it
    // charges. Exiting early needs no new state: `detect_rebuild_cursor` already persists the
    // position and the driver re-arms on a `false` return, so both exits are resumable by
    // construction rather than by adding a second cursor.
    let chunk_c0 = Prim.performanceCounter(0);
    var steppedBytes : Nat = 0;
    var stepped : Nat = 0;
    while (stepped < AUDIT_NOTES_PER_CHUNK and detect_rebuild_cursor < noteCount()) {
      let encoded = switch (StableLog.get(note_log, detect_rebuild_cursor)) {
        case (?value) value;
        case null return detectRebuildFail("detect-rebuild:missing-note");
      };
      switch (NoteAudit.ciphertextPrefix(encoded, 40)) {
        case (?ct) {
          detect_rebuild_chain := DetectChain.fold(detect_rebuild_chain, DetectChain.entryBytes(detect_rebuild_cursor, ct));
          if ((detect_rebuild_cursor + 1) % DetectChain.DPAGE == 0) {
            List.add(detect_rebuild_boundaries, detect_rebuild_chain);
            DetectChain.frontierAppend(detect_rebuild_frontier, detect_rebuild_covered, detect_rebuild_chain);
            detect_rebuild_covered += 1;
          };
        };
        case null return detectRebuildFail("detect-rebuild:ciphertext-extract");
      };
      detect_rebuild_cursor += 1;
      stepped += 1;
      steppedBytes += encoded.size();
      // Both checked AFTER at least one note has been folded, so a single note larger than the
      // whole budget still makes progress and the walk can never stall. Returning `false` is the
      // existing "not done" reply, so the driver resumes from the cursor rather than restarting.
      if (steppedBytes >= AUDIT_BYTES_PER_CHUNK) return false;
      if (Prim.performanceCounter(0) - chunk_c0 >= AUDIT_INSTRUCTIONS_PER_CHUNK) return false;
    };
    if (detect_rebuild_cursor >= noteCount()) {
      // atomic swap in the SAME message the walk catches the live tail
      detect_chain_state.chain := detect_rebuild_chain;
      detect_chain_state.count := detect_rebuild_cursor;
      detect_chain_state.covered := detect_rebuild_covered;
      List.clear(detect_chain_state.boundaries);
      for (b in List.values(detect_rebuild_boundaries)) List.add(detect_chain_state.boundaries, b);
      List.clear(detect_chain_frontier.stack);
      for (node in List.values(detect_rebuild_frontier.stack)) List.add(detect_chain_frontier.stack, node);
      detect_chain_state.root := DetectChain.frontierRoot(detect_chain_frontier);
      List.clear(detect_rebuild_boundaries);
      List.clear(detect_rebuild_frontier.stack);
      detect_rebuild_active := false;
      refreshCertification();
      return true;
    };
    false
  };

  /// Admin recovery: rebuild the ENTIRE detect-chain anchor from the note log. Run
  /// restart_audit afterwards — a green audit over the rebuilt anchor is the recovery
  /// proof (and the only path to clearing a tripped guard).
  /// A5: resume a rebuild that gave up, WITHOUT discarding what it already did.
  ///
  /// `detectRebuildFail` clears `detect_rebuild_active`, so `detect_chain_rebuild` can already restart —
  /// the stop was never permanent. What it cannot do is continue: it resets `detect_rebuild_cursor`
  /// to 0 and clears the boundary and frontier lists, so every give-up throws away the whole run.
  /// On a large note set a rebuild that keeps meeting transient failures then never finishes,
  /// because each third consecutive failure returns it to the start.
  ///
  /// This is the same entry point minus those four resets: it clears the error and the consecutive
  /// failure count, and re-arms the tick from wherever the cursor stands.
  /// Drive the chunked relocation of the spent-nullifier table. Administrator-only
  /// and never called from a product path — the automatic reclamation in `put` stays bounded to one
  /// message, and this is the operator-driven route for a table too large for that.
  ///
  /// Refused while an audit is running: the audit captures `table_offset` at its start and walks
  /// the set across messages, and its exactness depends on the set being quiescent for the length of
  /// that walk. Moving slots under it would break that, so the guard preserves the invariant rather
  /// than weakening it.
  public shared ({ caller }) func compact_nullifier_set(budget : Nat64) : async Result<Bool> {
    if (not isAdministrator(caller)) return #err("REJECT:not-administrator");
    if (audit_state == #running) return #err("REJECT:audit-running");
    #ok(StableBlobSet.compactStep(spent_nullifiers, budget))
  };

  /// Old tables were retained and nothing pruned, and the chunked reclamation
  /// above reached exactly ONE of the four StableBlobSet instances. Since `312ada4` EVERY `put`
  /// reclaims automatically, for every set size, by draining a bounded `compactStep` slice per call
  /// (`compactIfBounded`, the old inline wholesale reclaim, was REMOVED — see `StableBlobSet.mo`).
  /// So the value path keeps a set's own superseded tables reclaimed on its own; this ADMIN entry
  /// exists to reclaim a set that is NOT being written to (a `historical_roots`,
  /// `completed_shield_intents` or `completed_unshield_intents` that has gone quiet keeps its
  /// superseded tables until something puts to it, and the operator may want them back sooner). Same
  /// admin gate and same audit-running refusal as the nullifier entry point; `compact_nullifier_set`
  /// is left in place.
  public shared ({ caller }) func compact_set(target : CompactTarget, budget : Nat64) : async Result<Bool> {
    if (not isAdministrator(caller)) return #err("REJECT:not-administrator");
    if (audit_state == #running) return #err("REJECT:audit-running");
    let set = switch (target) {
      case (#roots) historical_roots;
      case (#nullifiers) spent_nullifiers;
      case (#shields) completed_shield_intents;
      case (#unshields) completed_unshield_intents;
    };
    let before = Prim.performanceCounter(0);
    let done = StableBlobSet.compactStep(set, budget);
    compact_instructions := Prim.performanceCounter(0) - before;
    #ok(done)
  };

  /// Instructions consumed by the last compact_set call. openWindow drains an entire live
  /// compaction in ONE message, so the headroom between this number and the 40e9 update budget is
  /// what decides whether a growth-triggering put can trap while a compaction is open.
  /// Admin-gated on the same precedent as `is_nullifier_spent`, which traps for anonymous callers.
  /// Added ungated, this telemetry would itself have enumerated unauthenticated public entries --
  /// exactly the class the admin gate exists to police.
  // ADMIN-GATED QUERY — READ THIS BEFORE ADDING A FOURTH ONE.
  //
  // Three queries in this actor gate on isAdministrator: this one, `finalize_divergence` and
  // `pending_intent_detail`. A QUERY IS ANSWERED BY A SINGLE REPLICA WITHOUT CONSENSUS. The caller
  // identity itself is sound -- the ingress message is signed, so `caller` cannot be forged -- but
  // nothing forces a replica to RUN this check. A compromised replica can decline to enforce it and
  // serve the administrator answer to anyone, and no other replica ever sees the request.
  //
  // For `pending_intent_detail` and `finalize_divergence` that specifically restores the
  // note-to-account linkability the salted-handle work closed: those two are the only places the
  // RAW intent handle is reachable.
  //
  // WHY IT IS ACCEPTABLE HERE, and it is only acceptable while this stays written down: these are
  // CONFIDENTIALITY gates, not authorisation on a state change. No money moves through a query, and
  // no query mutates state, so the worst case is disclosure to someone who reached a dishonest
  // replica -- not theft and not corruption. A gate that must resist a malicious replica belongs on
  // an UPDATE call, which goes through consensus, or the answer must be certified.
  //
  // So: if you add a fourth admin-gated query, decide which kind it is. Confidentiality-only can
  // live here. Anything an attacker could act on must not.
  public query ({ caller }) func compact_cost() : async Nat64 {
    if (not isAdministrator(caller)) Runtime.trap("REJECT:not-administrator");
    compact_instructions
  };

  /// Release an unshield intent that can NEVER finalize, writing off its change notes.
  /// The accounting below is checked by `tests/ReleaseSolvencyNegativeControl.mo`, which knocks out
  /// each guard in turn and shows it holds its own invariant and only its own.
  ///
  /// WHY. `repair_tree_state` closes the idle corruption traps but refuses while a pending
  /// exists, and relaxing that would not help: the pending captured `root_after` against the
  /// corrupt tree, so after a repair the finalize cross-check disagrees and it still cannot
  /// settle. The lifecycle model leaves 8 funds-stuck states, all in-flight, and the worst is a
  /// paid intent whose receipt can never be written.
  ///
  /// THE HAZARD THIS AVOIDS. Nullifiers are burned only in `finalizeUnshield`, never at intent
  /// creation. So for a PAID intent the input notes are still spendable and `pool_value` still
  /// claims the money. Simply clearing the pending would be a double-spend AND a solvency break.
  /// The release therefore branches on what actually happened on the token ledger, established by
  /// the same `reconcileUnshieldBlock` the resume path uses — never by a flag and never by the
  /// caller's assertion.
  ///
  /// THIS IS A WRITE-OFF, NOT A RECOVERY. On the paid branch the two change notes are NOT
  /// appended, because the tree is corrupt — that is the premise. Their value is lost. The reply
  /// names it so the administrator calling it cannot mistake this for a repair.
  public shared ({ caller }) func release_unfinalizable_unshield() : async Result<{
    payout_found : Bool;
    nullifiers_burned : Nat;
    pool_debited : Nat;
    change_notes_lost : Nat;
  }> {
    if (not isAdministrator(caller)) return #err("REJECT:not-administrator");
    let pending = switch (pending_unshield) {
      case (?value) value;
      case null return #err("REJECT:no-pending-unshield");
    };

    // PROVE it cannot finalize, rather than trusting that it looks stuck. This is the same
    // rebuild `finalizeUnshield` performs; if it succeeds the intent CAN settle and the normal
    // path must be used instead of destroying value here.
    switch (
      frontierAppend(
        currentTree(),
        [blobToHex(pending.output_1.commitment), blobToHex(pending.output_2.commitment)],
      )
    ) {
      case (#ok(_)) return #err("REJECT:intent-can-finalize");
      case (#err(_)) {};
    };

    let outcome = await reconcileUnshieldBlock(pending);

    // COMMIT-POINT DISCIPLINE, the same the resume path applies: state can change across an
    // await, so the pending is RE-READ and confirmed identical before anything is written. A
    // release applied to an intent that moved underneath us would burn the wrong nullifiers.
    let current = switch (pending_unshield) {
      case (?value) value;
      case null return #err("REJECT:pending-unshield-changed");
    };
    if (current.intent_id != pending.intent_id) return #err("REJECT:pending-unshield-changed");

    switch (outcome) {
      // An inconclusive read must NEVER be treated as absent. That distinction is the difference
      // between a write-off and taking money that was never paid.
      case (#error(message)) return #err("PENDING:unshield-reconcile-scan:" # message);

      // Nothing left the token ledger. Clear the intent and touch nothing else: the input notes
      // stay spendable, which is correct, because no money moved.
      case (#absent) {
        pending_unshield := null;
        pending_unshield_prepared := null;
        if (pending_unshield_prepaid_debit > 0) { pending_unshield_prepaid_debit := 0 };
        refreshCertification();
        #ok({ payout_found = false; nullifiers_burned = 0; pool_debited = 0; change_notes_lost = 0 })
      };

      // The payout landed. From here nothing is fallible and the write is total.
      case (#found(_)) {
        addNullifier(current.nullifier_1);
        addNullifier(current.nullifier_2);
        pool_value -= current.pool_debit;
        if (pending_unshield_prepaid_debit > 0) {
          prepaid_fee_revenue += pending_unshield_prepaid_debit;
          pending_unshield_prepaid_debit := 0;
        };
        epoch += 1;
        switch (StableBlobSet.put(completed_unshield_intents, current.intent_id)) {
          case (#ok(true)) {
            unshields_put_counter += 1;
            unshields_fold_digest := xorFold(unshields_fold_digest, current.intent_id);
          };
          case (#ok(false)) Runtime.trap("stable-state:completed-unshield-duplicate");
          case (#err(message)) Runtime.trap(message);
        };
        pending_unshield := null;
        pending_unshield_prepared := null;
        refreshCertification();
        #ok({
          payout_found = true;
          nullifiers_burned = 2;
          pool_debited = current.pool_debit;
          change_notes_lost = 2;
        })
      };
    }
  };

  /// Repair a tree state that holds a non-canonical value, and clear quarantine as a consequence.
  /// The lane guard and the root derivation are both checked by
  /// `tests/RepairGuardNegativeControl.mo`; the reachability claim below by
  /// `tests/IntentLifecycleModel.mo`.
  ///
  /// WHY THIS EXISTS. The lifecycle model enumerates 30 reachable states and finds 12 from which
  /// settlement is unreachable, every one of them carrying a non-canonical stored value. The
  /// worst is a paid-but-unfinalized intent: the token payout has landed and the intent can never
  /// finalize, because `finalizeUnshield` rebuilds the frontier from `currentTree()` and a bad
  /// lane makes `frontierAppend` return `#err` forever. Adding this one transition takes all 12
  /// to zero.
  ///
  /// WHY IT IS SHAPED THIS WAY. A function that can write `tree_state` can install any root it
  /// likes — which is exactly the defect the intake fix closed. So the administrator does NOT
  /// name a root. They supply LANES; every lane must parse as a canonical field element through
  /// the same check intake uses; and the canister DERIVES the root from them with
  /// `frontierRootOf`, whose agreement with the append walk is pinned by
  /// `tests/FrontierRootProperty.mo`. A caller cannot assert a root into existence here.
  ///
  /// It refuses on a healthy pool, and the refusal is measured against the LIVE state rather than
  /// trusting `state_quarantine` — a flag can be stale, the stored values cannot. It refuses
  /// while any intent is in flight, because moving the anchor under a settlement is its own
  /// defect. Nothing is written on any refusal path: a partial repair is worse than none.
  public shared ({ caller }) func repair_tree_state(lanes : [Text], next_index : Nat64) : async Result<TreeState> {
    if (not isAdministrator(caller)) return #err("REJECT:not-administrator");
    if (not configured()) return #err("REJECT:unconfigured");
    // No repair while a settlement could be relying on the current anchor.
    if (pending_shield != null or pending_unshield != null) return #err("REJECT:pending-in-flight");

    // Refuse on a healthy pool, verified against stored values rather than the flag.
    let live = currentTree();
    var offenders = 0;
    switch (PoseidonTree.parseFieldElement(live.root)) { case (?_) {}; case null offenders += 1 };
    for (lane in live.filled.vals()) {
      switch (PoseidonTree.parseFieldElement(lane)) { case (?_) {}; case null offenders += 1 };
    };
    if (offenders == 0) return #err("REJECT:pool-not-corrupt");

    if (lanes.size() != PoseidonTree.DEPTH) return #err("REJECT:frontier-length");
    if (next_index >= (1 : Nat64) << 32) return #err("REJECT:tree-full");

    // Every supplied lane must be canonical, or nothing happens.
    let parsed = Prim.Array_init<Nat>(PoseidonTree.DEPTH, 0);
    var i = 0;
    for (lane in lanes.vals()) {
      switch (PoseidonTree.hexToNat(lane)) {
        case (?value) { parsed[i] := value };
        case null return #err("REJECT:lane-field");
      };
      i += 1;
    };

    // The root is DERIVED, never supplied.
    let zeros = PoseidonTree.zeroHashes();
    let frontier : PoseidonTree.Frontier = {
      filled = Array.fromVarArray(parsed);
      nextIndex = next_index;
    };
    let derivedRootHex = PoseidonTree.natToHex(PoseidonTree.frontierRootOf(frontier, zeros));
    let rootBlob = switch (hexToBlob(derivedRootHex)) {
      case (?value) value;
      case null return #err("REJECT:root-encode");
    };
    let repaired : TreeState = { filled = lanes; root = derivedRootHex; next_index };

    // Every refusal is above this line. From here the write is total.
    tree_state := ?repaired;
    note_root := rootBlob;
    addRoot(rootBlob);
    state_quarantine := false;
    state_quarantine_values := [];
    refreshCertification();
    #ok(repaired)
  };

  /// Slots inspected by one `canonicality_scan` call. A key read is 32 bytes against the 1 byte
  /// the audit's tag walk reads, so this window is deliberately far smaller than
  /// `AUDIT_SLOTS_PER_CHUNK`: at that width a census would read ~134 MB per call.
  let CANONICALITY_SLOTS_PER_CALL : Nat64 = 65_536;

  /// Canonicality census over one window of a set.
  ///
  /// The postupgrade scan covers `tree_state` and the pendings, and it is bounded deliberately.
  /// It cannot cover `historical_roots` or the nullifier set, because those are unbounded and an
  /// unbounded postupgrade is the defect class this ledger has already closed once. So the census
  /// lives here instead: bounded per call, resumable through a cursor the CALLER carries, and
  /// therefore adding no stable state and no cost to any existing path.
  ///
  /// REPORTS ONLY, and that is a deliberate choice rather than an omission. Finding a
  /// non-canonical key does NOT raise quarantine, because quarantine currently has no exit --
  /// nothing in the canister can clear the flag or repair the value. Wiring a new way INTO a
  /// state with no way out would convert a reporting gap into a freezing hazard, which is
  /// strictly worse than the gap. When a repair path exists, this is where it would be armed.
  ///
  /// Counts only: the reply carries totals, never key bytes, so it discloses nothing a membership
  /// query would not. Admin-gated on the `compact_cost` precedent above; it is a
  /// confidentiality-only gate on a single-replica answer, and nothing an attacker could act on.
  public query ({ caller }) func canonicality_scan(
    target : CompactTarget,
    from : Nat64,
    count : Nat64,
  ) : async Result<{ scanned : Nat; offenders : Nat; next : Nat64; done : Bool }> {
    if (not isAdministrator(caller)) return #err("REJECT:not-administrator");
    let set = switch (target) {
      case (#roots) historical_roots;
      case (#nullifiers) spent_nullifiers;
      case (#shields) completed_shield_intents;
      case (#unshields) completed_unshield_intents;
    };
    let capacity = StableBlobSet.activeCapacity(set);
    let window = if (count == 0 or count > CANONICALITY_SLOTS_PER_CALL) CANONICALITY_SLOTS_PER_CALL else count;
    switch (StableBlobSet.keysRange(set, set.table_offset, capacity, from, window)) {
      case (#err(message)) #err(message);
      case (#ok(keys)) {
        var offenders = 0;
        for (k in keys.vals()) {
          // `blobToNat` returns null at or above the field modulus, so it IS the canonicality
          // predicate. `natToHex` would TRAP on exactly the keys this census exists to find.
          switch (PoseidonTree.blobToNat(k)) { case (?_) {}; case null offenders += 1 };
        };
        let next = if (from + window > capacity) capacity else from + window;
        #ok({ scanned = keys.size(); offenders; next; done = next >= capacity })
      };
    }
  };

  public shared ({ caller }) func detect_chain_rebuild_resume() : async Result<()> {
    // NOT guardRejection()-gated, and its sibling `detect_chain_rebuild` is not either. A give-up
    // is frequently CAUSED by state the audit guard objects to, so guarding the resume made it
    // unreachable in precisely the situation it exists for: the operator was left with only the
    // entry point that discards progress. Measured — after a give-up at cursor 8000 the resume
    // returned `GUARDED:stable-state-audit-failed:note-codec:magic` while the restart ran.
    if (not isAdministrator(caller)) return #err("REJECT:not-administrator");
    if (not detect_chain_enabled) return #err("REJECT:detect-chain-not-enabled");
    // Two stalls, one entry point. (a) the retry limit gave up: active is false, error is set.
    // (b) an upgrade landed mid-rebuild: Motoko timers do not survive an upgrade, so the tick chain
    // is gone while `detect_rebuild_active` is still true and the cursor is frozen — nothing will
    // ever re-arm it. Gating on "must have failed" would leave (b) stuck forever, which is the
    // worse of the two because it presents as still running.
    if (detect_rebuild_cursor == 0 and detect_rebuild_error == null) {
      return #err("REJECT:detect-rebuild-nothing-to-resume");
    };
    detect_rebuild_active := true;
    detect_rebuild_error := null;
    detect_rebuild_retries := 0;
    ignore Timer.setTimer<system>(#seconds 0, detectRebuildTick);
    #ok(())
  };

  public shared ({ caller }) func detect_chain_rebuild() : async Result<()> {
    if (not isAdministrator(caller)) return #err("REJECT:not-administrator");
    if (not detect_chain_enabled) return #err("REJECT:detect-chain-not-enabled");
    if (detect_rebuild_active) return #err("REJECT:detect-rebuild-running");
    detect_rebuild_active := true;
    detect_rebuild_error := null;
    detect_rebuild_cursor := 0;
    detect_rebuild_chain := Blob.fromArray(Array.repeat<Nat8>(0, 32));
    detect_rebuild_covered := 0;
    List.clear(detect_rebuild_boundaries);
    List.clear(detect_rebuild_frontier.stack);
    detect_rebuild_retries := 0;
    ignore Timer.setTimer<system>(#seconds 0, detectRebuildTick);
    #ok(())
  };

  public query func detect_rebuild_status() : async { active : Bool; cursor : Nat; error : ?Text } {
    { active = detect_rebuild_active; cursor = detect_rebuild_cursor; error = detect_rebuild_error }
  };

  /// Clear the fail-closed guard (admin), permitted ONLY after a NEWER audit epoch has
  /// re-run green (#pass with audit_epoch > guard_epoch).
  public shared ({ caller }) func clear_audit_guard() : async Result<AuditStatus> {
    if (not isAdministrator(caller)) return #err("REJECT:not-administrator");
    switch (guard_code) {
      case null return #err("REJECT:guard-not-set");
      case (?_) {};
    };
    if (audit_state != #pass or audit_epoch <= guard_epoch) {
      return #err("REJECT:guard-requires-green-reaudit");
    };
    guard_code := null;
    #ok(auditStatusValue())
  };

  // ==== PIR v2 admin + backfill + query surface (all additive) ====

  public type Pir2IndexStatus = { #ok; #catching_up; #degraded; #repairing };
  public type Pir2RepairPhase = {
    #chain_replay : { next : Nat; upto : Nat };
    #zeroing : { shard : Nat; offset : Nat64 };
  };
  public type Pir2Repair = {
    from_shard : Nat;
    last_shard : Nat;
    phase : Pir2RepairPhase;
  };
  public type Pir2RepairStatus = { from_shard : Nat; phase : Text };
  public type Pir2Status = {
    enabled : Bool;
    backfilling : Bool;
    backfill_cursor : Nat;
    shard_size : Nat;
    record_count : Nat;
    note_count : Nat;
    // derived-index surface (all additive): the freshness watermark and the health of the
    // background fold driver — the ops dashboard for the derived-index containment story
    indexed_upto : Nat;
    lag : Nat;
    index_status : Pir2IndexStatus;
    last_fold_error : ?Text;
    fold_retries : Nat;
    fold_inflight : Bool;
    fold_trap_armed : Nat;
    last_chunk_instructions : Nat64;
    repair : ?Pir2RepairStatus;
  };
  public type Pir2Params = {
    /// Renamed from `lwe_dimension`: this field carries `Pir2.LWE_N`, the HINT
    /// dimension, not `LWE_DIMENSION`. The old name invited sizing a buffer from the wrong
    /// constant. The check stays: sizing from the other constant must STILL trap.
    hint_lwe_n : Nat;
    record_bytes : Nat;
    shard_size : Nat;
    records_per_column : Nat;
    m_rows : Nat;
    m_cols : Nat;
    a_domain : Blob;
  };

  func pir2StatusValue() : Pir2Status {
    let notes = noteCount();
    let indexed = pir2_state.record_count;
    let lag = if (notes > indexed) notes - indexed else 0;
    {
      enabled = pir2_state.enabled;
      backfilling = pir2_backfilling;
      backfill_cursor = pir2_backfill_cursor;
      shard_size = pir2_state.shard_size;
      record_count = indexed;
      note_count = notes;
      indexed_upto = indexed;
      lag;
      index_status = if (pir2_repair != null) #repairing
        else if (pir2_fold_retries >= PIR2_FOLD_FAILURE_LIMIT) #degraded
        else if (lag > 0) #catching_up
        else #ok;
      last_fold_error = pir2_last_fold_error;
      fold_retries = pir2_fold_retries;
      fold_inflight = pir2_fold_inflight;
      fold_trap_armed = test_pir2_fold_trap_remaining;
      last_chunk_instructions = pir2_last_chunk_instructions;
      repair = switch (pir2_repair) {
        case (?r) ?{
          from_shard = r.from_shard;
          phase = switch (r.phase) {
            case (#chain_replay(_)) "chain_replay";
            case (#zeroing(_)) "zeroing";
          };
        };
        case null null;
      };
    }
  };

  /// One-shot arm of the PIR v2 layer (admin). Sets the shard size (immutable thereafter),
  /// initializes the v2 regions, and arms the background fold driver — on a non-empty log
  /// the driver's catch-up IS the backfill (cursor 0 → tail). Queries serve any pin at or
  /// below the watermark from the first folded record on.
  public shared ({ caller }) func pir2_enable(shardSize : Nat) : async Result<Pir2Status> {
    if (not isAdministrator(caller)) return #err("REJECT:not-administrator");
    switch (guardRejection()) { case (?message) return #err(message); case null {} };
    if (pir2_state.enabled) return #err("REJECT:pir2-already-enabled");
    if (shardSize == 0) return #err("REJECT:pir2-shard-size-zero");
    Pir2.enable(pir2_state, shardSize);
    if (noteCount() > 0) {
      pir2_backfilling := true;
      pir2_backfill_cursor := 0;
    };
    pir2ArmDriver<system>();
    ignore Timer.setTimer<system>(#seconds 0, pir2DriverTick);
    #ok(pir2StatusValue())
  };

  func pir2Behind() : Bool {
    pir2_repair != null or pir2_state.record_count < noteCount()
  };

  /// Arm the recurring fold watchdog (idempotent per process lifetime; transient flag —
  /// postupgrade re-arms). ONLY armed when pir2 is enabled: a flag-off deployment runs no
  /// timers and is message-for-message identical to the pre-v2 ledger.
  func pir2ArmDriver<system>() {
    if (pir2_driver_armed) return;
    pir2_driver_armed := true;
    ignore Timer.recurringTimer<system>(#seconds 2, pir2DriverTick);
  };

  type Pir2FoldSelf = actor { __pir2_fold_chunk : shared (Bool) -> async Bool };

  /// The fold driver tick (audit-tick pattern): one awaited self-call per
  /// tick so a trapping chunk rolls back ONLY the chunk — the catch arm here always commits
  /// the failure record and the backoff. The idle path is O(1) and self-call-free. While the
  /// sticky audit guard is set the driver pauses: fail-closed extends to derived state (D17).
  func pir2DriverTick() : async () {
    // A deterministic trap will recur, so stop re-arming instead of burning a chunk every 64s
    // forever. pir2_reindex clears this, which is the operator's way back.
    if (pir2_fold_terminal) return;
    if (not pir2_state.enabled) return;
    if (pir2_fold_inflight) return;
    if (guard_code != null) return;
    if (not pir2Behind()) return;
    if (nowNat64() < pir2_fold_backoff_until) return;
    pir2_fold_inflight := true;
    var progressed = false;
    // Test-fault consumption commits at the await below, so an armed burst is finite even
    // though each faulted chunk itself rolls back (AC-D1 injection semantics).
    let trapNow = test_pir2_fold_trap_remaining > 0;
    if (trapNow) test_pir2_fold_trap_remaining -= 1;
    try {
      let self : Pir2FoldSelf = actor (Principal.toText(selfPrincipal()));
      progressed := await self.__pir2_fold_chunk(trapNow);
      pir2_fold_retries := 0;
      pir2_fold_trap_streak := 0;
      pir2_last_fold_error := null;
      pir2_fold_backoff_until := 0;
    } catch (e) {
      pir2_fold_retries += 1;
      let isTrap = switch (Error.code(e)) { case (#canister_error) true; case (_) false };
      if (isTrap) {
        pir2_fold_trap_streak += 1;
        if (pir2_fold_trap_streak >= PIR2_FOLD_FAILURE_LIMIT) pir2_fold_terminal := true;
      } else { pir2_fold_trap_streak := 0 };
      let prefix = if (isTrap) "pir2-fold-trap:" else "pir2-fold-transient:";
      pir2_last_fold_error := ?(prefix # Error.message(e));
      // exponential backoff, capped at 64s; the recurring watchdog retries after it expires
      let shift = Nat.min(pir2_fold_retries, 6);
      pir2_fold_backoff_until := nowNat64() + Nat64.fromNat(2 ** shift) *% 1_000_000_000;
    };
    pir2_fold_inflight := false;
    if (progressed and pir2Behind()) {
      ignore Timer.setTimer<system>(#seconds 0, pir2DriverTick);
    };
  };

  /// One fold chunk, message-atomic, self-only: services the repair machine if one is
  /// active, else folds up to PIR2_BACKFILL_PER_TICK records from the stable cursor
  /// (`pir2_state.record_count` — THE watermark) toward the log tail, using the exact live
  /// fold, so the derived index is bit-identical to a synchronously-built one. Returns
  /// whether progress was made.
  public shared ({ caller }) func __pir2_fold_chunk(trapNow : Bool) : async Bool {
    if (not Principal.equal(caller, selfPrincipal())) Runtime.trap("pir2-fold-chunk:self-only");
    if (trapNow) Runtime.trap("pir2-fold:test-trap");
    let c0 = Prim.performanceCounter(0);
    if (not pir2_state.enabled) return false;
    if (guard_code != null) return false;
    switch (pir2_repair) {
      case (?repair) {
        pir2RepairStep(repair);
        pir2_last_chunk_instructions := Prim.performanceCounter(0) - c0;
        return true;
      };
      case null {};
    };
    var processed = 0;
    let boundaryBefore = pir2_state.boundary_count;
    while (processed < PIR2_BACKFILL_PER_TICK and pir2_state.record_count < noteCount()) {
      let block = blockAt(pir2_state.record_count);
      Pir2.append(pir2_state, block.commitment, block.note_ciphertext);
      pir2_backfill_cursor := pir2_state.record_count;
      processed += 1;
    };
    if (pir2_backfilling and pir2_state.record_count >= noteCount()) {
      pir2_backfilling := false;
    };
    // certified stream anchor follows the fold (never the money path): republish when a
    // DPAGE boundary landed in this chunk
    if (pir2_state.boundary_count != boundaryBefore) refreshCertification();
    pir2_last_chunk_instructions := Prim.performanceCounter(0) - c0;
    processed > 0
  };

  /// One bounded repair step. Order is the whole design: the cursor was
  /// already rewound (atomically, in pir2_reindex) so nothing serves the affected shards;
  /// chain replay re-derives the digest from AUTHORITATIVE log records; zeroing clears every
  /// affected hint span (the fold is +=); then the normal catch-up refolds.
  func pir2RepairStep(repair : Pir2Repair) {
    switch (repair.phase) {
      case (#chain_replay({ next; upto })) {
        var i = next;
        let stop = Nat.min(i + PIR2_CHAIN_REPLAY_PER_CHUNK, upto);
        while (i < stop) {
          let block = blockAt(i);
          Pir2.chainAbsorb(pir2_state, Pir2.packRecord(block.commitment, block.note_ciphertext));
          i += 1;
        };
        pir2_repair := ?(
          if (i >= upto) { { repair with phase = #zeroing({ shard = repair.from_shard; offset = 0 : Nat64 }) } }
          else { { repair with phase = #chain_replay({ next = i; upto }) } }
        );
      };
      case (#zeroing({ shard; offset })) {
        let g = Pir2.geometry(pir2_state.shard_size);
        let total = Pir2.hintBytesPerShard(g);
        let take = Nat64.min(PIR2_ZERO_BYTES_PER_CHUNK, total - offset);
        Pir2.zeroHintSpan(pir2_state, shard, offset, take);
        let nextOffset = offset + take;
        pir2_repair := if (nextOffset >= total) {
          if (shard >= repair.last_shard) null
          else ?{ repair with phase = #zeroing({ shard = shard + 1; offset = 0 : Nat64 }) };
        } else {
          ?{ repair with phase = #zeroing({ shard; offset = nextOffset }) };
        };
      };
    };
  };

  /// Admin repair: rebuild the derived index for every shard >= `fromShard` from the
  /// authoritative note log (AC-D4). Rewinds the watermark FIRST (message-atomically —
  /// affected shards stop serving on every surface), restores the stream chain from the
  /// nearest DPAGE checkpoint, then hands the chunked replay/zero/refold to the fold driver.
  /// Transfers are unaffected throughout by construction.
  public shared ({ caller }) func pir2_reindex(fromShard : Nat) : async Result<Pir2Status> {
    pir2_fold_terminal := false;
    pir2_fold_trap_streak := 0;
    if (not isAdministrator(caller)) return #err("REJECT:not-administrator");
    switch (guardRejection()) { case (?message) return #err(message); case null {} };
    if (not pir2_state.enabled) return #err("REJECT:pir2-not-enabled");
    if (pir2_repair != null) return #err("REJECT:pir2-repair-in-progress");
    let currentShards = Pir2.shardCount(pir2_state);
    if (fromShard >= currentShards and currentShards > 0) return #err("REJECT:pir2-shard-beyond-fill");
    if (currentShards == 0) return #err("REJECT:pir2-nothing-indexed");
    let lastShard = currentShards - 1;
    let replayFrom = Pir2.repairRewind(pir2_state, fromShard);
    pir2_backfill_cursor := pir2_state.record_count;
    pir2_repair := ?{
      from_shard = fromShard;
      last_shard = lastShard;
      phase = #chain_replay({ next = replayFrom; upto = pir2_state.record_count });
    };
    // the certified anchor follows the rewound boundary state immediately
    refreshCertification();
    ignore Timer.setTimer<system>(#seconds 0, pir2DriverTick);
    #ok(pir2StatusValue())
  };

  public query func pir2_status() : async Pir2Status { pir2StatusValue() };

  public query func pir2_params() : async Result<Pir2Params> {
    if (not pir2_state.enabled) return #err("REJECT:pir2-not-enabled");
    let g = Pir2.geometry(pir2_state.shard_size);
    #ok({
      hint_lwe_n = Pir2.LWE_N;
      record_bytes = Pir2.RECORD_BYTES;
      shard_size = pir2_state.shard_size;
      records_per_column = g.records_per_column;
      m_rows = g.m_rows;
      m_cols = g.m_cols;
      a_domain = Pir2.A_DOMAIN;
    })
  };

  /// One stripe of the matvec. Serves any pin at or below the freshness watermark
  /// (`indexed_upto` == the module cursor); deeper pins trap in the module's bound check,
  /// so no query can ever decode against a partially-folded column segment.
  public query func pir2_query(shard : Nat, fill : Nat, stripe : Nat, kCols : Nat, qu : Blob)
    : async Result<(Blob, Pir2.StripeTrace)> {
    if (not pir2_state.enabled) return #err("REJECT:pir2-not-enabled");
    #ok(Pir2.answerStripe(pir2_state, shard, fill, stripe, kCols, qu))
  };

  /// Densely packed record stream (position 8B BE ‖ 288 cells per record) for tail-hint
  /// self-computation; capped at MAX_BLOCKS_PER_CALL records per call.
  public query func pir2_record_stream(start : Nat, count : Nat) : async Result<Blob> {
    if (not pir2_state.enabled) return #err("REJECT:pir2-not-enabled");
    #ok(Pir2.recordStream(pir2_state, start, Nat.min(count, MAX_BLOCKS_PER_CALL)))
  };

  /// Hint bytes for a FROZEN shard (traps for the mutable tail — clients self-compute it).
  public query func pir2_hint_chunk(shard : Nat, offset : Nat, len : Nat) : async Result<Blob> {
    if (not pir2_state.enabled) return #err("REJECT:pir2-not-enabled");
    #ok(Pir2.hintChunk(pir2_state, shard, offset, len))
  };

  /// Latest certified record-stream boundary digest (anchor for a streaming client's chain).
  public query func pir2_stream_boundary() : async Result<{ digest : Blob; covered : Nat }> {
    if (not pir2_state.enabled) return #err("REJECT:pir2-not-enabled");
    switch (Pir2.latestBoundary(pir2_state)) {
      case (?(digest, covered)) #ok({ digest; covered });
      case null #err("REJECT:pir2-no-boundary");
    }
  };

  /// Fail-closed rejection for every state-mutating endpoint while the guard is set.
  /// Audit failures keep their exact legacy string; a tree-frontier/oracle mismatch
  /// (set only while the frontier flag is ON) carries its own prefix.
  func guardRejection() : ?Text {
    switch (guard_code) {
      case (?code) {
        if (Text.startsWith(code, #text "tree-frontier-mismatch")) return ?("GUARDED:" # code);
        ?("GUARDED:stable-state-audit-failed:" # code)
      };
      case null null;
    }
  };

  /// Flip the sticky fail-closed guard on an in-canister/oracle tree disagreement —
  /// same mechanism, epoch bookkeeping, and clear path (`clear_audit_guard` after a
  /// newer green audit) as an audit FAIL.
  func flipFrontierGuard(detail : Text) {
    if (guard_code == null) {
      guard_code := ?("tree-frontier-mismatch:" # detail);
      guard_epoch := audit_epoch;
    };
  };

  system func postupgrade() {
    // Re-assert on every upgrade — a constant can change between builds.
    assertAuditProgressConstants();
    // Seed the publish salt on every upgrade. Seeding only inside shield/confidential_transfer
    // left it empty whenever neither had been accepted, so a pending could be published before any
    // salt existed. Same #seconds 0 timer pattern the audit driver uses.
    ignore Timer.setTimer<system>(#seconds 0, seedIntentPublishSalt);
    let heap_before = Prim.rts_heap_size();
    configuring := false;
    // Cleared HERE for the same reason `configuring` is, and the reason is the IC's await
    // semantics rather than tidiness: an await is a COMMIT POINT. `configure_token_ledger` sets
    // `token_configuring := true` and then awaits the token ledger's `icrc1_fee`/`icrc1_decimals`;
    // that `true` is committed at the await, while every line that clears it lives in a
    // CONTINUATION. An upgrade landing mid-await discards the continuation, so without this line
    // the flag survives as `true` with nothing left to clear it, and the in-progress guard refuses
    // EVERY later configuration permanently -- an unrecoverable pool, fixable only by shipping new
    // code. postupgrade is the only place guaranteed to run after the continuation is lost, which
    // is what makes it the correct home rather than a timeout or a lease.
    //
    // Clearing is safe because there is nothing to resume: an interrupted token configuration wrote
    // no state (the writes all sit after the awaits), so the next attempt starts from the same
    // place the interrupted one did. That is the difference from `detect_rebuild_active`, which is
    // deliberately NOT cleared below but RE-DRIVEN, because its work IS resumable.
    token_configuring := false;
    // Bounded scan: the live tree_state root + its 32 lanes, plus each pending's
    // commitments — ~33 values plus O(pendings), NOT a walk of the note set.
    let offenders = List.empty<Text>();
    switch (tree_state) {
      case (?state) {
        switch (PoseidonTree.parseFieldElement(state.root)) {
          case (?_) {}; case null List.add(offenders, "root:" # state.root);
        };
        for (lane in state.filled.vals()) {
          switch (PoseidonTree.parseFieldElement(lane)) {
            case (?_) {}; case null List.add(offenders, "lane:" # lane);
          };
        };
      };
      case null {};
    };
    switch (pending_shield) {
      case (?p) {
        switch (PoseidonTree.parseFieldElement(blobToHex(p.output.commitment))) {
          case (?_) {}; case null List.add(offenders, "shield-commitment:" # blobToHex(p.output.commitment));
        };
      };
      case null {};
    };
    switch (pending_unshield) {
      case (?p) {
        for (o in [p.output_1, p.output_2].vals()) {
          switch (PoseidonTree.parseFieldElement(blobToHex(o.commitment))) {
            case (?_) {}; case null List.add(offenders, "unshield-commitment:" # blobToHex(o.commitment));
          };
        };
      };
      case null {};
    };
    state_quarantine_values := List.toArray(offenders);
    state_quarantine := state_quarantine_values.size() > 0;
    switch (validateStableStateBounded()) {
      case (#ok(_)) {};
      case (#err(message)) Runtime.trap("postupgrade:" # message);
    };
    if (not Pir2.headersValid(pir2_state)) Runtime.trap("postupgrade:pir2-headers");
    // The fold driver is transient: re-arm whenever pir2 is enabled. Catch-up and repair
    // both resume from their STABLE cursors (mid-flight state cannot be lost).
    if (pir2_state.enabled) {
      pir2ArmDriver<system>();
      ignore Timer.setTimer<system>(#seconds 0, pir2DriverTick);
    };
    // re-arm an in-flight detect-chain rebuild (progress is stable; the timer is not)
    if (detect_rebuild_active) ignore Timer.setTimer<system>(#seconds 0, detectRebuildTick);
    refreshCertification();
    resetAudit<system>();
    postupgrade_heap_before := heap_before;
    postupgrade_heap_after := Prim.rts_heap_size();
    postupgrade_instructions := Prim.performanceCounter(0);
  };

  /// Postupgrade cost telemetry (T1 asserts ~flat vs note count).
  public query func postupgrade_stats() : async { instructions : Nat64; heap_before : Nat; heap_after : Nat } {
    { instructions = postupgrade_instructions; heap_before = postupgrade_heap_before; heap_after = postupgrade_heap_after }
  };

  func configured() : Bool {
    // with the in-canister frontier enabled the ledger no longer needs an oracle to
    // compute transitions; flag OFF keeps the legacy requirement byte-identically.
    verifier_id != null and tree_state != null and
    (tree_oracle_id != null or tree_frontier_enabled)
  };

  func mutation(outcome : Text, verifierOutcome : Text) : MutationResult {
    {
      outcome;
      verifier_outcome = verifierOutcome;
      note_root;
      note_count = noteCount();
      nullifier_count = nullifierCount();
      pool_value;
      epoch;
      instructions = Prim.performanceCounter(0);
    }
  };

  func fieldSized(value : Blob) : Bool { value.size() == 32 };

  func nibbleText(n : Nat) : Text {
    switch (n) {
      case 0 "0"; case 1 "1"; case 2 "2"; case 3 "3";
      case 4 "4"; case 5 "5"; case 6 "6"; case 7 "7";
      case 8 "8"; case 9 "9"; case 10 "a"; case 11 "b";
      case 12 "c"; case 13 "d"; case 14 "e"; case _ "f";
    }
  };

  func blobToHex(value : Blob) : Text {
    var result = "";
    for (byte in value.vals()) {
      let n = Nat8.toNat(byte);
      result #= nibbleText(n / 16) # nibbleText(n % 16);
    };
    result
  };

  func hexNibble(c : Char) : ?Nat8 {
    let n = Nat32.toNat(Char.toNat32(c));
    if (n >= 48 and n <= 57) return ?Nat8.fromNat(n - 48);
    if (n >= 97 and n <= 102) return ?Nat8.fromNat(n - 87);
    if (n >= 65 and n <= 70) return ?Nat8.fromNat(n - 55);
    null
  };

  func hexToBlob(value : Text) : ?Blob {
    // Bound the decode IN THE LOOP. Every caller decodes a tree ROOT — a 32-byte field
    // element = 64 hex chars — and rejects any non-32-byte result (`root.size() != 32`), so an
    // over-long input was already refused; this only stops the unbounded work/allocation the loop
    // did on a misbehaving-oracle string. Bailing at the 65th char via the LAZY char iterator is
    // O(1) (a `value.size() > 64` pre-check would instead be O(len) — `Text.size` walks the rope).
    let output = List.empty<Nat8>();
    var high : ?Nat8 = null;
    var seen : Nat = 0;
    for (c in value.chars()) {
      seen += 1;
      if (seen > 64) return null;
      let nibble = switch (hexNibble(c)) { case (?n) n; case null return null };
      switch (high) {
        case null { high := ?nibble };
        case (?h) {
          List.add(output, Nat8.fromNat(Nat8.toNat(h) * 16 + Nat8.toNat(nibble)));
          high := null;
        };
      };
    };
    if (high != null) return null;
    ?Blob.fromArray(List.toArray(output))
  };

  func nat64Field(valueInput : Nat64) : Blob {
    let output = Prim.Array_init<Nat8>(32, 0);
    var value = valueInput;
    var i : Nat = 0;
    while (i < 8) {
      output[i] := Nat8.fromNat(Nat64.toNat(value % 256));
      value /= 256;
      i += 1;
    };
    Blob.fromArray(Array.fromVarArray(output))
  };

  // ark-serialize Vec<Fr>: u64 little-endian length, then 32-byte compressed Fr values.
  func serializePublicInputs(fields : [Blob]) : ?Text {
    for (field in fields.vals()) { if (not fieldSized(field)) return null };
    let bytes = Prim.Array_init<Nat8>(8 + 32 * fields.size(), 0);
    var length = Nat64.fromNat(fields.size());
    var i : Nat = 0;
    while (i < 8) {
      bytes[i] := Nat8.fromNat(Nat64.toNat(length % 256));
      length /= 256;
      i += 1;
    };
    var offset : Nat = 8;
    for (field in fields.vals()) {
      for (byte in field.vals()) {
        bytes[offset] := byte;
        offset += 1;
      };
    };
    ?blobToHex(Blob.fromArray(Array.fromVarArray(bytes)))
  };

  func parseTransition(result : TreeTransition) : Result<TreeState> {
    switch (result.error) { case (?message) return #err(message); case null {} };
    switch (result.state) {
      case (?state) {
        if (state.filled.size() != 32) return #err("REJECT:tree-frontier-length");
        switch (hexToBlob(state.root)) {
          case (?root) { if (root.size() != 32) return #err("REJECT:tree-root-length") };
          case null return #err("REJECT:tree-root-hex");
        };
        // INTAKE now admits exactly what the read path admits. Both the root and ALL
        // THIRTY-TWO lanes go through the one smart constructor; the lanes were previously
        // COUNT-CHECKED ONLY, so a stored TreeState could carry 32 well-formed but non-canonical
        // lanes that `frontierAppend` would later refuse at `REJECT:frontier-field` — stranding the
        // intent after the money moved. A root-only remedy relocates the strand to that exit.
        // REJECTED, NOT REDUCED: reduction mod Fr.P gives one value two encodings, and roots are
        // compared AS HEX TEXT here, so a reduced value would no longer equal the text it came from.
        switch (PoseidonTree.parseFieldElement(state.root)) {
          case (?_) {};
          case null return #err("REJECT:tree-root-noncanonical");
        };
        for (lane in state.filled.vals()) {
          switch (PoseidonTree.parseFieldElement(lane)) {
            case (?_) {};
            case null return #err("REJECT:tree-lane-noncanonical");
          };
        };
        #ok(state)
      };
      case null #err("REJECT:tree-oracle-empty-response");
    }
  };

  func currentTree() : TreeState {
    switch (tree_state) { case (?state) state; case null Runtime.trap("unconfigured") }
  };

  func frontierZeros() : [Nat] {
    switch (zero_hashes_cache) {
      case (?zeros) zeros;
      case null {
        let zeros = PoseidonTree.zeroHashes();
        zero_hashes_cache := ?zeros;
        zeros
      };
    }
  };

  /// The tree oracle's `append` computed in-canister: parse the wire frontier, run the
  /// incremental-tree walk (`PoseidonTree.append`, arkworks-gated), emit the successor
  /// state. Validation order and error strings mirror `tree_oracle/src/lib.rs` exactly
  /// (frontier-length / leaf-count / tree-full / frontier-field / root-field /
  /// leaf-field) so a cross-checked oracle can never disagree on the rejection surface.
  func frontierAppend(state : TreeState, leaves : [Text]) : Result<TreeState> {
    if (state.filled.size() != PoseidonTree.DEPTH) return #err("REJECT:frontier-length");
    if (leaves.size() == 0 or leaves.size() > 2) return #err("REJECT:leaf-count");
    if (state.next_index > ((1 : Nat64) << 32) -% Nat64.fromNat(leaves.size())) {
      return #err("REJECT:tree-full");
    };
    let filled = Prim.Array_init<Nat>(PoseidonTree.DEPTH, 0);
    var level : Nat = 0;
    while (level < PoseidonTree.DEPTH) {
      switch (PoseidonTree.hexToNat(state.filled[level])) {
        case (?value) filled[level] := value;
        case null return #err("REJECT:frontier-field");
      };
      level += 1;
    };
    if (PoseidonTree.hexToNat(state.root) == null) return #err("REJECT:root-field");
    let parsedLeaves = Prim.Array_init<Nat>(leaves.size(), 0);
    var i : Nat = 0;
    while (i < leaves.size()) {
      switch (PoseidonTree.hexToNat(leaves[i])) {
        case (?value) parsedLeaves[i] := value;
        case null return #err("REJECT:leaf-field");
      };
      i += 1;
    };
    let zeros = frontierZeros();
    var frontier : PoseidonTree.Frontier = {
      filled = Array.fromVarArray(filled);
      nextIndex = state.next_index;
    };
    var root : Nat = 0;
    i := 0;
    while (i < leaves.size()) {
      let (next, newRoot) = PoseidonTree.append(frontier, zeros, parsedLeaves[i]);
      frontier := next;
      root := newRoot;
      i += 1;
    };
    #ok({
      filled = Array.map<Nat, Text>(frontier.filled, PoseidonTree.natToHex);
      root = PoseidonTree.natToHex(root);
      next_index = frontier.nextIndex;
    })
  };

  /// With the frontier flag ON, compute the in-canister transition BEFORE any await
  /// (atomic against the pre-verdict state); returns null with the flag OFF.
  func frontierLocalNext(state : TreeState, leaves : [Text]) : Result<?TreeState> {
    if (not tree_frontier_enabled) return #ok(null);
    switch (frontierAppend(state, leaves)) {
      case (#ok(next)) #ok(?next);
      case (#err(message)) #err(message);
    }
  };

  func frontierMismatchDetail(local : TreeState, oracle : TreeState) : ?Text {
    if (local.root != oracle.root) return ?("root:" # local.root # ":" # oracle.root);
    if (local.next_index != oracle.next_index) return ?"next-index";
    if (not Array.equal<Text>(local.filled, oracle.filled, Text.equal)) return ?"frontier-lanes";
    null
  };

  /// Cross-check the oracle's transition against the in-canister one (flag ON with an
  /// oracle attached). ANY disagreement flips the sticky fail-closed guard and rejects:
  /// the in-canister computation is authoritative, so no oracle-injected root can reach
  /// `historical_roots`. Returns the rejection message, or null when consistent.
  func frontierCrossCheck(localNext : ?TreeState, oracleNext : TreeState, site : Text) : ?Text {
    switch (localNext) {
      case null null;
      case (?local) {
        switch (frontierMismatchDetail(local, oracleNext)) {
          case null null;
          case (?detail) {
            flipFrontierGuard(site # ":" # detail);
            switch (guardRejection()) {
              case (?message) ?message;
              case null ?"GUARDED:tree-frontier-mismatch";
            }
          };
        }
      };
    }
  };

  // The verify boundary, in-process. Same verdict strings the Rust verifier canister returned
  // (ACCEPT / REJECT:hex / REJECT:proof-deserialize / REJECT:inputs-deserialize /
  // REJECT:pairing-check), so every downstream consumer and test is unchanged.
  func depositFlatVk(vk : Groth16Multi.PreparedVk) : Groth16Multi.FlatVk {
    switch (deposit_vk_flat) {
      case (?value) value;
      case null {
        let value = Groth16Multi.prepareFlatVk(vk);
        deposit_vk_flat := ?value;
        value
      };
    }
  };
  func transferFlatVk(vk : Groth16Multi.PreparedVk) : Groth16Multi.FlatVk {
    switch (transfer_vk_flat) {
      case (?value) value;
      case null {
        let value = Groth16Multi.prepareFlatVk(vk);
        transfer_vk_flat := ?value;
        value
      };
    }
  };
  func verifyShieldProof(proofHex : Text, inputsHex : Text) : Text {
    switch (deposit_vk_prepared) {
      case (?vk) Groth16Wire.verifyPreparedCached(vk, depositFlatVk(vk), proofHex, inputsHex);
      case null "REJECT:unconfigured";
    }
  };
  func verifyTransferProof(proofHex : Text, inputsHex : Text) : Text {
    switch (transfer_vk_prepared) {
      case (?vk) Groth16Wire.verifyPreparedCached(vk, transferFlatVk(vk), proofHex, inputsHex);
      case null "REJECT:unconfigured";
    }
  };

  func treeActor() : TreeOracle {
    switch (tree_oracle_id) {
      case (?id) actor (Principal.toText(id));
      case null Runtime.trap("unconfigured tree oracle");
    }
  };

  /// The block a note append WOULD write, as a pure function of its arguments and the tail it is
  /// given. Split out of appendBlock so a PREPARE phase can build and encode a block BEFORE any
  /// money moves, leaving the commit with nothing to do but write bytes it already holds.
  ///
  /// `position` and `phash` are parameters rather than reads of `noteCount()` and `last_block_hash`
  /// because PREPARE has to build two blocks at once: the second one's phash is the hash of the
  /// first, so neither can be derived from live state at the time the second is built.
  func buildNoteBlock(
    output : OutputRecord,
    nullifiers : [Blob],
    anchor : Blob,
    rootAfter : Blob,
    origin : NoteOrigin,
    position : Nat,
    phash : ?Blob,
  ) : ShieldedNoteBlock {
    {
      btype = "zknote1";
      phash;
      encoding_version = ENCODING_VERSION;
      note_position = position;
      commitment = output.commitment;
      ephemeral_key = output.ephemeral_key;
      note_ciphertext = output.note_ciphertext;
      nullifiers;
      anchor_before = anchor;
      note_root_after = rootAfter;
      timestamp = Nat64.fromNat(Int.abs(Time.now()));
      origin;
    }
  };

  func appendBlock(
    output : OutputRecord,
    nullifiers : [Blob],
    anchor : Blob,
    rootAfter : Blob,
    origin : NoteOrigin,
  ) {
    let position = noteCount();
    let block = buildNoteBlock(output, nullifiers, anchor, rootAfter, origin, position, last_block_hash);
    let encoded = switch (NoteCodec.encode(block)) {
      case (#ok(value)) value;
      case (#err(message)) Runtime.trap(message);
    };
    commitNoteBytes(encoded, position, ICRC3.hashValue(NoteAudit.blockValue(block)), output.note_ciphertext);
  };

  /// Write bytes that are already in hand. Everything fallible about a note append has happened
  /// before this is called — the encoding, and the region headroom that makes StableLog.append
  /// unable to reach its `out of stable memory` trap.
  ///
  /// The one remaining unbounded operation is DetectChain.append, which every DPAGE-th note pushes
  /// onto a doubling heap List and recomputes a Merkle root. It cannot be hoisted and it cannot be
  /// pre-reserved, so the totality of this function is CONDITIONAL on
  /// detect_chain_enabled being false, which is its default. That condition is asserted where
  /// totality is measured rather than assumed here.
  func commitNoteBytes(encoded : Blob, position : Nat, blockHash : Blob, ciphertext : Blob) {
    switch (StableLog.append(note_log, encoded)) {
      case (#ok(index)) { if (index != position) Runtime.trap("stable-state:note-position") };
      case (#err(message)) Runtime.trap(message);
    };
    // incremental change-detection digest: sha256 chain over the appended encodings
    let chain = Sha256.Digest(#sha256);
    chain.writeBlob(note_log_chain_digest);
    chain.writeBlob(encoded);
    note_log_chain_digest := chain.sum();
    // certified detection-stream anchor: fold this note's 48-B detection entry
    // (pos BE8 ‖ note_ciphertext[0..40]); a DPAGE boundary + Merkle root update happen inside.
    if (detect_chain_enabled) DetectChain.append(detect_chain_state, detect_chain_frontier, position, Blob.toArray(ciphertext));
    last_block_hash := ?blockHash;
    // NO PIR code here — the append is authoritative and complete without the derived
    // index; the background fold driver trails it (derived-index decoupling).
    // A PIR fault can degrade queries, never this message.
  };

  func validateOutput(output : OutputRecord) : ?Text {
    if (not fieldSized(output.commitment)) return ?"REJECT:commitment-length";
    if (output.ephemeral_key.size() == 0) return ?"REJECT:ephemeral-key-empty";
    if (output.note_ciphertext.size() == 0) return ?"REJECT:ciphertext-empty";
    null
  };

  public shared ({ caller }) func configure(
    verifierId : Principal,
    treeOracleId : Principal,
    transferVkHex : Text,
    depositVkHex : Text,
  ) : async Result<LedgerStatus> {
    switch (guardRejection()) { case (?message) return #err(message); case null {} };
    // This operation CREATES the administrator role — it ends with
    // `administrator := ?caller` — and it used to check nothing, so the first principal to call it
    // on a freshly installed canister owned the pool: the proving system, the root source, the
    // frontier gate, the guard-clearing path, and the unredacted in-flight intents. Every consumer
    // of the role was gated with isAdministrator; the operation that mints it was not.
    //
    // A controller is the only principal the platform already knows is entitled to this canister —
    // it installed the wasm — so that is the binding, and it cannot be raced because the controller
    // set is platform state rather than ledger state.
    if (not Principal.isController(caller)) return #err("REJECT:not-controller");
    if (configured() or configuring) return #err("REJECT:already-configured");
    if (transferVkHex.size() == 0 or depositVkHex.size() == 0) return #err("REJECT:empty-vk");
    // Pre-flight refusal. Estimate each preparation's cost from the vk length BEFORE running it,
    // and refuse the whole call if either would exceed the message ceiling — while NOTHING has been
    // touched (`configuring` is still false, no field assigned), so a refusal here leaves a pool a
    // caller can immediately retry with smaller keys. This is checked for BOTH keys together even
    // though the fix split their preparations across the await: each still runs in-process in its own
    // message, so each must be admissible on its own, and reporting the failure up front beats
    // discovering it 8-12e9 instructions into the transfer key with the deposit key still ahead.
    if (estimatedVkPrepareInstructions(transferVkHex) > VK_PREPARE_INSTR_CEILING or
        estimatedVkPrepareInstructions(depositVkHex) > VK_PREPARE_INSTR_CEILING) {
      return #err("REJECT:vk-prepare-budget");
    };
    // Parse + validate + prepare both verifying keys NOW (in-process, no await, no state
    // change on failure): every vk point is subgroup-checked and the three fixed G2 pairs are
    // precomputed once, so no per-proof message ever re-validates the vk.
    let transferPrepared = switch (Groth16Wire.parseAndPrepareVk(transferVkHex)) {
      case (?vk) vk;
      case null return #err("REJECT:vk-deserialize:transfer");
    };
    configure_prepare_instructions := Prim.performanceCounter(0);
    configuring := true;
    let oracle : TreeOracle = actor (Principal.toText(treeOracleId));
    let response = try { await oracle.empty() } catch (error) {
      configuring := false;
      return #err("REJECT:tree-oracle-call:" # Error.message(error));
    };
    let initial = switch (parseTransition(response)) {
      case (#ok(state)) state;
      case (#err(message)) { configuring := false; return #err(message) };
    };
    // The DEPOSIT vk is prepared here, after the await, not alongside the transfer vk above.
    // Preparing both before the await put 20,428,523,632 instructions — 51.1% of the 40e9 budget —
    // into ONE message, superlinear in vk size, so a pool with modestly larger keys could not be
    // configured at all. An await starts a fresh message with a fresh budget, so splitting the two
    // preparations across it roughly halves the peak without changing what is prepared or when it
    // becomes visible: both land in the same commit below, and a failure here still clears
    // `configuring` and leaves no partial state, exactly as the pre-await parse did.
    let depositPrepared = switch (Groth16Wire.parseAndPrepareVk(depositVkHex)) {
      case (?vk) vk;
      case null { configuring := false; return #err("REJECT:vk-deserialize:deposit") };
    };
    if (configured()) { configuring := false; return #err("REJECT:configuration-race") };
    verifier_id := ?verifierId;
    tree_oracle_id := ?treeOracleId;
    transfer_vk_hex := transferVkHex;
    deposit_vk_hex := depositVkHex;
    vk_epoch += 1;
    transfer_vk_prepared := ?transferPrepared;
    deposit_vk_prepared := ?depositPrepared;
    transfer_vk_flat := ?Groth16Multi.prepareFlatVk(transferPrepared);
    deposit_vk_flat := ?Groth16Multi.prepareFlatVk(depositPrepared);
    transfer_statement_version := 2;
    tree_state := ?initial;
    note_root := switch (hexToBlob(initial.root)) { case (?root) root; case null Runtime.trap("validated root") };
    addRoot(note_root);
    administrator := ?caller;
    refreshCertification();
    configuring := false;
    #ok(statusValue())
  };

  /// Upgrade an existing pool from the v1 transfer statement to recipient-bound v2 without
  /// replacing any note, nullifier, tree, token, or pool-balance state.
  public shared ({ caller }) func rotate_verifying_keys_v2(
    expectedOldTransferVkHex : Text,
    expectedOldDepositVkHex : Text,
    newTransferVkHex : Text,
    newDepositVkHex : Text,
  ) : async Result<LedgerStatus> {
    switch (guardRejection()) { case (?message) return #err(message); case null {} };
    if (not isAdministrator(caller)) return #err("REJECT:not-administrator");
    if (not configured()) return #err("REJECT:unconfigured");
    if (pending_shield != null or pending_unshield != null) return #err("REJECT:pending-token-mutation");
    if (transfer_vk_hex != expectedOldTransferVkHex) return #err("REJECT:transfer-vk-precondition");
    if (deposit_vk_hex != expectedOldDepositVkHex) return #err("REJECT:deposit-vk-precondition");
    if (newTransferVkHex.size() == 0 or newDepositVkHex.size() == 0) return #err("REJECT:empty-vk");
    let transferPrepared = switch (Groth16Wire.parseAndPrepareVk(newTransferVkHex)) {
      case (?value) value;
      case null return #err("REJECT:vk-deserialize:transfer");
    };
    let depositPrepared = switch (Groth16Wire.parseAndPrepareVk(newDepositVkHex)) {
      case (?value) value;
      case null return #err("REJECT:vk-deserialize:deposit");
    };
    transfer_vk_hex := newTransferVkHex;
    deposit_vk_hex := newDepositVkHex;
    vk_epoch += 1;
    transfer_vk_prepared := ?transferPrepared;
    deposit_vk_prepared := ?depositPrepared;
    transfer_vk_flat := ?Groth16Multi.prepareFlatVk(transferPrepared);
    deposit_vk_flat := ?Groth16Multi.prepareFlatVk(depositPrepared);
    transfer_statement_version := 2;
    #ok(statusValue())
  };

  /// THE single switch for the in-canister Poseidon frontier. Admin-gated,
  /// all-or-nothing, default OFF (= byte-identical legacy: oracle root trusted).
  /// Enabling validates that the live wire frontier parses canonically (every filled
  /// lane + root < r) and pre-warms the zero-hash cache so no user pays the one-time
  /// init. Disabling requires an attached oracle (otherwise the ledger would have no
  /// transition source at all).
  public shared ({ caller }) func set_tree_frontier(enabled : Bool) : async Result<LedgerStatus> {
    switch (guardRejection()) { case (?message) return #err(message); case null {} };
    if (not isAdministrator(caller)) return #err("REJECT:not-administrator");
    if (not configured()) return #err("REJECT:unconfigured");
    // The pending check guards the DISABLE direction ONLY. It used to sit here,
    // above the branch, freezing the flag in BOTH directions while an intent was in flight —
    // which made recovery by a single admin call impossible and turned the finalize refusal into a PERMANENT
    // funds-availability deadlock: money already moved, intent unable to finalize, flag unable
    // to be enabled to let it finalize, and no release path applicable because the transfer landed.
    //
    // ENABLING while pending is safe because it can only ADD a check. It cannot invalidate a
    // captured `root_after` — the pending already carries that value, and the finalize cross-check
    // merely recomputes locally and compares. Disagreement is exactly the detection this exists
    // for; agreement finalizes as before. DISABLING while pending is the genuinely unsafe
    // direction — that is what strands a settled intent — and it stays blocked.
    if (enabled) {
      let state = currentTree();
      if (state.filled.size() != PoseidonTree.DEPTH) return #err("REJECT:frontier-length");
      for (lane in state.filled.vals()) {
        if (PoseidonTree.hexToNat(lane) == null) return #err("REJECT:frontier-field");
      };
      if (PoseidonTree.hexToNat(state.root) == null) return #err("REJECT:root-field");
      ignore frontierZeros();
    } else {
      if (pending_shield != null or pending_unshield != null) {
        return #err("REJECT:pending-token-mutation");
      };
      if (tree_oracle_id == null) return #err("REJECT:no-tree-oracle");
    };
    tree_frontier_enabled := enabled;
    #ok(statusValue())
  };

  /// Attach or detach the tree oracle (admin). Detaching is permitted ONLY while the
  /// in-canister frontier is enabled — with the oracle detached the ledger computes
  /// every transition alone and the oracle is fully out of the root-trust base.
  public shared ({ caller }) func set_tree_oracle(oracle : ?Principal) : async Result<LedgerStatus> {
    switch (guardRejection()) { case (?message) return #err(message); case null {} };
    if (not isAdministrator(caller)) return #err("REJECT:not-administrator");
    if (not configured()) return #err("REJECT:unconfigured");
    if (pending_shield != null or pending_unshield != null) {
      return #err("REJECT:pending-token-mutation");
    };
    switch (oracle) {
      case null { if (not tree_frontier_enabled) return #err("REJECT:frontier-disabled") };
      case (?_) {};
    };
    tree_oracle_id := oracle;
    #ok(statusValue())
  };

  /// Telemetry: instructions used by `configure` before its first await.
  public query func configure_cost() : async Nat64 { configure_prepare_instructions };

  public query func tree_frontier_status() : async { enabled : Bool; tree_oracle : ?Principal } {
    { enabled = tree_frontier_enabled; tree_oracle = tree_oracle_id }
  };

  public shared ({ caller }) func configure_token_ledger(
    tokenLedgerId : Principal,
    historyAdapterId : Principal,
    poolSubaccount : ?Blob,
  ) : async Result<AtomicityStatus> {
    switch (guardRejection()) { case (?message) return #err(message); case null {} };
    if (not isAdministrator(caller)) return #err("REJECT:not-administrator");
    if (token_configuring) return #err("REJECT:token-configuration-in-progress");
    if (tokenConfigured()) return #err("REJECT:token-already-configured");
    if (noteCount() != 0 or pool_value != 0 or pending_shield != null or pending_unshield != null) {
      return #err("REJECT:token-configuration-after-state");
    };
    switch (poolSubaccount) {
      case (?value) { if (value.size() != 32) return #err("REJECT:pool-subaccount-length") };
      case null {};
    };
    token_configuring := true;
    let ledger : TransferLedger = actor (Principal.toText(tokenLedgerId));
    let metadata = try {
      let fee = await ledger.icrc1_fee();
      let decimals = await ledger.icrc1_decimals();
      (fee, decimals)
    } catch (error) {
      token_configuring := false;
      return #err("REJECT:token-metadata:" # Error.message(error));
    };
    if (metadata.1 != 8) {
      token_configuring := false;
      return #err("REJECT:token-decimals:" # Nat8.toText(metadata.1));
    };
    if (tokenConfigured() or noteCount() != 0 or pool_value != 0 or pending_shield != null or pending_unshield != null) {
      token_configuring := false;
      return #err("REJECT:token-configuration-race");
    };
    token_ledger_id := ?tokenLedgerId;
    history_adapter_id := ?historyAdapterId;
    transparent_ledger_fee := metadata.0;
    transparent_ledger_decimals := metadata.1;
    pool_subaccount := poolSubaccount;
    token_configuring := false;
    #ok(atomicityStatusValue())
  };

  func statusValue() : LedgerStatus {
    {
      configured = configured();
      administrator;
      note_root;
      note_count = noteCount();
      log_length = noteCount();
      nullifier_count = nullifierCount();
      historical_root_count = rootCount();
      pool_value;
      epoch;
      tree_state;
      transfer_statement_version;
    }
  };

  public query func status() : async LedgerStatus { statusValue() };

  /// Names the values that put this pool in quarantine, so the operator can see
  /// WHAT is wrong rather than only THAT something is. Empty when the pool is clean.
  public query func quarantine_status() : async (Bool, [Text]) {
    (state_quarantine, state_quarantine_values)
  };

  public query func recipient_binding(recipient : ICRC2.Account) : async Result<Blob> {
    recipientBindingValue(recipient)
  };

  // Digest fields are the incrementally-maintained CHANGE-DETECTION digests (folded at
  // append/first-insert) — the old one-shot region walks were O(n) with per-entry heap
  // allocation inside a single query message. Values differ from the old scheme
  // by construction; every consumer compares them across time, never against
  // recomputation. On a state migrated from a pre-fix wasm they cover post-migration
  // mutations only.
  func storageStatusValue() : StorageStatus {
    {
      layout_version = stable_layout_version;
      note_entries = noteCount();
      note_bytes = StableLog.dataSize(note_log);
      note_log_region_bytes = (StableLog.regionBytes(note_log)).0;
      note_digest = note_log_chain_digest;
      root_entries = rootCount();
      root_capacity = Nat64.toNat(historical_roots.capacity);
      root_region_bytes = StableBlobSet.bytesAllocated(historical_roots);
      root_digest = roots_fold_digest;
      nullifier_entries = nullifierCount();
      nullifier_capacity = Nat64.toNat(spent_nullifiers.capacity);
      nullifier_region_bytes = StableBlobSet.bytesAllocated(spent_nullifiers);
      nullifier_digest = nullifiers_fold_digest;
      completed_shield_entries = completedShieldCount();
      completed_shield_capacity = Nat64.toNat(completed_shield_intents.capacity);
      completed_shield_region_bytes = StableBlobSet.bytesAllocated(completed_shield_intents);
      completed_shield_digest = shields_fold_digest;
      completed_unshield_entries = completedUnshieldCount();
      completed_unshield_capacity = Nat64.toNat(completed_unshield_intents.capacity);
      completed_unshield_region_bytes = StableBlobSet.bytesAllocated(completed_unshield_intents);
      completed_unshield_digest = unshields_fold_digest;
    }
  };

  func redactPendingShield(pending : ?PendingShield) : ?AtomicityPending {
    switch (pending) {
      case null null;
      case (?p) ?{
        intent_id = publishedIntentId(p.intent_id);
        base_epoch = p.base_epoch;
        attempts = p.attempts;
        verifier_outcome = p.verifier_outcome;
        ledger_tip_before = p.ledger_tip_before;
      };
    }
  };

  func redactPendingUnshield(pending : ?PendingUnshield) : ?AtomicityPending {
    switch (pending) {
      case null null;
      case (?p) ?{
        intent_id = publishedIntentId(p.intent_id);
        base_epoch = p.base_epoch;
        attempts = p.attempts;
        verifier_outcome = p.verifier_outcome;
        ledger_tip_before = p.ledger_tip_before;
      };
    }
  };

  func atomicityStatusValue() : AtomicityStatus {
    {
      token_configured = tokenConfigured();
      token_ledger = token_ledger_id;
      history_adapter = history_adapter_id;
      transparent_ledger_fee;
      transparent_ledger_decimals;
      pool_account = poolAccount();
      pending = redactPendingShield(pending_shield);
      pending_unshield = redactPendingUnshield(pending_unshield);
      completed_intents = completedShieldCount();
      completed_intent_digest = shields_fold_digest;
      completed_unshield_intents = completedUnshieldCount();
      completed_unshield_intent_digest = unshields_fold_digest;
      test_fault_armed = test_fail_after_token_once;
    }
  };

  public query func atomicity_status() : async AtomicityStatus { atomicityStatusValue() };

  // The finalize-frontier divergence observable. Corruption-only and non-blocking (it never
  // trips the sticky guard, so the resume still converges the money). It lets the operator watch
  // `count` for a finalize-time frontier/oracle divergence that leaves an intent pending.
  //
  // `last_intent` USED TO BE THE RAW `intentId` assigned at the two finalize mismatch sites, on an
  // unauthenticated query — the same handle `redactPendingShield`/`redactPendingUnshield` salt
  // before publishing, so this method re-opened by the back door the linkability those two sites
  // close. The remedy is BOTH available controls, not a choice between them, because they fail
  // independently:
  //
  //   * SALTED for everyone else, via the same `publishedIntentId` the other two publish sites use.
  //     One handle derivation for every published exposure means a reader correlating this method
  //     with `atomicity_status()` still sees the SAME handle for the SAME intent — the observable
  //     stays useful — while nobody outside learns the raw one. `publishedIntentId` fails CLOSED on
  //     an unseeded salt (returns ""), and a query cannot seed it, so the withheld case is the
  //     empty handle and never the raw bytes.
  //   * ADMINISTRATOR sees the raw handle, matching `pending_intent_detail` directly below: the
  //     unredacted record is an administrator affordance, not a public one.
  //
  // `count` stays open to every caller deliberately. It is an aggregate with no note-to-account
  // linkage, and it exists so the operator — not only the administrator — can watch it; gating the
  // count would defeat the observable to buy no privacy. This is the RFC 6973 §6.1 data-minimisation
  // reading: publish the aggregate, withhold the identifier. Defence in depth over a single control
  // is Saltzer & Schroeder's fail-safe defaults + least privilege (Proc. IEEE 63(9), 1975).
  //
  // NON-BLOCKING PRESERVED STRUCTURALLY: a `query` mutates nothing, so this cannot reach
  // `flipFrontierGuard` (:2050) and cannot affect the resume. No state, no guard, no money.
  // Single-replica answer, no consensus: see the note on `compact_cost`. This is the second of the
  // two sites where the RAW handle is reachable, so the administrator branch below is only as
  // strong as the replica answering it. Confidentiality only; no state changes here.
  public query ({ caller }) func finalize_divergence() : async { count : Nat; last_intent : ?Blob } {
    let handle = switch (finalize_frontier_mismatch_last) {
      case null null;
      case (?id) { if (isAdministrator(caller)) ?id else ?publishedIntentId(id) };
    };
    { count = finalize_frontier_mismatch_count; last_intent = handle }
  };

  /// The unredacted in-flight intents, for the administrator only. Same record shapes the
  /// public status used to carry, so an operational consumer moves by changing the call target
  /// and nothing else. Caller-bound deliberately: these records link a shielded note to a
  /// transparent account, which is exactly what the pool must not publish.
  public query ({ caller }) func pending_intent_detail() : async Result<{
    shield : ?PendingShield;
    unshield : ?PendingUnshield;
  }> {
    // Single-replica answer, no consensus: see the note on `compact_cost` above. This is one of
    // the two sites where the RAW intent handle is reachable, so a replica that declines to
    // enforce this gate restores exactly the linkability the salted handle closed. Acceptable
    // because it is confidentiality only -- no state changes and no money moves through a query.
    if (not isAdministrator(caller)) return #err("REJECT:not-administrator");
    #ok({ shield = pending_shield; unshield = pending_unshield })
  };

  public query func storage_status() : async StorageStatus { storageStatusValue() };

  /// Runtime-system memory counters, for soak/ops telemetry. `memory_size` is the wasm
  /// memory high-water mark (EOP memory grows and never shrinks); `heap_size` is the live
  /// heap after the last GC increment. Diverging curves = allocation churn, not retention.
  public query func rts_status() : async RtsStatus {
    {
      memory_size = Prim.rts_memory_size();
      heap_size = Prim.rts_heap_size();
      total_allocation = Prim.rts_total_allocation();
      reclaimed = Prim.rts_reclaimed();
      max_live_size = Prim.rts_max_live_size();
    }
  };

  /// Bounded stable-state validation: the O(1)/O(k) postupgrade checks, NOT the
  /// full walk (which OOM'd at 51k notes). Returns #ok while the background audit is
  /// still #running — poll audit_status for the full-walk verdict; deep external
  /// verification pages through validate_stable_state_range.
  public query func validate_stable_state() : async Result<StorageStatus> {
    switch (validateStableStateBounded()) {
      case (#ok(_)) #ok(storageStatusValue());
      case (#err(message)) #err(message);
    }
  };

  /// Paged deep verification: run EXACTLY the old per-note checks over notes
  /// [from, from+count) (count capped), threading the parent hash between pages. Pass
  /// expected_parent = null for from == 0; feed each page's returned hash into the
  /// next. When the page reaches the log tip, the tip hash is compared to
  /// last_block_hash exactly like the old walk.
  public query func validate_stable_state_range(from : Nat, count : Nat, expected_parent : ?Blob) : async Result<?Blob> {
    let capped = Nat.min(count, 512);
    if (from > noteCount()) return #err("stable-state:range-out-of-bounds");
    if (from == 0 and expected_parent != null) return #err("stable-state:range-parent");
    var parent = expected_parent;
    var index = from;
    let end = Nat.min(from + capped, noteCount());
    while (index < end) {
      let encoded = switch (StableLog.get(note_log, index)) {
        case (?value) value;
        case null return #err("stable-state:missing-note");
      };
      switch (NoteAudit.referenceCheck(encoded, index, parent, historical_roots, spent_nullifiers)) {
        case (#err(message)) return #err(message);
        case (#ok(hash)) parent := ?hash;
      };
      index += 1;
    };
    if (index >= noteCount() and parent != last_block_hash) {
      return #err("stable-state:last-block-hash");
    };
    #ok(parent)
  };

  public query func certified_snapshot() : async CertifiedSnapshot {
    let tuple = certifiedTuple();
    let tree = CertifiedTuple.build(tuple);
    {
      last_block_index = tuple.last_block_index;
      last_block_hash = tuple.last_block_hash;
      note_root;
      note_count = noteCount();
      encoding_version = ENCODING_VERSION;
      archive_manifest = tuple.archive_manifest;
      certificate = CertifiedData.getCertificate();
      hash_tree = CertifiedTuple.encodeCBOR(tree);
    }
  };

  /// The on-chain verifying-key anchor a client pins its local proving keys to.
  ///
  /// `digest` and `epoch` are exactly the two halves of the certified `vk` leaf, so a client
  /// that wants subnet-verifiable truth reads `icrc3_get_tip_certificate`, verifies the
  /// certificate against the IC root key, and finds this same 40-byte value at label "vk"
  /// inside the hash tree — this query is the convenience form of that leaf, not a second
  /// source. `transfer_vk_hex`/`deposit_vk_hex` are returned so a client can recompute the
  /// digest itself rather than trusting this reply's `digest` field.
  public query func verifying_key_anchor() : async {
    transfer_vk_hex : Text;
    deposit_vk_hex : Text;
    digest : Blob;
    epoch : Nat64;
    certified : Bool;
  } {
    {
      transfer_vk_hex;
      deposit_vk_hex;
      digest = vkDigest();
      epoch = vk_epoch;
      // false only while unconfigured, i.e. exactly when the certified tree carries no vk leaf
      certified = vkAnchorLeaf() != null;
    }
  };

  public query func icrc3_get_tip_certificate() : async ?DataCertificate {
    if (noteCount() == 0) return null;
    switch (CertifiedData.getCertificate()) {
      case (?certificate) {
        ?{ certificate; hash_tree = CertifiedTuple.encodeCBOR(certifiedTree()) }
      };
      case null null;
    }
  };

  /// An unauthenticated membership oracle. Witnessed: the SAME anonymous caller, on the
  /// SAME nullifier bytes, gets `(false)` before the unshield and `(true)` after — so `2vxsx-fae`
  /// can watch a specific note be consumed on a pool it has no relationship with.
  ///
  /// Gated rather than dropped, and gated rather than left, on this test: gating is theatre
  /// when the answer is recomputable off-chain, which is why `recipient_binding` was deliberately
  /// left open. Nullifier membership is NOT recomputable by an outsider — it exists only in
  /// `spent_nullifiers` — so refusing it removes information rather than pretending to.
  public query ({ caller }) func is_nullifier_spent(nullifier : Blob) : async Bool {
    if (Principal.isAnonymous(caller)) Runtime.trap("REJECT:anonymous-membership-query");
    StableBlobSet.contains(spent_nullifiers, nullifier)
  };

  /// The second half of the same class. This was once closed on the ground that it "adds nothing
  /// over `status()` for a
  /// current root". `status()` carries ONE root; `historical_roots` accumulates one per state
  /// transition, so that argument covers a single element of an unbounded set and says nothing
  /// about the rest. For every root the pool has held and no longer holds, this answered a question
  /// `status()` cannot -- unauthenticated, while its sibling `is_nullifier_spent` was gated for
  /// exactly this class. Gated identically: membership is for authenticated callers, not the world.
  public query ({ caller }) func is_known_root(root : Blob) : async Bool {
    if (Principal.isAnonymous(caller)) Runtime.trap("REJECT:anonymous-membership-query");
    StableBlobSet.contains(historical_roots, root)
  };

  public query func icrc3_supported_block_types() : async [{ block_type : Text; url : Text }] {
    [{ block_type = "zknote1"; url = "https://github.com/dfinity/ICRC-1/tree/main/standards/ICRC-3" }]
  };

  public query func icrc3_get_archives(_args : GetArchivesArgs) : async [ArchiveInfo] { [] };

  // ICRC-3 permits returning fewer blocks than requested; clients paginate. The cap is
  // TOTAL across all requested ranges (a multi-range arg must not multiply the bound)
  // and bounds this query's decode work per message — the old uncapped loop
  // could be driven through the whole log in one call.
  let MAX_BLOCKS_PER_CALL : Nat = 512;

  public query func icrc3_get_blocks(args : [GetBlocksArgs]) : async GetBlocksResult {
    let result = List.empty<Block>();
    var emitted : Nat = 0;
    // A block carries a variable-length note, so `MAX_BLOCKS_PER_CALL` bounds how MANY blocks a
    // reply holds and says nothing about the bytes they carry. The count cap binds first for
    // ordinary traffic and stops binding exactly when traffic is abnormal, which is when the
    // bound is wanted -- the same reasoning that put a byte ceiling on the audit note walk.
    var emittedBytes : Nat = 0;
    label ranges for (range in args.vals()) {
      if (range.start < noteCount()) {
        let end = Nat.min(range.start + range.length, noteCount());
        var i = range.start;
        while (i < end) {
          if (emitted >= MAX_BLOCKS_PER_CALL) break ranges;
          let decoded = blockAt(i);
          List.add(result, { id = i; block = NoteAudit.blockValue(decoded) });
          emitted += 1;
          // The ciphertext is the variable-length part of a block; every other field is fixed
          // width, so it is the term that makes a reply's size unbounded in anything but count.
          emittedBytes += decoded.note_ciphertext.size();
          i += 1;
          // Checked AFTER the append, so a single oversized block is still returned rather than
          // making the range unreadable. `log_length` below lets a caller resume from `i`.
          if (emittedBytes >= AUDIT_BYTES_PER_CHUNK) break ranges;
        };
      };
    };
    { blocks = List.toArray(result); log_length = noteCount(); archived_blocks = [] }
  };

  // Compact detection stream for light-client note recognition. Returns densely packed
  // 48-byte entries `(note_position : 8B big-endian) || note_ciphertext[0..40]` — the envelope's
  // ephemeral X25519 key (32B) plus its 8-byte view tag (new-format envelopes) or the first 8 nonce
  // bytes (legacy, which a client ignores below its format cutover). It slices the stored envelope
  // bytes and performs NO envelope crypto or parsing beyond the note decode. Additive and read-only
  // (changes no existing behavior); same 512-block TOTAL cap and per-message bound as
  // icrc3_get_blocks (measured: ~418k instr/note, a 512-note call ~24× under the query budget).
  public query func detection_stream(start : Nat, count : Nat) : async Blob {
    let out = List.empty<Nat8>();
    let n = noteCount();
    if (start < n) {
      let end = Nat.min(start + Nat.min(count, MAX_BLOCKS_PER_CALL), n);
      var i = start;
      while (i < end) {
        var k : Nat = 8;
        while (k > 0) { k -= 1; List.add(out, Nat8.fromNat((i / (256 ** k)) % 256)) };
        let ct = Blob.toArray(blockAt(i).note_ciphertext);
        var j = 0;
        while (j < 40) {
          List.add(out, if (j < ct.size()) ct[j] else (0 : Nat8));
          j += 1;
        };
        i += 1;
      };
    };
    Blob.fromArray(List.toArray(out))
  };

  // ---- certified detection-stream anchor (additive, flag-gated; see src/DetectChain.mo) ----
  // Enable is GENESIS-ONLY: the chain must cover the full history for a birthday-less restore to
  // verify every page, and there is no backfill path — so it arms only on an empty log. Additive:
  // flag off leaves append, certification, and every existing endpoint byte-identical to 44692fc.
  // Administrator-only: enabling puts DetectChain.append's unbounded-in-N work back inside the
  // post-payout commit, which is the precondition the payout-path instruction bound relies on. The
  // authorisation check runs FIRST so a caller who is not the administrator learns nothing about
  // the pool's state from the answer.
  public shared ({ caller }) func detect_chain_enable() : async Result<()> {
    if (not isAdministrator(caller)) return #err("REJECT:not-administrator");
    if (detect_chain_enabled) return #err("REJECT:detect-chain-already-enabled");
    if (noteCount() != 0) return #err("REJECT:detect-chain-nonempty-log");
    detect_chain_enabled := true;
    refreshCertification();
    #ok(())
  };

  // Symmetric with enable, and permitted in exactly the same window: only on an empty log. Once a
  // note exists the chain covers history a client may already have bound to, and turning it off
  // then on again would leave the chain behind the log — the count-mismatch that fails the audit's
  // exact-equality cross-check closed. Reversible while it is harmless; frozen once it is not.
  public shared ({ caller }) func detect_chain_disable() : async Result<()> {
    if (not isAdministrator(caller)) return #err("REJECT:not-administrator");
    if (not detect_chain_enabled) return #err("REJECT:detect-chain-not-enabled");
    if (noteCount() != 0) return #err("REJECT:detect-chain-nonempty-log");
    detect_chain_enabled := false;
    refreshCertification();
    #ok(())
  };

  /// Trusted anchor a light client binds via the certified `detect_stream` tuple leaf
  /// (leaf == SHA256(root ‖ c_tip ‖ note_count LE8)); root/c_tip are never taken from a mirror.
  public query func detect_stream_anchor() : async Result<{ root : Blob; c_tip : Blob; note_count : Nat }> {
    if (not detect_chain_enabled) return #err("REJECT:detect-chain-not-enabled");
    #ok({ root = detect_chain_state.root; c_tip = detect_chain_state.chain; note_count = detect_chain_state.count })
  };

  /// Boundary leaf j + its Merkle path — public, mirror-servable data a client verifies against
  /// the certified root before scanning segment j.
  public query func detect_boundary_proof(j : Nat) : async Result<{ leaf : Blob; path : [(Blob, Bool)] }> {
    if (not detect_chain_enabled) return #err("REJECT:detect-chain-not-enabled");
    switch (DetectChain.boundaryProofAt(detect_chain_state, j)) {
      case (?p) #ok(p);
      case null #err("REJECT:detect-chain-no-boundary");
    }
  };

  func pendingById(intentId : Blob) : ?PendingShield {
    switch (pending_shield) {
      case (?pending) { if (Blob.equal(pending.intent_id, intentId)) ?pending else null };
      case null null;
    }
  };

  func tokenErrorName(error : ICRC2.TransferFromError) : Text {
    switch (error) {
      case (#BadFee(_)) "BadFee";
      case (#BadBurn(_)) "BadBurn";
      case (#InsufficientFunds(_)) "InsufficientFunds";
      case (#InsufficientAllowance(_)) "InsufficientAllowance";
      case (#TooOld) "TooOld";
      case (#CreatedInFuture(_)) "CreatedInFuture";
      case (#Duplicate(_)) "Duplicate";
      case (#TemporarilyUnavailable) "TemporarilyUnavailable";
      case (#GenericError(_)) "GenericError";
    }
  };

  func deterministicNoEffectError(error : ICRC2.TransferFromError) : Bool {
    switch (error) {
      case (#BadFee(_)) true;
      case (#BadBurn(_)) true;
      case (#InsufficientFunds(_)) true;
      case (#InsufficientAllowance(_)) true;
      case (#CreatedInFuture(_)) true;
      case _ false;
    }
  };

  /// Errors whose EFFECT cannot be inferred from the error alone, so the intent must be settled
  /// against the token log instead of latched or blindly cancelled.
  ///
  /// The default is deliberately inverted: anything not provably no-effect and not provably
  /// transient lands here, INCLUDING variants this canister does not know about. Enumerating the
  /// resolvable errors and latching the rest is what left a pending intent permanently stuck —
  /// closing #TooOld alone would close one entrance of nine and leave #GenericError, which no
  /// specification makes transient, reproducing the same freeze.
  ///
  /// #TemporarilyUnavailable is the one genuine exception: it is transient by definition, a retry
  /// may succeed, and staying pending is correct. #Duplicate never reaches here — it is consumed
  /// as a block index by the preceding match arm.
  func requiresLogSettlement(error : ICRC2.TransferFromError) : Bool {
    switch (error) {
      case (#TemporarilyUnavailable) false;
      case (#Duplicate(_)) false;
      case _ not deterministicNoEffectError(error);
    }
  };

  func finalizeShield(intentId : Blob) : MutationResult {
    if (StableBlobSet.contains(completed_shield_intents, intentId)) {
      return mutation("ACCEPT:already-finalized", "ACCEPT");
    };
    let pending = switch (pendingById(intentId)) {
      case (?value) value;
      case null return mutation("REJECT:pending-shield-changed", "NOT_CALLED");
    };
    if (epoch != pending.base_epoch or note_root != pending.anchor_before) {
      return mutation("REJECT:pending-shield-epoch", pending.verifier_outcome);
    };

    // No await after this point: the exact token block is already observed. If any stable write
    // traps, this callback rolls back to the pre-callback pending intent and remains recoverable.
    // Cross-check the transition at FINALIZE, not only at creation.
    // NON-CIRCULAR by construction: the left side is recomputed IN-CANISTER from the local tree
    // (`currentTree()`, still pre-transition here because `tree_state` is not reassigned until
    // below) and the commitments stored on the pending; the right side is the ORACLE's value
    // captured at creation. Comparing `pending.next_tree` to `pending.root_after` would instead
    // compare a value with itself -- both derive from the same `parseTransition` -- and pass
    // unconditionally. `currentTree()` is provably the state this intent was created against:
    // the guard above refuses unless `note_root == pending.anchor_before`.
    // ON MISMATCH WE RETURN, WHICH LEAVES THE INTENT PENDING. It is NOT cancelled -- cancelling
    // would convert a receipt defect into a funds-availability defect, and the money converges
    // only because the resume can still finalize.
    if (not tree_frontier_enabled) {
      return mutation("REJECT:finalize-frontier-disabled", pending.verifier_outcome);
    };
    switch (frontierAppend(currentTree(), [blobToHex(pending.output.commitment)])) {
      case (#err(message)) return mutation(message, pending.verifier_outcome);
      case (#ok(local)) {
        if (local.root != blobToHex(pending.root_after)) {
          // Raise the NON-BLOCKING divergence signal, then return unchanged (still leaves the
          // intent PENDING; no sticky-guard trip, so the resume can still converge).
          finalize_frontier_mismatch_count += 1;
          finalize_frontier_mismatch_last := ?intentId;
          return mutation("REJECT:finalize-frontier-mismatch", pending.verifier_outcome);
        };
      };
    };
    tree_state := ?pending.next_tree;
    note_root := pending.root_after;
    addRoot(pending.root_after);
    appendBlock(pending.output, [], pending.anchor_before, pending.root_after, #shield);
    pool_value += Nat64.toNat(pending.value);
    epoch += 1;
    switch (StableBlobSet.put(completed_shield_intents, intentId)) {
      case (#ok(true)) {
        shields_put_counter += 1;
        shields_fold_digest := xorFold(shields_fold_digest, intentId);
      };
      case (#ok(false)) Runtime.trap("stable-state:completed-shield-duplicate");
      case (#err(message)) Runtime.trap(message);
    };
    pending_shield := null;
    refreshCertification();
    mutation("ACCEPT", pending.verifier_outcome)
  };

  // Recovery by idempotency key: scan the token ledger's blocks from the pre-call low-water for the
  // unique 2xfer carrying memo == intent_id. Independent of the ICRC-2 dedup window, so it recovers
  // a trapped-after-transfer shield no matter how long the outage lasted. Bounded per message by
  // PAGE; the await loop paginates the instruction budget across messages.
  // ==================== retry budget for a pending intent ====================
  //
  // `attempts` was written by all three resume entries and read by nothing: no cap, no expiry, no
  // escalation. A caller stuck on a dependency that is down could drive the token ledger and the
  // archives without bound, one inter-canister call chain per resume, and nothing about the intent
  // ever changed to say so. A1 made the counter visible in atomicity_status; this makes it mean
  // something.
  //
  // The limit deliberately does NOT cancel, expire or otherwise resolve the intent. A pending
  // intent may have a payout already on the token ledger, and releasing one on a retry count rather
  // than on evidence is exactly the failure A6 is about. It refuses the RETRY, names itself in the
  // outcome so a latch is legible, and leaves the intent exactly where it was.
  //
  // The administrator is exempt, and that is load-bearing rather than a convenience: a cap with no
  // exemption would itself become the permanent latch it exists to make visible. Recovery stays
  // possible at any attempt count, through the same evidence-based path as every other resume.
  let INTENT_ATTEMPT_LIMIT : Nat = 32;

  /// How long a pending intent may sit before it is refused as expired. 24h in nanoseconds.
  let INTENT_TIMEOUT_NS : Nat64 = 86_400_000_000_000;

  func attemptLimitReached(attempts : Nat, caller : Principal) : Bool {
    attempts >= INTENT_ATTEMPT_LIMIT and not isAdministrator(caller)
  };

  type ReconcileResult = { #found : Nat; #absent; #error : Text };

  // ==================== archive-aware token-log scan ====================
  //
  // icrc3_get_blocks answers a range in two parts: the blocks the ledger still holds INLINE, and
  // `archived_blocks` — ranges it has handed to an archive canister, each with a callback that
  // serves them. A scan that reads only `blocks` sees an EMPTY reply for a range that has moved to
  // an archive, and cannot tell "these blocks do not exist" from "I did not look where they are".
  //
  // THE INVARIANT: #absent is returned only when absence was PROVEN — every index from the
  // starting tip to the log's end was actually observed and none matched. A failure to look must
  // never become a conclusion that nothing is there. So a callback that traps or rejects, a reply
  // that makes no progress, a block carrying an id outside the requested span, a malformed
  // archived range, or any bound being reached all produce #error, which leaves the intent pending
  // for another attempt. #error costs a retry; a false #absent cancels an intent whose payout has
  // already landed.
  //
  // GetBlocksCallback is self-recursive by specification — an archive's reply is itself a
  // GetBlocksResult and may defer again — so the walk is an explicit bounded worklist rather than
  // recursion, and the bound is a number in the code instead of a property of the call graph.

  let SCAN_PAGE : Nat = 64;
  let SCAN_PAGE_LIMIT : Nat = 256;
  let SCAN_DEPTH_LIMIT : Nat = 4;
  let SCAN_VISIT_LIMIT : Nat = 64;

  type ScanTask = { source : GetBlocksCallback; start : Nat; length : Nat; depth : Nat };
  type SpanOutcome = { #found : Nat; #observed : Nat; #error : Text };

  /// Length of the contiguous run of observed indices starting at the beginning of the span.
  /// A gap stops the count: the scan may only advance over indices it actually saw.
  func observedPrefix(mask : Nat64, length : Nat) : Nat {
    var count : Nat = 0;
    while (count < length and (mask & (1 << Nat64.fromNat(count))) != 0) { count += 1 };
    count
  };

  /// Observe [start, start+length) beginning from a reply already in hand, following every range
  /// that reply — or an archive's reply — defers. Returns #found on the first match, otherwise the
  /// length of the contiguous prefix of the span that was ACTUALLY observed.
  ///
  /// Coverage is tracked as a bitmask over the span rather than by counting blocks, so a reply that
  /// repeats an index cannot inflate the count and hide a gap. The span is capped at 64 indices,
  /// which is what makes one Nat64 sufficient.
  func scanSpan(
    first : GetBlocksResult,
    start : Nat,
    length : Nat,
    matches : ICRC3.Value -> Bool,
  ) : async SpanOutcome {
    if (length == 0 or length > 64) return #error("token-log-scan:span-width");
    let queue = List.empty<ScanTask>();
    var mask : Nat64 = 0;
    var reply = first;
    var depth : Nat = 0;
    var cursor : Nat = 0;
    loop {
      for (entry in reply.blocks.vals()) {
        // A block whose id falls outside the requested span cannot be attributed to it, and
        // counting it would let a reply shrink the span the caller believes it observed.
        if (entry.id < start or entry.id >= start + length) {
          return #error("token-log-scan:block-id-outside-span");
        };
        if (matches(entry.block)) return #found(entry.id);
        mask := mask | (1 << Nat64.fromNat(entry.id - start));
      };
      for (archived in reply.archived_blocks.vals()) {
        for (range in archived.args.vals()) {
          if (range.length == 0) return #error("token-log-scan:archive-empty-range");
          if (range.start < start or range.start + range.length > start + length) {
            return #error("token-log-scan:archive-range-outside-span");
          };
          if (depth + 1 > SCAN_DEPTH_LIMIT) return #error("token-log-scan:archive-depth-limit");
          if (List.size(queue) >= SCAN_VISIT_LIMIT) return #error("token-log-scan:archive-visit-limit");
          List.add(queue, {
            source = archived.callback;
            start = range.start;
            length = range.length;
            depth = depth + 1;
          });
        };
      };
      if (cursor >= List.size(queue)) return #observed(observedPrefix(mask, length));
      let task = switch (List.get(queue, cursor)) {
        case (?value) value;
        case null return #error("token-log-scan:worklist");
      };
      cursor += 1;
      depth := task.depth;
      reply := try {
        await task.source([{ start = task.start; length = task.length }])
      } catch (error) {
        // A callback that traps or rejects is a failure to LOOK, and stays one.
        return #error("token-log-scan:archive-call:" # Error.message(error));
      };
    }
  };

  /// Scan the token log from `tip` for a block satisfying `matches`.
  func reconcileTokenBlock(tip : Nat, matches : ICRC3.Value -> Bool) : async ReconcileResult {
    let history = historyActor();
    var index = tip;
    var pages : Nat = 0;
    loop {
      if (pages >= SCAN_PAGE_LIMIT) return #error("token-log-scan:page-limit");
      pages += 1;
      let page = try {
        await history.icrc3_get_blocks([{ start = index; length = SCAN_PAGE }])
      } catch (error) {
        return #error("token-log-scan:" # Error.message(error));
      };
      // The only proof of absence: the scan has reached the end of the log having observed every
      // index behind it.
      if (index >= page.log_length) return #absent;
      let want = if (index + SCAN_PAGE > page.log_length) page.log_length - index else SCAN_PAGE;
      switch (await scanSpan(page, index, want, matches)) {
        case (#found(id)) return #found(id);
        case (#error(message)) return #error(message);
        case (#observed(covered)) {
          // No progress means the log will not serve `index` — the empty inline reply that the
          // previous scan read as absence. The difference between those two readings is an intent
          // cancelled after its payout landed.
          if (covered == 0) return #error("token-log-scan:no-progress-at-" # Nat.toText(index));
          index += covered;
        };
      };
    }
  };

  /// Read exactly the block at `id`, following archives.
  ///
  /// The confirmation read after a token call used to be a bare icrc3_get_blocks for one index,
  /// judged by `blocks.size() != 1`. That is the same defect in a narrower shape: a block written a
  /// moment ago can already have been archived by the time it is read back, and an archived index
  /// answers with an empty inline reply. It latches the intent rather than cancelling it, so it
  /// costs liveness rather than funds — but it is reachable, and it is the same root cause.
  func fetchTokenBlock(id : Nat) : async { #found : ICRC3.Value; #absent; #error : Text } {
    let history = historyActor();
    let page = try {
      await history.icrc3_get_blocks([{ start = id; length = 1 }])
    } catch (error) {
      return #error("token-log-fetch:" # Error.message(error));
    };
    if (id >= page.log_length) return #absent;
    // The matcher accepts the single index in the span and captures it on the way past; scanSpan
    // reports which id matched, and the caller here needs the value as well.
    var captured : ?ICRC3.Value = null;
    switch (await scanSpan(page, id, 1, func(block : ICRC3.Value) : Bool { captured := ?block; true })) {
      case (#found(_)) {
        switch (captured) {
          case (?value) #found(value);
          case null #error("token-log-fetch:capture");
        };
      };
      case (#observed(_)) #error("token-log-fetch:not-observed-at-" # Nat.toText(id));
      case (#error(message)) #error(message);
    }
  };

  func reconcileShieldBlock(pending : PendingShield) : async ReconcileResult {
    await reconcileTokenBlock(
      pending.ledger_tip_before,
      func(block : ICRC3.Value) : Bool {
        ICRC2Block.matchesTransferFrom(block, pending.transfer_args, selfPrincipal())
      },
    )
  };

  func drivePendingShield(intentId : Blob, trapAfterToken : Bool, reconcileFirst : Bool) : async MutationResult {
    let pending = switch (pendingById(intentId)) {
      case (?value) value;
      case null return mutation("REJECT:pending-shield-changed", "NOT_CALLED");
    };
    // Recovery path: if the token block already landed under this intent's memo, finalize against it
    // directly — never re-call transfer_from (which would hit #TooOld or double-charge post-window).
    if (reconcileFirst) {
      switch (await reconcileShieldBlock(pending)) {
        case (#found(_)) {
          switch (pendingById(intentId)) {
            case (?current) {
              if (epoch != current.base_epoch or note_root != current.anchor_before) {
                return mutation("REJECT:pending-shield-epoch", current.verifier_outcome);
              };
              return finalizeShield(intentId);
            };
            case null {
              if (StableBlobSet.contains(completed_shield_intents, intentId)) {
                return mutation("ACCEPT:already-finalized", "ACCEPT");
              };
              return mutation("REJECT:pending-shield-changed", pending.verifier_outcome);
            };
          };
        };
        case (#error(msg)) return mutation("PENDING:reconcile-scan:" # msg, pending.verifier_outcome);
        case (#absent) {}; // transfer never landed — safe to (re)send below
      };
    };
    let response = try {
      await tokenActor().icrc2_transfer_from(pending.transfer_args)
    } catch (error) {
      return mutation("PENDING:token-call:" # Error.message(error), "CALL_FAILED");
    };

    let blockIndex = switch (response) {
      case (#Ok(index)) index;
      case (#Err(#Duplicate({ duplicate_of }))) duplicate_of;
      case (#Err(error)) {
        if (deterministicNoEffectError(error) and pendingById(intentId) != null) {
          pending_shield := null;
          return mutation("REJECT:token:" # tokenErrorName(error) # ":no-effect", pending.verifier_outcome);
        };
        // Anything whose effect is not inferable settles against the token log rather than
        // latching: the args are frozen, so an unresolvable error repeats identically and the
        // intent would block every shielded mutation permanently.
        if (requiresLogSettlement(error) and pendingById(intentId) != null) {
          switch (await reconcileShieldBlock(pending)) {
            case (#found(_)) {
              switch (pendingById(intentId)) {
                case (?current) {
                  if (epoch != current.base_epoch or note_root != current.anchor_before) {
                    return mutation("REJECT:pending-shield-epoch", current.verifier_outcome);
                  };
                  return finalizeShield(intentId);
                };
                case null {
                  if (StableBlobSet.contains(completed_shield_intents, intentId)) {
                    return mutation("ACCEPT:already-finalized", "ACCEPT");
                  };
                  return mutation("REJECT:pending-shield-changed", pending.verifier_outcome);
                };
              };
            };
            case (#error(msg)) return mutation("PENDING:reconcile-scan:" # msg, pending.verifier_outcome);
            case (#absent) {
              // Absence proven after the failing send: the transfer never landed, so the intent
              // is dead and its slot must be released.
              if (pendingById(intentId) == null) {
                return mutation("REJECT:pending-shield-changed", pending.verifier_outcome);
              };
              pending_shield := null;
              return mutation("REJECT:token:" # tokenErrorName(error) # ":absent", pending.verifier_outcome);
            };
          };
        };
        return mutation("PENDING:token:" # tokenErrorName(error), pending.verifier_outcome);
      };
    };

    if (trapAfterToken) Runtime.trap("TEST_ONLY:fail-after-token-before-finalize");
    let observed = switch (await fetchTokenBlock(blockIndex)) {
      case (#found(value)) value;
      case (#absent) return mutation("PENDING:token-block-absent", pending.verifier_outcome);
      case (#error(message)) return mutation("PENDING:token-block-call:" # message, pending.verifier_outcome);
    };
    let current = switch (pendingById(intentId)) {
      case (?value) value;
      case null {
        if (StableBlobSet.contains(completed_shield_intents, intentId)) {
          return mutation("ACCEPT:already-finalized", "ACCEPT");
        };
        return mutation("REJECT:pending-shield-changed", pending.verifier_outcome);
      };
    };
    // The id is no longer re-checked here: scanSpan rejects any block carrying an id outside the
    // requested span, so what fetchTokenBlock returns is the block at blockIndex or nothing.
    if (epoch != current.base_epoch or
        not ICRC2Block.matchesTransferFrom(observed, current.transfer_args, selfPrincipal())) {
      return mutation("PENDING:token-block-mismatch", current.verifier_outcome);
    };
    finalizeShield(intentId)
  };

  public shared ({ caller }) func shield(args : DepositArgs) : async MutationResult {
    // Seed the publish salt on an update path — queries cannot seed one, so it has to happen
    // here. REG-4: this comment used to end "an unseeded salt makes publishedIntentId fall through
    // to the raw handle, leaving the oracle open". That stopped being true at a3b82b3, which made
    // publishedIntentId fail CLOSED — an unseeded salt now returns "" and WITHHOLDS the handle.
    // The seeding therefore buys the OBSERVABLE, not the safety: without it a published handle is
    // empty and the operator loses the correlation, but nothing raw is ever disclosed. Corrected
    // because the stale wording is not inert — it was read as current behaviour during review and
    // produced the confident, wrong conclusion that salting a query path is a no-op.
    await seedIntentPublishSalt();
    // guard FIRST: even the already-finalized replay answer reads the completed set —
    // exactly the state a failed audit distrusts (and contains() can trap on a corrupt
    // slot); a guarded ledger answers with a clean reject, never a membership claim
    switch (guardRejection()) { case (?message) return mutation(message, "NOT_CALLED"); case null {} };
    if (not configured()) return mutation("REJECT:unconfigured", "NOT_CALLED");
    // FAIL CLOSED. Without the in-canister frontier nothing cross-checks the oracle's root, so the
    // value path refuses rather than trusting it. A pool that upgraded with the flag stored false is
    // told, not silently switched: one gated admin call, set_tree_frontier(true), restores service.
    // Refuse NEW intents while quarantined. Finalize paths are deliberately
    // untouched: an existing pending must still be able to complete, or quarantine would strand
    // the very intents it exists to protect — a funds-availability failure.
    if (state_quarantine) return mutation("REJECT:state-quarantined", "NOT_CALLED");
    if (not tree_frontier_enabled) return mutation("REJECT:frontier-disabled", "NOT_CALLED");
    if (not tokenConfigured()) return mutation("REJECT:token-unconfigured", "NOT_CALLED");
    if (pending_shield != null or pending_unshield != null) {
      return mutation("REJECT:pending-token-mutation", "NOT_CALLED");
    };
    if (not fieldSized(args.commitment)) return mutation("REJECT:commitment-length", "NOT_CALLED");
    if (args.client_nonce.size() != 32) return mutation("REJECT:client-nonce-length", "NOT_CALLED");
    switch (args.from_subaccount) {
      case (?value) { if (value.size() != 32) return mutation("REJECT:from-subaccount-length", "NOT_CALLED") };
      case null {};
    };
    if (args.ephemeral_key.size() == 0 or args.note_ciphertext.size() == 0) {
      return mutation("REJECT:opaque-record-empty", "NOT_CALLED");
    };
    let intentId = shieldIntentId(caller, args);
    if (StableBlobSet.contains(completed_shield_intents, intentId)) {
      return mutation("ACCEPT:already-finalized", "ACCEPT");
    };
    let inputs = switch (serializePublicInputs([args.commitment, nat64Field(args.value)])) {
      case (?encoded) encoded;
      case null return mutation("REJECT:public-input-encoding", "NOT_CALLED");
    };
    let startEpoch = epoch;
    // In-process verify: no await, so no state can change between the guards above and the
    // verdict — the old post-verify state-change re-check is structurally impossible to fail
    // and is gone with the call boundary.
    let verdict = verifyShieldProof(args.proof_hex, inputs);
    if (verdict != "ACCEPT") return mutation(verdict, verdict);

    let treeBefore = currentTree();
    // COMMITMENT INGRESS — the third stored value. Leaves never pass through
    // parseTransition, so a transition-only remedy leaves `REJECT:leaf-field` reachable at finalize
    // and the strand simply relocates. Same constructor, refused not reduced.
    let shieldLeaves = [blobToHex(args.commitment)];
    for (leaf in shieldLeaves.vals()) {
      switch (PoseidonTree.parseFieldElement(leaf)) {
        case (?_) {};
        case null return mutation("REJECT:commitment-noncanonical", "NOT_CALLED");
      };
    };
    // With the frontier flag ON the transition is computed in-canister BEFORE the
    // await (no state window); flag OFF leaves this null and the legacy path unchanged.
    let localNext = switch (frontierLocalNext(treeBefore, shieldLeaves)) {
      case (#ok(value)) value;
      case (#err(message)) return mutation(message, verdict);
    };
    let transition = switch (localNext) {
      case (?local) {
        if (tree_oracle_id == null) {
          // frontier authoritative, oracle detached: the ledger stands alone.
          { state = ?local; error = null } : TreeTransition
        } else {
          // oracle attached: still called, demoted to a cross-checked accelerator.
          try {
            await treeActor().append(treeBefore, shieldLeaves)
          } catch (error) {
            return mutation("REJECT:tree-oracle-call:" # Error.message(error), verdict);
          }
        }
      };
      case null {
        try {
          await treeActor().append(treeBefore, shieldLeaves)
        } catch (error) {
          return mutation("REJECT:tree-oracle-call:" # Error.message(error), verdict);
        }
      };
    };
    if (pending_shield != null or pending_unshield != null or epoch != startEpoch) {
      return mutation("REJECT:state-changed", verdict);
    };
    let next = switch (parseTransition(transition)) {
      case (#ok(state)) state;
      case (#err(message)) return mutation(message, verdict);
    };
    switch (frontierCrossCheck(localNext, next, "shield")) {
      case (?message) return mutation(message, verdict);
      case null {};
    };
    let rootAfter = switch (hexToBlob(next.root)) {
      case (?root) root;
      case null return mutation("REJECT:tree-root-hex", verdict);
    };
    let transferArgs : ICRC2.TransferFromArgs = {
      spender_subaccount = null;
      from = { owner = caller; subaccount = args.from_subaccount };
      to = poolAccount();
      amount = Nat64.toNat(args.value);
      fee = ?transparent_ledger_fee;
      memo = ?intentId;
      created_at_time = ?args.created_at_time;
    };
    // Low-water for dedup-window-independent recovery: the token ledger's block count BEFORE the
    // transfer. Any block minted by this shield lands at an index >= this, bounding the recovery scan.
    let ledgerTip = try {
      (await historyActor().icrc3_get_blocks([{ start = 0; length = 0 }])).log_length
    } catch (error) {
      return mutation("REJECT:ledger-tip-call:" # Error.message(error), verdict);
    };
    if (pending_shield != null or pending_unshield != null or epoch != startEpoch) {
      return mutation("REJECT:state-changed", verdict);
    };
    pending_shield := ?{
      intent_id = intentId;
      caller;
      output = {
        commitment = args.commitment;
        ephemeral_key = args.ephemeral_key;
        note_ciphertext = args.note_ciphertext;
      };
      value = args.value;
      transfer_args = transferArgs;
      anchor_before = note_root;
      root_after = rootAfter;
      next_tree = next;
      base_epoch = epoch;
      verifier_outcome = verdict;
      attempts = 1;
      ledger_tip_before = ledgerTip;
    };
    let trapAfterToken = test_fail_after_token_once;
    test_fail_after_token_once := false;
    await drivePendingShield(intentId, trapAfterToken, false)
  };

  public shared ({ caller }) func resume_shield() : async MutationResult {
    // Blocking resume while guarded is fund-safe: the pending intent is stable and
    // reconcile-by-memo is dedup-window-independent, so finalization only WAITS for
    // guard-clear + green re-audit (Main.mo ledger_tip_before design).
    switch (guardRejection()) { case (?message) return mutation(message, "NOT_CALLED"); case null {} };
    let pending = switch (pending_shield) {
      case (?value) value;
      case null return mutation("REJECT:no-pending-shield", "NOT_CALLED");
    };
    if (not Principal.equal(caller, pending.caller) and not isAdministrator(caller)) {
      return mutation("REJECT:not-pending-owner", "NOT_CALLED");
    };
    if (attemptLimitReached(pending.attempts, caller)) {
      return mutation("PENDING:shield-attempt-limit", pending.verifier_outcome);
    };
    pending_shield := ?{ pending with attempts = pending.attempts + 1 };
    // Same admin-gated fault hook the non-recovery entries consume. The recovery paths used to
    // hard-code false, which meant the code that exists specifically to survive a crash was the
    // only code that could not be crash-tested.
    let trapAfterToken = test_fail_after_token_once;
    test_fail_after_token_once := false;
    await drivePendingShield(pending.intent_id, trapAfterToken, true)
  };

  func pendingUnshieldById(intentId : Blob) : ?PendingUnshield {
    switch (pending_unshield) {
      case (?pending) { if (Blob.equal(pending.intent_id, intentId)) ?pending else null };
      case null null;
    }
  };

  func directTokenErrorName(error : ICRC2.TransferError) : Text {
    switch (error) {
      case (#BadFee(_)) "BadFee";
      case (#BadBurn(_)) "BadBurn";
      case (#InsufficientFunds(_)) "InsufficientFunds";
      case (#TooOld) "TooOld";
      case (#CreatedInFuture(_)) "CreatedInFuture";
      case (#Duplicate(_)) "Duplicate";
      case (#TemporarilyUnavailable) "TemporarilyUnavailable";
      case (#GenericError(_)) "GenericError";
    }
  };

  func directDeterministicNoEffectError(error : ICRC2.TransferError) : Bool {
    switch (error) {
      case (#BadFee(_)) true;
      case (#BadBurn(_)) true;
      case (#InsufficientFunds(_)) true;
      case (#CreatedInFuture(_)) true;
      case _ false;
    }
  };

  /// ICRC-1 twin of requiresLogSettlement; same inverted default, same settle-by-scan obligation.
  func directRequiresLogSettlement(error : ICRC2.TransferError) : Bool {
    switch (error) {
      case (#TemporarilyUnavailable) false;
      case (#Duplicate(_)) false;
      case _ not directDeterministicNoEffectError(error);
    }
  };

  /// PREPARE for the unshield commit: every fallible operation, before any money moves.
  ///
  /// A failure here is a clean reject with an honest receipt, because nothing has happened yet — and
  /// that includes a trap, which is why the headroom calls are allowed to trap rather than being
  /// wrapped. What must never happen is a failure AFTER the payout.
  ///
  /// Called before the RECONCILE, not merely before the payout: finalizeUnshield is reachable via
  /// reconcileFirst -> #found with no payout in that message at all, and on the resume path that is
  /// the common case. Placing this before the payout alone would leave the exact scenario the
  /// resume batteries reproduce uncovered while looking fixed.
  ///
  /// Idempotent. The headroom calls are predicates rather than reservations, so repeating this
  /// grows nothing — which matters because resume_unshield concurrency is unbounded.
  func prepareUnshieldCommit(pending : PendingUnshield) : Result<()> {
    // ---- the checks the commit would otherwise trap on ----
    if (StableBlobSet.contains(completed_unshield_intents, pending.intent_id)) {
      return #err("REJECT:prepare-already-completed");
    };
    // A DIFFERENT check from the one above: addNullifier traps on #ok(false), and the original
    // hoist table mapped the duplicate case only to completed_unshield_intents.
    if (StableBlobSet.contains(spent_nullifiers, pending.nullifier_1) or
        StableBlobSet.contains(spent_nullifiers, pending.nullifier_2)) {
      return #err("REJECT:prepare-nullifier-spent");
    };
    if (pending.pool_debit > pool_value) return #err("REJECT:prepare-pool-debit");

    // ---- the encodings, so NoteCodec.encode cannot trap inside the commit ----
    // Both blocks are built here because block 2's phash is block 1's hash: neither can be derived
    // from live state at the moment block 2 is built.
    let nullifiers = [pending.nullifier_1, pending.nullifier_2];
    let position1 = noteCount();
    let block1 = buildNoteBlock(pending.output_1, nullifiers, pending.anchor_before,
      pending.root_after, #confidential_transfer, position1, last_block_hash);
    let encoded1 = switch (NoteCodec.encode(block1)) {
      case (#ok(value)) value;
      case (#err(message)) return #err("REJECT:prepare-encode:" # message);
    };
    let hash1 = ICRC3.hashValue(NoteAudit.blockValue(block1));
    let block2 = buildNoteBlock(pending.output_2, nullifiers, pending.anchor_before,
      pending.root_after, #confidential_transfer, position1 + 1, ?hash1);
    let encoded2 = switch (NoteCodec.encode(block2)) {
      case (#ok(value)) value;
      case (#err(message)) return #err("REJECT:prepare-encode:" # message);
    };
    let hash2 = ICRC3.hashValue(NoteAudit.blockValue(block2));

    // ---- the headroom, so nothing in the commit can grow a region ----
    switch (StableBlobSet.ensureHeadroom(spent_nullifiers, 2)) {
      case (#err(message)) return #err("REJECT:prepare-headroom:" # message); case (_) {};
    };
    switch (StableBlobSet.ensureHeadroom(historical_roots, 1)) {
      case (#err(message)) return #err("REJECT:prepare-headroom:" # message); case (_) {};
    };
    switch (StableBlobSet.ensureHeadroom(completed_unshield_intents, 1)) {
      case (#err(message)) return #err("REJECT:prepare-headroom:" # message); case (_) {};
    };
    switch (StableLog.ensureHeadroom(note_log,
      Nat64.fromNat(encoded1.size() + encoded2.size()), 2)) {
      case (#err(message)) return #err("REJECT:prepare-headroom:" # message); case (_) {};
    };

    pending_unshield_prepared := ?{
      intent_id = pending.intent_id;
      encoded_1 = encoded1;
      encoded_2 = encoded2;
      hash_1 = hash1;
      hash_2 = hash2;
      position_1 = position1;
    };
    #ok(())
  };

  /// The prepared record for this intent, or null when it is absent or names a different one.
  func preparedFor(intentId : Blob) : ?PreparedUnshield {
    switch (pending_unshield_prepared) {
      case (?record) { if (record.intent_id == intentId) ?record else null };
      case null null;
    }
  };

  func finalizeUnshield(intentId : Blob) : MutationResult {
    if (StableBlobSet.contains(completed_unshield_intents, intentId)) {
      return mutation("ACCEPT:already-finalized", "ACCEPT");
    };
    let pending = switch (pendingUnshieldById(intentId)) {
      case (?value) value;
      case null return mutation("REJECT:pending-unshield-changed", "NOT_CALLED");
    };
    if (epoch != pending.base_epoch or note_root != pending.anchor_before or
        pending.pool_debit > pool_value) {
      return mutation("REJECT:pending-unshield-epoch", pending.verifier_outcome);
    };

    // Cross-check the transition at FINALIZE, not only at creation.
    // NON-CIRCULAR by construction: the left side is recomputed IN-CANISTER from the local tree
    // (`currentTree()`, still pre-transition here because `tree_state` is not reassigned until
    // below) and the commitments stored on the pending; the right side is the ORACLE's value
    // captured at creation. Comparing `pending.next_tree` to `pending.root_after` would instead
    // compare a value with itself -- both derive from the same `parseTransition` -- and pass
    // unconditionally. `currentTree()` is provably the state this intent was created against:
    // the guard above refuses unless `note_root == pending.anchor_before`.
    // ON MISMATCH WE RETURN, WHICH LEAVES THE INTENT PENDING. It is NOT cancelled -- cancelling
    // would convert a receipt defect into a funds-availability defect, and the money converges
    // only because the resume can still finalize.
    if (not tree_frontier_enabled) {
      return mutation("REJECT:finalize-frontier-disabled", pending.verifier_outcome);
    };
    switch (frontierAppend(currentTree(), [blobToHex(pending.output_1.commitment), blobToHex(pending.output_2.commitment)])) {
      case (#err(message)) return mutation(message, pending.verifier_outcome);
      case (#ok(local)) {
        if (local.root != blobToHex(pending.root_after)) {
          // Raise the NON-BLOCKING divergence signal, then return unchanged (still leaves the
          // intent PENDING; no sticky-guard trip, so the resume can still converge).
          finalize_frontier_mismatch_count += 1;
          finalize_frontier_mismatch_last := ?intentId;
          return mutation("REJECT:finalize-frontier-mismatch", pending.verifier_outcome);
        };
      };
    };

    // The PREPARE output. It is normally already here — drivePendingUnshield prepares before the
    // reconcile — and rebuilt on the defensive path where it is not, which is a pool that upgraded
    // holding this intent. A rebuild that fails here is no worse than the behaviour this fix
    // replaces; a rebuild that succeeds means the commit below cannot fail.
    let prepared = switch (preparedFor(intentId)) {
      case (?record) record;
      case null {
        switch (prepareUnshieldCommit(pending)) {
          case (#err(message)) return mutation("REJECT:unshield-prepare:" # message, pending.verifier_outcome);
          case (#ok(_)) {};
        };
        switch (preparedFor(intentId)) {
          case (?record) record;
          case null return mutation("REJECT:unshield-prepare-missing", pending.verifier_outcome);
        };
      };
    };

    // No await after this point, and now nothing fallible either: the encodings are already built,
    // the four sets and both note-log regions have guaranteed headroom, and the duplicate and
    // pool-debit checks were re-run before any money moved. The nullifiers, two change records, tree
    // root, physical pool balance, and completion marker commit together.
    addNullifier(pending.nullifier_1);
    addNullifier(pending.nullifier_2);
    tree_state := ?pending.next_tree;
    note_root := pending.root_after;
    addRoot(pending.root_after);
    commitNoteBytes(prepared.encoded_1, prepared.position_1, prepared.hash_1, pending.output_1.note_ciphertext);
    commitNoteBytes(prepared.encoded_2, prepared.position_1 + 1, prepared.hash_2, pending.output_2.note_ciphertext);
    pool_value -= pending.pool_debit;
    // The prepaid fee reserved at acceptance is earned now, atomically with the payout commit.
    if (pending_unshield_prepaid_debit > 0) {
      prepaid_fee_revenue += pending_unshield_prepaid_debit;
      pending_unshield_prepaid_debit := 0;
    };
    epoch += 1;
    switch (StableBlobSet.put(completed_unshield_intents, intentId)) {
      case (#ok(true)) {
        unshields_put_counter += 1;
        unshields_fold_digest := xorFold(unshields_fold_digest, intentId);
      };
      case (#ok(false)) Runtime.trap("stable-state:completed-unshield-duplicate");
      case (#err(message)) Runtime.trap(message);
    };
    pending_unshield := null;
    pending_unshield_prepared := null;
    refreshCertification();
    mutation("ACCEPT", pending.verifier_outcome)
  };

  func reconcileUnshieldBlock(pending : PendingUnshield) : async ReconcileResult {
    await reconcileTokenBlock(
      pending.ledger_tip_before,
      func(block : ICRC3.Value) : Bool {
        ICRC1Block.matchesTransfer(block, pending.transfer_args, selfPrincipal())
      },
    )
  };

  func drivePendingUnshield(intentId : Blob, trapAfterToken : Bool, reconcileFirst : Bool) : async MutationResult {
    let pending = switch (pendingUnshieldById(intentId)) {
      case (?value) value;
      case null return mutation("REJECT:pending-unshield-changed", "NOT_CALLED");
    };
    // PREPARE. Before the reconcile, not merely before the payout: finalizeUnshield is reachable
    // from the #found branch below with no payout in this message at all, and on the resume path
    // that is the common case. A failure here is a clean reject and nothing has happened.
    switch (prepareUnshieldCommit(pending)) {
      case (#err(message)) return mutation("REJECT:unshield-prepare:" # message, pending.verifier_outcome);
      case (#ok(_)) {};
    };

    if (reconcileFirst) {
      switch (await reconcileUnshieldBlock(pending)) {
        case (#found(_)) {
          switch (pendingUnshieldById(intentId)) {
            case (?current) {
              if (epoch != current.base_epoch or note_root != current.anchor_before) {
                return mutation("REJECT:pending-unshield-epoch", current.verifier_outcome);
              };
              return finalizeUnshield(intentId);
            };
            case null {
              if (StableBlobSet.contains(completed_unshield_intents, intentId)) {
                return mutation("ACCEPT:already-finalized", "ACCEPT");
              };
              return mutation("REJECT:pending-unshield-changed", pending.verifier_outcome);
            };
          };
        };
        case (#error(message)) return mutation("PENDING:unshield-reconcile-scan:" # message, pending.verifier_outcome);
        case (#absent) {};
      };
    };

    let response = try {
      await tokenActor().icrc1_transfer(pending.transfer_args)
    } catch (error) {
      return mutation("PENDING:unshield-token-call:" # Error.message(error), "CALL_FAILED");
    };
    let blockIndex = switch (response) {
      case (#Ok(index)) index;
      case (#Err(#Duplicate({ duplicate_of }))) duplicate_of;
      case (#Err(error)) {
        if (directDeterministicNoEffectError(error) and pendingUnshieldById(intentId) != null) {
          // The only path that cancels an unshield intent: refund its prepaid-fee reservation.
          if (pending_unshield_prepaid_debit > 0) {
            creditPrepaid(pending.caller, pending_unshield_prepaid_debit);
            pending_unshield_prepaid_debit := 0;
          };
          pending_unshield := null;
          pending_unshield_prepared := null;
          return mutation("REJECT:unshield-token:" # directTokenErrorName(error), pending.verifier_outcome);
        };
        // Effect not inferable: settle against the token log instead of latching forever.
        if (directRequiresLogSettlement(error) and pendingUnshieldById(intentId) != null) {
          switch (await reconcileUnshieldBlock(pending)) {
            case (#found(_)) {
              switch (pendingUnshieldById(intentId)) {
                case (?current) {
                  if (epoch != current.base_epoch or note_root != current.anchor_before) {
                    return mutation("REJECT:pending-unshield-epoch", current.verifier_outcome);
                  };
                  return finalizeUnshield(intentId);
                };
                case null {
                  if (StableBlobSet.contains(completed_unshield_intents, intentId)) {
                    return mutation("ACCEPT:already-finalized", "ACCEPT");
                  };
                  return mutation("REJECT:pending-unshield-changed", pending.verifier_outcome);
                };
              };
            };
            case (#error(msg)) return mutation("PENDING:unshield-reconcile-scan:" # msg, pending.verifier_outcome);
            case (#absent) {
              if (pendingUnshieldById(intentId) == null) {
                return mutation("REJECT:pending-unshield-changed", pending.verifier_outcome);
              };
              // Same refund obligation as the deterministic-no-effect cancel above.
              if (pending_unshield_prepaid_debit > 0) {
                creditPrepaid(pending.caller, pending_unshield_prepaid_debit);
                pending_unshield_prepaid_debit := 0;
              };
              pending_unshield := null;
              pending_unshield_prepared := null;
              return mutation("REJECT:unshield-token:" # directTokenErrorName(error), pending.verifier_outcome);
            };
          };
        };
        return mutation("PENDING:unshield-token:" # directTokenErrorName(error), pending.verifier_outcome);
      };
    };

    if (trapAfterToken) Runtime.trap("TEST_ONLY:fail-after-token-before-unshield-finalize");
    let observed = switch (await fetchTokenBlock(blockIndex)) {
      case (#found(value)) value;
      case (#absent) return mutation("PENDING:unshield-token-block-absent", pending.verifier_outcome);
      case (#error(message)) return mutation("PENDING:unshield-token-block-call:" # message, pending.verifier_outcome);
    };
    let current = switch (pendingUnshieldById(intentId)) {
      case (?value) value;
      case null {
        if (StableBlobSet.contains(completed_unshield_intents, intentId)) {
          return mutation("ACCEPT:already-finalized", "ACCEPT");
        };
        return mutation("REJECT:pending-unshield-changed", pending.verifier_outcome);
      };
    };
    if (epoch != current.base_epoch or
        not ICRC1Block.matchesTransfer(observed, current.transfer_args, selfPrincipal())) {
      return mutation("PENDING:unshield-token-block-mismatch", current.verifier_outcome);
    };
    finalizeUnshield(intentId)
  };

  public shared ({ caller }) func resume_unshield() : async MutationResult {
    switch (guardRejection()) { case (?message) return mutation(message, "NOT_CALLED"); case null {} };
    let pending = switch (pending_unshield) {
      case (?value) value;
      case null return mutation("REJECT:no-pending-unshield", "NOT_CALLED");
    };
    if (not Principal.equal(caller, pending.caller) and not isAdministrator(caller)) {
      return mutation("REJECT:not-pending-owner", "NOT_CALLED");
    };
    // A TIME bound, not only a count bound. attemptLimitReached gives up after
    // INTENT_ATTEMPT_LIMIT *attempts*, so a pending nobody retries is never given up on and sits
    // forever, blocking new intents. The timestamp needed for an expiry is already on the pending —
    // transfer_args.created_at_time, which reconciliation at :931 already requires non-null — so no
    // new stable field and no migration is involved.
    switch (pending.transfer_args.created_at_time) {
      case (?created) {
        if (not isAdministrator(caller) and nowNat64() > created + INTENT_TIMEOUT_NS) {
          return mutation("PENDING:unshield-expired", pending.verifier_outcome);
        };
      };
      case null {};
    };
    if (attemptLimitReached(pending.attempts, caller)) {
      return mutation("PENDING:unshield-attempt-limit", pending.verifier_outcome);
    };
    pending_unshield := ?{ pending with attempts = pending.attempts + 1 };
    // Same admin-gated fault hook the non-recovery entries consume. The recovery paths used to
    // hard-code false, which meant the code that exists specifically to survive a crash was the
    // only code that could not be crash-tested.
    let trapAfterToken = test_fail_after_token_once;
    test_fail_after_token_once := false;
    await drivePendingUnshield(pending.intent_id, trapAfterToken, true)
  };

  // ==================== prepaid fee balance ====================
  // Deposit transparent tokens once (public ICRC-2 pull into the dedicated fee subaccount),
  // debit internally per accepted shielded transfer (no token call, no public block — no
  // per-transfer fee trail), withdraw the remainder any time. See the type-level and
  // state-level comments for the custody identities and the flag-off guarantee.

  // Domain-separated fee custody subaccount: pool custody is NEVER commingled with fee custody.
  let prepaid_fee_subaccount : Blob = Sha256.fromBlob(#sha256, Text.encodeUtf8("zk-ledger/prepaid-fee-account/v1"));

  func prepaidFeeAccount() : ICRC2.Account {
    { owner = selfPrincipal(); subaccount = ?prepaid_fee_subaccount }
  };

  func prepaidFeeBalance(holder : Principal) : Nat {
    switch (Map.get(prepaid_fee_balances, Principal.compare, holder)) {
      case (?value) value;
      case null 0;
    }
  };

  func setPrepaidFeeBalance(holder : Principal, value : Nat) {
    if (value == 0) {
      ignore Map.delete(prepaid_fee_balances, Principal.compare, holder);
    } else {
      Map.add(prepaid_fee_balances, Principal.compare, holder, value);
    }
  };

  func creditPrepaid(holder : Principal, amount : Nat) {
    setPrepaidFeeBalance(holder, prepaidFeeBalance(holder) + amount);
    prepaid_fee_total += amount;
  };

  /// Debit `amount` from `holder`'s prepaid balance; false (and NO state change) if the
  /// balance is insufficient.
  func debitPrepaid(holder : Principal, amount : Nat) : Bool {
    let balance = prepaidFeeBalance(holder);
    if (balance < amount) return false;
    setPrepaidFeeBalance(holder, balance - amount);
    prepaid_fee_total -= amount;
    true
  };

  /// The rate a transfer accepted NOW must pay. 0 while the mechanism is disabled — the
  /// single expression that makes flag-off carry zero prepaid logic on the money path.
  func activePrepaidRate() : Nat { if (prepaid_fee_enabled) prepaid_fee_rate else 0 };

  func prepaidCompleted(intentId : Blob) : Bool {
    Map.get(completed_prepaid_intents, Blob.compare, intentId) != null
  };

  func pendingPrepaidById(intentId : Blob) : ?PendingPrepaid {
    switch (pending_prepaid) {
      case (?pending) { if (Blob.equal(pending.intent_id, intentId)) ?pending else null };
      case null null;
    }
  };

  func prepaidDepositIntentId(caller : Principal, args : PrepaidDepositArgs) : Blob {
    let entries = List.empty<(Text, ICRC3.Value)>();
    List.add(entries, ("domain", #Text("zk-ledger/prepaid-fee-deposit/v1")));
    List.add(entries, ("caller", #Blob(Principal.toBlob(caller))));
    switch (args.from_subaccount) {
      case (?value) List.add(entries, ("from_subaccount", #Blob(value)));
      case null {};
    };
    List.add(entries, ("created_at_time", #Nat(Nat64.toNat(args.created_at_time))));
    List.add(entries, ("client_nonce", #Blob(args.client_nonce)));
    List.add(entries, ("value", #Nat(Nat64.toNat(args.value))));
    switch (token_ledger_id) {
      case (?id) List.add(entries, ("token_ledger", #Blob(Principal.toBlob(id))));
      case null {};
    };
    List.add(entries, ("fee_owner", #Blob(Principal.toBlob(selfPrincipal()))));
    List.add(entries, ("fee_subaccount", #Blob(prepaid_fee_subaccount)));
    ICRC3.hashValue(#Map(List.toArray(entries)))
  };

  func prepaidWithdrawIntentId(
    caller : Principal,
    source : { #balance; #revenue },
    to : ICRC2.Account,
    amount : Nat64,
    createdAt : Nat64,
  ) : Blob {
    let entries = List.empty<(Text, ICRC3.Value)>();
    List.add(entries, ("domain", #Text("zk-ledger/prepaid-fee-withdraw/v1")));
    List.add(entries, ("caller", #Blob(Principal.toBlob(caller))));
    List.add(entries, ("source", #Text(switch (source) { case (#balance) "balance"; case (#revenue) "revenue" })));
    List.add(entries, ("to_owner", #Blob(Principal.toBlob(to.owner))));
    switch (to.subaccount) {
      case (?value) List.add(entries, ("to_subaccount", #Blob(value)));
      case null {};
    };
    List.add(entries, ("amount", #Nat(Nat64.toNat(amount))));
    List.add(entries, ("created_at_time", #Nat(Nat64.toNat(createdAt))));
    switch (token_ledger_id) {
      case (?id) List.add(entries, ("token_ledger", #Blob(Principal.toBlob(id))));
      case null {};
    };
    ICRC3.hashValue(#Map(List.toArray(entries)))
  };

  func prepaidFeeStatusValue() : PrepaidFeeStatus {
    {
      enabled = prepaid_fee_enabled;
      rate = prepaid_fee_rate;
      total_prepaid = prepaid_fee_total;
      revenue = prepaid_fee_revenue;
      fee_account = prepaidFeeAccount();
      holders = Map.size(prepaid_fee_balances);
      pending = pending_prepaid;
      completed_intents = Map.size(completed_prepaid_intents);
    }
  };

  public query func prepaid_fee_status() : async PrepaidFeeStatus { prepaidFeeStatusValue() };

  /// The caller's own prepaid balance. Deliberately caller-scoped: a public per-account
  /// balance query would broadcast debit timing (one decrement per accepted transfer).
  public query ({ caller }) func prepaid_fee_balance() : async Nat { prepaidFeeBalance(caller) };

  /// THE single mechanism flag (default OFF). Withdrawals stay available when disabled, so
  /// turning the mechanism off can never strand deposited balances.
  public shared ({ caller }) func set_prepaid_fee(enabled : Bool) : async Result<PrepaidFeeStatus> {
    switch (guardRejection()) { case (?message) return #err(message); case null {} };
    if (not isAdministrator(caller)) return #err("REJECT:not-administrator");
    prepaid_fee_enabled := enabled;
    #ok(prepaidFeeStatusValue())
  };

  public shared ({ caller }) func set_prepaid_fee_rate(rate : Nat64) : async Result<PrepaidFeeStatus> {
    switch (guardRejection()) { case (?message) return #err(message); case null {} };
    if (not isAdministrator(caller)) return #err("REJECT:not-administrator");
    prepaid_fee_rate := Nat64.toNat(rate);
    #ok(prepaidFeeStatusValue())
  };

  func reconcilePrepaidBlock(pending : PendingPrepaid) : async ReconcileResult {
    await reconcileTokenBlock(
      pending.ledger_tip_before,
      func(block : ICRC3.Value) : Bool {
        switch (pending.op) {
          case (#deposit(op)) ICRC2Block.matchesTransferFrom(block, op.transfer_args, selfPrincipal());
          case (#withdraw(op)) ICRC1Block.matchesTransfer(block, op.transfer_args, selfPrincipal());
        }
      },
    )
  };

  /// The endpoint answer for a prepaid op: the caller's balance after a deposit or a
  /// balance-sourced withdrawal; the remaining revenue after an admin collect.
  func prepaidAnswer(pending : PendingPrepaid) : Nat {
    switch (pending.op) {
      case (#deposit(_)) prepaidFeeBalance(pending.caller);
      case (#withdraw(op)) {
        switch (op.source) {
          case (#balance) prepaidFeeBalance(pending.caller);
          case (#revenue) prepaid_fee_revenue;
        }
      };
    }
  };

  /// Return a withdrawal's up-front reservation to its source. Deposit intents reserve
  /// nothing (the credit only happens at finalize).
  func refundPrepaidReservation(pending : PendingPrepaid) {
    switch (pending.op) {
      case (#deposit(_)) {};
      case (#withdraw(op)) {
        switch (op.source) {
          case (#balance) creditPrepaid(pending.caller, op.reserved);
          case (#revenue) prepaid_fee_revenue += op.reserved;
        }
      };
    }
  };

  /// Finalize a prepaid op whose token block has been observed. No awaits: the credit /
  /// completion marker / pending clear commit together or the callback rolls back to the
  /// recoverable pending intent.
  func finalizePrepaid(pending : PendingPrepaid) : Result<Nat> {
    switch (pending.op) {
      case (#deposit(op)) creditPrepaid(pending.caller, Nat64.toNat(op.value));
      case (#withdraw(_)) {}; // the reservation was debited when the intent was created
    };
    Map.add(completed_prepaid_intents, Blob.compare, pending.intent_id, ());
    pending_prepaid := null;
    #ok(prepaidAnswer(pending))
  };

  func drivePendingPrepaid(intentId : Blob, trapAfterToken : Bool, reconcileFirst : Bool) : async Result<Nat> {
    let pending = switch (pendingPrepaidById(intentId)) {
      case (?value) value;
      case null return #err("REJECT:pending-prepaid-changed");
    };
    if (reconcileFirst) {
      switch (await reconcilePrepaidBlock(pending)) {
        case (#found(_)) {
          switch (pendingPrepaidById(intentId)) {
            case (?current) return finalizePrepaid(current);
            case null {
              if (prepaidCompleted(intentId)) return #ok(prepaidAnswer(pending));
              return #err("REJECT:pending-prepaid-changed");
            };
          };
        };
        case (#error(message)) return #err("PENDING:prepaid-reconcile-scan:" # message);
        case (#absent) {}; // token movement never landed — safe to (re)send below
      };
    };
    let current = switch (pendingPrepaidById(intentId)) {
      case (?value) value;
      case null {
        if (prepaidCompleted(intentId)) return #ok(prepaidAnswer(pending));
        return #err("REJECT:pending-prepaid-changed");
      };
    };

    let blockIndex = switch (current.op) {
      case (#deposit(op)) {
        let response = try {
          await tokenActor().icrc2_transfer_from(op.transfer_args)
        } catch (error) {
          return #err("PENDING:prepaid-token-call:" # Error.message(error));
        };
        switch (response) {
          case (#Ok(index)) index;
          case (#Err(#Duplicate({ duplicate_of }))) duplicate_of;
          case (#Err(error)) {
            if (deterministicNoEffectError(error) and pendingPrepaidById(intentId) != null) {
              pending_prepaid := null;
              return #err("REJECT:prepaid-token:" # tokenErrorName(error));
            };
            // Effect not inferable: settle against the token log rather than latching.
            if (requiresLogSettlement(error) and pendingPrepaidById(intentId) != null) {
              switch (await reconcilePrepaidBlock(current)) {
                case (#found(_)) {
                  switch (pendingPrepaidById(intentId)) {
                    case (?settled) return finalizePrepaid(settled);
                    case null {
                      if (prepaidCompleted(intentId)) return #ok(prepaidAnswer(current));
                      return #err("REJECT:pending-prepaid-changed");
                    };
                  };
                };
                case (#error(message)) return #err("PENDING:prepaid-reconcile-scan:" # message);
                case (#absent) {
                  if (pendingPrepaidById(intentId) == null) {
                    return #err("REJECT:pending-prepaid-changed");
                  };
                  pending_prepaid := null;
                  return #err("REJECT:prepaid-token:" # tokenErrorName(error));
                };
              };
            };
            return #err("PENDING:prepaid-token:" # tokenErrorName(error));
          };
        }
      };
      case (#withdraw(op)) {
        let response = try {
          await tokenActor().icrc1_transfer(op.transfer_args)
        } catch (error) {
          return #err("PENDING:prepaid-token-call:" # Error.message(error));
        };
        switch (response) {
          case (#Ok(index)) index;
          case (#Err(#Duplicate({ duplicate_of }))) duplicate_of;
          case (#Err(error)) {
            if (directDeterministicNoEffectError(error) and pendingPrepaidById(intentId) != null) {
              refundPrepaidReservation(current);
              pending_prepaid := null;
              return #err("REJECT:prepaid-token:" # directTokenErrorName(error));
            };
            // Effect not inferable: settle against the token log rather than latching.
            if (directRequiresLogSettlement(error) and pendingPrepaidById(intentId) != null) {
              switch (await reconcilePrepaidBlock(current)) {
                case (#found(_)) {
                  switch (pendingPrepaidById(intentId)) {
                    case (?settled) return finalizePrepaid(settled);
                    case null {
                      if (prepaidCompleted(intentId)) return #ok(prepaidAnswer(current));
                      return #err("REJECT:pending-prepaid-changed");
                    };
                  };
                };
                case (#error(message)) return #err("PENDING:prepaid-reconcile-scan:" # message);
                case (#absent) {
                  if (pendingPrepaidById(intentId) == null) {
                    return #err("REJECT:pending-prepaid-changed");
                  };
                  refundPrepaidReservation(current);
                  pending_prepaid := null;
                  return #err("REJECT:prepaid-token:" # directTokenErrorName(error));
                };
              };
            };
            return #err("PENDING:prepaid-token:" # directTokenErrorName(error));
          };
        }
      };
    };

    if (trapAfterToken) Runtime.trap("TEST_ONLY:fail-after-token-before-prepaid-finalize");
    let observed = switch (await fetchTokenBlock(blockIndex)) {
      case (#found(value)) value;
      case (#absent) return #err("PENDING:prepaid-token-block-absent");
      case (#error(message)) return #err("PENDING:prepaid-token-block-call:" # message);
    };
    let final = switch (pendingPrepaidById(intentId)) {
      case (?value) value;
      case null {
        if (prepaidCompleted(intentId)) return #ok(prepaidAnswer(pending));
        return #err("REJECT:pending-prepaid-changed");
      };
    };
    let matches = switch (final.op) {
      case (#deposit(op)) ICRC2Block.matchesTransferFrom(observed, op.transfer_args, selfPrincipal());
      case (#withdraw(op)) ICRC1Block.matchesTransfer(observed, op.transfer_args, selfPrincipal());
    };
    if (not matches) return #err("PENDING:prepaid-token-block-mismatch");
    finalizePrepaid(final)
  };

  /// Move transparent tokens into the caller's prepaid fee balance over the verified ICRC-2
  /// rail: allowance pull with memo = intent id, exact-block observation, completed-intent
  /// replay answers, and a stable pending intent recoverable past the dedup window.
  public shared ({ caller }) func prepaid_fee_deposit(args : PrepaidDepositArgs) : async Result<Nat> {
    switch (guardRejection()) { case (?message) return #err(message); case null {} };
    if (not prepaid_fee_enabled) return #err("REJECT:prepaid-fee-disabled");
    if (not tokenConfigured()) return #err("REJECT:token-unconfigured");
    if (pending_prepaid != null) return #err("REJECT:pending-prepaid-mutation");
    if (args.value == 0) return #err("REJECT:prepaid-zero-value");
    if (args.client_nonce.size() != 32) return #err("REJECT:client-nonce-length");
    switch (args.from_subaccount) {
      case (?value) { if (value.size() != 32) return #err("REJECT:from-subaccount-length") };
      case null {};
    };
    let intentId = prepaidDepositIntentId(caller, args);
    if (prepaidCompleted(intentId)) return #ok(prepaidFeeBalance(caller));
    let transferArgs : ICRC2.TransferFromArgs = {
      spender_subaccount = null;
      from = { owner = caller; subaccount = args.from_subaccount };
      to = prepaidFeeAccount();
      amount = Nat64.toNat(args.value);
      fee = ?transparent_ledger_fee;
      memo = ?intentId;
      created_at_time = ?args.created_at_time;
    };
    // Reconcile low-water BEFORE the transfer, exactly as the shield leg records it.
    let ledgerTip = try {
      (await historyActor().icrc3_get_blocks([{ start = 0; length = 0 }])).log_length
    } catch (error) {
      return #err("REJECT:prepaid-ledger-tip-call:" # Error.message(error));
    };
    if (pending_prepaid != null) return #err("REJECT:pending-prepaid-mutation");
    if (not prepaid_fee_enabled) return #err("REJECT:prepaid-fee-disabled");
    if (prepaidCompleted(intentId)) return #ok(prepaidFeeBalance(caller));
    pending_prepaid := ?{
      intent_id = intentId;
      caller;
      op = #deposit({ value = args.value; transfer_args = transferArgs });
      ledger_tip_before = ledgerTip;
      attempts = 1;
    };
    let trapAfterToken = test_fail_after_token_once;
    test_fail_after_token_once := false;
    await drivePendingPrepaid(intentId, trapAfterToken, false)
  };

  /// Withdraw part of the caller's prepaid balance back to their default token account.
  /// `amount + transparent_ledger_fee` is reserved (debited) up front; a deterministic token
  /// failure refunds it. Available regardless of the enable flag — disabling the mechanism
  /// must never strand deposited balances.
  public shared ({ caller }) func prepaid_fee_withdraw(amount : Nat64, createdAt : Nat64) : async Result<Nat> {
    switch (guardRejection()) { case (?message) return #err(message); case null {} };
    if (not tokenConfigured()) return #err("REJECT:token-unconfigured");
    if (pending_prepaid != null) return #err("REJECT:pending-prepaid-mutation");
    if (amount == 0) return #err("REJECT:prepaid-zero-value");
    await prepaidPayout(caller, #balance, { owner = caller; subaccount = null }, amount, createdAt)
  };

  /// Pay collected fee revenue out to an account chosen by the operator. Administrator only; the
  /// same payout rail as user withdrawals, so revenue is never trapped either.
  public shared ({ caller }) func prepaid_fee_collect(amount : Nat64, to : ICRC2.Account, createdAt : Nat64) : async Result<Nat> {
    switch (guardRejection()) { case (?message) return #err(message); case null {} };
    if (not isAdministrator(caller)) return #err("REJECT:not-administrator");
    if (not tokenConfigured()) return #err("REJECT:token-unconfigured");
    if (pending_prepaid != null) return #err("REJECT:pending-prepaid-mutation");
    if (amount == 0) return #err("REJECT:prepaid-zero-value");
    switch (to.subaccount) {
      case (?value) { if (value.size() != 32) return #err("REJECT:recipient-subaccount-length") };
      case null {};
    };
    await prepaidPayout(caller, #revenue, to, amount, createdAt)
  };

  func prepaidPayout(
    caller : Principal,
    source : { #balance; #revenue },
    to : ICRC2.Account,
    amount : Nat64,
    createdAt : Nat64,
  ) : async Result<Nat> {
    let reserved = Nat64.toNat(amount) + transparent_ledger_fee;
    let intentId = prepaidWithdrawIntentId(caller, source, to, amount, createdAt);
    let answer = func() : Nat {
      switch (source) { case (#balance) prepaidFeeBalance(caller); case (#revenue) prepaid_fee_revenue }
    };
    if (prepaidCompleted(intentId)) return #ok(answer());
    let transferArgs : ICRC2.TransferArg = {
      from_subaccount = ?prepaid_fee_subaccount;
      to;
      amount = Nat64.toNat(amount);
      fee = ?transparent_ledger_fee;
      memo = ?intentId;
      created_at_time = ?createdAt;
    };
    let ledgerTip = try {
      (await historyActor().icrc3_get_blocks([{ start = 0; length = 0 }])).log_length
    } catch (error) {
      return #err("REJECT:prepaid-ledger-tip-call:" # Error.message(error));
    };
    if (pending_prepaid != null) return #err("REJECT:pending-prepaid-mutation");
    if (prepaidCompleted(intentId)) return #ok(answer());
    // Reservation: debit BEFORE the token call — no await between here and the pending
    // record, so a concurrent debit can never leave an in-flight payout unfunded.
    switch (source) {
      case (#balance) {
        if (not debitPrepaid(caller, reserved)) return #err("REJECT:prepaid-fee-insufficient");
      };
      case (#revenue) {
        if (prepaid_fee_revenue < reserved) return #err("REJECT:prepaid-fee-insufficient");
        prepaid_fee_revenue -= reserved;
      };
    };
    pending_prepaid := ?{
      intent_id = intentId;
      caller;
      op = #withdraw({ reserved; source; transfer_args = transferArgs });
      ledger_tip_before = ledgerTip;
      attempts = 1;
    };
    let trapAfterToken = test_fail_after_token_once;
    test_fail_after_token_once := false;
    await drivePendingPrepaid(intentId, trapAfterToken, false)
  };

  public shared ({ caller }) func resume_prepaid() : async Result<Nat> {
    switch (guardRejection()) { case (?message) return #err(message); case null {} };
    let pending = switch (pending_prepaid) {
      case (?value) value;
      case null return #err("REJECT:no-pending-prepaid");
    };
    if (not Principal.equal(caller, pending.caller) and not isAdministrator(caller)) {
      return #err("REJECT:not-pending-owner");
    };
    if (attemptLimitReached(pending.attempts, caller)) {
      return #err("PENDING:prepaid-attempt-limit");
    };
    pending_prepaid := ?{ pending with attempts = pending.attempts + 1 };
    // Same admin-gated fault hook the non-recovery entries consume. The recovery paths used to
    // hard-code false, which meant the code that exists specifically to survive a crash was the
    // only code that could not be crash-tested.
    let trapAfterToken = test_fail_after_token_once;
    test_fail_after_token_once := false;
    await drivePendingPrepaid(pending.intent_id, trapAfterToken, true)
  };

  public shared ({ caller }) func confidential_transfer(args : TransferArgs) : async MutationResult {
    // Seed the publish salt on an update path — queries cannot seed one, so it has to happen
    // here. REG-4: this comment used to end "an unseeded salt makes publishedIntentId fall through
    // to the raw handle, leaving the oracle open". That stopped being true at a3b82b3, which made
    // publishedIntentId fail CLOSED — an unseeded salt now returns "" and WITHHOLDS the handle.
    // The seeding therefore buys the OBSERVABLE, not the safety: without it a published handle is
    // empty and the operator loses the correlation, but nothing raw is ever disclosed. Corrected
    // because the stale wording is not inert — it was read as current behaviour during review and
    // produced the confident, wrong conclusion that salting a query path is a no-op.
    await seedIntentPublishSalt();
    switch (guardRejection()) { case (?message) return mutation(message, "NOT_CALLED"); case null {} };
    if (not configured()) return mutation("REJECT:unconfigured", "NOT_CALLED");
    // Same fail-closed gate as shield: no in-canister frontier, no value path.
    // Refuse NEW intents while quarantined. Finalize paths are deliberately
    // untouched: an existing pending must still be able to complete, or quarantine would strand
    // the very intents it exists to protect — a funds-availability failure.
    if (state_quarantine) return mutation("REJECT:state-quarantined", "NOT_CALLED");
    if (not tree_frontier_enabled) return mutation("REJECT:frontier-disabled", "NOT_CALLED");
    if (transfer_statement_version != 2) {
      return mutation("REJECT:transfer-statement-version", "NOT_CALLED");
    };
    if (pending_shield != null or pending_unshield != null) {
      return mutation("REJECT:pending-token-mutation", "NOT_CALLED");
    };
    if (not fieldSized(args.anchor) or not fieldSized(args.nullifier_1) or not fieldSized(args.nullifier_2)) {
      return mutation("REJECT:field-length", "NOT_CALLED");
    };
    switch (validateOutput(args.output_1)) { case (?e) return mutation(e, "NOT_CALLED"); case null {} };
    switch (validateOutput(args.output_2)) { case (?e) return mutation(e, "NOT_CALLED"); case null {} };

    let isUnshield = args.v_pub_out > 0;
    let recipientBinding : Blob = if (isUnshield) {
      if (not tokenConfigured()) return mutation("REJECT:token-unconfigured", "NOT_CALLED");
      if (Nat64.toNat(args.fee) < transparent_ledger_fee) {
        return mutation("REJECT:unshield-fee-below-token-fee", "NOT_CALLED");
      };
      if (args.created_at_time == null) {
        return mutation("REJECT:unshield-created-at-time", "NOT_CALLED");
      };
      let recipient = switch (args.recipient) {
        case (?value) value;
        case null return mutation("REJECT:unshield-recipient-missing", "NOT_CALLED");
      };
      if (not Principal.equal(recipient.owner, caller)) {
        return mutation("REJECT:unshield-recipient-not-caller", "NOT_CALLED");
      };
      switch (recipientBindingValue(recipient)) {
        case (#ok(value)) value;
        case (#err(message)) return mutation(message, "NOT_CALLED");
      }
    } else {
      if (args.recipient != null or args.created_at_time != null) {
        return mutation("REJECT:private-transfer-public-recipient", "NOT_CALLED");
      };
      zeroField()
    };

    let intentId = if (isUnshield) ?unshieldIntentId(caller, args, recipientBinding) else null;
    switch (intentId) {
      case (?value) {
        if (StableBlobSet.contains(completed_unshield_intents, value)) {
          return mutation("ACCEPT:already-finalized", "ACCEPT");
        };
      };
      case null {};
    };

    // Cheap state-machine guards precede the pairing call. All are repeated after every await.
    if (not StableBlobSet.contains(historical_roots, args.anchor)) {
      return mutation("REJECT:unknown-anchor", "NOT_CALLED");
    };
    if (args.nullifier_1 == args.nullifier_2) {
      return mutation("REJECT:duplicate-nullifier-in-tx", "NOT_CALLED");
    };
    if (StableBlobSet.contains(spent_nullifiers, args.nullifier_1) or
        StableBlobSet.contains(spent_nullifiers, args.nullifier_2)) {
      return mutation("REJECT:nullifier-spent", "NOT_CALLED");
    };
    let poolDebit = if (isUnshield) Nat64.toNat(args.v_pub_out) + transparent_ledger_fee else 0;
    if (poolDebit > pool_value) {
      return mutation("REJECT:turnstile", "NOT_CALLED");
    };
    // Prepaid fee: the rate this transfer must pay, captured ONCE so a mid-flight admin
    // rate change cannot split the check from the debit. 0 whenever the flag is off — the
    // path below is then byte-equivalent to the pre-fee ledger. Cheap pre-verify guard;
    // re-checked at the atomic commit point of each variant.
    let prepaidRate = activePrepaidRate();
    if (prepaidRate > 0 and prepaidFeeBalance(caller) < prepaidRate) {
      return mutation("REJECT:prepaid-fee-insufficient", "NOT_CALLED");
    };

    let inputs = switch (serializePublicInputs([
      args.anchor,
      args.nullifier_1,
      args.nullifier_2,
      args.output_1.commitment,
      args.output_2.commitment,
      nat64Field(args.fee),
      nat64Field(args.v_pub_out),
      recipientBinding,
    ])) {
      case (?encoded) encoded;
      case null return mutation("REJECT:public-input-encoding", "NOT_CALLED");
    };
    let startEpoch = epoch;
    // In-process verify: no await before the tree append, so the anchor/nullifier/turnstile
    // guards above are still the live state when the verdict lands. The re-checks below the
    // old verifier await collapse into the post-tree-append re-checks that remain.
    let verdict = verifyTransferProof(args.proof_hex, inputs);
    if (verdict != "ACCEPT") return mutation(verdict, verdict);

    let treeBefore = currentTree();
    let transferLeaves = [
      blobToHex(args.output_1.commitment),
      blobToHex(args.output_2.commitment),
    ];
    for (leaf in transferLeaves.vals()) {
      switch (PoseidonTree.parseFieldElement(leaf)) {
        case (?_) {};
        case null return mutation("REJECT:commitment-noncanonical", "NOT_CALLED");
      };
    };
    // In-canister transition first (flag ON), oracle demoted to cross-check.
    let localNext = switch (frontierLocalNext(treeBefore, transferLeaves)) {
      case (#ok(value)) value;
      case (#err(message)) return mutation(message, verdict);
    };
    let transition = switch (localNext) {
      case (?local) {
        if (tree_oracle_id == null) {
          { state = ?local; error = null } : TreeTransition
        } else {
          try {
            await treeActor().append(treeBefore, transferLeaves)
          } catch (error) {
            return mutation("REJECT:tree-oracle-call:" # Error.message(error), verdict);
          }
        }
      };
      case null {
        try {
          await treeActor().append(treeBefore, transferLeaves)
        } catch (error) {
          return mutation("REJECT:tree-oracle-call:" # Error.message(error), verdict);
        }
      };
    };
    if (pending_shield != null or pending_unshield != null or epoch != startEpoch) {
      return mutation("REJECT:state-changed", verdict);
    };
    if (not StableBlobSet.contains(historical_roots, args.anchor)) return mutation("REJECT:unknown-anchor", verdict);
    if (StableBlobSet.contains(spent_nullifiers, args.nullifier_1) or
        StableBlobSet.contains(spent_nullifiers, args.nullifier_2)) {
      return mutation("REJECT:nullifier-spent", verdict);
    };
    if (poolDebit > pool_value) return mutation("REJECT:turnstile", verdict);
    let next = switch (parseTransition(transition)) {
      case (#ok(state)) state;
      case (#err(message)) return mutation(message, verdict);
    };
    switch (frontierCrossCheck(localNext, next, "transfer")) {
      case (?message) return mutation(message, verdict);
      case null {};
    };
    let rootAfter = switch (hexToBlob(next.root)) {
      case (?root) root;
      case null return mutation("REJECT:tree-root-hex", verdict);
    };

    if (not isUnshield) {
      // No await after this point: a private transfer commits all shielded state together —
      // including the prepaid fee debit, which is re-checked HERE because the balance can
      // have been drained by an interleaved transfer while the tree transition awaited.
      if (prepaidRate > 0) {
        if (not debitPrepaid(caller, prepaidRate)) {
          return mutation("REJECT:prepaid-fee-insufficient", verdict);
        };
        prepaid_fee_revenue += prepaidRate;
      };
      addNullifier(args.nullifier_1);
      addNullifier(args.nullifier_2);
      tree_state := ?next;
      note_root := rootAfter;
      addRoot(rootAfter);
      let nullifiers = [args.nullifier_1, args.nullifier_2];
      appendBlock(args.output_1, nullifiers, args.anchor, rootAfter, #confidential_transfer);
      appendBlock(args.output_2, nullifiers, args.anchor, rootAfter, #confidential_transfer);
      epoch += 1;
      refreshCertification();
      return mutation("ACCEPT", verdict);
    };

    let recipient = switch (args.recipient) { case (?value) value; case null Runtime.trap("validated recipient") };
    let createdAt = switch (args.created_at_time) { case (?value) value; case null Runtime.trap("validated timestamp") };
    let intent = switch (intentId) { case (?value) value; case null Runtime.trap("validated intent") };
    let ledgerTip = try {
      (await historyActor().icrc3_get_blocks([{ start = 0; length = 0 }])).log_length
    } catch (error) {
      return mutation("REJECT:unshield-ledger-tip-call:" # Error.message(error), verdict);
    };
    if (pending_shield != null or pending_unshield != null or epoch != startEpoch) {
      return mutation("REJECT:state-changed", verdict);
    };
    if (StableBlobSet.contains(spent_nullifiers, args.nullifier_1) or
        StableBlobSet.contains(spent_nullifiers, args.nullifier_2) or poolDebit > pool_value) {
      return mutation("REJECT:state-changed", verdict);
    };
    // Unshield prepaid debit: reserved NOW (same message segment as the pending intent —
    // at finalize time the payout has already happened and a failed debit could no longer
    // reject the operation). Held in pending_unshield_prepaid_debit, NOT in revenue:
    // revenue is only earned at finalize, so an admin collect can never race the refund.
    if (prepaidRate > 0) {
      if (not debitPrepaid(caller, prepaidRate)) {
        return mutation("REJECT:prepaid-fee-insufficient", verdict);
      };
      pending_unshield_prepaid_debit := prepaidRate;
    };
    let transferArgs : ICRC2.TransferArg = {
      from_subaccount = pool_subaccount;
      to = recipient;
      amount = Nat64.toNat(args.v_pub_out);
      fee = ?transparent_ledger_fee;
      memo = ?intent;
      created_at_time = ?createdAt;
    };
    pending_unshield := ?{
      intent_id = intent;
      caller;
      output_1 = args.output_1;
      output_2 = args.output_2;
      nullifier_1 = args.nullifier_1;
      nullifier_2 = args.nullifier_2;
      transfer_args = transferArgs;
      recipient_binding = recipientBinding;
      public_value = args.v_pub_out;
      pool_debit = poolDebit;
      anchor_before = args.anchor;
      root_after = rootAfter;
      next_tree = next;
      base_epoch = epoch;
      verifier_outcome = verdict;
      attempts = 1;
      ledger_tip_before = ledgerTip;
    };
    let trapAfterToken = test_fail_after_token_once;
    test_fail_after_token_once := false;
    await drivePendingUnshield(intent, trapAfterToken, false)
  };

  func publicRecordBit(record : [Nat8], bitIndex : Nat) : Bool {
    let byteIndex = bitIndex / 8;
    let bitInByte = BIT_SHIFTS[bitIndex % 8];
    ((Nat8.toNat(record[byteIndex]) / (2 ** bitInByte)) % 2) == 1
  };

  /// Fixed-shape private retrieval of a known note position. The API has no target index.
  /// The LWE query is linear in the note log at ~25.6M instructions per note (225,188,359 at 8
  /// notes, 820,557,992 at 32), so the 5e9 query ceiling is reached at ~195 notes. Independently the
  /// caller must supply one 630-Nat64 selector PER NOTE, which reaches the ~2 MB ingress limit at
  /// ~200. Both walls converge and neither is the caller's to fix.
  ///
  /// Checked BEFORE the selector count so the caller learns the real reason. Without it a large log
  /// yields "selector count must equal the full note log length", and a caller who then complies is
  /// rejected at ingress or burns to the instruction ceiling — three different opaque failures for
  /// one cause. The bound leaves ~4.1e9 of the 5e9 ceiling as margin.
  let PIR_LWE_MAX_NOTES : Nat = 160;

  public query func pir_query_lwe(args : LwePirArgs) : async LwePirResponse {
    let c0 = Prim.performanceCounter(0);
    if (noteCount() > PIR_LWE_MAX_NOTES) {
      Runtime.trap("pir-lwe:note-log-too-large:" # Nat.toText(noteCount()) # ">" # Nat.toText(PIR_LWE_MAX_NOTES));
    };
    if (args.selectors.size() != noteCount()) {
      Runtime.trap("selector count must equal the full note log length");
    };
    var selectorIndex : Nat = 0;
    while (selectorIndex < args.selectors.size()) {
      if (args.selectors[selectorIndex].a.size() != LWE_DIMENSION) {
        Runtime.trap("wrong LWE selector dimension");
      };
      selectorIndex += 1;
    };

    let records = Array.tabulate<[Nat8]>(noteCount(), func(index) {
      Blob.toArray(blockAt(index).commitment)
    });
    let outputs = Array.tabulate<LweCiphertext>(RECORD_BITS, func(bitIndex) {
      let sumA = Prim.Array_init<Nat64>(LWE_DIMENSION, 0);
      var sumB : Nat64 = 0;
      var recordIndex : Nat = 0;
      while (recordIndex < noteCount()) {
        // Branching depends only on the public database bit, never the encrypted selector.
        if (publicRecordBit(records[recordIndex], bitIndex)) {
          let selector = args.selectors[recordIndex];
          var coefficientIndex : Nat = 0;
          while (coefficientIndex < LWE_DIMENSION) {
            sumA[coefficientIndex] +%= selector.a[coefficientIndex];
            coefficientIndex += 1;
          };
          sumB +%= selector.b;
        };
        recordIndex += 1;
      };
      { a = Array.fromVarArray(sumA); b = sumB }
    });
    let c1 = Prim.performanceCounter(0);
    {
      ciphertexts = outputs;
      snapshot_root = note_root;
      trace = {
        records_scanned = noteCount();
        selectors_received = args.selectors.size();
        lwe_dimension = LWE_DIMENSION;
        output_bits = RECORD_BITS;
        selector_decryptions = 0;
        target_index_parameters = 0;
        target_dependent_branches = 0;
        instructions = c1 - c0;
      };
    }
  };
}
