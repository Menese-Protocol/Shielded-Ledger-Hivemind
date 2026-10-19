#!/usr/bin/env python3
"""Configure, check and freeze a freshly installed shielded ledger, and check its directory.

Run once, as the administrator identity, after the controller has installed `zk_ledger`, the tree
oracle, the ICP history adapter and the shielded directory. Every step is read back; the script
prints SETUP COMPLETE only when every launch setting is in force AND the verifying keys on the
ledger are the ceremony keys AND they are frozen. Re-running it on a finished ledger changes
nothing and checks everything again.

Steps:
  1. keyset gate: demo-frontend/scripts/verify-keyset.mjs --require-real-value re-verifies the
     ceremony transcript and the key file hashes (a test keyset is accepted on --network local
     only, with --test-keyset)
  2. configure (verifier = the ledger itself, the tree oracle, the two verifying keys)
  3. token: the NNS ICP ledger, its own history read directly (configure_icp_token_ledger); or,
     with --history, an ICRC-3 token and its history log (configure_token_ledger)
  4. tree: the in-canister Poseidon frontier (on by default) stays on and the tree oracle is
     detached, so the ledger computes every note-tree root itself and trusts no other canister
  5. launch settings: protocol fee (0.1 token per private send, 0.3% of every unshield, no
     recipient), claim envelopes required, note shape (32, 584)
  6. the certified vk anchor must equal sha256("zk-ledger/vk-anchor/v1" ‖ transfer_vk_hex ‖
     deposit_vk_hex) ‖ epoch 1, computed here from the gated key files
  7. freeze_verifying_keys with exactly that anchor, then read the freeze back
  8. directory: vetKD key name, administrator, limits read back

The forged-proof cool-down is left as found and reported; its threshold is set separately.

Usage:
  scripts/mainnet-setup.py --network ic --identity <admin identity> \
      --ledger <id> --tree-oracle <id> --token ryjl3-tyaaa-aaaaa-aaaba-cai --directory <id> \
      --keyset <dir with transfer_vk.hex, deposit_vk.hex, SETUP-MANIFEST.json, transcript>
"""

import argparse
import hashlib
import json
import pathlib
import subprocess
import sys

SEND_FEE = 10_000_000  # 0.1 ICP in e8s
UNSHIELD_BPS = 30
NOTE_SHAPE = (32, 584)
DIRECTORY_KEY_NAME = "key_1"
REPO = pathlib.Path(__file__).resolve().parent.parent


class SetupError(Exception):
    pass


def fail(message):
    raise SetupError(message)


class Dfx:
    def __init__(self, network, identity):
        self.network = network
        self.identity = identity

    def call(self, canister, method, argument="()", query=False):
        command = ["dfx", "canister", "call", "--network", self.network, "--identity", self.identity, "--output", "json"]
        if query:
            command.append("--query")
        command += [canister, method, argument]
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode != 0:
            fail(f"{method}: dfx failed: {result.stderr.strip()[:400]}")
        return json.loads(result.stdout)

    def principal(self):
        result = subprocess.run(
            ["dfx", "identity", "get-principal", "--identity", self.identity], capture_output=True, text=True
        )
        if result.returncode != 0:
            fail(f"identity {self.identity}: {result.stderr.strip()}")
        return result.stdout.strip()


def blob_bytes(value):
    """dfx --output json renders a blob as a list of byte values or as a hex string."""
    if isinstance(value, list):
        return bytes(value)
    if isinstance(value, str):
        return bytes.fromhex(value)
    fail(f"unexpected blob encoding: {value!r}")


def candid_blob(data):
    return 'blob "' + "".join(f"\\{byte:02x}" for byte in data) + '"'


def ok(result, method):
    if isinstance(result, dict) and "ok" in result:
        return result["ok"]
    if isinstance(result, dict) and "err" in result:
        fail(f"{method}: {result['err']}")
    fail(f"{method}: unexpected reply {result!r}")


def opt(value):
    """An opt from dfx json: [] for null, [x] for some."""
    if isinstance(value, list):
        return value[0] if value else None
    return value


def nat(value):
    return int(str(value).replace("_", ""))


def step(text):
    print(f"[setup] {text}", flush=True)


def keyset_gate(keyset, network, test_keyset):
    command = ["node", str(REPO / "demo-frontend/scripts/verify-keyset.mjs"), str(keyset)]
    if test_keyset:
        if network != "local":
            fail("--test-keyset is refused on any network but local")
    else:
        command.append("--require-real-value")
    result = subprocess.run(command, capture_output=True, text=True, cwd=REPO / "demo-frontend")
    sys.stdout.write("".join(f"  | {line}\n" for line in result.stdout.splitlines()))
    if result.returncode != 0:
        fail(f"keyset gate refused the keyset: {result.stderr.strip()[-400:]}")
    transfer = (keyset / "transfer_vk.hex").read_text().strip()
    deposit = (keyset / "deposit_vk.hex").read_text().strip()
    return transfer, deposit


def expected_anchor(transfer_vk_hex, deposit_vk_hex, epoch=1):
    digest = hashlib.sha256(b"zk-ledger/vk-anchor/v1" + transfer_vk_hex.encode() + deposit_vk_hex.encode()).digest()
    return digest + epoch.to_bytes(8, "big")


def anchor_of(reply):
    return blob_bytes(reply["digest"]) + nat(reply["epoch"]).to_bytes(8, "big")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--network", required=True)
    parser.add_argument("--identity", required=True)
    for name in ("ledger", "tree-oracle", "token", "directory"):
        parser.add_argument(f"--{name}", required=True)
    parser.add_argument("--history", default=None, help="ICRC-3 tokens only: the history log; omit for the ICP ledger")
    parser.add_argument("--keyset", required=True, type=pathlib.Path)
    parser.add_argument("--test-keyset", action="store_true", help="local network only: accept a test keyset")
    args = parser.parse_args()
    dfx = Dfx(args.network, args.identity)
    me = dfx.principal()

    step(f"1/8 keyset gate on {args.keyset}")
    transfer_vk, deposit_vk = keyset_gate(args.keyset.resolve(), args.network, args.test_keyset)
    want_anchor = expected_anchor(transfer_vk, deposit_vk)
    step(f"    expected vk anchor {want_anchor.hex()}")

    status = dfx.call(args.ledger, "status", query=True)
    step("2/8 configure")
    if status["configured"]:
        step("    already configured")
    else:
        argument = f'(principal "{args.ledger}", principal "{args.tree_oracle}", "{transfer_vk}", "{deposit_vk}")'
        ok(dfx.call(args.ledger, "configure", argument), "configure")
        status = dfx.call(args.ledger, "status", query=True)
    administrator = opt(status["administrator"])
    if administrator != me:
        fail(f"administrator is {administrator}, not this identity ({me})")
    step(f"    administrator {administrator}")

    step("3/8 token ledger")
    atomicity = dfx.call(args.ledger, "atomicity_status", query=True)
    token = opt(atomicity.get("token_ledger"))
    if token is None:
        if args.history is None:
            ok(dfx.call(args.ledger, "configure_icp_token_ledger", f'(principal "{args.token}", null)'), "configure_icp_token_ledger")
        else:
            ok(dfx.call(args.ledger, "configure_token_ledger", f'(principal "{args.token}", principal "{args.history}", null)'),
               "configure_token_ledger")
        atomicity = dfx.call(args.ledger, "atomicity_status", query=True)
        token = opt(atomicity.get("token_ledger"))
    history = opt(atomicity.get("history_adapter"))
    icp_history = atomicity.get("icp_history") is True
    if token != args.token:
        fail(f"token ledger {token}, wanted {args.token}")
    if args.history is None and not (icp_history and history is None):
        fail(f"the ledger does not read the ICP ledger's own history (icp_history={icp_history}, adapter={history})")
    if args.history is not None and history != args.history:
        fail(f"history adapter {history}, wanted {args.history}")
    step(f"    token {token}, history: {'the ICP ledger itself' if icp_history else history}")

    step("4/8 tree")
    tree = dfx.call(args.ledger, "tree_frontier_status", query=True)
    if tree["enabled"] is not True:
        ok(dfx.call(args.ledger, "set_tree_frontier", "(true)"), "set_tree_frontier")
    if opt(tree["tree_oracle"]) is not None:
        ok(dfx.call(args.ledger, "set_tree_oracle", "(null)"), "set_tree_oracle")
    tree = dfx.call(args.ledger, "tree_frontier_status", query=True)
    if tree["enabled"] is not True or opt(tree["tree_oracle"]) is not None:
        fail(f"tree read back as {tree}")
    step("    in-canister frontier on, tree oracle detached")

    step("5/8 launch settings")
    ok(dfx.call(args.ledger, "set_protocol_fee",
                f"(record {{ send_fee = {SEND_FEE} : nat64; unshield_bps = {UNSHIELD_BPS} : nat; recipient = null }})"),
       "set_protocol_fee")
    ok(dfx.call(args.ledger, "set_claim_envelopes_required", "(true)"), "set_claim_envelopes_required")
    ok(dfx.call(args.ledger, "set_note_shape",
                f"(opt record {{ ephemeral_key_len = {NOTE_SHAPE[0]} : nat; note_ciphertext_len = {NOTE_SHAPE[1]} : nat }})"),
       "set_note_shape")
    fee = dfx.call(args.ledger, "protocol_fee_status", query=True)
    if nat(fee["send_fee"]) != SEND_FEE or nat(fee["unshield_bps"]) != UNSHIELD_BPS or opt(fee["recipient"]) is not None:
        fail(f"protocol fee read back as {fee}")
    claims = dfx.call(args.ledger, "claim_status", query=True)
    if claims["required"] is not True:
        fail(f"claim envelopes read back as {claims}")
    shape = opt(dfx.call(args.ledger, "get_note_shape", query=True))
    if shape is None or (nat(shape["ephemeral_key_len"]), nat(shape["note_ciphertext_len"])) != NOTE_SHAPE:
        fail(f"note shape read back as {shape}")
    step(f"    fee {SEND_FEE} e8s per send + {UNSHIELD_BPS} bps per unshield, no recipient; envelopes required; note shape {NOTE_SHAPE}")

    step("6/8 verifying keys on the ledger")
    anchor = dfx.call(args.ledger, "verifying_key_anchor", query=True)
    if anchor["transfer_vk_hex"] != transfer_vk or anchor["deposit_vk_hex"] != deposit_vk:
        fail("the ledger's verifying keys are not the gated ceremony keys")
    if anchor_of(anchor) != want_anchor:
        fail(f"vk anchor {anchor_of(anchor).hex()} != expected {want_anchor.hex()} (rotated since configure?)")
    step("    keys = ceremony keys, epoch 1")

    step("7/8 freeze")
    if anchor["frozen"]:
        step("    already frozen")
    else:
        frozen_at = blob_bytes(ok(dfx.call(args.ledger, "freeze_verifying_keys", f"({candid_blob(want_anchor)})"),
                                  "freeze_verifying_keys"))
        if frozen_at != want_anchor:
            fail(f"freeze returned {frozen_at.hex()}")
    anchor = dfx.call(args.ledger, "verifying_key_anchor", query=True)
    if anchor["frozen"] is not True or anchor_of(anchor) != want_anchor:
        fail(f"freeze read back as frozen={anchor['frozen']} anchor={anchor_of(anchor).hex()}")
    step("    frozen")

    step("8/8 directory")
    directory = dfx.call(args.directory, "status", query=True)
    if directory["vetkd_key_name"] != DIRECTORY_KEY_NAME:
        fail(f"directory vetKD key {directory['vetkd_key_name']}, wanted {DIRECTORY_KEY_NAME}")
    if directory["administrator"] != me:
        fail(f"directory administrator {directory['administrator']}, not this identity ({me})")
    limits = directory["limits"]
    step(f"    key {DIRECTORY_KEY_NAME}, administrator {me}, limits {json.dumps(limits)}, cycles {directory['cycles']}")

    guard = dfx.call(args.ledger, "forged_proof_guard_status", query=True)
    step(f"forged-proof cool-down left as found: {json.dumps(guard['config'])}")
    print("SETUP COMPLETE: ceremony keys installed and frozen, launch settings in force", flush=True)


if __name__ == "__main__":
    try:
        main()
    except SetupError as error:
        print(f"SETUP FAILED: {error}", file=sys.stderr, flush=True)
        sys.exit(1)
