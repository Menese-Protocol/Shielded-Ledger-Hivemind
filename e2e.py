#!/usr/bin/env python3
"""Bounded end-to-end oracle for the sandbox ZK ledger + private-read layer."""

from __future__ import annotations

import json
import copy
import hashlib
import math
import os
import secrets
import shlex
import shutil
import subprocess
import tempfile
import time
import base64
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
VECTORS = HERE / "fixtures" / "pool-vectors-bls12-381"
DIMENSION = 630
OUTPUT_BITS = 256
MASK64 = (1 << 64) - 1
DELTA = 1 << 63
ROUNDING = 1 << 62
NOISE_SIGMA = 1 << 49
QUERY_LIMIT = 5_000_000_000
ORACLE = HERE / "target" / "debug" / "icrc3-oracle"
CERT_ORACLE = HERE / "target" / "debug" / "cert-oracle"
LOCAL_REPLICA = os.environ.get("ZK_LEDGER_REPLICA_URL", "http://127.0.0.1:4945")
EMPTY_ARCHIVE_MANIFEST = hashlib.sha256(b"").digest()
# The certified `audit` leaf on a healthy ledger: ICRC-3 map hash of {state: "pass"}
# (single-entry map: sha256(keyhash || valuehash)). The audit leaf is a pure function of
# the audit VERDICT — wait_audit_pass() below is called after every upgrade so all
# hash-tree captures compare like-for-like.
AUDIT_PASS_DIGEST = hashlib.sha256(
    hashlib.sha256(b"state").digest() + hashlib.sha256(b"pass").digest()
).digest()
TREE_ORACLE_WASM_SHA256 = "271b4f029e6f3e506667321d5b2a4c7b44aeb3fbf0d6248a2be0029401fe307e"
ICP_DECIMALS = 8
ICP_FEE_E8S = 10_000
ICP_SYMBOL = "ICP"
ICP_LEDGER_CANISTER = "icp_ledger_fixture"
NNS_ARCHIVE_CANISTER = "nns_archive_fixture"
NNS_ADAPTER_CANISTER = "nns_adapter"
NNS_METADATA_PROBE_CANISTER = "nns_adapter_metadata_probe"
NNS_ORACLE = HERE / "nns_adapter" / "target" / "debug" / "nns-adapter-oracle"


def read(name: str) -> str:
    return (VECTORS / name).read_text(encoding="utf-8").strip()


def field(name: str) -> bytes:
    value = bytes.fromhex(read(name))
    assert len(value) == 32
    return value


def as_int(value: Any) -> int:
    if isinstance(value, bool):
        raise TypeError("bool is not an integer")
    return int(value)


def as_blob(value: Any) -> bytes:
    if isinstance(value, str):
        return bytes.fromhex(value[2:] if value.startswith("0x") else value)
    if isinstance(value, list):
        return bytes(as_int(item) for item in value)
    raise TypeError(f"unexpected blob JSON {value!r}")


def variant(value: Any) -> tuple[str, Any]:
    if not isinstance(value, dict) or len(value) != 1:
        raise TypeError(f"expected one ICRC-3 variant, got {value!r}")
    return next(iter(value.items()))


def value_map(value: Any) -> dict[str, Any]:
    kind, entries = variant(value)
    if kind != "Map" or not isinstance(entries, list):
        raise TypeError(f"expected ICRC-3 Map, got {kind}")
    result: dict[str, Any] = {}
    for entry in entries:
        key = entry["0"]
        if key in result:
            raise ValueError(f"duplicate ICRC-3 map key {key}")
        result[key] = entry["1"]
    return result


def oracle_value(value: Any) -> dict[str, Any]:
    kind, payload = variant(value)
    if kind == "Blob":
        normalized: Any = as_blob(payload).hex()
    elif kind == "Text":
        normalized = payload
    elif kind in ("Nat", "Int"):
        normalized = str(as_int(payload))
    elif kind == "Array":
        normalized = [oracle_value(item) for item in payload]
    elif kind == "Map":
        normalized = [[entry["0"], oracle_value(entry["1"])] for entry in payload]
    else:
        raise TypeError(f"unsupported ICRC-3 variant {kind}")
    return {"kind": kind, "value": normalized}


def oracle_hash(value: Any) -> bytes:
    result = subprocess.run(
        [str(ORACLE)],
        cwd=HERE,
        input=json.dumps(oracle_value(value)),
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"ICRC-3 Rust oracle failed: {result.stderr.strip()}")
    return bytes.fromhex(result.stdout.strip())


def run_gate1_static_oracles() -> dict[str, Any]:
    sources = subprocess.run(
        ["mops", "sources"], cwd=HERE, check=True, capture_output=True, text=True
    ).stdout
    motoko = subprocess.run(
        [
            "/opt/moc-1.4.1/moc",
            "-r",
            *shlex.split(sources),
            "tests/ICRC3HashTest.mo",
        ],
        cwd=HERE,
        capture_output=True,
        text=True,
    )
    rust = subprocess.run(
        ["cargo", "test", "-p", "icrc3_oracle", "--locked"],
        cwd=HERE,
        capture_output=True,
        text=True,
    )
    rust_build = subprocess.run(
        ["cargo", "build", "-p", "icrc3_oracle", "--locked"],
        cwd=HERE,
        capture_output=True,
        text=True,
    )
    motoko_output = motoko.stdout + motoko.stderr
    rust_output = rust.stdout + rust.stderr
    return {
        "hash": (
            motoko.returncode == 0
            and rust.returncode == 0
            and rust_build.returncode == 0
            and "G1-HASH PASS" in motoko_output
            and "official_icrc3_hash_vectors ... ok" in rust_output
            and "nat_43_fails_the_nat_42_digest ... ok" in rust_output
        ),
        "map": (
            motoko.returncode == 0
            and rust.returncode == 0
            and rust_build.returncode == 0
            and "G1-MAP PASS" in motoko_output
            and "map_input_order_is_irrelevant ... ok" in rust_output
        ),
        "motoko_output": motoko_output.strip(),
        "rust_output": (rust_output + rust_build.stdout + rust_build.stderr).strip(),
    }


def build_cert_oracle() -> bool:
    result = subprocess.run(
        ["cargo", "build", "-p", "cert_oracle", "--locked"],
        cwd=HERE,
        capture_output=True,
        text=True,
    )
    return result.returncode == 0 and CERT_ORACLE.exists()


def artifact_checks() -> dict[str, Any]:
    positive = subprocess.run(
        ["sha256sum", "-c", "fixtures/SHA256SUMS"],
        cwd=HERE,
        capture_output=True,
        text=True,
    )
    with tempfile.TemporaryDirectory(prefix="zk-ledger-artifact-mutant-") as directory:
        mutant_root = Path(directory)
        shutil.copytree(HERE / "fixtures", mutant_root / "fixtures")
        shutil.copytree(HERE / "vendor", mutant_root / "vendor")
        verifier_path = mutant_root / "vendor" / "verifier" / "verifier.wasm"
        verifier = bytearray(verifier_path.read_bytes())
        verifier[0] ^= 1
        verifier_path.write_bytes(verifier)
        negative = subprocess.run(
            ["sha256sum", "-c", "fixtures/SHA256SUMS"],
            cwd=mutant_root,
            capture_output=True,
            text=True,
        )
    tree_wasm = HERE / ".dfx" / "local" / "canisters" / "tree_oracle" / "tree_oracle.wasm"
    tree_hash = hashlib.sha256(tree_wasm.read_bytes()).hexdigest() if tree_wasm.exists() else ""
    path_inputs = [HERE / "dfx.json", HERE / "Cargo.toml", HERE / "tree_oracle" / "Cargo.toml", HERE / "e2e.py"]
    forbidden_prefix = "".join(("/", "workspace"))
    canonical_paths_absent = all(
        forbidden_prefix not in path.read_text(encoding="utf-8") for path in path_inputs
    )
    return {
        "manifest_verified": positive.returncode == 0,
        "verifier_mutant_rejected": negative.returncode != 0,
        "tree_oracle_sha256": tree_hash,
        "tree_oracle_identity_verified": tree_hash == TREE_ORACLE_WASM_SHA256,
        "canonical_paths_absent": canonical_paths_absent,
        "manifest_output": (positive.stdout + positive.stderr).strip(),
        "mutant_output": (negative.stdout + negative.stderr).strip(),
    }


def cert_command(
    mode: str,
    canister: str,
    *,
    tip_index: int,
    tip_hash: bytes,
    note_count: int,
    note_root: bytes,
    minimum_tip: int,
) -> list[str]:
    return [
        str(CERT_ORACLE),
        mode,
        "--url",
        LOCAL_REPLICA,
        "--canister",
        canister,
        "--tip-index",
        str(tip_index),
        "--tip-hash",
        tip_hash.hex(),
        "--note-count",
        str(note_count),
        "--note-root",
        note_root.hex(),
        "--encoding-version",
        "1",
        "--archive-manifest",
        EMPTY_ARCHIVE_MANIFEST.hex(),
        "--audit-digest",
        AUDIT_PASS_DIGEST.hex(),
        "--minimum-tip",
        str(minimum_tip),
    ]


def cert_fetch(
    canister: str,
    *,
    tip_index: int,
    tip_hash: bytes,
    note_count: int,
    note_root: bytes,
    minimum_tip: int,
) -> dict[str, Any]:
    result = subprocess.run(
        cert_command(
            "fetch",
            canister,
            tip_index=tip_index,
            tip_hash=tip_hash,
            note_count=note_count,
            note_root=note_root,
            minimum_tip=minimum_tip,
        ),
        cwd=HERE,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"certificate oracle failed: {result.stderr.strip()}")
    return json.loads(result.stdout)


def cert_envelope_rejected(
    envelope: dict[str, Any],
    canister: str,
    *,
    tip_index: int,
    tip_hash: bytes,
    note_count: int,
    note_root: bytes,
    minimum_tip: int,
    marker: str,
) -> bool:
    result = subprocess.run(
        cert_command(
            "verify-envelope",
            canister,
            tip_index=tip_index,
            tip_hash=tip_hash,
            note_count=note_count,
            note_root=note_root,
            minimum_tip=minimum_tip,
        ),
        cwd=HERE,
        input=json.dumps(envelope),
        capture_output=True,
        text=True,
    )
    return result.returncode != 0 and marker in result.stderr


def cert_envelope_verified(
    envelope: dict[str, Any],
    canister: str,
    *,
    tip_index: int,
    tip_hash: bytes,
    note_count: int,
    note_root: bytes,
    minimum_tip: int,
) -> dict[str, Any]:
    result = subprocess.run(
        cert_command(
            "verify-envelope",
            canister,
            tip_index=tip_index,
            tip_hash=tip_hash,
            note_count=note_count,
            note_root=note_root,
            minimum_tip=minimum_tip,
        ),
        cwd=HERE,
        input=json.dumps(envelope),
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"certificate envelope verification failed: {result.stderr.strip()}")
    return json.loads(result.stdout)


def public_cert_report(report: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in report.items() if key != "envelope"}


def schema_valid(block_id: int, value: Any) -> bool:
    try:
        fields = value_map(value)
        required = {
            "btype",
            "encoding_version",
            "note_position",
            "commitment",
            "ephemeral_key",
            "note_ciphertext",
            "nullifiers",
            "anchor_before",
            "note_root_after",
            "timestamp",
            "origin",
        }
        expected = required if block_id == 0 else required | {"phash"}
        if set(fields) != expected:
            return False
        if variant(fields["btype"]) != ("Text", "zknote1"):
            return False
        if variant(fields["encoding_version"]) != ("Nat", "1"):
            return False
        if variant(fields["note_position"])[0] != "Nat" or as_int(variant(fields["note_position"])[1]) != block_id:
            return False
        for name in ("commitment", "anchor_before", "note_root_after"):
            kind, payload = variant(fields[name])
            if kind != "Blob" or len(as_blob(payload)) != 32:
                return False
        for name in ("ephemeral_key", "note_ciphertext"):
            kind, payload = variant(fields[name])
            if kind != "Blob" or not as_blob(payload):
                return False
        nullifier_kind, nullifiers = variant(fields["nullifiers"])
        if nullifier_kind != "Array":
            return False
        for nullifier in nullifiers:
            kind, payload = variant(nullifier)
            if kind != "Blob" or len(as_blob(payload)) != 32:
                return False
        if variant(fields["timestamp"])[0] != "Nat":
            return False
        if variant(fields["origin"])[0] != "Text" or variant(fields["origin"])[1] not in (
            "shield",
            "confidential_transfer",
        ):
            return False
        if block_id == 0:
            return "phash" not in fields
        kind, payload = variant(fields["phash"])
        return kind == "Blob" and len(as_blob(payload)) == 32
    except (KeyError, TypeError, ValueError):
        return False


def order_sensitive_map_hash(entries: list[dict[str, Any]]) -> bytes:
    digest = hashlib.sha256()
    for entry in entries:
        digest.update(hashlib.sha256(entry["0"].encode()).digest())
        digest.update(oracle_hash(entry["1"]))
    return digest.digest()


def candid_blob(value: bytes) -> str:
    return 'blob "' + "".join(f"\\{byte:02x}" for byte in value) + '"'


def wait_audit_pass(context: str, attempts: int = 240) -> None:
    """Poll the background stable-state audit to PASS (the replica's timers drive the
    chunks autonomously). Called after EVERY zk_ledger upgrade, before any snapshot or
    further install: the G2/G3/G4 gates compare certified hash trees across upgrades
    (the audit leaf must be back to "pass"), and an upgrade landing on an in-flight
    audit chunk is rejected by the moc EOP runtime (outstanding callbacks)."""
    status = None
    for _ in range(attempts):
        status = call("zk_ledger", "audit_status", query=True)
        state = status["state"]
        if isinstance(state, dict):
            if "pass" in state:
                return
            if "fail" in state:
                raise RuntimeError(f"stable-state audit FAILED ({context}): {state}")
        elif state == "pass":
            return
        time.sleep(0.5)
    raise RuntimeError(f"audit did not complete within bound ({context}): {status}")


def call(canister: str, method: str, argument: str = "()", *, query: bool = False) -> Any:
    command = ["dfx", "canister", "call", canister, method]
    if len(argument) < 100_000:
        command.append(argument)
    else:
        with tempfile.NamedTemporaryFile("w", suffix=".did", encoding="utf-8") as handle:
            handle.write(argument)
            handle.flush()
            command += ["--argument-file", handle.name]
            if query:
                command.append("--query")
            command += ["--output", "json"]
            result = subprocess.run(command, cwd=HERE, capture_output=True, text=True)
            if result.returncode != 0:
                raise RuntimeError(f"{method} failed: {result.stderr.strip()}")
            return json.loads(result.stdout) if result.stdout.strip() else None
    if query:
        command.append("--query")
    command += ["--output", "json"]
    result = subprocess.run(command, cwd=HERE, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"{method} failed: {result.stderr.strip()}")
    return json.loads(result.stdout) if result.stdout.strip() else None


def call_raw(canister: str, method: str, argument: str = "()") -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["dfx", "canister", "call", canister, method, argument, "--output", "json"],
        cwd=HERE,
        capture_output=True,
        text=True,
    )


def canister_id(name: str) -> str:
    return subprocess.run(
        ["dfx", "canister", "id", name], cwd=HERE, check=True, capture_output=True, text=True
    ).stdout.strip()


def current_principal() -> str:
    return subprocess.run(
        ["dfx", "identity", "get-principal"], cwd=HERE, check=True, capture_output=True, text=True
    ).stdout.strip()


def principal_blob(text: str) -> bytes:
    compact = text.replace("-", "").upper()
    padded = compact + "=" * ((8 - len(compact) % 8) % 8)
    decoded = base64.b32decode(padded)
    if len(decoded) < 4:
        raise ValueError("short principal")
    return decoded[4:]


def principal_text(raw: bytes) -> str:
    encoded = base64.b32encode(zlib.crc32(raw).to_bytes(4, "big") + raw).decode().lower().rstrip("=")
    return "-".join(encoded[index:index + 5] for index in range(0, len(encoded), 5))


def candid_account(owner: str, subaccount: bytes | None = None) -> str:
    sub = "null" if subaccount is None else f"opt {candid_blob(subaccount)}"
    return f'record {{ owner = principal "{owner}"; subaccount = {sub} }}'


def adapter_account(value: Any) -> tuple[str, bytes | None]:
    owner, subaccount = token_account_value(value)
    return principal_text(owner), subaccount


def hint_from_block(block_id: int, block: Any) -> dict[str, Any]:
    outer = value_map(block)
    btype_kind, btype = variant(outer["btype"])
    tx_kind, tx_value = variant(outer["tx"])
    if btype_kind != "Text" or tx_kind != "Map":
        raise ValueError("noncanonical fixture block")
    tx = value_map({"Map": tx_value})
    tx_fee = tx.get("fee")
    outer_fee = outer.get("fee")
    fee_value = tx_fee if tx_fee is not None else outer_fee
    if fee_value is None:
        raise ValueError("block has no effective fee")

    def optional_nat(name: str) -> int | None:
        return as_int(variant(tx[name])[1]) if name in tx else None

    def optional_blob(name: str) -> bytes | None:
        return as_blob(variant(tx[name])[1]) if name in tx else None

    return {
        "block_index": block_id,
        "btype": btype,
        "from": adapter_account(tx["from"]),
        "to": adapter_account(tx["to"]) if "to" in tx else None,
        "spender": adapter_account(tx["spender"]) if "spender" in tx else None,
        "amount": as_int(variant(tx["amt"])[1]),
        "effective_fee": as_int(variant(fee_value)[1]),
        "fee_was_supplied": tx_fee is not None,
        "memo": optional_blob("memo"),
        "created_at_time": optional_nat("ts"),
        "expected_allowance": optional_nat("expected_allowance"),
        "expires_at": optional_nat("expires_at"),
    }


def hint_argument(hint: dict[str, Any]) -> str:
    def account(value: tuple[str, bytes | None]) -> str:
        return candid_account(value[0], value[1])

    def opt_account(value: tuple[str, bytes | None] | None) -> str:
        return "null" if value is None else f"opt {account(value)}"

    def opt_nat(value: int | None, annotation: str = "nat64") -> str:
        return "null" if value is None else f"opt ({value} : {annotation})"

    def opt_blob(value: bytes | None) -> str:
        return "null" if value is None else f"opt {candid_blob(value)}"

    supplied = "true" if hint["fee_was_supplied"] else "false"
    return (
        "(record { "
        f"block_index = {hint['block_index']} : nat64; btype = \"{hint['btype']}\"; "
        f"from = {account(hint['from'])}; to = {opt_account(hint['to'])}; "
        f"spender = {opt_account(hint['spender'])}; amount = {hint['amount']} : nat64; "
        f"effective_fee = {hint['effective_fee']} : nat64; fee_was_supplied = {supplied}; "
        f"memo = {opt_blob(hint['memo'])}; created_at_time = {opt_nat(hint['created_at_time'])}; "
        f"expected_allowance = {opt_nat(hint['expected_allowance'])}; "
        f"expires_at = {opt_nat(hint['expires_at'])} "
        "})"
    )


def register_hint_accounts(adapter: str, hint: dict[str, Any]) -> list[Any]:
    results = []
    for key in ("from", "to", "spender"):
        if hint[key] is not None:
            results.append(call(adapter, "register_account", f"({candid_account(*hint[key])})"))
    return results


def sync_and_register_fixture_history(adapter: str) -> tuple[Any, list[Any]]:
    synced = call(adapter, "sync")
    source = call(
        ICP_LEDGER_CANISTER,
        "icrc3_get_blocks",
        "(vec { record { start = 0; length = 1000000 } })",
        query=True,
    )
    registered = []
    for entry in source["blocks"]:
        hint = hint_from_block(as_int(entry["id"]), entry["block"])
        register_hint_accounts(adapter, hint)
        registered.append(call(adapter, "register_transaction_hint", hint_argument(hint)))
    return synced, registered


def token_transfer_argument(
    *,
    spender_subaccount: bytes | None,
    from_owner: str,
    from_subaccount: bytes | None,
    to_owner: str,
    to_subaccount: bytes | None,
    amount: int,
    fee: int,
    memo: bytes,
    created_at_time: int,
) -> str:
    spender_sub = "null" if spender_subaccount is None else f"opt {candid_blob(spender_subaccount)}"
    return (
        "(record { "
        f"spender_subaccount = {spender_sub}; "
        f"from = {candid_account(from_owner, from_subaccount)}; "
        f"to = {candid_account(to_owner, to_subaccount)}; "
        f"amount = {amount}; fee = opt {fee}; memo = opt {candid_blob(memo)}; "
        f"created_at_time = opt {created_at_time} : opt nat64 "
        "})"
    )


def token_account_value(value: Any) -> tuple[bytes, bytes | None]:
    kind, payload = variant(value)
    if kind != "Array" or not isinstance(payload, list) or len(payload) not in (1, 2):
        raise ValueError("noncanonical ICRC account")
    owner_kind, owner = variant(payload[0])
    if owner_kind != "Blob":
        raise ValueError("account owner is not Blob")
    subaccount = None
    if len(payload) == 2:
        sub_kind, sub = variant(payload[1])
        if sub_kind != "Blob":
            raise ValueError("account subaccount is not Blob")
        subaccount = as_blob(sub)
    return as_blob(owner), subaccount


def token_2xfer_matches(block: Any, expected: dict[str, Any]) -> bool:
    try:
        outer = value_map(block)
        if variant(outer["btype"]) != ("Text", "2xfer"):
            return False
        if "fee" in outer:
            return False
        tx_kind, tx_value = variant(outer["tx"])
        if tx_kind != "Map":
            return False
        tx = value_map({"Map": tx_value})
        if as_int(variant(tx["amt"])[1]) != expected["amount"]:
            return False
        if as_int(variant(tx["fee"])[1]) != expected["fee"]:
            return False
        if as_int(variant(tx["ts"])[1]) != expected["created_at_time"]:
            return False
        if as_blob(variant(tx["memo"])[1]) != expected["memo"]:
            return False
        return (
            token_account_value(tx["from"]) == expected["from"]
            and token_account_value(tx["to"]) == expected["to"]
            and token_account_value(tx["spender"]) == expected["spender"]
        )
    except (KeyError, TypeError, ValueError):
        return False


def token_1xfer_matches(block: Any, expected: dict[str, Any]) -> bool:
    try:
        outer = value_map(block)
        if variant(outer["btype"]) != ("Text", "1xfer") or "fee" in outer:
            return False
        tx_kind, tx_value = variant(outer["tx"])
        if tx_kind != "Map":
            return False
        tx = value_map({"Map": tx_value})
        if as_int(variant(tx["amt"])[1]) != expected["amount"]:
            return False
        if as_int(variant(tx["fee"])[1]) != expected["fee"]:
            return False
        if as_int(variant(tx["ts"])[1]) != expected["created_at_time"]:
            return False
        if as_blob(variant(tx["memo"])[1]) != expected["memo"]:
            return False
        return (
            "spender" not in tx
            and token_account_value(tx["from"]) == expected["from"]
            and token_account_value(tx["to"]) == expected["to"]
        )
    except (KeyError, TypeError, ValueError):
        return False


def token_2approve_matches(block: Any, expected: dict[str, Any]) -> bool:
    try:
        outer = value_map(block)
        if variant(outer["btype"]) != ("Text", "2approve") or "fee" in outer:
            return False
        tx_kind, tx_value = variant(outer["tx"])
        if tx_kind != "Map":
            return False
        tx = value_map({"Map": tx_value})
        if as_int(variant(tx["amt"])[1]) != expected["amount"]:
            return False
        if as_int(variant(tx["fee"])[1]) != expected["fee"]:
            return False
        if as_int(variant(tx["ts"])[1]) != expected["created_at_time"]:
            return False
        if as_int(variant(tx["expected_allowance"])[1]) != expected["expected_allowance"]:
            return False
        if as_blob(variant(tx["memo"])[1]) != expected["memo"]:
            return False
        return (
            token_account_value(tx["from"]) == expected["from"]
            and token_account_value(tx["spender"]) == expected["spender"]
        )
    except (KeyError, TypeError, ValueError):
        return False


def public_inputs(values: list[bytes]) -> str:
    assert all(len(value) == 32 for value in values)
    return (len(values).to_bytes(8, "little") + b"".join(values)).hex()


def u64_field(value: int) -> bytes:
    return value.to_bytes(32, "little")


def output_record(commitment: bytes, tag: int) -> str:
    epk = bytes([tag]) * 32
    ciphertext = f"opaque-note-ciphertext-{tag}".encode()
    return (
        "record { "
        f"commitment = {candid_blob(commitment)}; "
        f"ephemeral_key = {candid_blob(epk)}; "
        f"note_ciphertext = {candid_blob(ciphertext)} "
        "}"
    )


def transfer_argument(
    anchor: bytes,
    nf1: bytes,
    nf2: bytes,
    cm1: bytes,
    cm2: bytes,
    fee: int,
    v_pub_out: int,
    proof: str,
    *,
    recipient_owner: str | None = None,
    created_at_time: int | None = None,
) -> str:
    recipient = (
        f'opt record {{ owner = principal "{recipient_owner}"; subaccount = null }}'
        if recipient_owner is not None else "null"
    )
    timestamp = f"opt ({created_at_time} : nat64)" if created_at_time is not None else "null"
    return (
        "(record { "
        f"anchor = {candid_blob(anchor)}; "
        f"nullifier_1 = {candid_blob(nf1)}; "
        f"nullifier_2 = {candid_blob(nf2)}; "
        f"output_1 = {output_record(cm1, 0xA1)}; "
        f"output_2 = {output_record(cm2, 0xA2)}; "
        f"fee = {fee} : nat64; v_pub_out = {v_pub_out} : nat64; "
        f"recipient = {recipient}; created_at_time = {timestamp}; "
        f'proof_hex = "{proof}" '
        "})"
    )


def stable_tuple(status: dict[str, Any]) -> tuple[Any, ...]:
    return (
        as_blob(status["note_root"]),
        as_int(status["note_count"]),
        as_int(status["log_length"]),
        as_int(status["nullifier_count"]),
        as_int(status["pool_value"]),
        as_int(status["epoch"]),
        status["tree_state"],
    )


@dataclass(frozen=True)
class LweCiphertext:
    a: tuple[int, ...]
    b: int


def gaussian_error() -> int:
    scale = 1 << 53
    u1 = (secrets.randbits(53) + 1) / (scale + 1)
    u2 = (secrets.randbits(53) + 1) / (scale + 1)
    normal = math.sqrt(-2.0 * math.log(u1)) * math.cos(2.0 * math.pi * u2)
    return round(normal * NOISE_SIGMA)


def encrypt_bit(secret: tuple[int, ...], bit: int) -> LweCiphertext:
    a = tuple(secrets.randbits(64) for _ in range(DIMENSION))
    dot = sum(value for value, secret_bit in zip(a, secret) if secret_bit) & MASK64
    return LweCiphertext(a, (dot + bit * DELTA + gaussian_error()) & MASK64)


def decrypt_bit(secret: tuple[int, ...], ciphertext: LweCiphertext) -> int:
    dot = sum(value for value, secret_bit in zip(ciphertext.a, secret) if secret_bit) & MASK64
    phase = (ciphertext.b - dot) & MASK64
    return (((phase + ROUNDING) & MASK64) >> 63) & 1


def lwe_argument(selectors: list[LweCiphertext]) -> str:
    records = []
    for selector in selectors:
        mask = "; ".join(f"{value} : nat64" for value in selector.a)
        records.append(f"record {{ a = vec {{ {mask} }}; b = {selector.b} : nat64 }}")
    return f"(record {{ selectors = vec {{ {'; '.join(records)} }} }})"


def recover(secret: tuple[int, ...], values: list[dict[str, Any]]) -> bytes:
    assert len(values) == OUTPUT_BITS
    output = bytearray(32)
    for bit_index, value in enumerate(values):
        ciphertext = LweCiphertext(tuple(as_int(x) for x in value["a"]), as_int(value["b"]))
        output[bit_index // 8] |= decrypt_bit(secret, ciphertext) << (7 - bit_index % 8)
    return bytes(output)


def main() -> None:
    adapter_build = subprocess.run(
        ["cargo", "build", "--manifest-path", "nns_adapter/Cargo.toml"],
        cwd=HERE,
        capture_output=True,
        text=True,
    )
    assert adapter_build.returncode == 0, adapter_build.stderr
    with (
        tempfile.NamedTemporaryFile(suffix=".did") as generated_fixture_did,
        tempfile.NamedTemporaryFile(suffix=".did") as generated_archive_did,
    ):
        fixture_idl = subprocess.run(
            [
                "/opt/moc-1.4.1/moc", "--idl",
                *shlex.split(subprocess.run(
                    ["mops", "sources"], cwd=HERE, check=True, capture_output=True, text=True
                ).stdout),
                "-o", generated_fixture_did.name, "tests/IcpLedgerFixture.mo",
            ],
            cwd=HERE,
            capture_output=True,
            text=True,
        )
        candid_compat = subprocess.run(
            ["didc", "check", generated_fixture_did.name,
             "nns_adapter/pinned/adapter_ledger_surface.did"],
            cwd=HERE,
            capture_output=True,
            text=True,
        )
        archive_idl = subprocess.run(
            [
                "/opt/moc-1.4.1/moc", "--idl",
                *shlex.split(subprocess.run(
                    ["mops", "sources"], cwd=HERE, check=True, capture_output=True, text=True
                ).stdout),
                "-o", generated_archive_did.name, "tests/NnsArchiveFixture.mo",
            ],
            cwd=HERE,
            capture_output=True,
            text=True,
        )
        archive_candid_compat = subprocess.run(
            ["didc", "check", generated_archive_did.name,
             "nns_adapter/pinned/ledger_archive.did"],
            cwd=HERE,
            capture_output=True,
            text=True,
        )
    pinned_candid_compat = all(
        result.returncode == 0
        for result in (fixture_idl, candid_compat, archive_idl, archive_candid_compat)
    )
    assert pinned_candid_compat, (
        fixture_idl.stderr + candid_compat.stderr
        + archive_idl.stderr + archive_candid_compat.stderr
    )
    artifacts = artifact_checks()
    assert artifacts["manifest_verified"] and artifacts["verifier_mutant_rejected"], artifacts
    assert artifacts["tree_oracle_identity_verified"], artifacts
    gate1_static = run_gate1_static_oracles()
    block_match_test = subprocess.run(
        ["/opt/moc-1.4.1/moc", "-r", *shlex.split(subprocess.run(
            ["mops", "sources"], cwd=HERE, check=True, capture_output=True, text=True
        ).stdout), "tests/ICRC2BlockTest.mo"],
        cwd=HERE,
        capture_output=True,
        text=True,
    )
    block_match_output = block_match_test.stdout + block_match_test.stderr
    assert block_match_test.returncode == 0 and "G4-BLOCK-MATCH PASS" in block_match_output
    cert_oracle_built = build_cert_oracle()
    assert cert_oracle_built
    storage_module_test = call("stable_storage_test", "result", query=True)
    assert (
        storage_module_test["codec"] is True
        and storage_module_test["storage"] is True
        and as_int(storage_module_test["set_entries"]) == 30
    ), storage_module_test
    ledger_canister = canister_id("zk_ledger")
    token_canister = canister_id(ICP_LEDGER_CANISTER)
    archive_canister = canister_id(NNS_ARCHIVE_CANISTER)
    adapter_canister = canister_id(NNS_ADAPTER_CANISTER)
    metadata_probe_canister = canister_id(NNS_METADATA_PROBE_CANISTER)
    user_principal = current_principal()
    verifier = canister_id("zk_verifier")
    tree = canister_id("tree_oracle")
    transfer_vk = read("transfer_vk.hex")
    deposit_vk = read("deposit_vk.hex")
    icp_name = call(ICP_LEDGER_CANISTER, "icrc1_name", "()", query=True)
    icp_symbol = call(ICP_LEDGER_CANISTER, "icrc1_symbol", "()", query=True)
    icp_decimals = as_int(call(ICP_LEDGER_CANISTER, "icrc1_decimals", "()", query=True))
    icp_fee = as_int(call(ICP_LEDGER_CANISTER, "icrc1_fee", "()", query=True))
    icp_standards = call(ICP_LEDGER_CANISTER, "icrc1_supported_standards", "()", query=True)
    icp_block_types = call(ICP_LEDGER_CANISTER, "icrc3_supported_block_types", "()", query=True)
    icp_interface = (
        icp_name == "Internet Computer"
        and icp_symbol == ICP_SYMBOL
        and icp_decimals == ICP_DECIMALS
        and icp_fee == ICP_FEE_E8S
        and {entry["name"] for entry in icp_standards} == {"ICRC-1", "ICRC-2"}
        and {entry["block_type"] for entry in icp_block_types} == {"1xfer", "2approve", "2xfer"}
    )

    # Metadata is fetched, not compiled in: reject a 7-decimal ledger, then observe a changed fee
    # on an independent adapter instance before configuring the production-under-test adapter.
    call(ICP_LEDGER_CANISTER, "test_set_decimals", "(7 : nat8)")
    decimal_rejection = call(
        NNS_METADATA_PROBE_CANISTER, "configure", f'(principal "{token_canister}")'
    )
    call(ICP_LEDGER_CANISTER, "test_set_decimals", "(8 : nat8)")
    changed_fee = 12_345
    call(ICP_LEDGER_CANISTER, "test_set_fee", f"({changed_fee})")
    dynamic_configure = call(
        NNS_METADATA_PROBE_CANISTER, "configure", f'(principal "{token_canister}")'
    )
    dynamic_metadata = call(NNS_METADATA_PROBE_CANISTER, "metadata", query=True)
    call(ICP_LEDGER_CANISTER, "test_set_fee", f"({ICP_FEE_E8S})")
    adapter_configured = call(
        NNS_ADAPTER_CANISTER, "configure", f'(principal "{token_canister}")'
    )
    dynamic_metadata_control = (
        "decimals:7" in decimal_rejection["err"]
        and "ok" in dynamic_configure
        and as_int(dynamic_metadata["fee"][0]) == changed_fee
        and as_int(dynamic_metadata["decimals"][0]) == ICP_DECIMALS
        and "ok" in adapter_configured
    )
    configured = call(
        "zk_ledger",
        "configure",
        f'(principal "{verifier}", principal "{tree}", "{transfer_vk}", "{deposit_vk}")',
    )
    assert "ok" in configured, configured
    token_configured = call(
        "zk_ledger",
        "configure_token_ledger",
        f'(principal "{token_canister}", principal "{adapter_canister}", null)',
    )
    assert "ok" in token_configured, token_configured

    # Exercise the ICRC-1 method surface and canonical 1xfer schema independently of Gate 4.
    probe_owner = "2vxsx-fae"
    icrc1_from_sub = bytes([0x44]) * 32
    icrc1_memo = bytes([0x45]) * 32
    icrc1_time = time.time_ns()
    icrc1_from = candid_account(user_principal, icrc1_from_sub)
    icrc1_to = candid_account(probe_owner)
    call(
        ICP_LEDGER_CANISTER, "test_set_balance",
        f"({icrc1_from}, {ICP_FEE_E8S + 1})",
    )
    icrc1_transfer = call(
        ICP_LEDGER_CANISTER, "icrc1_transfer",
        "(record { "
        f"from_subaccount = opt {candid_blob(icrc1_from_sub)}; to = {icrc1_to}; amount = 1; "
        f"fee = opt {ICP_FEE_E8S}; memo = opt {candid_blob(icrc1_memo)}; "
        f"created_at_time = opt ({icrc1_time} : nat64) "
        "})",
    )
    icrc1_index = as_int(icrc1_transfer["Ok"])
    icrc1_block = call(
        ICP_LEDGER_CANISTER, "icrc3_get_blocks",
        f"(vec {{ record {{ start = {icrc1_index}; length = 1 }} }})",
        query=True,
    )
    icrc1_transfer_schema = (
        len(icrc1_block["blocks"]) == 1
        and token_1xfer_matches(
            icrc1_block["blocks"][0]["block"],
            {
                "amount": 1,
                "fee": ICP_FEE_E8S,
                "created_at_time": icrc1_time,
                "memo": icrc1_memo,
                "from": (principal_blob(user_principal), icrc1_from_sub),
                "to": (principal_blob(probe_owner), None),
            },
        )
    )
    fixture_archives = call(
        ICP_LEDGER_CANISTER, "icrc3_get_archives", "(record { from = null })", query=True
    )

    # Independent ICRC-2/3 capability probe: failed preconditions cannot poison exact retries, and
    # transaction identity is the complete call rather than created_at_time alone.
    probe_sub = bytes([0x11]) * 32
    probe_to_sub = bytes([0x22]) * 32
    probe_memo = bytes([0x31]) * 32
    probe_time = time.time_ns()
    probe_from = candid_account(probe_owner, probe_sub)
    probe_spender = candid_account(user_principal)
    call(ICP_LEDGER_CANISTER, "test_set_balance", f"({probe_from}, {3 * ICP_FEE_E8S + 30})")
    probe_arg = token_transfer_argument(
        spender_subaccount=None,
        from_owner=probe_owner,
        from_subaccount=probe_sub,
        to_owner=user_principal,
        to_subaccount=probe_to_sub,
        amount=20,
        fee=ICP_FEE_E8S,
        memo=probe_memo,
        created_at_time=probe_time,
    )
    probe_before = call(
        ICP_LEDGER_CANISTER, "icrc3_get_blocks", "(vec { record { start = 0; length = 0 } })", query=True
    )
    wrong_fee_arg = token_transfer_argument(
        spender_subaccount=None,
        from_owner=probe_owner,
        from_subaccount=probe_sub,
        to_owner=user_principal,
        to_subaccount=probe_to_sub,
        amount=20,
        fee=ICP_FEE_E8S - 1,
        memo=bytes([0x30]) * 32,
        created_at_time=probe_time,
    )
    wrong_fee_control = call(ICP_LEDGER_CANISTER, "icrc2_transfer_from", wrong_fee_arg)
    probe_after_wrong_fee = call(
        ICP_LEDGER_CANISTER, "icrc3_get_blocks", "(vec { record { start = 0; length = 0 } })", query=True
    )
    probe_no_allowance = call(ICP_LEDGER_CANISTER, "icrc2_transfer_from", probe_arg)
    probe_after_error = call(
        ICP_LEDGER_CANISTER, "icrc3_get_blocks", "(vec { record { start = 0; length = 0 } })", query=True
    )
    call(
        ICP_LEDGER_CANISTER, "test_set_allowance",
        f"({probe_from}, {probe_spender}, {ICP_FEE_E8S + 20})",
    )
    probe_success = call(ICP_LEDGER_CANISTER, "icrc2_transfer_from", probe_arg)
    probe_index = as_int(probe_success["Ok"])
    probe_block = call(
        ICP_LEDGER_CANISTER,
        "icrc3_get_blocks",
        f"(vec {{ record {{ start = {probe_index}; length = 1 }} }})",
        query=True,
    )
    probe_expected = {
        "amount": 20,
        "fee": ICP_FEE_E8S,
        "created_at_time": probe_time,
        "memo": probe_memo,
        "from": (principal_blob(probe_owner), probe_sub),
        "to": (principal_blob(user_principal), probe_to_sub),
        "spender": (principal_blob(user_principal), None),
    }
    probe_replay = call(ICP_LEDGER_CANISTER, "icrc2_transfer_from", probe_arg)
    call(
        ICP_LEDGER_CANISTER, "test_set_allowance",
        f"({probe_from}, {probe_spender}, {ICP_FEE_E8S + 10})",
    )
    distinct_memo = bytes([0x32]) * 32
    distinct_arg = token_transfer_argument(
        spender_subaccount=None,
        from_owner=probe_owner,
        from_subaccount=probe_sub,
        to_owner=user_principal,
        to_subaccount=probe_to_sub,
        amount=10,
        fee=ICP_FEE_E8S,
        memo=distinct_memo,
        created_at_time=probe_time,
    )
    probe_distinct = call(ICP_LEDGER_CANISTER, "icrc2_transfer_from", distinct_arg)
    capability_positive = (
        as_int(wrong_fee_control["Err"]["BadFee"]["expected_fee"]) == ICP_FEE_E8S
        and "InsufficientAllowance" in probe_no_allowance["Err"]
        and as_int(probe_before["log_length"]) == as_int(probe_after_error["log_length"])
        and "Ok" in probe_success
        and len(probe_block["blocks"]) == 1
        and token_2xfer_matches(probe_block["blocks"][0]["block"], probe_expected)
        and as_int(probe_replay["Err"]["Duplicate"]["duplicate_of"]) == probe_index
        and "Ok" in probe_distinct
        and as_int(probe_distinct["Ok"]) != probe_index
    )

    # Bounded read-only-ICRC-ME-style mutant: it records timestamp/index before allowance success.
    mutant_sub = bytes([0x33]) * 32
    mutant_from = candid_account(probe_owner, mutant_sub)
    mutant_memo = bytes([0x41]) * 32
    mutant_time = time.time_ns() + 1
    mutant_arg = token_transfer_argument(
        spender_subaccount=None,
        from_owner=probe_owner,
        from_subaccount=mutant_sub,
        to_owner=user_principal,
        to_subaccount=None,
        amount=20,
        fee=ICP_FEE_E8S,
        memo=mutant_memo,
        created_at_time=mutant_time,
    )
    call(ICP_LEDGER_CANISTER, "test_set_balance", f"({mutant_from}, {ICP_FEE_E8S + 20})")
    call(ICP_LEDGER_CANISTER, "test_set_dedup_mode", "(variant { timestamp_only_preinsert })")
    mutant_first = call(ICP_LEDGER_CANISTER, "icrc2_transfer_from", mutant_arg)
    call(
        ICP_LEDGER_CANISTER, "test_set_allowance",
        f"({mutant_from}, {probe_spender}, {ICP_FEE_E8S + 20})",
    )
    mutant_retry = call(ICP_LEDGER_CANISTER, "icrc2_transfer_from", mutant_arg)
    mutant_index = as_int(mutant_retry["Err"]["Duplicate"]["duplicate_of"])
    mutant_block = call(
        ICP_LEDGER_CANISTER,
        "icrc3_get_blocks",
        f"(vec {{ record {{ start = {mutant_index}; length = 1 }} }})",
        query=True,
    )
    mutant_expected = {
        "amount": 20,
        "fee": ICP_FEE_E8S,
        "created_at_time": mutant_time,
        "memo": mutant_memo,
        "from": (principal_blob(probe_owner), mutant_sub),
        "to": (principal_blob(user_principal), None),
        "spender": (principal_blob(user_principal), None),
    }
    capability_mutant_rejected = (
        "InsufficientAllowance" in mutant_first["Err"]
        and "Duplicate" in mutant_retry["Err"]
        and (
            len(mutant_block["blocks"]) != 1
            or not token_2xfer_matches(mutant_block["blocks"][0]["block"], mutant_expected)
        )
    )
    call(ICP_LEDGER_CANISTER, "test_set_dedup_mode", "(variant { conformant })")

    # Golden lossy vector: legacy Candid substitutes the block timestamp when the protobuf
    # transaction omitted created_at_time. The paired encoded block preserves the missing bit.
    call(
        ICP_LEDGER_CANISTER, "test_set_balance",
        f"({icrc1_from}, {ICP_FEE_E8S + 2})",
    )
    lossy_transfer = call(
        ICP_LEDGER_CANISTER,
        "icrc1_transfer",
        f"(record {{ from_subaccount = opt {candid_blob(icrc1_from_sub)}; "
        f"to = {icrc1_to}; amount = 2; fee = null; memo = null; created_at_time = null }})",
    )
    lossy_index = as_int(lossy_transfer["Ok"])
    created_presence = call(ICP_LEDGER_CANISTER, "test_created_at_presence", query=True)
    lossy_vector_present = created_presence[lossy_index] is False

    # Move a real prefix into an archive fixture, then require paired Candid/encoded resolution.
    archive_count = 2
    call(
        NNS_ARCHIVE_CANISTER,
        "test_sync",
        f'(principal "{token_canister}", 0 : nat64, {archive_count} : nat64)',
    )
    call(
        ICP_LEDGER_CANISTER,
        "test_set_archive",
        f'(opt principal "{archive_canister}", {archive_count})',
    )
    adapter_initial_sync = call(NNS_ADAPTER_CANISTER, "sync")
    unhinted_history = call(
        NNS_ADAPTER_CANISTER,
        "icrc3_get_blocks",
        "(vec { record { start = 0; length = 1000 } })",
        query=True,
    )
    fixture_history = call(
        ICP_LEDGER_CANISTER,
        "icrc3_get_blocks",
        "(vec { record { start = 0; length = 1000 } })",
        query=True,
    )
    first_hint = hint_from_block(0, fixture_history["blocks"][0]["block"])
    register_hint_accounts(NNS_ADAPTER_CANISTER, first_hint)
    second_hint = hint_from_block(1, fixture_history["blocks"][1]["block"])
    register_hint_accounts(NNS_ADAPTER_CANISTER, second_hint)
    first_swapped_hint = copy.deepcopy(first_hint)
    first_swapped_hint["block_index"] = 1
    first_swapped_control = call(
        NNS_ADAPTER_CANISTER,
        "register_transaction_hint",
        hint_argument(first_swapped_hint),
    )
    second_swapped_hint = copy.deepcopy(second_hint)
    second_swapped_hint["block_index"] = 0
    second_swapped_control = call(
        NNS_ADAPTER_CANISTER,
        "register_transaction_hint",
        hint_argument(second_swapped_hint),
    )
    wrong_kind_hint = copy.deepcopy(first_hint)
    wrong_kind_hint["btype"] = "2approve"
    wrong_kind_control = call(
        NNS_ADAPTER_CANISTER,
        "register_transaction_hint",
        hint_argument(wrong_kind_hint),
    )
    wrong_preimage_hint = copy.deepcopy(first_hint)
    wrong_preimage_hint["to"] = first_hint["from"]
    wrong_preimage_control = call(
        NNS_ADAPTER_CANISTER,
        "register_transaction_hint",
        hint_argument(wrong_preimage_hint),
    )
    missing_created_hint = copy.deepcopy(first_hint)
    missing_created_hint["created_at_time"] = None
    missing_created_control = call(
        NNS_ADAPTER_CANISTER,
        "register_transaction_hint",
        hint_argument(missing_created_hint),
    )
    first_hint_registered = call(
        NNS_ADAPTER_CANISTER,
        "register_transaction_hint",
        hint_argument(first_hint),
    )
    flipped_fee_hint = copy.deepcopy(first_hint)
    flipped_fee_hint["fee_was_supplied"] = not first_hint["fee_was_supplied"]
    conflicting_fee_control = call(
        NNS_ADAPTER_CANISTER,
        "register_transaction_hint",
        hint_argument(flipped_fee_hint),
    )
    conflicting_fee_control_repeat = call(
        NNS_ADAPTER_CANISTER,
        "register_transaction_hint",
        hint_argument(flipped_fee_hint),
    )
    adapter_seed_sync, adapter_seed_hints = sync_and_register_fixture_history(NNS_ADAPTER_CANISTER)
    adapter_seed_history = call(
        NNS_ADAPTER_CANISTER,
        "icrc3_get_blocks",
        "(vec { record { start = 0; length = 1000 } })",
        query=True,
    )
    hint_controls = (
        as_int(unhinted_history["log_length"]) == len(fixture_history["blocks"])
        and unhinted_history["blocks"] == []
        and "err" in wrong_preimage_control
        and "err" in missing_created_control
        and "err" in first_swapped_control
        and "err" in second_swapped_control
        and "err" in wrong_kind_control
        and "ok" in first_hint_registered
        and "conflicting-sealed-hint" in conflicting_fee_control["err"]
        and conflicting_fee_control == conflicting_fee_control_repeat
        and all("ok" in result for result in adapter_seed_hints)
        and [oracle_hash(entry["block"]) for entry in adapter_seed_history["blocks"]]
        == [oracle_hash(entry["block"]) for entry in fixture_history["blocks"]]
    )
    archive_boundary_control = (
        as_int(adapter_initial_sync["ok"]["archive_ranges"]) == 1
        and as_int(adapter_seed_sync["ok"]["archive_ranges"]) == 1
        and as_int(adapter_seed_sync["ok"]["encoded_roundtrips"])
        == len(fixture_history["blocks"])
    )

    # Fund and approve only local fixture units. No external ledger or funds are in scope.
    user_account = candid_account(user_principal)
    pool_account = candid_account(ledger_canister)
    shield_value_e8s = int(read("deposit1_v.txt")) + int(read("deposit2_v.txt"))
    shield_allowance_e8s = shield_value_e8s + 2 * ICP_FEE_E8S
    user_initial_e8s = ICP_FEE_E8S + shield_allowance_e8s
    call(ICP_LEDGER_CANISTER, "test_set_balance", f"({user_account}, {user_initial_e8s})")

    def deposit_argument(index: int, created: int, nonce: bytes) -> str:
        cm = field(f"deposit{index}_cm.hex")
        value = int(read(f"deposit{index}_v.txt"))
        return (
            "(record { "
            f"value = {value} : nat64; from_subaccount = null; "
            f"created_at_time = {created} : nat64; client_nonce = {candid_blob(nonce)}; "
            f"commitment = {candid_blob(cm)}; "
            f"ephemeral_key = {candid_blob(bytes([index]) * 32)}; "
            f"note_ciphertext = {candid_blob(f'opaque-deposit-{index}'.encode())}; "
            f'proof_hex = "{read(f"deposit{index}_proof.hex")}" '
            "})"
        )

    deposit1_time = time.time_ns() + 2
    deposit1_nonce = bytes([0x51]) * 32
    deposit1_arg = deposit_argument(1, deposit1_time, deposit1_nonce)
    shield_error_before_status = call("zk_ledger", "status", query=True)
    shield_error_before_storage = call("zk_ledger", "storage_status", query=True)
    shield_error_before_token = call(
        ICP_LEDGER_CANISTER, "icrc3_get_blocks", "(vec { record { start = 0; length = 0 } })", query=True
    )
    shield_no_allowance = call("zk_ledger", "shield", deposit1_arg)
    shield_error_after_status = call("zk_ledger", "status", query=True)
    shield_error_after_storage = call("zk_ledger", "storage_status", query=True)
    shield_error_after_token = call(
        ICP_LEDGER_CANISTER, "icrc3_get_blocks", "(vec { record { start = 0; length = 0 } })", query=True
    )

    approve_time = time.time_ns() + 3
    approve_memo = bytes([0x61]) * 32
    approve = call(
        ICP_LEDGER_CANISTER,
        "icrc2_approve",
        "(record { "
        "from_subaccount = null; "
        f"spender = {pool_account}; amount = {shield_allowance_e8s}; expected_allowance = opt 0; "
        f"expires_at = null; fee = opt {ICP_FEE_E8S}; memo = opt {candid_blob(approve_memo)}; "
        f"created_at_time = opt ({approve_time} : nat64) "
        "})",
    )
    assert "Ok" in approve, approve
    approve_index = as_int(approve["Ok"])
    approve_block = call(
        ICP_LEDGER_CANISTER, "icrc3_get_blocks",
        f"(vec {{ record {{ start = {approve_index}; length = 1 }} }})",
        query=True,
    )
    approval_schema = (
        len(approve_block["blocks"]) == 1
        and token_2approve_matches(
            approve_block["blocks"][0]["block"],
            {
                "amount": shield_allowance_e8s,
                "fee": ICP_FEE_E8S,
                "created_at_time": approve_time,
                "expected_allowance": 0,
                "memo": approve_memo,
                "from": (principal_blob(user_principal), None),
                "spender": (principal_blob(ledger_canister), None),
            },
        )
    )
    approval_adapter_sync, approval_adapter_hints = sync_and_register_fixture_history(
        NNS_ADAPTER_CANISTER
    )
    assert all("ok" in result for result in approval_adapter_hints), approval_adapter_hints
    armed = call("zk_ledger", "test_arm_fail_after_token_once")
    assert "ok" in armed, armed
    callback_trap = call_raw("zk_ledger", "shield", deposit1_arg)
    pending_status = call("zk_ledger", "status", query=True)
    pending_atomicity = call("zk_ledger", "atomicity_status", query=True)
    pending_storage = call("zk_ledger", "storage_status", query=True)
    pending_snapshot = call("zk_ledger", "certified_snapshot", query=True)
    pending_user_balance = as_int(call(ICP_LEDGER_CANISTER, "icrc1_balance_of", f"({user_account})", query=True))
    pending_pool_balance = as_int(call(ICP_LEDGER_CANISTER, "icrc1_balance_of", f"({pool_account})", query=True))
    pending_source_sync = call(NNS_ADAPTER_CANISTER, "sync")
    pending_target = as_int(pending_atomicity["pending"][0]["ledger_tip_before"])
    unhinted_pending_block = call(
        NNS_ADAPTER_CANISTER,
        "icrc3_get_blocks",
        f"(vec {{ record {{ start = {pending_target}; length = 1 }} }})",
        query=True,
    )
    pending_fixture_block = call(
        ICP_LEDGER_CANISTER,
        "icrc3_get_blocks",
        f"(vec {{ record {{ start = {pending_target}; length = 1 }} }})",
        query=True,
    )["blocks"][0]
    pending_hint = hint_from_block(pending_target, pending_fixture_block["block"])
    pending_transfer_args = pending_atomicity["pending"][0]["transfer_args"]
    pending_hint_matches_persisted = (
        pending_hint["amount"] == as_int(pending_transfer_args["amount"])
        and pending_hint["effective_fee"] == as_int(pending_transfer_args["fee"][0])
        and pending_hint["created_at_time"]
        == as_int(pending_transfer_args["created_at_time"][0])
        and pending_hint["memo"] == as_blob(pending_transfer_args["memo"][0])
        and pending_hint["from"] == (pending_transfer_args["from"]["owner"], None)
        and pending_hint["to"] == (pending_transfer_args["to"]["owner"], None)
        and pending_hint["spender"] == (ledger_canister, None)
    )
    register_hint_accounts(NNS_ADAPTER_CANISTER, pending_hint)
    wrong_spender_hint = copy.deepcopy(pending_hint)
    wrong_spender_hint["spender"] = (probe_owner, None)
    register_hint_accounts(NNS_ADAPTER_CANISTER, wrong_spender_hint)
    wrong_spender_control = call(
        NNS_ADAPTER_CANISTER,
        "register_transaction_hint",
        hint_argument(wrong_spender_hint),
    )
    pending_adapter_sync, pending_adapter_hints = sync_and_register_fixture_history(
        NNS_ADAPTER_CANISTER
    )
    pending_adapter_block = call(
        NNS_ADAPTER_CANISTER,
        "icrc3_get_blocks",
        f"(vec {{ record {{ start = {pending_target}; length = 1 }} }})",
        query=True,
    )
    pending_hint_control = (
        as_int(pending_source_sync["ok"]["source_blocks"]) == pending_target + 1
        and unhinted_pending_block["blocks"] == []
        and "err" in wrong_spender_control
        and all("ok" in result for result in pending_adapter_hints)
        and len(pending_adapter_block["blocks"]) == 1
        and pending_hint_matches_persisted
    )
    changed_deposit_arg = deposit_argument(1, deposit1_time, bytes([0x52]) * 32)
    pending_changed_reject = call("zk_ledger", "shield", changed_deposit_arg)
    pending_transfer_reject = call(
        "zk_ledger",
        "confidential_transfer",
        transfer_argument(
            field("anchor.hex"), field("nf1.hex"), field("nf2.hex"),
            field("cm_out1.hex"), field("cm_out2.hex"), int(read("fee.txt")),
            int(read("v_pub_out.txt")), read("transfer_proof.hex"),
        ),
    )
    pending_upgrade = subprocess.run(
        ["dfx", "canister", "install", "zk_ledger", "--mode", "upgrade"],
        cwd=HERE,
        capture_output=True,
        text=True,
    )
    if pending_upgrade.returncode != 0:
        raise RuntimeError(f"pending ledger upgrade failed: {pending_upgrade.stderr.strip()}")
    wait_audit_pass("pending-shield upgrade")
    pending_post_upgrade_status = call("zk_ledger", "status", query=True)
    pending_post_upgrade_atomicity = call("zk_ledger", "atomicity_status", query=True)
    pending_post_upgrade_storage = call("zk_ledger", "storage_status", query=True)
    pending_post_upgrade_snapshot = call("zk_ledger", "certified_snapshot", query=True)
    # Post-window recovery hardening: advance the fixture clock past its 24h transaction window so a
    # re-call of transfer_from would now fail #TooOld. Recovery must still finalize by reconciling the
    # already-minted 2xfer via memo == intent_id (idempotency key), never via the dedup cache. This
    # closes the trapped-after-transfer strand (money in pool, no note) that a long outage would open.
    recovery_intent = as_blob(pending_atomicity["pending"][0]["intent_id"])
    window_advance_ns = 90_000_000_000_000
    call(ICP_LEDGER_CANISTER, "test_advance_time", f"({window_advance_ns})")
    window_probe = call(
        ICP_LEDGER_CANISTER,
        "icrc2_transfer_from",
        token_transfer_argument(
            spender_subaccount=None,
            from_owner=user_principal, from_subaccount=None,
            to_owner=ledger_canister, to_subaccount=None,
            amount=70, fee=ICP_FEE_E8S, memo=recovery_intent, created_at_time=deposit1_time,
        ),
    )
    resumed = call("zk_ledger", "resume_shield")
    tip0_status = call("zk_ledger", "status", query=True)
    tip0_blocks = call(
        "zk_ledger", "icrc3_get_blocks", "(vec { record { start = 0; length = 1 } })", query=True
    )
    tip0_hash = oracle_hash(tip0_blocks["blocks"][0]["block"])
    tip0_cert: dict[str, Any] | None = cert_fetch(
        ledger_canister,
        tip_index=0,
        tip_hash=tip0_hash,
        note_count=1,
        note_root=as_blob(tip0_status["note_root"]),
        minimum_tip=0,
    )
    token_log_after_resume = call(
        ICP_LEDGER_CANISTER, "icrc3_get_blocks", "(vec { record { start = 0; length = 1000 } })", query=True
    )
    first_intent = as_blob(pending_atomicity["pending"][0]["intent_id"])
    shield1_expected = {
        "amount": 70,
        "fee": ICP_FEE_E8S,
        "created_at_time": deposit1_time,
        "memo": first_intent,
        "from": (principal_blob(user_principal), None),
        "to": (principal_blob(ledger_canister), None),
        "spender": (principal_blob(ledger_canister), None),
    }
    shield1_blocks = [
        block for block in token_log_after_resume["blocks"]
        if token_2xfer_matches(block["block"], shield1_expected)
    ]
    token_length_before_idempotent = as_int(token_log_after_resume["log_length"])
    idempotent_retry = call("zk_ledger", "shield", deposit1_arg)
    token_length_after_idempotent = as_int(call(
        ICP_LEDGER_CANISTER, "icrc3_get_blocks", "(vec { record { start = 0; length = 0 } })", query=True
    )["log_length"])

    # Second verified shield uses the remaining exact allowance and follows the non-fault path.
    # deposit2 runs after the recovery test advanced the fixture clock, so its created_at_time must
    # track the advanced clock to stay inside the token's transaction window.
    deposit2_arg = deposit_argument(2, time.time_ns() + window_advance_ns + 4, bytes([0x53]) * 32)
    deposit2_pending = call("zk_ledger", "shield", deposit2_arg)
    deposit2_sync, deposit2_hints = sync_and_register_fixture_history(NNS_ADAPTER_CANISTER)
    deposit2 = call("zk_ledger", "resume_shield")
    deposits = [resumed, deposit2]

    deposited = call("zk_ledger", "status", query=True)
    anchor = field("anchor.hex")
    assert as_blob(deposited["note_root"]) == anchor
    assert as_int(deposited["note_count"]) == 2
    assert as_int(deposited["pool_value"]) == 100
    pre_blocks = call(
        "zk_ledger",
        "icrc3_get_blocks",
        "(vec { record { start = 0; length = 2 } })",
        query=True,
    )
    pre_served = {as_int(block["id"]): block["block"] for block in pre_blocks["blocks"]}
    pre_tip_hash = oracle_hash(pre_served[1])
    pre_snapshot = call("zk_ledger", "certified_snapshot", query=True)
    pre_cert = cert_fetch(
        ledger_canister,
        tip_index=1,
        tip_hash=pre_tip_hash,
        note_count=2,
        note_root=anchor,
        minimum_tip=0,
    )

    # Gate 3: actual same-module local upgrade after two deposits.
    pre_upgrade_status = copy.deepcopy(deposited)
    pre_upgrade_storage = call("zk_ledger", "storage_status", query=True)
    pre_upgrade_validation = call("zk_ledger", "validate_stable_state", query=True)
    assert "ok" in pre_upgrade_validation, pre_upgrade_validation
    upgrade = subprocess.run(
        ["dfx", "canister", "install", "zk_ledger", "--mode", "upgrade"],
        cwd=HERE,
        capture_output=True,
        text=True,
    )
    if upgrade.returncode != 0:
        raise RuntimeError(f"ledger upgrade failed: {upgrade.stderr.strip()}")
    wait_audit_pass("gate3 upgrade")
    post_upgrade_status = call("zk_ledger", "status", query=True)
    post_upgrade_storage = call("zk_ledger", "storage_status", query=True)
    post_upgrade_validation = call("zk_ledger", "validate_stable_state", query=True)
    post_upgrade_blocks = call(
        "zk_ledger",
        "icrc3_get_blocks",
        "(vec { record { start = 0; length = 2 } })",
        query=True,
    )
    post_upgrade_snapshot = call("zk_ledger", "certified_snapshot", query=True)
    post_upgrade_cert = cert_fetch(
        ledger_canister,
        tip_index=1,
        tip_hash=pre_tip_hash,
        note_count=2,
        note_root=anchor,
        minimum_tip=1,
    )
    same_witness_envelope = {
        "certificate_hex": post_upgrade_cert["envelope"]["certificate_hex"],
        "hash_tree_hex": pre_cert["envelope"]["hash_tree_hex"],
    }
    same_witness_verified = cert_envelope_verified(
        same_witness_envelope,
        ledger_canister,
        tip_index=1,
        tip_hash=pre_tip_hash,
        note_count=2,
        note_root=anchor,
        minimum_tip=1,
    )
    assert tip0_cert is not None
    older_witness_envelope = {
        "certificate_hex": post_upgrade_cert["envelope"]["certificate_hex"],
        "hash_tree_hex": tip0_cert["envelope"]["hash_tree_hex"],
    }
    older_witness_rejected = cert_envelope_rejected(
        older_witness_envelope,
        ledger_canister,
        tip_index=1,
        tip_hash=pre_tip_hash,
        note_count=2,
        note_root=anchor,
        minimum_tip=1,
        marker="witness digest is not the certified_data value",
    )
    snapshot_mutant = copy.deepcopy(pre_upgrade_status)
    snapshot_mutant["note_count"] = as_int(snapshot_mutant["note_count"]) + 1
    upgrade_snapshot_mutant_rejected = stable_tuple(snapshot_mutant) != stable_tuple(post_upgrade_status)
    pre_snapshot_without_certificate = {key: value for key, value in pre_snapshot.items() if key != "certificate"}
    post_snapshot_without_certificate = {
        key: value for key, value in post_upgrade_snapshot.items() if key != "certificate"
    }
    gate3_upgrade = (
        upgrade.returncode == 0
        and stable_tuple(pre_upgrade_status) == stable_tuple(post_upgrade_status)
        and pre_upgrade_storage == post_upgrade_storage
        and pre_blocks == post_upgrade_blocks
        and pre_snapshot_without_certificate == post_snapshot_without_certificate
        and "ok" in post_upgrade_validation
        and as_int(post_upgrade_storage["layout_version"]) == 1
        and upgrade_snapshot_mutant_rejected
    )
    gate3_recert = (
        post_upgrade_cert["valid"]
        and post_upgrade_cert["certificate_signature_verified"]
        and post_upgrade_cert["witness_digest_bound"]
        and post_upgrade_cert["tuple_leaves_verified"]
        and same_witness_verified["valid"]
        and older_witness_rejected
        and post_upgrade_cert["note_root_witness_mutant_rejected"]
    )
    deposited = post_upgrade_status

    # The checked-in withdrawal proof binds its eighth public input to a pinned recipient scalar.
    # Changing only that scalar must fail in the reference verifier. This tiny fixture's public
    # value is below the real token fee, so the ledger itself must also fail closed before mutation;
    # the browser E2E exercises a full-value recipient-bound payout and callback recovery.
    withdraw_anchor = field("withdraw_anchor.hex")
    withdraw_nf1, withdraw_nf2 = field("withdraw_nf1.hex"), field("withdraw_nf2.hex")
    withdraw_cm1, withdraw_cm2 = field("withdraw_cm_out1.hex"), field("withdraw_cm_out2.hex")
    withdraw_fee = int(read("withdraw_fee.txt"))
    withdraw_v_pub_out = int(read("withdraw_v_pub_out.txt"))
    withdraw_inputs = public_inputs([
        withdraw_anchor,
        withdraw_nf1,
        withdraw_nf2,
        withdraw_cm1,
        withdraw_cm2,
        u64_field(withdraw_fee),
        u64_field(withdraw_v_pub_out),
        field("withdraw_recipient_binding.hex"),
    ])
    withdraw_crypto = call(
        "zk_verifier",
        "verify_bls12381",
        f'("{transfer_vk}", "{read("withdraw_proof.hex")}", "{withdraw_inputs}")',
    )
    withdraw_tampered_binding = bytearray(field("withdraw_recipient_binding.hex"))
    withdraw_tampered_binding[0] ^= 1
    withdraw_tampered_inputs = public_inputs([
        withdraw_anchor,
        withdraw_nf1,
        withdraw_nf2,
        withdraw_cm1,
        withdraw_cm2,
        u64_field(withdraw_fee),
        u64_field(withdraw_v_pub_out),
        bytes(withdraw_tampered_binding),
    ])
    withdraw_tampered_crypto = call(
        "zk_verifier",
        "verify_bls12381",
        f'("{transfer_vk}", "{read("withdraw_proof.hex")}", "{withdraw_tampered_inputs}")',
    )
    withdraw_before_status = call("zk_ledger", "status", query=True)
    withdraw_before_storage = call("zk_ledger", "storage_status", query=True)
    withdraw_before_snapshot = call("zk_ledger", "certified_snapshot", query=True)
    withdraw_before_token_length = as_int(call(
        ICP_LEDGER_CANISTER, "icrc3_get_blocks", "(vec { record { start = 0; length = 0 } })", query=True
    )["log_length"])
    withdraw_before_pool_balance = as_int(call(
        ICP_LEDGER_CANISTER, "icrc1_balance_of", f"({pool_account})", query=True
    ))
    withdraw_rejected = call(
        "zk_ledger",
        "confidential_transfer",
        transfer_argument(
            withdraw_anchor,
            withdraw_nf1,
            withdraw_nf2,
            withdraw_cm1,
            withdraw_cm2,
            withdraw_fee,
            withdraw_v_pub_out,
            read("withdraw_proof.hex"),
            recipient_owner=user_principal,
            created_at_time=time.time_ns(),
        ),
    )
    withdraw_after_status = call("zk_ledger", "status", query=True)
    withdraw_after_storage = call("zk_ledger", "storage_status", query=True)
    withdraw_after_snapshot = call("zk_ledger", "certified_snapshot", query=True)
    withdraw_after_token_length = as_int(call(
        ICP_LEDGER_CANISTER, "icrc3_get_blocks", "(vec { record { start = 0; length = 0 } })", query=True
    )["log_length"])
    withdraw_after_pool_balance = as_int(call(
        ICP_LEDGER_CANISTER, "icrc1_balance_of", f"({pool_account})", query=True
    ))

    nf1, nf2 = field("nf1.hex"), field("nf2.hex")
    cm1, cm2 = field("cm_out1.hex"), field("cm_out2.hex")
    fee, v_pub_out = int(read("fee.txt")), int(read("v_pub_out.txt"))
    before_bad = stable_tuple(deposited)
    before_bad_storage = call("zk_ledger", "storage_status", query=True)

    # Z1 first, so its nullifiers are known-fresh and the bad proof reaches the real verifier.
    bad = call(
        "zk_ledger",
        "confidential_transfer",
        transfer_argument(anchor, nf1, nf2, cm1, cm2, fee, v_pub_out, read("transfer_badproof.hex")),
    )
    after_bad = call("zk_ledger", "status", query=True)
    after_bad_storage = call("zk_ledger", "storage_status", query=True)
    bad_snapshot = call("zk_ledger", "certified_snapshot", query=True)
    z1 = (
        bad["outcome"] in ("REJECT:proof-deserialize", "REJECT:pairing-check")
        and bad["verifier_outcome"] == bad["outcome"]
        and stable_tuple(after_bad) == before_bad
        and after_bad_storage == before_bad_storage
    )

    # Z3's proof is cryptographically valid for an attacker-fabricated tree.
    fake_anchor = field("fake_anchor.hex")
    fake_nf1, fake_nf2 = field("fake_nf1.hex"), field("fake_nf2.hex")
    fake_cm1, fake_cm2 = field("fake_cm_out1.hex"), field("fake_cm_out2.hex")
    fake_inputs = public_inputs(
        [
            fake_anchor, fake_nf1, fake_nf2, fake_cm1, fake_cm2,
            u64_field(fee), u64_field(v_pub_out), field("recipient_binding.hex"),
        ]
    )
    fake_crypto = call(
        "zk_verifier",
        "verify_bls12381",
        f'("{transfer_vk}", "{read("fake_proof.hex")}", "{fake_inputs}")',
    )
    before_absent = stable_tuple(after_bad)
    before_absent_storage = after_bad_storage
    absent = call(
        "zk_ledger",
        "confidential_transfer",
        transfer_argument(
            fake_anchor,
            fake_nf1,
            fake_nf2,
            fake_cm1,
            fake_cm2,
            fee,
            v_pub_out,
            read("fake_proof.hex"),
        ),
    )
    after_absent = call("zk_ledger", "status", query=True)
    after_absent_storage = call("zk_ledger", "storage_status", query=True)
    absent_snapshot = call("zk_ledger", "certified_snapshot", query=True)
    z3 = (
        fake_crypto["accepted"] is True
        and absent["outcome"] == "REJECT:unknown-anchor"
        and absent["verifier_outcome"] == "NOT_CALLED"
        and stable_tuple(after_absent) == before_absent
        and after_absent_storage == before_absent_storage
    )

    valid_inputs = public_inputs([
        anchor, nf1, nf2, cm1, cm2, u64_field(fee), u64_field(v_pub_out),
        field("recipient_binding.hex"),
    ])
    valid_crypto = call(
        "zk_verifier",
        "verify_bls12381",
        f'("{transfer_vk}", "{read("transfer_proof.hex")}", "{valid_inputs}")',
    )
    private_transfer_token_length_before = as_int(call(
        ICP_LEDGER_CANISTER, "icrc3_get_blocks", "(vec { record { start = 0; length = 0 } })", query=True
    )["log_length"])
    private_transfer_pool_before = as_int(call(
        ICP_LEDGER_CANISTER, "icrc1_balance_of", f"({pool_account})", query=True
    ))
    valid = call(
        "zk_ledger",
        "confidential_transfer",
        transfer_argument(anchor, nf1, nf2, cm1, cm2, fee, v_pub_out, read("transfer_proof.hex")),
    )
    after_valid = call("zk_ledger", "status", query=True)
    private_transfer_token_length_after = as_int(call(
        ICP_LEDGER_CANISTER, "icrc3_get_blocks", "(vec { record { start = 0; length = 0 } })", query=True
    )["log_length"])
    private_transfer_pool_after = as_int(call(
        ICP_LEDGER_CANISTER, "icrc1_balance_of", f"({pool_account})", query=True
    ))
    after_valid_storage = call("zk_ledger", "storage_status", query=True)
    after_valid_validation = call("zk_ledger", "validate_stable_state", query=True)
    blocks = call(
        "zk_ledger",
        "icrc3_get_blocks",
        "(vec { "
        "record { start = 0; length = 2 }; "
        "record { start = 2; length = 2 }; "
        "record { start = 4; length = 1 }; "
        "record { start = 3; length = 0 }; "
        "record { start = 1; length = 2 }; "
        "record { start = 0; length = 0 } "
        "})",
        query=True,
    )
    archives = call("zk_ledger", "icrc3_get_archives", "(record { from = null })", query=True)
    supported = call("zk_ledger", "icrc3_supported_block_types", query=True)
    snapshot = call("zk_ledger", "certified_snapshot", query=True)
    block_ids = [as_int(block["id"]) for block in blocks["blocks"]]
    served = {as_int(block["id"]): block["block"] for block in blocks["blocks"]}
    served_fields = {block_id: value_map(served[block_id]) for block_id in range(4)}

    shape_positive = (
        set(served) == {0, 1, 2, 3}
        and all(schema_valid(block_id, served[block_id]) for block_id in range(4))
        and supported
        == [
            {
                "block_type": "zknote1",
                "url": "https://github.com/dfinity/ICRC-1/tree/main/standards/ICRC-3",
            }
        ]
    )
    missing_btype = copy.deepcopy(served[0])
    missing_entries = variant(missing_btype)[1]
    missing_entries[:] = [entry for entry in missing_entries if entry["0"] != "btype"]
    shape_negative = not schema_valid(0, missing_btype)

    parent_positive = "phash" not in served_fields[0]
    parent_hashes: list[str] = []
    for block_id in range(1, 4):
        prior_hash = oracle_hash(served[block_id - 1])
        parent_hashes.append(prior_hash.hex())
        parent_positive = (
            parent_positive
            and as_blob(variant(served_fields[block_id]["phash"])[1]) == prior_hash
        )

    mutated_prior = copy.deepcopy(served[1])
    mutated_commitment = value_map(mutated_prior)["commitment"]["Blob"]
    mutated_commitment[0] = (as_int(mutated_commitment[0]) ^ 1) & 0xFF
    parent_negative = (
        oracle_hash(mutated_prior) != as_blob(variant(served_fields[2]["phash"])[1])
    )

    map_forward = {
        "Map": [
            {"0": "alpha", "1": {"Nat": "1"}},
            {"0": "beta", "1": {"Text": "two"}},
        ]
    }
    map_reverse = {"Map": list(reversed(copy.deepcopy(map_forward["Map"])))}
    map_runtime = (
        oracle_hash(map_forward) == oracle_hash(map_reverse)
        and order_sensitive_map_hash(map_forward["Map"])
        != order_sensitive_map_hash(map_reverse["Map"])
    )

    range_positive = (
        block_ids == [0, 1, 2, 3, 1, 2]
        and as_int(blocks["log_length"]) == 4
        and blocks["archived_blocks"] == []
        and archives == []
    )
    range_negative = block_ids != [0, 1, 2, 3]
    post_tip_hash = oracle_hash(served[3])
    post_root = as_blob(after_valid["note_root"])
    post_cert = cert_fetch(
        ledger_canister,
        tip_index=3,
        tip_hash=post_tip_hash,
        note_count=4,
        note_root=post_root,
        minimum_tip=3,
    )
    mixed_snapshot_rejected = cert_envelope_rejected(
        pre_cert["envelope"],
        ledger_canister,
        tip_index=3,
        tip_hash=post_tip_hash,
        note_count=4,
        note_root=post_root,
        minimum_tip=0,
        marker="last_block_index",
    )
    rollback_rejected = cert_envelope_rejected(
        pre_cert["envelope"],
        ledger_canister,
        tip_index=1,
        tip_hash=pre_tip_hash,
        note_count=2,
        note_root=anchor,
        minimum_tip=3,
        marker="rollback:",
    )
    z0 = (
        valid_crypto["accepted"] is True
        and valid["outcome"] == "ACCEPT"
        and valid["verifier_outcome"] == "ACCEPT"
        and as_int(after_valid["note_count"]) == 4
        and as_int(after_valid["nullifier_count"]) == 2
        and as_int(after_valid["pool_value"]) == 100
        and as_int(after_valid["epoch"]) == 3
        and as_int(blocks["log_length"]) == 4
        and block_ids == [0, 1, 2, 3, 1, 2]
        and as_blob(variant(served_fields[2]["commitment"])[1]) == cm1
        and as_blob(variant(served_fields[3]["commitment"])[1]) == cm2
        and as_blob(snapshot["note_root"]) == as_blob(after_valid["note_root"])
        and snapshot["certificate"] is not None
    )

    before_replay = stable_tuple(after_valid)
    before_replay_storage = after_valid_storage
    replay = call(
        "zk_ledger",
        "confidential_transfer",
        transfer_argument(anchor, nf1, nf2, cm1, cm2, fee, v_pub_out, read("transfer_proof.hex")),
    )
    after_replay = call("zk_ledger", "status", query=True)
    after_replay_storage = call("zk_ledger", "storage_status", query=True)
    replay_snapshot = call("zk_ledger", "certified_snapshot", query=True)
    z2 = (
        replay["outcome"] == "REJECT:nullifier-spent"
        and replay["verifier_outcome"] == "NOT_CALLED"
        and stable_tuple(after_replay) == before_replay
        and after_replay_storage == before_replay_storage
    )

    # PIR-private read of the first transfer output at note position 2.
    secret = tuple(secrets.randbits(1) for _ in range(DIMENSION))
    selectors = [encrypt_bit(secret, 1 if index == 2 else 0) for index in range(4)]
    pir = call("zk_ledger", "pir_query_lwe", lwe_argument(selectors), query=True)
    recovered = recover(secret, pir["ciphertexts"])
    trace = {key: as_int(value) for key, value in pir["trace"].items()}
    pir_ok = (
        recovered == cm1
        and as_blob(pir["snapshot_root"]) == as_blob(after_valid["note_root"])
        and trace["records_scanned"] == 4
        and trace["selectors_received"] == 4
        and trace["lwe_dimension"] == DIMENSION
        and trace["output_bits"] == OUTPUT_BITS
        and trace["selector_decryptions"] == 0
        and trace["target_index_parameters"] == 0
        and trace["target_dependent_branches"] == 0
        and 0 < trace["instructions"] < QUERY_LIMIT
    )

    gate1_all = (
        gate1_static["hash"]
        and gate1_static["map"]
        and map_runtime
        and shape_positive
        and shape_negative
        and parent_positive
        and parent_negative
        and range_positive
        and range_negative
    )
    gate2_tree = (
        post_cert["valid"]
        and post_cert["tuple_leaves_verified"]
        and post_cert["tree_digest_hex"] == post_cert["certified_data_hex"]
        and post_cert["tip_index"] == 3
        and post_cert["tip_hash_hex"] == post_tip_hash.hex()
        and post_cert["note_count"] == 4
        and post_cert["note_root_hex"] == post_root.hex()
        and post_cert["encoding_version"] == 1
        and post_cert["archive_manifest_hex"] == EMPTY_ARCHIVE_MANIFEST.hex()
        and post_cert["ascii_tip_index_mutant_rejected"]
    )
    gate2_cert = (
        post_cert["certificate_signature_verified"]
        and post_cert["certificate_time_verified"]
        and post_cert["canister_path_bound"]
        and post_cert["certificate_signature_mutant_rejected"]
        and post_cert["wrong_root_key_rejected"]
    )
    gate2_witness = (
        post_cert["witness_digest_bound"]
        and post_cert["note_root_witness_mutant_rejected"]
    )
    pre_tree = as_blob(pre_snapshot["hash_tree"])
    post_tree = as_blob(snapshot["hash_tree"])
    gate2_atomic = (
        pre_cert["valid"]
        and pre_cert["certified_data_hex"] != post_cert["certified_data_hex"]
        and pre_tree == as_blob(bad_snapshot["hash_tree"])
        and pre_tree == as_blob(absent_snapshot["hash_tree"])
        and pre_tree != post_tree
        and post_tree == as_blob(replay_snapshot["hash_tree"])
        and mixed_snapshot_rejected
    )
    gate2_rollback = post_cert["monotonic_tip_verified"] and rollback_rejected
    gate3_codec = (
        storage_module_test["codec"] is True
        and "ok" in after_valid_validation
        and shape_positive
        and parent_positive
    )
    gate3_storage = (
        storage_module_test["storage"] is True
        and as_int(storage_module_test["set_entries"]) == 30
        and as_int(pre_upgrade_storage["layout_version"]) == 1
        and as_int(pre_upgrade_storage["note_entries"]) == 2
        and as_int(pre_upgrade_storage["root_entries"]) == 3
        and as_int(pre_upgrade_storage["nullifier_entries"]) == 0
        and as_int(after_valid_storage["layout_version"]) == 1
        and as_int(after_valid_storage["note_entries"]) == 4
        and as_int(after_valid_storage["root_entries"]) == 4
        and as_int(after_valid_storage["nullifier_entries"]) == 2
        and as_blob(pre_upgrade_storage["note_digest"])
        != as_blob(after_valid_storage["note_digest"])
        and as_blob(pre_upgrade_storage["root_digest"])
        != as_blob(after_valid_storage["root_digest"])
        and as_blob(pre_upgrade_storage["nullifier_digest"])
        != as_blob(after_valid_storage["nullifier_digest"])
    )
    gate3_continue = (
        gate3_upgrade
        and z0
        and z2
        and z3
        and pir_ok
        and "ok" in after_valid_validation
        and after_bad_storage == before_bad_storage
        and after_absent_storage == before_absent_storage
        and after_replay_storage == before_replay_storage
    )
    gate3_portable_boundary = (
        artifacts["manifest_verified"]
        and artifacts["verifier_mutant_rejected"]
        and artifacts["tree_oracle_identity_verified"]
        and artifacts["canonical_paths_absent"]
    )
    final_atomicity = call("zk_ledger", "atomicity_status", query=True)
    final_user_balance = as_int(call(
        ICP_LEDGER_CANISTER, "icrc1_balance_of", f"({user_account})", query=True
    ))
    final_pool_balance = as_int(call(
        ICP_LEDGER_CANISTER, "icrc1_balance_of", f"({pool_account})", query=True
    ))
    final_allowance = call(
        ICP_LEDGER_CANISTER,
        "icrc2_allowance",
        f"(record {{ account = {user_account}; spender = {pool_account} }})",
        query=True,
    )
    nns_oracle_run = subprocess.run(
        [
            str(NNS_ORACLE),
            "--url", LOCAL_REPLICA,
            "--ledger", token_canister,
            "--adapter", adapter_canister,
        ],
        cwd=HERE,
        capture_output=True,
        text=True,
    )
    if nns_oracle_run.returncode != 0:
        raise RuntimeError(
            "NNS adapter oracle failed: " + nns_oracle_run.stderr.strip()
            + "\n" + nns_oracle_run.stdout.strip()
        )
    nns_oracle = json.loads(nns_oracle_run.stdout)
    final_adapter_metadata = call(NNS_ADAPTER_CANISTER, "metadata", query=True)
    final_adapter_history = call(
        NNS_ADAPTER_CANISTER,
        "icrc3_get_blocks",
        "(vec { record { start = 0; length = 1000 } })",
        query=True,
    )
    final_fixture_history = call(
        ICP_LEDGER_CANISTER,
        "icrc3_get_blocks",
        "(vec { record { start = 0; length = 1000 } })",
        query=True,
    )
    canonical_adapter_emission = (
        as_int(final_adapter_history["log_length"])
        == as_int(final_fixture_history["log_length"])
        and [as_int(entry["id"]) for entry in final_adapter_history["blocks"]]
        == [as_int(entry["id"]) for entry in final_fixture_history["blocks"]]
        and [oracle_hash(entry["block"]) for entry in final_adapter_history["blocks"]]
        == [oracle_hash(entry["block"]) for entry in final_fixture_history["blocks"]]
    )
    pending_snapshot_logical = {key: value for key, value in pending_snapshot.items() if key != "certificate"}
    pending_post_upgrade_logical = {
        key: value for key, value in pending_post_upgrade_snapshot.items() if key != "certificate"
    }
    gate4_capability = capability_positive and capability_mutant_rejected
    gate4_shield = (
        shield_no_allowance["outcome"] == "REJECT:token:InsufficientAllowance"
        and shield_no_allowance["verifier_outcome"] == "ACCEPT"
        and stable_tuple(shield_error_before_status) == stable_tuple(shield_error_after_status)
        and shield_error_before_storage == shield_error_after_storage
        and as_int(shield_error_before_token["log_length"])
        == as_int(shield_error_after_token["log_length"])
        and callback_trap.returncode != 0
        and "TEST_ONLY:fail-after-token-before-finalize" in (callback_trap.stdout + callback_trap.stderr)
        and pending_user_balance == user_initial_e8s - 2 * ICP_FEE_E8S - 70
        and pending_pool_balance == 70
        and as_int(pending_status["note_count"]) == 0
        and pending_atomicity["pending"]
        and pending_atomicity["test_fault_armed"] is False
        and len(shield1_blocks) == 1
        and resumed["outcome"] == "ACCEPT"
        and resumed["verifier_outcome"] == "ACCEPT"
        and idempotent_retry["outcome"] == "ACCEPT:already-finalized"
        and token_length_before_idempotent == token_length_after_idempotent
        and deposit2["outcome"] == "ACCEPT"
        and final_user_balance == user_initial_e8s - 3 * ICP_FEE_E8S - shield_value_e8s
        and final_pool_balance == shield_value_e8s
        and as_int(final_allowance["allowance"]) == 0
        and final_atomicity["pending"] == []
        and as_int(final_atomicity["completed_intents"]) == 2
    )
    gate4_recovery = (
        pending_changed_reject["outcome"] == "REJECT:pending-token-mutation"
        and pending_changed_reject["verifier_outcome"] == "NOT_CALLED"
        and pending_transfer_reject["outcome"] == "REJECT:pending-token-mutation"
        and pending_transfer_reject["verifier_outcome"] == "NOT_CALLED"
        and pending_upgrade.returncode == 0
        and stable_tuple(pending_status) == stable_tuple(pending_post_upgrade_status)
        and pending_storage == pending_post_upgrade_storage
        and pending_atomicity == pending_post_upgrade_atomicity
        and pending_snapshot_logical == pending_post_upgrade_logical
        and len(shield1_blocks) == 1
        and as_int(tip0_status["note_count"]) == 1
        and as_int(tip0_status["pool_value"]) == 70
    )
    gate4_recovery_window = (
        "TooOld" in str(window_probe)                       # re-call would strand: window genuinely passed
        and len(shield1_blocks) == 1                        # exactly one 2xfer for the intent: no double-charge
        and as_int(tip0_status["note_count"]) == 1          # the note was minted on the post-window resume
        and as_int(tip0_status["pool_value"]) == 70
        and token_length_before_idempotent == token_length_after_idempotent
    )
    withdraw_before_logical = {
        key: value for key, value in withdraw_before_snapshot.items() if key != "certificate"
    }
    withdraw_after_logical = {
        key: value for key, value in withdraw_after_snapshot.items() if key != "certificate"
    }
    gate4_fail_closed = (
        withdraw_crypto["accepted"] is True
        and withdraw_tampered_crypto["accepted"] is False
        and withdraw_rejected["outcome"] == "REJECT:unshield-fee-below-token-fee"
        and withdraw_rejected["verifier_outcome"] == "NOT_CALLED"
        and stable_tuple(withdraw_before_status) == stable_tuple(withdraw_after_status)
        and withdraw_before_storage == withdraw_after_storage
        and withdraw_before_logical == withdraw_after_logical
        and withdraw_before_token_length == withdraw_after_token_length
        and withdraw_before_pool_balance == withdraw_after_pool_balance == 100
        and private_transfer_token_length_before == private_transfer_token_length_after
        and private_transfer_pool_before == private_transfer_pool_after == 100
        and "G4-FEE-ARITHMETIC PASS" in block_match_output
        and z0 and z1 and z2 and z3 and pir_ok
    )
    icp_round_trip = (
        icp_interface
        and icrc1_transfer_schema
        and fixture_archives == []
        and approval_schema
        and len(shield1_blocks) == 1
        and approve_index < as_int(token_log_after_resume["log_length"])
        and resumed["outcome"] == "ACCEPT"
        and deposit2["outcome"] == "ACCEPT"
        and as_int(deposited["note_count"]) == 2
        and as_int(deposited["pool_value"]) == shield_value_e8s
        and final_pool_balance == shield_value_e8s
        and as_int(final_allowance["allowance"]) == 0
    )
    icp_wrong_fee_control = (
        as_int(wrong_fee_control["Err"]["BadFee"]["expected_fee"]) == ICP_FEE_E8S
        and as_int(probe_before["log_length"]) == as_int(probe_after_wrong_fee["log_length"])
    )
    source_oracle = nns_oracle["source"]
    adapter_oracle = nns_oracle["adapter"]
    nns_candid_byte_oracle = (
        pinned_candid_compat
        and lossy_vector_present
        and source_oracle["encoded_roundtrips"] == as_int(final_fixture_history["log_length"])
        and source_oracle["candid_semantic_matches"] == as_int(final_fixture_history["log_length"])
        and source_oracle["parent_chain_verified"]
        and source_oracle["lossy_created_at_case_observed"]
        and source_oracle["lossy_reconstruction_rejected"]
    )
    nns_certificate_controls = all(
        source_oracle[key]
        for key in (
            "certificate_signature_verified",
            "certificate_time_verified",
            "canister_path_bound",
            "certified_tip_hash_bound",
            "bad_signature_rejected",
            "wrong_root_key_rejected",
            "wrong_canister_rejected",
            "stale_certificate_rejected",
            "tampered_tip_rejected",
            "tampered_block_rejected",
        )
    )
    nns_archive_boundary = (
        archive_boundary_control
        and source_oracle["archive_ranges"] == 1
        and source_oracle["archive_boundary_verified"]
        and source_oracle["archive_boundary_tamper_rejected"]
    )
    nns_hint_preimages = hint_controls and pending_hint_control
    nns_adapter_certificate = all(
        adapter_oracle[key]
        for key in (
            "certificate_signature_verified",
            "certificate_time_verified",
            "canister_path_bound",
            "witness_digest_bound",
            "last_block_index_bound",
            "last_block_hash_bound",
            "source_tip_hash_bound",
            "source_ledger_bound",
            "two_hash_domains_distinct",
            "adapter_block_mutant_rejected",
        )
    )
    nns_gate4_roundtrip = (
        pending_hint_control
        and "ok" in approval_adapter_sync
        and all("ok" in result for result in approval_adapter_hints)
        and deposit2_pending["outcome"] == "PENDING:token-block-mismatch"
        and "ok" in deposit2_sync
        and all("ok" in result for result in deposit2_hints)
        and resumed["outcome"] == "ACCEPT"
        and deposit2["outcome"] == "ACCEPT"
        and final_pool_balance == shield_value_e8s
        and as_int(deposited["note_count"]) == 2
    )
    assertions = {
        "G1-HASH": gate1_static["hash"],
        "G1-MAP": gate1_static["map"] and map_runtime,
        "G1-SHAPE": shape_positive and shape_negative,
        "G1-PHASH": parent_positive and parent_negative,
        "G1-RANGE": range_positive and range_negative,
        "G1-REGRESSION": z0 and z1 and z2 and z3 and pir_ok,
        "G2-TREE": gate2_tree,
        "G2-CERT": gate2_cert,
        "G2-WITNESS": gate2_witness,
        "G2-ATOMIC": gate2_atomic,
        "G2-ROLLBACK": gate2_rollback,
        "G2-REGRESSION": gate1_all and z0 and z1 and z2 and z3 and pir_ok,
        "G3-CODEC": gate3_codec,
        "G3-STORAGE": gate3_storage,
        "G3-UPGRADE": gate3_upgrade,
        "G3-RECERT": gate3_recert,
        "G3-CONTINUE": gate3_continue,
        "G3-PORTABLE": gate3_portable_boundary,
        "G3-REGRESSION": (
            gate1_all
            and gate2_tree
            and gate2_cert
            and gate2_witness
            and gate2_atomic
            and gate2_rollback
            and z0
            and z1
            and z2
            and z3
            and pir_ok
        ),
        "G4-CAPABILITY": gate4_capability,
        "G4-SHIELD": gate4_shield,
        "G4-RECOVERY": gate4_recovery,
        "G4-RECOVERY-WINDOW": gate4_recovery_window,
        "G4-FAIL-CLOSED": gate4_fail_closed,
        "ICP-ROUNDTRIP": icp_round_trip,
        "ICP-WRONG-FEE-CONTROL": icp_wrong_fee_control,
        "NNS-CANDID-BYTE-ORACLE": nns_candid_byte_oracle,
        "NNS-CERT-CONTROLS": nns_certificate_controls,
        "NNS-ARCHIVE-BOUNDARY": nns_archive_boundary,
        "NNS-HINT-PREIMAGES": nns_hint_preimages,
        "NNS-CANONICAL-ICRC3": canonical_adapter_emission,
        "NNS-ADAPTER-CERT": nns_adapter_certificate,
        "NNS-DYNAMIC-METADATA": dynamic_metadata_control,
        "NNS-GATE4-ROUNDTRIP": nns_gate4_roundtrip,
        "Z0": z0,
        "Z1": z1,
        "Z2": z2,
        "Z3": z3,
        "PIR": pir_ok,
    }
    report = {
        "assertions": assertions,
        "canisters": {
            "zk_ledger": canister_id("zk_ledger"),
            "zk_verifier": verifier,
            "tree_oracle": tree,
            "icp_ledger_fixture": token_canister,
            "nns_archive_fixture": archive_canister,
            "nns_adapter": adapter_canister,
        },
        "fixture_anchor_hex": anchor.hex(),
        "post_transfer_root_hex": as_blob(after_valid["note_root"]).hex(),
        "outcomes": {
            "valid": valid,
            "tampered": bad,
            "double_spend": replay,
            "absent_note": absent,
            "absent_note_pairing_accepted": fake_crypto,
            "valid_pairing": valid_crypto,
            "withdraw_recipient_bound_pairing": withdraw_crypto,
            "withdraw_tampered_recipient_binding_pairing": withdraw_tampered_crypto,
            "withdraw_fail_closed": withdraw_rejected,
        },
        "gate1_icrc3": {
            "block_ids": block_ids,
            "parent_hashes_hex": parent_hashes,
            "archives": archives,
            "archived_blocks": blocks["archived_blocks"],
            "supported_block_types": supported,
            "negative_controls": {
                "nat43_does_not_match_nat42": gate1_static["hash"],
                "order_sensitive_map_differs": map_runtime,
                "missing_btype_rejected": shape_negative,
                "mutated_prior_rejected": parent_negative,
                "deduplicated_range_expectation_rejected": range_negative,
            },
            "motoko_oracle_output": gate1_static["motoko_output"],
            "rust_oracle_output": gate1_static["rust_output"],
        },
        "gate2_certified_tuple": {
            "pre_transfer": public_cert_report(pre_cert),
            "post_transfer": public_cert_report(post_cert),
            "negative_controls": {
                "certificate_signature_mutant_rejected": post_cert[
                    "certificate_signature_mutant_rejected"
                ],
                "wrong_root_key_rejected": post_cert["wrong_root_key_rejected"],
                "note_root_witness_mutant_rejected": post_cert[
                    "note_root_witness_mutant_rejected"
                ],
                "ascii_tip_index_mutant_rejected": post_cert[
                    "ascii_tip_index_mutant_rejected"
                ],
                "mixed_snapshot_rejected": mixed_snapshot_rejected,
                "rollback_rejected": rollback_rejected,
                "rejected_transactions_preserved_tree": (
                    pre_tree == as_blob(bad_snapshot["hash_tree"])
                    and pre_tree == as_blob(absent_snapshot["hash_tree"])
                    and post_tree == as_blob(replay_snapshot["hash_tree"])
                ),
            },
        },
        "gate3_stable_upgrade": {
            "artifact_checks": artifacts,
            "storage_module_test": storage_module_test,
            "upgrade_exit": upgrade.returncode,
            "upgrade_stdout": upgrade.stdout.strip(),
            "pre_upgrade_storage": pre_upgrade_storage,
            "post_upgrade_storage": post_upgrade_storage,
            "post_transfer_storage": after_valid_storage,
            "snapshot_mutant_rejected": upgrade_snapshot_mutant_rejected,
            "immediate_pre_upgrade_witness_still_valid": same_witness_verified["valid"],
            "older_tip0_witness_rejected": older_witness_rejected,
            "post_upgrade_certificate": public_cert_report(post_upgrade_cert),
            "post_upgrade_validation": post_upgrade_validation,
            "post_transfer_validation": after_valid_validation,
            "rejected_storage_unchanged": {
                "tampered_proof": after_bad_storage == before_bad_storage,
                "unknown_anchor": after_absent_storage == before_absent_storage,
                "replay": after_replay_storage == before_replay_storage,
            },
        },
        "gate4_icrc2_atomicity": {
            "normative_commit": "5d670e54d9a58fbf472bf0a25f33743d60cfd0e6",
            "block_match_test_output": block_match_output.strip(),
            "capability": {
                "positive": capability_positive,
                "mutant_rejected": capability_mutant_rejected,
                "wrong_fee_control": wrong_fee_control,
                "failed_precondition": probe_no_allowance,
                "success": probe_success,
                "exact_replay": probe_replay,
                "same_timestamp_distinct_args": probe_distinct,
                "matched_block_index": probe_index,
                "mutant_first": mutant_first,
                "mutant_false_duplicate": mutant_retry,
                "mutant_duplicate_block_count": len(mutant_block["blocks"]),
            },
            "shield": {
                "failed_without_allowance": shield_no_allowance,
                "approval": approve,
                "callback_trap_exit": callback_trap.returncode,
                "callback_trap_error": (callback_trap.stdout + callback_trap.stderr).strip(),
                "pending_user_balance": pending_user_balance,
                "pending_pool_balance": pending_pool_balance,
                "pending_status": pending_atomicity,
                "resume": resumed,
                "matching_2xfer_blocks": [as_int(block["id"]) for block in shield1_blocks],
                "idempotent_retry": idempotent_retry,
                "token_log_length_before_idempotent": token_length_before_idempotent,
                "token_log_length_after_idempotent": token_length_after_idempotent,
                "second_deposit_initial": deposit2_pending,
                "second_deposit_resume": deposit2,
                "final_user_balance": final_user_balance,
                "final_pool_balance": final_pool_balance,
                "final_allowance": final_allowance,
                "final_atomicity": final_atomicity,
            },
            "recovery": {
                "changed_request_while_pending": pending_changed_reject,
                "valid_transfer_while_pending": pending_transfer_reject,
                "pending_upgrade_exit": pending_upgrade.returncode,
                "pending_upgrade_stdout": pending_upgrade.stdout.strip(),
                "pending_storage_equal": pending_storage == pending_post_upgrade_storage,
                "pending_atomicity_equal": pending_atomicity == pending_post_upgrade_atomicity,
                "pending_certified_tuple_equal": pending_snapshot_logical == pending_post_upgrade_logical,
            },
            "fail_closed_unshield": {
                "recipient_bound_statement_accepted": withdraw_crypto["accepted"],
                "tampered_recipient_binding_rejected": not withdraw_tampered_crypto["accepted"],
                "ledger_result": withdraw_rejected,
                "storage_unchanged": withdraw_before_storage == withdraw_after_storage,
                "certified_tuple_unchanged": withdraw_before_logical == withdraw_after_logical,
                "token_log_unchanged": withdraw_before_token_length == withdraw_after_token_length,
                "pool_balance_unchanged": withdraw_before_pool_balance == withdraw_after_pool_balance,
                "pool_debit_accounting": (
                    "pool debit = public amount delivered to recipient + transparent ledger fee; "
                    "browser E2E verifies the exact payout block and balance delta"
                ),
            },
        },
        "icp_ledger_fixture": {
            "name": icp_name,
            "symbol": icp_symbol,
            "decimals": icp_decimals,
            "fee_e8s": icp_fee,
            "supported_standards": icp_standards,
            "supported_block_types": icp_block_types,
            "interface_assertion": icp_interface,
            "icrc1_transfer_schema": icrc1_transfer_schema,
            "icrc1_transfer_block_index": icrc1_index,
            "icrc3_archives": fixture_archives,
            "approval_2approve_schema": approval_schema,
            "approval_block_index": approve_index,
            "shield_value_e8s": shield_value_e8s,
            "pool_balance_e8s": final_pool_balance,
            "note_count": as_int(deposited["note_count"]),
            "wrong_fee_control": wrong_fee_control,
            "production_interface_gap": (
                "The pinned NNS ledger exposes legacy query_blocks/query_encoded_blocks, not "
                "ICRC-3. The split history adapter closes that method-shape gap; production "
                "deployment must supply the IC root of trust and an authenticated hint registrar."
            ),
        },
        "nns_icrc3_adapter": {
            "pinned_commit": "c6a37193d91ddad3254fccce83fff18809fbbc1d",
            "pinned_candid_compatible": pinned_candid_compat,
            "dynamic_metadata": dynamic_metadata,
            "final_metadata": final_adapter_metadata,
            "initial_archive_sync": adapter_initial_sync,
            "hint_controls": {
                "fail_closed_without_hint": unhinted_history["blocks"] == [],
                "wrong_preimage_rejected": wrong_preimage_control,
                "missing_created_presence_rejected": missing_created_control,
                "first_swapped_hint_rejected": first_swapped_control,
                "second_swapped_hint_rejected": second_swapped_control,
                "wrong_operation_kind_rejected": wrong_kind_control,
                "conflicting_fee_presence_rejected": conflicting_fee_control,
                "conflict_repeat_rejected": conflicting_fee_control_repeat,
                "wrong_spender_rejected": wrong_spender_control,
                "gate4_persisted_args_match": pending_hint_matches_persisted,
            },
            "oracle": nns_oracle,
            "canonical_icrc3_matches_fixture": canonical_adapter_emission,
        },
        "pir": {
            "target": 2,
            "recovered_hex": recovered.hex(),
            "expected_hex": cm1.hex(),
            "trace": trace,
            "fraction_of_5b": trace["instructions"] / QUERY_LIMIT,
        },
        "certified_snapshot": {
            "certificate_present": snapshot["certificate"] is not None,
            "note_count": as_int(snapshot["note_count"]),
            "last_block_index": as_int(snapshot["last_block_index"][0]),
            "last_block_hash_hex": as_blob(snapshot["last_block_hash"][0]).hex(),
            "archive_manifest_hex": as_blob(snapshot["archive_manifest"]).hex(),
            "note_root_hex": as_blob(snapshot["note_root"]).hex(),
        },
        "compiler": "Motoko 1.4.1",
        "network": "local sandbox",
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    if not all(assertions.values()):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
