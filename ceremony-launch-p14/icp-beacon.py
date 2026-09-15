#!/usr/bin/env python3
"""Resolve the ceremony finalize beacon from the ICP ledger, or check a claimed one.

The beacon rule (see BEACON.md in this directory) names a TIMESTAMP, not a block index:

    the ICP ledger block with the SMALLEST index whose block timestamp is >= T

where T is fixed and published before the contribution window closes. The ledger
(ryjl3-tyaaa-aaaaa-aaaba-cai) is an append-only, hash-chained log; every block is served
forever either by the ledger or by one of its archive canisters, so the resolution can be
repeated by anyone at any later date and must give the same answer.

The block hash is SHA-256 over the block's protobuf encoding exactly as `query_encoded_blocks`
returns it. That is the ledger's own chaining hash: it equals `parent_hash` of the next block,
which this tool cross-checks whenever the next block exists.

Beacon string fed to `ceremony-cli finalize` / `submit_beacon`, as ASCII bytes:

    icp-ledger-block:<index>:<sha256 hex>

Requires python3 and ic-py (`pip install ic-py`). Reads only public query endpoints.

    icp-beacon.py resolve 2026-09-16T12:00:00Z        # find the beacon block for T
    icp-beacon.py check   <index>                      # timestamp + hash of one block
    icp-beacon.py verify  'icp-ledger-block:<i>:<hex>' 2026-09-16T12:00:00Z
"""
import hashlib
import json
import sys
from datetime import datetime, timezone

from ic.agent import Agent
from ic.canister import Canister
from ic.client import Client
from ic.identity import Identity

LEDGER = "ryjl3-tyaaa-aaaaa-aaaba-cai"
IC_URL = "https://icp-api.io"

DID = """
type GetBlocksArgs = record { start : nat64; length : nat64 };
type QueryArchiveError = variant {
  BadFirstBlockIndex : record { requested_index : nat64; first_valid_index : nat64 };
  Other : record { error_code : nat64; error_message : text } };
type ArchivedEncodedBlocksRange = record {
  start : nat64; length : nat64;
  callback : func (GetBlocksArgs) -> (variant { Ok : vec blob; Err : QueryArchiveError }) query };
type QueryEncodedBlocksResponse = record {
  certificate : opt blob; blocks : vec blob; chain_length : nat64; first_block_index : nat64;
  archived_blocks : vec ArchivedEncodedBlocksRange };
service : { query_encoded_blocks : (GetBlocksArgs) -> (QueryEncodedBlocksResponse) query; }
"""
ARCHIVE_DID = """
type GetBlocksArgs = record { start : nat64; length : nat64 };
type QueryArchiveError = variant {
  BadFirstBlockIndex : record { requested_index : nat64; first_valid_index : nat64 };
  Other : record { error_code : nat64; error_message : text } };
service : { get_encoded_blocks : (GetBlocksArgs) -> (variant { Ok : vec blob; Err : QueryArchiveError }) query; }
"""

_agent = Agent(Identity(anonymous=True), Client(IC_URL))
_ledger = Canister(agent=_agent, canister_id=LEDGER, candid=DID)
_archives = {}


def _as_bytes(b):
    return bytes(b) if isinstance(b, (list, bytes, bytearray)) else bytes.fromhex(b)


def chain_length():
    return int(_ledger.query_encoded_blocks({"start": 0, "length": 0})[0]["chain_length"])


def fetch_encoded(index):
    """Protobuf-encoded block `index`, from the ledger or the archive it points us to."""
    r = _ledger.query_encoded_blocks({"start": index, "length": 1})[0]
    if r["blocks"]:
        return _as_bytes(r["blocks"][0])
    if not r["archived_blocks"]:
        raise SystemExit(f"block {index} not available: chain_length={r['chain_length']}")
    rng = r["archived_blocks"][0]
    cid, method = str(rng["callback"][0]), rng["callback"][1]
    if method != "get_encoded_blocks":
        raise SystemExit(f"unexpected archive callback {method}")
    if cid not in _archives:
        _archives[cid] = Canister(agent=_agent, canister_id=cid, candid=ARCHIVE_DID)
    res = _archives[cid].get_encoded_blocks({"start": int(rng["start"]), "length": 1})[0]
    if "Ok" not in res:
        raise SystemExit(f"archive {cid} refused block {index}: {res}")
    return _as_bytes(res["Ok"][0])


# --- minimal protobuf reader: the ledger Block is { 1: Hash { 1: bytes }, 2: TimeStamp { 1: uint64 }, 3: Transaction }
def _varint(buf, i):
    v = s = 0
    while True:
        b = buf[i]; i += 1
        v |= (b & 0x7F) << s; s += 7
        if not b & 0x80:
            return v, i


def _fields(buf):
    i, out = 0, {}
    while i < len(buf):
        key, i = _varint(buf, i)
        fnum, wt = key >> 3, key & 7
        if wt == 0:
            v, i = _varint(buf, i)
        elif wt == 2:
            n, i = _varint(buf, i); v = buf[i:i + n]; i += n
        elif wt == 1:
            v = buf[i:i + 8]; i += 8
        elif wt == 5:
            v = buf[i:i + 4]; i += 4
        else:
            raise ValueError(f"unsupported wire type {wt}")
        out.setdefault(fnum, []).append(v)
    return out


def decode_block(enc):
    f = _fields(enc)
    parent_msg = f.get(1, [b""])[0]
    parent = _fields(parent_msg).get(1, [b""])[0] if parent_msg else b""
    ts_msg = f.get(2, [b""])[0]
    ts = _fields(ts_msg).get(1, [0])[0] if ts_msg else 0
    return {"parent_hash": parent.hex(), "timestamp_nanos": int(ts), "sha256": hashlib.sha256(enc).hexdigest()}


def block(index):
    d = decode_block(fetch_encoded(index))
    d["index"] = index
    return d


def cross_check(index, sha_hex):
    """The ledger's own chaining: block index+1 must carry our hash as its parent_hash."""
    try:
        nxt = block(index + 1)
    except SystemExit:
        return "next block not yet available; chaining cross-check pending"
    if nxt["parent_hash"] != sha_hex:
        raise SystemExit(f"CHAIN MISMATCH: block {index+1}.parent_hash={nxt['parent_hash']} != sha256(block {index})={sha_hex}")
    return f"confirmed: block {index+1}.parent_hash == sha256(block {index})"


def parse_time(s):
    if s.isdigit():
        return int(s)
    return int(datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc).timestamp()) * 1_000_000_000


def fmt_ts(ns):
    return datetime.fromtimestamp(ns // 1_000_000_000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") + f" ({ns})"


def resolve(t_nanos):
    """Smallest index with timestamp_nanos >= t_nanos, by binary search over [0, chain_length)."""
    n = chain_length()
    tip = block(n - 1)
    if tip["timestamp_nanos"] < t_nanos:
        return None, n, tip
    lo, hi = 0, n - 1  # invariant: block(hi).ts >= T
    while lo < hi:
        mid = (lo + hi) // 2
        if block(mid)["timestamp_nanos"] >= t_nanos:
            hi = mid
        else:
            lo = mid + 1
    b = block(lo)
    # both neighbours are re-read so the answer never depends on the search path
    if lo > 0 and block(lo - 1)["timestamp_nanos"] >= t_nanos:
        raise SystemExit(f"timestamps not monotone around {lo}; refusing to resolve")
    return b, n, tip


def main(argv):
    if len(argv) < 2 or argv[1] not in ("resolve", "check", "verify"):
        print(__doc__); return 2
    cmd = argv[1]
    if cmd == "check":
        b = block(int(argv[2]))
        b["timestamp"] = fmt_ts(b["timestamp_nanos"])
        b["chain_check"] = cross_check(b["index"], b["sha256"])
        print(json.dumps(b, indent=2)); return 0
    t = parse_time(argv[3] if cmd == "verify" else argv[2])
    b, n, tip = resolve(t)
    if b is None:
        print(f"NOT YET: chain_length={n}, tip block {tip['index']} at {fmt_ts(tip['timestamp_nanos'])} is before T={fmt_ts(t)}")
        return 3
    beacon = f"icp-ledger-block:{b['index']}:{b['sha256']}"
    out = {"T": fmt_ts(t), "index": b["index"], "timestamp": fmt_ts(b["timestamp_nanos"]),
           "sha256": b["sha256"], "chain_check": cross_check(b["index"], b["sha256"]),
           "chain_length_at_resolution": n, "beacon": beacon}
    if cmd == "verify":
        claimed = argv[2].strip()
        out["claimed"] = claimed
        out["verdict"] = "BEACON VALID" if claimed == beacon else "BEACON MISMATCH"
        print(json.dumps(out, indent=2))
        return 0 if claimed == beacon else 1
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
