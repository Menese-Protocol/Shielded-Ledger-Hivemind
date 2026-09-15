#!/usr/bin/env python3
"""Finalize the Phase-2 ceremony: export the on-chain transcript, apply the public beacon locally,
stage the beacon step on the coordinator and call `submit_beacon`, then prove the result from the
chain with the standalone verifier.

The coordinator canister is the ONLY place the transcript lives, and the Rust CLI carries no IC
agent. This script is the bridge, in both directions:

    finalize.py export <parts-dir>
        Pull the initial parameters and every contribution from the coordinator into the
        `assemble-transcript` parts format. Every blob is checked against the SHA-256 the
        coordinator itself recorded for it.

    finalize.py submit <emit-dir> <beacon> [--rehearsal]
        Stage the beacon step that `ceremony-cli emit-contribution` wrote and call
        `submit_beacon` from the authority identity. Refuses unless the coordinator is in a state
        where the call can succeed, the emitted step sits exactly on the current transcript head,
        and (outside --rehearsal) the beacon string verifies against the ICP ledger.

    finalize.py run <beacon> <workdir> [--rehearsal]
        The whole thing: export -> assemble -> verify (unfinalized) -> finalize locally -> verify
        (finalized) -> emit -> submit -> export again -> assemble -> verify --selfcheck. The final
        verdict compares the verifying-key hashes of the locally finalized transcript with those of
        the transcript re-read from the chain after submission: two independent paths to the same
        keys.

Beacon rule: BEACON.md in this directory. `icp-beacon.py resolve 2026-09-16T12:00:00Z` names the
block once T has passed; the string it prints is the <beacon> argument here.

Identity: the ceremony authority is dfx's `default` identity
(~/.config/dfx/identity/default/identity.pem) unless --pem says otherwise. `export` needs no
identity. Requires python3 and ic-py.
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time

import ecdsa
import httpx
from ic.agent import Agent
from ic.canister import Canister
from ic.client import Client
from ic.identity import Identity

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
CLI = os.path.join(REPO, "ceremony", "target", "release", "ceremony-cli")
VERIFIER = os.path.join(REPO, "ceremony", "target", "release", "verify-transcript")
SRS = os.path.join(HERE, "sapling-phase1-p14.srs.bin")
BEACON_T = "2026-09-16T12:00:00Z"                 # BEACON.md, section "The rule"
COORDINATOR = "osqjo-zyaaa-aaaad-agxua-cai"
IC_URL = "https://icp-api.io"
DEFAULT_PEM = os.path.expanduser("~/.config/dfx/identity/default/identity.pem")
CHUNK = 1_500_000                                  # under the 2 MB ingress bound, with headroom

# The subset of coordinator.did this script speaks. Kept inline so the script is self-contained.
DID = """
type R = variant { ok : text; err : text };
type PokWire = record { s_g1 : blob; s_delta_g1 : blob; r_delta_g2 : blob };
type Circuit = variant { deposit; transfer };
type ContributionMeta = record {
  beacon : blob; contributor : blob; deposit_delta_hash : blob; deposit_delta_len : nat;
  deposit_pok : PokWire; index : nat; is_beacon : bool; timestamp : int;
  transfer_delta_hash : blob; transfer_delta_len : nat; transfer_pok : PokWire;
};
type CeremonyInfo = record {
  authority : principal; configured : bool; contribution_count : nat; current_turn : opt principal;
  current_turn_started : int; deposit_fixed_hash : blob; deposit_initial_hash : blob; end_time : int;
  finalized : bool; genesis_challenge : blob; honest_count : nat; init_done : bool; now : int;
  phase : text; power : nat32; queue_length : nat; running_challenge : blob; srs_sha256 : blob;
  start_time : int; transfer_fixed_hash : blob; transfer_initial_hash : blob; turn_timeout : int;
};
service : {
  get_ceremony_info : () -> (CeremonyInfo) query;
  get_contribution : (nat) -> (opt ContributionMeta) query;
  get_contribution_chunk : (nat, Circuit, nat, nat) -> (blob) query;
  get_initial_chunk : (Circuit, nat, nat) -> (blob) query;
  begin_beacon_staging : () -> (R);
  upload_contribution_chunk : (Circuit, blob) -> (R);
  submit_beacon : (blob, PokWire, PokWire) -> (R);
  abort_contribution : () -> (R);
}
"""


class PatientClient(Client):
    """ic-py's Client posts with httpx's 5-second default, which a 1.5 MB chunk query on mainnet
    exceeds. Same three endpoints, a timeout sized for the payloads, and bounded retries on
    transport errors only (an HTTP-level rejection is returned as-is for the agent to report)."""

    TIMEOUT = httpx.Timeout(180.0, connect=30.0)
    ATTEMPTS = 4

    def _post(self, endpoint, data):
        last = None
        for attempt in range(1, self.ATTEMPTS + 1):
            try:
                return httpx.post(endpoint, data=data, headers={"Content-Type": "application/cbor"},
                                  timeout=self.TIMEOUT)
            except httpx.TransportError as e:
                last = e
                log(f"  transport error ({e.__class__.__name__}), attempt {attempt}/{self.ATTEMPTS}")
                time.sleep(2 * attempt)
        raise last

    def query(self, canister_id, data):
        return self._post(self.url + "/api/v2/canister/" + canister_id + "/query", data).content

    def call(self, canister_id, req_id, data):
        self._post(self.url + "/api/v2/canister/" + canister_id + "/call", data)
        return req_id

    def read_state(self, canister_id, data):
        return self._post(self.url + "/api/v2/canister/" + canister_id + "/read_state", data).content


class LowSIdentity(Identity):
    """ic-py signs secp256k1 requests with whatever `s` the `ecdsa` library produces. The IC's
    verifier rejects a high-S signature (s > n/2), which is about half of them, with
    "EcdsaSecp256k1 signature could not be verified". dfx normalizes; this does the same:
    s -> n - s whenever s > n/2. Measured on a local replica: raw high-S 0/7 accepted,
    normalized 12/12."""

    @staticmethod
    def from_pem(pem):
        base = Identity.from_pem(pem)
        if base.key_type != "secp256k1":
            return base
        self = LowSIdentity(privkey=base._privkey, type="secp256k1")
        return self

    def sign(self, msg):
        pub, sig = super().sign(msg)
        if self.key_type == "secp256k1" and sig is not None:
            n = ecdsa.SECP256k1.order
            r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
            if s > n // 2:
                sig = r.to_bytes(32, "big") + (n - s).to_bytes(32, "big")
        return pub, sig


def log(msg):
    print(msg, flush=True)


def die(msg, code=1):
    print(f"error: {msg}", file=sys.stderr, flush=True)
    sys.exit(code)


def as_bytes(x):
    return bytes(x) if not isinstance(x, (bytes, bytearray)) else bytes(x)


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def coordinator(host, canister_id, pem=None):
    ident = LowSIdentity.from_pem(open(pem).read()) if pem else Identity(anonymous=True)
    agent = Agent(ident, PatientClient(host))
    return Canister(agent=agent, canister_id=canister_id, candid=DID), ident


def info(c):
    return c.get_ceremony_info()[0]


def result(r, what):
    """Unwrap the coordinator's `R` variant or fail loudly."""
    v = r[0]
    if "ok" in v:
        return v["ok"]
    die(f"{what}: coordinator refused: {v.get('err')}")


def circuit(name):
    return {name: None}


def pull(fetch, total, label):
    """Read `total` bytes through a chunked query, verifying we got exactly that many."""
    out = bytearray()
    while len(out) < total:
        want = min(CHUNK, total - len(out))
        piece = as_bytes(fetch(len(out), want)[0])
        if not piece:
            die(f"{label}: short read at offset {len(out)} of {total}")
        out += piece
    if len(out) != total:
        die(f"{label}: read {len(out)} bytes, expected {total}")
    return bytes(out)


def pull_until_end(fetch, label):
    """For the initial parameters, whose length the coordinator does not publish: read to EOF."""
    out = bytearray()
    while True:
        piece = as_bytes(fetch(len(out), CHUNK)[0])
        out += piece
        if len(piece) < CHUNK:
            break
    if not out:
        die(f"{label}: empty")
    return bytes(out)


def pok_hex(p):
    return (as_bytes(p["s_g1"]).hex(), as_bytes(p["s_delta_g1"]).hex(), as_bytes(p["r_delta_g2"]).hex())


# ------------------------------------------------------------------------------------------ export


def cmd_export(args):
    c, _ = coordinator(args.host, args.canister)
    os.makedirs(args.parts, exist_ok=True)
    inf = info(c)
    count = int(inf["contribution_count"])
    log(f"coordinator {args.canister}: power={inf['power']} contributions={count} "
        f"finalized={inf['finalized']} phase={inf['phase']}")

    for name, hash_key in (("transfer", "transfer_initial_hash"), ("deposit", "deposit_initial_hash")):
        b = pull_until_end(lambda off, n: c.get_initial_chunk(circuit(name), off, n), f"initial {name}")
        want = as_bytes(inf[hash_key]).hex()
        if sha256(b) != want:
            die(f"initial {name}: sha256 {sha256(b)} != coordinator's {want}")
        open(os.path.join(args.parts, f"initial_{name}.wire"), "wb").write(b)
        log(f"  initial_{name}.wire {len(b):,} B  sha256 ok")

    rows = []
    for i in range(count):
        m = c.get_contribution(i)[0]
        if m is None:
            die(f"contribution {i} missing")
        m = m[0] if isinstance(m, list) else m
        if int(m["index"]) != i:
            die(f"contribution {i}: coordinator reports index {m['index']}")
        for name in ("transfer", "deposit"):
            total = int(m[f"{name}_delta_len"])
            b = pull(lambda off, n: c.get_contribution_chunk(i, circuit(name), off, n), total, f"c{i} {name}")
            want = as_bytes(m[f"{name}_delta_hash"]).hex()
            if sha256(b) != want:
                die(f"c{i} {name}: sha256 {sha256(b)} != coordinator's {want}")
            open(os.path.join(args.parts, f"c{i}_{name}.wire"), "wb").write(b)
        rows.append([
            str(i), as_bytes(m["contributor"]).hex(), str(int(m["timestamp"])),
            "true" if m["is_beacon"] else "false", as_bytes(m["beacon"]).hex(),
            *pok_hex(m["transfer_pok"]), *pok_hex(m["deposit_pok"]),
        ])
        log(f"  c{i}: {'BEACON' if m['is_beacon'] else 'contribution'} transfer {int(m['transfer_delta_len']):,} B "
            f"deposit {int(m['deposit_delta_len']):,} B  sha256 ok")

    with open(os.path.join(args.parts, "manifest.tsv"), "w") as f:
        f.write(f"{int(inf['power'])}\t{'true' if inf['finalized'] else 'false'}\n")
        for r in rows:
            assert len(r) == 11
            f.write("\t".join(r) + "\n")
    log(f"wrote {args.parts}/manifest.tsv ({count} row(s), finalized={inf['finalized']})")
    return inf


# ------------------------------------------------------------------------------------------ submit


def load_emitted(emit_dir):
    metas = sorted(f for f in os.listdir(emit_dir) if f.endswith("_meta.json"))
    if len(metas) != 1:
        die(f"{emit_dir}: expected exactly one c<i>_meta.json, found {metas}")
    meta = json.load(open(os.path.join(emit_dir, metas[0])))
    i = int(meta["index"])
    wires = {}
    for name in ("transfer", "deposit"):
        b = open(os.path.join(emit_dir, f"c{i}_{name}.wire"), "rb").read()
        if sha256(b) != meta[f"{name}_delta_sha256"]:
            die(f"{emit_dir}: c{i}_{name}.wire does not match its recorded sha256")
        wires[name] = b
    return i, meta, wires


def pok_arg(p):
    return {"s_g1": bytes.fromhex(p["s_g1"]), "s_delta_g1": bytes.fromhex(p["s_delta_g1"]),
            "r_delta_g2": bytes.fromhex(p["r_delta_g2"])}


def beacon_verified(beacon, t):
    r = subprocess.run([sys.executable, os.path.join(HERE, "icp-beacon.py"), "verify", beacon, t],
                       capture_output=True, text=True)
    log(r.stdout.strip())
    return r.returncode == 0 and "BEACON VALID" in r.stdout


def cmd_submit(args):
    i, meta, wires = load_emitted(args.emit)
    beacon = args.beacon.encode()
    if not meta["is_beacon"]:
        die(f"emitted step {i} is not a beacon step")
    if meta["beacon_hex"] != beacon.hex():
        die(f"emitted step carries beacon {bytes.fromhex(meta['beacon_hex'])!r}, not {args.beacon!r}")

    if args.rehearsal:
        log("REHEARSAL: the beacon string is NOT checked against the ICP ledger")
    else:
        if not beacon_verified(args.beacon, args.beacon_t):
            die("beacon does not verify against the ICP ledger; refusing to finalize")

    c, ident = coordinator(args.host, args.canister, args.pem)
    me = ident.sender().to_str()
    inf = info(c)
    log(f"coordinator {args.canister}: contributions={inf['contribution_count']} finalized={inf['finalized']} "
        f"queue={inf['queue_length']} phase={inf['phase']}")
    if str(inf["authority"]) != me:
        die(f"identity {me} is not the ceremony authority {inf['authority']}")
    if not inf["init_done"] or inf["finalized"]:
        die("coordinator is not accepting a beacon (not initialized, or already finalized)")
    if int(inf["now"]) <= int(inf["end_time"]) and int(inf["queue_length"]) > 0:
        die("window still open and queue not empty: submit_beacon would be refused")
    if int(inf["contribution_count"]) != i:
        die(f"emitted step is index {i} but the coordinator holds {inf['contribution_count']} contributions; "
            f"re-export and recompute the beacon step on the current head")

    log(f"begin_beacon_staging as {me} ...")
    result(c.begin_beacon_staging(), "begin_beacon_staging")
    try:
        for name in ("transfer", "deposit"):
            b = wires[name]
            n = (len(b) + CHUNK - 1) // CHUNK
            for k in range(n):
                piece = b[k * CHUNK:(k + 1) * CHUNK]
                t0 = time.time()
                result(c.upload_contribution_chunk(circuit(name), piece), f"upload {name} chunk {k + 1}/{n}")
                log(f"  uploaded {name} chunk {k + 1}/{n} ({len(piece):,} B, {time.time() - t0:.1f}s)")
        log(f"submit_beacon({args.beacon!r}) ...")
        msg = result(c.submit_beacon(beacon, pok_arg(meta["transfer_pok"]), pok_arg(meta["deposit_pok"])),
                     "submit_beacon")
    except SystemExit:
        log("aborting the staging slot ...")
        try:
            c.abort_contribution()
        except Exception as e:  # the failure being reported is the one that matters
            log(f"  abort_contribution: {e}")
        raise
    log(f"coordinator: {msg}")
    if not msg.startswith("FINALIZED"):
        die(f"submit_beacon returned ok but not FINALIZED: {msg!r}")

    inf = info(c)
    m = c.get_contribution(i)[0]
    m = m[0] if isinstance(m, list) else m
    checks = {
        "finalized = true": bool(inf["finalized"]),
        f"contribution_count = {i + 1}": int(inf["contribution_count"]) == i + 1,
        f"contribution {i} is the beacon step": m is not None and bool(m["is_beacon"]),
        "recorded beacon bytes match": m is not None and as_bytes(m["beacon"]) == beacon,
        "recorded transfer delta hash matches": m is not None and as_bytes(m["transfer_delta_hash"]).hex() == meta["transfer_delta_sha256"],
        "recorded deposit delta hash matches": m is not None and as_bytes(m["deposit_delta_hash"]).hex() == meta["deposit_delta_sha256"],
    }
    bad = [k for k, v in checks.items() if not v]
    for k, v in checks.items():
        log(f"  [{'OK ' if v else 'BAD'}] {k}")
    if bad:
        die("post-submit checks failed: " + ", ".join(bad))
    log("SUBMITTED: the coordinator is finalized with the beacon step")


# --------------------------------------------------------------------------------------------- run


def sh(cmd, what, cwd=REPO):
    log(f"$ {' '.join(os.path.basename(x) if x.startswith('/') else x for x in cmd)}")
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
    out = (r.stdout + r.stderr).strip()
    log("  " + out.replace("\n", "\n  "))
    if r.returncode != 0:
        die(f"{what} failed (exit {r.returncode})")
    return out


def vk_hashes(verifier_out):
    t = d = None
    for line in verifier_out.splitlines():
        if "transfer vk SHA-256" in line:
            t = line.split(":")[-1].strip()
        if "deposit  vk SHA-256" in line or "deposit vk SHA-256" in line:
            d = line.split(":")[-1].strip()
    if not t or not d:
        die("could not read the vk hashes from the verifier output")
    return t, d


def cmd_run(args):
    for p, what in ((CLI, "ceremony-cli"), (VERIFIER, "verify-transcript"), (SRS, "SRS")):
        if not os.path.exists(p):
            die(f"{what} not found at {p}")
    w = os.path.abspath(args.workdir)
    os.makedirs(w, exist_ok=True)
    parts, parts_final, emit = (os.path.join(w, x) for x in ("parts", "parts-final", "emit"))
    pre, post, final = (os.path.join(w, x) for x in ("pre.transcript.bin", "post.transcript.bin", "final.transcript.bin"))

    log("=== 1. export the transcript as the chain holds it now")
    inf = cmd_export(argparse.Namespace(host=args.host, canister=args.canister, parts=parts))
    if inf["finalized"]:
        die("the coordinator is already finalized")
    count = int(inf["contribution_count"])

    log("=== 2. assemble + verify it (must be VALID and unfinalized)")
    sh([CLI, "assemble-transcript", SRS, parts, pre], "assemble-transcript")
    out = sh([VERIFIER, SRS, pre], "verify-transcript (pre)")
    if "TRANSCRIPT VALID" not in out or "finalized (beacon)   : false" not in out:
        die("pre-finalize transcript is not VALID+unfinalized")

    log(f"=== 3. apply the beacon locally: step {count}")
    shutil.copyfile(pre, post)
    sh([CLI, "finalize", SRS, post, args.beacon], "ceremony-cli finalize")
    out_local = sh([VERIFIER, SRS, post], "verify-transcript (locally finalized)")
    if "TRANSCRIPT VALID" not in out_local or "finalized (beacon)   : true" not in out_local:
        die("locally finalized transcript does not verify")
    local_vk = vk_hashes(out_local)

    log("=== 4. emit the beacon step in wire form")
    sh([CLI, "emit-contribution", post, str(count), emit], "emit-contribution")

    log("=== 5. stage + submit_beacon")
    cmd_submit(argparse.Namespace(host=args.host, canister=args.canister, pem=args.pem, emit=emit,
                                  beacon=args.beacon, rehearsal=args.rehearsal, beacon_t=args.beacon_t))

    log("=== 6. re-export from the chain and verify with --selfcheck")
    inf2 = cmd_export(argparse.Namespace(host=args.host, canister=args.canister, parts=parts_final))
    if not inf2["finalized"] or int(inf2["contribution_count"]) != count + 1:
        die("chain state after submit is not finalized with one more contribution")
    sh([CLI, "assemble-transcript", SRS, parts_final, final], "assemble-transcript (final)")
    out_chain = sh([VERIFIER, SRS, final, "--selfcheck"], "verify-transcript --selfcheck (final)")
    ok = ("TRANSCRIPT VALID" in out_chain and "finalized (beacon)   : true" in out_chain
          and "KEYS WORK" in out_chain)
    chain_vk = vk_hashes(out_chain)

    log("=== verdict")
    log(f"  local  vk: transfer {local_vk[0]}  deposit {local_vk[1]}")
    log(f"  chain  vk: transfer {chain_vk[0]}  deposit {chain_vk[1]}")
    if not ok:
        die("the from-chain final transcript did not pass --selfcheck")
    if local_vk != chain_vk:
        die("verifying keys from the local finalize and from the chain DISAGREE")
    log(f"FINALIZED AND VERIFIED FROM THE CHAIN: {count + 1} steps, final transcript at {final}")
    if args.rehearsal:
        log("(rehearsal: the beacon string was not checked against the ICP ledger)")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--canister", default=COORDINATOR)
    ap.add_argument("--host", default=IC_URL)
    ap.add_argument("--pem", default=DEFAULT_PEM, help="authority identity PEM (submit/run)")
    ap.add_argument("--beacon-t", default=BEACON_T, help="the published T the beacon must resolve from")
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("export"); e.add_argument("parts")
    s = sub.add_parser("submit"); s.add_argument("emit"); s.add_argument("beacon")
    s.add_argument("--rehearsal", action="store_true", help="skip the ledger check of the beacon (local replica only)")
    r = sub.add_parser("run"); r.add_argument("beacon"); r.add_argument("workdir")
    r.add_argument("--rehearsal", action="store_true", help="skip the ledger check of the beacon (local replica only)")
    args = ap.parse_args()
    if getattr(args, "rehearsal", False) and not is_loopback(args.host):
        die(f"--rehearsal skips the ledger check of the beacon and is only accepted against a loopback host, "
            f"not {args.host}; submit_beacon on the live coordinator is one-shot")
    {"export": cmd_export, "submit": cmd_submit, "run": cmd_run}[args.cmd](args)


def is_loopback(host):
    from urllib.parse import urlsplit
    h = (urlsplit(host).hostname or "").lower()
    return h in ("127.0.0.1", "::1", "localhost")


if __name__ == "__main__":
    main()
