#!/usr/bin/env python3
"""Verify that the published contributor page serves exactly the files in this repository.

    scripts/verify-published-page.py [canister-id] [--network ic]

The contributor page is where a ceremony secret is sampled, so "is the page I am looking at the
page that was reviewed?" is the question that matters most to a participant, and it is one they
should not have to take anyone's word for.

The asset canister publishes a SHA-256 for every asset it serves. This compares each of those
against the file on disk, in BOTH directions:

  * every repository file must be served, and served with a matching hash;
  * every served asset must exist in the repository.

The second direction is the one that catches an attack. A page with one extra script appended
would still pass a naive "do my files appear on the site" check; it fails here.

Note what this does NOT prove. It proves the bytes match this working tree, so run it against a
checkout of the reviewed commit. Combined with the deployed module hash — which for this page is
the stock dfx asset canister, meaning every visitor is served the same certified content — it
closes the gap between "reviewed source" and "what a contributor's browser actually runs".
"""
import hashlib, json, subprocess, sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ASSETS = REPO / "demo-frontend" / "contributor-client"
PKG_HASHES = REPO / "demo-frontend" / "contributor-wasm" / "PKG-HASHES.txt"
DEFAULT_CANISTER = "ovrp2-uaaaa-aaaad-agxuq-cai"

# Emitted by the asset canister itself, not by us; they are not repository files.
CANISTER_GENERATED = {"/.well-known/ic-domains", "/.well-known/ii-alternative-origins"}


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    canister = args[0] if args else DEFAULT_CANISTER
    network = "ic"
    if "--network" in sys.argv:
        network = sys.argv[sys.argv.index("--network") + 1]

    print(f"canister   {canister}")
    print(f"network    {network}")
    print(f"assets     {ASSETS}")

    out = subprocess.run(
        ["dfx", "canister", "call", canister, "list", "(record {})",
         "--network", network, "--query", "--output", "json"],
        capture_output=True, text=True, cwd=REPO, timeout=600,
    )
    if out.returncode != 0:
        print("could not read the asset list:\n" + out.stderr[-600:])
        return 2

    served = {}
    for entry in json.loads(out.stdout):
        key = entry["content_type"] and entry["key"] if "key" in entry else entry.get("key")
        for enc in entry.get("encodings", []):
            # `identity` is the unencoded file; the gzip encoding hashes the compressed bytes and
            # is not comparable to a file on disk.
            if enc.get("content_encoding") != "identity":
                continue
            sha = enc.get("sha256")
            if not sha:
                continue
            raw = sha[0] if isinstance(sha[0], list) else sha
            served[key] = bytes(raw).hex()

    on_disk = {}
    for p in sorted(ASSETS.rglob("*")):
        if not p.is_file() or p.name.startswith("."):
            continue
        on_disk["/" + str(p.relative_to(ASSETS))] = hashlib.sha256(p.read_bytes()).hexdigest()

    # The compiled client under pkg/ is deliberately not tracked: a ceremony contributor should
    # build it from source rather than receive a binary from us. That stance used to make this
    # check unrunnable for anyone but us -- a fresh clone has no pkg/, so the served wasm looked
    # like an EXTRA asset and the run failed for everybody. The build records its outputs in
    # PKG-HASHES.txt, so a clone can compare against that instead.
    #
    # Be precise about the strength of that link rather than blurring it into one "match": on its
    # own, matching the record proves the page is unchanged since publication, not that the record
    # follows from the source. demo-frontend/contributor-wasm/verify-build.sh is what supplies the
    # other half, by rebuilding those exact hashes from source in two checkouts at different paths.
    recorded = {}
    if PKG_HASHES.exists():
        for line in PKG_HASHES.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            sha, _, name = line.partition("  ")
            if sha and name:
                recorded["/pkg/" + name.strip()] = sha

    ok, via_record, bad = 0, 0, []
    print()
    for key in sorted(set(served) | set(on_disk) | set(recorded)):
        if key in CANISTER_GENERATED:
            print(f"  skip     {key}  (emitted by the asset canister)")
            continue
        s, d, r = served.get(key), on_disk.get(key), recorded.get(key)
        if s is None:
            bad.append(key); print(f"  MISSING  {key}  in the repository but NOT served")
        elif d is not None:
            # A file present on disk always wins over the recorded hash: it is the stronger
            # check, because it is the reader's own bytes rather than our record of them.
            if s != d:
                bad.append(key); print(f"  DIFFERS  {key}\n             served {s}\n             repo   {d}")
            else:
                ok += 1; print(f"  match    {key}  {s[:16]}…")
        elif r is not None:
            if s != r:
                bad.append(key); print(f"  DIFFERS  {key}\n             served   {s}\n             recorded {r}")
            else:
                via_record += 1; print(f"  match*   {key}  {s[:16]}…  (against PKG-HASHES.txt)")
        else:
            bad.append(key); print(f"  EXTRA    {key}  served but NOT in the repository")

    print(f"\n  matched {ok}   matched against the build record {via_record}   discrepancies {len(bad)}")
    if via_record:
        print("  * those assets are the compiled client, which is not tracked by design. This run")
        print("    checked them against demo-frontend/contributor-wasm/PKG-HASHES.txt, which shows")
        print("    the page is unchanged since publication. To also confirm that record follows")
        print("    from the source rather than taking it from us, run:")
        print("      demo-frontend/contributor-wasm/verify-build.sh")
    if bad:
        print("=== FAIL: the published page is not this source ===")
        return 1
    print("=== PASS: the published page serves exactly this source ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
