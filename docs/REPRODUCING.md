# Reproducing and checking the ceremony

This page is for someone deciding whether to trust the ceremony enough to contribute a secret to
it, or auditing it afterwards. It lists every check you can run, in order, with the command and the
output you should get. Nothing here asks you to take our word for a value we could have chosen.

It also tells you, in section 5, about the one check that does **not** work yet. That section is
not buried, because a verification page that only lists its successes is marketing.

Read [`CEREMONY.md`](CEREMONY.md) first if you have not: section 3 is the trust model, section 8 is
what the ceremony does not give you even when every check below passes.

## 0. What you need

```
dfx 0.32.0            the checks call it; a different dfx computes different module hashes
python3               for the published-page check
```

Only for section 5, and only if you want to build the client yourself:

```
rustc 1.95.0          pinned by demo-frontend/contributor-wasm/rust-toolchain.toml
wasm-pack 0.13.1
wasm-opt 123          (binaryen); its version changes the output bytes
```

The versions are exact on purpose. A compiler bakes its own identity into what it emits, so a
different toolchain produces a different hash from identical source, and you would not be able to
tell that apart from tampering. `demo-frontend/contributor-wasm/Dockerfile` pins all three if you
would rather not install them.

Clone the commit you intend to review, and run everything from that checkout — several checks
compare the live deployment against your working tree, so they mean exactly as much as the tree you
point them at.

## 1. The coordinator is this source

```bash
coordinator/verify-build.sh
```

Expected:

```
REPRODUCIBLE BUILD VERIFIED: coordinator wasm hash matches source.
```

with `expected` and `actual` both `ce34f578fa583f9ff785f3a9c235d801b7fd36dde50e1db985c7e6cefc6fe616`.

Then confirm the canister taking contributions is that binary:

```bash
dfx canister info osqjo-zyaaa-aaaad-agxua-cai --network ic
```

The `Module hash` must equal the value above. If it does, the coordinator receiving your
contribution is the code in this repository and not something else wearing its id.

If the script reports `TOOLCHAIN MISMATCH`, that is not a tampering finding — it means your dfx or
moc is not the pinned one, and it says so separately for exactly that reason. Reproduce on the pin
before concluding anything.

## 2. Nobody can change the coordinator

The same command prints:

```
Controllers:
```

That line must be **empty**. The coordinator is blackholed: it has no controllers, so no key — ours,
yours, or a stolen one — can upgrade it. This is what stops the transcript being rewritten after
contributors have relied on it. If that line ever lists a principal, the property is gone, and you
should not treat the transcript as append-only.

## 3. The page is a stock asset canister

```bash
dfx canister info ovrp2-uaaaa-aaaad-agxuq-cai --network ic
```

Module hash must be
`04e565b3425fe7510ee16b02adcfe3f01abc9a2725c82a21cb08969241debd62`, which is dfx 0.32.0's own
`assetstorage.wasm.gz`. Reproduce it by running `dfx deploy` for any asset canister on dfx 0.32.0
and hashing `.dfx/<network>/canisters/<name>/assetstorage.wasm.gz`.

This one matters more than it looks. The standard asset canister serves the same certified content
to everyone. A bespoke canister could serve one script to an auditor and a different one to a
contributor, and no amount of checking the version *you* were served would detect it.

Unlike the coordinator, this canister **does** have a controller. That is deliberate — the page has
to be fixable — and it is why section 4 exists.

## 4. The page serves exactly this repository

```bash
python3 scripts/verify-published-page.py
```

Expected, from a fresh clone:

```
  matched 3   matched against the build record 5   discrepancies 0
=== PASS: the published page serves exactly this source ===
```

The check runs in **both** directions: every file in the repository must be served with a matching
hash, and every asset served must exist in the repository. The second direction is the one that
catches an attack — a page with one extra script appended passes a naive "are my files there?"
check and fails this one.

Note the two categories in that output, because they are not equally strong:

- **`match`** — the served bytes equal a file in your checkout. You verified this yourself.
- **`match*`** — the served bytes equal a hash recorded in
  `demo-frontend/contributor-wasm/PKG-HASHES.txt`. Those are the compiled client, which is not
  committed (you should build it, not receive it). This proves the page has not changed since that
  record was published. It does **not** prove the record follows from the source. Section 5 is why.

## 5. The client that samples your secret

This is the wasm that generates your secret, mixes it into the parameters, and destroys it — the
artifact you have the most reason to check.

```bash
demo-frontend/contributor-wasm/verify-build.sh
```

Expected:

```
  A matches PKG-HASHES.txt
  B matches PKG-HASHES.txt (checkout at /tmp/…/elsewhere)
REPRODUCIBLE BUILD VERIFIED: the contributor wasm rebuilds to the published hashes from
two checkouts at different paths, so the result does not depend on where you cloned it.
```

It builds twice — once from your checkout, once from a copy of it at a different path — and both
must match. Together with section 4 that closes the chain: source → binary → the bytes the live
page serves. Neither half is sufficient alone. Section 4 alone would compare the page against a
binary you were handed; this alone would not tell you the page serves it.

**The build path is part of the hash, and this is the part that surprises people.** Cargo derives
each crate's `-C metadata` — which seeds every symbol name — from the package's absolute path.
`--remap-path-prefix` does not reach it, because it is Cargo's input to rustc rather than something
rustc emits. So the same source compiled in a different directory produces a different binary: six
checkouts at six paths gave six distinct wasm files here. `build.sh --canonical` stages the sources
to a fixed path (`/src`, override with `ZK_CANONICAL_SRC`) so your hash is comparable with anyone
else's, and the Dockerfile does the same with a fixed `WORKDIR`. `verify-build.sh` uses `--canonical`
for you.

To build it yourself without the verifier:

```bash
demo-frontend/contributor-wasm/build.sh --canonical /tmp/my-pkg
```

The script prints each output's SHA-256 and tells you whether it matched `PKG-HASHES.txt`. If you
build **without** `--canonical`, it warns you and the hash will not match — that is expected, not a
finding.

**How to read a mismatch.** In order of likelihood:

1. **You built without `--canonical`.** The script warns when you do. Re-run with it.
2. **Your toolchain is not the pinned one.** `verify-build.sh` says `TOOLCHAIN MISMATCH` and exits
   3 rather than calling it a source mismatch, because those mean opposite things. Use the
   Dockerfile.
3. **Neither of those.** Then it is a real finding. Do not reason your way past it, and do not
   accept a tool that offers to: a small difference is not reassuring, because the bytes most
   likely to move are pointers, and repointing a constant is precisely the shape a malicious edit
   takes. Report it with the output.

**Read it as well as build it**, because this is the claim no hash can make for you.
`demo-frontend/contributor-wasm/src/lib.rs` is 133 lines, and the property that matters is visible
in its shape. The module exports exactly two functions, and neither returns a contribution secret:

- `transform_contribution(current_transfer_wire, current_deposit_wire, prev_challenge)` returns a
  JSON string of transformed **public** parameters and their proofs of knowledge. The two secrets
  are sampled inside that call, used, and dropped before it returns — they are never stored,
  returned, or logged.
- `random_nonce_hex()` returns a fresh 32-byte hex string for the UI (an anti-CSRF nonce). It is an
  independent draw from the browser CSPRNG: not the contribution secret, and not derived from it.

Because no export returns the secret, there is no path by which any JavaScript on that page could
send it anywhere, however that JavaScript behaves. That is a claim you confirm by reading two
function signatures, not by trusting a hash — which is why it is worth stating separately from
everything above.

## 6. Verifying the ceremony result

Contributing is separate from checking the outcome. To verify the transcript rather than the
deployment, download the Phase-1 SRS and the published transcript and run the standalone verifier:
it re-derives the opening parameters, replays every contribution, checks each proof of knowledge
and the full cross-point consistency, checks the chaining and the beacon finalize, then proves and
verifies a real transfer and deposit against the final keys. `CEREMONY.md` section 5 has the
commands.

Being appended to the chain is **not** confirmation that a contribution's proof checked out — the
coordinator's on-chain acceptance is structural only. The soundness-critical checks run off-chain,
in a verifier that shares no code with the coordinator's acceptance path.

## 7. If a check fails

Open an issue with the command you ran, its full output, the commit you checked out, and your
toolchain versions. A toolchain mismatch and a source mismatch are different findings and the
scripts label them differently — say which one you got. Do not contribute a secret through a page
whose checks you could not make pass.
