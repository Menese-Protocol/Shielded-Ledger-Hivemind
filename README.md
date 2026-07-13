# Menese Shielded Ledger; Hivemind

A shielded token pool that runs entirely on the Internet Computer. Groth16 proofs are verified
inside the canister, in Motoko; notes and keys never leave the user's browser; private lookups
are answered by a ledger that never learns the question.

**Live demo: https://nl5gm-2aaaa-aaaau-ag27q-cai.icp0.io/**

Two browsers, two users, a private transfer, and a live panel showing exactly what a node
provider can and cannot see.

*Privacy you can watch.*

## Why this exists

Every public ledger publishes who paid whom, how much, forever. That is not an acceptable
property for money. A shielded pool changes what gets written: amounts, balances, and the
sender-to-recipient link do not exist in any readable form. Not encrypted and held by someone;
never written at all.

Building this on the Internet Computer carries one constraint most chains do not have: there is
no native pairing precompile. A zero-knowledge verifier has to be written in the canister
language itself, and a full verification has to fit inside a single message's instruction
ceiling. This repository is that verifier, the ledger built around it, and the demo that lets
anyone watch it work.

## What is in this repository

- **`src/`**: the shielded ledger canister (Motoko). Verified shield deposits, 2-in/2-out
  confidential transfers, nullifier replay protection, recipient-bound withdrawals reconciled
  against the exact ICRC-1 payout block, certified root publication, opaque `zknote1` ICRC-3
  blocks, and an LWE PIR query endpoint.
- **`src/groth16/`**: a complete Groth16 verifier over BLS12-381, written in Motoko. Field
  tower, curve operations, subgroup validation, compressed-point decoding, an inversion-free
  multi-Miller loop, and a cyclotomic final exponentiation. No FFI, no precompile, no host
  function; it runs in-process, inside the ledger's own message.
- **`circuit/`**: the transfer and deposit circuits (arkworks 0.5, Rust), the deterministic
  test-vector generator, and the frozen public fixtures.
- **`verifier-lab/`**: the verifier's independent test batteries; differential tests against a
  pure-`Nat` reference implementation, pinned arkworks oracle vectors, and forgery batteries.
- **`demo-frontend/`**: the public demo. All privacy-critical cryptography runs client-side in
  WebAssembly: note secrets, commitment and nullifier derivation, the Merkle tree rebuilt from
  the public commitment log, Groth16 proving, and the PIR client. Shielded keys derive from
  Internet Identity through vetKeys and live only in memory.
- **`scripts/security-gate.sh`**: one command that re-runs the full offline security battery.
- **`nns_adapter/`, `tree_oracle/`, `icrc3_oracle/`, `cert_oracle/`**: the certified
  NNS-to-ICRC-3 adapter and the native Rust oracles the tests compare against.

## How the pool works

Value enters the pool as notes. A note is a Poseidon commitment to an amount and its owner's
keys. The ledger publishes commitments and nullifiers; nothing else. A transfer is a Groth16
proof of one statement: two notes I own and have not spent exist in the tree, and the two new
commitments conserve their value. The canister checks the proof with its in-process verifier,
records the nullifiers, appends the new commitments, and learns nothing about amounts, owners,
or which notes were spent.

Withdrawals are bound to their recipient inside the proof. The transfer statement carries eight
public inputs (`anchor, nf1, nf2, cm_out1, cm_out2, fee, v_pub_out, recipient_binding`), so a
withdrawal proof is valid only for the exact ICRC account it names. The canister pays that
account, verifies the exact payout block on the token ledger, and only then finalizes. Change
one byte of any public input, or any of the 192 proof bytes, and verification fails; the
security gate mutates every one of them to prove it.

*The proving key never touches a server.*

Proofs are produced in the user's browser. The transfer circuit is 20,146 constraints and
proves in about 5 seconds in browser WebAssembly; a deposit proves in about 0.3 seconds.

## Where the keys live

Shielded keys are never written to browser storage.

Sign in with Internet Identity and the shielded keys are derived through the IC's vetKeys: the
directory canister issues a deterministic, principal-bound vetKey, encrypted to a fresh one-use
transport key the browser generates for that session. The browser verifies the encrypted key
and derives the spend and note-opening keys in memory. Close the tab and the keys are gone;
sign in with the same Internet Identity on any device and the identical keys derive again, and
a rescan of the public commitment log recovers every note you own. Instant trial identities are
memory-only by design and vanish with the tab.

## What the node provider sees

Most ledgers answer this question with a privacy policy. This one answers it with a panel.

Open the demo and watch the raw canister state: commitments, nullifiers, opaque ciphertext.
There is no amount field, no balance table, no sender and no recipient anywhere in state. After
a private transfer the demo stamps the public record plainly: nothing was written here.

## Private lookups; PIR

Reading your own money can leak as much as spending it. A wallet that asks the ledger for
record 217 has told the ledger which record it cares about. This wallet does not ask.

The ledger exposes an LWE-based private information retrieval endpoint, `pir_query_lwe`. The
client encrypts its selector, so no index travels on the wire; the ledger performs the same
uniform scan over every record regardless of the target; the client decrypts the answer
locally. Every response reports `records_scanned` (always all of them) and
`target_dependent_branches` (always zero), and the security gate asserts both.

*The ledger answers without knowing the question.*

## The verifier, and what it costs

The verifier is built in two layers. **L1** is a pure-`Nat` reference: every field and curve
operation written the plainest way and validated against arkworks oracle vectors. **L2** is the
optimized layer: Montgomery (REDC) field arithmetic, Jacobian scalar multiplication, an
inversion-free projective Miller loop with reusable G2 preparation, and one shared cyclotomic
final exponentiation across all four pairings. Every L2 module is differentially tested against
L1 on the same inputs, with live formula mutants that must turn the tests red before the
optimization is accepted. Optimizations earn their place by measurement, not by argument.

Measured on the Internet Computer, per verification, garbage collection included:

| statement | instructions | share of the 40B message ceiling |
|---|---|---|
| assembled Groth16 verify (bare statement) | 9.24B | 23.1% |
| pool transfer / withdraw verify (8 public inputs) | 12.57B | 31.4% |
| pool deposit (shield) verify | 10.12B | 25.3% |

A complete Groth16 verification runs in Motoko inside a single message.

## The security gate

```bash
mops install
./scripts/security-gate.sh
```

One command, offline, no canister installs. It re-verifies: SHA-256 integrity of every frozen
fixture; byte-identity of the vendored circuit source; deterministic regeneration of every
public test vector; randomized circuit-property batteries and the Groth16 mutation battery
(all eight public inputs and every one of the 192 compressed proof bytes); the independent
Motoko curve, pairing, and wire oracles; ICRC-3 official hash vectors and exact-block matching;
the canister compile gates and the DEMO token API boundary; key provenance with negative
controls; and a production frontend build booted in a real browser. `--with-replica-e2e`
additionally runs the stateful local-replica suite.

## Trusted setup; read this before you trust it

Groth16 requires a trusted setup, and this repository refuses to hide that behind small print.
A setup produces toxic waste: whoever holds it can forge proofs and mint value out of thin air,
undetectably. The policy here is explicit:

- The checked-in fixtures use a **deterministic test setup with public randomness**; loudly
  labeled, deployment-forbidden, rejected by the frontend.
- The live demo uses a **single-party OS-CSPRNG setup**. Its manifest states what it is:
  `real_value_eligible: false`. You are trusting one machine, and for a valueless demo token
  that is exactly as far as trust should stretch.
- A real-value launch requires a **multi-party ceremony**: many independent contributors, each
  mixing in secret randomness and destroying it, so that a single honest participant makes
  forgery impossible forever. Our team is actively working through that ceremony's design now;
  participant recruitment, tooling, the public transcript, and how the final verifying key is
  ratified on-chain. The full acceptance checklist a production keyset must pass is in
  [`docs/TRUSTED-SETUP-POLICY.md`](docs/TRUSTED-SETUP-POLICY.md), and the production key gate
  in this repository intentionally fails until a reviewed ceremony transcript exists.

*The ceremony comes before the money.*

## Running it yourself

Prerequisites: `dfx`, Rust with the `wasm32-unknown-unknown` target, `wasm-pack`, `node`,
[`mops`](https://mops.one), Python 3.

```bash
# ledger + tests
mops install
sha256sum -c fixtures/SHA256SUMS
dfx start --clean          # second terminal: dfx deploy && python3 e2e.py

# demo frontend (full walkthrough in demo-frontend/README.md)
cd demo-frontend
cd prover-wasm && wasm-pack build --target web --release --out-dir ../src/prover-pkg && cd ..
npm install && npm run dev
```

`node demo-frontend/verify.mjs` drives the entire two-user story headless: faucet, shields,
private transfer, PIR lookup, recipient-bound withdrawal; it screenshots every step.

## Status and boundaries

This is a working system and a valueless demo, and the difference is stated precisely. The DEMO
token has no value; its faucet is open by design. The keyset is single-party. The demo ledger
keeps an administrator-only fault-injection hook so the payout-failure recovery path stays
provable; that surface belongs to the demo classification and must not exist in a real-value
deployment. Before real value: the ceremony above, plus independent review of the circuit, the
verifier, the ledger integration, browser randomness, stable-state upgrades, and key rotation.

*We built the machinery first. The pool holds real value only after the setup deserves it.*

## License

MIT. Built by the Menese DeFi Team, Mercatura Forum; part of the Menese Protocol's
privacy research on the Internet Computer.
