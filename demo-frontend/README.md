# Shielded-Pool Public Demo; "privacy you can watch"

An interactive demo that makes the privacy of the shielded ledger **visible**: two in-browser
users move a demo token privately, next to a live panel showing the exact raw state a node
provider running the ledger can (and cannot) read. Menese DeFi Team. Runs locally or as the
explicitly valueless mainnet DEMO.

All privacy-critical crypto runs **client-side** in WebAssembly: note secrets, commitment /
nullifier derivation, the Merkle tree rebuilt from the public commitment log, Groth16 proving
(BLS12-381), and the LWE PIR client. The ledger only verifies; with the in-process Motoko
verifier this demo's ledger already uses.

## Panels

1. **Alice / Bob split screen**; fresh in-browser Ed25519 identities; faucet → shield →
   private transfer → balances update.
2. **What the node provider sees**; live raw canister state: the public ICRC-3 note blocks
   (commitments, nullifiers, opaque ciphertext). No amount, balance, or sender→recipient field
   exists anywhere.
3. **Private lookup (PIR)**; encrypted selectors leave the browser (no index on the wire), the
   ledger runs a uniform scan (`records_scanned` = all, `target_dependent_branches` = 0), and the
   answer is decrypted client-side. "The ledger answered without knowing the question."
4. **Unshield**; the user chooses the amount; the proof binds both that amount and the exact
   recipient account. The token transfer is reconciled before nullifiers and change are finalized.

## Client-side proving

The pool `TransferCircuit` (20,146 constraints) and `DepositCircuit` are compiled to wasm via
`wasm-pack` (`prover-wasm/`). Measured in-browser: deposit proof ~0.3 s, transfer proof ~5 s;
feasible, no server-side proving. Proofs are verified in-canister by the Motoko verifier.

## Build & run (local)

Prerequisites: `dfx`, `wasm-pack`, `node`, and the BLS12-381 pool fixtures + proving keys.

```bash
# 1. Generate a DEMO keyset with setup randomness drawn directly from the OS CSPRNG:
#    (in ../circuit)
#    cargo run --release -p gen --features bls12-381 -- /tmp/picp-keyset \
#      --setup os-csprng-single-party
#    Copy transfer_pk.bin, deposit_pk.bin, transfer_vk.hex, deposit_vk.hex, and
#    SETUP-MANIFEST.json into public/keys/. The frontend verifies every manifest hash and refuses
#    deterministic test-setup artifacts. This removes the published-seed flaw, but a real-value
#    launch still requires a separately verified multi-party ceremony transcript; see
#    ../docs/TRUSTED-SETUP-POLICY.md.
# 2. Build the WASM prover and candid declarations:
cd prover-wasm && wasm-pack build --target web --release --out-dir ../src/prover-pkg && cd ..
dfx generate zk_ledger && dfx generate demo_token
# 3. Start the demo replica, deploy + configure:
dfx start --clean            # binds 127.0.0.1:4955 (see dfx.json)
./scripts/redeploy.sh        # deploys + configures the ledger with the manifest-bound vks + DEMO token
# 4. Run the frontend:
npm install && npm run dev   # http://localhost:5178
```

`npm run verify:keyset` accepts the OS-CSPRNG keyset for this valueless DEMO. The production gate,
`npm run verify:keyset:production`, intentionally fails until an independently verified MPC
ceremony keyset and transcript replace it.

## Verify

`node verify.mjs` drives the whole story headless (Playwright) and screenshots every panel to
`verify-shots/`: faucet → 2 shields → private transfer → PIR match (`target_dependent_branches=0`)
→ custom-amount, recipient-bound unshield. Asserts the provider pane never renders an amount field.
