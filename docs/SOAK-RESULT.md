# Soak result

Randomized, model-checked PocketIC soak of the shielded ledger. Every random element derives from the printed seed; a reviewer re-running with the same seed on the same commit sees the identical operation sequence and final state hash. How to run and what each battery item asserts is in [`../TESTING.md`](../TESTING.md).

The smoke tier below is complete. The full tier (10,000 accounts / 100,000 operations, seed 20260717) runs on this box and its results are appended here on completion. The two tiers run the identical harness and battery; only the account and operation counts differ, both set by environment variables.

## Tier: smoke (200 accounts / 1000 operations)

- seed: `20260717`
- final state hash: `79b23834613849663d843a918b2991a42599ef5d2584eb7b4a6d364f13fcb043`
- wall clock: 1049 s
- moc: Motoko compiler 1.4.1 (source k8r4z8c3-7zqv9is3-l7cx4q5j-651yrgww)
- wasm SHA-256: zk_ledger `2bcad37550920203...`, token `cbb9675c92896dc2...`, tree_oracle `271b4f029e6f3e50...`

Operation mix (accepted):

| kind | count |
|---|---|
| shield | 409 |
| private transfer | 392 |
| unshield | 97 |
| shield fault-recovery (resume_shield) | 0 |
| unshield fault-recovery (resume_unshield) | 1 |
| mid-run upgrades | 3 at ops [374, 482, 753] |
| blocks written | 1389 |
| notes created / spent | 1389 / 980 |

Adversarial injections: 101 total, 101 rejected (100%). By class:

| class | count | one transcript (canister outcome / verifier) |
|---|---|---|
| CounterfeitMint | 17 | `REJECT:turnstile` / `NOT_CALLED` |
| DoubleSpend | 16 | `REJECT:nullifier-spent` / `NOT_CALLED` |
| InsufficientAllowance | 1 | `REJECT:token:InsufficientAllowance` / `ACCEPT` |
| ProofMutation | 18 | `REJECT:proof-deserialize` / `REJECT:proof-deserialize` |
| ProofReplay | 18 | `REJECT:nullifier-spent` / `NOT_CALLED` |
| UnknownAnchor | 16 | `REJECT:unknown-anchor` / `NOT_CALLED` |
| WrongRecipientBinding | 15 | `REJECT:pairing-check` / `REJECT:pairing-check` |

Final solvency: pool_value 1582611915 == token custody 1582611915 == Σ unspent 1582611915.

Battery:

| item | verdict |
|---|---|
| B1 keyset (regenerated SHA == manifest; frozen fixtures verify under regenerated vk) | PASS |
| B2-block-log-vs-model | PASS (1389 blocks field-identical) |
| B3/B7-replayer-phash-chain | PASS (1389 links verified across 3 upgrades) |
| B3-full-population-balances | PASS (all 200 accounts, wallet scan + independent replayer) |
| B4-solvency | PASS (custody == pool_value == unspent == 1582611915, model + replayer) |
| A2-conservation | PASS (pool_value == 2034988372 shielded in - 452376457 paid out) |
| B6-certification | PASS (root-key verified, tip bound to replayer chain hash, 3 tamper controls rejected) |
| B5-adversarial-injections | PASS (101 injected, 100% rejected, all 7 classes exercised) |
| B7-upgrades-under-load | PASS (3 upgrades at ops [374, 482, 753]) |
| B10-keyless-observer | PASS (0/1960 amount hits, 0 principal hits, keyless recognized 0 vs keyed 1389) |
| B11-linkage-cryptanalysis | PASS crypto (a) nf->cm percentile 0.5067 within 0.046 of 0.5, top1 0.00612<=chance 0.00391; (b) same-account 0.5064 within 0.030 of 0.5 |

## Honesty boundary

This suite is a state-machine and value-conservation stress test plus a leakage regression guard. It does not prove circuit soundness against a novel parameter flaw, and it does not prove cryptographic unlinkability; those rest on the trusted-setup policy, the circuit design, and independent review, as stated in the README and `docs/TRUSTED-SETUP-POLICY.md`. The counterfeit-mint (Zcash-2018 class) and keyless-observer items guard the known bug classes, not the unknown ones.

