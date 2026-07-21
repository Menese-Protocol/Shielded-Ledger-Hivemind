# Soak result

Randomized, model-checked PocketIC soak of the shielded ledger. Every random element derives from the printed seed; a reviewer re-running with the same seed on the same commit sees the identical operation sequence and final state hash. How to run and what each battery item asserts is in [`../TESTING.md`](../TESTING.md).

## Tier: smoke (200 accounts / 1000 operations)

- seed: `20260720`
- final state hash: `76a8bf887723bf12e0013c39a3dd43998d8dbd395673f5c711fbcadbc7c42af7`
- wall clock: 807 s
- moc: Motoko compiler 1.4.1 (source k8r4z8c3-7zqv9is3-l7cx4q5j-651yrgww)
- wasm SHA-256: zk_ledger `4e1854ee259fc7c8...`, token `cbb9675c92896dc2...`, tree_oracle `271b4f029e6f3e50...`

Operation mix (accepted):

| kind | count |
|---|---|
| shield | 411 |
| private transfer | 382 |
| unshield | 102 |
| shield fault-recovery (resume_shield) | 1 |
| unshield fault-recovery (resume_unshield) | 0 |
| mid-run upgrades | 3 at ops [367, 447, 534] |
| blocks written | 1380 |
| notes created / spent | 1380 / 968 |

Adversarial injections: 104 total, 104 rejected (100%). By class:

| class | count | one transcript (canister outcome / verifier) |
|---|---|---|
| CounterfeitMint | 18 | `REJECT:turnstile` / `NOT_CALLED` |
| DoubleSpend | 19 | `REJECT:nullifier-spent` / `NOT_CALLED` |
| InsufficientAllowance | 1 | `REJECT:token:InsufficientAllowance` / `ACCEPT` |
| ProofMutation | 15 | `REJECT:proof-deserialize` / `REJECT:proof-deserialize` |
| ProofReplay | 17 | `REJECT:nullifier-spent` / `NOT_CALLED` |
| UnknownAnchor | 17 | `REJECT:unknown-anchor` / `NOT_CALLED` |
| WrongRecipientBinding | 17 | `REJECT:pairing-check` / `REJECT:pairing-check` |

Final solvency: pool_value 1672313327 == token custody 1672313327 == Σ unspent 1672313327.

Battery:

| item | verdict |
|---|---|
| B1 keyset (regenerated SHA == manifest; frozen fixtures verify under regenerated vk) | PASS |
| B2-block-log-vs-model | PASS (1380 blocks field-identical) |
| B3/B7-replayer-phash-chain | PASS (1380 links verified across 3 upgrades) |
| B3-full-population-balances | PASS (all 200 accounts, wallet scan + independent replayer) |
| B4-solvency | PASS (custody == pool_value == unspent == 1672313327, model + replayer) |
| A2-conservation | PASS (pool_value == 2027099765 shielded in - 354786438 paid out) |
| B6-certification | PASS (root-key verified, tip bound to replayer chain hash, 3 tamper controls rejected) |
| B5-adversarial-injections | PASS (104 injected, 100% rejected, all 7 classes exercised) |
| B7-upgrades-under-load | PASS (3 upgrades at ops [367, 447, 534]) |
| B10-keyless-observer | PASS (0/1936 amount hits, 0 principal hits, keyless recognized 0 vs keyed 1380) |
| B11-linkage-cryptanalysis | PASS crypto (a) nf->cm percentile 0.5134 within 0.046 of 0.5, top1 0.00826<=chance 0.00391; (b) same-account 0.4934 within 0.030 of 0.5 |

## Tier: full (10000 accounts / 100000 operations)

- seed: `20260717`
- final state hash: `ed14b49995428338153870a311d8e100efb313209254ce9a9156930573a9b512`
- wall clock: 44646 s
- moc: Motoko compiler 1.4.1 (source k8r4z8c3-7zqv9is3-l7cx4q5j-651yrgww)
- wasm SHA-256: zk_ledger `4e1854ee259fc7c8...`, token `cbb9675c92896dc2...`, tree_oracle `271b4f029e6f3e50...`

Operation mix (accepted):

| kind | count |
|---|---|
| shield | 35265 |
| private transfer | 41304 |
| unshield | 12997 |
| shield fault-recovery (resume_shield) | 183 |
| unshield fault-recovery (resume_unshield) | 158 |
| mid-run upgrades | 3 at ops [37446, 55290, 75307] |
| blocks written | 144366 |
| notes created / spent | 144366 / 108918 |

Adversarial injections: 10093 total, 10093 rejected (100%). By class:

| class | count | one transcript (canister outcome / verifier) |
|---|---|---|
| CounterfeitMint | 1685 | `REJECT:turnstile` / `NOT_CALLED` |
| DoubleSpend | 1683 | `REJECT:nullifier-spent` / `NOT_CALLED` |
| InsufficientAllowance | 1 | `REJECT:token:InsufficientAllowance` / `ACCEPT` |
| ProofMutation | 1685 | `REJECT:proof-deserialize` / `REJECT:proof-deserialize` |
| ProofReplay | 1680 | `REJECT:nullifier-spent` / `NOT_CALLED` |
| UnknownAnchor | 1680 | `REJECT:unknown-anchor` / `NOT_CALLED` |
| WrongRecipientBinding | 1679 | `REJECT:pairing-check` / `REJECT:pairing-check` |

Final solvency: pool_value 129172033555 == token custody 129172033555 == Σ unspent 129172033555.

Battery:

| item | verdict |
|---|---|
| B1 keyset (regenerated SHA == manifest; frozen fixtures verify under regenerated vk) | PASS |
| B2-block-log-vs-model | PASS (144366 blocks field-identical) |
| B3/B7-replayer-phash-chain | PASS (144366 links verified across 3 upgrades) |
| B3-full-population-balances | PASS (all 10000 accounts, wallet scan + independent replayer) |
| B4-solvency | PASS (custody == pool_value == unspent == 129172033555, model + replayer) |
| A2-conservation | PASS (pool_value == 178837069936 shielded in - 49665036381 paid out) |
| B6-certification | PASS (root-key verified, tip bound to replayer chain hash, 3 tamper controls rejected) |
| B5-adversarial-injections | PASS (10093 injected, 100% rejected, all 7 classes exercised) |
| B7-upgrades-under-load | PASS (3 upgrades at ops [37446, 55290, 75307]) |
| B10-keyless-observer | PASS (0/215852 amount hits, 0 principal hits, keyless recognized 0 vs keyed 144366) |
| B11-linkage-cryptanalysis | PASS crypto (a) nf->cm percentile 0.4984 within 0.030 of 0.5, top1 0.00476<=chance 0.00391; (b) same-account 0.5306 within 0.179 of 0.5 |

## Honesty boundary

This suite is a state-machine and value-conservation stress test plus a leakage regression guard. It does not prove circuit soundness against a novel parameter flaw, and it does not prove cryptographic unlinkability; those rest on the trusted-setup policy, the circuit design, and independent review, as stated in the README and `docs/TRUSTED-SETUP-POLICY.md`. The counterfeit-mint (Zcash-2018 class) and keyless-observer items guard the known bug classes, not the unknown ones.

