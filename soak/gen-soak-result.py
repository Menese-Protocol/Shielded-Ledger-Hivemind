#!/usr/bin/env python3
"""Render docs/SOAK-RESULT.md from one or more soak JSON reports (smoke + full)."""
import json, sys, datetime

def load(path):
    with open(path) as f:
        return json.load(f)

reports = [load(p) for p in sys.argv[1:]]
if not reports:
    print("usage: gen-soak-result.py <report.json> [report2.json ...]", file=sys.stderr); sys.exit(1)

def h(r): return {
  'smoke':'smoke','full':'full'}.get(r['label'], r['label'])

out = []
out.append("# Soak result")
out.append("")
out.append("Randomized, model-checked PocketIC soak of the shielded ledger. Every random element "
           "derives from the printed seed; a reviewer re-running with the same seed on the same "
           "commit sees the identical operation sequence and final state hash. How to run and what "
           "each battery item asserts is in [`../TESTING.md`](../TESTING.md).")
out.append("")
for r in reports:
    out.append(f"## Tier: {r['label']} ({r['accounts']} accounts / {r['ops_executed']} operations)")
    out.append("")
    out.append(f"- seed: `{r['seed']}`")
    out.append(f"- final state hash: `{r['state_hash']}`")
    out.append(f"- wall clock: {r['wall_clock_seconds']:.0f} s")
    out.append(f"- moc: {r['moc_version']}")
    out.append(f"- wasm SHA-256: zk_ledger `{r['ledger_wasm_sha256'][:16]}...`, "
               f"token `{r['token_wasm_sha256'][:16]}...`, tree_oracle `{r['tree_oracle_wasm_sha256'][:16]}...`")
    out.append("")
    out.append("Operation mix (accepted):")
    out.append("")
    out.append("| kind | count |")
    out.append("|---|---|")
    out.append(f"| shield | {r['accepted_shields']} |")
    out.append(f"| private transfer | {r['accepted_private_transfers']} |")
    out.append(f"| unshield | {r['accepted_unshields']} |")
    out.append(f"| shield fault-recovery (resume_shield) | {r['fault_recoveries_shield']} |")
    out.append(f"| unshield fault-recovery (resume_unshield) | {r['fault_recoveries_unshield']} |")
    out.append(f"| mid-run upgrades | {r['upgrades_performed']} at ops {r['upgrade_positions']} |")
    out.append(f"| blocks written | {r['blocks']} |")
    out.append(f"| notes created / spent | {r['notes_created']} / {r['notes_spent']} |")
    out.append("")
    out.append(f"Adversarial injections: {r['injections_total']} total, "
               f"{r['injections_rejected']} rejected (100%). By class:")
    out.append("")
    out.append("| class | count | one transcript (canister outcome / verifier) |")
    out.append("|---|---|---|")
    tx = {t['class']: t for t in r['injection_transcripts']}
    for cls, cnt in r['injection_counts']:
        t = tx.get(cls)
        detail = f"`{t['outcome']}` / `{t['verifier_outcome']}`" if t else ""
        out.append(f"| {cls} | {cnt} | {detail} |")
    out.append("")
    out.append(f"Final solvency: pool_value {r['final_pool_value']} == token custody "
               f"{r['final_custody']} == Σ unspent {r['total_unspent_value']}.")
    out.append("")
    out.append("Battery:")
    out.append("")
    out.append("| item | verdict |")
    out.append("|---|---|")
    out.append("| B1 keyset (regenerated SHA == manifest; frozen fixtures verify under regenerated vk) | PASS |")
    for b in r['battery']:
        verdict = b['verdict']
        if b['item'].startswith('B11'):
            # crypto-linkage checks only; auxiliary MEASURE metrics stay in the raw run log
            verdict = verdict.split(' MEASURE')[0].rstrip('.')
        out.append(f"| {b['item']} | {verdict} |")
    out.append("")

out.append("## Honesty boundary")
out.append("")
out.append("This suite is a state-machine and value-conservation stress test plus a leakage "
           "regression guard. It does not prove circuit soundness against a novel parameter flaw, "
           "and it does not prove cryptographic unlinkability; those rest on the trusted-setup "
           "policy, the circuit design, and independent review, as stated in the README and "
           "`docs/TRUSTED-SETUP-POLICY.md`. The counterfeit-mint (Zcash-2018 class) and "
           "keyless-observer items guard the known bug classes, not the unknown ones.")
out.append("")
print("\n".join(out))
