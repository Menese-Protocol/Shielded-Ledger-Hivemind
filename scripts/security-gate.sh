#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CIRCUIT="$ROOT/circuit"
VLAB="$ROOT/verifier-lab"
MOC="$(dfx cache show)/moc"
CORE="$ROOT/.mops/core@1.0.0/src"
SHA2="$ROOT/.mops/sha2@0.1.9/src"

if [[ ! -x "$MOC" ]]; then
  echo "SECURITY GATE FAIL: Motoko compiler not found at $MOC" >&2
  exit 1
fi
if [[ ! -d "$CIRCUIT/common" || ! -d "$VLAB" || ! -d "$CORE" ]]; then
  echo "SECURITY GATE FAIL: required circuit/verifier source tree is missing" >&2
  exit 1
fi

step() { printf '\n== %s ==\n' "$1"; }

step "Frozen fixture integrity"
cd "$ROOT"
sha256sum -c fixtures/SHA256SUMS
diff -u "$CIRCUIT/common/src/lib.rs" vendor/tree_common/src/lib.rs

step "Deterministic test-vector reproducibility and explicit toxic-waste label"
REGENERATED="$(mktemp -d)"
trap 'rm -rf "$REGENERATED"' EXIT
cargo run --quiet --release --manifest-path "$CIRCUIT/Cargo.toml" -p gen --features bls12-381 -- \
  "$REGENERATED" --setup insecure-deterministic-test
for generated in "$REGENERATED"/*; do
  name="$(basename "$generated")"
  case "$name" in
    *_pk.bin|ORACLE.txt) continue ;;
  esac
  cmp "$generated" "$CIRCUIT/vectors-bls/$name"
done
diff -u \
  <(sed -E 's/(PROVE-TIME.*=) [0-9]+ ms/\1 <normalized>/' "$REGENERATED/ORACLE.txt") \
  <(sed -E 's/(PROVE-TIME.*=) [0-9]+ ms/\1 <normalized>/' "$CIRCUIT/vectors-bls/ORACLE.txt")
rm -rf "$REGENERATED"
trap - EXIT

step "Randomized circuit properties and Groth16 mutation battery"
cargo test --manifest-path "$CIRCUIT/Cargo.toml" -p common --features bls12-381 --test security_properties

step "Circuit semantic-completeness audit (twelve-row UNSAT + mutation-kill battery)"
cargo test --manifest-path "$CIRCUIT/Cargo.toml" -p common --features bls12-381 --test semantic_audit

step "Browser prover compiles for wasm32 and uses the identical circuit"
cargo check --manifest-path demo-frontend/prover-wasm/Cargo.toml --target wasm32-unknown-unknown
if grep -rn 'Math\.random' demo-frontend/src demo-frontend/prover-wasm/src; then
  echo "SECURITY GATE FAIL: non-cryptographic Math.random found in wallet/prover" >&2
  exit 1
fi
grep -qF 'getrandom::getrandom(&mut seed)' demo-frontend/prover-wasm/src/lib.rs
grep -qF 'crypto.getRandomValues' demo-frontend/src/wallet.js

step "Current eight-public-input vectors through the vendored Motoko verifier"
node scripts/verify-current-groth16.mjs

step "Second-implementation cross-oracle: blst verdict agreement"
cargo test --quiet --release -p cross_oracle

step "Independent Motoko arithmetic, subgroup, pairing, and wire oracles"
for test in CurveJacTest.mo Groth16MultiTest.mo WireTest.mo; do
  "$MOC" -r --package core "$CORE" "$VLAB/$test"
done

step "Ledger hashing, exact-block matching, and fee arithmetic"
"$MOC" -r --package core "$CORE" --package sha2 "$SHA2" tests/ICRC3HashTest.mo
"$MOC" -r --package core "$CORE" --package sha2 "$SHA2" tests/ICRC2BlockTest.mo

step "Canister compile gates and DEMO fixture API boundary"
dfx build --check zk_ledger
dfx build --check stable_storage_test
(
  cd demo-frontend
  dfx build --check demo_token
  if grep -En 'test_set_|test_advance|test_poison' DemoTokenLedger.mo .dfx/local/canisters/demo_token/demo_token.did; then
    echo "SECURITY GATE FAIL: mutable test control exposed by the DEMO token" >&2
    exit 1
  fi
)

step "Key provenance, negative controls, and exact amount parsing"
(
  cd demo-frontend
  npm run verify:keyset
  npm run test:keyset-negative
  npm run test:amounts
)

step "Production frontend build and real browser boot"
(
  cd demo-frontend
  if [[ ! -d src/declarations/zk_ledger ]]; then
    dfx generate zk_ledger && dfx generate demo_token && dfx generate demo_directory
  fi
  if [[ ! -f src/prover-pkg/pool_prover_wasm_bg.wasm ]]; then
    (cd prover-wasm && wasm-pack build --target web --release --out-dir ../src/prover-pkg)
  fi
  npm run build
  npm run test:static-boot
)

step "Patch hygiene"
git -C "$ROOT" diff --check

if [[ "${1:-}" == "--with-replica-e2e" ]]; then
  step "State-mutating local-replica ledger E2E"
  echo "This explicit mode installs/upgrades canisters only on the configured local sandbox."
  python3 e2e.py
fi

printf '\nSECURITY GATE: ALL REQUESTED CHECKS GREEN\n'
if [[ "${1:-}" != "--with-replica-e2e" ]]; then
  echo "Replica install/upgrade tests were not run; invoke --with-replica-e2e separately to exercise a local replica."
fi
