#!/usr/bin/env bash
# Redeploy the demo stack on the local demo replica (port 4955) and configure the ledger with
# the pinned BLS12-381 vks + the DEMO token + the shielded-address directory. Regenerates
# src/config.js. Menese DeFi Team.
set -euo pipefail
cd "$(dirname "$0")/.."
KEYS=public/keys

node scripts/verify-keyset.mjs "$KEYS"

dfx deploy tree_oracle >/dev/null 2>&1 || true
dfx deploy zk_ledger --mode reinstall -y >/dev/null
dfx deploy demo_token --mode reinstall -y >/dev/null
dfx deploy demo_directory --mode reinstall -y >/dev/null

LEDGER=$(dfx canister id zk_ledger)
TREE=$(dfx canister id tree_oracle)
TOKEN=$(dfx canister id demo_token)
DIRECTORY=$(dfx canister id demo_directory)
TVK=$(cat "$KEYS/transfer_vk.hex")
DVK=$(cat "$KEYS/deposit_vk.hex")

dfx canister call zk_ledger configure "(principal \"$LEDGER\", principal \"$TREE\", \"$TVK\", \"$DVK\")" >/dev/null
dfx canister call zk_ledger configure_token_ledger "(principal \"$TOKEN\", principal \"$TOKEN\", null)" >/dev/null

cat > src/config.js <<EOF
// Local demo replica (port 4955) canister IDs — regenerate with scripts/redeploy.sh.
// Menese DeFi Team.
export const HOST = "http://127.0.0.1:4955";
export const CANISTERS = {
  zk_ledger: "$LEDGER",
  demo_token: "$TOKEN",
  tree_oracle: "$TREE",
  demo_directory: "$DIRECTORY",
};
export const DECIMALS = 8;
export const BASE = 100_000_000n;
EOF
echo "configured: ledger=$LEDGER token=$TOKEN tree=$TREE directory=$DIRECTORY"
