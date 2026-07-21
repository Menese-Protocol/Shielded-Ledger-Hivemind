// IC mainnet demo canister IDs — Menese DeFi Team.
export const HOST = "https://icp-api.io";
export const CANISTERS = {
  zk_ledger: "nf7le-bqaaa-aaaau-ag26q-cai",
  demo_token: "nm4ay-xyaaa-aaaau-ag27a-cai",
  tree_oracle: "nc6nq-miaaa-aaaau-ag26a-cai",
  demo_directory: "gvlus-biaaa-aaaau-ag3aa-cai",
};
export const DECIMALS = 8;
export const BASE = 100_000_000n;

// ---- read-path scaling ----
// The SINGLE switch for new-format (view-tag) envelope WRITING. Unset (false) ⇒ sealNote emits
// byte-identical legacy envelopes; the READ path auto-detects old+new unconditionally regardless
// of this flag. Flip to true only when the official frontend cuts over (record the log_length at
// that deploy as VIEW_TAG_CUTOVER so wallets may trust tag-detection at/above it).
export const VIEW_TAG_ENABLED = false;
// Log position at/above which every note is guaranteed new-format (the recorded flip position +
// a straggler margin). null ⇒ no cutover known ⇒ wallets full-open every note (never-miss default).
export const VIEW_TAG_CUTOVER = null;
// ICRC-3 response cap (mirrors src/Main.mo MAX_BLOCKS_PER_CALL) — the pagination page size.
export const BLOCKS_PER_PAGE = 512;
