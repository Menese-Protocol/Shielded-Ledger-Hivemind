// Live decode of the DEMO token's PUBLIC ICRC-3 ledger (Menese DeFi Team).
//
// This feed is the demo's foil: a normal token ledger, where every mint, approval and transfer
// is written with the amount and both parties in the open — exactly what a node provider (or
// anyone) reads. The shielded pool's log next to it is what privacy looks like instead.
import { Principal } from "@dfinity/principal";

const asMap = (v) => (v && v.Map ? Object.fromEntries(v.Map) : null);

function decodeAccount(v) {
  // accounts encode as Array([Blob(principal), Blob(subaccount)?])
  try {
    const arr = v.Array;
    const owner = Principal.fromUint8Array(new Uint8Array(arr[0].Blob)).toText();
    return owner;
  } catch {
    return null;
  }
}

// Returns newest-first plain entries: { index, btype, ts, amt, from, to, spender }
export async function readTokenLedger(actors) {
  const res = await actors.token.icrc3_get_blocks([{ start: 0n, length: 100_000n }]);
  const entries = [];
  for (const { id, block } of res.blocks) {
    const outer = asMap(block);
    if (!outer) continue;
    const tx = asMap(outer.tx) || {};
    entries.push({
      index: Number(id),
      btype: outer.btype?.Text || "?",
      ts: outer.ts ? Number(outer.ts.Nat) : null,
      amt: tx.amt ? BigInt(tx.amt.Nat) : null,
      from: tx.from ? decodeAccount(tx.from) : null,
      to: tx.to ? decodeAccount(tx.to) : null,
      spender: tx.spender ? decodeAccount(tx.spender) : null,
    });
  }
  entries.sort((a, b) => b.index - a.index);
  return { entries, tip: entries.length ? entries[0].index : -1 };
}
