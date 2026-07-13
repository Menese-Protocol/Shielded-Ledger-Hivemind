// IC agent + typed actors for the demo (Menese DeFi Team).
import { HttpAgent, Actor } from "@dfinity/agent";
import { Principal } from "@dfinity/principal";
import { HOST, CANISTERS } from "./config.js";
import { idlFactory as ledgerIdl } from "./declarations/zk_ledger/zk_ledger.did.js";
import { idlFactory as tokenIdl } from "./declarations/demo_token/demo_token.did.js";

// The directory's interface is small enough to declare inline.
const directoryIdl = ({ IDL }) =>
  IDL.Service({
    vetkey_public_key: IDL.Func([], [IDL.Vec(IDL.Nat8)], []),
    derive_shielded_key: IDL.Func(
      [IDL.Vec(IDL.Nat8)],
      [IDL.Variant({ ok: IDL.Vec(IDL.Nat8), err: IDL.Text })],
      []
    ),
    register: IDL.Func([IDL.Text, IDL.Text], [IDL.Variant({ ok: IDL.Null, err: IDL.Text })], []),
    lookup: IDL.Func(
      [IDL.Principal],
      [IDL.Opt(IDL.Record({ shielded_pk: IDL.Text, enc_pk: IDL.Text }))],
      ["query"]
    ),
    count: IDL.Func([], [IDL.Nat], ["query"]),
  });

async function agentFor(identity) {
  const agent = new HttpAgent({ host: HOST, identity });
  // Root key must only be fetched against a local replica; on mainnet the
  // hardcoded NNS root key in the agent is the trust anchor.
  if (HOST.includes("127.0.0.1") || HOST.includes("localhost")) {
    await agent.fetchRootKey();
  }
  return agent;
}

export async function actorsFor(identity) {
  const agent = await agentFor(identity);
  return {
    principal: identity.getPrincipal(),
    ledger: Actor.createActor(ledgerIdl, { agent, canisterId: CANISTERS.zk_ledger }),
    token: Actor.createActor(tokenIdl, { agent, canisterId: CANISTERS.demo_token }),
    directory: Actor.createActor(directoryIdl, { agent, canisterId: CANISTERS.demo_directory }),
  };
}

export const poolPrincipal = () => Principal.fromText(CANISTERS.zk_ledger);

// ---- hex <-> bytes ----
export const hexToBytes = (h) => {
  const clean = h.startsWith("0x") ? h.slice(2) : h;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(2 * i, 2), 16);
  return out;
};
export const bytesToHex = (b) =>
  Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
