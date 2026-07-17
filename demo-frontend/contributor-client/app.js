// Browser contributor UI for the Phase-2 trusted-setup ceremony.
//
// Flow (one click once it is your turn):
//   1. download the current public parameters of both circuits from the coordinator (chunked);
//   2. call the wasm module `transform_contribution` — it samples a secret from WebCrypto, applies
//      it, builds the proof of knowledge, and DROPS the secret, all inside the wasm sandbox;
//   3. upload the transformed public parameters (chunked) and the proof; the coordinator verifies
//      the proof on-chain and appends your contribution to the public transcript.
//
// The secret is never touched by this JavaScript and never appears in any request body.

import { Actor, HttpAgent } from "https://esm.sh/@dfinity/agent@2.1.3";
import { AuthClient } from "https://esm.sh/@dfinity/auth-client@2.1.3";
import init, { transform_contribution } from "./pkg/ceremony_contributor_wasm.js";

const CHUNK = 1_800_000; // < 2 MB ingress limit
const $ = (id) => document.getElementById(id);
const log = (msg, cls = "") => {
  const line = document.createElement("div");
  if (cls) line.className = cls;
  line.textContent = msg;
  $("log").appendChild(line);
  $("log").scrollTop = $("log").scrollHeight;
};

// Candid interface of the coordinator (subset the client uses).
const idlFactory = ({ IDL }) => {
  const Circuit = IDL.Variant({ transfer: IDL.Null, deposit: IDL.Null });
  const PokWire = IDL.Record({ s_g1: IDL.Vec(IDL.Nat8), s_delta_g1: IDL.Vec(IDL.Nat8), r_delta_g2: IDL.Vec(IDL.Nat8) });
  const R = IDL.Variant({ ok: IDL.Text, err: IDL.Text });
  const CeremonyInfo = IDL.Record({
    phase: IDL.Text, power: IDL.Nat32, contribution_count: IDL.Nat, honest_count: IDL.Nat,
    queue_length: IDL.Nat, current_turn: IDL.Opt(IDL.Principal), finalized: IDL.Bool,
    running_challenge: IDL.Vec(IDL.Nat8), start_time: IDL.Int, end_time: IDL.Int, now: IDL.Int,
    init_done: IDL.Bool,
  });
  const Meta = IDL.Record({ transfer_hash: IDL.Vec(IDL.Nat8), deposit_hash: IDL.Vec(IDL.Nat8), transfer_len: IDL.Nat, deposit_len: IDL.Nat });
  return IDL.Service({
    get_ceremony_info: IDL.Func([], [CeremonyInfo], ["query"]),
    get_current_params_meta: IDL.Func([], [Meta], ["query"]),
    get_current_params_chunk: IDL.Func([Circuit, IDL.Nat, IDL.Nat], [IDL.Vec(IDL.Nat8)], ["query"]),
    join_queue: IDL.Func([], [R], []),
    begin_contribution: IDL.Func([], [R], []),
    upload_contribution_chunk: IDL.Func([Circuit, IDL.Vec(IDL.Nat8)], [R], []),
    submit_contribution: IDL.Func([PokWire, PokWire], [R], []),
  });
};

let actor = null, agent = null, myPrincipal = null;

const hexToBytes = (h) => Uint8Array.from(h.match(/.{1,2}/g).map((b) => parseInt(b, 16)));
const circuitOf = (name) => (name === "transfer" ? { transfer: null } : { deposit: null });

async function downloadParams(circuit, len) {
  const parts = [];
  for (let off = 0; off < len; off += CHUNK) {
    const want = Math.min(CHUNK, len - off);
    const chunk = await actor.get_current_params_chunk(circuitOf(circuit), off, want);
    parts.push(new Uint8Array(chunk));
  }
  const out = new Uint8Array(len);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

async function uploadParams(circuit, bytes) {
  for (let off = 0; off < bytes.length; off += CHUNK) {
    const slice = bytes.slice(off, Math.min(off + CHUNK, bytes.length));
    const r = await actor.upload_contribution_chunk(circuitOf(circuit), Array.from(slice));
    if ("err" in r) throw new Error(r.err);
  }
}

async function refresh() {
  const info = await actor.get_ceremony_info();
  const mine = info.current_turn.length && myPrincipal && info.current_turn[0].toText() === myPrincipal;
  $("status").innerHTML =
    `phase: <b>${info.phase}</b> · power 2^${info.power} · contributions ${info.contribution_count} ` +
    `(honest ${info.honest_count}) · queue ${info.queue_length} · ` +
    (info.finalized ? "<b class='ok'>FINALIZED</b>" : mine ? "<b class='ok'>YOUR TURN</b>" : "waiting");
  $("join").disabled = info.finalized || info.phase !== "open";
  $("contribute").disabled = !mine || info.finalized;
  return info;
}

$("connect").onclick = async () => {
  try {
    await init(); // load wasm
    const host = $("host").value.trim();
    const canisterId = $("canisterId").value.trim();
    const authClient = await AuthClient.create();
    // Local dev uses the anonymous or a dev identity; production uses Internet Identity.
    agent = new HttpAgent({ host, identity: authClient.getIdentity() });
    if (host.includes("127.0.0.1") || host.includes("localhost")) await agent.fetchRootKey();
    myPrincipal = (await agent.getPrincipal()).toText();
    $("whoami").textContent = "principal: " + myPrincipal;
    actor = Actor.createActor(idlFactory, { agent, canisterId });
    $("refresh").disabled = false;
    log("connected", "ok");
    await refresh();
  } catch (e) { log("connect failed: " + e.message, "err"); }
};

$("refresh").onclick = () => refresh().catch((e) => log(e.message, "err"));

$("join").onclick = async () => {
  try {
    const r = await actor.join_queue();
    if ("err" in r) throw new Error(r.err);
    log("joined queue: " + r.ok, "ok");
    await refresh();
  } catch (e) { log("join failed: " + e.message, "err"); }
};

$("contribute").onclick = async () => {
  try {
    $("contribute").disabled = true;
    log("opening staging slot ...");
    let r = await actor.begin_contribution();
    if ("err" in r) throw new Error(r.err);

    const info = await actor.get_ceremony_info();
    const meta = await actor.get_current_params_meta();
    log(`downloading current parameters (transfer ${meta.transfer_len} B, deposit ${meta.deposit_len} B) ...`);
    const curTransfer = await downloadParams("transfer", Number(meta.transfer_len));
    const curDeposit = await downloadParams("deposit", Number(meta.deposit_len));

    log("sampling secret + transforming IN THIS TAB (secret never leaves) ...", "warn");
    const out = JSON.parse(transform_contribution(curTransfer, curDeposit, new Uint8Array(info.running_challenge)));

    log("uploading transformed PUBLIC parameters ...");
    await uploadParams("transfer", hexToBytes(out.transfer_delta));
    await uploadParams("deposit", hexToBytes(out.deposit_delta));

    const pk = (p) => ({ s_g1: Array.from(hexToBytes(p.s_g1)), s_delta_g1: Array.from(hexToBytes(p.s_delta_g1)), r_delta_g2: Array.from(hexToBytes(p.r_delta_g2)) });
    log("submitting proof of knowledge (verified on-chain) ...");
    r = await actor.submit_contribution(pk(out.transfer_pok), pk(out.deposit_pok));
    if ("err" in r) throw new Error(r.err);
    log("CONTRIBUTION ACCEPTED: " + r.ok, "ok");
    log("your secret has been discarded. thank you.", "ok");
    await refresh();
  } catch (e) { log("contribution failed: " + e.message, "err"); await refresh(); }
};
