// Browser contributor UI for the Phase-2 trusted-setup ceremony.
//
// Flow (one click once it is your turn):
//   1. download the current public parameters of both circuits from the coordinator (chunked);
//   2. call the wasm module `transform_contribution` — it samples a secret from WebCrypto, applies
//      it, builds the proof of knowledge, and DROPS the secret, all inside the wasm sandbox;
//   3. upload the transformed public parameters (chunked) and the proof; the coordinator runs
//      STRUCTURAL checks on-chain (points canonical, on-curve, non-identity; the delta advanced;
//      lengths right; the challenge chains) and appends your contribution to the public transcript.
//
// This comment previously said "the coordinator verifies the proof on-chain". It does not:
// `checkOneCircuit` calls `PokVerify.structuralCheck`, never `verifyPok`. The soundness-critical
// subgroup and pairing checks run OFF-CHAIN in the standalone verifier over the published
// transcript, per docs/CEREMONY.md section 8. That distinction matters most on exactly this page,
// because it is what a contributor reads before deciding what on-chain acceptance proves: being
// appended is NOT confirmation that your proof of knowledge checked out.
//
// The secret is never touched by this JavaScript and never appears in any request body.

// Vendored, not fetched. This page samples the ceremony secret, so a third-party CDN in its
// import graph would be a party to the trust model: whoever serves esm.sh could replace the agent
// with one that exfiltrates, and nothing the contributor can inspect would show it. The bundle is
// built from the versions pinned in package-lock.json with
//   esbuild <entry re-exporting Actor/HttpAgent/AuthClient> --bundle --format=esm --platform=browser
// so it is reproducible from the lockfile and reviewable in-tree. Deliberately NOT minified: a
// contributor asked to trust this page should be able to read the dependency it runs, and the
// bundle keeps its upstream license attributions where a minified one drops them into noise. This
// does not make the page trustless — the wasm module is what holds the secret — but it removes a
// host that had no reason to be trusted at all.
import { Actor, HttpAgent, AuthClient } from "./vendor/dfinity.js";
import init, { transform_contribution } from "./pkg/ceremony_contributor_wasm.js";

// ---------------------------------------------------------------------------------------------
// LAUNCH CONFIGURATION.
//
// Set both of these in the PUBLISHED copy of this page, at deploy time, once the coordinator
// canister exists. When they are set the fields below are pinned read-only and the contributor is
// not asked to supply an address.
//
// This is a security setting, not a convenience one. An address the contributor types is an address
// an attacker can substitute: a look-alike page, or a wrong id pasted into a chat, sends
// contributions to a canister nobody audited. Publish the real id here AND print it in
// docs/CEREMONY.md so the two can be cross-checked against each other.
//
// Left empty they remain editable, for local testing against a replica.
const PINNED_CANISTER_ID = "osqjo-zyaaa-aaaad-agxua-cai";
const PINNED_HOST = "https://icp-api.io";
// ---------------------------------------------------------------------------------------------

const CHUNK = 1_800_000; // < 2 MB ingress limit
const $ = (id) => document.getElementById(id);

// --- identity -----------------------------------------------------------------------------------
// The ceremony's whole assurance argument is "1 of N independent participants was honest", and the
// coordinator tells participants apart by their principal alone. Every anonymous caller on the IC
// shares ONE principal, so an unauthenticated contributor is not a weak participant — they are
// indistinguishable from every other one: the second `join_queue` is refused as a duplicate, the
// `staging.who != caller` guard that protects an in-flight upload never trips, and the transcript
// records one identity for the whole ceremony. Sign-in is therefore mandatory off localhost.
const ANONYMOUS_PRINCIPAL = "2vxsx-fae";
const IDENTITY_PROVIDER = "https://identity.ic0.app";
const isLocal = (h) => h.includes("127.0.0.1") || h.includes("localhost");

// Resolved at module load, deliberately. Internet Identity opens a popup, and a popup only opens
// while the click's user-activation is still live; awaiting AuthClient.create() (an IndexedDB read)
// inside the handler is enough to lose that activation in Safari and have the window blocked.
const authClientReady = AuthClient.create();

const signIn = (authClient) =>
  new Promise((resolve, reject) =>
    authClient.login({
      identityProvider: IDENTITY_PROVIDER,
      // A contribution is minutes; this only has to outlive one sitting at the page.
      maxTimeToLive: BigInt(8) * BigInt(3_600_000_000_000),
      onSuccess: resolve,
      onError: (e) => reject(new Error(e || "Internet Identity sign-in was cancelled")),
    }),
  );

let logEmpty = true;
const log = (msg, cls = "") => {
  if (logEmpty) { $("log").textContent = ""; logEmpty = false; }
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
    init_done: IDL.Bool, genesis_challenge: IDL.Vec(IDL.Nat8), configured: IDL.Bool,
  });
  const Meta = IDL.Record({ transfer_hash: IDL.Vec(IDL.Nat8), deposit_hash: IDL.Vec(IDL.Nat8), transfer_len: IDL.Nat, deposit_len: IDL.Nat });
  const ContributionMeta = IDL.Record({
    index: IDL.Nat, contributor: IDL.Vec(IDL.Nat8), timestamp: IDL.Int,
    is_beacon: IDL.Bool, beacon: IDL.Vec(IDL.Nat8),
    transfer_delta_hash: IDL.Vec(IDL.Nat8), transfer_delta_len: IDL.Nat,
    deposit_delta_hash: IDL.Vec(IDL.Nat8), deposit_delta_len: IDL.Nat,
    transfer_pok: PokWire, deposit_pok: PokWire,
  });
  return IDL.Service({
    get_ceremony_info: IDL.Func([], [CeremonyInfo], ["query"]),
    get_current_params_meta: IDL.Func([], [Meta], ["query"]),
    get_current_params_chunk: IDL.Func([Circuit, IDL.Nat, IDL.Nat], [IDL.Vec(IDL.Nat8)], ["query"]),
    get_contribution: IDL.Func([IDL.Nat], [IDL.Opt(ContributionMeta)], ["query"]),
    join_queue: IDL.Func([], [R], []),
    begin_contribution: IDL.Func([], [R], []),
    abort_contribution: IDL.Func([], [R], []),
    upload_contribution_chunk: IDL.Func([Circuit, IDL.Vec(IDL.Nat8)], [R], []),
    submit_contribution: IDL.Func([PokWire, PokWire], [R], []),
  });
};

// Two actors. `anonActor` is built at page load with no identity and serves the public reads —
// the chain, the vitals, the running challenge. Everything a visitor or an auditor wants to see is
// query data, so requiring a sign-in before the page will show it would be backwards: it would
// hide the ceremony's public record behind an authentication step that only the ACT of
// contributing actually needs. `actor` carries the signed-in identity and appears only after
// sign-in; every read prefers it once it exists.
let actor = null, anonActor = null, agent = null, myPrincipal = null;
const api = () => actor || anonActor;

let inQueue = false, contributed = false, myIndex = null;

// Set for exactly as long as the coordinator holds an open staging slot for us. Closing the tab
// in that window abandons the slot and burns the turn, so the browser is asked to confirm.
let stagingOpen = false;
window.addEventListener("beforeunload", (e) => {
  if (!stagingOpen) return;
  e.preventDefault();
  e.returnValue = "Your contribution is still uploading. Leaving now abandons your turn.";
  return e.returnValue;
});

const hexToBytes = (h) => Uint8Array.from(h.match(/.{1,2}/g).map((b) => parseInt(b, 16)));
const bytesToHex = (a) => Array.from(a, (b) => b.toString(16).padStart(2, "0")).join("");
const circuitOf = (name) => (name === "transfer" ? { transfer: null } : { deposit: null });
const mb = (n) => (n / 1_000_000).toFixed(2) + " MB";

// --- pending state -----------------------------------------------------------------------------
// Every async action must acknowledge the click immediately. Without this the page looks dead for
// the whole round trip and people click again or assume it is broken.
async function busy(btn, label, fn) {
  const el = $(btn);
  const original = el.innerHTML;
  const all = ["connect", "join", "contribute", "refresh"].map($);
  const wasDisabled = all.map((o) => o.disabled);
  all.forEach((o) => (o.disabled = true));
  el.innerHTML = `<span class="spinner"></span> ${label}`;
  try {
    return await fn();
  } finally {
    el.innerHTML = original;
    // refresh() is the single source of truth for button state once we are connected. Restoring
    // the pre-click state here instead would undo whatever the action just changed — e.g. clearing
    // the enable that taking your turn produced.
    if (api()) {
      try { await refresh(); } catch { all.forEach((o, i) => (o.disabled = wasDisabled[i])); }
    } else {
      all.forEach((o, i) => (o.disabled = wasDisabled[i]));
    }
  }
}

function progress(show, label = "", pct = 0) {
  $("progressWrap").classList.toggle("show", show);
  $("progressLabel").textContent = label;
  $("progressBar").value = pct;
}

function banner(kind, text) {
  const b = $("banner");
  b.className = "banner" + (kind ? ` show ${kind}` : "");
  $("bannerText").textContent = text;
}

// --- the four stages of a contribution ------------------------------------------------------------
// A genuine sequence, so it is numbered. Each stage reports what it is actually doing rather than
// spinning, because the one operation on this page that must not be interrupted is stage 02-03.
function stage(n, state, detail) {
  const li = $("st" + n);
  if (!li) return;
  li.className = state || "";
  li.querySelector(".d").textContent = detail || "";
}
const resetStages = () => { for (let i = 1; i <= 4; i++) stage(i, "", ""); };

// --- seal glyphs ----------------------------------------------------------------------------------
// A contribution's seal is a pure function of its own delta hash: 7x7, mirrored about the vertical
// axis so it reads as a seal rather than as noise. Nothing here is random and nothing is derived
// from anyone's secret — the input is the same public SHA-256 that goes on the receipt and into
// the published transcript. That is the point: a contributor can look at the chain and recognise
// their own link, which is exactly what "verify your contribution is in it" asks them to do.
const SEAL_N = 7;
function sealSvg(bytes, color) {
  const half = Math.ceil(SEAL_N / 2); // 4 generated columns, mirrored to 7
  let cells = "";
  for (let y = 0; y < SEAL_N; y++) {
    for (let x = 0; x < half; x++) {
      const i = y * half + x;
      if (!((bytes[i % bytes.length] >> (i % 8)) & 1)) continue;
      cells += `<rect x="${x}" y="${y}" width="1" height="1"/>`;
      const mx = SEAL_N - 1 - x;
      if (mx !== x) cells += `<rect x="${mx}" y="${y}" width="1" height="1"/>`;
    }
  }
  return `<svg viewBox="0 0 ${SEAL_N} ${SEAL_N}" aria-hidden="true"><g fill="${color}">${cells}</g></svg>`;
}

const GOLD = "#e0b13c", GOLD_DIM = "#8d6f2c", VERDIGRIS = "#56b394";
const contribCache = new Map();

async function loadContributions(count) {
  for (let i = 0; i < count; i++) {
    if (contribCache.has(i)) continue;
    try {
      const got = await api().get_contribution(BigInt(i));
      if (got.length) {
        const c = got[0];
        contribCache.set(i, {
          bytes: new Uint8Array(c.transfer_delta_hash),
          hash: bytesToHex(new Uint8Array(c.transfer_delta_hash)),
          isBeacon: c.is_beacon,
        });
      }
    } catch { /* a link we cannot read is left out rather than drawn wrong */ }
  }
}

function linkEl(cls, inner, cap, frag, title) {
  const d = document.createElement("div");
  d.className = "link " + cls;
  if (title) d.title = title;
  d.innerHTML = `<div class="seal">${inner}</div><div class="cap">${cap}</div>` +
                (frag ? `<div class="frag">${frag}</div>` : "");
  return d;
}

async function renderChain(info) {
  const chain = $("chain");
  const count = Number(info.contribution_count);
  await loadContributions(count);

  const frag = document.createDocumentFragment();
  const push = (el) => {
    if (frag.childNodes.length) {
      const c = document.createElement("div");
      c.className = "connector";
      frag.appendChild(c);
    }
    frag.appendChild(el);
  };

  const genesis = new Uint8Array(info.genesis_challenge);
  const gHex = bytesToHex(genesis);
  push(linkEl("genesis", sealSvg(genesis, GOLD_DIM), "genesis", gHex.slice(0, 8),
              "The opening parameters, before any contribution — genesis challenge " + gHex));

  for (let i = 0; i < count; i++) {
    const c = contribCache.get(i);
    if (!c) continue;
    const mine = myIndex === i;
    const cls = (c.isBeacon ? "beacon " : "") + (mine ? "mine" : "");
    const cap = c.isBeacon ? "beacon" : (mine ? "you" : String(i).padStart(2, "0"));
    push(linkEl(cls, sealSvg(c.bytes, c.isBeacon ? VERDIGRIS : GOLD), cap, c.hash.slice(0, 8),
                `Contribution ${i} · transfer delta SHA-256 ${c.hash}`));
  }

  if (!info.finalized) {
    const mineTurn = info.current_turn.length && myPrincipal &&
                     info.current_turn[0].toText() === myPrincipal;
    const cap = mineTurn && !contributed ? "you" : "next";
    push(linkEl("slot" + (mineTurn && !contributed ? " forging" : ""),
                "", cap, "", "The next link in the chain"));
  }

  chain.replaceChildren(frag);
  $("challengeHex").textContent = bytesToHex(new Uint8Array(info.running_challenge));
  $("chainSummary").textContent = count === 0
    ? "no contributions yet — the first link is still open"
    : `${count} contribution${count === 1 ? "" : "s"} sealed · every link is a seal drawn from that contribution's own hash`;
}

// --- chunked transfer, with progress -------------------------------------------------------------
async function downloadParams(circuit, len, onBytes) {
  const parts = [];
  for (let off = 0; off < len; off += CHUNK) {
    const want = Math.min(CHUNK, len - off);
    const chunk = await actor.get_current_params_chunk(circuitOf(circuit), off, want);
    parts.push(new Uint8Array(chunk));
    onBytes(Math.min(off + want, len));
  }
  const out = new Uint8Array(len);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

async function uploadParams(circuit, bytes, onBytes) {
  for (let off = 0; off < bytes.length; off += CHUNK) {
    const slice = bytes.slice(off, Math.min(off + CHUNK, bytes.length));
    const r = await actor.upload_contribution_chunk(circuitOf(circuit), Array.from(slice));
    if ("err" in r) throw new Error(r.err);
    onBytes(Math.min(off + slice.length, bytes.length));
  }
}

const vital = (label, value, sub) =>
  `<div class="vital"><dt>${label}</dt><dd>${value}${sub ? ` <small>${sub}</small>` : ""}</dd></div>`;

async function refresh() {
  const info = await api().get_ceremony_info();
  const signedIn = !!actor;
  const mine = info.current_turn.length && myPrincipal &&
               info.current_turn[0].toText() === myPrincipal;

  const phase = info.finalized ? "sealed" : info.phase;
  $("phaseText").textContent =
    info.finalized ? "ceremony sealed"
    : info.phase === "open" ? "window open"
    : info.phase === "closed" ? "window closed"
    : info.phase;
  $("phasePill").className =
    "pill " + (info.finalized ? "sealed" : info.phase === "open" ? "live" : "shut");

  $("stats").innerHTML =
    vital("Phase", phase) +
    vital("Contributions", info.contribution_count, `${info.honest_count} honest`) +
    vital("Queue", info.queue_length) +
    vital("Power", "2<sup>" + info.power + "</sup>");

  await renderChain(info);

  if (info.finalized) banner("done", "The ceremony is sealed. The parameters are frozen.");
  else if (contributed) banner("done", "Your contribution is in the chain. Thank you.");
  else if (mine) banner("turn", "It is your turn. Choose Contribute now when you are ready — do not close the tab once it starts.");
  else if (inQueue) banner("hold", `You are in the queue. ${info.queue_length} waiting.`);
  else banner("", "");

  // Signing in is a one-time step and the button stays disabled afterwards, so relabel it —
  // a disabled button still reading "Sign in" looks stuck rather than finished. This runs after
  // busy() has restored the original label, so it is the last word on it.
  if (signedIn) {
    $("connect").textContent = "Signed in";
    $("connect").disabled = true;
  }

  const open = info.phase === "open" && !info.finalized;
  $("join").disabled = !signedIn || !open || inQueue || contributed;
  $("contribute").disabled = !signedIn || !mine || info.finalized || contributed;
  $("refresh").disabled = false;
  return info;
}

// --- actions -------------------------------------------------------------------------------------
if (PINNED_CANISTER_ID) {
  $("canisterId").value = PINNED_CANISTER_ID;
  $("canisterId").readOnly = true;
}
if (PINNED_HOST) {
  $("host").value = PINNED_HOST;
  $("host").readOnly = true;
}
if (PINNED_CANISTER_ID && PINNED_HOST) {
  $("pinnedNote").textContent =
    "Baked into this published page and shown read-only. Cross-check this canister id against " +
    "docs/CEREMONY.md before you contribute — an address you are asked to type is an address an " +
    "attacker can substitute.";
} else {
  $("idWarn").textContent =
    "Unpinned build: check this canister id against docs/CEREMONY.md — an address you paste is one an attacker can substitute.";
}

// Show the public record immediately, with no identity at all. The chain, the vitals and the
// running challenge are query data that anyone is entitled to read, and an observer auditing the
// ceremony should never have to sign in to watch it.
(async function showPublicRecord() {
  const host = $("host").value.trim(), cid = $("canisterId").value.trim();
  if (!host || !cid) return; // unpinned local build: nothing to read until the fields are filled in
  try {
    const a = new HttpAgent({ host });
    if (isLocal(host)) await a.fetchRootKey();
    anonActor = Actor.createActor(idlFactory, { agent: a, canisterId: cid });
    await refresh();
  } catch (e) {
    $("phaseText").textContent = "coordinator unreachable";
    log("could not read the ceremony: " + e.message, "err");
  }
})();

$("connect").onclick = () => busy("connect", "signing in", async () => {
  try {
    // Read and validate the fields synchronously, then sign in as the FIRST await, so the
    // Internet Identity popup is still inside the click's user-activation window. Loading the
    // ~1 MB contributor wasm first would forfeit it.
    const host = $("host").value.trim();
    const canisterId = $("canisterId").value.trim();
    if (!canisterId) throw new Error("enter the coordinator canister id");
    if (!host) throw new Error("enter the host");

    const authClient = await authClientReady;
    if (!isLocal(host) && !(await authClient.isAuthenticated())) {
      log("opening Internet Identity — approve in the popup ...");
      await signIn(authClient);
    }

    log("loading the contributor wasm module ...");
    await init();

    agent = new HttpAgent({ host, identity: authClient.getIdentity() });
    if (isLocal(host)) await agent.fetchRootKey();
    myPrincipal = (await agent.getPrincipal()).toText();
    if (!isLocal(host) && myPrincipal === ANONYMOUS_PRINCIPAL) {
      throw new Error(
        "still anonymous after sign-in. Every anonymous contributor shares one principal, so the " +
          "ceremony cannot tell participants apart — contributing this way would corrupt the " +
          "participant record. Sign in with Internet Identity and try again.",
      );
    }
    $("whoami").textContent = myPrincipal;
    actor = Actor.createActor(idlFactory, { agent, canisterId });
    log("connected", "ok");
    await refresh();
  } catch (e) { log("connect failed: " + e.message, "err"); }
});

$("refresh").onclick = () => busy("refresh", "refreshing", async () => {
  try { await refresh(); } catch (e) { log(e.message, "err"); }
});

$("join").onclick = () => busy("join", "joining", async () => {
  try {
    const r = await actor.join_queue();
    if ("err" in r) throw new Error(r.err);
    inQueue = true;
    log("joined queue: " + r.ok, "ok");
    await refresh();
  } catch (e) { log("join failed: " + e.message, "err"); await refresh().catch(() => {}); }
});

$("contribute").onclick = () => busy("contribute", "contributing", async () => {
  const TOTAL_PHASES = 2; // download, then upload; the transform sits between them
  try {
    resetStages();
    log("opening staging slot ...");
    let r = await actor.begin_contribution();
    if ("err" in r) throw new Error(r.err);
    stagingOpen = true;
    stage(1, "active", "opening…");

    const info = await actor.get_ceremony_info();
    const meta = await actor.get_current_params_meta();
    const tLen = Number(meta.transfer_len), dLen = Number(meta.deposit_len);
    const total = tLen + dLen;

    log(`downloading current parameters (transfer ${tLen} B, deposit ${dLen} B) ...`);
    let done = 0;
    const dl = (base) => (n) => {
      const cur = base + n;
      progress(true, `downloading ${mb(cur)} of ${mb(total)}`, (cur / total) * (100 / TOTAL_PHASES));
      stage(1, "active", `${mb(cur)} of ${mb(total)}`);
    };
    const curTransfer = await downloadParams("transfer", tLen, dl(0));
    const curDeposit = await downloadParams("deposit", dLen, dl(tLen));

    stage(1, "done", mb(total));
    stage(2, "active", "do not close this tab");
    progress(true, "transforming in this tab — do not close this page", 50);
    log("sampling secret + transforming IN THIS TAB (secret never leaves) ...", "warn");
    // Yield a frame so the label above actually paints before the wasm blocks the thread.
    await new Promise((res) => setTimeout(res, 30));
    const out = JSON.parse(transform_contribution(curTransfer, curDeposit, new Uint8Array(info.running_challenge)));

    stage(2, "done", "secret discarded");
    stage(3, "active", "");
    log("uploading transformed PUBLIC parameters ...");
    const tBytes = hexToBytes(out.transfer_delta), dBytes = hexToBytes(out.deposit_delta);
    const upTotal = tBytes.length + dBytes.length;
    // Set the label before the first chunk resolves, or it keeps reading "transforming" for the
    // whole of the first upload round trip.
    progress(true, `uploading ${mb(0)} of ${mb(upTotal)}`, 50);
    const ul = (base) => (n) => {
      const cur = base + n;
      progress(true, `uploading ${mb(cur)} of ${mb(upTotal)}`, 50 + (cur / upTotal) * 50);
      stage(3, "active", `${mb(cur)} of ${mb(upTotal)}`);
    };
    await uploadParams("transfer", tBytes, ul(0));
    await uploadParams("deposit", dBytes, ul(tBytes.length));

    const pk = (p) => ({ s_g1: Array.from(hexToBytes(p.s_g1)), s_delta_g1: Array.from(hexToBytes(p.s_delta_g1)), r_delta_g2: Array.from(hexToBytes(p.r_delta_g2)) });
    stage(3, "done", mb(upTotal));
    stage(4, "active", "submitting proof");
    progress(true, "submitting proof of knowledge", 100);
    log("submitting proof of knowledge (structural checks on-chain; soundness verified off-chain) ...");
    r = await actor.submit_contribution(pk(out.transfer_pok), pk(out.deposit_pok));
    if ("err" in r) throw new Error(r.err);
    stagingOpen = false;
    contributed = true;
    stage(4, "done", "appended");
    log("CONTRIBUTION ACCEPTED: " + r.ok, "ok");
    log("your secret has been discarded. thank you.", "ok");
    progress(false);
    await showReceipt();
    await refresh();
  } catch (e) {
    stagingOpen = false;
    progress(false);
    resetStages();
    log("contribution failed: " + e.message, "err");
    await refresh().catch(() => {});
  }
});

// --- receipt -------------------------------------------------------------------------------------
// The trust model asks the contributor to confirm their own contribution survived into the final
// transcript. That is only actionable if they leave with the values to check, so hand them over.
async function showReceipt() {
  try {
    const info = await actor.get_ceremony_info();
    const idx = Number(info.contribution_count) - 1;
    const got = await actor.get_contribution(BigInt(idx));
    if (!got.length) return;
    const c = got[0];
    myIndex = idx; // so the chain can mark which link is yours
    const rows = {
      // 0-based, because that is the index the standalone verifier reports and the one the
      // contributor will be matching against. The coordinator's own acceptance message counts
      // from 1 ("contribution 1 accepted"), so name this explicitly rather than say "#".
      "Transcript index (0-based)": String(idx),
      "Your principal": myPrincipal,
      "Coordinator": $("canisterId").value.trim(),
      "Transfer delta SHA-256": bytesToHex(new Uint8Array(c.transfer_delta_hash)),
      "Deposit delta SHA-256": bytesToHex(new Uint8Array(c.deposit_delta_hash)),
    };
    $("receiptBody").innerHTML = Object.entries(rows)
      .map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join("");
    $("receipt").classList.add("show");
    $("copyReceipt").onclick = async () => {
      const text = Object.entries(rows).map(([k, v]) => `${k}: ${v}`).join("\n");
      try {
        await navigator.clipboard.writeText(text);
        $("copyReceipt").textContent = "Copied";
        setTimeout(() => ($("copyReceipt").textContent = "Copy receipt"), 1800);
      } catch { log("clipboard blocked — select the receipt text manually", "warn"); }
    };
  } catch (e) { log("could not load receipt: " + e.message, "warn"); }
}
