// pICP shielded pool — a guided, live demo on IC mainnet (Menese DeFi Team).
//
// The page is built around one contrast, kept on screen at all times:
//   LEFT  — the public token ledger, where every entry carries amounts and principals.
//   RIGHT — the shielded pool, where the same machine stores only sealed envelopes.
// You sign in with your real Internet Identity principal, register a shielded address,
// and move value between the two worlds while both feeds update live from mainnet.
import React, { useEffect, useMemo, useRef, useState, useCallback } from "react";
import { Principal } from "@dfinity/principal";
import { actorsFor, bytesToHex, hexToBytes } from "./ic.js";
import { loadProver, loadProvingKeys } from "./prover.js";
import { CANISTERS, BASE, BIRTHDAY_RECOVERY_ENABLED } from "./config.js";
import { parseDemoAmount } from "./amounts.js";
import * as W from "./wallet.js";
import * as ledgerFeed from "./ledgerFeed.js";
import {
  existingSession, loginWithInternetIdentity, logout as iiLogout,
  throwawayIdentity, ephemeralShieldedAccountFor, legacyShieldedAccountFor, legacyShieldedAccounts,
  vetkeyShieldedAccountFor,
  forgetLegacyShieldedAccount, encPkHex,
} from "./auth.js";

const fmt = (e8s) => (Number(e8s) / Number(BASE)).toLocaleString(undefined, { maximumFractionDigits: 4 });
const shortP = (t) => (t.length > 14 ? t.slice(0, 5) + "…" + t.slice(-5) : t);
const shortHex = (h, n = 10) => h.slice(0, n) + "…" + h.slice(-6);

const ACTS = [
  { n: "01", key: "connect", title: "Sign in" },
  { n: "02", key: "fund", title: "Get demo tokens" },
  { n: "03", key: "shield", title: "Shield them" },
  { n: "04", key: "send", title: "Send privately" },
  { n: "05", key: "find", title: "Find your money" },
  { n: "06", key: "exit", title: "Withdraw safely" },
];

function Pill({ tone = "dim", children, ...rest }) {
  const map = {
    ok: "bg-ok/10 text-ok border-ok/30",
    warn: "bg-observer/10 text-observer border-observer/30",
    danger: "bg-danger/10 text-danger border-danger/30",
    veil: "bg-veil/10 text-veil border-veil/30",
    day: "bg-daylight/10 text-daylight border-daylight/30",
    dim: "bg-slab text-dim border-hairline",
  };
  return (
    <span {...rest} className={`px-2 py-0.5 rounded-full border text-[11px] font-mono ${map[tone]}`}>
      {children}
    </span>
  );
}

function Stage({ stage }) {
  const [, force] = useState(0);
  useEffect(() => {
    if (!stage) return;
    const t = setInterval(() => force((x) => x + 1), 500);
    return () => clearInterval(t);
  }, [stage]);
  if (!stage) return null;
  const secs = Math.max(0, Math.round((Date.now() - stage.startedAt) / 1000));
  return (
    <div className="flex items-center gap-3 bg-veil/10 border border-veil/30 rounded-lg px-3 py-2 animate-risein" data-testid="stage">
      <span className="inline-block w-3 h-3 rounded-full border-2 border-veil border-t-transparent animate-spin" />
      <span className="text-sm text-bright">{stage.label}</span>
      <span className="ml-auto text-xs font-mono text-dim">{secs}s</span>
    </div>
  );
}

function ActionError({ error }) {
  if (!error) return null;
  return (
    <div className="bg-danger/10 border border-danger/40 rounded-lg px-3 py-2 text-sm text-danger animate-risein" data-testid="action-error">
      {error}
    </div>
  );
}

export default function App() {
  const wasmRef = useRef(null);
  const keysRef = useRef(null);
  const feedTipRef = useRef(-1);

  const [status, setStatus] = useState("booting");
  const [lineage, setLineage] = useState(null);
  const [setupMode, setSetupMode] = useState(null);
  const [session, setSession] = useState(null); // { actors, principalText, mode, account, registered }
  const [act, setAct] = useState(0);
  const [busy, setBusy] = useState(false);
  const [stage, setStage] = useState(null);
  const [error, setError] = useState(null);

  const [balance, setBalance] = useState(0n);
  const [shielded, setShielded] = useState({ notes: [], scanned: 0, opened: 0, scannedOnce: false });
  const [feed, setFeed] = useState({ entries: [], tip: -1 });
  const [providerNotes, setProviderNotes] = useState([]);
  const [ledgerStatus, setLedgerStatus] = useState(null);
  const [poolView, setPoolView] = useState("provider"); // provider | mine
  const [freshFeedIdx, setFreshFeedIdx] = useState(new Set());
  const [stampOn, setStampOn] = useState(false);
  const [sentOnce, setSentOnce] = useState(false);
  const [pir, setPir] = useState(null);
  const [unshield, setUnshield] = useState(null);
  const [migrationTarget, setMigrationTarget] = useState(null);
  const [log, setLog] = useState([]);

  const [shieldAmt, setShieldAmt] = useState("40000");
  const [sendAmt, setSendAmt] = useState("12000");
  const [sendTo, setSendTo] = useState("");
  const [withdrawAmt, setWithdrawAmt] = useState("1000");
  const [lastWithdrawAmt, setLastWithdrawAmt] = useState(null);

  const addLog = useCallback((who, msg, tone = "dim") => {
    setLog((l) => [{ t: new Date().toLocaleTimeString(), who, msg, tone }, ...l].slice(0, 60));
  }, []);

  const stageStep = (label) => setStage({ label, startedAt: Date.now() });

  // ---------- boot ----------
  useEffect(() => {
    (async () => {
      try {
        const wasm = await loadProver();
        wasmRef.current = wasm;
        setStatus("loading proving keys");
        keysRef.current = await loadProvingKeys();
        const okT = wasm.assert_pk_matches_vk(keysRef.current.transfer, keysRef.current.transferVk);
        const okD = wasm.assert_pk_matches_vk(keysRef.current.deposit, keysRef.current.depositVk);
        setLineage(okT && okD);
        setSetupMode(keysRef.current.manifest.setup_mode);
        setStatus("ready");
        addLog("system", `prover loaded; manifest hashes and embedded proving-key lineage ${okT && okD ? "verified" : "MISMATCH"}; setup=${keysRef.current.manifest.setup_mode}`, okT && okD ? "ok" : "danger");
        const params = new URLSearchParams(window.location.search);
        if (params.get("mode") === "demo") {
          await connect("demo");
        } else {
          const restored = await existingSession();
          if (restored) await connectWith(restored, "ii");
        }
      } catch (e) {
        setStatus("error: " + e.message);
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ---------- connect + register ----------
  async function connectWith(identity, mode, deriveWithVetKey = mode === "ii") {
    const wasm = wasmRef.current;
    stageStep(deriveWithVetKey
      ? "Recovering your II-bound shielded account with vetKeys…"
      : "Creating a memory-only throwaway shielded account…");
    const actors = await actorsFor(identity);
    const principalText = actors.principal.toText();
    const secureAccount = deriveWithVetKey
      ? await vetkeyShieldedAccountFor(wasm, actors)
      : ephemeralShieldedAccountFor(wasm);
    const legacyAccount = legacyShieldedAccountFor(wasm, principalText);
    let registered = false;
    const entry = await W.lookupPrincipal(actors, principalText);
    let account = secureAccount;
    let migration = null;
    const matches = (candidate) => candidate && entry &&
      entry.shielded_pk === candidate.pk && entry.enc_pk === encPkHex(candidate.encPk);
    if (matches(secureAccount)) {
      registered = true;
      addLog("you", "your principal recovered the same vetKey shielded account — no browser key storage", "ok");
    } else if (deriveWithVetKey && matches(legacyAccount)) {
      account = legacyAccount;
      migration = { source: legacyAccount, target: secureAccount, storagePrincipalText: principalText };
      registered = true;
      addLog("you", "legacy browser-held notes found — they remain usable until you approve migration to the II-bound account", "warn");
    } else if (entry) {
      throw new Error("This principal already has a different shielded address, but its legacy key is not available in this browser. Refusing to rotate it or strand funds.");
    } else {
      stageStep("Registering your shielded address on-chain…");
      // Creation floor, sampled BEFORE register: a sender can only discover this pk via the
      // directory AFTER registration, so no owned note can sit below this height. syncWallet
      // publishes it (sealed) once the directory confirms no record exists — flag-gated.
      const creationSample = BIRTHDAY_RECOVERY_ENABLED ? await W.recordBirthday(actors) : null;
      const res = await W.registerInDirectory(actors, secureAccount, encPkHex(secureAccount.encPk));
      if ("err" in res) throw new Error("registration failed: " + res.err);
      if (creationSample != null) secureAccount.creationBirthday = creationSample;
      registered = true;
      addLog("you", deriveWithVetKey
        ? "II-bound shielded account registered: the private keys can be recovered after the same login"
        : "throwaway shielded account registered: its secrets exist in memory only and vanish when this tab closes",
      deriveWithVetKey ? "ok" : "warn");
    }
    // Search all old keys on this origin after establishing the current directory entry. This
    // rescues notes created under a throwaway identity whose public principal no longer exists in
    // the new tab. Only accounts that actually open an unspent note are offered for migration.
    if (deriveWithVetKey && !migration) {
      for (const candidate of legacyShieldedAccounts(wasm)) {
        if (candidate.account.pk === secureAccount.pk) continue;
        const legacyScan = await W.scanNotes(actors, wasm, candidate.account);
        const legacyValue = legacyScan.notes.reduce((sum, note) => sum + note.v, 0n);
        if (legacyValue > 0n) {
          migration = {
            source: candidate.account,
            target: secureAccount,
            storagePrincipalText: candidate.principalText,
          };
          addLog("you", `found ${fmt(legacyValue)} DEMO under an old browser-held demo key — it can be migrated without the obsolete throwaway principal`, "warn");
          break;
        }
      }
    }
    setMigrationTarget(migration);
    setSession({ actors, principalText, mode, account, registered });
    setStage(null);
    setAct(1);
    await refreshAll(actors, account);
  }

  async function connect(mode) {
    setError(null);
    setBusy(true);
    try {
      // Deterministic throwaway identities are available only in Vite's development build so
      // Playwright can reload the same principal while exercising legacy-key migration. The
      // production bundle always generates a fresh random throwaway identity.
      const requestedSeed = import.meta.env.DEV
        ? new URLSearchParams(window.location.search).get("e2e_seed")
        : null;
      const testSeed = requestedSeed && /^[0-9a-f]{64}$/i.test(requestedSeed)
        ? hexToBytes(requestedSeed)
        : undefined;
      const identity = mode === "ii"
        ? await loginWithInternetIdentity()
        : throwawayIdentity(testSeed);
      await connectWith(identity, mode, mode === "ii" || Boolean(testSeed));
    } catch (e) {
      setStage(null);
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function disconnect() {
    if (session?.mode === "ii") await iiLogout();
    window.location.search = ""; // full reset — simplest honest state clear
  }

  // ---------- refreshers ----------
  const refreshAll = useCallback(async (actors, account) => {
    const a = actors || session?.actors;
    const acc = account || session?.account;
    if (!a) return;
    const [bal, f, pool, st] = await Promise.all([
      W.tokenBalance(a, a.principal),
      ledgerFeed.readTokenLedger(a),
      W.readNotes(a),
      a.ledger.status(),
    ]);
    setBalance(bal);
    const fresh = new Set(f.entries.filter((e) => e.index > feedTipRef.current).map((e) => e.index));
    if (feedTipRef.current >= 0 && fresh.size > 0) {
      setFreshFeedIdx(fresh);
      setStampOn(false);
    }
    feedTipRef.current = f.tip;
    setFeed(f);
    setProviderNotes(pool.slice().reverse());
    setLedgerStatus({
      note_count: Number(st.note_count),
      nullifier_count: Number(st.nullifier_count),
      note_root: bytesToHex(new Uint8Array(st.note_root)),
    });
    if (acc) {
      // ii-vetkey accounts go through the one-call sync (cursor + birthday + encrypted cache).
      // With BIRTHDAY_RECOVERY_ENABLED unset this is byte-identical to the direct scanNotes
      // genesis scan (no store, no directory birthday traffic); when set, a fresh device
      // recovers its birthday from the vetKey-sealed directory record and scans [birthday, tip].
      const scan = acc.custody === "ii-vetkey"
        ? await W.syncWallet(a, wasmRef.current, acc, {
            store: BIRTHDAY_RECOVERY_ENABLED ? W.indexedDbStore() : null,
            creationBirthday: acc.creationBirthday ?? null,
          })
        : await W.scanNotes(a, wasmRef.current, acc);
      setShielded({ ...scan, scannedOnce: true });
    }
  }, [session]);

  useEffect(() => {
    if (!session) return;
    const t = setInterval(() => { refreshAll().catch(() => {}); }, 20000);
    return () => clearInterval(t);
  }, [session, refreshAll]);

  const run = (fn) => async (...args) => {
    setBusy(true);
    setError(null);
    try {
      await fn(...args);
    } catch (e) {
      setError(e.message);
      addLog("error", e.message, "danger");
    } finally {
      setBusy(false);
      setStage(null);
    }
  };

  // ---------- act handlers ----------
  const doFaucet = run(async () => {
    stageStep("Asking the faucet to top you up…");
    const r = await W.faucet(session.actors);
    if ("ok" in r) addLog("you", `faucet minted ${fmt(r.ok)} DEMO to your principal — publicly`, "ok");
    else if (r.err === "balance-sufficient") setError("You already hold 100,000 DEMO — spend some first, then the faucet refills you.");
    else setError("Faucet: " + r.err);
    await refreshAll();
    if (act === 1) setAct(2);
  });

  const affordable = balance > W.SHIELD_OVERHEAD ? (balance - W.SHIELD_OVERHEAD) / BASE : 0n;

  const doShield = run(async () => {
    const whole = BigInt(shieldAmt.replace(/[^0-9]/g, "") || "0");
    if (whole <= 0n) { setError("Enter an amount to shield."); return; }
    if (whole > affordable) {
      setError(`You can shield at most ${affordable.toLocaleString()} DEMO right now (your balance minus 0.0002 in token fees).`);
      return;
    }
    const value = whole * BASE;
    stageStep("Proving your deposit in this browser — the proof shows the note is well-formed without revealing its secrets…");
    await new Promise((r) => setTimeout(r, 30)); // let the stage paint before wasm blocks the thread
    const { res } = await W.shield(session.actors, wasmRef.current, keysRef.current, session.account, value);
    if (res.outcome !== "ACCEPT" && !res.outcome.startsWith("ACCEPT")) {
      setError("The ledger rejected the deposit: " + res.outcome);
      return;
    }
    addLog("you", `shielded ${whole.toLocaleString()} DEMO — this deposit is the last public thing that happens to it`, "veil");
    stageStep("Rescanning the pool with your key…");
    await refreshAll();
    if (shielded.notes.length + 1 >= 2 && act <= 2) setAct(3);
    setShieldAmt(whole === 40000n ? "25000" : "10000");
  });

  const doSend = run(async () => {
    let recipientPrincipal;
    try {
      recipientPrincipal = Principal.fromText(sendTo.trim()).toText();
    } catch {
      setError("That doesn't parse as an ICP principal. Paste the recipient's principal (or use yours to send to yourself).");
      return;
    }
    const whole = BigInt(sendAmt.replace(/[^0-9]/g, "") || "0");
    if (whole <= 0n) { setError("Enter an amount to send."); return; }
    const notes = shielded.notes.slice().sort((a, b) => (a.v > b.v ? -1 : 1));
    if (notes.length < 2) {
      setError("A private transfer spends two notes at once — shield one more time first.");
      return;
    }
    const ins = notes.slice(0, 2);
    const total = ins[0].v + ins[1].v;
    if (total < whole * BASE) {
      setError(`Your two largest notes hold ${fmt(total)} DEMO together — send at most that.`);
      return;
    }
    stageStep("Looking up the recipient's shielded address in the directory…");
    const entry = await W.lookupPrincipal(session.actors, recipientPrincipal);
    if (!entry) {
      setError("That principal hasn't opened a shielded account yet. They need to sign in here once — registration is automatic.");
      return;
    }
    const tipBefore = feed.tip;
    stageStep("Sealing the note to the recipient and proving the transfer in your browser (10–30s)…");
    await new Promise((r) => setTimeout(r, 30));
    const { res } = await W.privateTransfer(
      session.actors, wasmRef.current, keysRef.current, session.account, ins, entry, whole * BASE, 0n
    );
    if (res.outcome !== "ACCEPT") {
      setError("The ledger rejected the transfer: " + res.outcome);
      return;
    }
    setSentOnce(true);
    addLog("you", `private transfer accepted — ${whole.toLocaleString()} DEMO to ${shortP(recipientPrincipal)}; no amount or recipient exists on-chain`, "veil");
    stageStep("Checking the public ledger for what it learned…");
    await refreshAll();
    const f = await ledgerFeed.readTokenLedger(session.actors);
    if (f.tip === tipBefore) {
      setStampOn(true);
      addLog("chain", "the public token ledger wrote NOTHING for that transfer", "ok");
    }
    if (act <= 3) setAct(4);
  });

  const doRescan = run(async () => {
    stageStep("Trying your key on every sealed envelope in the pool…");
    await refreshAll();
    addLog("you", `your key opened ${shielded.opened} of ${shielded.scanned} envelopes — the chain never learned which ones are yours`, "veil");
  });

  const doMigrateKeys = run(async () => {
    if (!migrationTarget) return;
    const sourceScan = await W.scanNotes(session.actors, wasmRef.current, migrationTarget.source);
    const targetBefore = await W.scanNotes(session.actors, wasmRef.current, migrationTarget.target);
    const targetValueBefore = targetBefore.notes.reduce((sum, note) => sum + note.v, 0n);
    const spendable = sourceScan.notes.slice().sort((a, b) => (a.v > b.v ? -1 : 1));
    if (spendable.length < 2) {
      setError("Migration needs two inputs. Shield one small additional note with the legacy account, then migrate again.");
      return;
    }
    const inputs = spendable.slice(0, 2);
    const moved = inputs[0].v + inputs[1].v;
    stageStep("Privately moving legacy notes into your deterministic II/vetKey account…");
    await new Promise((r) => setTimeout(r, 30));
    const { res } = await W.privateTransfer(
      session.actors,
      wasmRef.current,
      keysRef.current,
      migrationTarget.source,
      inputs,
      { shielded_pk: migrationTarget.target.pk, enc_pk: encPkHex(migrationTarget.target.encPk) },
      moved,
      0n
    );
    if (res.outcome !== "ACCEPT") throw new Error("migration transfer rejected: " + res.outcome);

    const remaining = await W.scanNotes(session.actors, wasmRef.current, migrationTarget.source);
    const remainingValue = remaining.notes.reduce((sum, note) => sum + note.v, 0n);
    if (remainingValue > 0n) {
      if (session.account.pk === migrationTarget.source.pk) {
        setShielded({ ...remaining, scannedOnce: true });
      }
      addLog("you", `migrated ${fmt(moved)} DEMO; ${fmt(remainingValue)} remains in legacy notes — run migration once more`, "warn");
      return;
    }

    const register = await W.registerInDirectory(
      session.actors,
      migrationTarget.target,
      encPkHex(migrationTarget.target.encPk),
    );
    if ("err" in register) throw new Error("secure address registration failed: " + register.err);
    const recovered = await W.scanNotes(session.actors, wasmRef.current, migrationTarget.target);
    if (recovered.notes.reduce((sum, note) => sum + note.v, 0n) < targetValueBefore + moved) {
      throw new Error("secure-account rescan did not recover the migrated value; legacy key retained");
    }
    forgetLegacyShieldedAccount(migrationTarget.storagePrincipalText);
    setSession((current) => ({ ...current, account: migrationTarget.target }));
    setMigrationTarget(null);
    setShielded({ ...recovered, scannedOnce: true });
    addLog("you", "migration verified; the old localStorage secret was erased and the account now recovers through II + vetKeys", "ok");
  });

  const doPir = run(async () => {
    const all = await W.readNotes(session.actors);
    if (all.length === 0) { setError("Nothing in the pool yet — shield first."); return; }
    const mine = shielded.notes.length ? shielded.notes[shielded.notes.length - 1].position : all.length - 1;
    stageStep("Encrypting selectors — the record number never leaves your browser…");
    const out = await W.pirLookup(session.actors, wasmRef.current, mine, all.length);
    const expected = all.find((n) => n.position === mine)?.commitment;
    setPir({ ...out, target: mine, match: out.recovered === expected });
    addLog("you", `the ledger scanned all ${out.trace.records_scanned} records uniformly and answered without knowing the question`, "ok");
  });

  const doUnshield = run(async () => {
    const notes = shielded.notes.slice().sort((a, b) => (a.v > b.v ? -1 : 1));
    if (notes.length < 2) { setError("You need two unspent notes to build the withdraw proof — shield again first."); return; }
    const amount = parseDemoAmount(withdrawAmt);
    if (amount === null || amount <= 0n) {
      setError("Enter a positive DEMO amount with no more than 8 decimal places.");
      return;
    }
    const inputs = notes.slice(0, 2);
    const total = inputs[0].v + inputs[1].v;
    const maximum = total > W.UNSHIELD_FEE ? total - W.UNSHIELD_FEE : 0n;
    if (amount > maximum) {
      setError(`Your two selected notes can withdraw at most ${fmt(maximum)} DEMO after the ${fmt(W.UNSHIELD_FEE)} DEMO ledger fee.`);
      return;
    }
    const balanceBefore = balance;
    stageStep(`Binding ${fmt(amount)} DEMO and your public ICRC account into the proof…`);
    await new Promise((r) => setTimeout(r, 30));
    const r = await W.unshield(session.actors, wasmRef.current, keysRef.current, session.account, inputs, amount);
    setUnshield(r.outcome);
    if (!r.outcome.startsWith("ACCEPT")) {
      addLog("chain", `withdrawal did not finalize: ${r.outcome}; the pending intent can be resumed without double-paying`, "warn");
      return;
    }
    setLastWithdrawAmt(amount);
    await refreshAll();
    const after = await W.tokenBalance(session.actors, session.actors.principal);
    if (after < balanceBefore + amount) throw new Error("withdrawal finalized but the requested public balance delta is missing");
    addLog("chain", `${fmt(amount)} DEMO withdrew to your bound public account; the exact ICRC-1 payout block was verified before shielded state finalized`, "ok");
  });

  const doResumeUnshield = run(async () => {
    stageStep("Reconciling the token ledger by intent before any retry…");
    const r = await session.actors.ledger.resume_unshield();
    setUnshield(r.outcome);
    if (!r.outcome.startsWith("ACCEPT")) {
      addLog("chain", `withdrawal remains recoverable: ${r.outcome}`, "warn");
      return;
    }
    await refreshAll();
    addLog("chain", "pending withdrawal reconciled and finalized without a second token transfer", "ok");
  });

  // ---------- copy per act ----------
  const you = session?.principalText;
  const withdrawalInputs = shielded.notes.slice().sort((a, b) => (a.v > b.v ? -1 : 1)).slice(0, 2);
  const withdrawalInputTotal = withdrawalInputs.reduce((sum, note) => sum + note.v, 0n);
  const maximumWithdrawal = withdrawalInputs.length === 2 && withdrawalInputTotal > W.UNSHIELD_FEE
    ? withdrawalInputTotal - W.UNSHIELD_FEE
    : 0n;
  const labelFor = (p) => {
    if (!p) return "—";
    if (p === you) return "you";
    if (p === CANISTERS.zk_ledger) return "the pool";
    return shortP(p);
  };
  const feedLine = (e) => {
    const amt = e.amt !== null ? fmt(e.amt) + " DEMO" : "";
    if (e.btype === "1mint") return { icon: "⬇", text: `Faucet minted ${amt} → ${labelFor(e.to)}` };
    if (e.btype === "2approve") return { icon: "✍", text: `${labelFor(e.from)} allowed ${labelFor(e.spender)} to pull up to ${amt}` };
    if (e.btype === "2xfer") return { icon: "→", text: `${labelFor(e.from)} → ${labelFor(e.to)} · ${amt}` };
    if (e.btype === "1xfer") return { icon: "→", text: `${labelFor(e.from)} → ${labelFor(e.to)} · ${amt}` };
    return { icon: "·", text: e.btype };
  };

  const shieldedTotal = shielded.notes.reduce((a, n) => a + n.v, 0n);

  // ---------- render ----------
  return (
    <div className="relative max-w-7xl mx-auto px-4 md:px-8 pb-16">
      {/* header */}
      <header className="flex items-center gap-3 py-5 flex-wrap">
        <div className="font-display font-bold text-lg tracking-tight">
          pICP<span className="text-veil"> · shielded pool</span>
        </div>
        <Pill tone={status === "ready" ? "ok" : "warn"} data-testid="status">{status}</Pill>
        <Pill tone={lineage ? "ok" : lineage === null ? "dim" : "danger"}>
          keyset {lineage === null ? "…" : lineage ? "integrity verified" : "MISMATCH"}
        </Pill>
        {setupMode && <Pill tone="warn">setup: {setupMode}</Pill>}
        <Pill tone="veil">Groth16 in your browser</Pill>
        <div className="ml-auto flex items-center gap-2">
          {session && (
            <>
              <span className="font-mono text-xs text-dim bg-slab border border-hairline rounded-full px-3 py-1"
                data-testid="principal" data-principal={session.principalText} title={session.principalText}>
                {session.mode === "ii" ? "II · " : "throwaway · "}{shortP(session.principalText)}
              </span>
              <button onClick={() => navigator.clipboard?.writeText(session.principalText)}
                className="text-xs text-dim hover:text-bright border border-hairline rounded-full px-3 py-1"
                title="Copy your principal — give it to someone so they can send you shielded funds">
                copy
              </button>
              <button onClick={disconnect} className="text-xs text-dim hover:text-danger border border-hairline rounded-full px-3 py-1">
                sign out
              </button>
            </>
          )}
        </div>
      </header>

      {session && migrationTarget && (
        <section className="mb-5 rounded-2xl border border-observer/35 bg-observer/10 p-4 md:flex items-center gap-5 shadow-glow" data-testid="key-migration">
          <div className="flex-1">
            <div className="font-display font-medium text-bright">Move this demo account out of browser storage</div>
            <p className="text-sm text-dim mt-1">
              Your existing notes are still safe and spendable with the legacy key on this device.
              Approve one private migration to an II-bound vetKey account recoverable after the same login on another device.
            </p>
          </div>
          <button onClick={doMigrateKeys} disabled={busy} data-testid="migrate-keys"
            className="mt-3 md:mt-0 bg-observer text-abyss font-semibold rounded-xl px-5 py-2.5 hover:brightness-110 disabled:opacity-40">
            Secure my existing notes
          </button>
        </section>
      )}

      {/* hero (pre-connect) */}
      {!session && (
        <section className="relative py-16 md:py-24 lg:pr-[390px] min-h-[610px]">
          <div className="inline-flex items-center gap-2 rounded-full bg-white/70 border border-white px-3 py-1 text-xs text-veil shadow-card mb-6">
            <span className="h-2 w-2 rounded-full bg-ok" /> Live privacy, verifiable end to end
          </div>
          <h1 className="font-display font-bold text-4xl md:text-6xl leading-[1.08] tracking-tight">
            Move value <span className="text-transparent bg-clip-text bg-gradient-to-r from-veil via-[#8a63ff] to-daylight">no one can watch.</span>
          </h1>
          <p className="mt-5 text-dim text-base md:text-lg leading-relaxed">
            This is a live shielded pool on Internet Computer mainnet. Sign in with your real
            principal, put a demo token behind the veil, and send it to any other principal —
            while the page shows you, side by side, what the public ledger records and what the
            machines running the network can actually see. Every proof is made in your browser;
            authenticated shielded keys are recovered into browser memory through II + vetKeys,
            never exported from the passkey or stored by the app.
          </p>
          <div className="mt-8 flex gap-3 flex-wrap items-center">
            <button onClick={() => connect("ii")} disabled={busy || status !== "ready"}
              data-testid="connect-ii"
              className="bg-veil text-white font-semibold rounded-xl px-6 py-3 hover:bg-veil/90 disabled:opacity-40 shadow-glow transition">
              Sign in with Internet Identity
            </button>
            <button onClick={() => connect("demo")} disabled={busy || status !== "ready"}
              data-testid="connect-demo"
              className="bg-white/70 border border-hairline text-dim hover:text-bright rounded-xl px-5 py-3 disabled:opacity-40 shadow-card transition">
              Try instantly with a throwaway identity
            </button>
          </div>
          <div className="mt-6"><Stage stage={stage} /><ActionError error={error} /></div>
          <div className="mt-10 flex gap-2 flex-wrap">
            <Pill tone="day">a real ICRC token ledger, in the open</Pill>
            <Pill tone="veil">sealed notes only your key opens</Pill>
            <Pill tone="warn">the node provider's view, live</Pill>
          </div>
          <aside className="hidden lg:block absolute right-0 top-16 w-[340px] rounded-[2rem] border border-white bg-white/70 backdrop-blur-xl p-5 shadow-glow rotate-[1.5deg]">
            <div className="flex items-center justify-between mb-5">
              <span className="text-[10px] tracking-[.22em] font-mono text-dim">VALUE, TWO VIEWS</span>
              <span className="h-2.5 w-2.5 rounded-full bg-ok shadow-[0_0_0_6px_rgba(8,124,89,.1)]" />
            </div>
            <div className="rounded-2xl border border-daylight/20 bg-daylight/5 p-4">
              <div className="text-[10px] tracking-[.18em] font-mono text-daylight">PUBLIC EDGE</div>
              <div className="font-display text-lg mt-2">35,000 DEMO</div>
              <div className="text-xs text-dim mt-1 font-mono">principal · amount · timestamp</div>
            </div>
            <div className="relative h-16 flex items-center justify-center">
              <div className="absolute w-px h-full bg-gradient-to-b from-daylight via-veil to-veil" />
              <span className="relative rounded-full bg-white border border-veil/25 px-3 py-1 text-[10px] text-veil font-mono shadow-card">
                client-side proof
              </span>
            </div>
            <div className="rounded-2xl bg-gradient-to-br from-veil to-[#8569ff] p-4 text-white shadow-glow">
              <div className="text-[10px] tracking-[.18em] font-mono text-white/70">SHIELDED CORE</div>
              <div className="font-display text-lg mt-2">2 sealed notes</div>
              <div className="text-xs text-white/70 mt-1 font-mono">no owner · no amount · no link</div>
            </div>
            <div className="grid grid-cols-2 gap-2 mt-3 text-[10px] font-mono">
              <div className="rounded-xl bg-abyss p-3"><span className="text-ok">✓</span> II + vetKey recovery</div>
              <div className="rounded-xl bg-abyss p-3"><span className="text-ok">✓</span> bound withdrawal</div>
            </div>
          </aside>
        </section>
      )}

      {session && (
        <>
          {/* journey rail */}
          <nav className="flex gap-2 overflow-x-auto scroll-thin py-3" aria-label="demo steps">
            {ACTS.map((a, i) => (
              <button key={a.key} onClick={() => setAct(i)} data-testid={`act-${i}`}
                className={`flex items-center gap-2 rounded-full border px-4 py-1.5 whitespace-nowrap text-sm transition
                  ${i === act ? "border-veil bg-veil/10 text-bright" : "border-hairline text-dim hover:text-bright"}`}>
                <span className="font-display text-[11px]">{a.n}</span>
                {a.title}
              </button>
            ))}
          </nav>

          {/* wallet strip — both balances, always in view */}
          <div className="flex gap-4 flex-wrap items-baseline bg-white/75 backdrop-blur border border-white rounded-2xl px-5 py-3 mb-4 text-xs font-mono shadow-card">
            <span><span className="text-dim">public DEMO </span><span className="text-daylight text-sm" data-testid="bal">{fmt(balance)}</span></span>
            <span><span className="text-dim">shielded </span><span className="text-veil text-sm">{fmt(shieldedTotal)}</span></span>
            <span><span className="text-dim">notes </span><span className="text-veil" data-testid="note-count">{shielded.notes.length}</span></span>
          </div>

          {/* action stage */}
          <section className="bg-white/90 backdrop-blur border border-white rounded-3xl p-5 md:p-7 mb-6 animate-risein shadow-card" key={act}>
            {act === 0 && (
              <div className="md:flex gap-8 items-start">
                <div className="md:w-2/5 space-y-2">
                  <h2 className="font-display font-medium text-xl">You're in.</h2>
                  {session.account.custody === "ii-vetkey" ? (
                    <p className="text-dim text-sm leading-relaxed">
                      Your principal is your public name on the Internet Computer. After login, the
                      IC delivered a deterministic <span className="text-veil">vetKey</span> encrypted
                      to this tab. Your browser verified it and derived the spend and envelope keys
                      in memory, so the same II principal can recover the same shielded account on
                      another device without exporting the passkey.
                    </p>
                  ) : (
                    <p className="text-dim text-sm leading-relaxed">
                      This instant trial made a random principal and shielded account in tab memory.
                      Nothing is saved, but nothing is recoverable either: close or reload this tab
                      and the throwaway funds are gone. Sign in with Internet Identity for passkey-
                      backed, cross-device vetKey recovery.
                    </p>
                  )}
                </div>
                <div className="flex-1 space-y-2 mt-4 md:mt-0 text-sm">
                  <div className="bg-abyss rounded-lg p-3 font-mono text-xs">
                    <div className="text-dim mb-1">your principal (public)</div>
                    <div className="hexwrap text-daylight">{session.principalText}</div>
                  </div>
                  <div className="bg-abyss rounded-lg p-3 font-mono text-xs">
                    <div className="text-dim mb-1">your shielded address (public — where notes are sent)</div>
                    <div className="hexwrap text-veil">{shortHex(session.account.pk, 18)}</div>
                  </div>
                  <p className="text-xs text-dim">
                    <span className="text-ok">No shielded secret is stored by the app.</span> The
                    public address is registered on-chain; private key material lives only in this
                    page session. {session.account.custody === "ii-vetkey"
                      ? "The vetKey broker canister remains part of the demo's trust boundary."
                      : "This throwaway account cannot be recovered after the tab closes."}
                  </p>
                  <button onClick={() => setAct(1)} className="bg-veil/15 text-veil rounded-lg px-4 py-2 text-sm hover:bg-veil/25">
                    Next: get demo tokens →
                  </button>
                </div>
              </div>
            )}

            {act === 1 && (
              <div className="md:flex gap-8 items-start">
                <div className="md:w-2/5 space-y-2">
                  <h2 className="font-display font-medium text-xl">Get demo tokens — publicly.</h2>
                  <p className="text-dim text-sm leading-relaxed">
                    DEMO is an ordinary ICRC token that exists for this demo. The faucet tops you up
                    to 100,000. Watch the ledger on the left when you press it: the mint appears
                    with <span className="text-daylight">your principal and the amount in the open</span> —
                    that's what every normal token transaction looks like, to everyone, forever.
                  </p>
                </div>
                <div className="flex-1 space-y-3 mt-4 md:mt-0">
                  <div className="bg-abyss rounded-lg p-3 flex items-baseline gap-3">
                    <span className="text-dim text-xs">your DEMO balance</span>
                    <span className="font-mono text-2xl">{fmt(balance)}</span>
                  </div>
                  <button onClick={doFaucet} disabled={busy} data-testid="faucet-run"
                    className="bg-daylight/15 text-daylight rounded-lg px-5 py-2.5 text-sm hover:bg-daylight/25 disabled:opacity-40">
                    Faucet — top me up to 100,000 DEMO
                  </button>
                  <Stage stage={stage} /><ActionError error={error} />
                </div>
              </div>
            )}

            {act === 2 && (
              <div className="md:flex gap-8 items-start">
                <div className="md:w-2/5 space-y-2">
                  <h2 className="font-display font-medium text-xl">Shield: step behind the veil.</h2>
                  <p className="text-dim text-sm leading-relaxed">
                    Shielding moves tokens into the pool and hands you a <span className="text-veil">note</span> —
                    a sealed claim only your key can open. The deposit itself is public (left pane:
                    you → the pool, amount visible). It is the <em>last</em> public thing that happens
                    to this money. Shield <strong>twice</strong> — a private transfer spends two notes at once.
                  </p>
                  <p className="text-xs text-dim">
                    The proof runs in your browser (~1s). Your note secrets never leave it.
                  </p>
                </div>
                <div className="flex-1 space-y-3 mt-4 md:mt-0">
                  <div className="flex gap-2">
                    <input value={shieldAmt} onChange={(e) => setShieldAmt(e.target.value)} data-testid="shield-amt"
                      inputMode="numeric"
                      className="flex-1 bg-abyss border border-hairline rounded-lg px-3 py-2.5 font-mono text-sm w-0" />
                    <button onClick={doShield} disabled={busy} data-testid="shield-run"
                      className="bg-veil/15 text-veil rounded-lg px-5 py-2.5 text-sm hover:bg-veil/25 disabled:opacity-40 whitespace-nowrap">
                      Shield →
                    </button>
                  </div>
                  <p className="text-xs text-dim">
                    You can shield up to <span className="font-mono text-bright">{affordable.toLocaleString()}</span> DEMO
                    (balance minus 0.0002 token fees). Notes so far:{" "}
                    <span className="font-mono text-veil">{shielded.notes.length}</span>
                  </p>
                  <Stage stage={stage} /><ActionError error={error} />
                </div>
              </div>
            )}

            {act === 3 && (
              <div className="md:flex gap-8 items-start">
                <div className="md:w-2/5 space-y-2">
                  <h2 className="font-display font-medium text-xl">Send to any principal. Privately.</h2>
                  <p className="text-dim text-sm leading-relaxed">
                    Paste any ICP principal whose owner has signed in here once. Your browser seals
                    a note to their key, proves the transfer is honest without revealing amount,
                    sender or recipient — and the public ledger on the left will record{" "}
                    <span className="text-bright">nothing at all</span>. They sign in on their own
                    device and find the money with their key.
                  </p>
                  <p className="text-xs text-dim">
                    Alone right now? Paste your own principal ({shortP(you)}) and send to yourself —
                    the chain can't tell the difference. That's the point.
                  </p>
                </div>
                <div className="flex-1 space-y-3 mt-4 md:mt-0">
                  <input value={sendTo} onChange={(e) => setSendTo(e.target.value)} data-testid="send-to"
                    placeholder="recipient principal, e.g. w3gef-eqllq-…"
                    className="w-full bg-abyss border border-hairline rounded-lg px-3 py-2.5 font-mono text-xs" />
                  <div className="flex gap-2">
                    <input value={sendAmt} onChange={(e) => setSendAmt(e.target.value)} data-testid="send-amt"
                      inputMode="numeric"
                      className="flex-1 bg-abyss border border-hairline rounded-lg px-3 py-2.5 font-mono text-sm w-0" />
                    <button onClick={doSend} disabled={busy} data-testid="send-run"
                      className="bg-veil text-abyss font-semibold rounded-lg px-5 py-2.5 text-sm hover:bg-veil/85 disabled:opacity-40 whitespace-nowrap">
                      Send privately →
                    </button>
                  </div>
                  <button onClick={() => setSendTo(you)} className="text-xs text-dim hover:text-bright underline underline-offset-2">
                    use my own principal
                  </button>
                  <Stage stage={stage} /><ActionError error={error} />
                </div>
              </div>
            )}

            {act === 4 && (
              <div className="md:flex gap-8 items-start">
                <div className="md:w-2/5 space-y-2">
                  <h2 className="font-display font-medium text-xl">Find your money.</h2>
                  <p className="text-dim text-sm leading-relaxed">
                    There is no balance field anywhere on-chain. Your wallet finds your funds by
                    trying its key on <em>every</em> sealed envelope in the pool — the ones that open
                    are yours. A <span className="text-veil">PIR lookup</span> solves a different
                    problem: privately retrieving a record whose number your browser already knows.
                  </p>
                  <div className="mt-4 rounded-xl border border-veil/25 bg-veil/5 p-3 space-y-2 text-xs leading-relaxed">
                    <p>
                      <span className="font-semibold text-bright">Why this matters:</span>{" "}
                      asking a server “give me record #13” reveals exactly which record interests
                      you. Timing that request against later activity can expose useful metadata.
                    </p>
                    <p>
                      <span className="font-semibold text-veil">What this demo does:</span>{" "}
                      your browser encrypts one selector for every record. The canister scans and
                      combines them all, without receiving an index or decrypting the selectors.
                      Only this browser decrypts the returned commitment.
                    </p>
                    <p className="text-dim">
                      <span className="font-semibold">Honest limit:</span> this does not discover
                      which notes are yours—the full-envelope rescan does that. It is a linear-cost,
                      known-record PIR demonstration, not yet a production-scale indexer. It hides
                      the selected record number, not the fact or timing of this authenticated request.
                    </p>
                  </div>
                </div>
                <div className="flex-1 space-y-3 mt-4 md:mt-0">
                  <div className="flex gap-2 flex-wrap">
                    <button onClick={doRescan} disabled={busy} data-testid="rescan-run"
                      className="bg-veil/15 text-veil rounded-lg px-5 py-2.5 text-sm hover:bg-veil/25 disabled:opacity-40">
                      Rescan the pool with my key
                    </button>
                    <button onClick={doPir} disabled={busy} data-testid="pir-run"
                      className="border border-veil/40 text-veil rounded-lg px-5 py-2.5 text-sm hover:bg-veil/10 disabled:opacity-40">
                      Privately verify one known record (PIR)
                    </button>
                  </div>
                  {shielded.scannedOnce && (
                    <p className="text-xs text-dim">
                      Last scan: your key opened{" "}
                      <span className="font-mono text-veil">{shielded.opened}</span> of{" "}
                      <span className="font-mono">{shielded.scanned}</span> envelopes.
                    </p>
                  )}
                  {pir && (
                    <div className="bg-abyss rounded-lg p-3 text-xs space-y-2 font-mono">
                      <div className="font-sans text-bright">
                        Your browser selected record #{pir.target}. That number stayed here.
                      </div>
                      <div className="text-dim">encrypted selectors sent instead (one ciphertext per record):</div>
                      <div className="text-dim/70 hexwrap">[{pir.selectorPreview.join(", ")} …]</div>
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                        <div><div className="text-dim">records scanned</div><div data-testid="pir-scanned">{pir.trace.records_scanned}</div></div>
                        <div><div className="text-dim">record-number fields</div><div className="text-ok">{pir.trace.target_index_parameters}</div></div>
                        <div><div className="text-dim">target-dependent branches</div><div className="text-ok" data-testid="pir-branches">{pir.trace.target_dependent_branches}</div></div>
                        <div><div className="text-dim">selector decryptions</div><div className="text-ok">{pir.trace.selector_decryptions}</div></div>
                      </div>
                      <div data-testid="pir-match" className={pir.match ? "text-ok" : "text-danger"}>
                        {pir.match ? "✓ decrypted record matches the on-ledger commitment" : "MISMATCH"}
                      </div>
                      <div className="text-veil italic font-sans">
                        The canister computed the encrypted answer without learning which record was selected.
                      </div>
                    </div>
                  )}
                  <Stage stage={stage} /><ActionError error={error} />
                </div>
              </div>
            )}

            {act === 5 && (
              <div className="md:flex gap-8 items-start">
                <div className="md:w-2/5 space-y-2">
                  <h2 className="font-display font-medium text-xl">Bring it back into the light.</h2>
                  <p className="text-dim text-sm leading-relaxed">
                    Your exact ICRC account is hashed into the Groth16 public statement. The pool
                    then pays that account once, verifies the exact public-ledger block, and only
                    afterward commits the nullifiers and change notes. A timeout leaves a resumable
                    intent—not a second payout and not stranded value.
                  </p>
                </div>
                <div className="flex-1 space-y-3 mt-4 md:mt-0">
                  <div className="flex gap-2 items-stretch">
                    <div className="flex-1 flex items-center bg-abyss border border-hairline rounded-lg overflow-hidden">
                      <input value={withdrawAmt} onChange={(event) => setWithdrawAmt(event.target.value)}
                        data-testid="unshield-amt" inputMode="decimal" aria-label="Withdrawal amount in DEMO"
                        className="flex-1 min-w-0 bg-transparent px-3 py-2.5 font-mono text-sm" />
                      <span className="px-3 text-xs text-dim font-mono">DEMO</span>
                    </div>
                    <button onClick={doUnshield} disabled={busy} data-testid="unshield-run"
                      className="bg-ok/15 text-ok border border-ok/35 rounded-lg px-5 py-2.5 text-sm hover:bg-ok/25 disabled:opacity-40 whitespace-nowrap">
                      Withdraw to my principal
                    </button>
                  </div>
                  <p className="text-xs text-dim">
                    Available from your two selected notes after the {fmt(W.UNSHIELD_FEE)} DEMO ledger fee:{" "}
                    <span className="font-mono text-bright" data-testid="unshield-max">{fmt(maximumWithdrawal)}</span> DEMO
                  </p>
                  <button onClick={doResumeUnshield} disabled={busy} data-testid="resume-unshield"
                    className="border border-observer/35 text-observer rounded-lg px-4 py-2.5 text-sm hover:bg-observer/10 disabled:opacity-40">
                    Resume a pending withdrawal
                  </button>
                  {unshield && (
                    <div className="bg-abyss rounded-lg p-3 text-sm font-mono" data-testid="unshield-result">
                      <Pill tone={unshield.startsWith("ACCEPT") ? "ok" : "warn"}>
                        {unshield.startsWith("ACCEPT") ? "FINALIZED" : "RECOVERABLE"}
                      </Pill>{" "}
                      <span className={unshield.startsWith("ACCEPT") ? "text-ok" : "text-observer"}>{unshield}</span>
                      <div className="text-dim text-xs mt-1 font-sans">
                        {unshield.startsWith("ACCEPT")
                          ? `The bound public account received ${lastWithdrawAmt === null ? "the proven amount" : `${fmt(lastWithdrawAmt)} DEMO`}; spent notes cannot be replayed.`
                          : "No blind retry: the same intent can reconcile the ledger and resume safely."}
                      </div>
                    </div>
                  )}
                  <Stage stage={stage} /><ActionError error={error} />
                </div>
              </div>
            )}
          </section>

          {/* the two worlds */}
          <div className="grid lg:grid-cols-2 gap-5">
            {/* public ledger */}
            <section className="bg-white/90 border border-white rounded-3xl p-5 relative overflow-hidden shadow-card" data-testid="public-ledger">
              <div className="text-[11px] tracking-[0.2em] text-daylight/70 font-mono mb-1">IN THE OPEN</div>
              <h3 className="font-display font-medium text-lg mb-1">The public token ledger</h3>
              <p className="text-xs text-dim mb-4">
                Every entry is readable by everyone — including every node provider. Amounts,
                senders, recipients, forever.
              </p>
              {stampOn && (
                <div className="mb-3 border-2 border-ok/60 text-ok rounded-lg px-4 py-3 font-display font-bold text-sm animate-stampin"
                  data-testid="no-entry-stamp">
                  NOTHING WAS WRITTEN HERE
                  <div className="font-sans font-normal text-xs text-dim mt-1">
                    Your private transfer produced no entry on this ledger.
                  </div>
                </div>
              )}
              <div className="max-h-80 overflow-y-auto scroll-thin space-y-1.5">
                {feed.entries.length === 0 && (
                  <p className="text-dim text-sm">No entries yet — press the faucet and watch the mint land here.</p>
                )}
                {feed.entries.map((e) => {
                  const l = feedLine(e);
                  return (
                    <div key={e.index} data-testid="ledger-entry" data-btype={e.btype}
                      className={`bg-abyss rounded-lg px-3 py-2 text-xs font-mono flex gap-2 items-center border border-hairline
                        ${freshFeedIdx.has(e.index) ? "animate-pulseonce border-daylight/50" : ""}`}>
                      <span className="text-daylight w-4">{l.icon}</span>
                      <span className="text-bright/90">{l.text}</span>
                      <span className="ml-auto text-dim/60">#{e.index}</span>
                    </div>
                  );
                })}
              </div>
            </section>

            {/* shielded pool */}
            <section className="bg-white/90 border border-white rounded-3xl p-5 shadow-card" data-testid="pool-pane">
              <div className="text-[11px] tracking-[0.2em] text-veil/70 font-mono mb-1">BEHIND THE VEIL</div>
              <div className="flex items-center justify-between gap-2 flex-wrap mb-1">
                <h3 className="font-display font-medium text-lg">The shielded pool</h3>
                <div className="flex rounded-lg border border-hairline overflow-hidden text-xs">
                  <button onClick={() => setPoolView("provider")} data-testid="view-provider"
                    className={`px-3 py-1.5 ${poolView === "provider" ? "bg-observer/15 text-observer" : "text-dim hover:text-bright"}`}>
                    what the node provider sees
                  </button>
                  <button onClick={() => setPoolView("mine")} data-testid="view-mine"
                    className={`px-3 py-1.5 ${poolView === "mine" ? "bg-veil/15 text-veil" : "text-dim hover:text-bright"}`}>
                    what your key sees
                  </button>
                </div>
              </div>

              {poolView === "provider" ? (
                <>
                  <p className="text-xs text-dim mb-3">
                    This is the machine's honest view — the operator who physically runs this
                    canister stores these bytes and can open none of them. No amount, no balance,
                    no sender→recipient link exists anywhere below.
                  </p>
                  {ledgerStatus && (
                    <div className="grid grid-cols-3 gap-2 mb-3 text-xs">
                      <div className="bg-abyss rounded-lg p-2"><div className="text-dim">sealed notes</div><div className="font-mono" data-testid="pool-notes">{ledgerStatus.note_count}</div></div>
                      <div className="bg-abyss rounded-lg p-2"><div className="text-dim">nullifiers spent</div><div className="font-mono">{ledgerStatus.nullifier_count}</div></div>
                      <div className="bg-abyss rounded-lg p-2"><div className="text-dim">tree root</div><div className="font-mono">{shortHex(ledgerStatus.note_root, 8)}</div></div>
                    </div>
                  )}
                  <div className="max-h-72 overflow-y-auto scroll-thin space-y-1.5">
                    {providerNotes.length === 0 && (
                      <p className="text-dim text-sm">Empty — shield something and watch it arrive as an opaque record.</p>
                    )}
                    {providerNotes.map((n) => (
                      <div key={n.id} className="bg-abyss rounded-lg p-2.5 text-xs font-mono border border-hairline" data-testid="provider-note">
                        <div className="flex gap-2 items-center mb-1">
                          <Pill tone={n.origin === "shield" ? "day" : "veil"}>{n.origin === "shield" ? "deposit" : "private transfer"}</Pill>
                          <span className="text-dim/60">record #{n.position}</span>
                        </div>
                        <div className="hexwrap"><span className="text-dim">commitment </span><span className="text-bright/80">{shortHex(n.commitment, 22)}</span></div>
                        <div className="hexwrap"><span className="text-dim">sealed envelope </span><span className="text-dim/60">{shortHex(n.ciphertext, 26)}</span></div>
                        {n.nullifiers.length > 0 && (
                          <div className="hexwrap"><span className="text-dim">nullifiers </span><span className="text-danger/80">{n.nullifiers.map((x) => shortHex(x, 10)).join(", ")}</span></div>
                        )}
                      </div>
                    ))}
                  </div>
                </>
              ) : (
                <>
                  <p className="text-xs text-dim mb-3">
                    The same records, opened with keys derived into this authenticated tab's memory.
                  </p>
                  <div className="bg-abyss rounded-lg p-3 mb-3 flex items-baseline gap-3">
                    <span className="text-dim text-xs">your shielded balance</span>
                    <span className="font-mono text-2xl text-veil" data-testid="shielded-bal">{fmt(shieldedTotal)}</span>
                    <span className="text-xs text-dim font-mono" data-testid="shielded-notes">{shielded.notes.length} notes</span>
                  </div>
                  <div className="max-h-64 overflow-y-auto scroll-thin space-y-1.5">
                    {shielded.notes.length === 0 && (
                      <p className="text-dim text-sm" data-testid="no-notes">
                        Your key opened no unspent envelopes{shielded.scannedOnce ? "" : " yet"} — shield something, or rescan.
                      </p>
                    )}
                    {shielded.notes.map((n) => (
                      <div key={n.cm} className="bg-abyss rounded-lg p-2.5 text-xs font-mono border border-veil/20" data-testid="my-note">
                        <span className="text-veil text-sm">{fmt(n.v)} DEMO</span>
                        <span className="text-dim/60 ml-2">record #{n.position}</span>
                        <div className="hexwrap text-dim/60">{shortHex(n.cm, 18)}</div>
                      </div>
                    ))}
                  </div>
                  <button onClick={doRescan} disabled={busy} data-testid="rescan-mine"
                    className="mt-3 text-xs text-veil border border-veil/30 rounded-lg px-3 py-1.5 hover:bg-veil/10 disabled:opacity-40">
                    rescan
                  </button>
                </>
              )}
            </section>
          </div>

          {/* activity */}
          <section className="mt-5 bg-slab/60 border border-hairline rounded-2xl p-4">
            <h3 className="text-xs tracking-[0.2em] text-dim font-mono mb-2">ACTIVITY</h3>
            <div className="max-h-40 overflow-y-auto scroll-thin space-y-1 text-xs font-mono">
              {log.map((e, i) => (
                <div key={i} className="flex gap-2">
                  <span className="text-dim/50">{e.t}</span>
                  <span className="text-dim w-12 shrink-0">{e.who}</span>
                  <span className={{ ok: "text-ok", warn: "text-observer", danger: "text-danger", veil: "text-veil", dim: "text-bright/80" }[e.tone]}>{e.msg}</span>
                </div>
              ))}
            </div>
          </section>
        </>
      )}

      <footer className="text-center text-xs text-dim/60 pt-8">
        Live on Internet Computer mainnet · proofs BLS12-381 Groth16, verified in-canister ·
        pool {shortHex(CANISTERS.zk_ledger, 8)} · Menese DeFi Team
      </footer>
    </div>
  );
}
