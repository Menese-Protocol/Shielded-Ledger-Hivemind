// Export a LIVE coordinator's public transcript into a parts directory that
// `ceremony-cli assemble-transcript` turns into a verifiable transcript.
//
// docs/CEREMONY.md §5 tells every participant and observer to verify the finished ceremony with
// the standalone verifier. That was not actually possible: the verifier reads a transcript file,
// and nothing could produce one from a deployed coordinator, so it could only ever check
// transcripts the local simulator had written. This is the missing half.
//
// The split is deliberate. The `ceremony` crate carries no agent dependency and is offline by
// design, so the network side lives here and the crypto side stays there. This script downloads
// bytes and writes them out; it makes no judgement about them. Every check — point validation,
// the proofs of knowledge, the challenge chain, and whether the coordinator's initial parameters
// are the ones the SRS implies — happens in `assemble-transcript` and `verify-transcript`.
//
// Usage:
//   node scripts/export-live-ceremony.mjs <canisterId> <host> <outDir>
//   ceremony-cli assemble-transcript <srs.bin> <outDir> <out.transcript>
//   verify-transcript <srs.bin> <out.transcript> --selfcheck
import { mkdir, writeFile } from "node:fs/promises";
import { HttpAgent, Actor } from "@dfinity/agent";

const [canisterId, host, outDir] = process.argv.slice(2);
if (!canisterId || !host || !outDir) {
  console.error("usage: export-live-ceremony.mjs <canisterId> <host> <outDir>");
  process.exit(2);
}
const CHUNK = 1_800_000;
const hex = (bytes) => Buffer.from(new Uint8Array(bytes)).toString("hex");

const idlFactory = ({ IDL }) => {
  const Circuit = IDL.Variant({ transfer: IDL.Null, deposit: IDL.Null });
  const PokWire = IDL.Record({
    s_g1: IDL.Vec(IDL.Nat8), s_delta_g1: IDL.Vec(IDL.Nat8), r_delta_g2: IDL.Vec(IDL.Nat8),
  });
  const ContributionMeta = IDL.Record({
    index: IDL.Nat, contributor: IDL.Vec(IDL.Nat8), timestamp: IDL.Int,
    is_beacon: IDL.Bool, beacon: IDL.Vec(IDL.Nat8),
    transfer_pok: PokWire, deposit_pok: PokWire,
    transfer_delta_hash: IDL.Vec(IDL.Nat8), transfer_delta_len: IDL.Nat,
    deposit_delta_hash: IDL.Vec(IDL.Nat8), deposit_delta_len: IDL.Nat,
  });
  const Summary = IDL.Record({
    count: IDL.Nat, power: IDL.Nat32, finalized: IDL.Bool,
    srs_sha256: IDL.Vec(IDL.Nat8), genesis_challenge: IDL.Vec(IDL.Nat8),
    running_challenge: IDL.Vec(IDL.Nat8),
    transfer_initial_hash: IDL.Vec(IDL.Nat8), deposit_initial_hash: IDL.Vec(IDL.Nat8),
  });
  return IDL.Service({
    get_transcript_summary: IDL.Func([], [Summary], ["query"]),
    get_contribution: IDL.Func([IDL.Nat], [IDL.Opt(ContributionMeta)], ["query"]),
    get_contribution_chunk: IDL.Func(
      [IDL.Nat, Circuit, IDL.Nat, IDL.Nat], [IDL.Vec(IDL.Nat8)], ["query"]),
    get_initial_chunk: IDL.Func([Circuit, IDL.Nat, IDL.Nat], [IDL.Vec(IDL.Nat8)], ["query"]),
  });
};

const circuitOf = (n) => (n === "transfer" ? { transfer: null } : { deposit: null });
const agent = await HttpAgent.create({
  host, shouldFetchRootKey: host.includes("127.0.0.1") || host.includes("localhost"),
});
const actor = Actor.createActor(idlFactory, { agent, canisterId });

async function pull(fetchChunk, len) {
  const out = new Uint8Array(Number(len));
  let o = 0;
  for (let off = 0; off < Number(len); off += CHUNK) {
    const part = await fetchChunk(off, Math.min(CHUNK, Number(len) - off));
    out.set(new Uint8Array(part), o);
    o += part.length;
  }
  return out;
}

await mkdir(outDir, { recursive: true });
const s = await actor.get_transcript_summary();
console.log(`power ${s.power} · ${s.count} contribution(s) · finalized=${s.finalized}`);
console.log(`srs_sha256 ${hex(s.srs_sha256)}`);

// The initial parameters. Their length is not in the summary, so take it from the on-chain
// length the first contribution records, or from the current params when there are none yet.
const meta0 = Number(s.count) > 0 ? (await actor.get_contribution(0n))[0] : null;
for (const [c, len] of [
  ["transfer", meta0 ? meta0.transfer_delta_len : null],
  ["deposit", meta0 ? meta0.deposit_delta_len : null],
]) {
  if (len === null) {
    console.error("cannot size the initial parameters: the ceremony has no contributions yet");
    process.exit(1);
  }
  const bytes = await pull((o, n) => actor.get_initial_chunk(circuitOf(c), o, n), len);
  await writeFile(`${outDir}/initial_${c}.wire`, bytes);
  console.log(`  initial_${c}.wire ${bytes.length} B`);
}

const lines = [`${s.power}\t${s.finalized}`];
for (let i = 0; i < Number(s.count); i++) {
  const opt = await actor.get_contribution(BigInt(i));
  if (!opt.length) {
    console.error(`contribution ${i} missing`);
    process.exit(1);
  }
  const m = opt[0];
  for (const [c, len] of [["transfer", m.transfer_delta_len], ["deposit", m.deposit_delta_len]]) {
    const bytes = await pull(
      (o, n) => actor.get_contribution_chunk(BigInt(i), circuitOf(c), o, n), len);
    await writeFile(`${outDir}/c${i}_${c}.wire`, bytes);
    console.log(`  c${i}_${c}.wire ${bytes.length} B`);
  }
  lines.push([
    i, hex(m.contributor), m.timestamp.toString(), m.is_beacon, hex(m.beacon),
    hex(m.transfer_pok.s_g1), hex(m.transfer_pok.s_delta_g1), hex(m.transfer_pok.r_delta_g2),
    hex(m.deposit_pok.s_g1), hex(m.deposit_pok.s_delta_g1), hex(m.deposit_pok.r_delta_g2),
  ].join("\t"));
}
await writeFile(`${outDir}/manifest.tsv`, lines.join("\n") + "\n");
console.log(`\nwrote ${outDir}/manifest.tsv`);
console.log(`next: ceremony-cli assemble-transcript <srs.bin> ${outDir} <out.transcript>`);
