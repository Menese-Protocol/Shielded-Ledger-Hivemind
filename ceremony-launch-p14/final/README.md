# Ceremony result

The Phase-2 ceremony closed with 25 honest contributions and was finalized with the beacon named
in advance in `../BEACON.md` (ICP ledger block 38420079). This folder holds the complete public
record, so anyone can check that the verifying keys the live ledger uses came out of that ceremony.

| File | What it is |
|---|---|
| `sapling-phase1-p14.srs.bin` | Phase-1 parameters, extracted from the Zcash Sapling MPC (`../PROVENANCE-p14.json`) |
| `final.transcript.bin` | the full Phase-2 transcript: initial parameters, 25 contributions, the beacon step |
| `transfer_vk.hex`, `deposit_vk.hex` | the verifying keys exported from the transcript |
| `transfer_pk.bin`, `deposit_pk.bin` | the matching proving keys, for clients that generate proofs |
| `SETUP-MANIFEST.json` | hashes of all of the above |
| `finalize-run.log` | the finalize run: export from the coordinator, assemble, beacon, submit, re-export, verify |
| `SHA256SUMS` | checksums of every file here |

## Check it yourself

1. The files are intact:

   ```
   cd ceremony-launch-p14/final && sha256sum -c SHA256SUMS
   ```

2. The transcript is valid and produces these keys. From the repository root:

   ```
   cargo run --release --manifest-path ceremony/Cargo.toml --bin verify-transcript -- \
       ceremony-launch-p14/final/sapling-phase1-p14.srs.bin \
       ceremony-launch-p14/final/final.transcript.bin --selfcheck
   ```

   Expected: `TRANSCRIPT VALID`, `honest contributions : 25`, `finalized (beacon) : true`,
   `transfer vk SHA-256 : f409d18f8149ccae11d9319f95c80fde72f3a9b13834d1c3410050e190116514`,
   `deposit vk SHA-256 : b0afc42ad1b764b9fc2c435c41b328bc822c2ac70937211df1bcd9af23112224`,
   and `KEYS WORK` (a real transfer and deposit proof verify under the keys).

3. The live ledger uses exactly these keys, frozen. Read them from the chain without signing in:

   ```
   dfx canister call --network ic --identity anonymous --query --output json \
       3pwrb-oiaaa-aaaao-bbqba-cai verifying_key_anchor
   ```

   The SHA-256 of the hex-decoded `transfer_vk_hex` and `deposit_vk_hex` must equal the two hashes
   in step 2, and `frozen` must be `true`: the ledger can never switch to other keys.

4. The beacon was the one named in advance, before the window closed (`../BEACON.md`):

   ```
   python3 ceremony-launch-p14/icp-beacon.py verify \
       'icp-ledger-block:38420079:589baa51acbeffde82538bd5d1bfcdb0b96b69a4cbd2e739d2f9cae5faaf44ea' \
       2026-09-16T12:00:00Z
   ```

   Expected: `BEACON VALID`. The coordinator `osqjo-zyaaa-aaaad-agxua-cai` has no controllers and
   records the beacon bytes it accepted.
