# Groth16 trusted-setup policy

The pool uses circuit-specific Groth16 over BLS12-381. A setup keyset is part of the protocol's
soundness boundary, not an ordinary build artifact.

## Keyset classes

1. `insecure-deterministic-test` exists only to reproduce public positive and negative fixtures.
   Its seed and toxic setup randomness are public. The generator requires this mode explicitly,
   labels it deployment-forbidden, and the frontend rejects it.
2. `os-csprng-single-party` draws setup randomness directly from the operating system CSPRNG. It
   removes the published-seed forgery path and is acceptable only for the valueless DEMO. It still
   asks users to trust the one setup machine and is therefore marked `real_value_eligible: false`.
3. A real-value keyset must come from an independently reviewed multi-party ceremony. The local
   generator cannot mark any keyset real-value eligible.

## Production acceptance gate

Before any valuable token is configured, all of the following are required:

- Freeze and publish the exact transfer and deposit circuits, dependency lockfile, constraint
  counts, source commit, and reproducible ceremony binary hash.
- Use reviewed BLS12-381 Groth16 phase-one and circuit-specific phase-two ceremony tooling that can
  export keys byte-compatible with the arkworks verifier/prover used here. Do not improvise a new
  MPC protocol inside this repository.
- Obtain contributions from multiple independent operators on separately controlled machines.
  Each contribution must verify against the preceding transcript; the final security argument is
  that at least one contributor generated and destroyed its secret correctly.
- Publish the complete ordered transcript, contribution hashes, verification output, participant
  attestations, final proving/verifying-key hashes, and transcript hash.
- Independently reproduce transcript verification on at least two implementations or review teams.
- Run the native oracle controls, Motoko verifier controls, browser proving tests, forged-proof
  negatives, recipient-binding negatives, and a clean two-user end-to-end test against the final
  keyset.
- Create a provenance manifest that sets `multi_party_ceremony: true` and
  `real_value_eligible: true`, binds the transcript hash, and is reviewed separately from the party
  that coordinated the ceremony.
- Rotate the ledger verifying keys and frontend proving keys as one scheduled release. Never
  reinstall the ledger, and retain a tested rollback/recovery procedure that does not restore the
  compromised verifying keys.

Until this checklist is complete, `npm run verify:keyset:production` must fail and the application
must remain explicitly DEMO-only.
