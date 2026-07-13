# Vendored Motoko Groth16 verifier (BLS12-381)

VERBATIM copies of the verifier modules in [`../../verifier-lab/`](../../verifier-lab/); do not
edit here. Fix in `verifier-lab/`, re-run the batteries, then re-vendor, keeping the two copies
byte-identical:

```sh
for f in *.mo; do diff "$f" "../../verifier-lab/$f"; done
```

Proven by the batteries in `verifier-lab/` (all runnable through `scripts/security-gate.sh`):

- `CurveJacTest`: Jacobian scalar multiplication and subgroup validation, differentially tested
  against the pure-`Nat` reference `Curve`, anchored to the arkworks vk_x oracle vector.
- `Groth16MultiTest`: the assembled one-message verifier against the arkworks multi-Miller
  oracle; 12-coefficient comparisons, the final-exponentiation identity, and pinned forgery
  classes (forged proof, forged vk, forged inputs, wrong-subgroup points, negated A).
- `WireTest`: the compressed wire boundary; G2 decode battery, little-endian Fr parsing, and
  full hex round-trips with verdict parity against the native oracle.
- `verify-current-groth16.mjs` (in `scripts/`): the current eight-public-input transfer and
  deposit fixtures through this exact verifier, including rejection of the legacy
  seven-input statement shape.

Measured on-canister: transfer verify from hex 12.566B instructions (31.4% of the 40B message
ceiling), deposit 10.121B (25.3%), flat across garbage collection.
