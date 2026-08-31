#!/usr/bin/env python3
"""Poseidon round-number security margin, re-derived for the shipped configuration (audit F5).

The pool's Poseidon instance (circuit/common/src/lib.rs `poseidon_config`) is:

    width t = 3 (rate 2 + capacity 1), S-box x^5 (alpha = 5), R_F = 8 full rounds,
    R_P = 57 partial rounds, over BLS12-381 Fr (255-bit; BN254 Fr in the dev-default build).

This script re-derives the minimum secure round numbers from the round-number inequalities of
the Poseidon paper (Grassi, Khovratovich, Rechberger, Roy, Schofnegger — USENIX Security '21,
eprint 2019/458, Section 5.5: Eq. 2 statistical, Eq. 3/4 interpolation, Eq. 5/6 Groebner), as
implemented by the authors' reference script `calc_round_numbers.py`
(https://extgit.isec.tugraz.at/krypto/hadeshash, function `sat_inequiv_alpha`, alpha > 0 arm)
and cross-checked against the independent transcription in
https://github.com/ingonyama-zk/poseidon-hash (`round_numbers.py`). The two sources state the
statistical bound differently — floor(log2(p) - (alpha-1)/2) vs floor(log2(p)) - log2(alpha-1)
— which coincide for alpha = 5 (both subtract 2); this script implements the original
(hadeshash) form and asserts the transcription agrees for this instance.

Everything below is COMPUTED at run time and printed, so this script is the authority for the
round-number margins rather than any transcription of them. Exit code is non-zero if the shipped
parameters fail any bound.

Run:  python3 scripts/poseidon-round-margin.py
"""

from math import ceil, floor, gcd, log, log2
import sys

# ---- the shipped instances (mirror circuit/common/src/lib.rs) ----
#
# There are TWO, and both must clear every bound. `t` was module-level and hardcoded to 3
# until 2026-08-27, so the tree instance's round numbers could only ever be checked by
# editing this file by hand — which is the "documented provenance nobody re-derives"
# failure this script exists to prevent, reproduced inside the script itself. Every bound
# function already took `t`; only the caller was fixed. Now both instances are checked on
# every run, so widening the tree sponge again cannot silently skip its security argument.
#
# The bounds DO depend on t: the Groebner bounds (Eq. 5/6) and the statistical bound are
# all functions of the state width, so a wider sponge is not automatically covered by a
# narrower one's margin.
ALPHA = 5      # S-box x^5
R_F_SHIPPED = 8
R_P_SHIPPED = 57
M = 128        # target security level in bits

#           label,                        t, rate, capacity
INSTANCES = [
    ("NOTE  poseidon_config()",           3, 2,    1),
    ("TREE  poseidon_config_tree()",      5, 4,    1),
]

# BLS12-381 scalar-field modulus (primary; the curve of the deployed Motoko verifier).
BLS12_381_FR = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
# BN254 scalar-field modulus (the crate's dev-default field; same round numbers shared).
BN254_FR = 0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001


def sat_inequiv_alpha(p: int, t: int, r_f: int, r_p: int, alpha: int, m: int) -> bool:
    """Verbatim port of hadeshash calc_round_numbers.py `sat_inequiv_alpha`, alpha > 0 arm."""
    n = ceil(log(p, 2))
    if alpha <= 0:
        raise ValueError("only the alpha > 0 arm is relevant here")
    # Eq. 2 — statistical (differential/linear) attacks
    r_f_1 = 6 if m <= (floor(log(p, 2) - ((alpha - 1) / 2.0)) * (t + 1)) else 10
    # Eq. 3/4 — interpolation attack
    r_f_2 = 1 + ceil(log(2, alpha) * min(m, n)) + ceil(log(t, alpha)) - r_p
    # Eq. 5 — Groebner basis attack, first bound
    r_f_3 = 1 + (log(2, alpha) * min(m / 3.0, log(p, 2) / 2.0)) - r_p
    # Eq. 6 — Groebner basis attack, second bound
    r_f_4 = t - 1 + min((log(2, alpha) * m) / float(t + 1), (log(2, alpha) * log(p, 2)) / 2.0) - r_p
    r_f_max = max(ceil(r_f_1), ceil(r_f_2), ceil(r_f_3), ceil(r_f_4))
    return r_f >= r_f_max


def stat_bound_ingonyama(p: int, t: int, alpha: int, m: int) -> int:
    """The ingonyama-zk transcription's statistical bound, for the cross-check."""
    c = log2(alpha - 1)
    return 6 if m <= ((floor(log(p, 2)) - c) * (t + 1)) else 10


def per_attack_bounds(p: int, t: int, r_p: int, alpha: int, m: int):
    n = ceil(log(p, 2))
    r_f_1 = 6 if m <= (floor(log(p, 2) - ((alpha - 1) / 2.0)) * (t + 1)) else 10
    r_f_2 = 1 + ceil(log(2, alpha) * min(m, n)) + ceil(log(t, alpha)) - r_p
    r_f_3 = 1 + (log(2, alpha) * min(m / 3.0, log(p, 2) / 2.0)) - r_p
    r_f_4 = t - 1 + min((log(2, alpha) * m) / float(t + 1), (log(2, alpha) * log(p, 2)) / 2.0) - r_p
    return ceil(r_f_1), ceil(r_f_2), ceil(r_f_3), ceil(r_f_4)


def min_rp_at(p: int, t: int, r_f: int, alpha: int, m: int) -> int:
    """Smallest R_P satisfying every inequality at a fixed R_F (strict bound, no margin)."""
    for r_p in range(0, 500):
        if sat_inequiv_alpha(p, t, r_f, r_p, alpha, m):
            return r_p
    raise RuntimeError("no R_P < 500 satisfies the inequalities")


def paper_recommended(p: int, t: int, alpha: int, m: int):
    """The reference optimizer: minimize S-boxes (t*R_F + R_P) over all satisfying pairs,
    then apply the paper's security margin (+2 full rounds, +7.5% partial rounds)."""
    best = None
    for r_p_t in range(1, 500):
        for r_f_t in range(4, 100, 2):
            if sat_inequiv_alpha(p, t, r_f_t, r_p_t, alpha, m):
                r_f = r_f_t + 2
                r_p = int(ceil(r_p_t * 1.075))
                cost = t * r_f + r_p
                if best is None or cost < best[0] or (cost == best[0] and r_f < best[1]):
                    best = (cost, r_f, r_p, r_f_t, r_p_t)
    assert best is not None
    return best  # (cost, R_F_with_margin, R_P_with_margin, R_F_base, R_P_base)


def report(label: str, p: int, t: int, rate: int, capacity: int) -> bool:
    bits = ceil(log(p, 2))
    ok = True
    print(f"== {label} | t={t} (rate {rate} + capacity {capacity}) | modulus {bits} bits ==")
    assert gcd(ALPHA, p - 1) == 1, "alpha must be coprime to p-1 for x^alpha to permute"
    print(f"  S-box x^{ALPHA} is a permutation: gcd({ALPHA}, p-1) = 1  OK")

    s1, s2, s3, s4 = per_attack_bounds(p, t, R_P_SHIPPED, ALPHA, M)
    print(f"  per-attack minimum R_F at R_P = {R_P_SHIPPED}:")
    print(f"    statistical (Eq. 2)      : R_F >= {s1}")
    print(f"    interpolation (Eq. 3/4)  : R_F >= {s2}")
    print(f"    Groebner bound 1 (Eq. 5) : R_F >= {s3}")
    print(f"    Groebner bound 2 (Eq. 6) : R_F >= {s4}")

    if not sat_inequiv_alpha(p, t, R_F_SHIPPED, R_P_SHIPPED, ALPHA, M):
        print(f"  FAIL: shipped (R_F={R_F_SHIPPED}, R_P={R_P_SHIPPED}) violates a bound")
        ok = False
    else:
        print(f"  shipped (R_F={R_F_SHIPPED}, R_P={R_P_SHIPPED}) satisfies ALL bounds at M={M}")

    strict_rp = min_rp_at(p, t, R_F_SHIPPED, ALPHA, M)
    print(f"  strict minimum R_P at R_F={R_F_SHIPPED} (no margin)   : {strict_rp}"
          f"   -> shipped margin: +{R_P_SHIPPED - strict_rp} partial rounds")
    if R_P_SHIPPED < strict_rp:
        ok = False

    cost, rf_m, rp_m, rf_b, rp_b = paper_recommended(p, t, ALPHA, M)
    print(f"  paper-recommended (base ({rf_b},{rp_b}) + margin '+2 R_F, +7.5% R_P')"
          f" : (R_F={rf_m}, R_P={rp_m}), {cost} S-boxes")
    print(f"  shipped vs recommended: R_F {R_F_SHIPPED} vs {rf_m}"
          f" ({'==' if R_F_SHIPPED == rf_m else '!='}),"
          f" R_P {R_P_SHIPPED} vs {rp_m} ({R_P_SHIPPED - rp_m:+d} partial rounds)")
    if R_F_SHIPPED < rf_m or R_P_SHIPPED < rp_m:
        print("  FAIL: shipped parameters fall below the margin-inclusive recommendation")
        ok = False

    # cross-check: the two public statements of the statistical bound agree for alpha = 5
    ing = stat_bound_ingonyama(p, t, ALPHA, M)
    if ing != s1:
        print(f"  FAIL: statistical-bound cross-check divergence (hadeshash {s1} vs ingonyama {ing})")
        ok = False
    else:
        print(f"  statistical-bound cross-check (hadeshash vs ingonyama transcription): both R_F >= {s1}")

    # sponge-level security from the capacity
    cap_bits = capacity * bits
    print(f"  sponge capacity: {capacity} field element = {cap_bits} bits"
          f" -> collision/preimage level min(M, capacity/2) = {min(M, cap_bits // 2)} bits"
          f" (effective ~{min(M, cap_bits // 2)}-bit security)")
    print()
    return ok


def main() -> int:
    print("Poseidon round-number margin re-derivation (audit F5)")
    print(f"alpha={ALPHA}, R_F={R_F_SHIPPED}, R_P={R_P_SHIPPED}, target M={M} bits")
    print(f"{len(INSTANCES)} shipped instance(s): "
          + ", ".join(f"t={t}" for _, t, _, _ in INSTANCES))
    print()
    ok = True
    for label, t, rate, capacity in INSTANCES:
        ok = report(f"{label} / BLS12-381 Fr (deployment field)", BLS12_381_FR, t, rate, capacity) and ok
        ok = report(f"{label} / BN254 Fr (dev-default field)", BN254_FR, t, rate, capacity) and ok
    if ok:
        print("POSEIDON ROUND MARGIN: ALL BOUNDS SATISFIED for EVERY shipped instance"
              " (R_F/R_P at or above every computed minimum, margin quantified above)")
        return 0
    print("POSEIDON ROUND MARGIN: BOUND VIOLATION — see FAIL lines above")
    return 1


if __name__ == "__main__":
    sys.exit(main())
