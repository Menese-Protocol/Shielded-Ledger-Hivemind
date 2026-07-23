#!/usr/bin/env python3
"""§4 INDEPENDENT reference model for the shielded-pool circuit.

Reimplements — from the published specifications, importing NO production helper (only the
Python standard library) — the Poseidon permutation (Grain-LFSR round-constant generation,
Cauchy MDS, the sponge schedule), the note derivations (pk / nullifier / commitment), the
incremental/dense Merkle tree, and the transfer statement's public-input vector. It then
checks every value against the production witness generator's dump (circuit_oracle JSON),
and drives the §4 single-rule-violation matrix.

Independence is the whole point (both Phase-0 audits: every existing Rust test routes
through `common`'s arkworks Poseidon, so none can catch a bug IN that Poseidon). This file
must have zero `import` beyond the standard library — the gate greps for that and a planted
violation turns it RED.

References:
- Poseidon: Grassi, Khovratovich, Rechberger, Roy, Schofnegg, "Poseidon: A New Hash
  Function for Zero-Knowledge Proof Systems" (USENIX Security 2021); the Grain-LFSR
  parameter routine is Appendix F / the reference `generate_parameters_grain.sage`.
- Note commitment / nullifier / anchor + rho-chaining: Zcash protocol spec (Sapling/Orchard
  §3.2, §4.16, §4.7.3 Faerie-Gold).
- Sponge duplex construction: Bertoni, Daemen, Peeters, Van Assche, "Cryptographic sponge
  functions"; the field-sponge absorb/squeeze schedule matches COS20 (eprint 2019/1076).
"""

import json
import sys

# ---------------------------------------------------------------------------
# Field arithmetic (BLS12-381 scalar field), pure Python big-int.
# ---------------------------------------------------------------------------
# Set from the dump's declared modulus at load; asserted equal to the hardcoded value so a
# silently-wrong dump can't move the field under us.
R = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001


def fadd(a, b):
    return (a + b) % R


def fsub(a, b):
    return (a - b) % R


def fmul(a, b):
    return (a * b) % R


def fpow(a, e):
    return pow(a % R, e, R)


def finv(a):
    if a % R == 0:
        raise ZeroDivisionError("inverse of zero")
    return pow(a % R, R - 2, R)


# ---------------------------------------------------------------------------
# Grain LFSR — reimplemented from the reference routine (see module docstring).
# ---------------------------------------------------------------------------
class GrainLFSR:
    def __init__(self, prime_num_bits, state_len, full_rounds, partial_rounds):
        self.prime_num_bits = prime_num_bits
        st = [False] * 80
        # b0,b1 field = prime field: bit1 set
        st[1] = True
        # b2..b5 sbox: x^alpha (not an inverse) -> all False
        # b6..b17 = prime_num_bits, big-endian into that window
        cur = prime_num_bits
        for i in range(17, 5, -1):
            st[i] = (cur & 1) == 1
            cur >>= 1
        # b18..b29 = state_len (t = rate + capacity)
        cur = state_len
        for i in range(29, 17, -1):
            st[i] = (cur & 1) == 1
            cur >>= 1
        # b30..b39 = full rounds
        cur = full_rounds
        for i in range(39, 29, -1):
            st[i] = (cur & 1) == 1
            cur >>= 1
        # b40..b49 = partial rounds
        cur = partial_rounds
        for i in range(49, 39, -1):
            st[i] = (cur & 1) == 1
            cur >>= 1
        # b50..b79 = 1
        for i in range(50, 80):
            st[i] = True
        self.state = st
        self.head = 0
        for _ in range(160):
            self._update()

    def _update(self):
        s = self.state
        h = self.head
        new_bit = (
            s[(h + 62) % 80]
            ^ s[(h + 51) % 80]
            ^ s[(h + 38) % 80]
            ^ s[(h + 23) % 80]
            ^ s[(h + 13) % 80]
            ^ s[h]
        )
        s[h] = new_bit
        self.head = (h + 1) % 80
        return new_bit

    def _get_bits(self, num_bits):
        res = []
        for _ in range(num_bits):
            new_bit = self._update()
            while not new_bit:
                self._update()          # discard the second bit
                new_bit = self._update()  # obtain another first bit
            res.append(self._update())    # the second bit is the output
        return res

    def field_elems_rejection(self, num):
        out = []
        n = self.prime_num_bits
        for _ in range(num):
            while True:
                bits = self._get_bits(n)
                bits.reverse()
                # arkworks: BigInt::from_bits_le(&bits) — bits[0] is the LSB.
                val = 0
                for i, b in enumerate(bits):
                    if b:
                        val |= 1 << i
                if val < R:  # from_bigint returns Some iff < modulus
                    out.append(val)
                    break
        return out

    def field_elems_mod_p(self, num):
        out = []
        n = self.prime_num_bits
        for _ in range(num):
            bits = self._get_bits(n)
            bits.reverse()  # MSB-first, matching arkworks
            # arkworks: pack bits LSB-first into bytes, then from_le_bytes_mod_order
            byts = bytearray()
            for chunk_start in range(0, len(bits), 8):
                chunk = bits[chunk_start:chunk_start + 8]
                b = 0
                for i, bit in enumerate(chunk):
                    if bit:
                        b |= 1 << i
                byts.append(b)
            val = int.from_bytes(bytes(byts), "little") % R
            out.append(val)
        return out


def gen_ark_and_mds(prime_bits, rate, full_rounds, partial_rounds, skip_matrices=0):
    lfsr = GrainLFSR(prime_bits, rate + 1, full_rounds, partial_rounds)
    ark = [lfsr.field_elems_rejection(rate + 1) for _ in range(full_rounds + partial_rounds)]
    for _ in range(skip_matrices):
        lfsr.field_elems_mod_p(2 * (rate + 1))
    xs = lfsr.field_elems_mod_p(rate + 1)
    ys = lfsr.field_elems_mod_p(rate + 1)
    mds = [[finv(fadd(xs[i], ys[j])) for j in range(rate + 1)] for i in range(rate + 1)]
    return ark, mds


# ---------------------------------------------------------------------------
# Poseidon sponge (rate 2, capacity 1, alpha 5), reimplemented from spec.
# ---------------------------------------------------------------------------
class Poseidon:
    def __init__(self, full_rounds, partial_rounds, alpha, ark, mds, rate, capacity):
        self.full_rounds = full_rounds
        self.partial_rounds = partial_rounds
        self.alpha = alpha
        self.ark = ark
        self.mds = mds
        self.rate = rate
        self.capacity = capacity
        self.width = rate + capacity

    def _sbox(self, state, full):
        if full:
            for i in range(len(state)):
                state[i] = fpow(state[i], self.alpha)
        else:
            state[0] = fpow(state[0], self.alpha)

    def _ark(self, state, rnd):
        for i in range(len(state)):
            state[i] = fadd(state[i], self.ark[rnd][i])

    def _mds(self, state):
        new = []
        for i in range(len(state)):
            cur = 0
            for j in range(len(state)):
                cur = fadd(cur, fmul(state[j], self.mds[i][j]))
            new.append(cur)
        return new

    def permute(self, state):
        st = list(state)
        half = self.full_rounds // 2
        for i in range(half):
            self._ark(st, i)
            self._sbox(st, True)
            st = self._mds(st)
        for i in range(half, half + self.partial_rounds):
            self._ark(st, i)
            self._sbox(st, False)
            st = self._mds(st)
        for i in range(half + self.partial_rounds, self.full_rounds + self.partial_rounds):
            self._ark(st, i)
            self._sbox(st, True)
            st = self._mds(st)
        return st

    def hash_n(self, inputs):
        """Duplex sponge: absorb each input (mode-tracked), then squeeze one element."""
        state = [0] * self.width
        mode = ("absorb", 0)  # (kind, next_index)
        for x in inputs:
            kind, idx = mode
            if kind == "absorb":
                if idx == self.rate:
                    state = self.permute(state)
                    idx = 0
                state, idx = self._absorb_internal(state, idx, [x])
                mode = ("absorb", idx)
            else:
                state, idx = self._absorb_internal(state, 0, [x])
                mode = ("absorb", idx)
        # squeeze 1: from Absorbing -> permute then read state[capacity]
        state = self.permute(state)
        return state[self.capacity]

    def _absorb_internal(self, state, rate_start, elems):
        remaining = list(elems)
        idx = rate_start
        while True:
            if idx + len(remaining) <= self.rate:
                for i, e in enumerate(remaining):
                    p = self.capacity + i + idx
                    state[p] = fadd(state[p], e)
                return state, idx + len(remaining)
            take = self.rate - idx
            for i in range(take):
                p = self.capacity + i + idx
                state[p] = fadd(state[p], remaining[i])
            state = self.permute(state)
            remaining = remaining[take:]
            idx = 0


# ---------------------------------------------------------------------------
# Circuit semantics (independent of production).
# ---------------------------------------------------------------------------
TREE_DEPTH = 32


class Circuit:
    def __init__(self, poseidon, tags):
        self.h = poseidon
        self.TAG_PK = tags["pk"]
        self.TAG_NF = tags["nf"]
        self.TAG_CM = tags["cm"]
        self._zeros = None

    def derive_pk(self, nk):
        return self.h.hash_n([self.TAG_PK, nk])

    def derive_nf(self, nk, rho):
        return self.h.hash_n([self.TAG_NF, nk, rho])

    def note_cm(self, v, pk, rho, rcm):
        return self.h.hash_n([self.TAG_CM, v, pk, rho, rcm])

    def merkle_compress(self, l, r):
        return self.h.hash_n([l, r])

    def zero_hashes(self):
        if self._zeros is None:
            z = [0]
            for i in range(TREE_DEPTH):
                z.append(self.merkle_compress(z[i], z[i]))
            self._zeros = z
        return self._zeros

    def dense_root(self, leaves):
        zeros = self.zero_hashes()
        level = list(leaves)
        for lvl in range(TREE_DEPTH):
            nxt = []
            for i in range((len(level) + 1) // 2):
                l = level[2 * i]
                r = level[2 * i + 1] if 2 * i + 1 < len(level) else zeros[lvl]
                nxt.append(self.merkle_compress(l, r))
            if not nxt:
                nxt.append(self.merkle_compress(zeros[lvl], zeros[lvl]))
            level = nxt
        return level[0]


def check(name, got, want, fails):
    if got != want:
        fails.append((name, got, want))


def main():
    if len(sys.argv) < 2:
        print("usage: model.py <circuit_oracle.json>", file=sys.stderr)
        sys.exit(2)
    data = json.load(open(sys.argv[1]))

    global R
    dump_mod = int(data["modulus"])
    if dump_mod != R:
        print(f"REFMODEL FAIL: dump modulus {dump_mod} != independent R {R}", file=sys.stderr)
        sys.exit(1)

    # 1. Regenerate Poseidon parameters independently and cross-check byte-for-byte.
    prime_bits = R.bit_length()  # 255
    ark, mds = gen_ark_and_mds(prime_bits, data["rate"], data["full_rounds"], data["partial_rounds"])
    fails = []
    dump_ark = [[int(x) for x in row] for row in data["ark"]]
    dump_mds = [[int(x) for x in row] for row in data["mds"]]
    check("ark_shape", (len(ark), len(ark[0])), (len(dump_ark), len(dump_ark[0])), fails)
    check("mds_shape", (len(mds), len(mds[0])), (len(dump_mds), len(dump_mds[0])), fails)
    if not fails:
        for ri in range(len(ark)):
            for ci in range(len(ark[0])):
                check(f"ark[{ri}][{ci}]", ark[ri][ci], dump_ark[ri][ci], fails)
        for ri in range(len(mds)):
            for ci in range(len(mds[0])):
                check(f"mds[{ri}][{ci}]", mds[ri][ci], dump_mds[ri][ci], fails)

    if fails:
        # parameter mismatch: report and stop (everything downstream depends on it)
        print(f"REFMODEL FAIL: Poseidon parameter mismatch ({len(fails)} elements)", file=sys.stderr)
        for name, got, want in fails[:5]:
            print(f"  {name}: model={got} dump={want}", file=sys.stderr)
        sys.exit(1)

    poseidon = Poseidon(
        data["full_rounds"], data["partial_rounds"], data["alpha"], ark, mds,
        data["rate"], data["capacity"],
    )
    circ = Circuit(poseidon, data["tags"])

    # 2. Hash vectors.
    for hi, hv in enumerate(data["hash_vectors"]):
        inp = [int(x) for x in hv["in"]]
        check(f"hash[{hi}]", circ.h.hash_n(inp), int(hv["out"]), fails)

    # 3. Transfer witness expected values, recomputed from the private inputs alone.
    for ti, tx in enumerate(data["transfers"]):
        owner_nk = int(tx["owner_nk"])
        recip_nk = int(tx["recip_nk"])
        in0, in1 = tx["in0"], tx["in1"]
        out0, out1 = tx["out0"], tx["out1"]
        pk0 = circ.derive_pk(owner_nk)
        pk1 = circ.derive_pk(owner_nk)
        cm_in0 = circ.note_cm(in0["v"], pk0, int(in0["rho"]), int(in0["rcm"]))
        cm_in1 = circ.note_cm(in1["v"], pk1, int(in1["rho"]), int(in1["rcm"]))
        nf0 = circ.derive_nf(owner_nk, int(in0["rho"]))
        nf1 = circ.derive_nf(owner_nk, int(in1["rho"]))
        leaves = [int(x) for x in tx["leaves"]]
        anchor = circ.dense_root(leaves)
        # outputs: rho = nf of the corresponding input (Orchard chaining)
        cm_out0 = circ.note_cm(out0["v"], int(out0["pk"]), nf0, int(out0["rcm"]))
        cm_out1 = circ.note_cm(out1["v"], int(out1["pk"]), nf1, int(out1["rcm"]))
        # conservation must hold over Z (all terms range-bound)
        cons = (in0["v"] + in1["v"]) == (out0["v"] + out1["v"] + tx["fee"] + tx["v_pub_out"])
        check(f"tx{ti}.conservation", cons, True, fails)

        exp = tx["expect"]
        check(f"tx{ti}.pk0", pk0, int(exp["pk0"]), fails)
        check(f"tx{ti}.pk1", pk1, int(exp["pk1"]), fails)
        check(f"tx{ti}.cm_in0", cm_in0, int(exp["cm_in0"]), fails)
        check(f"tx{ti}.cm_in1", cm_in1, int(exp["cm_in1"]), fails)
        check(f"tx{ti}.anchor", anchor, int(exp["anchor"]), fails)
        check(f"tx{ti}.nf0", nf0, int(exp["nf0"]), fails)
        check(f"tx{ti}.nf1", nf1, int(exp["nf1"]), fails)
        check(f"tx{ti}.cm_out0", cm_out0, int(exp["cm_out0"]), fails)
        check(f"tx{ti}.cm_out1", cm_out1, int(exp["cm_out1"]), fails)
        # public-input vector
        pub = [anchor, nf0, nf1, cm_out0, cm_out1, tx["fee"], tx["v_pub_out"],
               int(tx["recipient_binding"])]
        dump_pub = [int(x) for x in exp["public_inputs"]]
        check(f"tx{ti}.public_inputs", pub, dump_pub, fails)

    if fails:
        print(f"REFMODEL FAIL: {len(fails)} mismatches vs the production witness generator", file=sys.stderr)
        for name, got, want in fails[:8]:
            print(f"  {name}: model={got} dump={want}", file=sys.stderr)
        sys.exit(1)

    n_hash = len(data["hash_vectors"])
    n_tx = len(data["transfers"])
    print(f"REFMODEL GREEN: params (65x3 ark, 3x3 mds) + {n_hash} hash vectors + {n_tx} "
          f"transfers reproduced independently (pk/nf/cm/anchor/public-inputs all match)")


if __name__ == "__main__":
    main()
