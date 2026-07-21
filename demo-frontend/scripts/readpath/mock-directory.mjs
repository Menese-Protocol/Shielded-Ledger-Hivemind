// Node test-rig directory for the wallet-birthday battery (Menese DeFi Team).
//
// A faithful in-memory mirror of DemoDirectory.mo's birthday surface, with a request log AND
// adversary modes, so the battery can model the malicious/faulty directory rather than the happy
// path. Every guard is modelled byte-for-byte against
// tests/DemoDirectory.mo:
//   * set_birthday — anonymous rejected; registration required; ct.size() must equal EXACTLY
//     BIRTHDAY_CT_SIZE (113); caller-keyed Map overwrite (Map.add semantics).
//   * get_birthday — caller-keyed, returns ONLY the caller's own record as candid opt ([]/[ct]).
//     (On chain this is an UPDATE call — certified; `replayOldest` below models the rollback a
//     non-certified read would permit, proving the floor invariant holds even then.)
//   * register — anonymous rejected + size guards (mirrored for completeness).
//
// Adversary modes (test setup only):
//   * replayOldest = true — get_birthday serves the OLDEST genuine ciphertext ever stored
//     (state rollback / replay).
//   * plant(principal, ct) — store an arbitrary ciphertext, bypassing guards (models a
//     compromised-owner-session write or raw state corruption).
//   * unreachable = true — every birthday endpoint throws (directory down).

const BIRTHDAY_CT_SIZE = 113;

export class MockDirectory {
  constructor() {
    this.entries = new Map(); // principalText -> { shielded_pk, enc_pk }
    this.birthdays = new Map(); // principalText -> Uint8Array (current)
    this.history = new Map(); // principalText -> [Uint8Array, ...] every genuine write, in order
    this.requestLog = [];
    this.replayOldest = false;
    this.unreachable = false;
  }

  resetLog() {
    this.requestLog = [];
  }

  birthdayCalls() {
    return this.requestLog.filter((e) => e.method === "set_birthday" || e.method === "get_birthday");
  }

  // Raw stored blob for the at-rest assertions.
  storedCt(principalText) {
    return this.birthdays.get(principalText) ?? null;
  }

  plant(principalText, ct) {
    this.birthdays.set(principalText, ct);
  }

  // The caller-bound actor surface (`actors.directory`) for a given authenticated principal.
  // `anonymous: true` models an unauthenticated caller for the guard tests.
  for(principalText, { anonymous = false } = {}) {
    const caller = anonymous ? null : principalText;
    return {
      register: async (shielded_pk, enc_pk) => {
        this.requestLog.push({ method: "register", caller });
        if (!caller) return { err: "anonymous-caller" };
        if (shielded_pk.length === 0 || shielded_pk.length > 128) return { err: "bad-shielded-pk" };
        if (enc_pk.length === 0 || enc_pk.length > 128) return { err: "bad-enc-pk" };
        this.entries.set(caller, { shielded_pk, enc_pk });
        return { ok: null };
      },
      lookup: async (p) => {
        this.requestLog.push({ method: "lookup" });
        const e = this.entries.get(typeof p === "string" ? p : String(p));
        return e ? [e] : [];
      },
      set_birthday: async (ct) => {
        this.requestLog.push({ method: "set_birthday", caller, size: ct?.length ?? 0 });
        if (this.unreachable) throw new Error("directory unreachable");
        if (!caller) return { err: "anonymous-caller" };
        if (!this.entries.has(caller)) return { err: "not-registered" };
        if (!(ct instanceof Uint8Array) || ct.length !== BIRTHDAY_CT_SIZE) return { err: "bad-birthday-ct-size" };
        this.birthdays.set(caller, ct);
        if (!this.history.has(caller)) this.history.set(caller, []);
        this.history.get(caller).push(ct);
        return { ok: null };
      },
      get_birthday: async () => {
        this.requestLog.push({ method: "get_birthday", caller });
        if (this.unreachable) throw new Error("directory unreachable");
        if (!caller) return [];
        const hist = this.history.get(caller) ?? [];
        const ct = this.replayOldest && hist.length ? hist[0] : this.birthdays.get(caller);
        return ct ? [ct] : [];
      },
    };
  }
}

export { BIRTHDAY_CT_SIZE };
