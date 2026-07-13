# `zknote1` ICRC-3 block schema — version 1

`zknote1` is the experimental custom block type served by the shielded companion ledger. Each block
is an ICRC-3 `Value.Map`. The map is hashed with ICRC-3 representation-independent hashing; map entry
order therefore carries no meaning.

| key | ICRC-3 Value | constraint |
|---|---|---|
| `btype` | `Text` | exactly `zknote1` |
| `phash` | `Blob` | absent on genesis; otherwise the 32-byte ICRC-3 hash of the exact preceding block Value |
| `encoding_version` | `Nat` | exactly `1` |
| `note_position` | `Nat` | dense zero-based note/log position; equals returned block ID |
| `commitment` | `Blob` | exactly 32 opaque commitment bytes |
| `ephemeral_key` | `Blob` | non-empty opaque recipient key material |
| `note_ciphertext` | `Blob` | non-empty opaque encrypted note payload |
| `nullifiers` | `Array` of `Blob` | empty for `shield`; the transaction's two 32-byte nullifiers for both transfer outputs |
| `anchor_before` | `Blob` | exactly 32 circuit-root bytes |
| `note_root_after` | `Blob` | exactly 32 circuit-root bytes |
| `timestamp` | `Nat` | IC time in nanoseconds at append |
| `origin` | `Text` | `shield` or `confidential_transfer` |

The block type is local/experimental rather than an allocated ICRC standard number. Its advertised
URL remains the generic ICRC-3 specification because no externally published schema URL was
authorized for this sandbox. A production registration must replace that URL with an immutable,
public schema URL without changing already-hashed blocks.

This schema describes the shielded companion log only. Transparent ICRC-1/ICRC-2 account and
transaction schemas remain owned by the base ledger and are not synthesized into shielded blocks.

## `Int` compatibility guard

No `zknote1` field uses ICRC-3 `Int`; all numeric fields are non-negative and use `Nat`. The pinned
external oracle, `icrc-ledger-types 0.1.13`, hashes some positive `Int` values with unsigned
rather than signed LEB128, producing collisions such as `Int(64)==Int(-64)` in that crate. Motoko is spec-correct and the regression battery proves those
values distinct. Until external indexers have a corrected, countersigned oracle, adding any `#Int`
field to this block type is prohibited and requires a new schema version plus differential gate.
