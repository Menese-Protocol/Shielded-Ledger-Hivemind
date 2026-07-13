# NNS Candid pin

The byte and compatibility oracle is pinned to `dfinity/ic`
`c6a37193d91ddad3254fccce83fff18809fbbc1d`.

- `ledger.did`: SHA-256 `18c2fe7ea500c88df92eddd83a69a3e44c07a289465e06941b07c0dffc7099df`
- `ledger_archive.did`: SHA-256 `8b9f602f2eb8b87a74d595a46f5c52117b9c0ba5bbb67731b349e0d4cadc3232`
- `adapter_ledger_surface.did`: exact projection of the six methods consumed by the adapter.

The e2e regenerates the Motoko fixture Candid and requires it to be a subtype of the
projected real-ledger interface with `didc check`.
