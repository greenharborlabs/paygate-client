# Patched platform-utils provenance

- `spark-sdk-platform-utils`: `https://github.com/breez/spark-sdk.git` at `f660f5a3bf24323e5c14235efcd28e5aef06c8aa`.
- `boltz-client-platform-utils`: `https://github.com/breez/boltz-client` at `809ac77cfc9ab2d809e3ef05f31c6d23ee9c4730`.
- `spark-sdk-breez-sdk-core`: copied only from `crates/breez-sdk/core` in
  `https://github.com/breez/spark-sdk.git` at
  `f660f5a3bf24323e5c14235efcd28e5aef06c8aa`.

For each source-distinct crate, the only behavioral delta is replacing
`Duration::from_mins(1)` with the Rust-1.88-compatible equivalent
`Duration::from_secs(60)`.

The core package's `UPSTREAM_SHA256SUMS` records every copied upstream file.
Its allowed delta is the standalone Cargo manifest plus exactly four equivalent
duration substitutions: 1 minute to 60 seconds (three occurrences) and 10
minutes to 600 seconds (one occurrence).

Distinct SemVer build metadata preserves two unambiguous local package IDs in
`Cargo.lock`; it does not change either crate's `0.1.0` compatibility version.
