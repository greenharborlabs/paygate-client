# ADR: Rust cutover dependency and interface qualification

- Status: **accepted, contingent on the required native qualification workflow**
- Date: 2026-07-18
- Scope: Wave 2 of `../rust-cutover.md`

## Decision

The Rust implementation uses Rust 1.88.0 and the committed `Cargo.lock`. The direct
security-boundary dependencies are exact pins, not compatible ranges:

| Boundary | Selection | Features and linkage rationale | License |
| --- | --- | --- | --- |
| BOLT11 | `lightning-invoice = 0.34.1` | `std`; verifies Bech32 and recoverable secp256k1 signatures. Its `bitcoin`/`secp256k1` graph compiles native code but does not require OpenSSL. | MIT OR Apache-2.0 |
| YAML | `serde-saphyr = 0.0.29` | `default-features = false`, `deserialize` only. `src/config.rs` is the sole parser-event validation and deserialization boundary. | MIT OR Apache-2.0 |
| Keyring | `keyring = 4.1.5` | Default `v1`: Apple Keychain on macOS and Secret Service over D-Bus on Linux. Absence of a usable service is an expected, typed condition that selects the mode-0600 fallback; it never silently stores plaintext at a broader mode. | MIT OR Apache-2.0 |
| HTTP | `reqwest = 0.12.23` | Default features disabled; `rustls-tls`, `http2`, `json`, and `system-proxy`. This intentionally avoids OpenSSL linkage. Redirects must be disabled by each credential-bearing client. | MIT OR Apache-2.0 |
| Locking | `fs4 = 1.1.0` | Cross-process native file locking with no libc wrapper dependency. Wave 3 must preserve the existing `<file>.lock` contract. | MIT OR Apache-2.0 |
| Breez Spark | package `breez-sdk-spark`, crate `breez_sdk_spark`, workspace subdirectory `crates/breez-sdk/core` | Canonical source `https://github.com/breez/spark-sdk.git`; annotated tag `0.17.1`, tag object `90f0bfe103c614fb5178be940b2f35295d5aacb1`, commit/rev `f660f5a3bf24323e5c14235efcd28e5aef06c8aa`. Default features disabled; only `sqlite` enabled, so `connect` exists and the Rust wallet has isolated native storage. `passkey`, `uniffi`, `postgres`, `mysql`, `turnkey`, `test-utils`, and tracing/benchmark features remain disabled. SQLite is bundled by the pinned graph. | Repository-level MIT (the workspace packages omit Cargo license fields) |

No implementation wave may replace a version, source, revision, package,
subdirectory, or feature selection above without amending this ADR and the plan.

## Immutable source and license policy

The resolved graph contains exactly three git sources:

- Spark SDK at `f660f5a3bf24323e5c14235efcd28e5aef06c8aa`.
- Breez `boltz-client` at `809ac77cfc9ab2d809e3ef05f31c6d23ee9c4730`.
- Lightspark `frost` at `9aaf1b6b9fa3c2c3c2c7c70da83061deda1a9180`.

CI compares the complete Cargo.lock git-source set with that allowlist. A branch,
tag-only source, new git source, or changed commit fails. The committed license
checker parses complete SPDX expressions with AND/OR/WITH precedence and parentheses;
unknown identifiers, exceptions, syntax, or trailing content fail closed. Three known
legacy slash spellings are normalized explicitly. Missing metadata is accepted only
for the following exact `(package, version, normalized Cargo source)` identities.
The checker rejects a name, version, source revision/index, or license change
independently; it also rejects duplicate metadata identities, a stale allowlist
member, and any newly unlicensed package. This is an identity allowlist, never a
source-only, name-only, or version-range exception.

| Package | Version | Normalized Cargo source | Reviewed upstream license basis |
| --- | --- | --- | --- |
| `boltz-client` | `0.1.0` | `git+https://github.com/breez/boltz-client?rev=809ac77cfc9ab2d809e3ef05f31c6d23ee9c4730#809ac77cfc9ab2d809e3ef05f31c6d23ee9c4730` | Breez boltz-client repository-level MIT; package manifest omits `license`. |
| `breez-sdk-common` | `0.1.0` | `git+https://github.com/breez/spark-sdk.git?rev=f660f5a3bf24323e5c14235efcd28e5aef06c8aa#f660f5a3bf24323e5c14235efcd28e5aef06c8aa` | Spark SDK repository-level MIT; workspace package manifest omits `license`. |
| `breez-sdk-spark` | `0.1.0` | `git+https://github.com/breez/spark-sdk.git?rev=f660f5a3bf24323e5c14235efcd28e5aef06c8aa#f660f5a3bf24323e5c14235efcd28e5aef06c8aa` | Spark SDK repository-level MIT; workspace package manifest omits `license`. |
| `flashnet` | `0.1.0` | `git+https://github.com/breez/spark-sdk.git?rev=f660f5a3bf24323e5c14235efcd28e5aef06c8aa#f660f5a3bf24323e5c14235efcd28e5aef06c8aa` | Spark SDK repository-level MIT; workspace package manifest omits `license`. |
| `lnurl-models` | `0.1.0` | `git+https://github.com/breez/spark-sdk.git?rev=f660f5a3bf24323e5c14235efcd28e5aef06c8aa#f660f5a3bf24323e5c14235efcd28e5aef06c8aa` | Spark SDK repository-level MIT; workspace package manifest omits `license`. |
| `macros` | `0.1.0` | `git+https://github.com/breez/boltz-client?rev=809ac77cfc9ab2d809e3ef05f31c6d23ee9c4730#809ac77cfc9ab2d809e3ef05f31c6d23ee9c4730` | Breez boltz-client repository-level MIT; package manifest omits `license`. |
| `macros` | `0.1.0` | `git+https://github.com/breez/spark-sdk.git?rev=f660f5a3bf24323e5c14235efcd28e5aef06c8aa#f660f5a3bf24323e5c14235efcd28e5aef06c8aa` | Spark SDK repository-level MIT; workspace package manifest omits `license`. |
| `platform-utils` | `0.1.0` | `git+https://github.com/breez/boltz-client?rev=809ac77cfc9ab2d809e3ef05f31c6d23ee9c4730#809ac77cfc9ab2d809e3ef05f31c6d23ee9c4730` | Breez boltz-client repository-level MIT; package manifest omits `license`. |
| `platform-utils` | `0.1.0` | `git+https://github.com/breez/spark-sdk.git?rev=f660f5a3bf24323e5c14235efcd28e5aef06c8aa#f660f5a3bf24323e5c14235efcd28e5aef06c8aa` | Spark SDK repository-level MIT; workspace package manifest omits `license`. |
| `spark` | `0.1.0` | `git+https://github.com/breez/spark-sdk.git?rev=f660f5a3bf24323e5c14235efcd28e5aef06c8aa#f660f5a3bf24323e5c14235efcd28e5aef06c8aa` | Spark SDK repository-level MIT; workspace package manifest omits `license`. |
| `spark-wallet` | `0.1.0` | `git+https://github.com/breez/spark-sdk.git?rev=f660f5a3bf24323e5c14235efcd28e5aef06c8aa#f660f5a3bf24323e5c14235efcd28e5aef06c8aa` | Spark SDK repository-level MIT; workspace package manifest omits `license`. |
| `tokio-tungstenite-wasm` | `0.8.2` | `registry+https://github.com/rust-lang/crates.io-index` | Reviewed upstream crate repository is MIT; this published manifest omits `license`. |
| `utils` | `0.1.0` | `git+https://github.com/breez/spark-sdk.git?rev=f660f5a3bf24323e5c14235efcd28e5aef06c8aa#f660f5a3bf24323e5c14235efcd28e5aef06c8aa` | Spark SDK repository-level MIT; workspace package manifest omits `license`. |

The table has one exact tuple per checker entry (including the same package name from
distinct sources). Its table-driven self-tests mutate every
allowlisted tuple's name, version, source, and license independently and require a
full `name@version source=...` rejection diagnostic. Valid SPDX continues to pass;
invalid or unapproved SPDX fails closed.

`cargo-audit 0.21.2` runs against the committed graph with warnings denied. A new
advisory or license/source-policy failure blocks qualification; it is not waived
by a successful build.

## YAML security subset

`serde-saphyr` is qualified only as the low-level decoder. `src/config.rs` validates
its parser event stream before domain deserialization and rejects:

- duplicate mapping keys at every nesting level;
- anchors, aliases, and merge keys (`<<`), which make source order and ownership
  ambiguous;
- explicit/custom tags and directives;
- YAML 1.1 implicit booleans such as `yes`, `no`, `on`, and `off` (only literal
  JSON-style `true` and `false` are accepted);
- malformed, multi-document, non-UTF-8, or trailing documents.

The event boundary is followed by duplicate-key, merge-key, strict-boolean, and
one-document deserializer defenses. A source-policy test forbids permissive direct
deserialization elsewhere. Typed errors are redacted and never retain source text.

## Platform and dynamic-linkage gate

Linux release builds occur in the pinned Rust 1.88 bullseye image and must resolve
from the prepared vendor tree with `CARGO_NET_OFFLINE=true`. `ldd` and `readelf`
must show no GLIBC symbol newer than 2.31. macOS uses
`MACOSX_DEPLOYMENT_TARGET=15.0`. The committed linkage helper permits only explicit
common Linux libraries plus the target loader and pseudo-vDSO, or exact macOS system
dylib/framework paths. It rejects unresolved, nonabsolute, unlisted, package-manager,
user, rpath/loader/executable paths, wrong architecture, GLIBC >2.31, and a minOS
other than 15.0. `protoc` is a build prerequisite of the
pinned Spark token graph. It is installed only on the ephemeral qualification
builder and is not a runtime dependency.

The four native legs run `paygate --version`, compile the complete locked Breez
feature graph, exercise BOLT11 corruptions, and run the non-paying Breez lifecycle.
Each process mixes 32 fresh OS-random bytes with target, run ID, run attempt, and PID,
then exclusively creates storage whose collision is fatal. An RAII guard removes it
without printing secrets or the full path. A private qualification wrapper exposes
only connect/readiness/receive-one-sat/prepare-only/disconnect and no SDK handle or
send capability. Each target therefore has distinct empty wallet/storage;
no Python wallet directory or payer secret is available. The lifecycle creates a
fresh one-satoshi receive invoice, prepares it, never invokes `send_payment`, then
disconnects and deletes the isolated storage.

## Keyring ownership

The service is exactly `paygate-client.credentials`. The primary account is
`<namespace>:<credential_id>`. Only namespace `default` may fall back to the
legacy unnamespaced `<credential_id>` account, and the lookup order remains
namespaced first. Native Linux and macOS qualification use independent accounts for
Python-write/Rust-read-delete and Rust-write/Python-read-delete, plus Python legacy
lookup for default only. Only classified backend-unavailable errors select the
Python schema-v1 fallback; permission, malformed/corrupt, symlink, nonregular, and
ambiguous failures fail closed. Fallback writes preserve unrelated entries, use the
compatible lock, flush and sync, and reassert/verify mode 0600. Its record-aware put
creates a complete schema-v1 file and credential on first use. Duplicate identity
records fail every read/write/delete operation, and deletion removes the matching
record rather than leaving a keyring marker with no secret.

## Fail-closed rule

An unsupported compiler/OS floor, unsafe YAML behavior, advisory or license
failure, keyring mismatch, Breez lifecycle failure, mutable source, unavailable
native runner, or runtime/linkage drift invalidates this decision. The remedy is
an amended decision and plan, never a substituted dependency or skipped target.
