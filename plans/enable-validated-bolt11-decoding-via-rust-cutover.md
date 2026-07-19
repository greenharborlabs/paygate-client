# Enable Validated BOLT11 Decoding via Rust Cutover

**Created at:** `f56cbd0` on `2026-07-18` | **Mode:** `eng`

## Summary

Replace the unpublished Python 0.1.0 package with a Rust 0.2.0 `paygate` CLI so every real payment uses `lightning-invoice`'s fully validated BOLT11 decoder. Preserve the existing command, configuration, policy, state, credential, backend, diagnostic, and error contracts while making the exact signed invoice amount and payment hash authoritative before wallet submission.

Python oracle boundary: frozen Python has no cancellation timing marker. Rust
`BeforeSubmission` and `AfterSubmissionUnknown` semantics are
`intentional_security_delta` cases owned by W2-02, with no Python observation
pointer; see `plans/decisions/python-oracle-transition-boundary.md`.

This plan deliberately uses ten dependency barriers and 16 work units despite the normal compact-plan threshold. Native runner provisioning, compatibility/interface/dependency qualification, deterministic core porting, isolated wallet adapters, parity/security approval, release preparation, local ownership transfer, prerelease publication, external tap validation, and promotion/observation have different stop conditions; splitting them into disconnected plans would weaken the release gate and rollback chain.

## Existing Code Leverage

- `paygate_client/invoices.py` centralizes the current partial amount/hash extraction and defines the behavior that the validated Rust domain replaces.
- `paygate_client/orchestrator.py` already funnels Payment and L402 challenges through policy, payer invocation, credential construction, cache, retry, and ledger settlement.
- `paygate_client/payers/base.py` provides the shared payer/result verification contract; `lnd_rest.py`, `phoenixd.py`, `breez.py`, and `test_mode.py` provide adapter-specific behavior and test seams.
- `paygate_client/config.py`, `session_cache.py`, and `ledger.py` define environment precedence, keyring identifiers, JSON schemas, paths, permissions, and POSIX locking semantics that Rust must preserve.
- `tests/` already covers CLI envelopes, challenge parsing, backend contracts, redaction, state behavior, and release metadata. These tests become the Python compatibility oracle and seed the Rust corpus.
- `.github/workflows/ci.yml`, `.github/workflows/publish.yml`, `scripts/check-dist.sh`, and `docs/releasing.md` provide release provenance and clean-install checks that will be replaced, not discarded without evidence.
- `plans/bind-validated-bolt11-amount-and-payment-hash-to-every-policy-approved-payment-before-wallet-submission.md` supplies the proof-first invoice and synthetic-input constraints; this cutover supersedes its Python implementation path.

## Architecture

```text
untrusted HTTP 402 / diagnostic invoice
                 |
                 v
       challenge parser + Bolt11Invoice::from_str
                 |
                 v
          immutable ValidatedBolt11
      (original, amount_msat/sats, p-tag hash)
                 |
        +--------+---------+
        |                  |
        v                  v
   policy + ledger    synthetic test input
        |              (separate type/path)
        v
 pre-submit binding verifier
        |
        v
 async payer trait -> LND REST | Phoenixd | Breez Spark
        |
        v
 post-payment hash/preimage verifier -> credential/cache/retry/output
```

The Rust crate is introduced beside the frozen Python oracle. Wave 1 provisions real target runners; Wave 2 freezes the crate interfaces, compatibility corpus, and dependency graph; Waves 3 and 4 fill non-overlapping core and adapter modules; Wave 5 alone wires the registry and end-to-end flow. Wave 6 prepares release automation without deleting or publishing, and Waves 7-10 separate operator-approved ownership transfer, prerelease publication, external tap validation, and final promotion/observation.

## Blast Radius

| Modified File/Interface | Consumers | Covered by Work Unit? |
| --- | --- | --- |
| `.github/workflows/rust-platform.yml`, runner provisioning/docs | four-target build and runtime gates | W1-01 |
| `compat/manifest.yaml`, `compat/python_oracle/`, `compat/fixtures/` (new) | all parity and release gates | W2-01 |
| `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `src/` module/interface skeleton | every Rust unit and target build | W2-02 |
| `src/cli.rs`, `src/config.rs`, `src/serialization.rs`, `src/error.rs` | CLI and integration | W3-01 |
| `src/invoice.rs`, `src/challenge.rs`, `src/credentials.rs` | policy, diagnostics, every payer | W3-02 |
| `src/policy.rs`, `src/state/cache.rs`, `src/state/ledger.rs`, `src/state/keyring.rs` | orchestration and mixed-version state | W3-03 |
| `src/payers/test_mode.rs`, `lnd_rest.rs`, `phoenixd.rs`, `breez.rs` | payer registry/orchestrator | W4-01 through W4-04 |
| `src/orchestrator.rs`, `src/diagnostics.rs`, `src/http.rs`, `src/redaction.rs`, `src/trace.rs` | public CLI behavior | W5-01 |
| `.github/workflows/ci.yml`, `.github/workflows/release.yml`, release scripts/docs | contributors and GitHub Releases | W5-01, W6-01, W8-01 |
| Python package, tests, PyPI workflow, Breez/setup scripts | rollback artifact or retirement | W2-01, W6-01, W7-01 |
| install/state ownership runbook and host inventory | pip/pipx/direct/Homebrew operators | W6-01, W7-01 |
| `greenharborlabs/homebrew-tap` formula | Homebrew users | W9-01 |

The plan touches more than eight files because it replaces the language runtime for a stateful security-sensitive CLI. Work-unit ownership and Wave 2 module stubs keep parallel changes isolated; the compatibility manifest prevents broad rewrites from silently changing behavior.

## Public Interfaces and Invariants

- Continue shipping the executable as `paygate`; preserve commands, flags, no-argument/help behavior, stdout/stderr placement, sorted JSON envelopes, exit codes, YAML paths, environment precedence, cache/ledger schemas, lock paths, and keyring identifiers.
- Retire the Python import API without PyO3, FFI, decoder subprocess, or production sidecar.
- Support only `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu` with glibc >=2.31, plus `x86_64-apple-darwin` and `aarch64-apple-darwin` with macOS >=15.
- A real payment accepts only immutable `ValidatedBolt11`, constructed by `str::parse::<Bolt11Invoice>()`, retaining the exact submitted string, signed millisatoshi amount, checked whole-satoshi amount, and signed 32-byte payment hash.
- Reject amountless, fractional-satoshi, overflowing, malformed, or signature-invalid invoices before policy evaluation, ledger reservation, payer construction where practical, or wallet access.
- Immediately before submission, shared code must prove decoded amount equals the policy-approved amount, decoded hash equals the expected challenge hash, and the exact validated string is submitted.
- Verify every backend-provided hash and preimage against the validated expected hash before emitting success or constructing a credential.
- Synthetic test-mode input is a separate type and cannot be passed to any real payer.

## Risk Flags

`security`: yes | `performance`: yes | `migration`: yes | `public-api`: yes | `concurrency`: yes

## Wave 1: Provision Native Target Infrastructure

### W1-01: Provision four-target build and runtime qualification infrastructure

Provision and document actual builders and runtime executors for all supported triples. Compilation alone is insufficient: the gate must execute per-target binaries on glibc 2.31 aarch64/x86_64 Linux and macOS 15 Intel/Apple Silicon, with controlled artifact transfer and no payment secrets in untrusted emulation.

**Files:** `.github/workflows/rust-platform.yml` (new), `.github/actions/aggregate-rust-platform/` (new), `infra/runners/` or provider configuration references (new), `docs/platform-qualification.md` (new), `tests/platform-smoke/` (new)

**Acceptance criteria:**
- The document names each native/self-hosted/provider runner, OS image/version, CPU architecture, trust boundary, secret policy, owner, availability/SLA, timeout, and cost ceiling.
- Emulation may prove deterministic CLI behavior but cannot substitute for minimum-glibc/macOS native runtime or real wallet canaries.
- Per-target artifacts move from builders to runtime executors through checksummed/provenance-bound workflow artifacts and are reverified before execution.
- A manifest maps target triple to artifact hash, source commit, `Cargo.lock` hash, and runner identity.
- A required aggregation job fails closed on missing, skipped, timed-out, or stale target evidence.
- If macOS 15 or aarch64 glibc 2.31 execution cannot be secured, stop and amend the supported target matrix before implementation.

**Error handling:** Runner unavailability, architecture mismatch, stale image, artifact/hash/provenance mismatch, secret exposure risk, or incomplete required-check aggregation blocks qualification rather than silently skipping a target.

**Tests:** Workflow dry runs, runner attestation, artifact-transfer tamper tests, native version/help smoke, linkage/minimum-OS checks, and required-check failure injection.

**Test spec:**
- Execute each target's checksummed stub binary, built from the same commit and `Cargo.lock`, on its native target floor and record the triple/artifact hash/runner identity manifest.
- Tamper with a transferred artifact and assert the executor rejects it before launch.
- Make each matrix leg fail, skip, and time out in a test branch; assert the aggregate required check remains failed.

## Wave 2: Freeze Compatibility, Interfaces, and Dependencies

Both units depend on the qualified native runners and are independent and release-blocking. Any failed qualification stops the plan before production Rust implementation.

### W2-01: Freeze the Python oracle and compatibility manifest

Retain the already-frozen 37-case offline deterministic oracle for commit
`f56cbd0` and inventory every runtime, test, script, workflow, documentation,
and publication behavior. The Python bundle is transitional legacy coverage;
do not expand it with new adapter-negative, config-precedence,
backend-`pay-invoice`, redaction/replay, or submission-timing evidence. Rust
tests own those new acceptance criteria and the cancellation/security deltas;
see `plans/decisions/python-oracle-transition-boundary.md`.

**Files:** `compat/manifest.yaml` (new), `compat/python_oracle/` (new), `compat/fixtures/` (new), existing `tests/`, `scripts/`, `.github/workflows/`, and docs as read-only inputs

**Acceptance criteria:**
- Python 3.11 plus an immutable dependency lock can run the oracle offline from a clean checkout of `f56cbd0`.
- Clock, UUID, locale, timezone, HOME/XDG directories, keyring, network, and backend responses are injected or fixture-controlled.
- The manifest preserves the existing frozen CLI, config, challenge, error,
  credential, cache, ledger, keyring, permission, locking, and reservation
  observations without adding new Python cases.
- Every Python script/workflow/doc is assigned `port`, `replace`, `neutral_fixture`, `rollback_only`, or `retire` with an owning later unit.
- Two consecutive clean offline runs produce byte-identical golden outputs and
  manifest hashes; the checked-in baseline remains 37 cases.

**Error handling:** Missing pins, nondeterministic output, live network/keyring
access, or drift in the frozen baseline is a Wave 2 failure. Do not normalize
differences or infer Rust-only behavior from Python.

**Tests:** Oracle self-tests, clean-environment replay, fixture completeness, and golden-hash comparison.

**Test spec:**
- Run the full oracle twice with different real clock/HOME values and assert identical results.
- Make network and real keyring access fatal, then prove the corpus still completes.
- Assert every current command, backend, persistent schema, script, workflow, and documented output contract maps to a manifest entry and later owner.

### W2-02: Qualify Rust dependencies, module boundaries, and four targets

Create a compileable Rust 1.88.0 crate skeleton with all cross-wave module/trait stubs, then qualify the exact decoder, YAML, keyring, HTTP, locking, and Breez Spark dependency graph on the supported targets. Pin the canonical `https://github.com/breez/spark-sdk.git` source at tag `0.17.1`, tag object `90f0bfe103c614fb5178be940b2f35295d5aacb1`, and commit `f660f5a3bf24323e5c14235efcd28e5aef06c8aa`; the ADR must name the exact Cargo package/crate, workspace subdirectory, enabled/default-disabled features, vendor/checksum policy, and no implementation unit may substitute them without amending this plan.

**Files:** `Cargo.toml` (new), `Cargo.lock` (new), `rust-toolchain.toml` (new), `src/lib.rs` (new), `src/main.rs` (new), `src/payers/mod.rs` (new), `src/payers/base.rs` (new), other module stubs under `src/` (new), `tests/interface_contract.rs` (new), `reports/rust-qualification.md` (new), `.github/workflows/rust-qualification.yml` (new), `plans/decisions/rust-cutover-dependencies.md` (new)

**Acceptance criteria:**
- Pin Rust `1.88.0`, `lightning-invoice = 0.34.1`, `keyring = 4.1.5`, `serde-saphyr = 0.0.29`, and the immutable Breez source; commit the resolved graph.
- The ADR records licenses, advisories, transitive git sources, feature flags, dynamic linkage, and why the supported YAML subset rejects duplicate keys, aliases/merges, custom tags, YAML 1.1 booleans, and malformed documents.
- Breez connect/readiness/prepare/disconnect prototypes pass on all four targets without sharing wallet storage with Python.
- Python/Rust keyring interoperability passes for service `paygate-client.credentials`, account `<namespace>:<credential_id>`, the legacy unnamespaced default fallback, and a mode-0600 file fallback.
- Linux artifacts built in glibc 2.31 environments pass `ldd`/`readelf`; macOS builds use `MACOSX_DEPLOYMENT_TARGET=15.0`, pass `otool`, and smoke on macOS 15.
- `src/payers/base.rs` freezes signatures for `ValidatedBolt11`, `SyntheticPaymentChallenge`, the async real-payer trait, raw and verified payment results, the common verifier, cancellation semantics, and `NotSubmitted | SubmittedUnknown | Succeeded | FailedFinal` submission outcomes. `src/payers/mod.rs` freezes adapter exports and registry inputs.
- Compile-contract tests prove Waves 2 and 3 can implement those interfaces without editing shared signatures; the stubs compile without functional implementations.

**Error handling:** Any unsupported floor, unsafe YAML behavior, advisory/license failure, keyring mismatch, Breez lifecycle failure, or mutable/unpinned source stops the plan and requires an amended dependency decision.

**Tests:** Dependency smoke tests, official valid/invalid BOLT11 vectors, YAML rejection matrix, cross-language keyring round trips, target linkage/runtime checks, and Breez lifecycle tests using isolated wallets.

**Test spec:**
- Decode a signed amount-bearing vector, then independently corrupt checksum and signature and assert rejection.
- Write/read/delete the same credential from Python then Rust and Rust then Python, including legacy fallback and keyring-unavailable mode-0600 storage.
- Build each target from `Cargo.lock` with network-disabled resolution after vendoring/cache preparation; inspect minimum runtime/linkage and execute `paygate --version`.

## Wave 3: Port the Deterministic Core and Persistent State

All units depend on Wave 2 and may run in parallel by filling the frozen module stubs. They must not wire payer registry or CLI integration.

### W3-01: Port CLI, configuration, serialization, and domain errors

Implement the Clap surface and deterministic serializers without integrating orchestration. Reproduce Python path-expansion boundaries and parse `voltage-env.sh` data without executing shell code.

**Files:** `src/cli.rs`, `src/config.rs`, `src/serialization.rs`, `src/error.rs`, `tests/cli_contract.rs` (new), `tests/config_contract.rs` (new), `tests/serialization_contract.rs` (new)

**Acceptance criteria:**
- Commands, flags, help/no-argument behavior, exit codes, stdout/stderr, defaults, aliases, and environment precedence match every `must_match` oracle case.
- CLI JSON uses sorted Python-compatible spacing; credential JSON is compact/sorted; cache JSON is sorted/indented with trailing newline; ledger serialization follows the frozen schema/order.
- YAML accepts only the qualified subset and reports stable redacted configuration errors for all rejected constructs.
- Satoshi arithmetic and numeric conversions use checked `u64`; top-level panics become stable internal-error envelopes without secrets.

**Error handling:** Map Clap, path, UTF-8, env-file, YAML, overflow, I/O, and panic failures to manifest-owned exit/output contracts. Never echo environment secret values or execute env-file content.

**Tests:** Golden CLI snapshots, config/parser table tests, serializer byte comparisons, arithmetic boundary/property tests, and panic-containment tests.

**Test spec:**
- Differentially run every help/version/config error case and compare exit code plus stdout/stderr bytes.
- Feed duplicate keys, merges, aliases, tags, `yes`/`on`, malformed quotes, invalid UTF-8, and overflowing integers; assert stable errors and no command execution.
- Serialize each frozen envelope/state/signing fixture and compare exact bytes, including final newlines.

### W3-02: Implement validated invoice, challenge, and credential domains

Replace independent partial parsing with proof-first types. Parse repeated authentication headers and credential payloads while ensuring invoice-derived values cannot be overridden by challenge metadata.

**Files:** `src/invoice.rs`, `src/challenge.rs`, `src/credentials.rs`, `tests/invoice_contract.rs` (new), `tests/challenge_contract.rs` (new), `tests/credential_contract.rs` (new), `compat/fixtures/bolt11/` (new)

**Acceptance criteria:**
- Implement the frozen `ValidatedBolt11` and `SyntheticPaymentChallenge` interfaces without changing their Wave 2 signatures. `ValidatedBolt11` is constructible only through `Bolt11Invoice::from_str` and exposes the exact original string, exact millisatoshi amount, checked whole-satoshi amount, and normalized signed payment hash.
- Amountless, fractional-satoshi, overflow, mixed-case, bad checksum/signature/recovery id, malformed or conflicting mandatory tags, declared amount mismatch, and declared hash mismatch fail closed.
- Payment and L402 parsing preserve repeated-header behavior while deriving authoritative amount/hash only from `ValidatedBolt11`.
- Pre-submit and post-payment verifiers check exact invoice string, approved amount, backend hash, and preimage; errors never include invoice, preimage, token, or credential material.
- Credential signing bytes match the Python oracle for valid bound challenges.

**Error handling:** Typed decode, amountless, fractional, overflow, amount-binding, hash-binding, header, and credential errors preserve safe causes internally and expose only stable redacted domain messages.

**Tests:** Official vectors, mutation/property tests, parser corpus replay, compile-time constructor constraints where practical, and credential golden tests.

**Test spec:**
- Validate a signed 25-sat invoice and bind it to 25 sats/the correct hash; reject 24 sats, a different hash, and a copied string differing from the validated original.
- Mutate checksum, signature, recovery id, amount units, `p` tag, header repetition, and credential payload fields; assert no panic and the expected manifest class.
- Verify correct and incorrect backend hashes/preimages and assert only the correct proof can reach credential construction.

### W3-03: Port policy, cache, ledger, paths, and keyring state

Port policy and persistent state independently of orchestration. Preserve schema v1, namespace behavior, local-date accounting, hash/UUID formats, permissions, and `<file>.lock` POSIX `flock` interoperability.

**Files:** `src/policy.rs`, `src/state/mod.rs`, `src/state/cache.rs`, `src/state/ledger.rs`, `src/state/keyring.rs`, `tests/policy_contract.rs` (new), `tests/state_contract.rs` (new), `tests/mixed_state_processes.rs` (new)

**Acceptance criteria:**
- Policy decisions, reservation lifecycle, default paths, profiles, request/policy hashes, credential IDs, dates, and JSON schemas match the oracle.
- Cache and ledger honor the existing lock filenames and block safely across Python/Rust processes; Breez wallet/storage is never shared in these tests.
- Corrupt, truncated, wrong-type, negative, over-budget, permission-denied, and lock-failure states return stable errors without partial success.
- New files and fallback secret files have mode 0600; directories and replacements do not widen permissions.
- If cache writes become atomic rather than truncate-in-place, the manifest records an intentional security delta and Python can consume the Rust output.

**Error handling:** Typed lock/read/write/corruption/keyring/permission/reservation errors preserve ledger consistency. Cleanup errors cannot erase the primary error; ambiguous reservation states follow the frozen matrix.

**Tests:** Golden state replay, property tests, permission/fault injection, cross-process contention, mixed-version read/write, and reservation state-machine tests.

**Test spec:**
- Race Python and Rust reservations against one daily cap and prove committed plus pending spend never exceeds it.
- Hold each Python lock while Rust attempts access, and vice versa; verify blocking/timeout behavior and uncorrupted final JSON.
- Round-trip every schema-v1/cache/keyring fixture in both directions, inject failures at read/write/fsync/rename/unlock, and assert the frozen error and reservation outcome.

## Wave 4: Port Isolated Payer Adapters

Each unit depends on Wave 3 and fills one frozen adapter stub. Units are parallel: they do not edit the registry, orchestrator, shared invoice type, or CLI wiring.

### W4-01: Port the synthetic test-mode adapter

Implement the deterministic no-wallet adapter using the frozen `SyntheticPaymentChallenge`; it cannot be accepted by the real payer trait or converted into `ValidatedBolt11`.

**Files:** `src/payers/test_mode.rs`, `tests/payer_test_mode_contract.rs` (new)

**Acceptance criteria:**
- Test mode reproduces frozen preimage/result behavior without network, wallet, keyring, or real invoice validation bypass.
- Real payer entry points cannot accept the synthetic type; test mode cannot fabricate a `ValidatedBolt11`.
- Missing, malformed, or mismatched synthetic preimages fail before producing authorization output.

**Error handling:** Return typed synthetic-input and preimage errors; never fall back from a failed real decode into test mode.

**Tests:** Unit/compile-fail contract tests and Python/Rust differential fixtures.

**Test spec:**
- Run every frozen test-mode challenge and compare result/error bytes.
- Attempt to pass synthetic input to each real payer trait boundary and assert compile failure or pre-transport rejection.
- Corrupt/miss the preimage and assert no credential or success result is constructed.

### W4-02: Port the LND REST adapter

Implement LND's streaming router contract behind the frozen async real-payer trait, consuming only `ValidatedBolt11` and using the shared result verifier.

**Files:** `src/payers/lnd_rest.rs`, `tests/payer_lnd_rest_contract.rs` (new), `compat/fixtures/backends/lnd/` (new)

**Acceptance criteria:**
- Request URL/body, macaroon header, TLS/custom CA, fee limit, timeout, and streaming/partial NDJSON behavior match the oracle.
- Redirects are disabled and macaroon material is never replayed across origins.
- Only terminal success with invoice-bound amount/hash/preimage is accepted; intermediate, failed, missing, malformed, binary, gzip, and non-UTF-8 responses retain stable classifications.
- Cancellation and ambiguous post-submission outcomes return the frozen status needed by Wave 5 ledger handling and never retry payment automatically.

**Error handling:** Distinguish configuration/TLS/auth/transport/timeout/cancellation/HTTP/payment/malformed/proof failures without leaking macaroon, invoice, response secrets, hash, or preimage.

**Tests:** Recording HTTP server contract tests, stream chunk/property tests, redaction tests, and differential fixtures.

**Test spec:**
- Stream in-flight then terminal success across arbitrary chunk boundaries and accept once; test terminal failure, EOF, timeout, cancellation, and connection loss after submission.
- Return redirects to same and different origins and assert no automatic follow and no credential replay.
- Exercise gzip, binary/non-UTF-8, custom CA, proxy, wrong amount/hash/preimage, and repeated auth headers; assert stable safe errors.

### W4-03: Port the Phoenixd adapter

Implement Phoenixd HTTP payment behavior behind the same validated trait, preserving its explicit fee-capability safety gate.

**Files:** `src/payers/phoenixd.rs`, `tests/payer_phoenixd_contract.rs` (new), `compat/fixtures/backends/phoenixd/` (new)

**Acceptance criteria:**
- Form fields, Basic auth, configured fee parameter, success/failure shapes, timeout, TLS/proxy behavior, and result normalization match the oracle.
- The adapter refuses before submission when it cannot enforce `max_fee_sats`.
- Redirects are disabled and Basic auth is never replayed across origins.
- Only invoice-bound amount/hash/preimage produces success.

**Error handling:** Distinguish missing fee capability, auth, timeout, transport, HTTP rejection, malformed body, backend failure, and proof mismatch; redact password, invoice, hash, and preimage.

**Tests:** Recording HTTP server contract tests, response-shape tables, redirect/auth tests, and differential fixtures.

**Test spec:**
- Assert the exact form and fee field for success, then omit fee capability and prove zero requests.
- Return 401/403/4xx, malformed JSON, gzip/binary/non-UTF-8 bodies, timeout, redirect, and ambiguous disconnect; compare classifications and ensure no retry.
- Vary returned amount/hash/preimage and assert only invoice-bound proof succeeds.

### W4-04: Port the pinned Breez Spark adapter

Implement the qualified Breez lifecycle and fee preparation using the exact locked commit and an isolated Rust wallet/storage owner.

**Files:** `src/payers/breez.rs`, `tests/payer_breez_contract.rs` (new), `compat/fixtures/backends/breez/` (new), `docs/breez-runtime.md` (new)

**Acceptance criteria:**
- Connect/readiness/prepare/send/completion/disconnect behavior and error mapping match the qualified prototype and oracle.
- Prepared fees over the approved cap reject before send; only a BOLT11 Lightning payment route is accepted.
- Rust and Python differential/canary tests use distinct wallets and storage; simultaneous access to one Breez storage directory is prohibited and detected where possible.
- Success requires invoice-bound amount/hash/preimage and safe disconnect behavior.

**Error handling:** Distinguish missing dependency/config/secret, storage ownership, readiness, prepare, fee, route, timeout/cancellation, send, malformed SDK result, missing preimage, and proof mismatch without secret or invoice leakage.

**Tests:** Fake-SDK contract tests, lifecycle ordering/fault injection, isolated testnet smoke, and platform smoke from the locked graph.

**Test spec:**
- Record lifecycle calls for success and inject a failure at every stage; assert disconnect/cleanup and stable error behavior.
- Exceed the prepared fee and return non-BOLT11 route, missing result, wrong hash, and wrong preimage; assert send/success is blocked at the correct boundary.
- Attempt duplicate storage ownership and prove the second process fails closed without opening the wallet.

## Wave 5: Integrate and Approve Parity

### W5-01: Wire the client and close all compatibility/security gates

Integrate only reviewed Wave 4 adapters into the registry, orchestrator, diagnostics, CLI, HTTP, redaction, and tracing layers. Run the complete Python/Rust corpus, fuzz/property suites, target builds, testnet canaries, and the bounded mainnet canary; produce the explicit release-approval record that Wave 6 consumes.

**Files:** `src/orchestrator.rs`, `src/diagnostics.rs`, `src/http.rs`, `src/redaction.rs`, `src/trace.rs`, `src/payers/mod.rs`, `src/cli.rs`, `src/main.rs`, `.github/workflows/ci.yml`, `tests/integration/` (new), `fuzz/` (new), `reports/rust-parity-and-security.md` (new), `plans/decisions/rust-release-approval.md` (new), user-facing docs

**Acceptance criteria:**
- Every `must_match` case matches exact observable behavior; every difference is explained and approved under its manifest classification.
- Invalid/mismatched invoices fail before policy reservation and payer construction/invocation; backend hash/preimage/amount mismatch cannot emit success, credential, cache entry, or success trace.
- Synthetic input is accepted only when `payer.backend == "test-mode"`; `SyntheticModeDisabled`, malformed synthetic proof, real invoice on test mode, and synthetic input on a real backend all fail before reservation, payer construction, network/wallet access, credential output, or cache write.
- Cancellation/ambiguous submission consumes or releases reservations exactly per the frozen matrix and never auto-resubmits.
- Preserve `paymentHash` in explicitly requested successful CLI and diagnostic payment envelopes because it is a frozen public contract. Classify removal of hashes from traces as an intentional security delta. Logs, errors, traces, panic reports, and serialized upstream HTTP bodies contain no secrets, invoice strings, payment hashes, or preimages; failed diagnostic envelopes contain none.
- `cargo fmt --check`, Clippy with warnings denied, unit/integration/doc tests, license/source/advisory checks, fuzz smoke, cross-process locks, and all four target build/link/runtime tests pass from `Cargo.lock`.
- Canary matrix: LND REST and Phoenixd each complete a named isolated testnet payment using dedicated wallets; Breez Spark completes a Lightning Mainnet payment because its Regtest network does not provide a developed Lightning network. Every row names the backend/network, invoice source, dedicated wallet/storage owner, expected proof, retry prohibition, cleanup, and rollback.
- Breez's operator-approved Mainnet canary uses a dedicated wallet funded with no more than 1,000 sats and pays one 21-sat invoice under `max_request_sats: 100`, `max_fee_sats: 10`, and `daily_budget_sats: 100`; total authorized loss across all Mainnet canary attempts is capped at 100 sats and no ambiguous attempt is retried.
- Release approval lists each intentional delta and exact passing source commit; any canary anomaly blocks Wave 6.

**Error handling:** The integrated client preserves typed boundary errors and redaction, catches top-level panics, does not retry ambiguous payments, and aborts qualification on any amount/hash/preimage, fee, reservation, parity, redaction, timeout, or duplicate-submission anomaly.

**Tests:** Full differential suite, end-to-end CLI/backend contracts, fuzz/property suites, concurrency/fault tests, platform builds, testnet canaries, and one tightly bounded mainnet canary.

**Test spec:**
- Replay the entire manifest and fail on any unclassified byte/exit/state difference.
- Exercise every synthetic/real backend combination and assert only configured test mode accepts the frozen synthetic contract; all rejected combinations leave payer construction, network calls, ledger, credentials, and cache untouched.
- Fuzz invoice, auth headers, YAML, cache/ledger, backend payloads, and numeric boundaries with assertions for no panic, no secret output, and no payer invocation on invalid input.
- Inject failure/cancellation before prepare, before send, after send, after backend success, during verification, credential construction, cache write, and retry; assert the frozen ledger/submission state.
- Download each CI-built target artifact into a clean runner, inspect linkage, execute CLI smoke, and run the applicable backend canary using isolated storage.

## Wave 6: Prepare Release Automation and Migration Runbooks

### W6-01: Dry-run immutable release automation and installed-client migration

Build all release and migration machinery while Python remains intact and without creating tags, releases, tap changes, or real payments. Produce the rollback wheel, dry-run release archives/metadata, and an operator runbook that discovers every installed client and background launch path before any destructive step.

**Files:** `.github/workflows/release.yml` (new), release/build/check scripts (new), `docs/releasing.md`, `docs/installing.md`, `docs/rust-migration-runbook.md` (new), `CHANGELOG.md`, shell completion/manpage source, `compat/rollback/` metadata (new); existing Python package/workflows remain present

**Acceptance criteria:**
- The last Python source commit builds an install-tested wheel with recorded commit, version, dependency lock, and SHA-256; the workflow can later attach those exact retained bytes without rebuilding.
- Release dry-run produces four versioned archives, `SHA256SUMS`, SPDX and CycloneDX SBOMs, license inventory, provenance inputs, completions, and man page without publishing or requesting production credentials.
- The runbook performs read-only discovery of `command -a paygate`, shell command hashes, pip/pipx/venv/editable installs, direct archives, Homebrew, PATH shadowing, cron, systemd user/system services, launchd, active processes, stale locks, and cache/ledger/Breez storage ownership.
- Forward and rollback procedures cover pip/pipx-to-Homebrew, pip/pipx-to-direct archive, and direct-archive upgrades, including old-binary quarantine/removal and resolved-path verification.
- The release workflow has explicit environment approvals for real payment, annotated tag creation, GitHub prerelease publication, promotion, and rollback actions; dry-run paths cannot reach them.

**Error handling:** Missing rollback bytes, incomplete install discovery, unresolved PATH/service ownership, artifact drift, metadata/signing-input failure, or a dry run capable of external publication blocks Wave 7.

**Tests:** Clean rollback-wheel installs, release workflow dry runs, archive/metadata reproducibility, runbook fixture hosts, PATH/service discovery tests, and credential-boundary tests.

**Test spec:**
- Model pipx, editable pip, direct archive, duplicate PATH entries, shell hashing, cron/systemd/launchd jobs, and stale locks; assert the inventory finds every executable and launcher without mutation.
- Build release artifacts twice from the same commit and compare payload manifests; prove dry run cannot mint production OIDC or publish.
- Install the retained Python wheel in a clean environment and run the frozen oracle smoke.

## Wave 7: Transfer Local Ownership and Remove the Python Runtime

### W7-01: Quiesce clients, back up state, and perform the repository cutover

Under recorded operator approval, stop all Python/Rust client and wallet processes, verify backups, create the immutable Python rollback tag pointing to the retained wheel's source, then remove only manifest-classified Python runtime assets and install the approved Rust candidate locally. This wave changes repository and host state but does not create `v0.2.0`, publish a GitHub release, modify Homebrew, or make a real payment.

**Files:** remove `paygate_client/`, Python-only `tests/`, `pyproject.toml`, `.github/workflows/publish.yml`, and retired scripts only per W1 manifest; preserve `compat/`, reports, neutral fixtures, last-Python tag/rollback metadata; update `README.md`, `LICENSE`, `CHANGELOG.md`, and migration/release docs

**Acceptance criteria:**
- A named operator records approval, inventory output, active-handle checks, backup paths/hashes, rollback tag/commit/wheel hash, selected installation path, and state owner before mutation.
- No process holds cache, ledger, or Breez storage; configured cron/systemd/launchd jobs are disabled; every old `paygate` executable is removed or quarantined and shell resolution points only to the candidate Rust binary.
- Cache and ledger backups are restorable and verified before ownership transfer; a state-owner marker/process lock prevents Python and Rust from concurrently owning the same state/storage.
- Only W1-manifest `retire` assets are deleted; `neutral_fixture` and `rollback_only` assets remain reachable and checksummed.
- The final source tree passes the full W4 gate without a real canary and is ready for immutable tagging.

**Error handling:** Any unclassified installation, active/stale handle with uncertain ownership, launcher that cannot be disabled, backup/hash/readback failure, multiple resolved binaries, state-owner collision, or test regression aborts and restores the pre-cutover host/repository state from retained bytes.

**Tests:** Quiescence failure injection, backup/restore, install-path migrations, exclusive owner/process-lock tests, final-source quality gates, and rollback rehearsal without publication.

**Test spec:**
- Hold cache, ledger, and Breez handles in turn and assert cutover aborts before deletion or ownership change.
- Migrate fixture hosts from pipx and direct archive to Rust, refresh shell lookup, and assert exactly one resolved `paygate` plus disabled launchers.
- Roll back locally to the retained Python wheel and forward again, proving exclusive state ownership and schema readability.

## Wave 8: Publish Immutable Rust Prerelease Artifacts

### W8-01: Tag, build, sign, and publish the public prerelease

After explicit operator approval, create annotated tag `v0.2.0` at the exact W7-approved commit. Build, attest, sign, and publish immutable public prerelease assets; do not promote the release or edit the Homebrew tap in this wave.

**Files:** `.github/workflows/release.yml`, Git tag `v0.2.0`, GitHub prerelease assets and metadata generated from the tagged workflow

**Acceptance criteria:**
- Approval records the exact commit, W5/W7 evidence, version, tag command, authorized Mainnet canary budget, and rollback owner before tag creation.
- Four archives contain binary, README, license, completions, and man page; asset names and internal versions match `v0.2.0`.
- CI generates and verifies `SHA256SUMS`, SPDX/CycloneDX SBOMs, license inventory, GitHub/SLSA provenance, and OIDC keyless Sigstore bundles for every archive and checksum file.
- Signature verification constrains issuer `https://token.actions.githubusercontent.com` and identity `https://github.com/greenharborlabs/paygate-client/.github/workflows/release.yml@refs/tags/v0.2.0`.
- The GitHub release is public prerelease; asset IDs, bytes, names, URLs, hashes, signatures, and provenance are recorded as the immutable promotion baseline.

**Error handling:** Tag/source mismatch, missing approval, failed final gate, build drift, signing/provenance/SBOM/checksum failure, partial publication, or asset mismatch stops the train. Never retag or replace an asset; preserve evidence and issue a forward version if bytes must change.

**Tests:** Tag provenance, reproducible archive comparison, signature/provenance/SBOM/license verification, clean public download, and partial-publication recovery drill.

**Test spec:**
- Resolve `refs/tags/v0.2.0^{commit}` and assert it equals the approved commit on `main` before any upload.
- Download every public asset and verify checksum, bundle issuer/workflow identity, provenance subject, SBOM, and internal version.
- Simulate a failed/partial upload and assert the workflow cannot mutate or silently reuse the release.

## Wave 9: Stage Homebrew and Validate Exact Downloaded Bytes

### W9-01: Test the external tap and public prerelease on every platform

Under separate approval to modify `greenharborlabs/homebrew-tap`, stage formula `paygate` against the exact public prerelease URLs and hashes. Validate install lifecycle, Gatekeeper guidance, rollback, and the backend/network canary matrix using downloaded—not workflow-local—binaries; do not merge the tap or promote the GitHub release.

**Files:** staging branch in `greenharborlabs/homebrew-tap` for `Formula/paygate.rb` and tests; release baseline/evidence in `reports/v0.2.0-prerelease-validation.md` (new); installation docs only if a forward `v0.2.1` is required

**Acceptance criteria:**
- Formula selects all four OS/CPU assets and installs the binary, completions, and man page using recorded immutable URLs/hashes.
- Fresh install, upgrade, uninstall/reinstall, direct-archive install, and rollback pass on the qualified native runners; resolved PATH shows exactly the expected binary.
- A fresh quarantined macOS download demonstrates the expected Gatekeeper failure, then succeeds only after checksum/Sigstore verification and documented quarantine removal; 0.2.0 does not claim notarization.
- Downloaded binaries pass CLI/state smoke, LND and Phoenixd testnet canaries, and the operator-approved bounded Breez Mainnet canary from W5. Ambiguous attempts are not retried and total Mainnet loss remains within the approved cap.
- Formula commit, public asset IDs/hashes, test evidence, and candidate merge commit are frozen for promotion.

**Error handling:** Tap permission failure, URL/hash mismatch, install/PATH collision, Gatekeeper documentation failure, state incompatibility, canary anomaly, ambiguous payment, or changed public asset blocks Wave 10. Published bytes are never replaced; code fixes require a forward version.

**Tests:** Formula audit/style/test, four-platform install lifecycle, direct-download verification, Gatekeeper flow, state migration/rollback, downloaded-byte canaries, and external-repository approval checks.

**Test spec:**
- Install every formula branch and direct archive on its target, run version/help/state smoke, uninstall/reinstall, and roll back without concurrent state owners.
- Compare downloaded asset IDs/hashes to the W7 baseline before and after every canary.
- Run the named canary matrix with submission recording; inject one ambiguous outcome and prove no automatic/operator retry occurs.

## Wave 10: Promote, Observe, and Drill Rollback

### W10-01: Promote unchanged artifacts and complete the observation window

With final operator approval, merge the already-tested tap commit and toggle the unchanged GitHub prerelease to final. Run post-release install and backend-readiness smoke, observe production for a defined 24-hour window, then perform the operational rollback/forward drill using retained immutable artifacts. Breez readiness in this wave is non-paying; any additional Mainnet submission requires a new recorded approval, a new cumulative loss cap spanning Waves 5, 9, and 10, and the existing no-retry rule.

**Files:** merge the frozen `greenharborlabs/homebrew-tap` staging commit; GitHub release promotion metadata; `reports/v0.2.0-post-release.md` (new); no source or asset changes

**Acceptance criteria:**
- Approval confirms W8/W9 asset IDs/hashes, tap commit, cumulative canary spend, rollback owner, monitoring contacts, and 24-hour start/end timestamps.
- Promotion only toggles the same GitHub release and merges the exact tested formula commit; no tag, asset, URL, hash, signature, provenance, or formula byte changes.
- Fresh public installs and post-release CLI/state/backend smoke pass; Breez uses non-paying connect/readiness/disconnect only, and monitoring records console/error, download/install, and backend anomalies during the 24-hour window.
- The rollback drill stops Rust, verifies no handles, restores state if required, installs the retained Python wheel or retained native archive/formula as selected, verifies health, then forwards again without concurrent ownership.
- Final evidence records success or activates rollback; the plan is not complete until the observation window and drill finish.

**Error handling:** Baseline drift, missing approval/on-call owner, promotion mismatch, readiness anomaly, unauthorized payment attempt, state-owner conflict, or rollback failure stops forward action and activates the documented incident/rollback path. Never rebuild mutable HEAD for rollback.

**Tests:** Promotion immutability comparison, public install smoke, 24-hour monitoring checklist, state/process ownership checks, full rollback/forward drill, and incident-path tabletop.

**Test spec:**
- Compare release/tap bytes before and after promotion and assert only release status/branch merge metadata changed.
- Poll documented health/install/backend signals through the 24-hour window and record zero unexplained anomalies or a triggered rollback decision.
- Roll back from public Rust to retained Python/native bytes and forward again, verifying exclusive handles, state readability, PATH resolution, and version at each boundary.

## NOT in Scope

- Windows support.
- Preserving the Python import/library API.
- PyO3, FFI, a decoder subprocess, or hybrid Python/Rust production operation.
- New commands, configuration formats, backend redesign, or product-level payment caps.
- BOLT11 expiry or Lightning-network validation changes; retain current semantics and track separately.
- macOS Developer ID signing or notarization in 0.2.0.
- An external security audit; internal qualification remains release-blocking.

## Security Considerations

The HTTP challenge, BOLT11 string, backend response, config/state files, environment, and credential store are trust boundaries. Only `ValidatedBolt11` may cross from untrusted invoice input into real policy/payer code; no nullable parse result, metadata fallback, backend-authoritative value, diagnostic shortcut, or synthetic flag may upgrade invalid input. Secret-bearing headers must not survive redirects, and all errors/traces/panics must pass structural redaction before serialization.

The release graph is also a trust boundary. Dependencies and actions are immutable, final binaries are built from the approved tagged commit, public URLs are tested before promotion, Sigstore verification constrains issuer and workflow identity, and rollback uses retained artifacts rather than rebuilding mutable source.

## Performance Considerations

BOLT11 parsing and binding happen once per challenge and are negligible beside network/wallet latency. The important performance risks are blocking SDK/HTTP behavior in the async runtime, unbounded backend response buffering, lock starvation across Python/Rust processes, and oversized fuzz/corpus workloads in required CI. Adapter tests must exercise streaming and cancellation; state tests must bound lock waits; CI may separate long fuzz/platform/canary jobs while keeping a deterministic required summary gate.

## Failure Modes Summary

| Codepath | Failure Mode | Handled In | Tested? |
| --- | --- | --- | --- |
| Platform infrastructure | missing/non-native target, stale runner, artifact/provenance transfer failure | W1-01 | Yes |
| Compatibility oracle | nondeterminism, live dependency, missing contract classification | W2-01 | Yes |
| Dependency gate | unsafe/unpinned graph, wrong Breez source/features, keyring/YAML failure | W2-02 | Yes |
| CLI/config/serialization | incompatible bytes/exit/path/env behavior, overflow, panic | W3-01 | Yes |
| Invoice/challenge | invalid signature/checksum/tags, amountless/fractional/overflow, amount/hash mismatch | W3-02 | Yes |
| Policy/state | corrupt state, permission/lock failure, mixed-process race, ambiguous reservation | W3-03 | Yes |
| Synthetic payer | unauthorized synthetic mode, synthetic input reaches real payer, fabricated validation | W4-01, W5-01 | Yes |
| LND REST | auth/TLS/stream/redirect/timeout/ambiguous result/proof mismatch | W4-02 | Yes |
| Phoenixd | absent fee enforcement, auth/redirect/malformed/ambiguous result/proof mismatch | W4-03 | Yes |
| Breez Spark | storage collision, lifecycle/fee/route/timeout/proof failure | W4-04 | Yes |
| Integrated payment | invalid input reaches wallet, secret leak, wrong reservation/submission outcome | W5-01 | Yes |
| Release preparation | incomplete install inventory, unreproducible rollback/release bytes, unsafe dry run | W6-01 | Yes |
| Ownership transfer | active handles/launchers, backup failure, PATH collision, concurrent state owner | W7-01 | Yes |
| Prerelease publication | tag/source mismatch, partial upload, signature/provenance/SBOM failure | W8-01 | Yes |
| Tap/download validation | formula/hash/Gatekeeper/canary/rollback mismatch | W9-01 | Yes |
| Promotion/observation | baseline drift, unauthorized payment, post-release anomaly, failed rollback | W10-01 | Yes |

## Architect Review Findings

### Auto-Incorporated

- Replaced the infeasible blanket testnet requirement with named LND/Phoenixd testnet canaries and a tightly bounded, operator-approved Breez Lightning Mainnet canary, matching Breez's documented network limitations.
- Split the destructive, cross-repository release unit into release preparation, local ownership transfer, prerelease publication, external tap/download validation, and promotion/observation waves with separate approvals and stop conditions.
- Moved the async payer trait, validated/synthetic input types, raw/verified results, cancellation semantics, shared verifier, and four-state submission outcome into explicit Wave 2 files with compile-contract tests.
- Made native runner provisioning a standalone prerequisite wave, mapped each target triple to its own artifact/hash/runner, and prohibited one cross-target binary or emulation-only evidence.
- Made Wave 10 Breez readiness explicitly non-paying unless a new approval and cumulative Waves 5/9/10 loss cap are recorded.
- Resolved the compatibility/redaction conflict: successful user-requested CLI/diagnostic envelopes retain `paymentHash`; removal from traces is an intentional security delta; errors/traces/upstream-body serialization remain hash-free.
- Added a runtime gate allowing synthetic input only for configured `test-mode`, with typed failures and zero-side-effect integration tests.
- Added native four-target runner provisioning and required-check aggregation as a release-blocking qualification unit.
- Added installed-client/PATH/launcher discovery, state-owner enforcement, pip/pipx/direct/Homebrew migration paths, and rollback exercises before repository removal.
- Identified Breez's canonical repository and required the ADR to freeze the exact Cargo package, workspace path, features, and vendor/checksum policy.

### Resolved with User Input

None.

### Deferred

None.

## Confidence Assessment

| Dimension | Score | Source | Notes |
| --- | --- | --- | --- |
| Architecture | 92% (High) | architect review + corrected delta review | Proof-first boundaries, shared interfaces, native infrastructure prerequisite, adapter isolation, and sequential external-state waves are explicit. |
| Error Handling | 95% (High) | architect review | Each unit names failures, stop conditions, redaction, ambiguous-submission behavior, and rollback/rescue rules. |
| Test Strategy | 93% (High) | architect review + corrected delta review | Golden/differential, compile-contract, property/fuzz, fault, mixed-process, native-runtime, canary, artifact, migration, and rollback tests are concrete. |
| Data Flow | 91% (High) | plan synthesis | Untrusted invoice through validation, policy, submission, result proof, credential/cache, and release evidence is traceable, including error exits. |
| Security | 95% (High) | architect review + plan synthesis | Invoice binding, synthetic-mode authorization, secret redaction, redirect controls, wallet isolation, supply-chain provenance, approval gates, and loss caps are fail-closed. |
| Performance / Concurrency | 87% (High) | plan synthesis | Async adapter, streaming, cancellation, lock wait, runner timeout, and CI workload risks have bounded checks; no latency target is required for this compatibility cutover. |
| Migration / Public API | 93% (High) | architect review + plan synthesis | Compatibility classifications, retained success hashes, trace delta, PATH/launcher discovery, exclusive state ownership, immutable rollback, and staged promotion are explicit. |

**Gate result:** Passed round 2. All initial critical/important findings and the three delta corrections are incorporated; all scored dimensions are High and no open questions remain.

## Orchestration Playbook

```bash
# Provision native runners first; do not continue on any stop condition.
/greenharbor-orchestrate plans/enable-validated-bolt11-decoding-via-rust-cutover.md --scope "Wave 1"

# Qualify dependencies/interfaces, then implement and approve the client.
/greenharbor-orchestrate plans/enable-validated-bolt11-decoding-via-rust-cutover.md --scope "Wave 2"
/greenharbor-orchestrate plans/enable-validated-bolt11-decoding-via-rust-cutover.md --scope "Wave 3"
/greenharbor-orchestrate plans/enable-validated-bolt11-decoding-via-rust-cutover.md --scope "Wave 4"
/greenharbor-orchestrate plans/enable-validated-bolt11-decoding-via-rust-cutover.md --scope "Wave 5"

# Waves 6-10 cross operator, host, publication, and external-repository boundaries.
# Run each scope separately and record the approval required by that wave.
/greenharbor-orchestrate plans/enable-validated-bolt11-decoding-via-rust-cutover.md --scope "Wave 6"
/greenharbor-orchestrate plans/enable-validated-bolt11-decoding-via-rust-cutover.md --scope "Wave 7"
/greenharbor-orchestrate plans/enable-validated-bolt11-decoding-via-rust-cutover.md --scope "Wave 8"
/greenharbor-orchestrate plans/enable-validated-bolt11-decoding-via-rust-cutover.md --scope "Wave 9"
/greenharbor-orchestrate plans/enable-validated-bolt11-decoding-via-rust-cutover.md --scope "Wave 10"

# Full-plan command for orchestration engines that enforce all approval gates.
/greenharbor-orchestrate plans/enable-validated-bolt11-decoding-via-rust-cutover.md
```
