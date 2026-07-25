# Simplified Rust Cutover

**Created:** 2026-07-19  
**Status:** authoritative  
**Supersedes:** the original Rust cutover plan, its Wave 2 corrective plan, and
the earlier Python BOLT11-binding implementation plan

## Summary

Replace the Python `paygate-client` runtime with a Rust `paygate` CLI whose real
payment path accepts only fully validated, amount-bearing BOLT11 invoices. Keep
the security boundary, supported user behavior, state compatibility, LND REST,
and Breez Spark while reducing the cutover from ten waves to six.

The Rust architecture remains valid. The earlier plans became blocked because
release certification was pulled into the interface/dependency-freeze stage.
Four native targets, live keyrings, Breez lifecycle, linkage floors, offline
artifacts, and immutable evidence are integration/release proofs, not
prerequisites for implementing the Rust core.

The known Wave 2 blockers are classified as follows:

- The Docker oracle replay succeeds deterministically. The reported failure was
  caused by losing the running process handle and inspecting its redirected
  output before completion.
- The `runpy` message is a benign eager-import warning. Remove the eager import
  so a successful replay has clean diagnostics.
- Missing `protoc` is a native Breez build prerequisite, not a development-gate
  product failure.
- `cargo vendor` is unsuitable for this locked graph because Cargo 1.88 cannot
  flatten identically named/versioned packages from separate Git sources into
  one vendor directory.
- Full-wave resets and fixed reviewer-cycle exhaustion are process failures;
  they must not erase valid, input-bound evidence.

## Public Interfaces and Compatibility

- Continue shipping the executable as `paygate` with the existing public
  commands, flags, configuration keys and precedence, machine-readable JSON
  fields and error codes, state schemas and paths, permissions, locking
  behavior, and keyring identifiers.
- Preserve behavioral compatibility. Exact JSON whitespace/key order,
  human-readable wording, internal scripts, traces, and non-public diagnostics
  are not compatibility gates.
- Retire the Python import API without PyO3, FFI, a decoder subprocess, or a
  hybrid Python/Rust production runtime.
- A real payment accepts only an immutable `ValidatedBolt11` constructed by
  full `lightning-invoice` parsing and retaining the exact invoice, signed
  amount, checked whole-satoshi amount, and signed payment hash.
- `VerifiedPaymentResult` remains opaque and constructible only through the
  common verifier after amount, hash, preimage, and submission-outcome checks.
- Synthetic payment input is accepted only by configured test mode and cannot
  reach a real payer.
- Rust 0.2.0 supports LND REST and Breez Spark. Phoenixd configuration fails
  closed with a stable unsupported-backend result before network access and is
  deferred to a follow-up capability project.
- Release targets remain Linux x86_64/ARM64 and macOS Intel/Apple Silicon.

## Wave 1: Platform Infrastructure — Complete

Retain the accepted four-runner provisioning, target-floor documentation,
artifact-transfer checks, and platform evidence scaffold. Platform availability
is no longer a dependency barrier for local Rust implementation; these assets
are consumed by Wave 5.

**Acceptance:** Treat the already-resolved W1-01 checkpoint as complete. Do not
repeat runner provisioning unless a runner definition or supported target
changes.

## Wave 2: Development Readiness

Close a small, deterministic gate before implementing production behavior.

### W2-01: Freeze and replay the Python oracle

- Keep the existing 37-case frozen oracle; do not expand it with Rust-only
  behavior.
- Remove the eager package import that produces the `runpy` warning without
  changing the oracle API or golden evidence.
- Run the one documented Docker replay command to completion. That command
  already performs two controlled oracle runs internally, so do not wrap it in
  additional duplicate replays.
- Require zero live network/keyring access, 227 passing frozen tests, identical
  internal runs, and the checked-in golden hash.

### W2-02: Freeze Rust interfaces and dependency policy

- Retain Rust 1.88.0, the committed `Cargo.lock`, exact direct dependency pins,
  the approved Git revisions, and the dependency ADR.
- Retain private `VerifiedPaymentResult` fields, read-only accessors, the sole
  verifier construction path, and compile-fail forgery coverage.
- Retain exact `(package, version, source)` missing-license exceptions and their
  fail-closed mutation tests.
- Keep Breez lifecycle, native-keyring, and linkage prototypes as later
  qualification assets; they are not local Wave 2 blockers.
- Remove the premature full-native evidence aggregator/action and its dedicated
  evidence tests. Recreate that gate in Wave 5 against the integrated client.
- Make the Rust pull-request workflow run only the balanced development gate,
  not four 90-minute native jobs.

**Wave 2 gate:**

```sh
cargo +1.88.0 fmt --check
CARGO_NET_OFFLINE=true cargo +1.88.0 test --locked --offline \
  --test interface_contract \
  --test dependency_qualification \
  --test keyring_qualification
CARGO_NET_OFFLINE=true cargo +1.88.0 metadata --locked --offline \
  --all-features --format-version 1 > /tmp/paygate-wave2-metadata.json
python3 scripts/check-rust-licenses.py --self-test
python3 scripts/check-rust-licenses.py /tmp/paygate-wave2-metadata.json
git diff --check
```

The OS-native keyring test remains intentionally ignored in this gate. Close
Wave 2 after the canonical oracle replay and this complete command set pass once
for the intended source and lockfile.

## Wave 3: Rust Core and Persistent State

Implement two coherent work units against the frozen Wave 2 interfaces.

### W3-01: Validated payment domain

- Implement validated invoice parsing, challenge normalization, policy binding,
  credential construction, raw-result verification, and typed/redacted errors.
- Reject malformed, invalid-signature, amountless, fractional-satoshi,
  overflowing, amount-mismatched, or hash-mismatched invoices before policy
  reservation, payer construction, wallet access, or network access.
- Implement explicit `BeforeSubmission` and `AfterSubmissionUnknown`
  cancellation semantics as Rust security behavior, not Python oracle claims.

### W3-02: CLI, configuration, and state

- Implement the CLI, safe YAML subset, environment precedence, serialization,
  cache, ledger, permissions, locking, and keyring fallback.
- Preserve machine-readable field semantics and state compatibility while
  allowing documented formatting and human-message improvements.
- Prove Python-to-Rust state readability, corruption handling, atomic writes,
  concurrency limits, and exclusive state ownership.

**Acceptance:** Unit, property, compile-contract, state fault-injection, and
behavioral oracle comparisons pass without a real payer or payment.

## Wave 4: Supported Payer Adapters

Implement adapters independently using injected SDK/HTTP seams and isolated
storage.

- **Test mode:** deterministic synthetic payments only; real invoices cannot use
  synthetic proof material.
- **LND REST:** fee-bound streaming payment with disabled credential-bearing
  redirects, terminal-result handling, and invoice-bound proof verification.
- **Breez Spark:** isolated storage, readiness/prepare/send/disconnect ordering,
  BOLT11-only routes, prepared-fee enforcement, and verified results using the
  locked SDK revision.
- **Phoenixd:** retain only a fail-closed unsupported path with zero submission
  capability.

**Acceptance:** Fake-server/SDK success, fee rejection, timeout, malformed
response, cancellation, ambiguous submission, proof mismatch, cleanup, and
duplicate-storage-ownership tests pass. Live services are not required per work
unit.

## Wave 5: Integration and Native Qualification

Integrate the CLI, orchestrator, state, and reviewed adapters, then perform the
expensive qualification once per integration candidate.

- Replay the Python oracle as semantic JSON/state/exit behavior, not byte-level
  formatting, and approve every intentional difference.
- Run formatting, Clippy with warnings denied, unit/integration/doc tests,
  dependency/license/advisory policy, fuzz smoke, state concurrency tests, and
  redaction checks.
- Run native keyring interoperability, non-paying Breez lifecycle, linkage and
  runtime-floor checks, and CLI smoke on all four release targets.
- Reintroduce immutable four-target evidence bound to source commit,
  `Cargo.lock`, target, runner, binary hash, and workflow run.
- Do not use `cargo vendor`. Prime a fresh isolated `CARGO_HOME` from
  `Cargo.lock` during a network-enabled preparation step, then build with
  `--locked --offline`; Linux additionally runs the build container with
  networking disabled.
- Run only the bounded Breez Mainnet canary after explicit approval. LND canary
  qualification is excluded because the Voltage payer is no longer available
  and LNBits cannot serve as the payer. Preserve the existing fee/spend cap and
  never retry an ambiguous attempt.

**Acceptance:** One source/lock identity passes every required local and native
gate, all four evidence records aggregate successfully, and the approved Breez
canary returns invoice-bound proof without redaction or state anomalies.

## Wave 6: Migration and GitHub Release

- Build reproducible, checksummed, signed archives for all four targets plus
  SBOMs/provenance and a retained, install-tested Python rollback wheel.
- Discover existing installations and launchers, quiesce active clients, back
  up state, and rehearse exclusive ownership, migration, rollback, and forward
  recovery before removing the Python runtime.
- Publish a GitHub prerelease from the accepted commit, download and verify the
  public bytes, run installation/state/backend smoke, and promote the same
  immutable artifacts after explicit approval.
- Defer Homebrew formula work, Phoenixd support, and a separate 24-hour
  orchestration wave to follow-up plans.

**Acceptance:** Source/tag/artifact identities match, all downloaded artifacts
verify and install on their targets, rollback uses retained immutable bytes, and
promotion changes no artifact content.

## Failure and Review Policy

- A product, security, or behavioral-compatibility assertion failure blocks the
  affected stage and invalidates evidence that depends on it.
- A harness, invocation, runner, or missing-tool failure preserves unrelated
  passing evidence. Fix the prerequisite and rerun the affected gate.
- A source, `Cargo.lock`, oracle fixture, or gate-logic change invalidates only
  evidence derived from that input.
- Run one complete gate before closing Wave 2, accepting the Wave 5 integration
  candidate, and publishing the Wave 6 release candidate.
- Do not impose fixed coder/reviewer-cycle exhaustion. If the same unexplained
  failure recurs twice, stop that work unit for focused root-cause investigation
  rather than resetting the entire wave.
- Use one implementation review per work unit, one security-focused review for
  invoice/payment proof boundaries, and one final integration/release review.

## Global Security and Test Invariants

- No invalid or mismatched invoice can reserve policy budget or reach a wallet.
- No raw backend result can be forged into a verified payment result.
- No mismatched amount, payment hash, or preimage can produce success,
  credentials, cache entries, or committed state.
- Errors, traces, panics, and upstream bodies never expose credentials,
  macaroons, invoices, payment hashes, or preimages except fields intentionally
  retained in successful public response contracts.
- Cache and ledger operations remain atomic, mode-restricted, corruption-aware,
  and safe across processes.
- No commit, push, release, host cutover, or real payment occurs without the
  corresponding explicit approval.

## Execution

Run only one wave at a time from this file:

```text
/greenharbor-orchestrate plans/rust-cutover.md --scope "Wave 2"
/greenharbor-orchestrate plans/rust-cutover.md --scope "Wave 3"
/greenharbor-orchestrate plans/rust-cutover.md --scope "Wave 4"
/greenharbor-orchestrate plans/rust-cutover.md --scope "Wave 5"
/greenharbor-orchestrate plans/rust-cutover.md --scope "Wave 6"
```
