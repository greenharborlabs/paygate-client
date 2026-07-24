# Rust dependency qualification report

Date: 2026-07-19  
Scope: Wave 2 / W2-02  
Toolchain: Rust 1.88.0 (`rustc 1.88.0`, `cargo 1.88.0`)

## Current result

The crate skeleton, shared payer contracts, exact dependency selections, and
resolved 601-package graph are ready for native qualification. Local evidence is
green for the tests that do not require platform services. The release decision
remains contingent on `.github/workflows/rust-qualification.yml` passing on all
four native targets; this report does not fabricate that remote evidence.

| Check | Local result | Required native evidence |
| --- | --- | --- |
| Interface compile contract | PASS (2 tests) | Repeated on every target |
| BOLT11 signed amount vector | PASS; valid decode plus independent bad-checksum and rechecksummed invalid-recovery-signature rejection | Repeated on every target |
| Exact pins/git allowlist | PASS; Spark tag object and commit independently matched canonical remote | CI repeats lock/source comparison |
| Safe YAML boundary | Parser-backed rejection matrix implemented locally; native rerun pending | Every target repeats the rejection and source-policy tests |
| File fallback interop | Rust first-use record creation→Python read/delete and Python creation→Rust read/delete pass independently; Rust deletion is visible as Python absence, duplicates fail every operation, unrelated records survive, and mode remains 0600 | Repeated on all targets |
| OS keyring interop | Not claimed locally | Every target runs independent Python→Rust, Rust→Python, and default-only legacy probes |
| Breez full graph compile | BLOCKED locally by missing `protoc`, recorded rather than bypassed | Ephemeral native builders install `protoc` and compile the locked graph offline |
| Breez lifecycle | Compile/source policy checked locally; live service evidence pending | Every target runs connect/readiness/create-invoice/prepare-only/disconnect with OS-random per-process isolation and no send capability |
| Linux ABI/linkage | Not available on this macOS host | x86_64/aarch64 bullseye native runners require glibc 2.31 and inspect `ldd`/`readelf` |
| Linkage parser | Local permitted/injected fixtures pass | Native helper checks release CLI and Breez qualification executable against exact per-OS allowlists, architecture and floor |
| Advisories/licenses | Full current Cargo metadata passes the fail-closed SPDX parser and its injected rejection tests; local cargo-audit unavailable | CI installs pinned cargo-audit 0.21.2, denies warnings, then invokes the same SPDX/missing-metadata classifier |

## Frozen module contract

`ValidatedBolt11` is owned by `invoice.rs`, has private fields, and retains the exact string, exact
millisatoshi amount, checked whole-satoshi amount, and 32-byte signed payment
hash. Construction is module-private beside the future Wave 3 decoder, while
`payers::base::ValidatedBolt11` remains a public re-export preserving the frozen path.
`SyntheticPaymentChallenge` is a different type and cannot satisfy `RealPayer`.

`RealPayer` is object-safe and asynchronous. It exposes readiness, payment of a
borrowed `ValidatedBolt11` with an explicit fee cap and cancellation semantics,
and disconnect. Backend output remains `RawPaymentResult` until the common
verifier binds amount, hash, and SHA-256 preimage into `VerifiedPaymentResult`.
Ledger-visible outcomes are exactly `NotSubmitted`, `SubmittedUnknown`,
`Succeeded`, and `FailedFinal`.

Adapter module exports and registry inputs are present, but every adapter stub
returns `NotImplemented`; no stub claims a functional payment path.

## Reproduction

```text
cargo +1.88.0 test --locked --test interface_contract
cargo +1.88.0 test --locked --test dependency_qualification
cargo +1.88.0 test --locked --test keyring_qualification
cargo +1.88.0 test --locked --features breez-qualification --test breez_lifecycle_qualification --no-run
python3 scripts/check-rust-linkage.py --self-test
python3 scripts/check-rust-licenses.py --self-test
python3 scripts/check-rust-licenses.py /tmp/paygate-metadata.json
```

The Breez and target-floor commands intentionally live in the native workflow.
An always-running final gate fails unless policy and every native matrix leg succeeds.
Live four-target evidence remains pending until that workflow runs; workflow source
and local results are not represented as native proof.

## Wave 5 candidate acceptance

No Wave 5 candidate has been accepted. This document is an evidence index only;
it is not an acceptance record and does not change the blocked cutover status.

When all qualification work has actually completed, reviewers must index the
single accepted `wave5-candidate-manifest.json` here with its SHA-256 and the
exact GitHub Actions URLs/run IDs for all seven evidence records:

| Evidence class | Required run | Current evidence |
| --- | --- | --- |
| Local structural contract tests | local command output | PASS only for offline structure; not native, integration, or payment proof |
| Integration semantic bundle | `rust-integration-qualification.yml` run ID | Pending |
| Native aggregate | `rust-platform.yml` run ID, all four targets | Pending |
| LND protected canary | `rust-payment-canary.yml` LND run ID | Pending; requires explicit protected-environment approval |
| Breez protected canary | `rust-payment-canary.yml` Breez run ID | Pending; requires separate explicit protected-environment approval |
| Candidate acceptance | `rust-wave5-acceptance.yml` run ID and manifest SHA-256 | Pending |

The acceptance workflow takes these IDs explicitly, re-downloads historical
redacted artifacts with read-only permissions, validates source/lock identity,
digests, schema, target/backend/runner identity, attestation or canary
signature, and emits the manifest digest. A failed, skipped, expired, missing,
ambiguous, or unverifiable record remains a rejection; it must never be written
as PASS in this report.

Post-acceptance publication must follow
[`docs/wave5-evidence-publication.md`](../docs/wave5-evidence-publication.md).
The cutover checkpoint remains blocked until the real integration, four-target
native, LND canary, and Breez canary runs succeed; candidate acceptance and both
independent reviews complete; explicit docs-only commit approval is recorded;
and the exact published report passes the report verifier. The immutable
acceptance artifact remains authoritative; this source-controlled report is
only a publication copy.
