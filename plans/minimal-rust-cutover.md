# Minimal Rust Cutover

**Created at:** `50e4562` on `2026-07-25` | **Mode:** `eng`

## Summary

Finish the Rust product path that already exists: first lock the real deployment target and pre-existing dirty state, then bind the pinned Breez Spark SDK to a payment-attempt contract that cannot lose confirmed-submission state, run the HTTP/challenge/policy/payment/retry flow, complete the three operational commands, and cut over only that deployment after live acceptance. Preserve the Python CLI's semantic JSON envelopes, exit codes, state paths, and cache behavior while explicitly excluding the uncommitted Wave 5 qualification work and all non-Breez distribution expansion.

This crosses more than eight files because the missing behavior spans five existing trust boundaries—configuration, wallet lifecycle, HTTP authentication, persistent spend/credential state, and the installed command. The plan adds no generalized backend framework and keeps each change inside the existing module boundary or a small command module extracted from `src/cli.rs`.

## Existing Code Leverage

- `src/invoice.rs`, `src/challenge.rs`: full BOLT11 parsing plus amount/hash binding before wallet access.
- `src/payers/base.rs`: opaque verified-payment type and the sole amount/hash/preimage verifier.
- `src/payers/breez.rs`: exclusive storage ownership, BOLT11-only prepare/send seam, prepared/final fee checks, and disconnect invariants tested with a fake SDK.
- `src/orchestrator.rs`, `src/policy.rs`: payer construction after challenge and local-policy approval; needs HTTP, daily-ledger, and protocol integration rather than replacement.
- `src/state/cache.rs`, `src/state/ledger.rs`, `src/state/keyring.rs`: Python-compatible schema-v1 cache, keyring fallback, atomic locking, and process-safe daily reservations.
- `tests/test_paygate_fixtures.py`, `tests/oracle_semantic_bridge.rs`, `compat/python_oracle/`: frozen externally visible behavior and semantic comparison machinery.
- `tests/breez_sdk_contract.rs`, `tests/breez_lifecycle_qualification.rs`, `tests/wave4_payer_adapters.rs`: pinned Spark API shape, non-paying lifecycle proof, and adapter security contracts.
- `plans/breez-spark-paygate-findings.md`: prior real 5-sat payment established `prefer_spark=false`, preimage return, and invoice-hash verification as the viable path.

## Architecture

```text
paygate CLI
   |-- config + env references ------------------------------+
   |-- credential cache / daily-spend ledger                 |
   |                                                         v
   +--> HTTP initial-or-cached request --> 402 challenge parser
                                          | Payment | optional L402
                                          v
                             invoice normalization + policy
                                          |
                                  reserve daily spend
                                          v
                            production Breez payer factory
                  connect -> ready -> prepare -> quoted-fee gate -> send
                                          |
                        classify submission -> verify hash + preimage
                                          |
                          disconnect without erasing submission state
                                          v
                      Payment/L402 Authorization -> HTTP retry
                                          |
                         commit spend + cache/evict credential

backend doctor / pay-invoice -----------> same Breez factory + verifier
credentials purge ----------------------> same cache + keyring coordinator
Python fixtures/oracle -----------------> semantic envelope/exit/state checks
```

One layer owns each lifecycle: callers perform `check_ready -> pay -> disconnect`; `BreezSparkPayer::pay` must not reconnect or disconnect internally. A structured attempt outcome distinguishes not submitted, submitted/finally failed, submitted/unknown, and confirmed payment, while a separate post-submission condition records final-fee or cleanup failure. This removes the current double-readiness/double-disconnect path and prevents a confirmed payment from being rolled back or paid again merely because a later condition failed.

## Blast Radius

| Modified File/Interface | Consumers | Covered by Work Unit? |
| --- | --- | --- |
| deployment preflight record and pre-existing dirty-path manifest | packaging, launcher cutover, every wave guard | W1-01/W3-01 |
| `Cargo.toml`, `Cargo.lock` Breez production feature | release binary, offline tests | W1-01 |
| `src/config.rs` typed Breez settings and secret references | payer factory, doctor, pay-invoice, request | W1-01 |
| `src/payers/base.rs`, `src/payers/breez.rs` attempt outcome and production SDK lifecycle | request and backend commands | W1-01 |
| `src/main.rs`, `src/cli.rs`, `src/lib.rs`, `src/commands/*` async dispatch | every public CLI command | W1-01 |
| `src/http.rs`, `src/challenge.rs`, `src/credentials.rs`, `src/orchestrator.rs` | `paygate request` | W2-01 |
| `src/trace.rs`, `src/redaction.rs`, `src/serialization.rs` | verbose/JSON traces and public envelopes | W2-01 |
| `src/policy.rs`, `src/state/ledger.rs` | payment safety and restart semantics | W2-01 |
| `src/state/cache.rs`, `src/state/keyring.rs` | cache consumption and purge | W2-02 |
| `src/diagnostics.rs`, `src/commands/backend.rs`, `src/commands/credentials.rs` | operational commands | W2-02 |
| Rust interface/fixture/oracle tests | compatibility and regression gates | W1-01 through W3-01 |
| package/cutover scripts and runbook | actual deployment only | W3-01 |
| current dirty Wave 5 workflow/keyring files | no consumer in this plan | Explicitly untouched |

## Risk Flags

`security`: yes | `performance`: no | `migration`: yes | `public-api`: yes | `concurrency`: yes

Security/public-API risk comes from constructing bearer authorization values and preserving CLI behavior. Migration risk comes from replacing the installed executable. Concurrency risk comes from wallet-directory ownership plus cache/ledger locking across restarts and multiple processes.

## Wave 1: Lock the Deployment and Executable Payment Contracts

### W1-01: Freeze the cutover baseline and implement submission-aware Breez execution

Before editing runtime code, run a read-only preflight on the actual deployment to record its OS/architecture/Rust target, current `paygate` launcher and resolved binary, service supervisor/process ownership, Python installation, wallet/cache/keyring/ledger paths, and the complete pre-existing dirty-path set from `git status --porcelain=v1 -z`. Store that redacted, mode-0600 record outside the repository and hash each dirty path by content and file type; the current baseline includes six modified paths plus untracked `compat/native-keyring-requirements.txt`. Every wave must verify those pre-existing paths are unchanged before it can close.

Replace the payer's lossy `Result<RawPaymentResult, PaymentError>` boundary with a structured attempt outcome that makes invalid state combinations unrepresentable: `NotSubmitted`, `SubmittedFailedFinal`, `SubmittedUnknown`, or `Confirmed { raw, post_submit_conditions }`. `post_submit_conditions` is an accumulating set, not a singular error, so final-fee excess and disconnect failure can coexist without losing confirmed raw proof or either safety flag. Quote rejection remains `NotSubmitted`, a provable terminal failure may release spend, ambiguity remains fail-closed, and confirmed payment always commits/reserves spend against repayment regardless of later errors.

Then make the pinned SDK part of the production Breez build and implement a concrete `BreezSparkSdk` that lazily connects with selected config, retains the opaque prepared response until send, forces BOLT11 Lightning settlement with `prefer_spark=false`, maps only redacted error classes, and returns the final amount, fee, payment hash, and preimage. Expand Rust config to retain `api_key_env`, `mnemonic_env`, `network`, expanded `storage_dir`, and bounded nonzero `completion_timeout_secs`. Preserve Python timing by validating selected-backend secret presence during config load while retaining only reference names; resolve secret values again only at wallet construction and never store them in `PaygateConfig`.

Normalize lifecycle ownership so the outer operation calls readiness once and disconnect once. Preserve the storage marker after failed disconnect, reject a second owner, and enforce the quoted fee before send. Convert the binary/dispatcher to async Tokio execution and extract request/backend/credential command modules without changing Clap grammar, JSON envelope emission, or exit behavior.

**Files:** `scripts/preflight-minimal-rust-cutover.sh` (new), `Cargo.toml`, `Cargo.lock`, `src/config.rs`, `src/payers/base.rs`, `src/payers/breez.rs`, `src/payers/mod.rs`, `src/orchestrator.rs`, `src/main.rs`, `src/cli.rs`, `src/lib.rs`, `src/commands/mod.rs` (new), `src/commands/request.rs` (new), `src/commands/backend.rs` (new), `src/commands/credentials.rs` (new), `tests/breez_sdk_contract.rs`, `tests/breez_lifecycle_qualification.rs`, `tests/wave4_payer_adapters.rs`, `tests/payment_attempt_outcomes.rs` (new), `tests/breez_production_adapter.rs` (new), `tests/wave3_cli_state.rs`, `tests/interface_contract.rs`

**Acceptance criteria:**

- The preflight record identifies one actual deployment target and launcher/supervisor mechanism before compilation; every later build/install command consumes that record rather than rediscovering or assuming a platform.
- The seven pre-existing dirty paths are content/type hashed before code edits and compare unchanged after Wave 1 and at every later wave boundary.
- A normal `cargo build --locked` for the recorded target contains the production Breez adapter; qualification-only binaries remain excluded.
- Parsed Breez config retains all five non-secret settings/references, accepts only the supported network spelling, expands storage once, validates referenced secret presence at load time, and rejects an invalid timeout before SDK/network access.
- Readiness connects exactly once, confirms wallet info/sync within the configured timeout, and every constructed SDK lifecycle ends in one awaited disconnect attempt.
- Prepare accepts only the original validated BOLT11; send consumes the exact prepared response, sets `prefer_spark=false`, and cannot run when the quoted fee exceeds the approved cap.
- Confirmed success retains amount, actual fee, payment hash, and preimage even when final fee or cleanup later fails; the common verifier remains the only path to authorization-capable proof.
- Every CLI invocation retains command/flag/default semantics, emits exactly one JSON value on stdout, uses exit `0` for success and `1` for classified runtime failure, and creates no nested runtime.

**Error handling:** Map config/connect/readiness/prepare/final-payment/timeout/cleanup failures to fixed redacted classes. Quote rejection is not submitted and rolls back. Terminal failed submission is not paid and may roll back but is never auto-retried in the same command. Unknown submission retains the daily reservation and never retries. Confirmed payment is `paid=true`; proof is verified and the purchased authorization may be used once even when accumulated final-fee/cleanup conditions make the command exit `1`. Failed disconnect retains the wallet marker. Missing/mismatched proof never authorizes, even if SDK status says paid, but remains classified as submitted/unknown unless the SDK proves a final non-payment. Internally retain all condition flags; when the one-field public envelope requires a primary error, use deterministic safety-first precedence: proof failure, spend-state persistence failure, cleanup failure, final-fee excess, credential-state failure, then authenticated-retry failure.

**Tests:** Preflight self-tests, attempt-outcome truth-table tests, SDK unit/compile contracts, the ignored non-paying live lifecycle, and CLI grammar/envelope regressions.

**Test spec:**

- Given quote rejection, terminal failed send, unknown send, confirmed success, confirmed success plus final-fee excess, confirmed success plus disconnect failure, and confirmed success with both conditions, assert the exact submission state, complete condition set, primary-error precedence, paid flag, ledger action, authorization eligibility, retry rule, exit class, and storage ownership.
- Given a quote one sat above cap, assert no SDK send and one disconnect; given a quote at cap, assert `prefer_spark=false` and the exact prepared object is consumed once.
- Given sentinel secrets through env references, assert config load fails when absent, succeeds with only references retained when present, resolves values at construction, and never emits the values through Debug/JSON/errors.
- Replay existing CLI parser cases before/after extraction and invoke from an existing Tokio runtime to prove identical public semantics and no nested-runtime panic.
- Mutate a disposable preflight fixture representing each dirty file type and assert the wave guard detects path addition/removal, content change, type change, and the untracked requirements file.

## Wave 2: Wire the Product Flow and Operational Commands

### W2-01: Run HTTP challenge, policy, payment, authorization, retry, and cache as one transaction

Implement the reqwest/envelope/trace boundary first, then complete the request orchestrator against the injected payer factory. Preserve Python behavior: try a usable scoped cached credential unless bypassed/refreshed, evict it on `401/402`, otherwise perform the initial request; accept `Payment` and, only when enabled, `L402` from repeated `WWW-Authenticate` values; bind the signed invoice amount/hash to host/service/request policy; reserve daily spend before payer construction; pay through Breez; verify proof; build the protocol-specific authorization; retry once; and update ledger/cache state.

Port `Payment` authorization encoding from the fixture/oracle contract rather than inventing a new shape; keep the existing L402 token/preimage format. Match httpx's current no-follow behavior by disabling redirects on initial, caller-authorized, cached, and paid attempts, and never copy a credential to another origin. Preserve a caller's Authorization only for the initial attempt; a scoped cached/paid credential deliberately replaces it. Treat the CLI timeout float, or 5 seconds by default, as a per-phase inactivity budget: connect/request-to-headers and each streamed response-body chunk get that budget, with no single total deadline. Buffer at most `8 * 1024 * 1024` body bytes, preserve complete Python-style JSON/text/base64 serialization within that bound, and emit `response_too_large` with `paid=false` before payment or `paid=true` after confirmed payment when exceeded.

**Files:** `src/http.rs`, `src/challenge.rs`, `src/credentials.rs`, `src/orchestrator.rs`, `src/policy.rs`, `src/state/ledger.rs`, `src/trace.rs`, `src/redaction.rs`, `src/serialization.rs`, `src/commands/request.rs`, `tests/http_boundary.rs` (new), `tests/request_flow.rs` (new), `tests/test_paygate_fixtures.py`, `tests/oracle_semantic_bridge.rs`

**Acceptance criteria:**

- Non-402 responses, `--no-pay`, unsupported/malformed/expired challenges, disallowed hosts/services, amount/hash mismatches, and budget exhaustion match the Python envelope/exit semantics without constructing a payer.
- Payment and optional L402 selection follows configured preference/fallback semantics across repeated headers.
- Daily spend is reserved after full challenge/policy validation but before wallet construction; it rolls back on proven pre-submission failure, commits once proof confirms payment even if the authenticated retry fails, and remains fail-closed/reserved when submission outcome is unknown.
- A failed reservation produces `paid=false`; rollback failure produces `paid=false` with state failure and leaves the reservation counted; commit failure after confirmed payment produces `paid=true` with state failure and leaves the reservation counted. Retained reservations naturally stop affecting the next deployment-local ledger day and are never auto-released or retried during this cutover.
- A verified Payment or L402 authorization is sent on exactly one same-origin retry; unverified/missing proof never reaches headers, cache, trace, or success output.
- Cache scope, credential fields, keyring storage, stale-credential eviction, `--refresh-credential`, `--no-cache`, and restart behavior remain schema-v1 compatible.
- Cache failures are phase-specific: `get` fails before HTTP/wallet access unless `--no-cache`; failed reject/delete prevents a fresh payment; failed `mark_success` returns the successful response with a credential-state error; failed `put` after confirmed payment still permits the one in-memory authenticated retry, returns `paid=true`/exit `1`, and leaves a non-secret confirmed-pending guard in the ledger keyed to request scope/payment hash so restart cannot repay that challenge during the current deployment-local ledger day.
- Response and error envelopes preserve Python field meaning and exit code even where JSON key order/whitespace differs.
- `--verbose` and `--trace-json` preserve their Python-visible destinations/shapes while redacting Authorization, preimage, invoice, upstream sensitive headers/body fields, and raw SDK/transport errors.

**Error handling:** Classify initial transport/phase-timeout/oversize, redirect response, unsupported challenge, policy denial, reserve/commit/rollback failure, pre-send fee rejection, final failed submission, ambiguous submission, accumulated confirmed post-submit conditions, proof failure, credential construction, cache get/put/delete/mark failure, retry transport/oversize, and paid-retry rejection separately. Confirmed proof is counted and authorized once even if accumulated conditions force `ok=false`, `paid=true`, and exit `1`; the response is retained if that retry succeeds. Aggregate all safety flags internally and apply W1-01's deterministic public-error precedence. Do not follow redirects, do not automatically retry any submitted attempt, and redact headers, proof, invoice, SDK errors, and upstream bodies from diagnostics/traces.

**Tests:** Rust fake-server integration tests plus existing fixtures/oracle semantic replay; mock only HTTP and payer boundaries.

**Test spec:**

- For Payment and enabled L402 fixtures, assert initial `402`, one policy reservation, one payer construction/send, invoice-bound proof verification, the expected Authorization scheme/value, one retry, committed spend, and compatible success envelope.
- For malformed header, amount/hash mismatch, host/service denial, or daily-budget exhaustion, assert one HTTP request, zero wallet calls, zero committed spend, and the matching public error classification.
- For pre-send fee rejection assert reservation rollback; for terminal failed submission assert no automatic second send and released budget; for ambiguous send assert no retry and retained budget; for confirmed payment plus combined final-fee/cleanup/commit failures assert counting spend, complete condition flags, primary-error precedence, verified authorization eligibility, one authenticated recovery retry, `paid=true`, and exit `1`.
- Inject reserve, rollback, and commit I/O failure, restart after each, and assert paid flag, retained counting state, cache eligibility, and no duplicate payment. Test rollover near midnight in the deployment timezone and document the fail-closed procedure as wallet-history inspection plus waiting for the next deployment-local ledger day; this cutover adds no manual reservation mutation command.
- Inject cache `get`, `put`, reject/delete, `mark_success`, and `mark_rejected` failures. Assert no wallet on read/eviction failure, in-memory retry plus confirmed-pending guard on post-payment `put` failure, successful-response retention on mark failure, restart behavior, and zero duplicate payment.
- Seed Python-compatible cache/keyring state, restart the Rust process, and assert a cache hit succeeds without wallet access; then reject that credential and assert eviction followed by at most one fresh payment flow.
- Exercise no-redirect behavior for initial/caller-Authorization/cached/paid attempts, same- and cross-origin `3xx`, default and explicit phase timeouts, a slow stream whose total duration exceeds the timeout while every chunk arrives within it, a stream with one over-timeout gap, an 8 MiB response, an 8 MiB + 1 byte response, binary serialization, repeated headers, and response/trace redaction.

### W2-02: Complete doctor, capped invoice payment, and credential purge

Implement all operational commands against the injected factory and existing state objects, allowing W2-01 and W2-02 to land independently. Breez doctor must validate selected config/secrets, exclusively acquire storage, connect/get readiness, report capabilities, and disconnect without preparing or paying. `backend pay-invoice` must parse an amount-bearing invoice, require an effective fee cap no greater than configured policy, apply request/daily amount caps, pay once through Breez, run the common proof verifier, redact the preimage field, and never retry ambiguity. Credential purge owns the only W2 cache API change: filter raw metadata by host, service, or `--all`, remove metadata and its keyring/fallback secret under one lock, and return the Python-compatible deleted count.

**Files:** `src/diagnostics.rs`, `src/commands/backend.rs`, `src/commands/credentials.rs`, `src/state/cache.rs`, `src/state/keyring.rs`, `tests/backend_commands.rs` (new), `tests/credential_purge.rs` (new)

**Acceptance criteria:**

- Breez doctor proves real config resolution, exclusive storage, connect/readiness/disconnect, and `preimageRequired`/`maxFeeLimitSupported` without invoice creation or payment.
- Pay-invoice refuses amountless/oversized invoices, zero or over-policy fee caps, unsupported backend, missing config/secrets, and an already-owned wallet before submission.
- A successful capped payment emits the established backend/payment/preimage-verification envelope, with `preimage` redacted and payment hash shown only where the Python contract intentionally exposes it.
- Confirmed payment followed by final-fee excess, cleanup failure, or ledger-commit failure emits `ok=false`, `paid=true`, the verified/redacted payment fields, and the stable post-submission/state error with exit `1`; it never becomes safe to repay.
- Purge supports host, service, their intersection, and `--all`; deletes both cache metadata and secret storage; counts only matched credentials; and works for expired/rejected entries rather than only usable cache hits.
- All command successes exit `0`; all classified failures exit `1` with the Python-compatible envelope and no Typer/Clap usage spill for runtime errors.

**Error handling:** Doctor cleanup failure is a failed doctor and retains the storage claim. Pay-invoice distinguishes not submitted, terminal failed, unknown, and confirmed outcomes exactly as W1-01 defines; ambiguity retains daily budget and never retries, while confirmed post-submit failure is reported as paid. Reserve/rollback/commit failures follow W2-01's paid/counting-state table. Purge fails closed on corrupt/unsafe state or secret-store failure and must not report deletion for entries that remain usable; partial secret deletion may be retried idempotently and never recreates a deleted credential.

**Tests:** Command-level Rust tests with fake SDK/keyring plus oracle comparisons for envelope and exit semantics.

**Test spec:**

- Assert doctor calls connect/readiness/disconnect and never prepare/send; simulate each failure and verify stable redacted JSON and exit `1`.
- With a 1-sat invoice and 1-sat effective cap, assert one prepare/send, verified proof, committed daily spend, redacted preimage, and exit `0`; with quote 2 sats assert no send and exit `1`.
- Repeat standalone payment with confirmed final-fee excess, confirmed disconnect failure, ambiguous submission, and commit failure; assert the exact `paid` flag, exit, retained counting state, proof visibility/redaction, storage marker, and zero automatic resend.
- Seed three credentials across host/service combinations and keyring/fallback records; purge each selector and `--all`, then reopen the process and assert exact counts plus absence of both metadata and secrets.

## Wave 3: Prove the Product Path and Perform the Controlled Cutover

### W3-01: Accept one deployment candidate, switch the installed command, and retire Python

Run only product-path acceptance against one immutable Rust candidate. First run the existing fixture/oracle and Rust tests. Build/package only the deployment target already frozen by W1-01 with the production Breez feature, verify doctor, then require explicit approval for one named low-value invoice whose amount and fee caps are visible before submission. Require a second explicit approval for one named protected API request, prove its authenticated retry, restart the deployed process, and prove the cached credential works (or is safely rejected/evicted according to challenge policy).

After all acceptance checks pass, confirm the current launcher/supervisor still matches the W1 preflight, create a checksummed rollback bundle containing the exact Python distribution/launcher and state backup, atomically point the installed command at the accepted Rust binary, and rerun doctor/request/restart checks from the installed path. Retain rollback through one successful deployed restart/cache validation window, for no more than 24 hours, then uninstall the Python package/runtime and remove the rollback bundle with a recorded recovery boundary. Do not modify, reset, stage, or depend on any pre-existing dirty path.

**Files:** `scripts/package-rust-paygate.sh` (new), `scripts/cutover-rust-paygate.sh` (new), `docs/minimal-rust-cutover-runbook.md` (new), `README.md`, `tests/cutover_scripts.rs` (new); actual installed launcher and rollback directory are deployment state, not repository files

**Acceptance criteria:**

- The candidate is bound to source commit, `Cargo.lock` hash, binary hash, and the single W1-recorded deployment target; the live host, launcher, supervisor, and state paths still match preflight before installation.
- Existing fixture/oracle behavior and all Rust product tests pass from a clean candidate while the listed dirty Wave 5 paths remain byte-for-byte unchanged.
- Real doctor succeeds against the configured wallet without payment.
- An explicitly approved low-value invoice is paid once within named amount/fee/daily caps, returns invoice-bound proof, and leaves no secret in logs/history artifacts.
- An explicitly approved protected request performs one initial/cached attempt, at most one payment, and one authenticated retry; its success envelope and server response are verified.
- After process/host restart, the installed Rust command reads compatible cache/keyring/ledger state and either succeeds from cache without payment or safely evicts a rejected credential without double-paying.
- The launcher switch is atomic and reversible until post-restart acceptance; after acceptance, Python is removed and `command -v paygate` plus process inspection prove the Rust binary is the only active product runtime.

**Error handling:** Any preflight drift, dirty-baseline drift, identity mismatch, fixture/oracle failure, doctor failure, cap mismatch, ambiguous payment, retry rejection, state incompatibility, launcher mismatch, or restart failure stops cutover before Python removal. The cutover script must refuse unknown launchers, active processes, missing backups, mismatched hashes, a wrong-target binary, or an unverifiable supervisor; rollback restores launcher/state without invoking a payment. Real payment and endpoint steps remain separate manual approval checkpoints and never infer approval from earlier test success.

**Tests:** Clean-room packaging/install/rollback tests in a temporary prefix, followed by the two explicitly approved live product-path checks on the deployment host.

**Test spec:**

- Package for the observed host target, install into a temporary prefix over a fake Python launcher, verify binary/hash/version/JSON behavior, roll back, and prove the original launcher/state are restored.
- Recheck W1's complete seven-path dirty baseline before and after the work unit and assert unchanged path, tracked/untracked status, file type, and content; the same guard must already have passed after Waves 1 and 2.
- Run the live doctor, approved invoice, approved protected request, installed-command restart/cache check, and no-Python-runtime inspection in the exact runbook order; capture only redacted pass/fail facts and immutable candidate identifiers.

## NOT in Scope

- LND REST and Phoenixd production adapters or qualification; unsupported selections continue to fail closed.
- Four-platform native keyring certification; only state behavior on the actual deployment platform is acceptance-critical.
- Wave 5 evidence aggregation, attestations, workflow repair, broad release qualification, or changes to `.github/workflows/rust-integration-qualification.yml`, `.github/workflows/rust-platform.yml`, `scripts/bootstrap-native-keyring.py`, `tests/keyring_qualification.rs`, `tests/platform-smoke/test_platform_qualification_scaffold.py`, `tests/platform-smoke/test_wave5_qualification_contracts.py`, or untracked `compat/native-keyring-requirements.txt`.
- Homebrew, PyPI replacement packaging, or broad binary distribution.
- Real merchant/payee Breez support, wallet backup/rotation redesign, or unattended mnemonic provisioning.
- More than one live invoice payment, more than one protected API smoke request, or automatic retry of an ambiguous submission.

## Security Considerations

- API key and mnemonic remain environment-resolved secrets; config/debug/JSON retains only reference names and non-secret settings.
- The remote challenge stays untrusted until full invoice parsing, amount/hash normalization, host/service policy, fee capability, and daily reservation all succeed.
- Preimages and authorization values are bearer secrets. They may exist only in the verifier/credential/cache boundary, must use keyring/fallback storage, and may not appear in errors, traces, command history artifacts, or retained acceptance evidence.
- Reqwest redirects are disabled for authenticated attempts, user-supplied Authorization is replaced only by the controlled credential, and no cross-origin retry is allowed.
- Payment ambiguity is never retried. Budget remains fail-closed until manual reconciliation, preventing a restart from silently paying again.
- Submission state is monotonic: cleanup, final-fee, proof, cache, ledger, or HTTP failures cannot reclassify a confirmed send as not submitted. Confirmed proof may recover the purchased response once, but every post-submit condition remains visible through `paid=true` and a failing exit where applicable.
- The cutover script validates explicit paths, hashes, launcher ownership, active processes, backups, and rollback location before any installed-runtime mutation or Python removal.

## Failure Modes Summary

| Codepath | Failure Mode | Handled In | Tested? |
| --- | --- | --- | --- |
| Config -> Breez factory | missing/invalid reference, network, path, timeout | W1-01 | yes |
| Breez lifecycle | connect/readiness/prepare/send/timeout/disconnect | W1-01 | yes |
| Attempt outcome | terminal failure, ambiguity, confirmed plus fee/cleanup failure | W1-01 | yes |
| Fee enforcement | quote above cap or final fee above cap after submission | W1-01/W2-02 | yes |
| Challenge boundary | malformed/unsupported/expired or amount/hash mismatch | W2-01 | yes |
| Policy/state | host/service/amount/daily denial, reserve/commit/rollback failure | W2-01 | yes |
| HTTP boundary | redirect, timeout, 8 MiB body limit, binary body, sensitive headers | W2-01 | yes |
| Submission | missing/mismatched proof or ambiguous outcome | W1-01/W2-01 | yes |
| Auth retry | redirect, transport error, `401/402`, second challenge | W2-01 | yes |
| Cache/purge | stale/rejected/expired entry, keyring/fallback failure | W2-01/W2-02 | yes |
| CLI compatibility | envelope or exit-code drift | W1-02/W2-01/W2-02 | yes |
| Live acceptance | real doctor/payment/request/restart failure | W3-01 | manual gate |
| Cutover | wrong target/hash/launcher, active process, rollback failure | W3-01 | yes |

## Architect Review Findings

### Auto-Incorporated

- Added a monotonic payment-attempt outcome so final-fee and disconnect failures cannot erase confirmed submission/proof; specified ledger, authorization, retry, cache, paid-flag, and exit behavior for each state.
- Preserved Python's load-time selected-secret presence validation while retaining only secret reference names in Rust configuration.
- Added `src/lib.rs`, trace, redaction, and serialization consumers plus concrete `--verbose`/`--trace-json` tests to the blast radius.
- Moved deployment-target/launcher/state discovery and the complete seven-path dirty baseline ahead of implementation; every wave rechecks it.
- Made Wave 2 units independent by leaving request flow on the existing cache API and assigning raw-entry purge changes solely to W2-02.
- Defined no-redirect behavior, Python-compatible per-phase 5-second default/CLI override inactivity timeout, an 8 MiB body limit, caller-Authorization rules, redacted response serialization, and limit/redirect/slow-stream tests.
- Defined reserve/commit/rollback failure semantics and safe restart behavior; ambiguous reservations remain counted for the current deployment-local ledger day and are inspected against wallet history rather than mutated or retried automatically.
- Delta review: made post-submit conditions cumulative with deterministic public-error precedence, specified every cache get/put/evict/mark failure, and added a confirmed-pending ledger guard to prevent repayment after credential persistence failure.

### Resolved with User Input

None.

### Deferred

None. The reviewer-requested operator reconciliation command was intentionally not added: the minimal fail-closed behavior is to retain the reservation for the current deployment-local ledger day, inspect wallet history, and never auto-retry; a broader reconciliation UX remains post-cutover work.

## Confidence Assessment

| Dimension | Score | Source | Notes |
| --- | --- | --- | --- |
| Architecture | HIGH | repository exploration + architect review | Existing validation/state seams are reused; preflight and monotonic attempt outcome close the two hidden dependency/state gaps. |
| Error Handling | MEDIUM | architect + delta review, explicit outcome/state tables | All named failure combinations now have deterministic behavior/tests; confidence becomes high only after implementation proves combined SDK/ledger/cache faults. |
| Test Strategy | MEDIUM | existing fixtures/oracle + planned fake/live gates | Deterministic coverage is strong; final confidence depends on the one real-wallet and one real-endpoint acceptance run. |
| Security | HIGH | trust-boundary review | Secret references, no redirects, proof verification, redaction, fail-closed budget, and explicit payment approvals are enforced. |
| Migration/Public API | MEDIUM | preflight + rollback design | JSON/exit/state contracts are frozen, but launcher/supervisor identity is deliberately learned from the deployment before implementation. |
| Concurrency | HIGH | existing locked state/storage + planned restart tests | Wallet ownership, ledger/cache locks, ambiguous reservations, and restart behavior are explicit. |

## Orchestration Playbook

```bash
/greenharbor-orchestrate plans/minimal-rust-cutover.md --scope "Wave 1"
/greenharbor-orchestrate plans/minimal-rust-cutover.md --scope "Wave 2"
/greenharbor-orchestrate plans/minimal-rust-cutover.md --scope "Wave 3"
/greenharbor-orchestrate plans/minimal-rust-cutover.md
```
