# Paygate Client V1 Implementation Plan

**Created at:** `no-commits` on `2026-06-10` | **Mode:** `ceo`

## Summary

Build `paygate-client` as a standalone Python CLI and library that lets agents call Paygate-protected APIs without understanding Lightning invoices, preimages, or protocol-specific retry headers. V1 centers on a safe request flow: call once, parse a `402` challenge, enforce local payment policy, pay through a configured backend that returns a preimage, retry with the correct credential, and emit a machine-readable JSON envelope.

The highest-risk product assumption is payer backend viability, so the implementation front-loads deterministic test-mode support, backend diagnostics, and LND REST before any wallet is positioned as a friendly default. LND REST is the first real-money adapter because LND's `SendPaymentV2` response exposes `payment_preimage` and lets callers set an explicit fee limit. Phoenixd remains a capability spike until it proves it can return preimages and enforce fee limits for Paygate payer mode.

## Existing Code Leverage

- `plans/initial-plan.md` - product direction, public CLI sketch, target config shape, protocol priority, backend priority, and initial test strategy.
- No application source exists yet. The first implementation wave must establish packaging, test infrastructure, and internal module boundaries before feature work.

## Dream State

```text
CURRENT STATE                 THIS PLAN                         12-MONTH IDEAL
Planning-only repository ---> Tested Python CLI/library ---> Default payment adapter for agent HTTP clients
Manual Paygate mechanics      Safe 402 payment loop             Policy-managed wallet abstraction
Backend uncertainty           test/LND/Phoenixd adapters        Multiple wallets with receipts, budgets, audit trails
```

Strong style references:

- `httpie` for predictable command ergonomics and JSON-friendly output.
- `stripe-cli` for clear config, secret handling, and actionable errors.
- `pipx`-installable Python CLIs for low-friction agent/runtime installation.

Anti-patterns to avoid:

- A custodial hosted wallet service in the client project; V1 should connect to user-controlled payer backends.
- Silent auto-spend behavior; every payment must pass explicit host/service/budget policy checks before paying.

## Architecture

```text
paygate CLI
   |
   v
RequestOrchestrator
   |-- HttpClient: initial request + authenticated retry
   |-- ChallengeParser: Payment + L402 challenge extraction
   |-- PolicyEngine: host, service, per-request, fee, and daily caps
   |-- PayerRegistry
   |     |-- TestModePayer
   |     |-- LndRestPayer
   |     `-- PhoenixdPayer
   |-- BackendDiagnostics: doctor + pay-invoice capability checks
   |-- CredentialBuilder: Payment or L402 Authorization value
   `-- EnvelopeRenderer: stable JSON output + error envelopes

External boundaries:
   - Target Paygate-protected API over HTTP(S)
   - Phoenixd HTTP API
   - LND REST API
   - Local config and env-provided secrets
```

Primary internal package layout:

- `paygate_client/cli.py` - Typer or Click command entrypoint.
- `paygate_client/config.py` - YAML config loading, env secret resolution, validation.
- `paygate_client/http.py` - HTTP request execution and response serialization.
- `paygate_client/challenges.py` - `Payment` and `L402` challenge parsing.
- `paygate_client/policy.py` - allowlists, spend caps, and budget ledger integration.
- `paygate_client/credentials.py` - Authorization credential construction.
- `paygate_client/diagnostics.py` - backend doctor and direct invoice-payment checks.
- `paygate_client/redaction.py` - shared redaction helpers for secrets, preimages, and credentials.
- `paygate_client/payers/base.py` - payer protocol and normalized payment result.
- `paygate_client/payers/test_mode.py` - deterministic local development backend.
- `paygate_client/payers/lnd_rest.py` - LND REST backend.
- `paygate_client/payers/phoenixd.py` - Phoenixd backend.
- `paygate_client/ledger.py` - local daily spend accounting.
- `tests/` - unit and integration-style tests with mocked external HTTP.

## Blast Radius

| Modified File/Interface | Consumers | Covered by Work Unit? |
| --- | --- | --- |
| `pyproject.toml` | Installers, CI, package metadata | W1-01 |
| `README.md` | Users and agents installing/running CLI | W4-01 |
| `paygate_client/cli.py` | Console script `paygate` | W1-02, W3-01, W3-02 |
| `paygate_client/config.py` | CLI, orchestrator, payer backends | W1-02, W2-02 |
| `paygate_client/http.py` | Orchestrator tests and CLI command | W3-01 |
| `paygate_client/challenges.py` | Orchestrator, policy, credential path | W2-01, W2-04 |
| `paygate_client/policy.py` | Orchestrator pre-payment gate | W2-02 |
| `paygate_client/ledger.py` | Policy daily budget checks | W2-02 |
| `paygate_client/credentials.py` | Retry Authorization builder | W2-03 |
| `paygate_client/redaction.py` | CLI errors, payer errors, debug output | W1-02, W3-01, W3-02 |
| `paygate_client/payers/base.py` | All payer adapters | W1-03 |
| `paygate_client/payers/test_mode.py` | Local test flow | W1-03, W3-01 |
| `paygate_client/diagnostics.py` | CLI users validating payer compatibility | W3-02 |
| `paygate_client/payers/lnd_rest.py` | LND/Voltage users | W3-03 |
| `paygate_client/payers/phoenixd.py` | Phoenixd users | W3-04 |
| `tests/fixtures/paygate/**` | Wire-format interop fixtures | W2-04 |
| `docs/payer-backend-compatibility.md` | Users choosing payer backends | W4-01 |
| `tests/**` | Project verification | All waves |
| `.github/workflows/ci.yml` | Maintainers, PR checks | W4-02 |

## Wave 1: Project Foundation

### W1-01: Create Python package skeleton

Establish an installable Python package with a console entrypoint, lint/type/test tooling, and predictable dependency management. Keep the package small and dependency choices conservative so later work units can focus on behavior rather than project setup.

**Files:** `pyproject.toml` (new), `paygate_client/__init__.py` (new), `tests/__init__.py` (new), `.gitignore` (new)

**Acceptance criteria:**

- `pip install -e .` exposes a `paygate` console command.
- `pytest`, formatter, linter, and type checker commands are declared in project tooling.
- Runtime dependencies include an HTTP client, YAML config parser, and CLI framework only.
- Package metadata names the distribution `paygate-client`.

**Error handling:** Installation metadata failures should surface through standard packaging errors; no custom runtime behavior is required in this unit.

**Tests:** Tooling smoke tests.

**Test spec:**

- Run the test command and confirm an empty or placeholder suite succeeds.
- Run `paygate --help` after editable install and confirm the command resolves.

### W1-02: Implement config loading, validation, and redaction policy

Add YAML config loading with env-based secret resolution for Phoenixd and LND settings, plus explicit validation for payer backend selection, protocol settings, policy caps, and allowlists. Define a shared redaction contract so later CLI, HTTP, and payer errors never expose macaroons, backend passwords, full credentials, invoices when configured as sensitive, or preimages.

**Files:** `paygate_client/config.py` (new), `paygate_client/redaction.py` (new), `tests/test_config.py` (new), `tests/test_redaction.py` (new)

**Acceptance criteria:**

- Loads the target config shape from `plans/initial-plan.md`.
- Supports `payer.backend` values `test-mode`, `phoenixd`, and `lnd-rest`.
- Resolves secrets only from named env vars and does not persist secret values.
- Rejects missing required backend fields with named validation errors.
- Applies safe defaults for optional protocol settings without widening spend policy.
- Redacts env secret values, macaroons, backend passwords, Authorization credentials, and preimages in exception strings and JSON error envelopes.

**Error handling:** Missing config file, invalid YAML, unknown backend, missing env secret, invalid cap values, and empty allowlists each produce typed config errors with actionable messages.

**Tests:** Unit tests for valid config, missing config, invalid backend, missing env var, bad policy values, and redaction of representative secret/preimage/credential values.

**Test spec:**

- Given a Phoenixd config with `password_env`, loading succeeds only when that env var exists.
- Given `max_request_sats: -1`, loading fails before any HTTP or payer code can run.
- Given an error containing `PAYGATE_CLIENT_LND_MACAROON_HEX` value or a 64-character preimage, rendered output contains a redacted marker and not the original value.

### W1-03: Define payer interface and test-mode backend

Define a normalized payer protocol that receives invoice/challenge payment input plus a required `max_fee_sats` limit and returns amount, fee, payment hash, and a lowercase 64-character preimage hex string. Implement `test-mode` as a deterministic backend for local Paygate test challenges and integration tests without real sats. The client must verify `sha256(bytes.fromhex(preimage)).hex()` against the Paygate challenge's expected `payment_hash`; if the backend also returns a payment hash, it must match the challenge hash too.

**Files:** `paygate_client/payers/base.py` (new), `paygate_client/payers/test_mode.py` (new), `paygate_client/payers/__init__.py` (new), `tests/test_payers_test_mode.py` (new)

**Acceptance criteria:**

- Payer interface accepts invoice/challenge payment inputs and returns a normalized `PaymentResult`.
- Payer interface includes `max_fee_sats`; backends that cannot enforce it before payment must fail closed before submitting an invoice.
- Preimage normalization rejects missing, malformed, non-hex, and non-32-byte values.
- Real and test backends verify the returned preimage hashes to the selected Paygate challenge's `payment_hash` before any credential is built.
- Backend-returned payment hashes are treated as supporting evidence only; the challenge `payment_hash` is the authority for credential validation.
- `test-mode` can use Paygate test challenges carrying `test_preimage` and can produce a deterministic fallback only for explicitly local synthetic tests.
- Payer failures distinguish payment rejected, backend unavailable, missing preimage, and preimage verification failure.

**Error handling:** A paid invoice without a returned preimage, or with a preimage that does not hash to the challenge `payment_hash`, is a hard failure and must never continue to credential construction.

**Tests:** Unit tests for interface normalization and test-mode success/failure behavior.

**Test spec:**

- Given uppercase preimage hex, `PaymentResult` stores lowercase hex.
- Given a backend response without preimage, the payer layer raises `MissingPreimageError`.
- Given a backend response with a preimage whose hash does not match the selected challenge, the payer layer raises `PreimageVerificationError`.
- Given `max_fee_sats` is absent or unsupported by the selected backend, real payer backends refuse payment before invoice submission.

## Wave 2: Protocol And Policy Core

### W2-01: Parse Payment and L402 challenges

Implement robust parsing for `Payment` and `L402` challenges from `402 Payment Required` responses, including the shared dataclasses consumed by policy, payer, and credential code. The parser must match Paygate's Java wire formats: repeated `WWW-Authenticate` headers, MPP `Payment id=..., realm=..., method="lightning", request="<base64url-nopad JCS JSON>", expires=..., digest=..., opaque=...`, and L402 `token`/`macaroon` plus `invoice` auth params.

**Files:** `paygate_client/challenges.py` (new), `tests/test_challenges.py` (new)

**Acceptance criteria:**

- Parses multiple `WWW-Authenticate` header values without collapsing comma-delimited auth params incorrectly.
- Parses MPP `request` as base64url-nopad JSON and extracts invoice, amount sats, payment hash, method details, service/realm, expiry, digest, description, and opaque data.
- Parses MPP `opaque` as base64url-nopad JSON when present and extracts `opaque.test_preimage`.
- Parses L402 `token`, `macaroon`, `invoice`, and `version`; treats `token` and `macaroon` as aliases only when Paygate emits identical values.
- Honors config preference for `Payment` vs `L402` when both are available.
- Rejects unsupported schemes, malformed quoted auth params, malformed base64url, invalid JSON, missing invoice, missing MPP request, missing L402 token/macaroon, and protocol-disabled cases.

**Error handling:** No supported challenge, malformed header, missing invoice, missing token/macaroon, malformed MPP request, malformed opaque payload, expired challenge, and protocol disabled produce distinct errors.

**Tests:** Unit tests with representative `Payment`, `L402`, dual-protocol repeated headers, disabled-L402, malformed auth params, malformed base64, and `opaque.test_preimage` fixtures.

**Test spec:**

- Given both `Payment` and `L402` challenges in separate `WWW-Authenticate` headers and `preferred: Payment`, parser selects `Payment`.
- Given an MPP `request` payload with `methodDetails.paymentHash`, parser exposes the payment hash used by credential tests.
- Given only `L402` and `allow_l402: false`, parser returns protocol-disabled error.

### W2-02: Add policy engine and atomic daily spend ledger

Implement local payment policy enforcement before any payer backend is invoked. The policy engine must check host allowlists, service allowlists when a service identifier is available, per-request amount caps, fee-limit support, and daily spend budget using a lock-backed local ledger.

**Files:** `paygate_client/policy.py` (new), `paygate_client/ledger.py` (new), `tests/test_policy.py` (new), `tests/test_ledger.py` (new)

**Acceptance criteria:**

- Host matching handles host plus port and rejects ambiguous or absent hosts.
- Service checks are enforced when the challenge provides a service identifier.
- Request amount caps are checked before any payer invocation.
- Fee policy is represented as `max_fee_sats` passed to payer backends; policy rejects selected backends that cannot enforce that limit before payment.
- Daily budget accounting is date-scoped and uses file locking or equivalent atomic check/reserve/commit semantics.
- Successful payments commit reserved spend; payer failure, credential failure, retry failure, or interrupted execution rolls back the reservation.
- Ledger location is configurable or uses a documented user-state default.

**Error handling:** Host denied, service denied, amount over cap, backend cannot enforce fee cap, ledger lock failure, ledger read/write failure, rollback failure, and daily budget exceeded each map to distinct policy errors.

**Tests:** Unit tests for each policy failure, successful reservation/commit, rollback on failure, and a concurrency test proving simultaneous invocations cannot exceed the daily budget.

**Test spec:**

- Given `allowed_hosts: ["localhost:8080"]`, a challenge from `localhost:8081` is rejected before payer invocation.
- Given prior spend of 490 sats and daily budget 500, a 20 sat challenge is rejected.
- Given two concurrent 20 sat requests and only 30 sats remaining, exactly one reservation succeeds.

### W2-03: Build credentials for authenticated retries

Create credential builders for `Authorization: Payment <base64url-nopad JSON>` and `Authorization: L402 <macaroon-or-token>:<preimage_hex>`. Keep protocol-specific formatting isolated so the orchestrator does not duplicate credential rules.

**Files:** `paygate_client/credentials.py` (new), `tests/test_credentials.py` (new)

**Acceptance criteria:**

- Builds MPP `Payment` credentials as base64url-nopad encoded JSON with `challenge`, optional `source`, and `payload.preimage`.
- Echoes all MPP challenge auth params needed by Paygate validation, including `id`, `realm`, `method`, `intent`, `request`, `expires`, `digest`, and optional `description`/`opaque`.
- Uses canonical compact JSON with stable key ordering for deterministic tests; encoded output has no `=` padding.
- Builds valid L402 authorization value as `L402 <macaroon-or-token>:<preimage_hex>` using the parsed Paygate macaroon/token value.
- Rejects missing token for L402 and invalid preimage for both protocols.
- Does not log or expose full credentials outside the final retry request and explicit output fields approved by the schema.

**Error handling:** Unsupported protocol, missing token, and invalid preimage raise credential errors before retrying the target API.

**Tests:** Unit tests for Payment, L402, unsupported protocol, malformed preimage cases, and golden MPP decode/round-trip fixtures.

**Test spec:**

- Given token `abc` and preimage `00...00`, builder returns `Authorization` value with exact `L402 abc:<preimage>` format.
- Given an MPP challenge fixture, builder emits `Payment <blob>` where decoding `<blob>` yields `payload.preimage` and an echoed `challenge.request` containing `methodDetails.paymentHash`.

### W2-04: Add Paygate wire-format interop fixtures

Create golden fixtures copied or generated from the current Java Paygate implementation so parser and credential tests pin the real wire protocol. These fixtures are the guardrail against accidentally implementing a plausible but incompatible client protocol.

**Files:** `tests/fixtures/paygate/mpp_challenge.json` (new), `tests/fixtures/paygate/l402_challenge.json` (new), `tests/fixtures/paygate/dual_challenge.json` (new), `tests/fixtures/paygate/mpp_credential.json` (new), `tests/test_paygate_fixtures.py` (new)

**Acceptance criteria:**

- Fixtures cover MPP-only, L402-only, and dual repeated `WWW-Authenticate` responses.
- MPP fixtures include base64url `request` with `methodDetails.paymentHash` and, for test-mode, `opaque.test_preimage`.
- L402 fixtures include `version`, `token`, `macaroon`, and `invoice`.
- Credential fixture decodes to the schema parsed by `MppCredentialParser`: `challenge`, optional `source`, and `payload.preimage`.
- Tests assert parser and credential builders pass against fixtures without network access.

**Error handling:** Fixture validation failures should identify the missing field or incompatible encoding instead of producing a generic assertion failure.

**Tests:** Golden fixture tests run as normal unit tests.

**Test spec:**

- Load `dual_challenge.json`, parse both headers, select preferred protocol, and assert no challenge fields are lost.
- Build an MPP credential from `mpp_challenge.json`, base64url-decode it, and assert exact expected JSON fields.

## Wave 3: Request Flow And Real Backends

### W3-01: Implement `paygate request` orchestration

Wire the CLI request command to the full flow: send the initial HTTP request, return a JSON envelope for non-402 responses, parse a 402 challenge, enforce policy and reserve budget atomically, pay with `max_fee_sats`, build the credential, retry, commit or roll back spend, and emit the final JSON envelope.

**Files:** `paygate_client/cli.py` (new or update), `paygate_client/http.py` (new), `paygate_client/orchestrator.py` (new), `tests/test_orchestrator.py` (new), `tests/test_cli.py` (new)

**Acceptance criteria:**

- Supports `paygate request METHOD URL` with optional headers/body/config path flags.
- Non-402 responses return `{ "ok": true, "paid": false, "response": ... }`.
- Successful paid responses include `paid`, `protocol`, `payerBackend`, `amountSats`, `feeSats`, `paymentHash`, optional `receipt`, and serialized response.
- Any pre-payment failure does not invoke the payer backend.
- Payer invocation always receives the policy-approved `max_fee_sats`.
- Payer result verification always checks `sha256(preimage) == challenge.payment_hash` before retrying.
- Budget reservations commit only after successful payment and accepted retry; payer/retry/credential failures roll back.
- Retry uses only the selected protocol's `Authorization` header.
- Non-JSON response bodies are safely represented without crashing.
- Test-mode flow consumes Paygate-style `test_preimage` from MPP opaque data or JSON 402 body and does not require real sats.
- JSON envelopes and error output redact Authorization values, macaroons, backend passwords, and full preimages.

**Error handling:** Network failure, target timeout, unsupported 402 challenge, policy denial, payer failure, missing preimage, preimage verification failure, credential failure, retry failure, and non-2xx paid retry all produce stable JSON error envelopes and non-zero CLI exit codes where appropriate.

**Tests:** Integration-style tests with mocked target API and test-mode payer, plus CLI runner tests.

**Test spec:**

- Mock target returns 402 with Payment challenge then 200 when Authorization is present; command exits 0 and emits `paid: true`.
- Mock target returns a Paygate test-mode MPP fixture with `test_preimage`; command retries with a valid MPP credential and no real payer call.
- Mock policy denial and assert payer mock was not called.
- Mock payer missing preimage and assert no retry request is sent.
- Mock payer preimage hash mismatch and assert no retry request is sent.
- Mock retry failure and assert ledger reservation is rolled back.

### W3-02: Add backend diagnostics commands

Add diagnostic commands that validate payer backend compatibility independently from the full Paygate request loop. These commands are critical because they distinguish "wallet cannot return a usable preimage" from "Paygate protocol/client flow is broken."

**Files:** `paygate_client/diagnostics.py` (new), `paygate_client/cli.py` (update), `tests/test_diagnostics.py` (new), `tests/test_cli.py` (update)

**Acceptance criteria:**

- Supports `paygate backend doctor --config ... --json`.
- Supports `paygate backend pay-invoice <bolt11> --config ... --max-fee-sats ... --json`.
- `doctor` validates config, env-secret availability, backend selection, and whether the selected backend can enforce fee limits.
- `pay-invoice` pays through the selected backend, extracts payment hash and preimage, verifies the preimage against the invoice/challenge payment hash when available, and emits a redacted JSON envelope.
- Missing preimage returns `PAYER_BACKEND_MISSING_PREIMAGE`.
- Preimage hash mismatch returns `PAYER_BACKEND_PREIMAGE_VERIFICATION_FAILED`.
- Diagnostics never print full macaroons, backend passwords, Authorization credentials, or full preimages.

**Error handling:** Invalid config, missing env secret, backend unreachable, auth failure, payment rejected, timeout, unsupported fee limit, malformed response, missing preimage, and preimage verification failure are distinct diagnostic failures.

**Tests:** CLI and unit tests with mocked payer backends.

**Test spec:**

- Given a configured test backend, `paygate backend doctor --json` exits 0 and reports preimage support.
- Given a mocked successful invoice payment, `paygate backend pay-invoice ... --json` reports `preimageVerified: true` and redacts the full preimage.
- Given a mocked successful payment with no preimage, the command exits non-zero with `PAYER_BACKEND_MISSING_PREIMAGE`.

### W3-03: Implement LND REST payer backend

Add LND REST support as the first real-money backend for LND/Voltage deployments. The backend must use env-resolved REST URL, macaroon, and optional TLS certificate settings from config.

**Files:** `paygate_client/payers/lnd_rest.py` (new), `tests/test_payers_lnd_rest.py` (new)

**Acceptance criteria:**

- Reads REST URL, macaroon hex, and TLS cert path from validated config.
- Sends payment requests to LND REST `POST /v2/router/send` and extracts preimage, payment hash, amount, and fee from the terminal successful payment update.
- Passes LND's fee-limit field derived from `max_fee_sats` and refuses payment if the field cannot be set.
- Handles LND's streaming/update semantics; intermediate updates must not be treated as a successful paid result.
- Verifies the returned `payment_preimage` hashes to the selected Paygate challenge's `payment_hash` before returning `PaymentResult`.
- Handles TLS certificate configuration explicitly.
- Does not print or persist macaroon values.

**Error handling:** Missing macaroon, invalid macaroon hex, TLS/cert error, backend unreachable, payment failure, timeout, unsupported fee limit, malformed response, missing preimage, and preimage verification failure map to distinct payer failures.

**Tests:** Unit tests with mocked LND REST responses for success, payment failure, TLS error, malformed response, missing preimage, and preimage mismatch.

**Test spec:**

- Given a mocked LND success response with `payment_preimage`, backend returns a normalized `PaymentResult`.
- Given an invalid macaroon hex value from env, config/backend initialization fails before an HTTP request is attempted.
- Given a request with `max_fee_sats: 10`, the mocked LND payment request contains the equivalent fee-limit field.
- Given an intermediate LND update without terminal success, backend does not return a paid result.
- Given a terminal successful LND update with a preimage whose hash does not match the challenge, backend raises `PreimageVerificationError`.

### W3-04: Implement Phoenixd payer backend and capability spike

Add Phoenixd backend support behind the normalized payer interface and include a documented capability check for whether the configured Phoenixd API returns payment preimages reliably. Treat missing preimage as unsupported for V1 rather than falling back silently.

**Files:** `paygate_client/payers/phoenixd.py` (new), `tests/test_payers_phoenixd.py` (new), `docs/phoenixd-spike.md` (new or `README.md` section in W4-01)

**Acceptance criteria:**

- Reads Phoenixd URL and password from validated config.
- Calls Phoenixd payment endpoint using documented authentication.
- Passes `max_fee_sats` or Phoenixd's equivalent fee-limit parameter when supported.
- Fails closed before invoice submission when the configured Phoenixd API cannot enforce the requested fee limit.
- Normalizes amount, fee, payment hash, and preimage from successful responses.
- Verifies the returned preimage hashes to the selected Paygate challenge's `payment_hash` before returning `PaymentResult`.
- Provides a command or documented procedure using `paygate backend doctor` and `paygate backend pay-invoice` to verify preimage availability against a small invoice.
- Marks Phoenixd unsupported when payment succeeds but preimage is absent.

**Error handling:** Backend unreachable, auth failure, payment rejected, timeout, unsupported fee limit, malformed response, missing preimage, and preimage verification failure are distinct payer failures.

**Tests:** Unit tests with mocked Phoenixd HTTP responses for success, auth failure, missing preimage, malformed response, timeout, and preimage mismatch.

**Test spec:**

- Given a mocked Phoenixd success response containing uppercase preimage, backend returns lowercase normalized preimage.
- Given a success response with no preimage field, backend raises `MissingPreimageError`.
- Given Phoenixd cannot enforce `max_fee_sats`, backend raises `FeeLimitUnsupportedError` before posting the invoice.
- Given a success response with a preimage whose hash does not match the challenge, backend raises `PreimageVerificationError`.

## Wave 4: Release Readiness

### W4-01: Write user-facing documentation and examples

Document installation, config, policies, protocol support, backend setup, safe test-mode usage, backend diagnostics, LND REST setup, Phoenixd spike procedure, payer backend compatibility, and JSON output schema. Keep examples copy-pasteable for agents and human developers.

**Files:** `README.md` (new), `docs/payer-backend-compatibility.md` (new), `docs/phoenixd-spike.md` (new if not created in W3-04), `examples/paygate-client.yaml` (new)

**Acceptance criteria:**

- README includes `pipx` or editable install instructions.
- README documents `paygate request GET "https://..."`.
- README documents `paygate backend doctor --json` and `paygate backend pay-invoice <bolt11> --json`.
- Example config matches implemented schema and uses env var names from `plans/initial-plan.md`.
- Example config uses `test-mode` for first local setup and `lnd-rest` for the first documented real-money backend.
- Documentation states that Phoenixd is a capability spike until `doctor` and `pay-invoice` prove preimage return and fee-limit enforcement.
- Documentation states that LNbits may be useful as a merchant/receiver backend, but is unsupported as an automated payer backend unless the configured funding source exposes payment preimages.
- `docs/payer-backend-compatibility.md` includes at least Test, LND REST/Voltage, Phoenixd, LNbits with Spark, LNbits with LND funding source, and Blink rows with `Can pay invoice`, `Returns preimage`, `Recommended for Paygate payer`, and `Notes` columns.
- Documentation warns that payment requires explicit host/service allowlists and spend caps.
- Documentation includes the exact MPP and L402 credential formats at a reference level, including the MPP base64url-nopad JSON shape.

**Error handling:** Documentation must include troubleshooting entries for missing preimage, preimage verification failure, unsupported fee limit, policy denial, missing env secret, and unsupported challenge.

**Tests:** Documentation command validation where practical.

**Test spec:**

- Run documented `paygate --help` and `paygate request --help` commands after install.
- Run documented `paygate backend --help`, `paygate backend doctor --help`, and `paygate backend pay-invoice --help` commands after install.
- Validate `examples/paygate-client.yaml` with config loader test.

### W4-02: Add CI and release quality gates

Add CI to run tests, linting, formatting checks, and type checks on pull requests. Include coverage for the critical payment loop and payer backends through mocked tests.

**Files:** `.github/workflows/ci.yml` (new), `pyproject.toml` (update), `tests/**` (update as needed)

**Acceptance criteria:**

- CI runs on pull requests and pushes to main.
- CI executes unit tests, CLI tests, lint, format check, and type check.
- CI does not require real Lightning credentials or network access to pass.
- Test suite includes mocked success and failure paths for all payer backends.

**Error handling:** CI failures should point to the failing tool; no secrets are required in CI.

**Tests:** CI workflow validation through local equivalent commands.

**Test spec:**

- Run the same commands locally that CI runs and confirm they pass without Phoenixd/LND credentials.

## NOT in Scope

- Hosted custodial Paygate wallet service - conflicts with the local payer-backend security model.
- LNbits as an automated payer backend - deferred unless the configured funding source exposes payment preimages.
- Consumer phone wallet automation - not suitable for unattended agent payment loops.
- Breez SDK implementation - research candidate after Phoenixd viability is known.
- Real-sats CI tests - too flaky and risky for default verification.
- Browser or SDK integrations beyond the Python CLI/library boundary.

## Failure Modes Summary

| Codepath | Failure Mode | Handled In | Tested? |
| --- | --- | --- | --- |
| Config load | Missing config, invalid YAML, missing env secret | W1-02 | Yes |
| Payer result normalization | Missing, malformed, or challenge-mismatched preimage | W1-03, W3-01, W3-03, W3-04 | Yes |
| Challenge parsing | Missing or unsupported 402 challenge, malformed MPP request | W2-01, W3-01 | Yes |
| Policy gate | Host/service denied, caps exceeded, unsupported fee-limit, ledger unavailable | W2-02 | Yes |
| Credential build | Missing L402 token, invalid preimage | W2-03 | Yes |
| Interop fixtures | Paygate wire-format drift | W2-04 | Yes |
| Initial request | Network failure, timeout | W3-01 | Yes |
| Backend diagnostics | Backend cannot prove fee-limit support or preimage return | W3-02 | Yes |
| Payment | Backend auth failure, rejection, timeout, unsupported fee-limit, malformed response | W3-03, W3-04 | Yes |
| Retry request | Non-2xx response, network failure | W3-01 | Yes |
| CLI output | Non-JSON response body, structured redacted error envelope | W1-02, W3-01 | Yes |
| CI/release | Missing credentials must not break tests | W4-02 | Yes |

## Architect Review Findings

### Auto-Incorporated

- F1 CRITICAL: MPP `Payment` credentials are now specified as base64url-nopad JSON with echoed challenge fields and `payload.preimage`, plus golden decode tests in W2-03/W2-04.
- F2 IMPORTANT: Challenge parsing now explicitly covers repeated `WWW-Authenticate` headers, MPP `request` and `opaque`, L402 `token`/`macaroon`/`invoice`, quoted params, malformed base64, expiry, digest, and protocol-disabled cases.
- F3 CRITICAL: `max_fee_sats` is now part of the payer interface and backend calls must pass an enforceable fee-limit or fail closed before invoice submission.
- F4 IMPORTANT: Test-mode now consumes Paygate `opaque.test_preimage` or response-body `test_preimage`, with fixture-backed orchestration tests.
- F5 IMPORTANT: Daily budget tracking now requires atomic reservation/commit/rollback semantics with a concurrency test.
- F6 MINOR: Corrected stale blast-radius references.
- M1-M5: Added W2-04 interop fixtures and folded fee-limit enforcement, atomic ledger budgeting, test-mode challenge support, and secret/credential redaction into existing implementation units.

### Resolved with User Input

- None.

### Deferred

- None.

## Confidence Assessment

| Dimension | Score | Source | Notes |
| --- | --- | --- | --- |
| Architecture | Medium | Architect review + revised plan | Boundaries are clear and Paygate interop is pinned; backend API details still need implementation-time verification. |
| Error Handling | Medium | Architect review + revised work-unit criteria | Named failures now cover fee-limit enforcement, atomic ledger rollback, parser failures, payer failures, and redaction. |
| Test Strategy | Medium | Architect review + W2-04 fixtures | Mocked coverage plus golden fixtures are strong; real Phoenixd validation remains a documented manual spike. |
| Data Flow | Medium | Architecture and W3 orchestration | Happy path, test-mode path, reservation/rollback path, and credential transformation are specified. |
| Security | Medium | Architect review + revised plan | Spend policy, fee-limit fail-closed behavior, env secrets, preimage handling, and redaction are explicit. |

## Orchestration Playbook

```bash
# Wave 1: Project Foundation
/orchestrate plans/paygate-client-v1.md --scope "Wave 1"

# Wave 2: Protocol And Policy Core
/orchestrate plans/paygate-client-v1.md --scope "Wave 2"

# Wave 3: Request Flow And Real Backends
/orchestrate plans/paygate-client-v1.md --scope "Wave 3"

# Wave 4: Release Readiness
/orchestrate plans/paygate-client-v1.md --scope "Wave 4"

# Full plan
/orchestrate plans/paygate-client-v1.md
```
