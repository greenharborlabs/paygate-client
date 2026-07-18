# Full Project Security Review: 12 issues (5 critical, 7 informational) across 5 sections

Reviewed sections: protocol/invoice parsing; policy/orchestration; payer backends and transport; credential/state handling; packaging and release automation.

## DESIGN - needs `/greenharbor-plan-work`

### CRITICAL

- **D1.** [`paygate_client/orchestrator.py:362`] **CRITICAL - The paid BOLT11 invoice is not bound to the policy-approved MPP amount or payment hash before submission.** The Payment path trusts `amount_sats` and `payment_hash` from the challenge payload, but submits the separate `invoice`; `verify_payment_result()` only checks the returned preimage after the wallet may have paid and never checks the returned amount against the challenge. The home-grown invoice helpers also omit checksum/signature validation, and `backend_pay_invoice()` labels an unparseable real invoice `local_synthetic`, bypassing the authoritative-hash guard. A valid high-value invoice paired with a low declared amount can bypass per-request and daily policy before the mismatch is detected.
  Why design needed: Introduce one validated BOLT11 decoding/binding boundary used by Payment, L402, diagnostics, and every payer before submission; define amountless-invoice semantics and reject any amount/hash disagreement pre-payment.
  Files: `paygate_client/invoices.py`, `paygate_client/orchestrator.py`, `paygate_client/payers/base.py`, `paygate_client/diagnostics.py`, associated tests and docs

- **D2.** [`paygate_client/orchestrator.py:252`] **CRITICAL - Ambiguous post-submission failures roll back budget and report `paid: false`.** Timeouts, missing preimages, malformed backend responses, and verification failures can occur after a wallet accepted or settled payment, yet lines 327-338 roll back the reservation because `real_payment_committed` is set only after `_pay()` returns. This releases budget for more spending and can exceed the configured daily cap.
  Why design needed: Model `reserved -> submitted -> confirmed/uncertain` states, keep submitted/uncertain amounts counted against budget, and make backends distinguish provably pre-submit failures from ambiguous post-submit failures.
  Files: `paygate_client/orchestrator.py`, `paygate_client/ledger.py`, `paygate_client/payers/base.py`, all real payer backends, associated tests and envelope docs

- **D3.** [`paygate_client/policy.py:94`] **HIGH - Missing service identifiers bypass `allowed_services`, and all L402 payments are unscoped.** Policy rejects only a present, disallowed service; `None` passes by design in `tests/test_policy.py:97`. The L402 conversion always sets `service=None` at `paygate_client/orchestrator.py:399`, so enabling L402 bypasses the documented service allowlist for every payment.
  Why design needed: Define protocol-specific service identity and an explicit default-deny policy for unscoped challenges, including whether L402 `realm` may be trusted or whether users must opt into unscoped L402.
  Files: `paygate_client/challenges.py`, `paygate_client/config.py`, `paygate_client/orchestrator.py`, `paygate_client/policy.py`, associated tests and docs

- **D4.** [`paygate_client/config.py:234`] **HIGH - Secret-bearing network paths accept plaintext HTTP for non-loopback hosts.** Target retries can send bearer-style Payment/L402 credentials over `http://`, while LND REST sends its macaroon and Phoenixd sends Basic-auth wallet credentials to URLs that receive no scheme/loopback validation. An on-path attacker can steal API credentials or wallet-admin secrets.
  Why design needed: Centralize URL trust policy: require HTTPS for non-loopback targets and payer endpoints, permit loopback HTTP deliberately, and define any explicit unsafe-development override.
  Files: `paygate_client/config.py`, `paygate_client/http.py`, `paygate_client/orchestrator.py`, `paygate_client/payers/lnd_rest.py`, `paygate_client/payers/phoenixd.py`, associated tests and docs

- **D5.** [`paygate_client/payers/phoenixd.py:50`] **HIGH - Phoenixd fee-limit capability is asserted by an arbitrary configured parameter name.** Any non-null `fee_limit_parameter` sets `supports_max_fee_limit=True`; the client then submits payment assuming Phoenixd enforces the form field. The repository documentation states upstream Phoenixd does not document such a cap, so a typo or ignored field can produce an uncapped payment despite local policy.
  Why design needed: Remove Phoenixd from automated real-money selection until a known API/version proves pre-submit fee enforcement, or introduce a capability handshake/versioned adapter rather than trusting an operator-supplied string.
  Files: `paygate_client/config.py`, `paygate_client/orchestrator.py`, `paygate_client/payers/phoenixd.py`, diagnostics, tests and compatibility docs

### INFORMATIONAL

- **D6.** [`paygate_client/session_cache.py:136`] **MEDIUM - Credential use limits are not atomic across processes.** `FileCredentialCache` inherits an unlocked in-memory `get()`, sends the credential, then separately locks and increments `use_count`; two processes can both acquire and send a `max_uses=1` credential before either marks success. This defeats `single-use` and `max-requests` policy.
  Why design needed: Replace `get` plus `mark_success` with an atomic lease/consume API under the file lock, including failure/rejection release semantics.
  Files: `paygate_client/session_cache.py`, `paygate_client/orchestrator.py`, associated concurrency tests and docs

## IMPL - ready for `/greenharbor-orchestrate`

### CRITICAL

No surgical critical findings. The release-blocking findings require explicit security semantics and cross-cutting design.

### INFORMATIONAL

- **I1.** [`paygate_client/http.py:50`] **MEDIUM - Serialized responses expose `Set-Cookie` and common session-secret fields.** `serialize_response()` emits all response headers/body and the denylist does not cover `set-cookie`, `cookie`, `session_id`, or `private_key`; a reproduced response preserved each secret verbatim in the CLI JSON envelope. This is risky for agent logs and captured stdout.
  Fix: Apply header-aware redaction for `Set-Cookie`/`Cookie` and extend conservative structured-key handling for session/private credential fields, with regression tests that preserve non-secret response data.
  Files: `paygate_client/http.py`, `paygate_client/redaction.py`, `tests/test_redaction.py`

- **I2.** [`paygate_client/orchestrator.py:521`] **MEDIUM - Unknown cache-policy strings fail open to expiry-based reuse.** The CLI accepts an unrestricted string; any typo falls through the `else` branch and may cache a credential until expiry rather than rejecting invalid policy input.
  Fix: Parse `--cache-policy` as an enum/Literal and raise before any request or payment unless the value is exactly one of the documented policies.
  Files: `paygate_client/cli.py`, `paygate_client/orchestrator.py`, `tests/test_cli.py`, `tests/test_orchestrator.py`

- **I3.** [`paygate_client/session_cache.py:240`] **MEDIUM - Cache read/corruption errors silently become cache misses and can trigger an unnecessary new payment.** Any `OSError` or JSON decoding error returns an empty cache, losing the paid-session credential without warning.
  Fix: Treat malformed/unreadable existing cache state as a typed fail-closed error; only a genuinely absent cache file should mean empty.
  Files: `paygate_client/session_cache.py`, `paygate_client/orchestrator.py`, `paygate_client/cli.py`, associated tests

- **I4.** [`paygate_client/payers/breez.py:99`] **MEDIUM - Breez wallet storage is created with ambient umask permissions.** The configured wallet state directory may become `0755` under a common `022` umask, exposing wallet metadata and relying on every SDK-created child file to secure itself.
  Fix: Create and verify the wallet storage directory as owner-only (`0700`), reject unsafe existing ownership/type, and document the requirement.
  Files: `paygate_client/payers/breez.py`, `tests/test_payers_breez.py`, `README.md`

- **I5.** [`pyproject.toml:61`] **MEDIUM - The dev constraint forces a pytest version affected by CVE-2025-71176.** `pytest>=8.2,<9` resolved to 8.4.2; `pip-audit` reports GHSA-6w46-j5rx-g56g (local tmpdir handling, fixed in 9.0.3). This is not a runtime dependency, but it affects local/CI test environments on Unix.
  Fix: Move to `pytest>=9.0.3,<10`, run the full Python 3.10-3.14 matrix, and add dependency auditing to CI so future vulnerable tool resolutions fail automatically.
  Files: `pyproject.toml`, `tests/test_package_metadata.py`, `.github/workflows/ci.yml`

- **I6.** [`scripts/check-dist.sh:13`] **LOW - The release validation script is not runnable on the project's supported macOS development platform.** It uses Bash `mapfile`, unavailable in macOS's bundled Bash 3.2; the artifact build succeeded locally but this final script stopped before Twine/install validation. CI is Ubuntu and is not affected.
  Fix: Replace `mapfile` with a Bash 3-compatible collection loop or explicitly require/install modern Bash in release documentation.
  Files: `scripts/check-dist.sh`, `tests/test_package_metadata.py`, `docs/releasing.md`

## Summary

| Category | Critical | Informational | Total |
|---|---:|---:|---:|
| DESIGN | 5 | 1 | 6 |
| IMPL | 0 | 6 | 6 |
| Total | 5 | 7 | 12 |

## Verification

- `pytest`: 227 passed on Python 3.14.5.
- Ruff lint and format: passed.
- Strict MyPy: passed for 20 source files.
- `compileall`: passed.
- Actionlint: passed for both workflows.
- Bandit: no medium/high findings; three low findings were one redaction sentinel false positive and two broad keyring exception handlers.
- `pip-audit`: runtime dependencies clean; one dev-only pytest advisory as I5.
- Secret scan: no private keys, PyPI/GitHub tokens, or matching production credentials found in tracked history sampled across all commits.
- Wheel/sdist: both built; archive contents contained expected package/docs/tests and no plans, local environments, credentials, or generated secrets. The final `check-dist.sh` stage hit I6 locally.
- PyPI preflight: `paygate-client` currently returns 404 from the official JSON endpoint, consistent with a first release.

## Release Recommendation

Do not publish a real-money-capable release until D1-D5 are fixed and regression-tested. I1-I5 should also be closed before publication; I6 may be fixed with the same release-polish work because macOS is a declared supported platform.

## Action Playbook

1. Design Wave 1: `/greenharbor-plan-work "Bind validated BOLT11 amount and payment hash to every policy-approved payment before wallet submission" --review reports/greenharbor-code-review-full-2026-07-17.md`
2. Design Wave 2: `/greenharbor-plan-work "Model submitted and uncertain payments so daily budget never rolls back ambiguous spend" --review reports/greenharbor-code-review-full-2026-07-17.md`
3. Design Wave 3: `/greenharbor-plan-work "Define fail-closed service identity semantics for Payment and L402" --review reports/greenharbor-code-review-full-2026-07-17.md`
4. Design Wave 4: `/greenharbor-plan-work "Enforce secure transports for target credentials and payer-admin secrets" --review reports/greenharbor-code-review-full-2026-07-17.md`
5. Design Wave 5: `/greenharbor-plan-work "Remove operator-asserted Phoenixd fee capability and gate unsupported real-money backends" --review reports/greenharbor-code-review-full-2026-07-17.md`
6. Design Wave 6: `/greenharbor-plan-work "Make credential acquisition and single-use consumption atomic across processes" --review reports/greenharbor-code-review-full-2026-07-17.md`
7. IMPL Wave 7 (parallel-safe): fix I1, I4, I5, and I6.
8. IMPL Wave 8: fix I2.
9. IMPL Wave 9: fix I3 after the error-envelope behavior from D2 is settled.
