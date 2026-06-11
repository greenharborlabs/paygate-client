# Security Review Remediation Plan

**Created at:** `11654c4` on `2026-06-11` | **Mode:** `eng`

## Summary
Remediate the Wave 1 security review by failing closed before invoice submission when a real payment challenge lacks an authoritative `payment_hash`, strengthening default envelope redaction for secret-like fields, and closing easy accidental secret-commit paths. Then make the verification toolchain installable and actionable on current developer machines so the security fixes can be proven with tests, lint, format, and mypy.

## Existing Code Leverage
- `paygate_client/payers/base.py` - central payer abstraction, fee-limit preflight, challenge/result dataclasses, preimage and payment-hash verification.
- `paygate_client/payers/test_mode.py` - deterministic synthetic/test payer behavior that must remain allowed for local synthetic challenges.
- `tests/test_payers_test_mode.py` - payer invariant tests with fake `AbstractPayer` subclasses that can assert whether `_pay_invoice()` was reached.
- `paygate_client/redaction.py` - recursive text/envelope redaction for authorization headers, preimages, invoices, and caller-supplied secrets.
- `tests/test_redaction.py` - redaction regression tests for text and JSON-like envelopes.
- `pyproject.toml` - declared dev dependencies and strict mypy settings.
- `.gitignore` - local-ignore policy for caches and build artifacts.

## Architecture
```text
PaymentChallenge
   |
   v
AbstractPayer.pay()
   |-- fee-limit preflight
   |-- challenge authority preflight  <--- new fail-closed guard
   |-- _pay_invoice()
   `-- verify_payment_result()

JSON/text error material
   |
   v
redact_error_envelope()
   |-- redact secret-like keyed values  <--- new default denylist
   |-- redact Authorization values
   `-- redact nested text/preimages/invoices

Developer workflow
   |
   v
pyproject + tests + .gitignore
   |-- install dev tooling on modern pip
   |-- type/lint/format cleanups
   `-- ignore local secrets/config
```

## Blast Radius
| Modified File/Interface | Consumers | Covered by Work Unit? |
| --- | --- | --- |
| `paygate_client/payers/base.py::AbstractPayer.pay()` | current inherited backend `TestModePayer`; future production backends only if constrained to inherit `AbstractPayer` | W1-01 |
| `paygate_client/payers/base.py::verify_payment_result()` | exported through `paygate_client.payers`, direct tests, future backend diagnostics | W1-01 |
| `tests/test_payers_test_mode.py` | pytest payer invariant coverage | W1-01 |
| `paygate_client/redaction.py::redact_error_envelope()` | CLI/error envelope callers and future backend error rendering | W1-02 |
| `tests/test_redaction.py` | pytest redaction coverage | W1-02 |
| `.gitignore` | repository-wide local file hygiene | W1-03 |
| `pyproject.toml` | dev install, ruff, mypy, and pytest workflows | W2-01 |
| `README.md` or `docs/dev-setup.md` | developers installing dev dependencies on older system pip | W2-01 |
| `paygate_client/config.py` | strict mypy and ruff checks, config loader callers | W2-01 |

## Wave 1: Fail-Closed Security Remediation

### W1-01: Add payer pre-submission challenge authority guard
Move the non-synthetic `payment_hash` requirement ahead of `_pay_invoice()` so real backends cannot spend on malformed or unverifiable challenges. Preserve the existing local synthetic exception and keep `verify_payment_result()` as a defense-in-depth post-payment verifier.

**Files:** `paygate_client/payers/base.py` (lines 103-123, 168-203), `tests/test_payers_test_mode.py` (payer invariant tests)

**Acceptance criteria:**
- `AbstractPayer.pay()` raises `PreimageVerificationError` before calling `_pay_invoice()` when `challenge.payment_hash is None` and `challenge.local_synthetic is False`.
- The backend contract states that all real-money payer backends must subclass `AbstractPayer`; direct structural implementations of `Payer` are allowed only for tests or adapters that delegate to an `AbstractPayer`.
- A contract test or exported-interface test covers the currently available backend set and proves production backend classes inherit `AbstractPayer`.
- Local synthetic challenges with `payment_hash=None` still work through `TestModePayer` and produce deterministic verified results.
- Challenges with malformed `payment_hash` continue to fail during `PaymentChallenge` construction or the new preflight path.
- `verify_payment_result()` keeps rejecting missing authoritative hashes for non-synthetic challenges when called directly.

**Error handling:** Missing authoritative challenge hash for a real challenge raises `PreimageVerificationError` and does not submit an invoice; malformed challenge hashes raise `PreimageVerificationError`; missing/malformed backend preimages and mismatched backend payment hashes continue to raise the existing payer errors. If a future production backend does not inherit `AbstractPayer`, the contract test fails before release.

**Tests:** Unit tests using a fake `AbstractPayer` that records whether `_pay_invoice()` was called, plus existing `TestModePayer` synthetic coverage.

**Test spec:**
- Given a non-synthetic `PaymentChallenge(invoice="lnbc1real", payment_hash=None, ...)`, `payer.pay()` raises `PreimageVerificationError` and `payer.submitted` remains `False`.
- Given a local synthetic `PaymentChallenge(payment_hash=None, local_synthetic=True)`, `TestModePayer().pay(..., max_fee_sats=0)` succeeds and returns a hash matching the returned preimage.
- Given direct `verify_payment_result(non_synthetic_missing_hash, raw_result_with_valid_preimage)`, verification raises `PreimageVerificationError`.
- Given the exported payer backend classes currently present, each real-money backend class is an `AbstractPayer` subclass; `TestModePayer` also remains an `AbstractPayer` subclass.

### W1-02: Redact secret-like envelope fields by default
Extend recursive envelope redaction so fields with secret-bearing names are redacted even when callers forget to pass exact `extra_secrets`. Keep Authorization scheme preservation, recurse through dict/list/tuple structures, and continue using `extra_secrets` and text regexes for free-form strings.

**Files:** `paygate_client/redaction.py` (lines 1-75), `tests/test_redaction.py`

**Acceptance criteria:**
- Secret-like keys are redacted case-insensitively by default after normalizing separators and camelCase to tokens. The classifier redacts exact token names and token groups for `password`, `passwd`, `pwd`, `token`, `access_token`, `refresh_token`, `api_key`, `apikey`, `secret`, `client_secret`, `macaroon`, `macaroon_hex`, `authorization`, `proxy_authorization`, and `preimage`.
- The classifier does not redact safe operational fields merely because they contain a weak substring, such as `status`, `message`, `amount_sats`, `invoice`, `token_count`, or `secretary`.
- Redaction applies recursively to nested mappings inside lists and tuples without mutating the original envelope.
- Authorization values still preserve recognized schemes as `Basic|Bearer|Payment|L402 [REDACTED_CREDENTIAL]`.
- Non-secret operational fields such as `status`, `message`, `amount_sats`, and `invoice` are not blanket-redacted; invoice redaction remains controlled by `redact_invoices`.

**Error handling:** Unknown object types are deep-copied as today; string fields are passed through `redact_text`; secret-like keyed values are replaced with the appropriate redaction marker without raising on non-string values.

**Tests:** Unit tests for representative secret-like keys, nested structures, casing variants, and original-object immutability.

**Test spec:**
- Given an envelope containing `{"password": "hunter2", "macaroon_hex": "abc", "token": "tkn", "api_key": "key"}`, `repr(redacted)` contains none of the raw values.
- Given nested `{"outer": [{"Access_Token": "abc"}, {"api-key": "key"}, {"clientSecret": "sec"}, {"safe": "value"}]}`, only the secret-like fields are redacted.
- Given safe keys `{"token_count": 3, "secretary": "Ada", "message": "ok"}`, the values are preserved.
- Given an `Authorization` field with `Payment token:credential`, the output is exactly `Payment [REDACTED_CREDENTIAL]`.
- Given an invoice field and `redact_invoices=False`, the invoice string remains unless the key is otherwise secret-like.

### W1-03: Ignore local secret and Paygate config files
Update `.gitignore` to block common local environment and Paygate config files that may contain backend URLs, password env names, macaroon env names, or accidental inline secrets. Keep tracked example/template files available by explicitly allowing safe samples where needed.

**Files:** `.gitignore`

**Acceptance criteria:**
- `.env`, `.env.*`, local Paygate YAML/TOML/JSON config patterns, and editor/runtime local secret files are ignored.
- Template/example config files can still be committed, for example `*.example.yml`, `*.example.yaml`, and `*.sample.yml`.
- Existing cache/build ignore behavior remains unchanged.

**Error handling:** None at runtime; the safety behavior is repository hygiene. Avoid ignoring broad source paths that would hide real package or test files.

**Tests:** Static verification with `git check-ignore` for ignored and allowed patterns.

**Test spec:**
- `git check-ignore .env .env.local paygate.local.yml paygate-client.local.yaml` reports those paths as ignored.
- `git check-ignore paygate.example.yml` does not report the template path.

## Wave 2: Tooling and Verification Closure

### W2-01: Make quality gates reproducible and green
Fix the verification failures reported by the security review after the security edits land so the remediation can be checked cleanly. Prefer narrow formatting/type fixes and dependency metadata updates over behavior changes, and add an actual dev setup target for the old-pip editable install failure.

**Files:** `pyproject.toml`, `README.md` or `docs/dev-setup.md` (new if absent), `paygate_client/config.py`, `paygate_client/redaction.py`, affected test files if formatting requires it

**Acceptance criteria:**
- Dev install path is documented or encoded in a committed file so developers are not blocked by system `pip 21.2.4`; acceptable fixes include a clear setup section in `README.md` or `docs/dev-setup.md`, a bootstrap script, or an encoded packaging compatibility path.
- The dev setup instructions explicitly state that editable installs require PEP 660 support and that users on `pip 21.2.4` should first run `python3 -m pip install --upgrade pip`.
- Mypy has the required PyYAML typing support, e.g. `types-PyYAML`, and strict type errors are resolved.
- `load_config()` path typing no longer requires `Path(object)`.
- Regex callback type annotations use parameterized `re.Match[str]`.
- Ruff check and format checks pass without broad rule suppression.

**Error handling:** Tooling failures should produce standard command output; do not weaken runtime validation or strict mypy settings to hide real type issues.

**Tests:** Run the project’s declared verification commands.

**Test spec:**
- `python3 -m pytest`
- `python3 -m ruff check .`
- `python3 -m ruff format --check .`
- `python3 -m mypy`

## NOT in Scope
- Implementing real Phoenixd or LND payment backends - this plan only secures the shared payer boundary already present.
- Building the full Paygate request/retry orchestration - the review findings are confined to Wave 1 primitives.
- Changing invoice parsing semantics - only pre-submission authority validation and redaction behavior are addressed.

## Failure Modes Summary
| Codepath | Failure Mode | Handled In | Tested? |
| --- | --- | --- | --- |
| `AbstractPayer.pay()` | Real challenge missing authoritative `payment_hash` | W1-01 | Yes |
| Payer backend contract | Future real-money backend bypasses `AbstractPayer.pay()` guard | W1-01 | Yes |
| `AbstractPayer.pay()` | Backend cannot enforce fee limit | Existing + W1-01 regression coverage remains | Existing |
| `verify_payment_result()` | Direct verifier called with non-synthetic missing challenge hash | W1-01 | Yes |
| `redact_error_envelope()` | Secret-like keyed values omitted from `extra_secrets` | W1-02 | Yes |
| `.gitignore` | Local `.env` or Paygate config accidentally staged | W1-03 | Static |
| Quality gates | Dev env lacks typing deps or formatting/type issues remain | W2-01 | Command verification |
| Dev install | System `pip 21.2.4` cannot perform editable PEP 660 install | W2-01 | Documentation/static |

## Architect Review Findings
### Auto-Incorporated
- F1 IMPORTANT: Clarified that the structural `Payer` protocol does not itself enforce the guard, and added a backend inheritance contract plus test criteria for real-money backends.
- F2 IMPORTANT / M1: Added `README.md` or `docs/dev-setup.md` as a concrete target for the pip 21.2.4 install failure.
- F3 IMPORTANT: Split tooling and final verification into Wave 2 so the quality-gate work depends on the security fixes instead of overlapping as a parallel unit.
- F4 MINOR: Defined the redaction key classifier precisely enough to test separator, casing, camelCase, and safe-key exceptions.
- Delta review: No remaining CRITICAL or IMPORTANT findings after the structural revision.

### Resolved with User Input
None.

### Deferred
None.

## Confidence Assessment
| Dimension | Score | Source | Notes |
| --- | --- | --- | --- |
| Architecture | High | Delta architect review | Core boundaries are small; production backend inheritance is explicit. |
| Error Handling | High | Delta architect review | Payer failures and redaction classifier behavior are named and testable. |
| Test Strategy | High | Delta architect review | Unit, static, and full command verification are ordered across two waves. |

## Orchestration Playbook
```bash
/orchestrate plans/security-review-remediation.md --scope "Wave 1"
/orchestrate plans/security-review-remediation.md --scope "Wave 2"
/orchestrate plans/security-review-remediation.md
```
