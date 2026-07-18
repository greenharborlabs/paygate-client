# Bind Validated BOLT11 Policy to Wallet Submission

**Created at:** `003bf09` on `2026-07-18` | **Mode:** `eng`

## Summary

Close review finding D1 by replacing independent invoice string parsing with one fail-closed BOLT11 validation and binding boundary. Every real Payment, L402, and standalone diagnostic payment must carry an immutable decoded invoice whose signature, checksum, payment hash, and amount have been validated and matched to the metadata used for policy before any wallet-facing payer method can run.

## Existing Code Leverage

- `paygate_client/invoices.py` already centralizes amount and payment-hash extraction; it is the natural home for the validated invoice value object and binding errors, but its current helpers do not validate the Bech32 checksum or BOLT11 signature.
- `paygate_client/orchestrator.py` already normalizes Payment and L402 into `_PayableChallenge` before `PolicyEngine.evaluate()` and funnels payment through `_pay()`.
- `paygate_client/payers/base.py` already provides a frozen `PaymentChallenge` and an `AbstractPayer.pay()` pre-submission guard shared by all built-in real backends.
- `paygate_client/diagnostics.py` funnels `paygate backend pay-invoice` through one function, but currently marks undecodable invoices as `local_synthetic`; that bypass must be removed.
- Existing policy, payer, diagnostic, and orchestrator tests already assert that denials occur before payer invocation and can be extended with signed BOLT11 fixtures.

## Architecture

```text
Payment challenge ----\
                       > validate_bolt11(invoice) -> ValidatedBolt11
L402 challenge -------/             | checksum + signature + p-tag + amount
                                     v
                         bind declared amount/hash
                                     |
                           policy evaluates bound amount
                                     |
                         PaymentChallenge(validated_invoice)
                                     |
                  AbstractPayer pre-submit invariant -> wallet backend

Standalone diagnostic -> same validate/bind boundary ----------------^
```

The invoice string remains the backend payload, but the immutable `ValidatedBolt11` produced from that exact string becomes the authoritative source for policy amount and payment hash. A real `PaymentChallenge` is constructed from that proof and exposes invoice, amount, and hash only as derived read-only properties; synthetic test input is a separate type that real payer classes cannot accept. Shared result binding checks both `RawPaymentResult` and already-normalized `PaymentResult` before policy commit, credential construction, or reporting.

## Blast Radius

| Modified File/Interface | Consumers | Covered by Work Unit? |
| --- | --- | --- |
| `plans/decisions/bolt11-decoder.md` (new) and `pyproject.toml`: qualified/pinned validator decision | package builds, supported Python matrix | W1-01 |
| `paygate_client/invoices.py`: replace nullable extraction helpers with validated decode/bind API | orchestrator, diagnostics, tests | W2-01 |
| `paygate_client/payers/base.py` and `payers/__init__.py`: proof-first real challenge, isolated synthetic type, shared result binding | all built-in payers, custom payer implementations, payer tests | W2-01, W3-01 |
| `paygate_client/orchestrator.py`: Payment/L402 normalization and pre-policy binding | `paygate request`, policy ledger, credential creation | W3-01 |
| `paygate_client/credentials.py`: audit bound values used for authorization payloads | retry credentials and cache metadata | W3-01 |
| `paygate_client/diagnostics.py`: validate before configuration/payer construction | `paygate backend pay-invoice`, CLI tests | W3-02 |
| Signed BOLT11 fixture support and `tests/test_invoices.py` | all payment-flow tests | W2-01 |
| `tests/test_orchestrator.py`, `tests/test_credentials.py`, `tests/test_payers_*.py` | protocol, credential, public payer API, backend result regressions | W2-01, W3-01 |
| `tests/test_diagnostics.py`, `tests/test_cli.py` | diagnostic/CLI fail-closed behavior | W3-02 |
| `README.md`, `PYPI_README.md`, compatibility docs | operators, package consumers, custom payer implementers | W2-01, W3-01 |

This exceeds eight files because the security invariant crosses three production entry points and a shared payer interface; centralizing the invariant limits production changes to four modules while the remaining files are regression fixtures, packaging, and documentation.

## Risk Flags

`security`: yes | `performance`: no | `migration`: yes | `public-api`: yes | `concurrency`: no

## Wave 1: Qualify the Decoder Trust Boundary

### W1-01: Select, document, and pin a real-funds BOLT11 validator

Run a release-blocking qualification before implementation. The selected decoder must validate Bech32 checksum and BOLT11 signature, expose exact millisatoshi amount and the signed `p` tag, have an acceptable security/maintenance posture, and install across Python `>=3.10,<3.15`; `bolt11` 2.2 currently excludes Python 3.13-3.14 and `pyln-proto` currently disclaims real-funds safety, so neither is accepted without resolving that evidence. Record the decision and pin the chosen dependency; do not silently reduce Python support or fall back to partial parsing.

**Files:** `plans/decisions/bolt11-decoder.md` (new), `pyproject.toml`, `.github/workflows/ci.yml` only if a dependency smoke step is needed

**Acceptance criteria:**
- ADR records candidates, exact selected version/range, checksum/signature guarantees, amount/hash API, license, maintenance/security posture, transitive dependencies, and rationale.
- A minimal decode smoke test installs and runs on Python 3.10, 3.11, 3.12, 3.13, and 3.14 on declared CI platforms.
- No selected package carries an unresolved warning against real-funds use.
- Failure to find a qualifying decoder stops orchestration at Wave 1 with a release-blocking decision; no production parsing code is changed.

**Error handling:** Treat unsupported interpreter/platform, missing wheels/build prerequisites, failed signature/checksum vectors, or adverse security posture as qualification failure, not a recoverable runtime fallback.

**Tests:** Isolated build/install matrix and official BOLT11 valid/invalid smoke vectors.

**Test spec:**
- Install the chosen pin in each supported Python job and decode one official signed amount-bearing vector.
- Mutate checksum and signature independently; assert the decoder rejects both.
- Build sdist/wheel with the pin and run clean-environment import/decode smoke tests.

## Wave 2: Make Validated Invoices the Only Real Payer Input

### W2-01: Implement immutable invoice binding and a proof-first payer contract

Replace nullable extractors with immutable `ValidatedBolt11` plus a `Bolt11Error` hierarchy and binding API. Real payments require a valid `p` tag, an amount-bearing invoice, and an exact whole-satoshi amount; Payment metadata must equal decoded amount/hash, while L402 and diagnostics derive both exclusively from the invoice. Model `PaymentChallenge` as `validated_invoice` plus non-authoritative service/metadata, with invoice/amount/hash derived properties; remove `local_synthetic` and independent real-payment fields. If direct synthetic tests remain necessary, use a separate `SyntheticPaymentChallenge` accepted only by `TestModePayer`, never a real `AbstractPayer` or the public real-payer protocol.

**Files:** `paygate_client/invoices.py`, `paygate_client/payers/base.py`, `paygate_client/payers/__init__.py`, `paygate_client/payers/test_mode.py`, `README.md`, `PYPI_README.md`, `docs/payer-backend-compatibility.md`, `tests/test_invoices.py`, `tests/test_payers_test_mode.py`, `tests/test_payers_lnd_rest.py`, `tests/test_payers_phoenixd.py`, `tests/test_payers_breez.py`, `tests/fixtures/bolt11/` (new), `tests/bolt11_fixtures.py` (new only if shared loader needed)

**Acceptance criteria:**
- Decode returns the exact original string, exact `amount_msat`/`amount_sats`, and normalized 32-byte hash only after checksum/signature/mandatory-tag validation.
- Mixed case, bad checksum, truncation, invalid signature/recovery id, malformed/duplicate mandatory tags, amountless, fractional-satoshi, amount mismatch, and hash mismatch fail closed; valid uppercase is accepted while preserving the submitted string.
- Real `PaymentChallenge` cannot represent invoice, amount, or hash independently of `ValidatedBolt11`.
- Real payers cannot accept the synthetic type; all exports/type hints and custom-payer compatibility notes reflect the constructor change.
- Legacy extraction helpers and `local_synthetic` are removed from production paths.
- Public docs describe the proof-first constructor migration, amountless rejection, and checksum/signature binding contract consistently.

**Error handling:** Define `Bolt11Error` with typed invalid, amountless, amount mismatch, and hash mismatch subclasses. Preserve decoder exceptions only as causes and never echo full invoices. Real payer type violations fail before `_pay_invoice()`.

**Tests:** Official conformance vectors, mutation tests, constructor/API contract tests, and transport-recording backend tests.

**Test spec:**
- Decode and bind a valid 25-sat vector, then reject 24-sat and different-hash declarations.
- Reject checksum, signature, recovery-id, mandatory-tag, amountless, and fractional-satoshi cases.
- Assert callers cannot construct a real challenge with raw invoice/amount/hash fields.
- Pass the synthetic type to every real payer with recording transports; assert no HTTP/SDK call.

## Wave 3: Bind Policy, Results, Diagnostics, and Documentation

### W3-01: Enforce binding before policy and after every payer return

Validate/bind Payment and L402 in `_to_payable_challenge()` before `PolicyEngine.evaluate()`, remove JSON amount/hash fallbacks, and carry only `ValidatedBolt11`. Add shared result verification that checks preimage, hash, and amount against the validated invoice for both `RawPaymentResult` and already-normalized `PaymentResult`; orchestrator must call it for arbitrary `Payer` protocol results before credential construction, success tracing, caching, or reporting. Audit `credentials.py` and add regression coverage proving authorization payloads and cache metadata cannot reintroduce declared challenge values. Update request/L402/troubleshooting docs and their package smoke coverage in the same unit so the final error/API contract is documented after implementation.

**Files:** `paygate_client/orchestrator.py`, `paygate_client/payers/base.py`, `paygate_client/credentials.py` only if audit finds a code change, `README.md`, `PYPI_README.md`, `tests/test_orchestrator.py`, `tests/test_credentials.py`, `tests/test_payers_test_mode.py`, `tests/test_package_metadata.py` only if published-doc assertions change, Paygate fixtures under `tests/fixtures/paygate/`

**Acceptance criteria:**
- Amount/hash binding completes before policy reservation, payer invocation, or wallet call; mismatches leave payer calls and ledger at zero.
- L402 policy values come only from the validated invoice; body metadata cannot override them.
- Backend/custom-payer amount or hash mismatch cannot be credentialed, cached, traced as success, or reported; reservation/commit treatment after payer invocation remains explicitly governed by the current ledger behavior pending D2.
- Valid Payment/L402 flows use bound values through policy, credential creation, and result envelopes.
- `test_preimage` no-wallet flow requires a valid signed invoice bound to that preimage/hash and never creates a synthetic real-payer challenge.
- Request/L402/operator docs name the stable error behavior, state validation precedes reservation/submission, and advise obtaining a corrected challenge instead of manually paying it.

**Error handling:** Catch `Bolt11Error` around normalization and map to `unsupported_402_challenge`, `paid: false`, before any reservation. Payer-result binding failures use a stable verification error and preserve current/D2 post-submission ledger semantics rather than asserting the wallet was never invoked or requiring rollback/commit changes in this plan.

**Tests:** Orchestrator integration, arbitrary custom-payer result tests, credential payload/cache regression tests.

**Test spec:**
- Pair a signed 100-sat invoice with 1 sat or a different hash; assert pre-policy denial, zero payer calls, zero ledger.
- Supply conflicting L402 body metadata; assert invoice values win or conflict is rejected.
- Return a `PaymentResult` with mismatched amount from a custom payer; assert no credential, cache, success trace, or success report, while making no new D2 ledger-state assertion.
- Exercise valid Payment/L402 success, policy denial, `--no-pay`, and test-preimage paths.

### W3-02: Validate standalone diagnostics before constructing a payer

Decode and bind `backend_pay_invoice()` input before config loading and `payer_factory` invocation where feasible, then use the shared proof-first challenge and result verifier. Remove the backend-authoritative/local-synthetic fallback; W3-01 owns the shared operator documentation so these same-wave units remain parallel-safe.

**Files:** `paygate_client/diagnostics.py`, `paygate_client/cli.py` only if command help/error-code handling changes, `tests/test_diagnostics.py`, `tests/test_cli.py`

**Acceptance criteria:**
- Malformed, checksum/signature-invalid, amountless, or missing-hash input returns `PAYER_INVOICE_INVALID` before payer construction/invocation.
- Success always reports invoice-bound amount/hash and `verificationSource: "invoice"`; backend-result fallback is gone.
- Both `RawPaymentResult` and `PaymentResult` amount/hash mismatches are rejected.
- Existing preimage and invoice redaction remains intact.

**Error handling:** Catch `Bolt11Error` before configuration/payer setup and map it to redacted `PAYER_INVOICE_INVALID`; retain backend verification codes for post-submission result failures.

**Tests:** Diagnostic/CLI envelopes with recording payer factory plus shared signed fixtures.

**Test spec:**
- Mutate checksum/signature and assert invalid code, nonzero CLI exit, payer factory not invoked, and invoice not echoed.
- Reject a valid amountless invoice before factory construction.
- Reject mismatched amount/hash from raw and normalized results.
- Verify valid success reports bound values and redacted secrets.
- Build/install artifacts, run signed-invoice smoke tests on all supported Python versions, and run `poe check` (or the equivalent format/lint/type/test commands).

## NOT in Scope

- Submitted/uncertain payment ledger states and rollback semantics (review D2) — requires its own state-machine plan and must not be conflated with pre-submit validation.
- Service identity/default-deny semantics (review D3) — independent policy dimension.
- Transport security, payer fee-capability changes, and credential-store atomicity (review D4-D6) — separate review findings.
- General BOLT12 support — this boundary is intentionally BOLT11-only.
- Amountless invoice payment — deferred until all payer backends can accept an explicit, policy-bound amount through a uniform contract.
- Invoice expiry/network allowlisting — valuable follow-up validation, but not required to close the amount/hash binding bypass unless architect review finds the chosen decoder exposes a no-cost safe check that should be mandatory now.

## Security Considerations

The server-controlled challenge and invoice are untrusted until the BOLT11 checksum/signature and binding checks pass. The validated object must be immutable, retain the exact submitted invoice string, and be the sole source of amount/hash values across policy, payer, credential, trace, and result verification. No `None`, parse failure, JSON-body fallback, backend-result fallback, or `local_synthetic` flag may upgrade an unvalidated real invoice into a payable challenge. Mutation/conformance tests must prove the checks fail before policy reservation or any wallet transport/SDK call.

Decoder selection is part of the trust boundary. W1-01 must record upstream version, Python/platform support, signature/checksum behavior, maintenance/security posture, and transitive dependencies. A decoder that disclaims real-funds safety or cannot install across the declared support matrix does not satisfy this plan without a separately approved support-policy or implementation decision.

## Failure Modes Summary

| Codepath | Failure Mode | Handled In | Tested? |
| --- | --- | --- | --- |
| Invoice decode | malformed Bech32, checksum, signature, recovery id, mandatory tags | W2-01 | Yes |
| Invoice decode | amountless or fractional-satoshi invoice under current contract | W2-01 | Yes |
| Payment binding | declared amount differs from signed invoice | W2-01 / W3-01 | Yes |
| Payment binding | declared hash differs from signed `p` tag | W2-01 / W3-01 | Yes |
| L402 normalization | body metadata attempts to override invoice | W3-01 | Yes |
| Direct payer call | missing validated proof or synthetic-type bypass | W2-01 | Yes |
| Diagnostic payment | invalid invoice reaches config/payer construction | W3-02 | Yes |
| Backend result | returned amount/hash/preimage differs from bound invoice | W3-01 / W3-02 | Yes |
| Dependency install | validator incompatible with supported Python/platform | W1-01 | Yes; release-blocking |

## Architect Review Findings

### Auto-Incorporated

- Made the public real-payment challenge proof-first, with invoice/amount/hash derived from `ValidatedBolt11`, and isolated synthetic test input from every real payer.
- Added shared post-payer amount/hash/preimage binding for raw and normalized results, including custom `Payer` implementations.
- Split decoder selection into a release-blocking Wave 1 ADR and Python 3.10-3.14 compatibility/security gate.
- Added explicit `Bolt11Error` translation at orchestrator and diagnostic boundaries.
- Moved diagnostic validation before configuration and payer-factory construction and added a factory-not-invoked test.
- Added credential construction/cache audit coverage.
- Marked the payer constructor change as migration/public-API risk and corrected all work-unit ownership mappings.
- Preserved ambiguous post-submission ledger semantics for the separate D2 plan while preventing invalid results from producing credentials or success output.

### Resolved with User Input

None.

### Deferred

- Ambiguous post-submission reservation/commit handling remains review finding D2; this plan does not claim a result-verification failure proves no payment occurred.

## Confidence Assessment

| Dimension | Score | Source | Notes |
| --- | --- | --- | --- |
| Architecture | 94% | architect delta review | Qualification, proof-first construction, and final submission/result boundaries are explicit. |
| Error Handling | 89% | architect delta review | Typed domain errors and stable boundary mappings cover pre-submit failures; D2 remains explicitly separate. |
| Test Strategy | 95% | architect delta review | Official vectors, mutations, caller-contract, transport/factory, integration, and full-matrix tests are specified. |
| Security | 93% | architect delta review | Untrusted invoice metadata cannot reach policy or a real payer without checksum/signature/binding proof. |
| Migration / Public API | 88% | plan synthesis | Constructor/type migration, exports, custom-payer notes, and compatibility tests are owned in W2-01. |

**Gate result:** Passed round 1. All scored dimensions are at least medium confidence and the delta review reported no remaining critical findings.

## Orchestration Playbook

```bash
# Wave 1: Qualify the Decoder Trust Boundary
/greenharbor-orchestrate plans/bind-validated-bolt11-amount-and-payment-hash-to-every-policy-approved-payment-before-wallet-submission.md --scope "Wave 1"

# Full plan
/greenharbor-orchestrate plans/bind-validated-bolt11-amount-and-payment-hash-to-every-policy-approved-payment-before-wallet-submission.md
```
