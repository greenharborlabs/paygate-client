# Complete Wave 2 Canary Qualification

**Created at:** `e8c4d92` on `2026-07-21` | **Mode:** `eng`

## Summary

Wave 2 is one review finding away from qualification: the canary precondition
checker verifies the signature and shape of a live infrastructure attestation,
but does not bind its `configuration_digest` to the committed redacted GitHub
environment and runner-group baseline. This plan adds an exact versioned digest
profile, proves drift rejection with signed black-box fixtures, restores the
targeted test environment, and reruns the complete Wave 2 evidence gate without
performing a payment or changing live GitHub settings.

## Existing Code Leverage

- `scripts/check-rust-canary-contract.py` already verifies Ed25519 signatures,
  freshness, repository/environment claims, runner identity, labels, protected
  deployment metadata, and contract/inventory parity.
- `infra/runners/payment-canary-github-audit.json` already records separate
  redacted configuration digests for both protected environments and the shared
  runner group.
- `security/payment-canary-contract.yaml` already owns the live-attestation
  schema and can declare the digest profile without creating another authority.
- `tests/platform-smoke/test_wave5_qualification_contracts.py` already contains
  signed canary-validator fixtures and parsed workflow assertions.
- `tests/test_payment_canary_runner.py` covers the candidate approval, sandbox,
  cap, result, and durable-ledger boundaries added during the prior review loop.
- `pyproject.toml` already declares `pytest` in the `dev` extra; verification
  should use an isolated project environment rather than modifying system Python.

## Architecture

The trusted infrastructure verifier and repository checker share a normative
profile and golden vectors. The literal profile input is:

```json
{"backend":"<backend>","environment_configuration_digest":"sha256:<hex>","profile":"paygate-github-protection-v1","repository":"greenharborlabs/paygate-client","runner_group_configuration_digest":"sha256:<hex>"}
```

Both sides serialize that object with sorted keys, comma/colon separators, and
ASCII-safe JSON, hash the resulting bytes with SHA-256, and prefix the lowercase
hex with `sha256:`. The signed attestation exposes separate exact
`digest_profile` and `baseline_composite_digest` claims; contract schema v7
rejects legacy attestations rather than silently changing the meaning of the
old `configuration_digest` field.

```text
fresh GitHub API state ─> trusted verifier ─> signed composite digest ─┐
                                                                      ├─ exact match ─> runner allowed
committed environment + runner-group baselines ─> expected composite ─┘
                                                   mismatch/missing ─> fail before invoice
```

## Blast Radius

| Modified File/Interface | Consumers | Covered by Work Unit? |
| --- | --- | --- |
| `security/payment-canary-composite-digest-profile-v1.json` inactive normative profile (new) | Trusted verifier, checker implementation | W1-01, W2-01 |
| `security/payment-canary-contract.yaml` active schema-v7 profile/claims | Precondition checker, protected canary jobs, reviewers | W2-01 |
| `infra/runners/payment-canary-github-audit.json` redacted baseline schema | Precondition checker, infrastructure review | W2-01 |
| `security/payment-canary-composite-digest-vectors.json` normative vectors (new) | Trusted verifier, checker, tests | W1-01, W2-01 |
| `infra/runners/payment-canary-verifier-conformance.json` signed rollout evidence (external input) | Conformance validator, Platform Engineering, Wave 2 reviewers | W1-01 |
| `scripts/check-payment-canary-verifier-conformance.py` conformance gate (new) | Orchestration, Platform Engineering | W1-01 |
| `tests/test_payment_canary_verifier_conformance.py` signed conformance fixtures (new) | Local conformance gate | W1-01 |
| `infra/payment-canary-runner/README.md` verifier handoff and rollout order | Platform Engineering | W1-01 |
| `scripts/check-rust-canary-contract.py` strict JSON and expected/live digest comparison | Both protected backend jobs | W2-01 |
| `tests/platform-smoke/test_wave5_qualification_contracts.py` signed drift fixtures | Local Wave 2 qualification gate | W2-01 |
| `tests/test_payment_canary_runner.py` existing runner boundary tests | Local Wave 2 qualification gate | W2-01 |
| `tests/test_package_metadata.py` release-artifact proof | Wave 2/Wave 6 packaging boundary | W2-01 |

## Risk Flags

`security`: yes | `performance`: no | `migration`: yes | `public-api`: no | `concurrency`: yes

Security risk is confined to the pre-payment trust boundary and evidence
provenance. Migration risk comes from the breaking verifier-first, checker-second
schema-v7 claim transition. Concurrency remains relevant because the final gate
must preserve the existing global no-overlap and no-retry properties; this plan
does not alter the payment execution path.

## Wave 1: Establish Verifier Conformance and Rollout Evidence

### W1-01: Version the composite profile and qualify the trusted verifier

Add an inactive, normative v1 profile document with the literal profile above,
the future schema-v7 claim names, exact types, canonicalization algorithm, and
legacy rejection rule. Do not change the active schema-v6 contract or checker in
this wave. Commit golden LND and Breez vectors containing redacted component
digests, canonical bytes, and expected composites. The same vectors are the
conformance interface for the external trusted verifier and repository checker.

Define Platform Engineering ownership and staged rollout in the runner README:
deploy the composite-capable verifier first; run it against freshly queried live
GitHub environment and runner-group state in non-paying mode; validate its output
against the golden vectors and schema; then record a redacted conformance result
with verifier immutable digest, profile, vector-result digests, observation time,
and evidence reference. The record is an exact `claims`/`signature` envelope
signed by the existing infrastructure-attestation trust authority. A dedicated
validator verifies canonical Ed25519 bytes, configured issuer/key ID, key
purpose/revocation/validity, the deployed verifier digest, exact profile/vector
digests and cases, `status: passed`, and an issued/expires window no longer than
seven days. Do not enable the stricter repository checker or payment capability
until this command passes. If the verifier cannot be inspected or cannot
reproduce the vectors, block Wave 1 rather than manufacturing a local PASS.

Keep the audit redacted and exact. Define duplicate JSON keys as invalid for all
security-sensitive contract inputs. The normative vectors must demonstrate that
equivalent input key order and whitespace yield the same composite; semantic
field/value changes must yield a different composite.

**Files:** `security/payment-canary-composite-digest-profile-v1.json` (new),
`security/payment-canary-composite-digest-vectors.json` (new),
`infra/runners/payment-canary-verifier-conformance.json` (external signed input),
`scripts/check-payment-canary-verifier-conformance.py` (new),
`tests/test_payment_canary_verifier_conformance.py` (new),
`infra/payment-canary-runner/README.md`

**Acceptance criteria:**

- The inactive v1 profile names `paygate-github-protection-v1`, the literal
  five-field canonical object, serialization rules, SHA-256 encoding, future
  schema-v7 claims, and fail-closed legacy behavior without changing active v6.
- Golden vectors cover both backends and are reproduced byte-for-byte by both
  the trusted verifier conformance process and repository checker tests.
- Equivalent object key ordering and insignificant JSON whitespace produce the
  same composite; every semantic field mutation produces a different composite.
- The audit and vector files contain only redacted IDs/digests, have exact schemas
  and backend coverage, and prohibit duplicate JSON keys.
- Platform Engineering supplies canonical Ed25519-signed non-paying conformance
  evidence for the deployed verifier, including its immutable digest and fresh
  observation, before checker enforcement is eligible to advance.
- The conformance validator binds that evidence to the existing infrastructure
  keyring, exact profile/vector file digests, complete case results, deployed
  verifier digest, and a validity window no longer than seven days.
- Completing Wave 1 leaves the active schema-v6 contract/checker pair unchanged
  and coherent; schema v7 activates only in Wave 2.
- Missing, stale, mismatched, unverifiable, or locally fabricated verifier
  conformance evidence blocks Wave 1.

**Error handling:** Unknown profiles, malformed vectors, duplicate keys,
non-reproducible composites, missing/invalid/revoked signature, wrong-purpose or
expired key, verifier/file digest mismatch, incomplete cases, absent live API
inspection, or stale conformance evidence block rollout. No repository fixture
can substitute for the external signed non-paying observation.

**Tests:** Golden-vector generation/verification and ephemeral-key black-box
tests for the conformance validator; no payment or secret-bearing fixtures.

**Test spec:**

- Reproduce both golden composites from their semantic objects and exact
  canonical bytes.
- Permute input key order and whitespace and prove invariance; mutate profile,
  repository, backend, either component digest, case, or value and prove change.
- Feed the vectors to the deployed verifier conformance command and retain only
  redacted outcome digests plus immutable verifier identity.
- Sign a valid conformance envelope with an ephemeral Ed25519 key and assert the
  validator passes; mutate signature, issuer/key, revocation/validity, profile,
  verifier digest, profile/vector file digests, case coverage/status, and
  issued/expires window independently and assert failure.
- Present absent or failed external evidence and confirm Wave 1 remains blocked.

## Wave 2: Enforce Drift Rejection and Complete Qualification

### W2-01: Enforce the signed composite and run deterministic Wave 2 evidence

Atomically activate contract schema v7 and the new attestation claims while
adding duplicate-aware JSON decoding for the contract, inventory, audit, keyring,
and live attestation so duplicate top-level, backend, signer, or digest keys fail.
Recompute the selected backend's expected composite from the committed audit
using the v1 profile, then require exact `digest_profile` and
`baseline_composite_digest` equality inside the existing Ed25519-signed payload.
Legacy or mixed-profile attestations fail before runner invocation.

Extend signed black-box fixtures for both backends and all semantic mutations.
Create an isolated development environment from `.[dev]` without changing
system Python. Add a deterministic Rust artifact test using a fresh temporary
`CARGO_TARGET_DIR` and `CARGO_NET_OFFLINE=true cargo +1.88.0 build --locked
--offline --release`; assert `target/release/paygate` exists and no
`payment_canary` executable exists. Run only this Rust artifact test plus the
targeted Wave 2 Python files, then obtain the mandatory independent review.

**Files:** `security/payment-canary-contract.yaml`,
`infra/runners/payment-canary-github-audit.json`,
`scripts/check-rust-canary-contract.py`,
`tests/platform-smoke/test_wave5_qualification_contracts.py`,
`tests/test_payment_canary_runner.py`, `tests/test_package_metadata.py`

**Acceptance criteria:**

- All security-sensitive JSON inputs reject duplicate keys at every nesting
  level before their values reach signature, identity, or digest checks.
- The checker accepts only contract schema v7 and exact
  `paygate-github-protection-v1` live claims; legacy/mixed profiles fail closed.
- LND and Breez expected composites use their own environment baseline and the
  shared runner-group baseline; cross-backend reuse fails.
- A fresh correctly signed matching composite passes, while independently
  mutated environment, runner-group, backend, profile, or composite values fail.
- Existing freshness, signer, protection, branch, labels, runner identity,
  candidate isolation, durable no-retry, unconditional result validation, and
  redaction assertions continue to pass.
- Diagnostics identify only the failure class/field and never print baseline,
  attestation, signature, resource ID, or secret contents.
- The isolated targeted Python suite passes without GitHub/payment access.
- The exact locked/offline default-feature Rust build produces `paygate` and no
  `payment_canary` executable in a clean temporary target directory.
- An independent reviewer passes every original W2-01 acceptance criterion.

**Error handling:** Missing or malformed inputs, duplicate keys, unsupported
schema/profile, canonicalization failure, backend mismatch, stale/invalid
signature, or any digest difference exits nonzero before runner execution.
Unavailable dev dependencies or offline Cargo inputs block qualification rather
than downgrading to syntax or manifest-string checks.

**Tests:** Ephemeral-key black-box validator tests; workflow structural tests;
existing runner boundary tests; locked/offline Rust artifact inspection.

**Test spec:**

- Sign matching LND and Breez attestations built from the golden vectors and
  assert success; prove each backend rejects the other's composite.
- Keep signatures valid while separately changing environment digest,
  runner-group digest, backend, profile, and final composite; each fails.
- Supply raw JSON with duplicate top-level, nested environment, runner-group,
  signer, and digest keys across every security-sensitive input; each fails.
- Remove/expire the attestation, revoke its key, or mutate existing protection,
  branch, group, label, and identity claims; retain existing failure behavior.
- Parse both protected jobs and prove the checker runs before exactly one fixed
  runner invocation and validation remains unconditional afterward.
- In an isolated `.[dev]` environment run `python3 -m pytest -q
  tests/test_payment_canary_runner.py
  tests/platform-smoke/test_wave5_qualification_contracts.py
  tests/test_package_metadata.py`.
- Run the exact locked/offline default-feature Cargo build in a temporary target
  directory and inspect executable artifacts for `paygate` only.

## NOT in Scope

- Changing live GitHub environments, runner groups, reviewers, or secrets; the
  plan requires Platform Engineering verifier conformance evidence but does not
  authorize those live mutations.
- Executing LND/Breez payments or treating fake adapters as production evidence.
- Wave 3 candidate aggregation, Wave 5 checkpoint advancement, deployment, or
  release publication; those begin only after Wave 2 independently passes.
- Reworking the already-reviewed candidate approval, sandbox, result signature,
  or durable-ledger designs unless a targeted regression test exposes a defect.

## Security Considerations

The committed audit and signed live attestation are different authorities: the
audit defines reviewed expected state, while the verifier proves freshly
observed state. Golden vectors and staged producer conformance prevent the
checker from silently adopting a digest meaning the deployed verifier does not
produce. The composite binds both the backend-specific environment and shared
runner group, is versioned to prevent ambiguous canonicalization, and remains
covered by the existing Ed25519 signature. Duplicate-aware decoding prevents
last-key-wins ambiguity. Tests use ephemeral keys and synthetic redacted data
only; failure output never echoes signed payloads or infrastructure identifiers.

## Failure Modes Summary

| Codepath | Failure Mode | Handled In | Tested? |
| --- | --- | --- | --- |
| Verifier rollout | Producer lacks v1 profile, trusted signature, freshness, or vector parity | W1-01 signed conformance validator blocks strict checker | Yes |
| Audit parsing | Duplicate key, missing backend, extra field, malformed digest | W2-01 duplicate-aware exact schema validation | Yes |
| Composite derivation | Wrong backend or profile ambiguity | W1-01 vectors + W2-01 canonical helper | Yes |
| Live comparison | Environment or runner-group drift | W2-01 exact signed composite equality | Yes |
| Signature/freshness | Missing, invalid, stale, revoked, or wrong-purpose signer | Existing checker retained and regression-tested in W2-01 | Yes |
| Workflow precondition | Checker failure bypasses runner guard | Existing ordering plus W2-01 structural regression test | Yes |
| Test environment | `pytest` unavailable or dependency bootstrap fails | Qualification blocks; isolated dev bootstrap in W2-01 | Yes |
| Packaging boundary | Canary binary leaks into normal artifact | W2-01 locked/offline artifact inspection fails | Yes |

## Architect Review Findings

### Auto-Incorporated

- Added producer conformance and staged rollout as a blocking prerequisite; a
  checker-only change cannot complete Wave 2.
- Kept Wave 1 profile/vectors non-active so schema-v6 remains coherent, then
  moved schema-v7 activation atomically beside checker enforcement in Wave 2.
- Defined signed conformance evidence, existing infrastructure-keyring trust,
  deployed-verifier/file digest binding, seven-day maximum validity, and an
  executable blocking validator instead of trusting a committed JSON shape.
- Defined the exact five-field v1 canonical object and new versioned attestation
  claims; legacy attestations fail closed under contract schema v7.
- Required duplicate-aware JSON parsing across every security-sensitive input.
- Replaced contradictory key-order rejection with positive canonicalization
  invariance and semantic-mutation tests plus shared golden vectors.
- Named the exact locked/offline Cargo build and temporary target isolation used
  to prove the qualification binary is absent from normal artifacts.

### Deferred

- Live GitHub configuration mutations and paying protected-runner smoke remain
  external operations; non-paying verifier conformance evidence is required in
  Wave 1 and cannot be deferred past Wave 2 qualification.

## Confidence Assessment

| Dimension | Score | Source | Notes |
| --- | --- | --- | --- |
| Requirements | 0.95 | Original W2-01 plan, final reviewer, architect | Checker and producer-side gates are explicit |
| Architecture | 0.94 | Existing attestation/audit split + delta review | Non-active profile then atomic activation preserves coherence |
| Codebase fit | 0.92 | Existing checker, audit, contract, and tests | Adds two small evidence artifacts and one external gate |
| Testability | 0.94 | Ephemeral signatures, golden vectors, offline Cargo | Live conformance remains a signed external blocking artifact |
| Security | 0.93 | Signed conformance, duplicate-aware parsing, exact digest binding | Trust anchors and redacted outputs are explicit |
| Migration | 0.91 | Architect-reviewed verifier-first sequencing | Active v6 remains coherent until atomic v7 activation |
| Overall | 0.94 | Weighted assessment | Above confidence gate; external conformance is explicit |

## Orchestration Playbook

```bash
/greenharbor-orchestrate plans/complete-wave-2-canary-qualification.md --scope "Wave 1"
/greenharbor-orchestrate plans/complete-wave-2-canary-qualification.md --scope "Wave 2"
/greenharbor-orchestrate plans/complete-wave-2-canary-qualification.md
```
