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
| `security/payment-canary-composite-digest-profile-v1.json` inactive normative profile (new) | Future verifier, checker implementation | W1-01, W2-01 |
| `security/payment-canary-contract.yaml` active schema-v7 profile/claims | Precondition checker, protected canary jobs, reviewers | W2-01 |
| `infra/runners/payment-canary-github-audit.json` redacted baseline schema | Precondition checker, infrastructure review | W2-01 |
| `security/payment-canary-composite-digest-vectors.json` normative vectors (new) | Future verifier, checker, tests | W1-01, W2-01 |
| `tests/test_payment_canary_verifier_conformance.py` local profile/vector fixtures (new) | Local qualification | W1-01 |
| `infra/payment-canary-runner/README.md` local-artifact scope and production-attestation deferral | Repository maintainers | W1-01 |
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

## Wave 1: Establish Local Composite-Digest Qualification

### W1-01: Version the repository-local composite profile and vectors

Add an inactive, normative v1 profile document with the literal five-field
canonical object above, the future schema-v7 claim names, exact types,
canonicalization algorithm, and legacy rejection rule. Do not change the active
schema-v6 contract or checker in this wave. Commit redacted LND and Breez golden
vectors containing component digests, exact canonical bytes, and expected
composites. These are repository-local contract artifacts for Wave 2 to consume
directly; they are not a live infrastructure attestation.

Keep parsing strict: duplicate JSON keys are invalid at every nesting level in
the profile and vectors. Local tests must prove exact schemas and backend
coverage, byte-for-byte reproduction, invariance to JSON key ordering and
insignificant whitespace, and a distinct output for every semantic-field
mutation. The runner README must state that live-verifier attestation is
deferred until production enablement; no GitHub inspection, payment, deployment,
signing key, or external evidence is required for this wave.

**Files:** `security/payment-canary-composite-digest-profile-v1.json` (new),
`security/payment-canary-composite-digest-vectors.json` (new),
`tests/test_payment_canary_verifier_conformance.py` (new),
`infra/payment-canary-runner/README.md`

**Acceptance criteria:**

- The inactive v1 profile names `paygate-github-protection-v1`, the literal
  five-field canonical object, serialization rules, SHA-256 encoding, future
  schema-v7 claims, and fail-closed legacy behavior without changing active v6.
- Redacted LND and Breez vectors exactly reproduce their canonical bytes and
  composites locally and define the repository-only Wave 2 input.
- Equivalent object key ordering and insignificant JSON whitespace produce the
  same composite; every semantic field mutation produces a different composite.
- The profile and vector files have exact schemas, cover both backends, contain
  no secrets, and reject nested duplicate JSON keys.
- Completing Wave 1 leaves the active schema-v6 contract/checker pair unchanged
  and coherent; schema v7 activates only in Wave 2.
- Documentation clearly defers live-verifier attestation to production
  enablement, so it does not block local qualification.

**Error handling:** Unknown profiles, malformed profile/vector schemas,
duplicate keys, unsupported backends, invalid digests, missing canonical bytes,
or non-reproducible composites fail local validation. This Wave neither queries
live GitHub state nor treats repository fixtures as production attestation.

**Tests:** Pure local golden-vector/profile tests; no external APIs, subprocesses,
signing keys, conformance command, payments, or secret-bearing fixtures.

**Test spec:**

- Reproduce both golden composites from semantic objects and exact canonical
  bytes.
- Permute input key order and whitespace and prove invariance; mutate profile,
  repository, backend, either component digest, case, or value and prove change.
- Reject duplicate keys, including nested profile and vector keys, and reject
  malformed schemas or incomplete backend coverage.
- Assert the active schema-v6 contract and checker remain outside Wave 1.

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

- Changing live GitHub environments, runner groups, reviewers, or secrets.
  Wave 1 is repository-only and neither requires nor authorizes a deployed
  verifier, live inspection, immutable deployment digest, or signed evidence.
- Executing LND/Breez payments or treating fake adapters as production evidence.
- Wave 3 candidate aggregation, Wave 5 checkpoint advancement, deployment, or
  release publication; those begin only after Wave 2 independently passes.
- Reworking the already-reviewed candidate approval, sandbox, result signature,
  or durable-ledger designs unless a targeted regression test exposes a defect.

## Security Considerations

Wave 2 preserves the separation between the committed audit, which defines the
reviewed expected state, and its signed attestation input. Golden vectors keep
the local checker from silently adopting an ambiguous digest meaning. A deployed
verifier producing freshly observed state is production hardening deferred until
actual payment enablement. The composite binds both the backend-specific
environment and shared runner group, is versioned to prevent ambiguous
canonicalization, and remains covered by the existing Ed25519 signature.
Duplicate-aware decoding prevents last-key-wins ambiguity. Tests use ephemeral
keys and synthetic redacted data only; failure output never echoes signed
payloads or infrastructure identifiers.

## Failure Modes Summary

| Codepath | Failure Mode | Handled In | Tested? |
| --- | --- | --- | --- |
| Production verifier rollout | Live attestation lacks v1 profile, trusted signature, freshness, or vector parity | Deferred until production payment enablement | No — intentionally outside Wave 1 |
| Audit parsing | Duplicate key, missing backend, extra field, malformed digest | W2-01 duplicate-aware exact schema validation | Yes |
| Composite derivation | Wrong backend or profile ambiguity | W1-01 vectors + W2-01 canonical helper | Yes |
| Live comparison | Environment or runner-group drift | W2-01 exact signed composite equality | Yes |
| Signature/freshness | Missing, invalid, stale, revoked, or wrong-purpose signer | Existing checker retained and regression-tested in W2-01 | Yes |
| Workflow precondition | Checker failure bypasses runner guard | Existing ordering plus W2-01 structural regression test | Yes |
| Test environment | `pytest` unavailable or dependency bootstrap fails | Qualification blocks; isolated dev bootstrap in W2-01 | Yes |
| Packaging boundary | Canary binary leaks into normal artifact | W2-01 locked/offline artifact inspection fails | Yes |

## Architect Review Findings

### Auto-Incorporated

- Kept Wave 1 profile/vectors non-active so schema-v6 remains coherent, then
  moved schema-v7 activation atomically beside checker enforcement in Wave 2.
- Defined the exact five-field v1 canonical object and new versioned attestation
  claims; legacy attestations fail closed under contract schema v7.
- Required duplicate-aware JSON parsing across every security-sensitive input.
- Replaced contradictory key-order rejection with positive canonicalization
  invariance and semantic-mutation tests plus shared golden vectors.
- Named the exact locked/offline Cargo build and temporary target isolation used
  to prove the qualification binary is absent from normal artifacts.

### Deferred

- Live GitHub configuration mutations, deployed-verifier rollout, live
  attestation, and paying protected-runner smoke remain production-hardening
  work until actual production payment enablement; none block Wave 1.

## Confidence Assessment

| Dimension | Score | Source | Notes |
| --- | --- | --- | --- |
| Requirements | 0.95 | Original W2-01 plan, final reviewer, architect | Wave boundaries and checker gate are explicit |
| Architecture | 0.94 | Existing attestation/audit split + delta review | Non-active profile then atomic activation preserves coherence |
| Codebase fit | 0.92 | Existing checker, audit, contract, and tests | Adds local profile/vector artifacts without new infrastructure |
| Testability | 0.94 | Ephemeral signatures, golden vectors, offline Cargo | Wave 1 is fully repository-local; Wave 2 retains targeted validation |
| Security | 0.93 | Signed Wave 2 claims, duplicate-aware parsing, exact digest binding | Trust anchors and redacted outputs are explicit |
| Migration | 0.91 | Architect-reviewed Wave 1-to-Wave 2 sequencing | Active v6 remains coherent until atomic v7 activation |
| Overall | 0.94 | Weighted assessment | Above confidence gate; production attestation is explicitly deferred |

## Orchestration Playbook

```bash
/greenharbor-orchestrate plans/complete-wave-2-canary-qualification.md --scope "Wave 1"
/greenharbor-orchestrate plans/complete-wave-2-canary-qualification.md --scope "Wave 2"
/greenharbor-orchestrate plans/complete-wave-2-canary-qualification.md
```
