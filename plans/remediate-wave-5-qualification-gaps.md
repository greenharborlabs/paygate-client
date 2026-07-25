# Remediate Wave 5 Qualification Gaps

**Created at:** `f33ad11` on `2026-07-19` | **Mode:** `eng`

## Summary

Wave 5 remains blocked because its Rust compatibility record is copied from
Python oracle material instead of observed from an executed Rust CLI, and
because the protected canary jobs neither execute a payment-capable runner nor
invoke their result validator. This plan replaces both disconnected proofs with
independent, end-to-end evidence paths and adds a machine-enforced Wave 5
candidate aggregate before any qualification report or checkpoint may pass.

The checkpoint at `.orchestrate/rust-cutover-14e6d251.json` remains the source of
truth for the blocked cutover. The current Wave 5 scaffolding is committed at
`f33ad11`; the working tree was clean when this plan was created.

## Existing Code Leverage

- `compat/python_oracle/replay.py` and
  `scripts/extract-python-semantic-evidence.py` already own the independent
  Python side of semantic comparison.
- `tests/oracle_semantic_bridge.rs` is the existing qualification entry point
  and can become a child-process harness around Cargo's compiled `paygate` test
  binary.
- `scripts/check-oracle-semantic-contract.py` already provides exact-case
  comparison, expiring intentional differences, and stale-approval rejection.
- `security/payment-canary-contract.yaml`,
  `scripts/check-rust-canary-contract.py`, and
  `scripts/check-rust-canary-result.py` provide the starting precondition/result
  schemas.
- `.github/workflows/rust-payment-canary.yml` already separates protected
  environments and disables cancellation; it must be connected to a real,
  reviewed execution plane.
- `infra/runners/platform-qualification.yml` establishes a tracked runner
  inventory/audit convention that the payment runners can extend.
- `.github/workflows/rust-platform.yml` and
  `.github/actions/aggregate-rust-platform/action.yml` already produce and
  aggregate four native records; the final candidate validator can consume that
  aggregate rather than replace it.

## Architecture

```text
Python replay -> Python extractor -> independent oracle cases -----------\
                                                                         > semantic validator
compiled paygate child processes -> JSON/exit/state/provenance ----------/

protected GitHub environment + isolated runner group
  -> immutable precondition check
  -> installed digest-pinned runner entrypoint
       -> durable atomic attempt ledger
       -> isolated approved candidate probe (no wallet credentials)
       -> runner-owned invoice/cap/backend submission (LND or Breez)
       -> canonical signed redacted result
  -> unconditional signature/current-run/result validation
  -> retained validated evidence (never the authoritative no-retry ledger)

native aggregate + integration evidence + two canary records
  -> Wave 5 candidate manifest validator
  -> qualification report/checkpoint eligibility
```

The oracle and Rust producers remain independent. The payment-capable runner is
a deployed infrastructure component with tracked source, immutable deployment
digest, durable storage, and a pinned verification key—not a shell fragment
downloaded or supplied by workflow input. GitHub artifacts transport only
validated redacted evidence and never serve as the durable attempt ledger.

## Blast Radius

| Modified File/Interface | Consumers | Covered by Work Unit? |
| --- | --- | --- |
| `scripts/extract-python-semantic-evidence.py` case schema | Semantic comparator and integration workflow | W1-01 |
| `tests/oracle_semantic_bridge.rs` Rust producer | Semantic comparator and integration workflow | W1-01 |
| `scripts/check-oracle-semantic-contract.py` evidence schema | Local contract tests and integration workflow | W1-01 |
| `.github/workflows/rust-integration-qualification.yml` evidence bundle | Candidate aggregate | W1-01, W3-01 |
| `infra/payment-canary-runner/` installed runner package (new) | Protected self-hosted runners | W2-01 |
| `Cargo.toml` feature-gated canary target/default-run | Cargo, native builds, packaging | W2-01 |
| `src/bin/payment_canary.rs` isolated candidate probe (new) | Installed runner entrypoint; excluded from releases | W2-01 |
| `infra/runners/payment-canary.yml` inventory/deployment contract (new) | Precondition validator and infrastructure audit | W2-01 |
| `infra/runners/payment-canary-github-audit.json` settings snapshot (new) | Precondition review and Wave 5 acceptance | W2-01 |
| `security/payment-canary-contract.yaml` attempt/result contract | Runner, both validators, both jobs | W2-01 |
| `security/payment-canary-trust/runner-v1.pub` trust anchor (new) | Result signature validator | W2-01 |
| `.github/workflows/rust-payment-canary.yml` protected control flow | LND/Breez canary environments and candidate aggregate | W2-01, W3-01 |
| `scripts/check-rust-canary-contract.py` preconditions | Both canary jobs | W2-01 |
| `scripts/check-rust-canary-result.py` signed/current-run result | Both canary jobs and final aggregate | W2-01, W3-01 |
| `tests/platform-smoke/test_wave5_qualification_contracts.py` | Local Wave 5 contract gate | W1-01, W2-01, W3-01 |
| `tests/test_package_metadata.py` release artifact selection | Python rollback/release packaging | W2-01 |
| `scripts/check-rust-wave5-candidate.py` cross-gate validator (new) | Final acceptance workflow | W3-01 |
| `.github/workflows/rust-wave5-acceptance.yml` (new) | Wave 5 reviewers/checkpoint | W3-01 |
| `reports/rust-qualification.md` actual evidence index | Wave 5 and release reviewers | W3-01 |

This exceeds eight files because both findings cross producers, validators,
workflows, tests, and an external payment trust boundary. Keeping the runner,
signature trust, and final aggregate implicit would recreate the rejected
scaffolding; production request modules remain unchanged.

## Risk Flags

`security`: yes | `performance`: no | `migration`: no | `public-api`: no | `concurrency`: yes

Security risk comes from payment execution, durable no-retry state, signature
trust, and evidence provenance. Concurrency risk is limited to globally
serializing canary attempts; production request concurrency is unchanged.

## Wave 1: Produce Independent Executable Semantic Evidence

### W1-01: Execute the Rust CLI and compare a shared semantic case contract

Define one versioned, shared case schema in the Python extractor and Rust
producer. The Python extractor projects fresh replay observations into that
schema; independently, the Rust integration harness launches
`env!("CARGO_BIN_EXE_paygate")`, captures actual child stdout/stderr/status, and
inspects isolated post-run state. The Rust producer must never open, embed, or
copy the Python golden/extracted evidence.

Use exact shared case IDs for: a successful JSON command over a private neutral
cache, a deterministic nonzero JSON error, and state observed through the public
CLI boundary. The neutral cache/config inputs are test-owned and specified by
the case contract rather than copied output values. Each Rust record includes
sanitized argv, parsed stdout JSON, exit code, safe stderr classification,
pre/post parsed state, executable SHA-256, full source commit, and `Cargo.lock`
SHA-256. The comparator verifies schema, provenance, required case coverage, and
digest-bound expiring differences.

**Files:** `scripts/extract-python-semantic-evidence.py`,
`tests/oracle_semantic_bridge.rs`,
`scripts/check-oracle-semantic-contract.py`,
`.github/workflows/rust-integration-qualification.yml`,
`tests/platform-smoke/test_wave5_qualification_contracts.py`

**Acceptance criteria:**

- Python extraction and Rust production name the same exact required case IDs
  and fields, but execute independently.
- Every Rust case starts the compiled `paygate` executable and derives JSON,
  state, and exit evidence only from child-process results and private temporary
  files.
- The Rust producer has no include/read/import path to the Python golden replay
  or extracted semantic JSON.
- At least one actual zero exit, one actual nonzero exit, and one public-CLI state
  observation are recorded.
- Workflow-computed binary/source/lock identities exactly match the Rust record.
- The comparator rejects the old fixture projection, missing/extra cases,
  malformed JSON, mismatched exit/state, forged provenance, wildcard or stale
  approvals, and unused approvals.
- The integration workflow retains the independently produced Python and Rust
  records plus comparator result in one immutable, GitHub-attested evidence
  bundle whose subject digest and retention window are recorded for W3-01.

**Error handling:** A child timeout/signal, malformed stdout JSON, unsafe or
unreadable state, unexpected stderr, missing binary, provenance mismatch,
extractor mismatch, or evidence write failure exits nonzero and leaves Wave 5
blocked. Diagnostics reveal classifications only, not credentials, invoices,
hashes, preimages, raw state, or secret-bearing paths.

**Tests:** Rust integration tests for child execution; Python black-box tests for
extractor/comparator schema, independence, rejection behavior, and workflow
wiring.

**Test spec:**

- Run `paygate credentials show ... --cache-path <private-temp>` through the
  compiled child and assert parsed redacted JSON, real status, and independently
  read post-run cache state are recorded.
- Run a deterministic failing command and assert its actual parsed error envelope
  and nonzero child status are recorded, not constants.
- Extract fresh Python replay cases and compare them with the executed Rust cases,
  using only explicit intentional-difference entries where semantics differ.
- Mutate provenance, one case ID, stdout JSON, state, exit, and approval expiry
  separately; each must fail.
- Run the full bridge with `CARGO_NET_OFFLINE=true cargo +1.88.0 test --locked
  --offline --test oracle_semantic_bridge`, then run the comparator and artifact
  bundle check.
- Mutate the integration bundle subject digest/attestation or present it after
  retention expiry; candidate ingestion must reject it.

## Wave 2: Build and Connect the Protected Canary Execution Plane

### W2-01: Deploy one atomic runner-to-validator control flow

Treat runner implementation, GitHub protection, payment execution, durable
ledger behavior, signed result validation, and workflow wiring as one atomic
trust-boundary unit. Platform Engineering owns the tracked runner package in
`infra/payment-canary-runner/`; it is built, reviewed, deployed under an
immutable digest, and installed at one absolute root-owned entrypoint recorded
in `infra/runners/payment-canary.yml`. The workflow may invoke only that fixed
path. The candidate repository supplies a feature-gated `payment_canary` probe
whose exact source/lock/binary attestation is separately approved after native
qualification. The runner executes it without wallet credentials in a restricted
sandbox and treats every output as untrusted. The digest-pinned runner—not the
candidate probe—owns invoice creation, independently enforces the immutable cap,
submits through LND/Breez, verifies the backend result, and returns structured
status. Candidate output can cause only a bounded request to the trusted runner;
it cannot select credentials, raise a cap, submit directly, or sign evidence.

Declare the second binary explicitly in `Cargo.toml` behind a qualification-only
feature, preserve `default-run = "paygate"`, and prove normal build/package/release
commands contain only the public `paygate` binary. The canary probe is never part
of Wave 6 release artifacts.

Before job wiring is enabled, configure and audit both protected environments,
required reviewers, deployment branch/tag restrictions, isolated runner groups,
immutable backend labels, authorized administrators, and secret placement.
Commit a redacted baseline snapshot containing resource IDs/configuration
digests—not secrets. At each canary run, a trusted infrastructure verifier must
query the live GitHub API and emit a short-lived signed attestation covering the
environment reviewers, branch restrictions, runner-group repository access,
labels, and current configuration digest. The precondition checker validates
that live attestation against the inventory/contract and rejects stale snapshots
or drift. If the runner deployment or GitHub settings cannot be freshly
inspected, stop W2-01; do not replace them with a fake or hosted-runner PASS.

The installed runner atomically claims an attempt key
`source_commit:cargo_lock_sha256:backend:workflow_run_id` in independently
durable storage before invoice creation. It records unsubmitted release,
definite failure, success, or submitted-unknown-permanent-no-retry and never
reclaims an ambiguous attempt. It emits a restricted canonical JSON payload and
detached Ed25519 signature. The contract pins key ID/public key, validity window,
issuer/runner identity, canonical byte rules, and rotation/revocation behavior;
signature fields are excluded from signed payload canonicalization.

Each backend job validates preconditions, invokes the fixed entrypoint once, and
then validates a result whenever invocation occurred—even when the runner exits
nonzero. Shell flow captures runner status instead of allowing `set -e` to skip
validation. `check-rust-canary-result.py` verifies the signature and equality to
job-computed backend, source, lock, run ID, runner identity, cap, invoice/payment
hash binding, spend+fee, durable proof, redaction, and terminal state. Only
`succeeded` passes; validated failure/ambiguous records may be retained redacted
for incident review, then the job fails. Missing or invalid result also fails.

Reject dispatches with both approval booleans true and place both jobs in one
shared `paygate-payment-canary` concurrency group with
`cancel-in-progress: false`, so cross-backend payment attempts cannot overlap.
Keep wallet secrets inside the isolated self-hosted runner; workflow inputs and
repository variables never carry secrets, commands, invoices, or preimages.

**Files:** `infra/payment-canary-runner/` (new),
`Cargo.toml`, `src/bin/payment_canary.rs` (new),
`infra/runners/payment-canary.yml` (new),
`infra/runners/payment-canary-github-audit.json` (new),
`security/payment-canary-contract.yaml`,
`security/payment-canary-trust/runner-v1.pub` (new),
`.github/workflows/rust-payment-canary.yml`,
`scripts/check-rust-canary-contract.py`,
`scripts/check-rust-canary-result.py`,
`tests/platform-smoke/test_wave5_qualification_contracts.py`,
`tests/test_package_metadata.py`

**Acceptance criteria:**

- The runner package source, owner, immutable build/deployment digest, absolute
  entrypoint, rollback digest, runner labels/groups, durable ledger authority,
  and availability state are tracked and independently reviewable.
- GitHub environment protection and runner-group isolation are configured, then
  verified from live API state by a short-lived signed infrastructure attestation
  before payment capability is enabled; the committed snapshot alone cannot pass.
- Both jobs run only on matching isolated self-hosted runners after matching
  protected-environment approval and invoke no dynamic/downloaded command.
- A durable attempt claim exists before invoice creation; ambiguous submission
  is permanently non-retriable under the attempt identity.
- The candidate probe digest is source/lock/attestation-bound and explicitly
  approved, runs without wallet credentials, and cannot submit or raise limits;
  the installed runner independently owns cap checks and backend submission.
- `payment_canary` is an explicit qualification-feature-only Cargo target,
  `paygate` remains the default/normal binary, and packaging tests prove the
  canary target is absent from normal release artifacts.
- Both jobs call the result validator after every runner invocation, including a
  nonzero runner exit, and cannot report success when validation is absent,
  skipped, invalid, or non-success.
- The validator checks an Ed25519 signature over the exact canonical restricted
  payload using a non-revoked key valid for the record time and matching the
  configured issuer/runner identity.
- Result fields exactly match current checkout/job facts; copied cross-run,
  cross-backend, stale-source, stale-lock, arbitrary-digest, temporary-ledger,
  cap-overflow, hash-mismatch, extra-field, and non-success records fail.
- Selecting both backends is rejected before either job starts, and the shared
  concurrency group prevents simultaneous LND/Breez attempts across runs.
- No wallet secret, raw invoice, preimage, credential, or unvalidated result is
  logged or uploaded.

**Error handling:** Configuration/identity/signature/ledger failures, a stale or
invalid live infrastructure attestation, an unapproved candidate digest, or
sandbox escape before invocation create no invoice. Candidate requests that
exceed the runner-owned cap or attempt direct backend access are refused before
submission. After invocation, the workflow always attempts safe result
validation; missing/malformed results and validator crashes fail.
Definite pre-submission failure releases only an unsubmitted claim. Submitted
unknown persists permanent no-retry and requires incident review. Rollback may
restore the prior runner package digest but never deletes ledger history or
retries an attempt.

**Tests:** Unit/property tests for the runner ledger and canonical payload;
non-paying conformance tests against fake LND/Breez boundaries; candidate
sandbox/cap-bypass tests; Cargo target and release-packaging tests; signature/key
rotation/revocation tests; live-infrastructure-attestation tests; Python
black-box validators; parsed workflow tests; and a protected-runner deployment
smoke that cannot submit value.

**Test spec:**

- Race two processes for the same attempt key and prove exactly one claim before
  the fake invoice marker; repeat after ambiguous state and prove both refuse.
- Simulate runner zero/nonzero/crash/timeout outcomes and assert validation runs
  after every actual invocation, with only a valid signed `succeeded` payload
  passing the job.
- Sign a canonical fixture, then mutate each field, signature, key ID, validity,
  issuer, or canonical encoding; all mutations fail without echoing values.
- Audit environment reviewers/branch rules and runner-group repository access;
  missing, stale, unsigned, drifted, or broader-than-declared live settings fail
  before invoice creation.
- Give the candidate probe forged cap/backend/credential requests and direct
  network access attempts; the sandbox and runner-owned policy must prevent
  submission. Assert the same binary is excluded from ordinary build/package
  artifacts and `cargo run` still selects `paygate`.
- Assert both workflow jobs order checkout, identity computation, precondition
  validation, one fixed entrypoint invocation, unconditional result validation,
  and validated-only evidence retention.
- Attempt dispatch with both booleans true and overlapping separate runs; prove
  rejection/serialization occurs before either candidate executable starts.

## Wave 3: Aggregate and Execute Wave 5 Qualification

### W3-01: Require one machine-validated candidate before acceptance

Create a Wave 5 candidate manifest and offline validator covering the integration
bundle, four-record native aggregate, separately approved LND result, and
separately approved Breez result. The acceptance workflow receives explicit
source run IDs, downloads artifacts with read-only Actions permission, verifies
GitHub attestations/signatures and retention availability, and recomputes every
digest. It must prove all records share the requested source commit and
`Cargo.lock` hash while preserving their distinct workflow run IDs, target,
backend, runner, and schema identities. A report is an index of this passing
manifest, never the acceptance mechanism.

After local negative tests pass, run the non-paying integration gate and four
native legs for one unchanged source/lock identity. Then obtain separate explicit
approval and dispatch only LND; after it finishes and validates, separately
approve/dispatch only Breez. Never retry an ambiguous attempt. Run the candidate
acceptance workflow with those exact evidence IDs. Update the qualification
report only after its validator passes; Wave 5 remains blocked until independent
integration/security review accepts the complete manifest.

**Files:** `.github/workflows/rust-integration-qualification.yml`,
`.github/workflows/rust-payment-canary.yml`,
`.github/workflows/rust-wave5-acceptance.yml` (new),
`scripts/check-rust-wave5-candidate.py` (new),
`tests/platform-smoke/test_wave5_qualification_contracts.py`,
`reports/rust-qualification.md`

**Acceptance criteria:**

- Integration and canary workflows retain validated, redacted, immutable
  evidence bundles with documented retention; the native aggregate remains
  consumable by explicit run ID.
- The candidate validator requires exactly one integration record, four native
  targets, one LND success, and one Breez success; no skipped, failed, stale,
  ambiguous, duplicate, or unknown record is accepted.
- Every record matches the requested source/lock identity and its own expected
  schema, workflow run, target/backend, runner, digest, and attestation/signature.
- The acceptance workflow uses read-only checkout/artifact permissions, rejects
  unavailable/expired artifacts, and emits a final candidate manifest digest.
- Actual integration, four-target native, LND, and Breez jobs execute; source or
  gate-logic changes invalidate only dependent evidence, while source/lock
  changes invalidate the entire candidate.
- `reports/rust-qualification.md` links exact run IDs/URLs and manifest digest,
  distinguishes local/native/integration/live evidence, and makes no fabricated
  or source-only PASS claims.
- Final integration and security reviewers accept the manifest before the
  orchestration checkpoint changes from blocked.

**Error handling:** Artifact absence/expiry, schema mismatch, stale/cross-run
identity, bad attestation/signature, non-success state, or validator crash fails
acceptance. Infrastructure failures preserve unrelated immutable evidence but
never become a PASS. Submitted unknown remains permanent no-retry and blocks the
candidate.

**Tests:** Offline table-driven candidate-validator tests, least-privilege
workflow structural tests, actual native/integration/canary runs, and final
independent integration/security review.

**Test spec:**

- Build a valid local candidate fixture, then remove/duplicate/swap each required
  record and mutate every source/lock/run/schema/target/backend/digest/trust
  field; each variant fails.
- Verify the acceptance workflow cannot substitute current-run artifacts for an
  explicitly named source run or access write/payment permissions.
- Dispatch integration/native qualification for one commit, dispatch only one
  protected canary at a time, then run final acceptance with their exact IDs.
- Run the focused offline semantic/advisory/canary/candidate validators and
  `git diff --check` as supporting—not substitutive—evidence.

## NOT in Scope

- Wave 6 packaging, migration, rollback, prerelease, or promotion.
- Fabricating native, protected-runner, payment, signature, or canary evidence.
- Changing production CLI semantics merely for byte-identical Python output;
  approved semantic differences use the reviewed registry.
- Storing wallet secrets in GitHub inputs, repository variables, artifacts, or
  result records.
- Retrying or auto-recovering an ambiguous payment.

## Security Considerations

The Rust producer and Python oracle are separate evidence trust domains. The
runner is the payment trust domain: its fixed deployed code owns wallet
credentials, invoice creation, independent cap enforcement, backend submission,
durable attempts, result verification, and signing. The feature-gated candidate
probe is untrusted, separately attested/approved, sandboxed, and credential-free.
GitHub coordinates approvals and transports validated records but owns neither
wallet secrets nor the authoritative ledger. Trust keys require explicit
validity, rotation, and revocation; environment and runner-group settings require
fresh signed live-state evidence because YAML names and committed snapshots alone
do not enforce protection.

## Performance Considerations

Semantic child processes are manual qualification-only and have short timeouts.
One shared canary concurrency group serializes all payment attempts with
cancellation disabled. Candidate aggregation is linear over seven small records
and is not a production hot path.

## Failure Modes Summary

| Codepath | Failure Mode | Handled In | Tested? |
| --- | --- | --- | --- |
| Python/Rust semantic schema | Missing case or producer coupling | W1-01 shared schema/independence | Yes |
| Rust child execution | Timeout, malformed JSON, false exit/state | W1-01 fail-closed harness | Yes |
| Runner infrastructure | Undeployed/unreviewed entrypoint or weak GitHub settings | W2-01 prerequisite audit | Yes |
| Durable attempt | Race or submitted-unknown retry | W2-01 atomic ledger | Yes |
| Signed result | Forged/stale/cross-run/cross-backend evidence | W2-01 signature/current-job validator | Yes |
| Workflow control | Validator skipped after nonzero exit or overlapping canaries | W2-01 captured status/shared concurrency | Yes |
| Final qualification | Missing native/integration/canary run | W3-01 candidate validator | Yes |

## Architect Review Findings

### Auto-Incorporated

- Added the Python extractor to the shared semantic schema work and required
  fresh replay coverage for every Rust case.
- Made the payment runner, durable ledger, bounded Rust executor, deployment
  digest/rollback, and GitHub protection audit explicit parts of one atomic
  work unit.
- Defined canonical signed payloads, a pinned Ed25519 trust anchor, key
  validity/rotation/revocation, and negative signature tests.
- Merged runner execution and result validation into one unit and required
  validation after both zero and nonzero runner exits.
- Enforced cross-backend serialization and rejection of dual-backend dispatches.
- Added a machine-enforced cross-gate candidate manifest/validator before report
  or checkpoint acceptance.
- Moved wallet access, invoice creation, cap enforcement, and submission wholly
  into the digest-pinned runner; the candidate probe is sandboxed, separately
  attested/approved, credential-free, and excluded from release artifacts.
- Replaced reliance on a committed GitHub settings snapshot with fresh signed
  live-state verification for every canary run.
- Added an attested integration bundle and its subject/retention verification.

### Resolved with User Input

None.

### Deferred

None.

## Confidence Assessment

| Dimension | Score | Source | Notes |
| --- | --- | --- | --- |
| Architecture | HIGH | Discovery + architect delta | Three dependency-ordered waves now cover both producers, the protected execution plane, and final aggregate without parallel write conflicts. |
| Error Handling | HIGH | Architect delta | Pre-submit refusal, unconditional post-invocation validation, submitted-unknown permanence, signature failure, drift, and artifact failure are named and tested. |
| Test Strategy | HIGH | Architect delta | Child-process, schema mutation, race, sandbox, signature, workflow, infrastructure-audit, packaging, and operational evidence tests cover each boundary. |
| Data Flow | HIGH | Plan trace | Happy/error paths are explicit from independent producers and protected runner through final candidate validation. |
| Security | MEDIUM | Architect delta + incorporated fixes | Wallet access and cap enforcement are runner-owned; remaining risk is inherent in deploying and operating payment-capable protected infrastructure and is gated by live attestation and independent review. |
| Performance | HIGH | Bounded qualification path | Manual child processes are timeout-bounded, canaries are globally serialized, and aggregation is linear over seven small records. |

**Gate:** Passed round 2. All critical findings are resolved in the plan and all
dimensions are at least MEDIUM. Passing this planning gate does not unblock Wave
5; only W3-01's actual machine-validated evidence and final reviews can do that.

## Orchestration Playbook

```bash
/greenharbor-orchestrate plans/remediate-wave-5-qualification-gaps.md --scope "Wave 1"
/greenharbor-orchestrate plans/remediate-wave-5-qualification-gaps.md
```
