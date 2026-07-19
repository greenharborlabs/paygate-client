# Correct Wave 2 Acceptance Gaps

**Created at:** `bd06fc7` on `2026-07-19` | **Mode:** `eng`

## Summary

Repair the actionable Wave 2 acceptance gaps while explicitly retiring the
exhausted W1-01 Python-oracle expansion. The Python bundle remains the coherent
37-case frozen baseline; Rust owns all new payment-proof, adapter, submission,
and CLI acceptance criteria. After local acceptance passes, stop for explicit
approval before commit or push; only a pushed branch may supply live four-target
evidence.

This companion plan preserves `plans/enable-validated-bolt11-decoding-via-rust-cutover.md` and the already-passing historical-commit, 46-wheel offline-closure, deterministic-replay, dependency, interface, fallback, linkage, formatting, license, and workflow checks.

## Existing Code Leverage

- `compat/python_oracle/probes.py` already runs the frozen `f56cbd0` CLI and state primitives under deterministic controls; extend its probes rather than inventing a second harness.
- `compat/python_oracle/inject/oracle_pytest.py` and `sitecustomize.py` already make uncontrolled network, subprocess, and keyring access fatal; backend doubles should enter through these established injection seams.
- `compat/fixtures/backends.json`, `controls.json`, and `keyring.json` already provide fail-closed fixture books and deterministic values.
- `tests/test_cli.py`, `tests/test_config.py`, `tests/test_diagnostics.py`, `tests/test_policy.py`, and payer tests at the frozen commit contain public behavioral cases for CLI output, precedence, backend invocation, and reservation transitions.
- `src/payers/base.rs::verify_payment_result` is already the common proof verifier, so it can remain the sole constructor of `VerifiedPaymentResult` while read-only accessors preserve consumers.
- `scripts/check-rust-licenses.py` already validates SPDX expressions and fails closed on unknown missing metadata; only its missing-license exception key needs to become exact.
- `.github/workflows/rust-platform.yml` and `.github/actions/aggregate-rust-platform/action.yml` already demonstrate target-bound artifact evidence and fail-closed completeness checks; reuse that pattern for the full Rust qualification workflow.
- `.github/workflows/rust-qualification.yml` already defines the four full native qualification legs; extend and locally review its evidence path before the approval-gated push.

## Architecture

The correction separates contracts the rejected evidence conflated. The frozen Python checkout records only historically observable public behavior; Rust-only cancellation/submission guarantees are intentional security deltas owned by later implementation tests. Untrusted Rust `RawPaymentResult` values cross into a field-private `VerifiedPaymentResult` only through `verify_payment_result`. Local tests validate the native-evidence schema and aggregate logic before approval; after a push, four GitHub runners populate that schema with live results.

## Blast Radius

| Modified File/Interface | Consumers | Covered by Work Unit? |
| --- | --- | --- |
| `compat/python_oracle/probes.py` | oracle replay and golden evidence | W1-01 |
| `compat/python_oracle/inject/oracle_pytest.py`, `sitecustomize.py` | detached frozen test/probe process | W1-01 |
| `compat/fixtures/backends.json`, `controls.json`, `keyring.json` | deterministic oracle inputs | W1-01 |
| `compat/manifest.yaml`, parent plan/decision, golden evidence, oracle tests/README | historical-versus-target compatibility contract and reviewers | W1-01, W2-01 |
| `src/payers/base.rs` public verified-result API | payer adapters, credential construction, later Wave 3/4 units | W1-02 |
| `tests/interface_contract.rs` | compile contract and later Rust consumers | W1-02 |
| `reports/rust-qualification.md` | consolidated qualification reviewers | W2-01 |
| `scripts/check-rust-licenses.py` | Cargo metadata policy and CI dependency gate | W1-03 |
| `plans/decisions/rust-cutover-dependencies.md` | dependency decision and license audit | W1-03 |
| `.github/workflows/rust-qualification.yml`, qualification evidence validator/action | four native runners, target evidence, and aggregate check | W1-04, W3-01 |
| qualification evidence scaffold tests | local missing/tampered/stale/incorrect-target rejection | W1-04, W2-01 |

The Python unit spans several existing oracle artifacts because evidence, manifest pointers, fixtures, and self-tests form one atomic trust boundary. Splitting them would create intermediate states where claims and observations disagree.

## Risk Flags

`security`: yes | `performance`: no | `migration`: no | `public-api`: yes | `concurrency`: yes

- Security/public API: proof construction and payer-submission evidence are trust boundaries.
- Concurrency: the plan must not infer pre/post-submission timing the synchronous Python baseline cannot expose; Rust-specific timing semantics remain later implementation contracts.
- No production payer implementation, state migration, release, or payment is authorized by this plan.

## Wave 1: Correct the Six Local Defects

The four units are independent and may run in parallel. Preserve all currently passing evidence and do not touch generated `target/` output except through normal test commands.

### W1-01: Retire the attempted Python-oracle expansion

W1-01 exhausted its permitted implementation/review cycles without producing a
coherent manifest, replay contract, or golden evidence set. Do not continue
repairing or expanding it. Restore and retain the last coherent 37-case
baseline from `f56cbd0`; treat it as frozen legacy compatibility coverage and a
rollback reference only.

The transition decision in
`plans/decisions/python-oracle-transition-boundary.md` is authoritative: the
synchronous Python process cannot prove submission timing or a typed
cancellation state. Rust tests must prove `BeforeSubmission` rollback,
`AfterSubmissionUnknown` retention, payment-proof binding, adapter negative
cases, configuration precedence, backend `pay-invoice`, deterministic
redaction/replay evidence, and new CLI behavior.

**Files:** Restore the existing `compat/` baseline; retain the transition
decision and frozen-oracle README. No new Python manifest cases, fixtures,
probes, replay rules, or golden evidence are authorized.

**Replacement acceptance criteria:**

- The Python oracle validates and replays its existing 37-case baseline without
  changes to historical evidence.
- Python is not cited as evidence for Rust-only security deltas or new Rust
  behavior.
- Rust unit, integration, adapter, CLI, and qualification tests own all new
  acceptance criteria listed above.

The detailed criteria below are retained only as the rejected W1-01 record;
they are not acceptance gates for this plan.

**Acceptance criteria:**

- Each backend fixture is consumed only by an injected Breez, LND REST, Phoenixd, or test-mode public call; evidence records redacted request-match fields, selected response/failure, call count, and unmatched/unused fixture failures from that call path.
- Success, caught payer failure, and an interruption escaping the synchronous payer call execute the frozen orchestrator/policy boundary and record actual payer call markers, exception/envelope, and ledger bytes; no historical case directly invokes `reserve`, `commit`, or `rollback` as the behavior under test.
- The reconciliation decision states that `f56cbd0` exposes neither a pre/post-submission marker nor a cancellation type. It records the baseline's genuinely ambiguous interruption behavior and maps Rust `BeforeSubmission` rollback and `AfterSubmissionUnknown` retention to `intentional_security_delta` cases owned by later Rust adapter/integration work.
- Rust-only delta cases have no Python observation pointer and cannot make Wave 2 oracle acceptance green through synthetic ledger operations; the parent plan and manifest use the same classification and later owner.
- Config cases state actual precedence field-by-field: YAML selects backend/settings and names environment references; `voltage-env.sh` supplies referenced variables; ambient environment overrides same-name companion exports. CLI fee/path/profile options are captured separately as runtime inputs, not generic YAML overrides.
- CLI evidence contains exact args, exit status, stdout, stderr, exception class, redaction assertions, and the claimed JSON envelope for request/fetch and diagnostics behavior.
- Dedicated manifest cases cover `credentials list`, filtered `credentials purge` with nonmatching entries retained, successful and failed `backend pay-invoice`, and existing show-found/show-missing behavior.
- Every evidence pointer resolves to the observation that proves its contract; generic fixture/control inventories cannot stand in for behavioral evidence.
- The case count and golden hash are intentionally updated, and two clean network-disabled replays still execute all frozen tests with byte-identical evidence.

**Error handling:** Unmatched or unused backend calls, uncontrolled network/keyring/subprocess access, a historical claim unsupported by a public observation, a Rust delta assigned to Python evidence, missing output, secret leakage, unresolved pointers, or changed unrelated golden behavior fails the oracle. Do not patch `f56cbd0`, normalize its behavior, or hand-author observations.

**Tests:** Extend oracle self-tests, replay validation, per-adapter fixture-consumption tests, CLI golden assertions, and historical payer/ledger observations against the detached frozen checkout.

**Test spec:**

- For each of Breez, LND REST, Phoenixd, and test mode, inject one success through that adapter's public SDK/HTTP/local payer seam and assert one redacted matched call; independently mutate a required request field and add an unused fixture, and assert both fail closed. Require CLI `backend pay-invoice` to consume one of these same call records.
- Invoke frozen orchestration with a recording payer for success, a caught `PayerError`, and an escaping interruption. Assert only markers and ledger outcomes the baseline exposes; separately assert the manifest classifies explicit Rust pre/post-submission semantics as later deltas without Python observation pointers.
- Load LND YAML whose referenced values exist in both `voltage-env.sh` and ambient environment and assert ambient wins; omit one ambient value and assert the companion file supplies it. Separately invoke CLI fee/profile/path flags and record downstream runtime arguments without calling them YAML overrides.
- Seed two cached credentials, run `credentials list`, purge one by host/service, run list again, and assert exact redacted JSON while the nonmatching credential remains.
- Invoke `backend pay-invoice` once with a verified fixture result and once with a missing/mismatched preimage; assert exact exit/output bytes and one injected backend call per case.

### W1-02: Seal verified Rust payment proofs behind the common verifier

Make `VerifiedPaymentResult` impossible to construct or mutate through public fields while keeping the frozen type path and read-only consumer access stable. Add a compile-fail contract proving external code cannot forge proof-bearing results.

**Files:** `src/payers/base.rs`, `tests/interface_contract.rs`

**Acceptance criteria:**

- All `VerifiedPaymentResult` fields are private outside `payers::base`; public access is through read-only accessors returning values or immutable references.
- `verify_payment_result` is the only production constructor and still verifies `Succeeded`, invoice amount, invoice payment hash, preimage length, and `sha256(preimage) == payment_hash` before construction.
- No public `new`, `Default`, conversion from `RawPaymentResult`, serde deserialization, or other safe construction route can bypass verification.
- Dependency-free Rustdoc `compile_fail` examples prove a downstream struct literal and field mutation are rejected, while runtime contract tests prove accessors expose the verified values; this unit does not alter `Cargo.toml` or `Cargo.lock`.
- The established `payers::base::VerifiedPaymentResult` export path and `RealPayer` signature remain unchanged for later waves.

**Error handling:** Non-success outcomes or absent/malformed/mismatched proof material remain typed verification failures and never return a partially verified value. If sealing requires changing an already-frozen signature or export path, stop and amend the parent plan instead.

**Tests:** Rustdoc compile-fail API-boundary tests, integration compile-contract tests, and verifier positive/negative tests under Rust 1.88.0 with `--locked` and network disabled.

**Test spec:**

- Compile an external fixture that attempts `VerifiedPaymentResult { ... }` and assignment to an accessor-backed field; require private-field compiler errors.
- Pass a valid signed invoice and matching raw success to the verifier and assert every accessor; independently vary outcome, amount, hash, preimage, and preimage length and assert no verified value is produced.

### W1-03: Bind missing-license exceptions to exact Cargo identities

Replace the current source-plus-name and broad-version exception logic with an explicit allowlist of exact `(package, version, source)` tuples derived from the locked graph and recorded dependency decision.

**Files:** `scripts/check-rust-licenses.py`, `plans/decisions/rust-cutover-dependencies.md`

**Acceptance criteria:**

- A package lacking license metadata is accepted only when its exact name, exact version, and exact normalized Cargo source tuple is enumerated.
- The exception list contains no set-wide version shortcut, wildcard, source-only allowance, or acceptance based on any two tuple members.
- The exception allowlist is exactly equal to the set of unlicensed `(name, version, source)` identities in checked-in `Cargo.lock`/`cargo metadata --locked --all-features`; every tuple is documented with its reviewed upstream license basis in the ADR.
- Table-driven self-tests mutate name, version, source revision/index, and license independently for every allowlisted tuple and require fail-closed rejection.
- Existing valid SPDX expressions continue to pass and invalid/unapproved expressions continue to fail.

**Error handling:** Missing tuple members, duplicate/conflicting exception entries, stale exceptions absent from metadata, new unlicensed packages, source drift, or unparsable SPDX data fails qualification with the full package identity in the diagnostic.

**Tests:** License-script self-tests plus full locked Cargo metadata validation; CI dependency-policy command remains unchanged unless needed to check stale exceptions.

**Test spec:**

- Iterate every exact allowlisted tuple, accept it unchanged, alter each tuple component one at a time, and assert `unclassified missing license metadata` includes name, version, and source.
- Add a stale exception to a test allowlist and assert the metadata completeness check rejects it rather than silently carrying dead policy.

### W1-04: Add immutable evidence to the full Rust qualification workflow

Adapt the tested `rust-platform.yml` evidence pattern to `.github/workflows/rust-qualification.yml`. Each full native leg must emit a non-secret record of the Breez, OS-keyring, offline-build, linkage, and runtime checks, then feed an aggregate validator requiring exactly four successful records bound to one source and lockfile.

**Files:** `.github/workflows/rust-qualification.yml`, `.github/actions/aggregate-rust-qualification/action.yml` (new), `tests/platform-smoke/test_rust_qualification_evidence.py` (new)

**Acceptance criteria:**

- Every native leg emits one JSON record containing schema version, target triple, source commit, full `Cargo.lock` SHA-256, runner identity, run ID/attempt, binary SHA-256, observed architecture/OS/runtime floor, and named outcomes for Breez lifecycle, native keyring, locked offline build, linkage, and CLI runtime checks.
- Records contain no credential, mnemonic, API key, macaroon, preimage, wallet path, raw upstream body, or unrestricted command output.
- The workflow uploads each record as a target-named artifact and the aggregate job validates exactly the four supported targets; all records share source commit and lock hash and match the current run.
- The validator rejects missing, duplicate, malformed, stale/future, failed/skipped/timed-out, wrong-target, wrong-run, mixed-commit, mixed-lock, invalid-hash, missing-check, or unexpected-target evidence.
- `qualification-gate` depends on dependency policy, all native legs, and successful evidence aggregation; `if: always()` cannot neutralize a failed or absent prerequisite.
- Local tests execute the actual aggregate logic with a complete synthetic four-record set and every rejection mutation; structural checks prove evidence creation occurs only after all named checks and action pins remain immutable.

**Error handling:** Failure before a successful record, inability to identify/hash the binary or platform, artifact transfer failure, schema drift, mixed identities, or a named check not equal to success fails the aggregate gate. Evidence contains only status/identity metadata and never serializes secrets or raw backend responses.

**Tests:** Hermetic aggregate-validator tests, workflow structural tests, action/shell lint, injected missing/tampered record tests, and existing Rust platform scaffold regression tests.

**Test spec:**

- Run the real validator locally against four valid fixtures, remove each target in turn, and mutate every identity/status/check field; require nonzero exit with the rejected target/field named.
- Inspect workflow structure and assert a leg cannot write `status: success` before Breez, native keyring, offline build, linkage, and runtime commands finish; assert the final gate needs evidence aggregation.
- Seed evidence with sentinel secret-shaped fields and assert schema validation rejects unknown/sensitive fields while diagnostics do not echo their values.

## Wave 2: Re-run Withheld Local Acceptance Gates

### W2-01: Prove the correction without weakening prior evidence

Run the complete local Wave 2 verification from clean state, then repeat the specialist acceptance cycle that previously rejected the work. This unit changes reports or generated evidence only when those outputs are direct results of the verified commands.

**Files:** `compat/python_oracle/golden/evidence.json`, `reports/rust-qualification.md`, local review artifacts produced by `/greenharbor-orchestrate`; all Wave 1 files as read-only verification inputs

**Acceptance criteria:**

- The historical commit still verifies across all 75 blobs, the 46-wheel closure installs offline, and two clean network-disabled oracle runs execute the full frozen suite and produce byte-identical output.
- Oracle acceptance confirms actual historical payer/ledger observations, honest separation of Rust-only cancellation deltas, per-adapter fixture-driven calls, field-specific config behavior, exact CLI evidence, credentials list/purge, and backend pay-invoice cases.
- Rust acceptance confirms unforgeable verified results, exact package/version/source missing-license exceptions, and locally executable four-target evidence completeness/tamper checks.
- All previously passing Rust dependency, interface, fallback, linkage, formatting, license, and workflow-focused local checks remain green; `git diff --check` passes.
- Mandatory Python-oracle and Rust-qualification reviewers return no critical or important acceptance finding; only then run and pass aggregate verification and the final specialist review.
- The work remains uncommitted and unpushed at the end of this wave.

**Error handling:** Any regression, nondeterminism, skipped mandatory check, unresolved critical/important review finding, or reviewer claim unsupported by command output stops the plan. Apply corrections in Wave 1 and repeat the entire Wave 2 gate; do not proceed on partial reruns.

**Tests:** Clean offline oracle replay twice, complete local Rust qualification suite, diff hygiene, and mandatory independent acceptance reviews.

**Test spec:**

- Run both oracle replays from different ambient HOME/clock values with network disabled and compare evidence byte-for-byte, then validate every manifest pointer against its claimed observation.
- Run formatter, locked dependency/interface/keyring/Breez compile checks, linkage and license self-tests/full metadata checks, and workflow scaffold tests; retain exact command/status output for reviewers.
- Ask reviewers to attempt the prior exploits: forge `VerifiedPaymentResult`, vary every allowed license tuple component, bypass each backend fixture path, find a Rust cancellation delta represented as Python observation, and make incomplete/mixed target evidence pass aggregation.

## Wave 3: Obtain Approval and Collect Native Evidence

### W3-01: Commit, push, and verify all four native qualification targets

**STOP CONDITION:** Do not begin this work unit without explicit user approval to commit and push the reviewed Wave 2 changes. After approval, commit only the intended Wave 2 source/evidence files (exclude generated `target/`), push a branch, then explicitly dispatch the reviewed workflow against that branch/SHA (or open an approved PR that triggers it) and use that run as the live qualification record.

**Files:** tracked Wave 2 files approved by the user; `.github/workflows/rust-qualification.yml` as the executed workflow; `reports/rust-qualification.md` only if recording immutable run URLs/IDs and target results is requested and reviewed

**Acceptance criteria:**

- The approved commit excludes `target/`, credentials, wallets, transient vendor trees, and unrelated workspace changes; its tree matches the locally reviewed content.
- The exact reviewed workflow revision is started through `workflow_dispatch` against the pushed ref or an explicitly approved PR; the accepted run's `head_sha` equals the reviewed commit. Do not add a broad `push` trigger merely to obtain evidence.
- Breez connect/readiness/create-invoice/prepare-only/disconnect, native Python↔Rust OS-keyring probes, locked offline builds, CLI runtime smoke, and linkage/minimum-OS checks pass independently on `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `x86_64-apple-darwin`, and `aarch64-apple-darwin`.
- Each target's evidence is bound to the commit SHA, `Cargo.lock` hash, target triple, runner identity, run ID/attempt, binary hash, architecture, OS/runtime floor, and command outcomes.
- `dependency-policy`, every native matrix leg, evidence aggregation, and `qualification-gate` succeed without skip, cancellation, neutralization, or manual artifact substitution.
- Specialist reviewers validate the live run and mark parent-plan Wave 2 ready; no merge, release, payment, or later-wave implementation occurs.

**Error handling:** Missing approval, dirty-scope ambiguity, workflow mutation after local review, skipped/cancelled/timed-out target, unavailable native keyring/Breez service, target/evidence mismatch, offline network access, linkage/floor drift, or failed aggregate gate blocks Wave 2 qualification. Fix forward through a newly reviewed commit; never force-push, rerun only a favorable subset, or describe workflow source as live evidence.

**Tests:** Git scope inspection before commit, GitHub required-check inspection, four target evidence validation, artifact/hash binding, and final specialist acceptance review.

**Test spec:**

- Before commit, compare the staged paths and diff to the accepted Wave 2 review inventory and assert `target/` is absent; after push, assert the workflow `head_sha` equals the approved commit.
- For each of the four targets, verify evidence identity/hash fields and the Breez, native keyring, offline build, linkage, and runtime outcomes; remove or alter one target record in a local copy and assert completeness validation fails.
- Rely on the locally reviewed injected failure tests for missing/skipped legs; do not spend a live runner merely to manufacture favorable or destructive branch evidence.

## NOT in Scope

- Implementing Waves 3-10 of the parent Rust cutover plan.
- Changing payer behavior in the frozen Python baseline; the oracle observes it without patching commit `f56cbd0`.
- Real Lightning payment, wallet funding, release secrets, publication, merge, or deployment.
- Replacing pinned Rust dependencies, target floors, native runner identities, or the accepted 46-wheel oracle closure unless a correction proves one is invalid and the parent ADR/plan is amended.
- Committing or pushing before explicit user approval following a clean Wave 2 acceptance result.

## Security Considerations

The key trust boundaries are backend submission, proof verification, secret-bearing credential/config output, and dependency license exceptions. Backend doubles must record calls without leaking macaroon, mnemonic, API key, authorization, or preimage values into unsafe evidence; golden assertions should verify redaction. `VerifiedPaymentResult` must be an opaque capability created only after cryptographic binding. License exceptions must fail closed on any identity drift. The native workflow remains read-only, secret-free, and non-paying.

## Failure Modes Summary

| Codepath | Failure Mode | Handled In | Tested? |
| --- | --- | --- | --- |
| Oracle payer transition | synthetic ledger label or Rust delta masquerades as historical submission evidence | W1-01 | Yes |
| Oracle backend fixture | fixture recorded but no backend call consumes it | W1-01 | Yes |
| Oracle CLI/config | evidence pointer captures inventory rather than resolved/output behavior | W1-01 | Yes |
| Credentials/pay-invoice coverage | command is absent or secret-bearing output is unverified | W1-01 | Yes |
| Rust verified result | downstream code constructs or mutates proof fields | W1-02 | Yes |
| License policy | package accepted on partial or stale identity | W1-03 | Yes |
| Qualification evidence | missing/mixed/tampered target record passes aggregation | W1-04 | Yes |
| Local acceptance | previously passing closure regresses or review is skipped | W2-01 | Yes |
| External transition | commit/push occurs without approval or with generated/unrelated files | W3-01 | Yes |
| Native qualification | one target/service/linkage/runtime check lacks live bound evidence | W3-01 | Yes |

## Architect Review Findings

### Auto-Incorporated

- Separated frozen Python observations from Rust intentional security deltas; the baseline is no longer required to expose cancellation states it does not implement.
- Replaced the nonexistent generic defaults/YAML/environment/CLI precedence chain with field-specific, publicly observable config and runtime-input contracts.
- Added W1-04 so the full Rust workflow emits, uploads, and aggregates locally tested target-bound evidence before any approved push.
- Expanded license negative tests from representative tuples to table-driven mutation and exact metadata equality for every exception.
- Expanded backend fixture tests to success plus mismatch/unused rejection for Breez, LND REST, Phoenixd, and test mode.
- Made workflow invocation explicit: dispatch against the approved pushed ref/SHA or use an approved PR, then verify `head_sha`; no broad push trigger is added.

### Resolved with User Input

None.

### Deferred

None.

## Confidence Assessment

| Dimension | Score | Source | Notes |
| --- | --- | --- | --- |
| Architecture | High | architect review + delta review | Historical Python facts, Rust security deltas, local qualification policy, and live native evidence are separate gates. |
| Error Handling | High | architect review + delta review | Unsupported observations, fixture drift, proof forgery, tuple drift, evidence tampering, and approval violations all fail closed. |
| Test Strategy | High | architect review + delta review | Tests replay every prior exploit across each adapter, every license tuple, the external Rust API boundary, and each target evidence record. |
| Data Flow | High | delta review | Backend fixtures flow through public calls; native check outcomes flow through target-bound artifacts into an exact-four aggregate. |
| Security | High | architect review + delta review | Redaction, opaque proof construction, exact dependency identity, secret-free artifacts, and explicit external-state approval are enforced. |
| Public API | High | plan synthesis + delta review | The verified-result path and payer trait remain stable while construction becomes module-private and access stays read-only. |

**Gate result:** Passed round 2. All critical and important findings were incorporated, the delta review found the revised structure sound, and every scored dimension is High.

## Orchestration Playbook

```bash
# Correct the local acceptance defects in four independent work units.
/greenharbor-orchestrate plans/correct-wave-2-acceptance-gaps.md --scope "Wave 1"

# Repeat all local verification and mandatory acceptance reviews; remain uncommitted.
/greenharbor-orchestrate plans/correct-wave-2-acceptance-gaps.md --scope "Wave 2"

# STOP: obtain explicit user approval to commit and push before running this scope.
/greenharbor-orchestrate plans/correct-wave-2-acceptance-gaps.md --scope "Wave 3"
```
