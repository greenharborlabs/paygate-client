# Close Wave 5 Freshness and Evidence-Index Gaps

**Created at:** `ffedfd8` on `2026-07-23` | **Mode:** `eng`

## Summary

Close the two remaining Wave 5 review blockers without running qualification or
payment workflows. The candidate gate will reject evidence older than 24 hours
using authoritative GitHub run timing, and a successful acceptance will emit a
canonical, immutable seven-record evidence index that can later be copied into
the qualification report through a separately approved documentation change.

This plan builds on the uncommitted Wave 5 candidate validator and acceptance
workflow already in the worktree. Those changes are user-owned inputs and must
be preserved.

## Existing Code Leverage

- `scripts/check-rust-wave5-candidate.py` already validates exact candidate
  cardinality, source/lock identity, native attestations, artifact digests, and
  signed canary results through an injected offline evidence root.
- `.github/workflows/rust-wave5-acceptance.yml` already retrieves four explicit
  historical runs, verifies their status/source identity, constructs a
  candidate, validates it, and uploads retained evidence with read-only
  permissions.
- `.github/actions/aggregate-rust-platform/action.yml` establishes the existing
  86,400-second inclusive freshness policy and native stale/future rejection
  behavior.
- `reports/rust-qualification.md` already distinguishes pending local, native,
  integration, live-canary, and final-acceptance evidence without claiming an
  unexecuted PASS.

## Architecture

```text
explicit historical run IDs
  -> GitHub run API metadata (source, workflow, URL, started_at, updated_at)
  -> exact candidate schema v3 + producer timestamps + signed/attested artifacts
  -> offline validation at one injected now_epoch with 24-hour freshness policy
  -> canonical seven-record evidence index
  -> canonical acceptance envelope + immutable artifact
  -> independent integration/security review
  -> separately approved docs-only report materialization
```

GitHub `updated_at` is the authoritative completion time only after the run is
proved `completed` and `success`; producer timestamps are signed or attested
consistency checks within the inclusive run interval. The offline validator
never contacts GitHub.

## Blast Radius

| Modified File/Interface | Consumers | Covered by Work Unit? |
| --- | --- | --- |
| `scripts/check-rust-wave5-candidate.py` candidate schema v3, `--now-epoch`, index output | Acceptance workflow, focused contract tests, final reviewers | W1-01, W2-01 |
| `.github/workflows/rust-integration-qualification.yml` metadata schema v2 and timestamp attestation | Acceptance workflow and candidate validator | W1-01 |
| `.github/workflows/rust-wave5-acceptance.yml` run metadata, canonical outputs, immutable upload | GitHub reviewers and post-acceptance publication | W1-01, W2-01 |
| `scripts/check-rust-qualification-report.py` (new) | Docs-only publication task and CI/static tests | W2-01, W3-01 |
| `reports/rust-qualification.md` pending/accepted machine markers | Release reviewers and docs-only publication | W2-01, W3-01 |
| `docs/wave5-evidence-publication.md` (new) | Maintainers performing approved evidence publication | W3-01 |
| `tests/platform-smoke/test_wave5_qualification_contracts.py` | Local Wave 5 contract gate | W1-01, W2-01, W3-01 |

## Risk Flags

`security`: yes | `performance`: no | `migration`: yes | `public-api`: yes | `concurrency`: no

Security risk comes from accepting payment and native-build evidence. Migration
risk is limited to intentionally rejecting candidate schema v2 and integration
metadata schema v1. The CLI/schema changes are qualification interfaces, not the
public `paygate` runtime API.

## Wave 1: Define and Enforce Fresh Evidence

### W1-01: Bind every source record to authoritative run timing

Upgrade the candidate to schema v3 and add an exact `source_run` object to the
integration record, every native target record, and both canary records. The
acceptance workflow must fetch each supplied run through
`gh api repos/$GITHUB_REPOSITORY/actions/runs/$run_id` and map the response as
follows:

- `id` -> decimal-string `run_id`;
- `html_url` -> canonical `url`;
- `name` -> `workflow_name`;
- the expected repository workflow filename -> `workflow_file`;
- `run_started_at` -> integer `started_at_epoch`;
- `updated_at` -> integer `completed_at_epoch`, but only after exact
  `status == completed`, `conclusion == success`, and `head_sha` identity checks.

The exact `source_run` fields are `run_id`, `url`, `workflow_name`,
`workflow_file`, `started_at_epoch`, and `completed_at_epoch`. The validator
receives required `--repository owner/name` and `--now-epoch <integer>` options.
It requires:

- `source_run.run_id == workflow_run_id`;
- `url == https://github.com/{repository}/actions/runs/{run_id}`;
- the expected display name and workflow filename for the record type;
- `0 <= now_epoch - completed_at_epoch <= 86400`;
- `started_at_epoch <= completed_at_epoch <= now_epoch`.

Producer timestamps are additional consistency checks:

- Integration metadata becomes schema v2, adds integer
  `observed_at_epoch`, and is separately included in GitHub attestation
  verification alongside the semantic bundle. It remains bound to source,
  workflow run, bundle digest, and 90-day retention.
- Native `observed_at_epoch` retains its established decimal-string format and
  must normalize to an integer within its source-run interval.
- Each signed canary artifact is re-read by the validator. `issued_at` and the
  durable receipt's `recorded_at` must be RFC 3339 values with explicit UTC
  offsets, normalize to UTC, satisfy `issued_at <= recorded_at`, and both fall
  within the canary source-run interval.

Only integers are accepted for `--now-epoch` and `source_run` epochs; booleans,
negative values, fractions, NaN, and infinity fail. The inclusive 86,400-second
boundary is a constant in the validator and is not caller-configurable.

**Files:** `scripts/check-rust-wave5-candidate.py`,
`.github/workflows/rust-integration-qualification.yml`,
`.github/workflows/rust-wave5-acceptance.yml`,
`tests/platform-smoke/test_wave5_qualification_contracts.py`

**Acceptance criteria:**

- All seven records carry exact, repository-bound `source_run` metadata from
  their explicitly supplied historical run IDs.
- Evidence aged exactly 86,400 seconds passes; 86,401 seconds fails.
- Every producer timestamp is within its own inclusive source-run interval;
  canary issuance never follows durable receipt recording.
- Integration metadata itself is attestation-verified before its timestamp is
  trusted.
- Candidate schema v2, integration metadata schema v1, wrong-repository URLs,
  workflow/run mismatches, stale/future/malformed timestamps, and cross-run
  substitutions fail closed.
- The validator is deterministic under `--now-epoch` and performs no network
  access.

**Error handling:** A missing GitHub field, invalid RFC 3339 value, non-success
run, unavailable run, invalid interval, stale record, metadata-attestation
failure, or schema mismatch exits nonzero and produces no accepted candidate or
index. Diagnostics identify only the evidence class and failure category.

**Tests:** Focused Python contract and workflow-structure tests.

**Test spec:**

- Build one valid seven-record fixture at an injected time and assert success at
  ages 0 and 86,400 seconds.
- Mutate each evidence class independently to age 86,401 seconds, start after
  completion, complete in the future, omit timing, use a float/bool/NaN, use a
  different repository/run URL, or use the wrong workflow name/file; each fails.
- Give integration/native timestamps values immediately outside their run
  intervals; each fails.
- Give canaries timezone-naive values, issued-after-recorded values, or signed
  timestamps outside their run intervals; each fails after genuine signature
  verification.
- Assert the workflow uses the explicit REST endpoint and a single captured
  `now_epoch`, verifies integration metadata attestation, and passes repository
  and clock arguments to the offline validator.

## Wave 2: Publish a Canonical Acceptance Artifact

### W2-01: Emit the index from validated data and add report verification

Extend `check-rust-wave5-candidate.py` with required
`--evidence-index-output <path>`. It writes the index only after every candidate
check succeeds, preventing a second workflow-side constructor from drifting
from validated data.

Canonical JSON bytes are defined once as:

```python
json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
```

Candidate, index, envelope, and validator-result JSON files contain those exact
newline-free bytes. Each checksum file uses the exact format
`<lowercase-hex><two spaces><filename>\n`.

`wave5-evidence-index.json` has these exact top-level fields:

- `schema_version`: integer `1`;
- `repository`: exact `owner/name`;
- `source_commit`: full commit SHA;
- `cargo_lock_sha256`: lockfile SHA-256;
- `accepted_at_epoch`: the injected `now_epoch`;
- `records`: exactly seven records with unique stable IDs.

The stable IDs are `integration`, the four
`native:<target-triple>` values, `canary:lnd-testnet-canary`, and
`canary:breez-mainnet-canary`. Every record has exactly `id`, `evidence_type`,
`source_run`, `age_at_acceptance_seconds`, and `provenance`.

The exact discriminated `provenance` objects are:

- Integration: `kind: github-slsa-v1`, `bundle_sha256`, `metadata_sha256`, and
  `signer_workflow: rust-integration-qualification.yml`.
- Native: `kind: github-slsa-v1`, `bundle_sha256`,
  `runtime_evidence_sha256`, and `signer_workflow: rust-platform.yml`.
- Canary: `kind: signed-canary-v1`, `result_sha256`, `result_key_id`,
  `ledger_key_id`, and `runner_identity` taken from the verified signed result.

The workflow then creates `wave5-acceptance-envelope.json` with exact fields
`schema_version`, `repository`, `acceptance_run_id`, `acceptance_run_url`,
`generated_at_epoch`, `candidate_manifest_sha256`,
`evidence_index_sha256`, and `validator_result_sha256`. It independently
recomputes every digest before upload.

Upload the canonical candidate, index, envelope, validator result, and a
checksum file for each under
`wave5-candidate-acceptance-${GITHUB_RUN_ID}` with `overwrite: false`,
90-day retention, and read-only repository permissions. The upload action's
artifact ID may be placed in the job summary after upload; it is not embedded
into the artifact it identifies.

Add `scripts/check-rust-qualification-report.py` with this interface:

```text
python3 scripts/check-rust-qualification-report.py \
  --report reports/rust-qualification.md \
  [--index wave5-evidence-index.json \
   --index-sha256 wave5-evidence-index.sha256]
```

Without index arguments, it validates pending mode: the report says no Wave 5
candidate has been accepted and has no accepted-evidence markers. With both
arguments, it requires exactly one region delimited by
`<!-- BEGIN WAVE5 ACCEPTED EVIDENCE -->` and
`<!-- END WAVE5 ACCEPTED EVIDENCE -->`, containing one fenced JSON block whose
bytes equal the canonical index plus the single Markdown-imposed trailing LF,
followed by the exact index checksum and acceptance run URL. Duplicate markers,
placeholders, partial blocks, digest mismatches, or accepted wording without a
valid block fail.

**Files:** `scripts/check-rust-wave5-candidate.py`,
`.github/workflows/rust-wave5-acceptance.yml`,
`scripts/check-rust-qualification-report.py` (new),
`reports/rust-qualification.md`,
`tests/platform-smoke/test_wave5_qualification_contracts.py`

**Acceptance criteria:**

- A successful validator invocation emits one byte-stable index with exactly
  seven unique records; any validation failure emits no index file.
- Index record URLs, run IDs, ages, source/lock identity, and provenance derive
  only from already validated candidate data.
- The envelope binds the acceptance run and the canonical candidate, index, and
  validator-result digests without self-reference.
- The uploaded artifact contains all four JSON files and all four checksum
  files under a unique non-overwriting name with 90-day retention.
- Acceptance retains only `actions: read`, `attestations: read`, and
  `contents: read`; it cannot dispatch workflows, write repository contents, or
  access payment secrets.
- Report pending mode and accepted mode are mutually exclusive and
  machine-verifiable.

**Error handling:** Canonicalization failure, duplicate/unknown index IDs,
repository or URL mismatch, missing output, checksum mismatch, artifact
collision, duplicate report markers, or report/index drift exits nonzero. A
failed validator removes or never creates its requested index output.

**Tests:** Focused validator, index, workflow-structure, and report-verifier
tests.

**Test spec:**

- Run the validator twice over the same fixture and assert byte-identical index
  files and checksum digests.
- Mutate each of the seven IDs, add an eighth record, remove one native target,
  or change provenance/run URL; each fails and leaves no index output.
- Assert index ages are `accepted_at_epoch - source_run.completed_at_epoch` and
  the four native records remain separate even though they share a run ID.
- Assert the envelope/index digest relationship and reject a changed candidate,
  index, validator result, acceptance URL, or checksum.
- Assert the upload lists all eight files, uses the acceptance run ID in its
  name, disables overwrite, retains for 90 days, and has no write permission.
- Validate the report in pending mode; then validate a fixture with one exact
  canonical accepted block. Reject placeholders, duplicate markers, missing
  records, altered bytes, extra newlines, and checksum drift.

## Wave 3: Define the Approved Documentation Handoff

### W3-01: Add a docs-only evidence publication runbook

Document the post-acceptance operation without performing it. The operator must
download the uniquely named acceptance artifact, verify all four checksum files,
obtain independent integration and security acceptance of the manifest, and
request explicit approval for a docs-only commit. After approval, they replace
the report's pending region with the exact canonical index block, checksum, and
acceptance URL, then run the report verifier before committing only the report
and runbook changes.

The Rust cutover checkpoint remains blocked until the real integration/native/
canary runs, candidate acceptance, independent reviews, and verified report
publication all complete. The runbook must explicitly forbid reusing expired
evidence, editing generated JSON, granting the acceptance workflow write
permissions, retrying an ambiguous canary, or representing the docs commit as
the acceptance authority.

**Files:** `docs/wave5-evidence-publication.md` (new),
`reports/rust-qualification.md`,
`scripts/check-rust-qualification-report.py`,
`tests/platform-smoke/test_wave5_qualification_contracts.py`

**Acceptance criteria:**

- The runbook has exact download, checksum, review, approval, report-verifier,
  and docs-only commit steps.
- It distinguishes the immutable acceptance artifact from the source-controlled
  evidence index and leaves the artifact as acceptance authority.
- It states every condition required before the Wave 5 checkpoint may change
  from blocked.
- No workflow gains repository write permissions or automatically commits the
  report.

**Error handling:** Missing/expired artifact, checksum failure, absent reviewer
signoff, missing explicit commit approval, report-verifier failure, or evidence
older than policy stops publication and leaves the report/checkpoint pending.

**Tests:** Static documentation/report contract tests.

**Test spec:**

- Assert the runbook names the unique artifact, all checksums, both required
  reviews, explicit commit approval, the report verifier, and checkpoint rule.
- Assert it contains no workflow-dispatch, payment-retry, automatic-commit, or
  write-permission instruction.
- Exercise report verification using a downloaded-index fixture, then mutate
  one byte and assert publication verification fails.

## NOT in Scope

- Dispatching integration, native, LND, Breez, or acceptance workflows.
- Performing a real payment, retrying an ambiguous attempt, or changing payment
  caps.
- Materializing an accepted report block before real evidence and reviews exist.
- Committing, pushing, closing Wave 5, updating its checkpoint, or starting
  Wave 6.
- Relabeling schema v1/v2, expired, or one-day-retention historical evidence as
  qualifying; affected evidence must be rerun.

## Security Considerations

GitHub run metadata is transport identity and freshness authority; signed or
attested producer records prove evidence content. Neither alone is sufficient.
Repository-bound canonical URLs prevent cross-repository substitution, exact
schemas prevent field smuggling, injected time makes offline validation
deterministic, and index generation occurs only from validated in-memory data.
The acceptance workflow remains read-only and the docs update remains a
separately approved human action.

## Failure Modes Summary

| Codepath | Failure Mode | Handled In | Tested? |
| --- | --- | --- | --- |
| Historical run metadata | Missing, non-success, cross-repo, wrong workflow, invalid interval | W1-01 | Yes |
| Freshness | Older than 24 hours, future completion, malformed epoch | W1-01 | Yes |
| Producer time | Outside source run, naive canary time, issued after receipt | W1-01 | Yes |
| Integration evidence | Metadata timestamp not attested or bundle identity mismatch | W1-01 | Yes |
| Index generation | Validation failure, duplicate/missing ID, constructor drift | W2-01 | Yes |
| Canonical artifacts | Byte/digest mismatch, incomplete upload, artifact collision | W2-01 | Yes |
| Report publication | Placeholder, duplicate block, checksum drift, missing approval | W2-01, W3-01 | Yes |
| Operational evidence | Expired/missing run or ambiguous canary | W3-01 | Static + later live review |

## Architect Review Findings

### Auto-Incorporated

- Defined GitHub `run_started_at` and successful-run `updated_at` as the exact
  source-run interval and completion authority.
- Added exact candidate `source_run`, evidence-index, provenance, acceptance-
  envelope, canonical-byte, checksum, repository-URL, and report-marker
  contracts.
- Required independent attestation verification for integration metadata.
- Moved index construction into the successful validator path so rejected
  candidates cannot publish an index.
- Added a read-only report verifier and explicit artifact completeness,
  timestamp, URL, and no-output-on-failure tests.
- Kept actual report materialization as a separately approved post-acceptance
  operation rather than part of this implementation cycle.

### Resolved with User Input

- Freshness is an inclusive 24-hour window for every evidence class.
- Accepted evidence is published through an immutable artifact followed by a
  separately approved docs-only commit; the workflow never writes the repo.

### Deferred

- Actual qualification/canary execution, independent evidence review, report
  materialization, checkpoint closure, and Wave 6 remain operational follow-up.

## Confidence Assessment

| Dimension | Score | Source | Notes |
| --- | --- | --- | --- |
| Architecture | HIGH | Repository discovery + architect review | One authority for run time, one validator-owned index path, and one separate docs handoff. |
| Error Handling | HIGH | Architect findings incorporated | Every stale, malformed, substituted, unsigned/unattested, and publication failure remains fail-closed. |
| Test Strategy | HIGH | Existing fixture patterns + architect review | Deterministic clock, real signatures, schema mutations, canonical bytes, and workflow/report structure are covered. |
| Data Flow | HIGH | Contract trace | Run metadata, evidence validation, index generation, envelope upload, and docs materialization have explicit boundaries. |
| Security | HIGH | Trust-boundary review | GitHub timing, attestations, signatures, repository identity, and human publication approval are independently bound. |

**Gate:** Passed after incorporating all blocking and high-priority architect
findings. No implementation decisions or open questions remain.

## Orchestration Playbook

```bash
# Wave 1: freshness and source-run contract
/greenharbor-orchestrate plans/close-wave5-critical-gaps.md --scope "Wave 1"

# Wave 2: canonical index, envelope, and report verification
/greenharbor-orchestrate plans/close-wave5-critical-gaps.md --scope "Wave 2"

# Wave 3: docs-only handoff runbook
/greenharbor-orchestrate plans/close-wave5-critical-gaps.md --scope "Wave 3"
```
