# Wave 5 evidence publication

This runbook begins only after a successful `rust-wave5-acceptance.yml` run. It
publishes a reviewed copy of accepted evidence into the qualification report;
it does not create acceptance. The uniquely named, retained, immutable
acceptance artifact is the acceptance authority. The source-controlled evidence
index and report block are publication copies and must byte-match that artifact.

## Preconditions and stop conditions

Assign the acceptance run ID and repository explicitly. Do not infer either
value from a most-recent run.

```bash
REPOSITORY=greenharborlabs/paygate-client
ACCEPTANCE_RUN_ID=<positive-run-id>
ARTIFACT_NAME="wave5-candidate-acceptance-${ACCEPTANCE_RUN_ID}"
EVIDENCE_DIR="$(mktemp -d)/${ARTIFACT_NAME}"
```

Stop publication and leave the report and Wave 5 checkpoint pending if the
artifact is missing, duplicated, expired, or outside retention; if any checksum
fails; if any evidence record is more than 86,400 seconds old at publication;
if either reviewer signoff is absent; if explicit commit approval is absent; or
if the report verifier fails. Never substitute historical or expired evidence.

This procedure is read-only with respect to GitHub Actions. Do not start,
trigger, rerun, or invoke a workflow. Never repeat an ambiguous canary payment
attempt. Do not grant the acceptance workflow repository write permission, and
do not add credentials or payment secrets. No automation may create the report
commit. Never edit any generated JSON file or checksum.

## 1. Download exactly one immutable artifact

Confirm that the selected acceptance run has exactly one artifact with the
unique expected name, then download that artifact by run ID and exact name.

```bash
test "$(gh api "repos/${REPOSITORY}/actions/runs/${ACCEPTANCE_RUN_ID}/artifacts" \
  --paginate --jq ".artifacts[] | select(.name == \"${ARTIFACT_NAME}\") | .name" | wc -l | tr -d ' ')" = 1
mkdir -p "$EVIDENCE_DIR"
gh run download "$ACCEPTANCE_RUN_ID" \
  --repo "$REPOSITORY" \
  --name "$ARTIFACT_NAME" \
  --dir "$EVIDENCE_DIR"
```

The directory must contain the four canonical JSON files and their four
checksum files:

- `wave5-candidate-manifest.json` and `wave5-candidate-manifest.sha256`
- `wave5-evidence-index.json` and `wave5-evidence-index.sha256`
- `wave5-acceptance-envelope.json` and `wave5-acceptance-envelope.sha256`
- `wave5-validator-result.json` and `wave5-validator-result.sha256`

## 2. Verify all four checksums and freshness

Run every checksum verification from the downloaded artifact directory. Any
nonzero result stops publication.

```bash
(
  cd "$EVIDENCE_DIR"
  sha256sum --check wave5-candidate-manifest.sha256
  sha256sum --check wave5-evidence-index.sha256
  sha256sum --check wave5-acceptance-envelope.sha256
  sha256sum --check wave5-validator-result.sha256
)
```

Independently check that every source run was complete no more than 86,400
seconds before the current publication time. This command only reads the
generated index.

```bash
FRESHNESS_CHECK_EPOCH="$(date -u +%s)"
python3 - "$EVIDENCE_DIR/wave5-evidence-index.json" "$FRESHNESS_CHECK_EPOCH" <<'PY'
import json
import sys
from pathlib import Path

index = json.loads(Path(sys.argv[1]).read_bytes())
now = int(sys.argv[2])
for record in index["records"]:
    age = now - record["source_run"]["completed_at_epoch"]
    if age < 0 or age > 86_400:
        raise SystemExit(f"publication stopped: {record['id']} is outside freshness policy")
PY
```

## 3. Obtain two independent reviews

Provide the downloaded `wave5-candidate-manifest.json`, evidence index,
envelope, validator result, all checksum results, and acceptance run URL to two
people who are independent of the operator and of each other:

1. An independent integration reviewer must accept the integration and all
   four native records, source/lock binding, attestations, run identity, and
   freshness.
2. An independent security reviewer must accept both signed canary records,
   durable receipts, runner/key identity, redaction, non-ambiguity, manifest
   integrity, and freshness.

Record both written signoffs against the exact acceptance run URL and candidate
manifest SHA-256. A conditional, missing, stale, or mismatched signoff stops
publication.

## 4. Request explicit docs-only commit approval

After both reviews accept the exact manifest, request explicit approval to make
a docs-only commit limited to `reports/rust-qualification.md` and this runbook.
Do not treat review signoff as commit approval. Do not edit the report until the
explicit approval identifies the acceptance run and manifest digest.

## 5. Materialize the canonical report region

After approval, replace the report's pending Wave 5 region with exactly one
region in this form:

````text
<!-- BEGIN WAVE5 ACCEPTED EVIDENCE -->
```json
<exact bytes from downloaded wave5-evidence-index.json>
```
<exact line from downloaded wave5-evidence-index.sha256>
https://github.com/<owner>/<repository>/actions/runs/<acceptance-run-id>
<!-- END WAVE5 ACCEPTED EVIDENCE -->
````

Copy the canonical index bytes and checksum line without reformatting,
normalizing, regenerating, or editing them. The URL must be the selected
acceptance run URL, not a source evidence run URL.

## 6. Verify and commit only documentation

Run the publication verifier against the downloaded files:

```bash
PUBLICATION_EPOCH="$(date -u +%s)"
python3 scripts/check-rust-qualification-report.py \
  --report reports/rust-qualification.md \
  --candidate "$EVIDENCE_DIR/wave5-candidate-manifest.json" \
  --candidate-sha256 "$EVIDENCE_DIR/wave5-candidate-manifest.sha256" \
  --index "$EVIDENCE_DIR/wave5-evidence-index.json" \
  --index-sha256 "$EVIDENCE_DIR/wave5-evidence-index.sha256" \
  --envelope "$EVIDENCE_DIR/wave5-acceptance-envelope.json" \
  --envelope-sha256 "$EVIDENCE_DIR/wave5-acceptance-envelope.sha256" \
  --validator-result "$EVIDENCE_DIR/wave5-validator-result.json" \
  --validator-result-sha256 "$EVIDENCE_DIR/wave5-validator-result.sha256" \
  --publication-epoch "$PUBLICATION_EPOCH"
```

Capture `PUBLICATION_EPOCH` immediately before this command; do not reuse the
earlier freshness-check clock. The verifier deterministically rejects a future
completion or any completion older than 86,400 seconds at that epoch. It also
verifies canonical bytes and exact checksums for the candidate, index,
acceptance envelope, and validator result; binds their source identity and
digests; and requires the report URL to equal the envelope's acceptance run URL.
A missing argument, mixed artifact set, or verifier failure stops publication;
restore the pending report rather than weakening the verifier. Inspect and stage
only the approved documentation paths:

```bash
git diff --check -- reports/rust-qualification.md docs/wave5-evidence-publication.md
git diff -- reports/rust-qualification.md docs/wave5-evidence-publication.md
git add -- reports/rust-qualification.md docs/wave5-evidence-publication.md
test -n "$(git diff --cached --name-only -- reports/rust-qualification.md)"
test -z "$(git diff --cached --name-only | grep -Ev '^(docs/wave5-evidence-publication.md|reports/rust-qualification.md)$' || true)"
git commit --only reports/rust-qualification.md docs/wave5-evidence-publication.md \
  -m "docs: publish reviewed Wave 5 acceptance evidence"
```

The docs commit is not the acceptance authority and cannot cure missing,
invalid, ambiguous, or expired evidence.

## Checkpoint rule

The Wave 5 checkpoint remains blocked until all real integration, four-target
native, LND canary, and Breez canary runs have completed successfully; the
candidate has been accepted into the immutable acceptance artifact; the
independent integration and security reviewers have signed off; explicit
docs-only commit approval has been received; and the exact report publication
has passed the verifier and been committed. If any condition later proves
false, the checkpoint remains blocked.
