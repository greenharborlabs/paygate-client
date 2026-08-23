# Minimal Rust cutover runbook

This runbook installs exactly one Rust `paygate` candidate frozen by the Wave 1
preflight. It is intentionally fail-closed. Never put a mnemonic, API key,
invoice preimage, authorization value, or response body in an acceptance record
or shell argument.

## Safety model

- Keep the preflight JSON outside the repository with mode `0600`. The package
  and install commands re-run its dirty-tree and deployment identity guards.
- Run packaging from the candidate source commit. The candidate manifest binds
  the commit, `Cargo.lock`, target triple, package/binary names, and binary hash.
- The scripts will not discover a replacement launcher, target, supervisor, or
  state location. Those values come exclusively from the preflight record.
- The preflight must have recorded no active product process. Stop the known
  supervisor/process using the deployment's normal procedure before install;
  an unknown or changed supervisor is a hard stop.
- Invoice and protected-request approval are separate checkpoints. An earlier
  passing test or doctor result is never approval to pay.
- Keep the candidate directory and rollback directory on the deployment host
  through the restart/cache validation. Finalize within 24 hours or roll back.

## 1. Package and identify one candidate

Set paths without secret values:

```bash
repo=/absolute/path/to/paygate-client
preflight=/secure/operator/path/paygate-preflight.json
candidate=/secure/operator/path/paygate-rust-candidate
rollback=/secure/operator/path/paygate-python-rollback
acceptance=/secure/operator/path/paygate-acceptance.json
config=/secure/operator/path/config.yaml
protected_url=https://approved.example/protected-resource
operator_id=operator-01

# One-time host provisioning. Run exactly once for this preflight record.
scripts/package-rust-paygate.sh provision-lock \
  --repo "$repo" --record "$preflight" \
  --confirm PROVISION_PAYGATE_RUNTIME_LOCK

scripts/package-rust-paygate.sh \
  --repo "$repo" --record "$preflight" --output "$candidate"

# If Breez is the selected backend, securely persist its already-exported
# secrets and verify both the candidate and frozen Python rollback launcher.
scripts/setup-breez-cutover-env.sh --use-process-env \
  --candidate "$candidate/paygate"
```

`operator_id` is a non-secret audit identifier. Every checkpoint records it,
an ordered epoch timestamp, strict boolean pass status, and (for pass gates) the
literal result `PASS`. Invoice/request names and positive integer caps are
schema-validated. Every entry also carries the exact top-level cutover session
ID; copied gates cannot be rekeyed into a new session. Install and finalize reject missing, extra, reordered,
mistyped, or candidate-mismatched v2 acceptance fields. The first checkpoint
creates a random cutover session. Install accepts exactly one fresh seven-gate
pre-install phase and creates a distinct installation session and epoch.

Packaging uses a clean `git archive` worktree and builds only the W1-recorded
target with `cargo build --locked --release --target … --bin paygate`. Review
`manifest.json`, then run the repository fixture/oracle and Rust product tests
against that same commit according to the release checklist. Re-run the W1
wave guard before and after those tests. A dirty-baseline mismatch stops work.
The explicit provisioning command creates or adopts the owner-only
`.paygate-runtime.lock` beside the recorded launcher and writes the immutable
owner-read-only binding record
`.paygate-runtime.lock.binding.json` beside it. The binding is deployment-global,
not derived from the preflight filename, and provisioning refuses to adopt an
existing unbound lock or run again once the binding exists. Preserve both files
for the lifetime of every issued candidate: do not unlink, replace, hard-link,
chmod, or edit either one. Ordinary packaging never creates or rebinds the
lock; it requires the sidecar, verifies its bound preflight hash and exact lock
device/inode, and compiles that identity into the candidate and manifest. A
different preflight pathname does not authorize reprovisioning. If either
object is lost or changed, stop: a new record alone is not sufficient recovery,
and this workflow provides no automated way to retire an orphaned inode. Every
runtime and maintenance operation fails closed if the provisioned lock identity
changes.
Record the two redacted test facts, in order:

```bash
scripts/cutover-rust-paygate.sh checkpoint --candidate "$candidate" \
  --acceptance "$acceptance" --gate fixture-oracle-pass --operator "$operator_id" \
  --result PASS --confirm
scripts/cutover-rust-paygate.sh checkpoint --candidate "$candidate" \
  --acceptance "$acceptance" --gate rust-product-tests-pass --operator "$operator_id" \
  --result PASS --confirm
```

Run the candidate's real `doctor` command with the configured wallet. Doctor
must return one valid JSON value, succeed, and make no payment. Record only the
redacted pass fact:

```bash
scripts/cutover-rust-paygate.sh checkpoint --candidate "$candidate" \
  --acceptance "$acceptance" --gate candidate-doctor-pass --operator "$operator_id" \
  --result PASS --confirm
```

## 2. Separately approve the one invoice and one request

An operator must inspect the named invoice and all three caps before approval:

```bash
scripts/cutover-rust-paygate.sh checkpoint --candidate "$candidate" \
  --acceptance "$acceptance" --gate invoice-approved --operator "$operator_id" \
  --name CUTOVER-INVOICE-01 --max-amount-sats 10 \
  --max-fee-sats 2 --daily-cap-sats 25 --confirm
```

Only after that checkpoint, submit the invoice once with the candidate. Do not
retry an ambiguous result. Verify the returned proof is bound to the invoice,
the amount/fee/daily caps held, and stdout is exactly one JSON value. Store no
proof or authorization secret; record only `PASS`:

```bash
scripts/cutover-rust-paygate.sh checkpoint --candidate "$candidate" \
  --acceptance "$acceptance" --gate invoice-pass --operator "$operator_id" --result PASS --confirm
```

Now inspect and separately approve one named protected endpoint:

```bash
scripts/cutover-rust-paygate.sh checkpoint --candidate "$candidate" \
  --acceptance "$acceptance" --gate request-approved --operator "$operator_id" \
  --name CUTOVER-PROTECTED-REQUEST-01 --confirm
```

Run it once with the challenge-defined cache policy and JSON tracing. Verify
one initial/cached attempt, no more than one payment, one authenticated
same-origin retry, the success envelope, and the expected server response:

```bash
"$candidate/paygate" request GET "$protected_url" --config "$config" \
  --cache-policy challenge-defined --trace-json
```

The accepted trace must select the configured `Payment` protocol and contain
`credential.cached` with a non-null future expiry. An L402 fallback, a missing
cache event, or a null/expired expiry is not cache-ready for this cutover: do
not record `request-pass`, do not retry, and do not install. List the redacted
credential metadata and confirm the exact request has a usable record after
the authenticated retry (`expiresAt` is in the future and `maxUses` is null or
`useCount < maxUses`):

```bash
"$candidate/paygate" credentials list --profile default
```

The list operation must also prove the authorization secret remains
retrievable from its configured secure storage; an entry whose secret cannot
be loaded is omitted and therefore cannot qualify. Record only the pass fact:

```bash
scripts/cutover-rust-paygate.sh checkpoint --candidate "$candidate" \
  --acceptance "$acceptance" --gate request-pass --operator "$operator_id" --result PASS --confirm
```

## 3. Back up and atomically install

```bash
scripts/cutover-rust-paygate.sh install \
  --repo "$repo" --record "$preflight" --candidate "$candidate" \
  --rollback-dir "$rollback" --acceptance "$acceptance"
```

Installation first revalidates W1 host/target/launcher/supervisor/state identity,
candidate hashes, commit, lockfile, inactive process state, and complete live
acceptance gates. It then takes the exact candidate-bound deployment lock
exclusively before its final process scan and holds it through publication,
launcher/environment mutation, and final verification. Under an acceptance-file
sibling lock it records the exact
old environment and `bin/paygate` filesystem identities and backs up the four
state paths. It publishes the rollback metadata, immutable receipt, and
installed acceptance, switches the launcher to Rust, then atomically renames
the old environment to a uniquely named sibling quarantine. A missing state
path or unsafe/broad/overlapping old environment is a refusal. State-root
symlinks are also refused because restoring them without
an independently frozen target identity could traverse outside the recorded
state boundary. The cutover never executes or interrogates deployed Python,
reads `pyvenv.cfg`, or infers virtual-environment semantics. It treats the
preflight-bound old package as inert filesystem bytes: its root and old
`paygate` entrypoint must retain their recorded path, ownership, mode, inode,
size, and hash. After install, the original environment path is absent, the
quarantine retains the same directory identity, Rust is the sole installed
launcher, and process inspection must find no Python invocation of the old or
quarantined entrypoint and no `python -m paygate` process. The bounded scan is
deliberately conservative for every non-helper process: either protected
entrypoint path anywhere in raw argv (including data), `-m paygate*`, static or
literal dynamic `paygate` imports, and `exec`/`open` of a protected path are
refused even when the interpreter was renamed. Exact-path false positives are
an accepted cutover safety tradeoff.

Every checkpoint also creates an immutable witness at
`<acceptance>.witnesses/<cutover-session>/<ordinal>-<gate>.json`. The witness
chain binds the candidate, canonical acceptance path, session, ordinal, gate,
canonical checkpoint hash, and previous witness hash; installed witnesses also
bind the install session/epoch, rollback hash, receipt path/hash, and launcher.
Witness directories are owner-only and witness files are bounded, read-only,
single-link regular files opened without symlink following. Checkpoint creation
writes and fsyncs the exclusive witness before atomically publishing acceptance.
A crash in between abandons that session; do not delete evidence to resume it.
Install requires exactly seven ordered witnesses and finalize exactly ten, with
no omission, tamper, or extra file.

Runtime checks are live point-in-time gates, not assumptions from preflight.
Install checks the recorded supervisor and process table before mutation and
again after quarantine. Each installed checkpoint repeats the complete Rust
launcher, candidate, receipt, quarantine, supervisor, and bounded process-table
check immediately before and after its acceptance update; a post-update failure
restores the prior acceptance bytes. Finalize repeats the same checks twice at
the rollback-metadata removal boundary. Unparseable or timed-out supervisor or
process state fails closed.
For a recorded launchd label, preinstall requires that exact label and its
configuration to remain inspectable while stopped (no numeric PID); a missing
label is not treated as absence of supervision. Installed and finalize checks
accept an active exact-label job configured through the canonical `paygate`
wrapper or directly to the frozen candidate. Either form is rejected if its
configuration references the original or quarantined Python entrypoint.
System/shared prefixes and environments overlapping repository, launcher,
state, candidate, acceptance, rollback, or recovery paths are refused. The OS
keyring is deliberately not exported; it remains in place.

From `command -v paygate`, run doctor again and record it:

```bash
scripts/cutover-rust-paygate.sh checkpoint --candidate "$candidate" \
  --record "$preflight" --rollback-dir "$rollback" --acceptance "$acceptance" --gate installed-doctor-pass --operator "$operator_id" \
  --result PASS --confirm
```

Restart the host or the W1-recorded supervisor using its normal operator
procedure. Repeat the exact protected request from the installed command
without `--refresh-credential`. It must report a cache hit and `paid: false`,
with no challenge or payment trace event. A miss or rejection is not
authorized to create a replacement payment: stop and roll back instead of
retrying. Record the result:

```bash
scripts/cutover-rust-paygate.sh checkpoint --candidate "$candidate" \
  --record "$preflight" --rollback-dir "$rollback" --acceptance "$acceptance" --gate restart-cache-pass --operator "$operator_id" \
  --result PASS --confirm
```

Inspect `command -v paygate`, its resolved binary hash, and the process table.
Confirm no Python-backed `paygate` process is active, then record:

```bash
scripts/cutover-rust-paygate.sh checkpoint --candidate "$candidate" \
  --record "$preflight" --rollback-dir "$rollback" --acceptance "$acceptance" --gate runtime-only-pass --operator "$operator_id" \
  --result PASS --confirm
```

## 4. Roll back or finalize

Until finalization, rollback is payment-free and restores the exact launcher
target and checksummed filesystem state:

```bash
scripts/cutover-rust-paygate.sh rollback \
  --record "$preflight" --rollback-dir "$rollback"
```

The immutable receipt is an anti-replay tombstone stored beside the acceptance file and binds the
candidate, cutover/install sessions, rollback manifest, acceptance path, and
both launcher targets. Never delete or edit it: it permanently consumes that
cutover session and prevents replay with another rollback directory. Receipt
users require the same non-symlink, regular, single-link, read-only, owned,
bounded object generation and the exact receipt schema and key set. Candidate,
canonical acceptance and rollback paths, both sessions, install epoch,
rollback-manifest hash, and both launcher targets must all match; replacement,
extra fields, binding drift, or permission drift is a refusal.

Rollback authority comes from the preflight, rollback manifest, receipt, and—
after restoration starts—one owner-only runtime recovery marker. It does not
come from mutable acceptance. Rollback therefore remains available if a crash
leaves Rust active but acceptance is missing, malformed, or stale. With no
recovery marker, an exact original-environment/Python-launcher deployment is a
safe no-op; later legitimate Python state changes are not overwritten.

On macOS, a reboot or operating-system update can remap the APFS device number
while preserving the recorded filesystem objects. Rollback remains fail-closed
unless an operator supplies an absolute path in
`PAYGATE_ROLLBACK_DEVICE_REMAP_AUTHORIZATION`. The referenced owner-only,
single-link, mode-`0400` `paygate-rollback-device-remap-v1` JSON object must bind
the current boot-session UUID, preflight and rollback-manifest hashes, installed
Rust target and binary hash, rollback directory, runtime-lock path and inode,
and the exact recorded-to-current device-number mapping. The authorization is
valid only on macOS, for one boot and one installed candidate; missing, stale,
extra, writable, or mismatched data is refused. Keep it with the immutable
rollback evidence and use it only after confirming that inode, ownership,
permissions, hashes, and paths are otherwise unchanged.

Before touching live state, rollback takes the exclusive runtime lock, confirms
its package-time device/inode binding is unchanged, confirms the recorded
supervisor and product processes are stopped, opens all four
immutable backups without following symlinks, verifies their recorded inode,
type, digest, and destination-parent identities, and durably copies every backup
to fixed staging paths. A pre-marker crash may leave staging residue; the next
run removes and rebuilds only the exact owned, non-symlink staging objects. A
parked object without a marker is invalid and requires investigation.

Rollback then publishes exactly one
`paygate-rust-rollback-recovery-v1` marker beside the runtime lock. The marker
binds the install session and rollback-manifest hash to every live, backup,
staging, parked, launcher, environment, and parent identity. It is never
rewritten and contains no phase or per-entry state. Recovery infers progress
from the filesystem: live+stage moves live to parked and stage to live;
absent+stage+parked moves stage to live; restored+parked needs cleanup; and a
restored object with neither private path is complete. Every other shape,
including destination+stage+parked, symlinks, wrong types or owners, changed
parents, and digest drift, is rejected before another mutation.

Recovery only moves forward toward Python. After all four state paths verify,
it accepts only quarantine/Rust, original/Rust, or fully restored
original/Python deployment shapes. It restores the recorded Python environment
when needed, removes only marker-bound staging and parked objects, reverifies
the complete restored state, and switches the launcher to Python last. Only
after the full Python deployment verifies does it unlink and fsync removal of
the marker. Any failure after marker publication leaves the marker in place,
which blocks Rust runtime startup. Retain the marker, receipt, and rollback
directory and rerun the same rollback command until it reports success. Never
delete or edit the marker, restore parked Rust-era state, switch the launcher
back to Rust, reset acceptance, or reuse cutover evidence. Reinstall requires a
new acceptance file/session and all seven manual live approvals.

After successful restart/cache/runtime-only validation, and no later than 24
hours after installation, explicitly cross the recovery boundary:

```bash
scripts/cutover-rust-paygate.sh finalize \
  --repo "$repo" --record "$preflight" --candidate "$candidate" \
  --rollback-dir "$rollback" --acceptance "$acceptance" \
  --recovery-record /secure/operator/path/paygate-recovery-boundary.json \
  --confirm FINALIZE_RUST_AND_RETAIN_QUARANTINE
```

Finalize reruns the W1 host/target/dirty guard and rechecks the installed Rust
launcher, process table, quarantine identity, candidate identity, receipt, and
every ordered checkpoint. It removes only the script-created rollback metadata
and state backups, never the old environment bytes. The recovery record states
that Python paygate is deactivated, records the original and quarantine paths,
and explicitly marks external cleanup as required. The quarantine remains for
separate audited cleanup after recovery review; do not delete it as part of
this cutover.
