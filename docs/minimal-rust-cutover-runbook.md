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
operator_id=operator-01

scripts/package-rust-paygate.sh \
  --repo "$repo" --record "$preflight" --output "$candidate"
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

Run it once. Verify one initial/cached attempt, no more than one payment, one
authenticated same-origin retry, the success envelope, and the expected server
response. Record only the pass fact:

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
acceptance gates. Under an acceptance-file sibling lock it records the exact
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
procedure. Repeat the protected request from the installed command. It must
either use the compatible cached credential without payment or reject and
safely evict it without double-paying. Record the result:

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

Rollback authority comes from the preflight, rollback manifest, and receipt,
not from mutable acceptance. Therefore rollback remains available if a crash
leaves Rust active but acceptance is missing, malformed, or stale; it is also a
safe no-op when the exact original Python launcher is already restored. If the
original environment is present while Rust is still the top launcher, rollback
changes only that launcher and never rewrites state. Only the exact
original-absent/quarantine-present/Rust-launcher state restores backed-up state;
it does so once, renames quarantine back, verifies the old entrypoint, and
restores the top launcher last. Both/neither environment, identity drift, a
quarantined environment with a non-Rust launcher, or an unknown third launcher
is refused before mutation. Rollback does not need to
rewrite the mutable acceptance phase: the retained receipt permanently consumes
the session. Reinstall always requires a new acceptance file/session and all seven manual
live approvals. After a crash, retain the receipt and rollback directory and
run the normal rollback command; never reset acceptance or reuse evidence.

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
