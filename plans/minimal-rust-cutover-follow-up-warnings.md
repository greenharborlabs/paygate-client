# Minimal Rust Cutover Follow-up Warnings

**Captured after:** Wave 1 of `plans/minimal-rust-cutover.md`  
**Wave 1 baseline:** `65cda89dcd9dd6c0881d18227df5386589c57020`  
**Purpose:** Preserve non-blocking specialist-review findings for work after the minimal Rust cutover plan is complete.

## Context

Wave 1 introduced the production Breez Spark build, submission-aware payment outcomes, async CLI dispatch, and deployment preflight guards. Its targeted tests, Rust 1.88 production check, general review, security review, and API-contract review passed.

The findings below were intentionally not expanded into Wave 1 implementation work. They do not reopen the completed payment-contract work, but they should be resolved before treating the deployment and vendored SDK boundaries as generally reusable infrastructure.

## F-01: Legacy preflight record cannot prove launcher contents

**Priority:** High before Wave 3 installation  
**Area:** Deployment identity and cutover safety  
**Relevant file:** `scripts/preflight-minimal-rust-cutover.sh`

### Current state

New preflight records bind the launcher symlink target and the resolved launcher's SHA-256 digest. The immutable Wave 1 record predates those fields. It records the launcher path, resolved path, interpreter, ownership, platform, and dirty baseline, but it contains no historical launcher-content digest or equivalent artifact identity.

The record remains mode `0600` and byte-for-byte unchanged with SHA-256:

```text
27b8289c9d377316643a002057b62a2e54658ee0bbedb1f8bdb5867729485b69
```

The installed Python distribution's PEP 376 `RECORD` cannot safely backfill the missing evidence: its recorded console-script hash and size do not match the currently resolved launcher, and the frozen preflight record does not bind that package receipt or version as its source of truth.

Consequently, the legacy record passes Wave and build guards but the install guard deliberately fails closed with a missing launcher-content-identity error.

### Why it matters

Path, ownership, executable mode, and shebang checks cannot detect an in-place launcher replacement that preserves those attributes. Allowing installation from this record would weaken the plan's promise that the exact preflighted deployment target is being replaced.

### Recommended follow-up

Choose and document a provenance-preserving recovery procedure before Wave 3. Acceptable directions include:

1. Re-establish a clean deployment checkpoint with explicit operator approval, independently verify the installed Python launcher/package artifact, and create a new content-bound preflight record before any further build or installation work.
2. Recover a trustworthy historical launcher artifact or package receipt that can be cryptographically tied to the original frozen observation.
3. Amend the cutover plan with an explicit migration exception and compensating controls if neither form of historical evidence exists.

Do not silently hash the current launcher and treat that value as if it had been recorded before Wave 1 compilation.

### Acceptance tests

- The approved record contains the launcher symlink target and resolved-target digest.
- In-place launcher content replacement fails while path, mode, owner, and shebang remain unchanged.
- The authoritative record is created before the candidate build/install sequence it authorizes.
- Wave, build, and install guards all consume the same record.
- The exception/recovery decision and approving operator are recorded without secrets.

## F-02: Preflight record ownership and file type are not fully enforced

**Priority:** Medium  
**Area:** Local record trust  
**Relevant file:** `scripts/preflight-minimal-rust-cutover.sh`

### Current state

The guard requires mode `0600`, validates schema/repository/target identity, and checks deployment and dirty-baseline data. The security audit noted that it does not also require the record itself to be a regular file owned by the expected deployment principal.

### Why it matters

A privileged or misconfigured invocation could consume a mode-`0600` record owned by a different principal. Non-regular-file behavior should also be rejected explicitly rather than depending on incidental read behavior.

### Recommended follow-up

- Require `lstat` to report a regular file, with no symlink following.
- Record or explicitly configure the expected record owner UID.
- Require the live record owner to match that principal.
- Keep mode, canonical-path, schema, repository, and content validation independent so each failure remains fail-closed and diagnosable.
- Consider placing records in a dedicated owner-only directory and validating the directory ownership/mode as well.

### Acceptance tests

- Correct owner plus mode `0600` passes.
- Wrong owner, group ownership policy violation, symlink, FIFO, directory, and device file fail.
- Replacing the record between validation and consumption is detected or prevented through a single opened file descriptor.
- Errors remain redacted and do not print state paths or secret-bearing values unnecessarily.

## F-03: Vendored SDK HTTP code can trace complete response bodies

**Priority:** Medium to high before enabling verbose SDK tracing  
**Area:** Secret and payment-data redaction  
**Relevant files:**

- `vendor/spark-sdk-platform-utils/src/http/client.rs`
- The equivalent HTTP client in `vendor/boltz-client-platform-utils/`

### Current state

The vendored upstream HTTP clients contain trace-level logging of complete upstream response bodies. Depending on the endpoint, those bodies may include payment, token, proof, JWT, or diagnostic material outside Paygate's application-level redaction boundary.

The code was retained during Wave 1 because the vendor policy allowed only the documented Rust 1.88 duration-constructor substitutions and standalone manifest normalization. Editing logging behavior would have expanded the reviewed vendor delta.

### Why it matters

Application-level redaction cannot remove sensitive material already emitted by a dependency. A permissive global tracing subscriber or future debugging configuration could therefore disclose bearer-capable or wallet-related data.

### Recommended follow-up

Prefer an upstream fix. If a local patch is required:

- Remove complete response-body logging or replace it with bounded, non-sensitive metadata such as status, content type, and byte count.
- Treat headers such as Authorization, Set-Cookie, macaroon/token fields, invoices, payment hashes, and preimages as sensitive.
- Update the vendor provenance manifest and allowed-delta verifier.
- Audit both source-distinct `platform-utils` packages; do not assume they have identical code or features.
- Document when the local patch can be removed after an upstream pinned revision includes an equivalent fix.

### Acceptance tests

- Exercise successful and failing SDK HTTP responses containing sentinel secrets.
- Enable the most verbose supported tracing configuration.
- Assert no response body, authorization value, token, invoice, payment proof, hash, or preimage sentinel reaches captured logs.
- Assert useful non-sensitive status and timing diagnostics remain available.
- Verify vendor provenance/hashes allow exactly the reviewed logging delta plus existing compatibility substitutions.

## Suggested sequencing

1. Resolve F-01 before any Wave 3 install or launcher mutation.
2. Harden the record trust boundary in F-02 while revising the preflight record format or recovery procedure.
3. Resolve F-03 before enabling SDK trace logging in production or generalizing the vendored SDK packages for broader use.

## Completion criteria

This follow-up is complete when all three findings have an implemented and reviewed resolution, targeted regression coverage, updated provenance/runbook documentation, and no remaining security warning at the corresponding trust boundary.
