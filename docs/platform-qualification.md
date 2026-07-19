# Rust native platform qualification

This is the native runner contract for the Rust cutover. All four targets use
standard GitHub-hosted runners available to this public repository. The
workflow's default dispatch value is `false` until the workflow is intentionally
dispatched; once enabled, missing or unavailable runners fail
qualification rather than silently passing or skipping a target.

## Supported qualification matrix

| Target | Native runner / OS floor | Provider and trust boundary | Owner / availability | Timeout / cost ceiling |
| --- | --- | --- | --- | --- |
| `x86_64-unknown-linux-gnu` | `ubuntu-22.04`; pinned Rust 1.88.0 bullseye OCI image; glibc >= 2.31 | GitHub-hosted native x64 VM plus digest-pinned container; no wallet access | Platform Engineering; GitHub-hosted best effort | 30 min / $0 monthly |
| `aarch64-unknown-linux-gnu` | `ubuntu-22.04-arm`; pinned Rust 1.88.0 bullseye OCI image; glibc >= 2.31 | GitHub-hosted native ARM64 VM plus digest-pinned container; no wallet access | Platform Engineering; GitHub-hosted best effort | 30 min / $0 monthly |
| `x86_64-apple-darwin` | `macos-15-intel`; macOS >= 15 | GitHub-hosted native Intel macOS VM; no wallet access | Platform Engineering; GitHub-hosted best effort | 35 min / $0 monthly |
| `aarch64-apple-darwin` | `macos-15`; macOS >= 15 | GitHub-hosted native Apple Silicon VM; no wallet access | Platform Engineering; GitHub-hosted best effort | 35 min / $0 monthly |

No payment, wallet, release, or production secrets may be exposed to builders,
executors, emulators, or workflow artifacts. Each runner is a fresh,
GitHub-hosted VM. Linux uses the multi-architecture Rust 1.88.0 bullseye image
pinned to OCI index digest
`sha256:b315f988b86912bafa7afd39a6ded0a497bf850ec36578ca9a3bdd6a14d5db4e`;
the host architecture must match the requested container platform.

Emulation may prove deterministic CLI behavior, but **emulation cannot qualify**
minimum-glibc runtime behavior, macOS runtime behavior, or real wallet canaries.
In particular, `macos-latest` is not evidence for the Intel macOS 15 floor. If native
macOS 15 or native aarch64 glibc 2.31 cannot be secured, qualification must stop
and the supported target matrix must be amended before the Rust implementation
is enabled.

Every executor verifies its physical kernel architecture with `uname` before
extracting or launching the target binary. The Intel macOS leg additionally
rejects `sysctl.proc_translated=1`, because Rosetta can otherwise report
`x86_64` from `uname`. Linux ARM execution through x86 binfmt and macOS Intel
execution through Rosetta therefore cannot produce qualifying evidence.

## Evidence contract

Builders package a target artifact with `Cargo.lock`, source commit, SHA-256,
and `builder_runner_identity` into a target-named bundle. GitHub's
`actions/attest-build-provenance` action creates a signed SLSA v1 build
attestation for that exact bundle; it requires only `attestations: write` and
`id-token: write` in the builder job. Executors use a runner-attested,
vendor-signed GitHub CLI to verify the bundle's GitHub attestation against this
repository and this workflow, then re-check its SHA-256, target, source commit,
and `Cargo.lock` hash before extracting it. The executor job has only
`contents: read` and `attestations: read`; its ephemeral GitHub token is used
only for the attestation lookup and is never available to untrusted/emulated
jobs. An executor adds (without replacing the
builder identity) `executor_runner_identity` only after native `--version` and
`--help` intent succeeds. Evidence uses one target-specific filename per
artifact so aggregate download cannot overwrite records. Linux intent verifies
dynamic linkage and rejects GLIBC requirements newer than 2.31; macOS builds
set `MACOSX_DEPLOYMENT_TARGET=15.0` and executors reject a missing or newer
Mach-O deployment target before accepting linked-library inspection. The
workflow uses the stock `shasum -a 256` where available (with `sha256sum` only
as a Linux fallback), not an unpinned macOS `python3`, for transfer hashing.
The aggregate action
fails closed if any target's evidence is missing, skipped, timed-out, stale,
malformed, or lacks required manifest fields.

Wave 1 builds the dependency-free Rust stub in `tests/platform-smoke/stub` with
Rust 1.88.0 and its own committed `Cargo.lock`. This breaks the dependency cycle:
native target infrastructure is qualified before Wave 2 creates the production
crate. Wave 2 replaces the stub manifest input with the production crate while
preserving the same artifact, attestation, linkage, and runtime gates.

## Repository-side verification

`python3 -m pytest tests/platform-smoke` checks workflow structure, native target
coverage, GitHub-attestation and tamper-rejection intent, and executed
missing/skipped/timed-out/stale aggregate failure injection. It does not
impersonate GitHub runners, native OS versions, or wallet canaries.
