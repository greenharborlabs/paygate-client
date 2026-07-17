# Paygate Client Public Release and Repository Polish

**Created at:** `e687fcc` on `2026-07-16` | **Mode:** `eng`

## Summary

Prepare `paygate-client` for a truthful, reproducible `v0.1.0` public release on PyPI, then advertise `pipx install "paygate-client[breez]"` only after the public artifact passes a clean install. Coordinate the narrowly related public-repository polish for `paygate-agent-trust` as a separately approved and separately committed sibling-repository change.

The supplied findings are partly stale. The client already declares `0.1.0`, builds a universal wheel, has an MIT license, and has a GitHub description; however, PyPI still returns 404, GitHub has no tag/release, package metadata is incomplete, public install guidance is internally contradictory, version metadata is duplicated, and CI does not validate distributable artifacts or its open-ended Python compatibility claim. The reference service still lacks a license, GitHub description, and homepage even though its README identifies the live Fly.io URL.

## Existing Code Leverage

- `pyproject.toml` already uses PEP 517/621 with setuptools, declares the `paygate` console script, and isolates Breez as the `breez` extra.
- `LICENSE` already supplies an MIT license that the current wheel build includes.
- `tests/test_cli_smoke.py` already verifies the CLI entry point and displayed version.
- `.github/workflows/ci.yml` already pins third-party actions and runs tests, lint, formatting, and MyPy.
- `README.md` already distinguishes contributor setup from payer configuration and contains the intended eventual PyPI/pipx command.
- `../paygate-agent-trust/README.md` already provides the canonical live URL, `https://paygate-agent-trust.fly.dev/`, plus the existing commit-pinned client install command.

## Architecture

Runtime behavior does not change. Release-ready source produces one sdist and one wheel; CI and the release workflow validate those artifacts in clean environments; a protected GitHub environment uses PyPI Trusted Publishing to upload the exact validated bytes; public documentation changes only after the PyPI artifact is verified.

```text
truthful source + deterministic metadata
                 |
                 v
       sdist + wheel + SHA-256 manifest
                 |
          clean-install gates
                 |
        protected release event
                 |
                 v
         PyPI Trusted Publisher
                 |
          public verification
                 |
                 v
     PyPI-first docs/repository links
```

## Blast Radius

| Modified File/Interface | Consumers | Covered by Work Unit? |
| --- | --- | --- |
| `README.md` installation guidance | Checkout users and prospective PyPI users | W1-01, W3-01 |
| `paygate_client/payers/breez.py` missing-extra guidance | Base-package users who configure Breez | W1-01, W3-01 |
| `tests/test_payers_breez.py`, `tests/test_diagnostics.py` | Runtime error contract | W1-01, W3-01 |
| `pyproject.toml` metadata/version/Python contract | setuptools, pip/pipx, PyPI, developers | W1-02 |
| `paygate_client.__version__` | CLI, source/editable/wheel installs, tag check | W1-02 |
| `PYPI_README.md` long description | Immutable `v0.1.0` PyPI page | W1-02 |
| Client CI and publish workflows | Pull requests, maintainers, PyPI | W2-01 |
| Client GitHub environment/settings/tag/release | Maintainers and package consumers | W2-01, W3-01 |
| `../paygate-agent-trust/LICENSE` and GitHub metadata | Reference-service users | W1-03 |
| `../paygate-agent-trust/README.md:225` | Reference-service client users | W3-01 |

## Risk Flags

`security`: yes | `performance`: no | `migration`: no | `public-api`: yes | `concurrency`: no

Security is marked because PyPI OIDC and release provenance are supply-chain trust boundaries. Public API is marked because the distribution name, version, Python range, platform support, optional extra, console script, and immutable artifacts become external contracts.

## Wave 1: Make Source Truthful and Release-Ready

### W1-01: Remove unavailable PyPI guidance before publication

Correct every public or runtime surface that currently presents `paygate-client[breez]` as installable from PyPI. Before publication, the README should use the exact commit-pinned Git command already used by the reference service (or checkout-local `.[breez]` where explicitly in a checkout), while the runtime missing-extra error should give source-neutral guidance to reinstall the same distribution with its `breez` extra. Preserve the final PyPI command as a clearly gated post-publication replacement in the release runbook, not as current instructions.

**Files:** `README.md`, `paygate_client/payers/breez.py`, `tests/test_payers_breez.py`, `tests/test_diagnostics.py`

**Acceptance criteria:**

- No current README instruction implies the 404 PyPI project exists.
- The pinned Git URL uses the full verified commit `e687fccb9a0a3d5ae9d3878b6e4fb4853df31901` and includes `[breez]` using valid pip direct-reference syntax.
- Missing-Breez runtime guidance works conceptually for checkout, Git, or index installs and does not hard-code an unavailable source.
- Existing error codes, exit behavior, and redaction remain unchanged.

**Error handling:** A missing optional dependency must remain a clear non-secret-bearing readiness error and must never attempt installation, load wallet credentials, or initiate payment.

**Tests:** Update behavioral tests around the missing-extra path and add a documentation command syntax check.

**Test spec:**

- Invoke Breez readiness without the SDK and assert a nonzero result with source-neutral `breez`-extra guidance and no credential values.
- Parse or dry-run the README's commit-pinned requirement in an isolated pip environment and assert it resolves the expected commit and extra.
- Search current user-facing text and assert the bare PyPI command appears only in explicitly future/post-publication context.

### W1-02: Define deterministic metadata, versioning, and compatibility

Make `paygate_client.__version__` the single maintained version source and configure setuptools dynamic version metadata with `dynamic = ["version"]` plus `[tool.setuptools.dynamic] version = {attr = "paygate_client.__version__"}`. Set the build requirement to `setuptools>=77.0.3`, use `license = "MIT"` and `license-files = ["LICENSE"]` in `[project]`, and add author/maintainer, keywords, classifiers, source, issues, and documentation/homepage URLs.

Use a dedicated `PYPI_README.md` as the immutable PyPI long description. It may describe the intended public install because it is rendered only when the artifact is published, while the GitHub README remains truthful during staging. For `v0.1.0`, declare `requires-python = ">=3.9,<3.15"` and test CPython 3.9–3.14; document Breez as tested on macOS 11+ universal2 and glibc Linux compatible with `manylinux_2_31` on x86_64/aarch64. Do not silently omit the Breez dependency through environment markers.

**Files:** `pyproject.toml`, `paygate_client/__init__.py`, `PYPI_README.md` (new), `tests/test_cli_smoke.py`, `tests/test_package_metadata.py` (new)

**Acceptance criteria:**

- `pyproject.toml` contains no literal project version and built sdist/wheel metadata resolves version `0.1.0` from `paygate_client.__version__`.
- Wheel metadata contains the Markdown long description, `License-Expression: MIT`, license file, authors/maintainers, project URLs, classifiers, `Requires-Python: >=3.9,<3.15`, console entry point, and `Provides-Extra: breez`.
- Source import, editable install, wheel install outside the repository, and sdist build/install all report `0.1.0`.
- `PYPI_README.md` is concise, contains only commands valid once the artifact exists, and links to source/docs for full configuration.
- Supported interpreter/platform claims match executable CI coverage and upstream Breez wheel availability; untested platforms are labeled unsupported or unverified.

**Error handling:** Metadata/build/import failures stop artifact creation. A tag/version mismatch is an explicit release failure. Unsupported Python versions fail via `Requires-Python` rather than a later import error.

**Tests:** Package metadata tests plus source/editable/sdist/wheel CLI smoke tests.

**Test spec:**

- Build from a clean Git archive, inspect both artifacts, and assert the exact metadata fields and long-description body.
- Install from sdist and wheel into separate empty environments outside the repository and assert `paygate --version`, `paygate --help`, and `import paygate_client` succeed.
- Pass a simulated tag `v0.1.1` against the built `0.1.0` artifact and assert the release check fails before publication.
- Attempt install under Python 3.15 (when available) or inspect `Requires-Python` with packaging tooling and assert the artifact is rejected.

### W1-03: Polish the reference service as a separate repository change

This work unit belongs to the coordinated finding but must execute from `../paygate-agent-trust`, never as part of a client commit. Before any edit, obtain owner approval for the license (MIT is only a consistency recommendation, not an assumed legal decision), record the starting hashes/diffs of the existing dirty `.orchestrate/post-production-publication-pass-9af6aae2.json` and `gradle.properties`, and keep both byte-identical. Commit the approved license/README change separately from GitHub settings updates.

**Files:** `../paygate-agent-trust/LICENSE` (new after approval), `../paygate-agent-trust/README.md` (only for license/open-source wording or link), GitHub settings for `greenharborlabs/paygate-agent-trust`

**Acceptance criteria:**

- An owner explicitly approves the license before the file or any “open source” wording is added.
- GitHub recognizes the committed license's expected SPDX identifier.
- GitHub description concisely identifies the Paygate reference trust-report service and homepage is exactly `https://paygate-agent-trust.fly.dev/`.
- The homepage and a documented public catalog/health endpoint respond successfully with bounded timeouts.
- The two pre-existing dirty files remain byte-identical and all reference-service work is committed independently of the client.

**Error handling:** Missing license approval blocks only W1-03, not the client release. An unhealthy live endpoint defers the homepage/live claim. Any overlap with the dirty files stops the work unit for user review.

**Tests:** Repository API, live endpoint, license detection, and dirty-file integrity checks; no application changes.

**Test spec:**

- Capture SHA-256 hashes and diffs for both dirty files before work; compare after work and require exact equality.
- Query GitHub after the file commit/settings update and assert description, homepage, and SPDX license.
- Request the homepage and `/api/v1/catalog` without payment and assert expected successful responses.

## Wave 2: Build a Reproducible, Least-Privilege Release Path

### W2-01: Validate once, publish exact bytes through Trusted Publishing

Extend CI with a CPython 3.9–3.14 base compatibility matrix and bounded Breez resolution/import jobs on the oldest and newest supported Python versions and documented Linux/macOS platforms. Add a reusable artifact build/validation job and a dedicated publish workflow: build one sdist and one wheel from the tagged commit, run strict metadata and clean-install checks, generate a SHA-256 manifest, transfer those exact files between jobs, verify hashes after transfer, and publish those bytes through PyPI Trusted Publishing.

The publish workflow must support a guarded manual dry run where upload is structurally impossible and a production GitHub `release.published` path. Use a protected `pypi` environment and exact pending-publisher tuple (`greenharborlabs`, `paygate-client`, workflow filename, environment, project name); configure and verify that tuple after the workflow is merged to `main`. Pin third-party actions by full SHA, use no long-lived PyPI token, and omit GitHub release-asset upload to avoid `contents: write`; retain workflow artifacts, checksums, and PyPI attestations instead.

**Files:** `.github/workflows/ci.yml`, `.github/workflows/publish.yml` (new), `pyproject.toml` (release-check tooling/tasks only), `scripts/check-dist.sh` (new if needed), `docs/releasing.md` (new), GitHub `pypi` environment and PyPI pending-publisher settings

**Acceptance criteria:**

- CI tests base installs on CPython 3.9–3.14 and Breez dependency resolution/import on the documented oldest/newest supported combinations without wallet secrets or payment calls.
- Both wheel and sdist install and pass CLI/version smoke tests outside the source tree; `twine check --strict` or equivalent passes.
- Dry-run/manual/PR paths cannot enter the publish job or request an OIDC token.
- Only the environment-gated publish job has `id-token: write`; ordinary jobs have read-only contents permissions.
- The tagged SHA is contained in `origin/main`, equals the GitHub release target, and its `vX.Y.Z` tag equals built metadata before OIDC acquisition.
- Hashes generated immediately after build equal hashes after artifact transfer and the files accepted by PyPI; workflow artifacts and manifest are retained.
- The runbook includes exact external setup, name-availability preflight, first release, approvals, retries, partial-upload handling, and forward-fix rules.

**Error handling:** Existing PyPI name/version, mismatched tag/metadata/SHA, missing full history, hash drift, failed artifact check, failed OIDC exchange, or partial upload stops publication. Never fall back to API tokens, retag, overwrite, or delete a failed immutable release. A same-tag rerun is allowed only for an external/transient failure when the tagged source, workflow, metadata, and validated artifact bytes are unchanged and PyPI accepted no file; every source, workflow, metadata, or artifact defect requires a forward version and new tag.

**Tests:** Workflow static validation, guarded manual dry run, clean archive distribution checks, and permission assertions.

**Test spec:**

- Run the reusable build/validate path manually and assert no publish job is eligible and no OIDC permission is available.
- Build exactly one sdist and wheel, validate them, transfer them through the workflow artifact mechanism, and compare the SHA-256 manifest before/after.
- Feed mismatched tag, release target, non-main commit, and existing-version fixtures to release preflight and assert each fails before OIDC.
- Install wheel and sdist in empty environments; install `[breez]` on the oldest/newest tested combinations and import the adapter/SDK without credentials.

## Wave 3: Execute, Verify, and Advertise v0.1.0

### W3-01: Run the first release through explicit approval gates

Execute the release as one operator lifecycle with four non-skippable checkpoints recorded in the release issue/runbook: (A) verify CI, exact pending-publisher tuple, protected environment, current PyPI name availability, version/tag/SHA, and obtain maintainer approval; (B) create and push annotated tag `v0.1.0` from the verified `main` commit and publish the GitHub release; (C) verify PyPI JSON, attestations/checksums, wheel and sdist installs, `pipx`, CLI, and Breez dependency readiness; (D) only after C passes and a second maintainer approval, switch public docs/settings.

Checkpoint D updates the client README to lead with `pipx install "paygate-client[breez]"`, keeps checkout instructions under development, updates runtime guidance/tests where the generic pre-release wording should become PyPI-specific, sets the client GitHub homepage to the verified PyPI page unless an owner-selected product/docs URL is supplied, and updates `../paygate-agent-trust/README.md:225` in its own repository commit to replace the commit-pinned install. A failure at B or C leaves all commit-pinned/current guidance intact.

**Files:** Git tag/release and GitHub settings for `greenharborlabs/paygate-client`, PyPI project `paygate-client`, `README.md`, `docs/dev-setup.md`, `paygate_client/payers/breez.py` (only if generic guidance is replaced), `tests/test_payers_breez.py`, `tests/test_diagnostics.py`, `../paygate-agent-trust/README.md` (separate post-verification commit)

**Acceptance criteria:**

- A recorded maintainer approval follows a fresh 404/name-availability check and precedes tag/release creation.
- Git tag/release, built metadata, PyPI JSON, and `paygate --version` agree on `0.1.0`; published artifact hashes match the retained manifest.
- Clean `pipx install "paygate-client[breez]"` succeeds from PyPI on documented supported systems, and help/version plus dependency-only Breez readiness work without a checkout.
- Public install guidance changes only after successful verification and a second approval; development instructions remain available and explicit.
- Client GitHub metadata links to a real public destination and does not claim the CLI is a hosted service.
- Reference-service README changes are made and committed separately without touching its pre-existing dirty files.

**Error handling:** If the name becomes claimed, stop and choose a new distribution name before tagging. Rerun the same tag only for an external/transient failure when source, workflow, metadata, and artifact bytes remain unchanged and PyPI accepted no file. Any tagged-code, workflow, metadata, or artifact defect—or any accepted PyPI file—requires a forward version and new tag. If public installation fails, do not execute checkpoint D.

**Tests:** End-to-end public artifact verification plus GitHub/PyPI API and documentation consistency checks.

**Test spec:**

- With no checkout on `PYTHONPATH`, install by pipx from PyPI, assert `0.1.0`, invoke help, and run readiness only to the expected missing-credentials boundary without payment.
- Install both public sdist and wheel with pip, recompute hashes, and compare metadata/checksums with the retained manifest and GitHub release tag.
- Query PyPI and GitHub APIs and assert version, project URLs, license, Python range, extra, release, description, and homepage consistency.
- Search both public READMEs and runtime guidance; assert normal-user paths use PyPI while Git/checkout commands are clearly labeled development or historical fallback instructions.

## NOT in Scope

- Changing request, policy, credential, payment, or payer behavior.
- Reserving the PyPI name with a placeholder or publishing an experimental package.
- Uploading to TestPyPI by default; the guarded dry run validates the same local path without creating a second index contract.
- Releasing or changing application/deployment behavior in `paygate-agent-trust`.
- Automatically choosing a legal license for the reference service.
- Broad governance documents or a support SLA.

## Security Considerations

- Scope PyPI OIDC to the exact owner, repository, workflow filename, protected environment, and project name.
- Never expose publishing permission to pull-request code, manual dry runs, wallet secrets, or long-lived API tokens.
- Pin release actions to full SHAs and build from a clean immutable Git ref with full history.
- Verify version/tag/release-target equality and artifact hashes before OIDC acquisition and after artifact transfer.
- Breez tests prove packaging/import readiness only; they never load credentials, create invoices, or send payments.

## Failure Modes Summary

| Codepath | Failure Mode | Handled In | Tested? |
| --- | --- | --- | --- |
| Pre-release guidance | Advertises unavailable PyPI package | W1-01 | Yes |
| Metadata/version | Source, tag, sdist, wheel, and CLI diverge | W1-02, W2-01, W3-01 | Yes |
| Python/Breez support | Advertised environment cannot install | W1-02, W2-01 | Yes |
| Artifact transfer | Uploaded bytes differ from validated bytes | W2-01, W3-01 | Yes |
| Publisher trust | Untrusted trigger obtains OIDC/upload access | W2-01 | Yes |
| PyPI first release | Name claimed, version exists, or partial upload | W2-01, W3-01 | Preflight + runbook |
| Documentation switch | Happens before public install succeeds | W3-01 | Approval gate + test |
| Reference license | License inferred without owner approval | W1-03 | Explicit prerequisite |
| Dirty sibling repo | Existing changes overwritten/mixed | W1-03, W3-01 | Hash/diff guard |

## Architect Review Findings

### Auto-Incorporated

- Added W1-01 to fix the currently broken README and runtime PyPI guidance before release.
- Added a dedicated immutable `PYPI_README.md` and long-description assertions so GitHub can remain truthful while staging.
- Selected setuptools dynamic metadata from `paygate_client.__version__` as the authoritative version mechanism.
- Bounded the advertised `v0.1.0` contract to CPython `>=3.9,<3.15` and documented/tested Breez platforms.
- Specified one artifact identity flow: build once, hash, validate, transfer, re-hash, publish exact bytes; workflow artifacts replace GitHub release assets.
- Replaced non-executable workflow tests and meaningless dirty-checkout logic with guarded dry runs, permission checks, tag/release-target equality, full-history, main-containment, and hash tests.
- Added exact pending-publisher setup/name preflight, explicit maintainer approvals, public verification, and forward-fix behavior.
- Kept reference-service work in scope but isolated its repository, approval, commit, and dirty-file integrity boundaries.
- Added all runtime, test, long-description, platform, and reference-service install consumers to blast radius.
- Made PEP 639 configuration exact (`setuptools>=77.0.3`, `license = "MIT"`, `license-files = ["LICENSE"]`) and limited same-tag reruns to unchanged bytes after external/transient failures.

### Resolved with User Input

None. The plan preserves owner decisions as explicit checkpoints rather than guessing them.

### Deferred

- The architect suggested six waves. This plan keeps three orchestrate-sized waves by treating first release, verification, and post-verification advertising as one operator lifecycle with four explicit non-skippable approval checkpoints; splitting those checkpoints across unattended orchestrator runs would weaken rather than strengthen the handoff.
- The delta review asserted Breez 0.17.1 lacks CPython 3.14 wheels. Current PyPI file metadata was checked on `2026-07-16` and includes CPython 3.14 wheels for macOS universal2, manylinux 2.31 x86_64/aarch64, and Windows, so `>=3.9,<3.15` remains the evidence-backed `v0.1.0` contract and CI must prove it before release.

## Confidence Assessment

| Dimension | Score | Source | Notes |
| --- | --- | --- | --- |
| Architecture | MEDIUM | Codebase exploration + architect delta review | Release boundary, artifact identity, repository boundary, and ordering are explicit; Wave 3 intentionally remains one attended lifecycle. |
| Error Handling | MEDIUM | Architect delta review | Name collision, mismatch, OIDC, partial upload, artifact drift, immutable-tag retry, and verification failures have stop/forward-fix behavior. |
| Test Strategy | HIGH | Architect revision | Source/editable/sdist/wheel, compatibility, workflow permissions, artifact hashes, and public installs are covered. |
| Security | HIGH | Architect revision | Exact OIDC trust tuple, protected environment, immutable action pins, least privilege, and no-token fallback are required. |

## Open Questions

- The `paygate-agent-trust` license remains an explicit owner/legal choice. MIT is a consistency recommendation only.
- If Green Harbor Labs has a canonical Paygate product/docs page, use it instead of PyPI as the client repository homepage.

## Orchestration Playbook

Run the two Wave 1 client units separately from W1-03. Execute W1-03 from the reference-service repository and never include its changes in a client commit.

```bash
# Wave 1 client work only
/greenharbor-orchestrate plans/public-release-and-repository-polish.md --scope "W1-01,W1-02"

# Wave 1 reference-service work only (separate repository and commit)
cd ../paygate-agent-trust
/greenharbor-orchestrate ../paygate-client/plans/public-release-and-repository-polish.md --scope "W1-03"
cd ../paygate-client

# Wave 2: reproducible build and gated publisher
/greenharbor-orchestrate plans/public-release-and-repository-polish.md --scope "Wave 2"

# Wave 3: attended production release lifecycle
/greenharbor-orchestrate plans/public-release-and-repository-polish.md --scope "Wave 3"

# Do not use a single unattended full-plan run: W1-03 and Wave 3 require
# separate repository handling and explicit maintainer approvals.
```
