# Wave 2: Local Release Readiness

**Re-scoped:** 2026-07-21
**Status:** local-only qualification; production canary controls deferred

## Decision

Paygate has not yet been deployed or enabled for real payments. Wave 2 therefore
qualifies only the local client artifact and its no-payment boundaries. It does
not activate live GitHub environment/runner attestations, change a canary
contract schema, require production rollback provenance, or treat local fixtures
as infrastructure evidence.

## In Scope

### W2-01: Prove the normal Rust release artifact excludes canary execution

Add a deterministic package-level test that uses a fresh temporary
`CARGO_TARGET_DIR` and runs:

```text
CARGO_NET_OFFLINE=true cargo +1.88.0 build --locked --offline --release
```

The test must assert that the default release directory contains `paygate` and
does not contain `payment_canary`. It must remain local-only: no GitHub API,
payment backend, signing key, deployment, or live runner access.

**Files:** `tests/test_package_metadata.py`

**Acceptance criteria:**

- The normal locked/offline release build produces `paygate`.
- The normal release build does not produce a `payment_canary` executable.
- Existing tests continue to verify that `payment_canary` is gated behind the
  qualification-only Cargo feature.
- The focused local test passes from an isolated `.[dev]` Python environment.

## Explicitly Deferred to Pre-production Enablement

- Activating schema v7 or altering `security/payment-canary-contract.yaml`.
- Composite environment/runner-group digests and signed live-attestation
  comparison.
- GitHub environment, runner-group, reviewer, secret, or deployment changes.
- Rollback artifact digest verification: establish this only once a real,
  immutable deployment artifact exists.
- Payment execution, production verifier rollout, or any canary evidence claim.

## Exit Criteria

Wave 2 is complete when the focused local package metadata test passes. Before
the first deployment or any payment-capable canary, create a separate
pre-production readiness plan for the deferred infrastructure controls and bind
it to verified deployed artifact digests.
