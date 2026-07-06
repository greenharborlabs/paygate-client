# Breez SDK Spark Payer Backend

**Created at:** `e89c5e2` on `2026-07-06` | **Mode:** `eng`

## Summary

Add Breez SDK Spark as an optional Paygate payer backend. The adapter pays
BOLT11 invoices with Spark preference disabled, enforces prepared Lightning fee
limits before payment submission, and returns success only when the Lightning
preimage verifies against the payment hash.

## Existing Code Leverage

- `paygate_client.payers.base`: shared payer contract, fee-limit gate, and
  preimage verification.
- `paygate_client.config`: typed YAML config with secret env references.
- `paygate_client.orchestrator`: central payer factory used by request and
  diagnostics flows.

## Architecture

`paygate request` loads config, constructs `BreezPayer`, evaluates local policy,
prepares the Breez BOLT11 payment, rejects fees above `max_fee_sats`, sends with
`prefer_spark=false`, and lets the shared payer verifier enforce
`sha256(preimage) == payment_hash`.

## Blast Radius

| Modified File/Interface | Consumers | Covered by Work Unit? |
| --- | --- | --- |
| `pyproject.toml` optional extras | installers, docs | yes |
| `paygate_client.config` | CLI, diagnostics, tests | yes |
| `paygate_client.payers.breez` | orchestrator factory | yes |
| `paygate_client.orchestrator` | request and backend diagnostics | yes |
| README/docs/examples/plans | users and reference-service handoff | yes |

## Risk Flags

`security`: yes | `performance`: no | `migration`: no | `public-api`: yes |
`concurrency`: yes

## Wave 1: Backend Integration

### W1-01: Add Breez Config And Optional Dependency

Add `paygate-client[breez]`, `BreezConfig`, `payer.backend: breez`, and YAML
validation for API key env, mnemonic env, network, storage directory, and send
completion timeout.

**Acceptance criteria:**
- Existing installs do not require Breez SDK.
- Missing Breez secrets fail closed with typed config errors.
- Config repr/asdict do not expose API key or mnemonic values.

**Tests:**
- Config loads with explicit and default Breez values.
- Missing env and invalid network fail.

### W1-02: Implement Breez Payer

Implement `BreezPayer` as a sync wrapper around Breez SDK Spark async calls.
Prepare the BOLT11 send, require BOLT11 method, reject quoted fees above
`max_fee_sats`, send with `prefer_spark=false`, and return a raw payment result
with amount, fee, payment hash, and preimage.

**Acceptance criteria:**
- Payment is never submitted when the prepared Lightning fee exceeds policy.
- Successful payments require a preimage and verified payment hash.
- Spark preference is always disabled for Paygate payments.

**Tests:**
- Success path with fake Breez SDK.
- Fee-limit rejection before send.
- Missing preimage and mismatched preimage fail.
- Non-BOLT11 prepare response fails.

### W1-03: Wire Factory And Diagnostics

Expose `BreezPayer`, add factory construction in `payer_from_config`, and rely on
existing diagnostics to report fee-limit and preimage capability.

**Acceptance criteria:**
- `paygate backend doctor` reports Breez as fee-limit capable.
- `paygate backend pay-invoice` can use Breez config and redacts preimage.

**Tests:**
- Factory constructs `BreezPayer`.
- Existing diagnostics tests continue passing.

## Wave 2: Documentation And Handoff

### W2-01: Document Usage And Findings

Update README, example config, backend compatibility docs, and add a portable
findings brief for the Paygate reference service.

**Acceptance criteria:**
- Users can configure Breez from docs without reading source code.
- Findings distinguish proven payer behavior from unproven merchant/payee work.
- Preimage values are treated as sensitive proof material.

**Tests:**
- Documentation reviewed for command/config consistency.

## Failure Modes Summary

| Codepath | Failure Mode | Handled In | Tested? |
| --- | --- | --- | --- |
| config load | missing API key or mnemonic | `BreezConfig` env refs | yes |
| prepare payment | unsupported method | `BreezPayer` | yes |
| prepare payment | quoted fee above policy | `BreezPayer` | yes |
| send payment | no preimage | shared payer verification | yes |
| send payment | wrong preimage | shared payer verification | yes |

## Architect Review Findings

### Auto-Incorporated

- Keep Breez optional so existing users are not forced to install the SDK.
- Treat fee safety as a pre-send prepare-response check.
- Preserve shared preimage verification instead of duplicating hash logic.

### Deferred

- Breez merchant/payee adapter for the reference service.
- Webhook/event settlement tracking.
- Wallet backup, rotation, and production operational runbook.

## Confidence Assessment

| Dimension | Score | Source | Notes |
| --- | --- | --- | --- |
| Architecture | High | repo inspection | Matches existing payer abstractions. |
| Error handling | Medium | SDK fake tests | Real SDK failure taxonomy may need refinement after more live use. |
| Test strategy | High | unit tests | External Breez boundary is mocked; manual smoke remains required. |
| Security | Medium | config review | Secrets are env-referenced; wallet mnemonic operations need ops docs later. |

## Orchestration Playbook

```bash
/greenharbor-orchestrate plans/breez-spark-payer-backend.md --scope "Wave 1"
/greenharbor-orchestrate plans/breez-spark-payer-backend.md
```
