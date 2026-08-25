# Payer backend compatibility

The production Rust CLI currently wires one real-money payer: Breez SDK Spark.
Other adapter modules remain in the source tree because their contracts and
failure semantics are tested, but that does not make them callable production
transports.

Paygate payer backends must do more than pay a BOLT11 invoice. They must return
the payment preimage and enforce a maximum routing fee before submission. A
backend that cannot prove both properties fails closed.

## Rust CLI support matrix

| Backend | Rust implementation | `request` payment | `backend doctor` | `backend pay-invoice` | Production status |
| --- | --- | --- | --- | --- | --- |
| Breez SDK Spark | Production SDK transport | Yes | Yes | Yes | Supported with explicit local policy |
| Test mode | Domain/test implementation | No | Config/readiness response only | No | Test and compatibility use only |
| LND REST / Voltage | Adapter contract with injectable test transport | No production HTTP transport | Unsupported response | Unsupported response | Not supported in this release |
| Phoenixd | Fail-closed placeholder | No | Unsupported response | Unsupported response | Not supported in this release |
| LNbits | No Rust payer adapter | No | No | No | Receiver/merchant use only unless a future payer adapter proves the required capabilities |
| Blink | No Rust payer adapter | No | No | No | Unsupported |

The retained Python client has additional historical adapters. Their presence,
PyPI packaging, or earlier documentation does not expand the production Rust
support matrix.

## Breez SDK Spark

Breez is the supported production payer because its Rust SDK path can:

- prepare a BOLT11 payment before submission;
- expose the prepared Lightning fee for comparison with `max_fee_sats`;
- send with `prefer_spark=false` so a Lightning preimage is available;
- return payment hash, amount, fee, and preimage evidence;
- disconnect while preserving post-submission ambiguity semantics; and
- use isolated local wallet storage with exclusive ownership.

The common verifier hashes the returned preimage and compares it with the
signed invoice payment hash. A proof mismatch never becomes a usable payment
credential.

## LND REST status

The Rust source includes a tested `LndRestPayer<T>` contract. Tests cover
pre-submission fee bounds, redirect refusal, terminal stream handling,
ambiguous submission, and invoice-bound proof verification. The production CLI
does not supply an LND HTTP transport, so selecting `lnd-rest` cannot submit a
payment and diagnostic payment commands return an unsupported classification.

Do not infer production support from `scripts/setup-voltage-paygate.sh` or the
legacy Python package. Those are retained migration/compatibility assets.

## Test-mode status

The example config uses `test-mode` because it is safe for parsing, doctor, and
ordinary unpaid request checks. The production Rust request dispatcher does not
wire it as a payer for `402` challenges. Rust integration tests inject the test
payer directly where deterministic challenge behavior is needed.

## Phoenixd status

Phoenixd is an explicit unsupported placeholder in the current Rust release.
It owns no endpoint, credentials, or submission capability. See
[Phoenixd status](phoenixd-spike.md).

## Required payer capabilities

A future production backend must:

- pay an amount-bearing BOLT11 invoice programmatically;
- enforce `max_fee_sats` before submission;
- return the exact successful payment preimage;
- return payment hash, amount, and final fee metadata;
- distinguish not-submitted, submitted-unknown, final failure, and confirmed
  outcomes; and
- fail closed when credentials, fee caps, transport responses, cleanup, or
  proof verification are unsafe.

## Local policy requirements

Every real payment requires explicit local policy:

- `policy.allowed_hosts` includes the exact target `host:port`;
- `policy.allowed_services` includes the Paygate challenge service;
- `policy.max_request_sats` caps each invoice amount;
- `policy.max_fee_sats` caps routing fees; and
- `policy.daily_budget_sats` caps retained counting spend.

Empty allowlists fail closed. Wildcard hosts and services are not supported.

## Credential reuse and profiles

Cached credentials are scoped by profile, target origin, service, protocol,
payer backend, policy context, and request key. Single-use claims are durably
consumed before their authorization value is returned. Expired or rejected
credentials are evicted before a new payment flow.

Use `--profile` whenever multiple agents share a Unix user or state volume:

```bash
paygate request GET "https://api.example.com/protected" \
  --config ~/.config/paygate-client/worker-a.yaml \
  --profile worker-a

paygate credentials list --profile worker-a
paygate credentials purge --all --profile worker-a
```

Credential metadata is stored in owner-only files. Authorization values use
the OS keyring when available and otherwise use the owner-only fallback file.
Profiles also isolate the daily spend ledger.

## Diagnostic commands

For a Breez config:

```bash
paygate backend doctor \
  --config ~/.config/paygate-client/config.yaml \
  --json

paygate backend pay-invoice <bolt11> \
  --config ~/.config/paygate-client/config.yaml \
  --max-fee-sats 5 \
  --json
```

`doctor` is non-paying. `pay-invoice` sends real money and must be explicitly
approved. Do not use a successful Breez result as evidence that another backend
is supported.
