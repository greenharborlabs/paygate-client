# Payer backend compatibility

Paygate payer backends must do more than pay a BOLT11 invoice. They must return
the payment preimage and enforce a maximum routing fee before payment. A backend
that cannot prove both capabilities is unsafe for automated payer use.

| Backend | Can pay invoice | Returns preimage | Recommended for Paygate payer | Notes |
| --- | --- | --- | --- | --- |
| Test | Yes, for test challenges only | Yes, from the challenge test preimage | Yes, for local development only | Does not send real Lightning payments. Use it for first setup and fixture-driven tests. |
| LND REST / Voltage | Yes | Yes, via terminal `payment_preimage` from `POST /v2/router/send` | Yes | First documented real-money backend. Requires `fee_limit_sat`, REST URL, macaroon hex, and usually a TLS cert path. Hosted LND providers are compatible when they expose equivalent LND REST credentials. |
| Phoenixd | Maybe | Maybe, API/version dependent | No, capability spike only | Unsupported for real automated payer use until `doctor` and `pay-invoice` prove preimage return and enforceable fee-limit behavior for the exact Phoenixd build. |
| LNbits with Spark | Yes, when wallet is funded | Not generally exposed to Paygate | No | Useful as a merchant/receiver wallet. Unsupported as an automated payer unless the configured funding source exposes payment preimages and fee-limit enforcement. |
| LNbits with LND funding source | Yes | Maybe, if the funding source exposes preimages through LNbits or direct LND access | No, use LND REST directly when possible | LNbits may sit in front of LND for receiving or merchant workflows, but Paygate payer automation should use direct LND REST credentials unless LNbits proves preimage and fee-cap support. |
| Blink | Yes | Not through a supported Paygate payer API | No | Not recommended for automated Paygate payer use unless Blink exposes payer-side preimages and enforceable fee caps through a supported API. |

## Required payer capabilities

- Pay a BOLT11 invoice programmatically.
- Return the exact payment preimage for successful payments.
- Enforce `max_fee_sats` before submitting or committing the payment.
- Return enough payment hash, amount, and fee metadata for diagnostics.
- Fail closed when credentials, fee caps, or backend responses are invalid.

## Policy requirements

Real payment requires explicit local policy:

- `policy.allowed_hosts` must include the target `host:port`.
- `policy.allowed_services` must include the Paygate challenge service.
- `policy.max_request_sats` must cap each invoice amount.
- `policy.max_fee_sats` must cap routing fees.
- `policy.daily_budget_sats` must cap daily automated spend.

Empty allowlists fail closed. Do not use wildcard host or service values.

## Diagnostic commands

```bash
paygate backend doctor --config ~/.config/paygate-client/config.yaml --json
paygate backend pay-invoice <bolt11> \
  --config ~/.config/paygate-client/config.yaml \
  --max-fee-sats 5 \
  --json
```

`doctor` must report `maxFeeLimitSupported: true`. `pay-invoice` must report
`ok: true`, `preimageVerified: true`, and a redacted payment preimage. If either
check fails, do not use that backend for automated Paygate payer traffic.
