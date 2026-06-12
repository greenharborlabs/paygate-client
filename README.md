# paygate-client

`paygate-client` is a Python CLI for calling HTTP services that require a
Paygate `402 Payment Required` challenge. It can parse Paygate MPP `Payment`
challenges, optionally parse L402 challenges, enforce local spend policy, pay a
BOLT11 invoice through a configured payer backend, and retry the request with a
payment credential.

## Install

For normal CLI use from this checkout:

```bash
pipx install -e .
paygate --help
```

For local development:

```bash
python3 -m pip install -e ".[dev]"
paygate --help
```

## First Local Config

Start with `test-mode`. It never sends real Lightning payments and can satisfy
test challenges that include a test preimage.

```bash
mkdir -p ~/.config/paygate-client
cp examples/paygate-client.yaml ~/.config/paygate-client/config.yaml
paygate --version
```

The config schema is:

```yaml
payer:
  backend: test-mode
policy:
  max_request_sats: 50
  max_fee_sats: 10
  daily_budget_sats: 500
  allowed_hosts:
    - localhost:8080
  allowed_services:
    - paygate-reference-service
protocol:
  preferred: Payment
  allow_l402: true
```

Payment is denied unless the target host is in `policy.allowed_hosts`, the
challenge service is in `policy.allowed_services`, the invoice amount is at or
below `policy.max_request_sats`, the local daily budget is available, and the
backend can enforce `policy.max_fee_sats`.

## Request A Resource

Command form:

```bash
paygate request GET "https://..."
```

```bash
paygate request GET "https://api.example.com/protected" \
  --config ~/.config/paygate-client/config.yaml
```

Headers and bodies are supported:

```bash
paygate request POST "https://api.example.com/protected" \
  --config ~/.config/paygate-client/config.yaml \
  -H "Content-Type: application/json" \
  --body '{"prompt":"hello"}' \
  --timeout 30
```

The command prints a JSON envelope. Successful unpaid responses include
`ok: true`, `paid: false`, and `response`. Successful paid responses include
`ok: true`, `paid: true`, `response`, and top-level `payerBackend`,
`amountSats`, `feeSats`, and `paymentHash` metadata. Failures include
`ok: false`, `paid`, and `error.code` plus `error.message`.

## Backend Diagnostics

Run diagnostics before enabling real payments. The diagnostic commands are
`paygate backend doctor --json` and
`paygate backend pay-invoice <bolt11> --json`; use the runnable forms below so
the required config and fee options are included.

Copy-pasteable forms with the required config and fee options:

```bash
paygate backend doctor --config ~/.config/paygate-client/config.yaml --json
```

Expected success shape:

```json
{
  "ok": true,
  "backend": "lnd-rest",
  "configValid": true,
  "envSecretsAvailable": true,
  "capabilities": {
    "preimageRequired": true,
    "maxFeeLimitSupported": true
  }
}
```

Pay a low-value standalone invoice only after `doctor` succeeds:

```bash
paygate backend pay-invoice <bolt11> \
  --config ~/.config/paygate-client/config.yaml \
  --max-fee-sats 5 \
  --json
```

Expected success shape:

```json
{
  "ok": true,
  "backend": "lnd-rest",
  "payment": {
    "amountSats": 1,
    "feeSats": 0,
    "paymentHash": "<hex>",
    "preimage": "[REDACTED_SECRET]"
  },
  "preimageVerified": true,
  "verificationSource": "invoice"
}
```

## Real-Money Backend: LND REST

The first documented real-money payer backend is `lnd-rest`, including hosted
LND providers such as Voltage when they expose LND REST credentials.

```yaml
payer:
  backend: lnd-rest
policy:
  max_request_sats: 50
  max_fee_sats: 10
  daily_budget_sats: 500
  allowed_hosts:
    - api.example.com:443
  allowed_services:
    - paygate-reference-service
protocol:
  preferred: Payment
  allow_l402: true
lnd:
  rest_url_env: "PAYGATE_CLIENT_LND_REST_URL"
  macaroon_hex_env: "PAYGATE_CLIENT_LND_MACAROON_HEX"
  tls_cert_path_env: "PAYGATE_CLIENT_LND_TLS_CERT_PATH"
```

```bash
export PAYGATE_CLIENT_LND_REST_URL="https://127.0.0.1:8080"
export PAYGATE_CLIENT_LND_MACAROON_HEX="$(xxd -p -c 256 ~/.lnd/data/chain/bitcoin/mainnet/admin.macaroon)"
export PAYGATE_CLIENT_LND_TLS_CERT_PATH="$HOME/.lnd/tls.cert"
paygate backend doctor --config ~/.config/paygate-client/config.yaml --json
```

`paygate-client` calls LND REST `POST /v2/router/send` with
`payment_request` and `fee_limit_sat`. It requires a terminal successful update
with `payment_preimage`.

## Phoenixd

Phoenixd support is a capability spike until `paygate backend doctor --json` and
`paygate backend pay-invoice <bolt11> --json` prove that your Phoenixd API
returns payment preimages and enforces the configured fee-limit parameter before
payment.

```yaml
payer:
  backend: phoenixd
phoenixd:
  url: "http://127.0.0.1:9740"
  password_env: "PAYGATE_CLIENT_PHOENIXD_PASSWORD"
  fee_limit_parameter: "maxFeeSat"
```

```bash
export PAYGATE_CLIENT_PHOENIXD_PASSWORD="replace-with-phoenixd-password"
paygate backend doctor --config ~/.config/paygate-client/config.yaml --json
```

See [docs/phoenixd-spike.md](docs/phoenixd-spike.md).

## Backend Compatibility

See [docs/payer-backend-compatibility.md](docs/payer-backend-compatibility.md).
LNbits can be useful as a merchant or receiver backend. It is unsupported as an
automated Paygate payer backend unless the configured funding source exposes
payment preimages. Blink is not recommended for Paygate payer automation unless
it exposes payer-side preimages and enforceable fee caps through a supported API.

## Protocol Reference

MPP `Payment` challenge:

```http
WWW-Authenticate: Payment realm="<service>", id="<challenge-id>", method="lightning", request="<base64url-json>", expires="<unix-seconds>", digest="<digest>", opaque="<base64url-json>"
```

The `request` auth param is base64url without padding. It decodes to a JSON
object:

```json
{
  "invoice": "lnbc...",
  "amountSats": 10,
  "service": "paygate-reference-service",
  "description": "optional text",
  "methodDetails": {
    "paymentHash": "<64 hex chars>"
  }
}
```

`amount_sats` and `payment_hash` are also accepted as snake-case aliases.
`opaque`, when present, is also base64url without padding. In test fixtures it
may decode to `{"test_preimage":"<64 hex chars>"}`.

MPP retry credential:

```http
Authorization: Payment <base64url-json>
```

The credential payload is base64url-nopad JSON and has this shape:

```json
{
  "challenge": {
    "id": "<challenge-id>",
    "realm": "<service>",
    "method": "lightning",
    "intent": "optional",
    "expires": 1710000000,
    "digest": "optional",
    "description": "optional",
    "opaque": "<base64url-json>",
    "request": {
      "invoice": "lnbc...",
      "amountSats": 10,
      "service": "paygate-reference-service",
      "methodDetails": {
        "paymentHash": "<64 hex chars>"
      }
    }
  },
  "payload": {
    "preimage": "<64 lowercase hex chars>"
  },
  "source": "lnd-rest"
}
```

`source` is optional. JSON is emitted compactly with sorted keys.

L402 challenge:

```http
WWW-Authenticate: L402 token="<token>", invoice="lnbc...", version="0"
WWW-Authenticate: L402 macaroon="<macaroon>", invoice="lnbc..."
```

L402 retry credential:

```http
Authorization: L402 <token-or-macaroon>:<64 lowercase hex preimage>
```

L402 must be enabled with `protocol.allow_l402: true`. Current request
orchestration returns `unsupported_402_challenge` for L402 payment challenges
because the implemented payment flow depends on MPP metadata.

## Troubleshooting

`PAYER_BACKEND_MISSING_PREIMAGE` or `missing_preimage`: the payer reported
success without a preimage. Use LND REST or another backend that returns the
payment preimage.

`PAYER_BACKEND_PREIMAGE_VERIFICATION_FAILED` or `preimage_verification_failed`:
the returned preimage does not hash to the invoice payment hash. Treat the
payment as suspect and do not retry manually with that credential.

`PAYER_BACKEND_UNSUPPORTED_FEE_LIMIT` or `policy_denied`: the backend cannot
enforce `max_fee_sats`, or local policy rejected the host, service, amount, fee
cap, or daily budget.

`PAYGATE_SECRET_MISSING`: set the configured secret env var, such as
`PAYGATE_CLIENT_LND_MACAROON_HEX`,
`PAYGATE_CLIENT_LND_REST_URL`,
`PAYGATE_CLIENT_LND_TLS_CERT_PATH`, or
`PAYGATE_CLIENT_PHOENIXD_PASSWORD`.

`unsupported_402_challenge`: the response did not include a supported `Payment`
challenge, the challenge was malformed or expired, or only L402 was available
while L402 is disabled or not supported by the request orchestrator.

## Development

```bash
python3 -m pytest tests/test_config.py
paygate --help
paygate request --help
paygate backend --help
paygate backend doctor --help
paygate backend pay-invoice --help
```

See [docs/dev-setup.md](docs/dev-setup.md) for more local setup notes.
