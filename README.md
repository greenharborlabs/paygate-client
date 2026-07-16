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

For guided Voltage/LND setup, run:

```bash
scripts/setup-voltage-paygate.sh
```

The wizard prompts for the Voltage REST URL, macaroon hex, optional TLS cert
path, allowlist entries, and spend caps. It writes the Paygate config to
`~/.config/paygate-client/config.yaml` and stores secrets only in
`~/.config/paygate-client/voltage-env.sh`.

## Breez Preimage Doctor

To test whether Breez SDK Spark can pay a BOLT11 invoice and return the
Lightning preimage Paygate needs, run the isolated spike script:

```bash
python3 -m pip install breez-sdk-spark
export BREEZ_API_KEY="..."
export BREEZ_MNEMONIC="..."
scripts/breez-preimage-doctor.py "<bolt11 invoice>"
```

The script forces `prefer_spark=False`, extracts `payment_hash` and `preimage`
from the returned payment object, verifies `sha256(preimage) == payment_hash`,
and prints `PASS` or a loud JSON failure.

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

By default, `paygate request` acts as a payment/session credential manager:

1. It checks for a valid cached credential scoped to the request.
2. If one works, it sends the request without paying again and returns
   `credentialCache.hit: true`.
3. If no reusable credential works and the server returns `402`, it enforces
   local policy, pays, builds the retry credential, caches it when the challenge
   has a safe reuse window, and retries.

Cached credentials are bearer-style payment credentials. Treat them like
secrets. The metadata file is `~/.config/paygate-client/credentials.json` with
`0600` permissions. When the optional keyring backend is available, the
credential secret is stored in the OS keyring and only metadata is written to
the file.

For shared machines or multi-agent environments, use `--profile` to isolate
each agent's cached credentials, keyring entries, and daily spend ledger. The
default profile preserves the legacy paths:

- default credential cache:
  `~/.config/paygate-client/credentials.json`
- profile credential cache:
  `~/.config/paygate-client/profiles/<profile>/credentials.json`
- default spend ledger:
  `~/.local/state/paygate-client/daily-spend-ledger.json`
- profile spend ledger:
  `~/.local/state/paygate-client/profiles/<profile>/daily-spend-ledger.json`

Profiles are intended for manager/subagent setups. A manager agent can use a
profile with payer credentials and a larger policy budget. Subagents should use
separate profiles with narrower config policy, restricted backend macaroons, or
no payer credentials at all. Do not share the manager profile with subagents.

Useful request flags:

```bash
# Inspect the 402 challenge and local policy result without paying.
paygate request GET "https://api.example.com/protected" \
  --config ~/.config/paygate-client/config.yaml \
  --no-pay --trace-json

# Show a human-readable step trail on stderr.
paygate request GET "https://api.example.com/protected" \
  --config ~/.config/paygate-client/config.yaml \
  --verbose

# Bypass cache and force a fresh payment flow.
paygate request GET "https://api.example.com/protected" \
  --config ~/.config/paygate-client/config.yaml \
  --refresh-credential

# Disable credential cache reads and writes for one request.
paygate request GET "https://api.example.com/protected" \
  --config ~/.config/paygate-client/config.yaml \
  --no-cache

# Run as a specific agent profile with isolated cache and budget ledger.
paygate request GET "https://api.example.com/protected" \
  --config ~/.config/paygate-client/config.yaml \
  --profile worker-a

# Override cache and ledger locations for containerized agents.
paygate request GET "https://api.example.com/protected" \
  --config ~/.config/paygate-client/config.yaml \
  --profile worker-a \
  --cache-path /tmp/paygate-worker-a/credentials.json \
  --ledger-path /tmp/paygate-worker-a/daily-spend-ledger.json
```

Credential cache commands:

```bash
paygate credentials list
paygate credentials show <credential-id>
paygate credentials purge --host localhost:8080 --service paygate-reference-service
paygate credentials purge --all

# Inspect or purge a specific agent profile.
paygate credentials list --profile worker-a
paygate credentials show <credential-id> --profile worker-a
paygate credentials purge --all --profile worker-a
```

`list` and `show` redact credential secrets by default.

### Multi-Agent Client Example

Use separate configs when agents have different authority. This example gives
the manager a broader LND macaroon and the worker a restricted macaroon and
smaller policy budget:

```yaml
# ~/.config/paygate-client/manager.yaml
payer:
  backend: lnd-rest
policy:
  max_request_sats: 100
  max_fee_sats: 10
  daily_budget_sats: 1000
  allowed_hosts:
    - api.example.com:443
  allowed_services:
    - paygate-reference-service
protocol:
  preferred: Payment
  allow_l402: true
lnd:
  rest_url_env: "PAYGATE_CLIENT_LND_REST_URL"
  macaroon_hex_env: "PAYGATE_CLIENT_MANAGER_MACAROON_HEX"
```

```yaml
# ~/.config/paygate-client/worker-a.yaml
payer:
  backend: lnd-rest
policy:
  max_request_sats: 10
  max_fee_sats: 2
  daily_budget_sats: 50
  allowed_hosts:
    - api.example.com:443
  allowed_services:
    - paygate-reference-service
protocol:
  preferred: Payment
  allow_l402: true
lnd:
  rest_url_env: "PAYGATE_CLIENT_LND_REST_URL"
  macaroon_hex_env: "PAYGATE_CLIENT_WORKER_A_MACAROON_HEX"
```

```bash
export PAYGATE_CLIENT_LND_REST_URL="https://127.0.0.1:8080"
export PAYGATE_CLIENT_MANAGER_MACAROON_HEX="<manager-macaroon-hex>"
export PAYGATE_CLIENT_WORKER_A_MACAROON_HEX="<restricted-worker-macaroon-hex>"

paygate request GET "https://api.example.com/protected" \
  --config ~/.config/paygate-client/manager.yaml \
  --profile manager

paygate request GET "https://api.example.com/protected" \
  --config ~/.config/paygate-client/worker-a.yaml \
  --profile worker-a
```

The two requests use separate credential caches, keyring accounts, and daily
budget ledgers. If the manager pays for reusable credentials, do not copy the
manager cache to workers unless the credential is intentionally delegated and
safe for that worker's host, service, and use window.

## Local Dev Payment Recipes

These recipes use `test-mode`, which does not make real Lightning payments. The
local reference service must run in dev mode and include a `test_preimage` in
local/test 402 responses. The preimage is a 32-byte Lightning payment preimage
encoded as 64 lowercase hex characters, and its SHA-256 hash must match the
challenge invoice's payment hash.

### L402 With Test Preimage

Use the default example config when it prefers L402:

```yaml
protocol:
  preferred: L402
  allow_l402: true
```

Run the local request:

```bash
paygate request GET \
  "http://localhost:8080/api/v1/trust/report?domain=example.com&checks=dns" \
  --config examples/paygate-client.yaml \
  --no-pay --trace-json
```

Then run the local paid retry path:

```bash
paygate request GET \
  "http://localhost:8080/api/v1/trust/report?domain=example.com&checks=dns" \
  --config examples/paygate-client.yaml \
  --verbose
```

Expected success shape:

```json
{
  "ok": true,
  "paid": true,
  "protocol": "L402",
  "payerBackend": "test-mode"
}
```

The retry sends:

```http
Authorization: L402 <token-or-macaroon>:<64 lowercase hex preimage>
```

### MPP Payment With Test Preimage

Create a temporary Payment-preferred config:

```bash
cp examples/paygate-client.yaml /tmp/paygate-client-payment.yaml
perl -0pi -e 's/preferred: L402/preferred: Payment/' \
  /tmp/paygate-client-payment.yaml
```

Run the same local request:

```bash
paygate request GET \
  "http://localhost:8080/api/v1/trust/report?domain=example.com&checks=dns" \
  --config /tmp/paygate-client-payment.yaml \
  --verbose
```

Expected success shape:

```json
{
  "ok": true,
  "paid": true,
  "protocol": "Payment",
  "payerBackend": "test-mode"
}
```

The retry sends:

```http
Authorization: Payment <base64url-json>
```

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

## Real-Money Backend: Breez SDK Spark

Breez SDK Spark can pay BOLT11 invoices without running a Lightning node. For
Paygate, Spark preference is disabled so successful payments must return a
Lightning preimage.

Install optional Breez support:

```bash
python -m pip install "paygate-client[breez]"
```

For local wallet checks from this repository, use the wrapper script. It uses
the repo `.venv`, installs the Breez extra there if needed, and avoids
Homebrew's externally managed Python restriction:

```bash
export BREEZ_API_KEY="replace-with-breez-api-key"
export BREEZ_MNEMONIC="replace-with-wallet-seed-words"
scripts/check-breez-wallet.sh
```

To print wallet payment history, use the matching history wrapper:

```bash
scripts/breez-payment-history.sh
scripts/breez-payment-history.sh --limit 10 --status completed
scripts/breez-payment-history.sh --type send --from 2026-07-01T00:00:00Z
```

The history script outputs JSON, sorts newest first by default, and redacts
sensitive fields such as preimages unless `--include-sensitive` is passed.

```yaml
payer:
  backend: breez
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
breez:
  api_key_env: "BREEZ_API_KEY"
  mnemonic_env: "BREEZ_MNEMONIC"
  network: mainnet
  storage_dir: "~/.local/share/paygate-client/breez"
  completion_timeout_secs: 10
```

```bash
export BREEZ_API_KEY="replace-with-breez-api-key"
export BREEZ_MNEMONIC="replace-with-wallet-seed-words"
paygate backend doctor --config ~/.config/paygate-client/config.yaml --json
```

The Breez backend checks the prepared `lightning_fee_sats` before submitting the
payment, sends with `prefer_spark=false`, and refuses success unless the returned
preimage verifies against the payment hash.

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

L402 must be enabled with `protocol.allow_l402: true`. For policy enforcement,
the client derives the payment hash and amount from the BOLT11 invoice. Local
test fixtures may provide `test_preimage` and `amountSats` in the 402 JSON body
when using `test-mode`.

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
`PAYGATE_CLIENT_PHOENIXD_PASSWORD`. If you used
`scripts/setup-voltage-paygate.sh`, make sure
`~/.config/paygate-client/voltage-env.sh` exists next to
`~/.config/paygate-client/config.yaml`; the CLI loads that companion file
automatically.

`credentialCache.hit: true`: the request succeeded with a cached payment
credential and did not pay a new invoice.

`cached_credential_rejected`: the server rejected a cached credential with a
non-`401`/`402` status. Purge the credential with `paygate credentials purge`
and retry.

`unsupported_402_challenge`: the response did not include a supported challenge,
the challenge was malformed or expired, L402 was disabled, or L402 invoice
metadata was insufficient to enforce policy before payment.

## Development

```bash
python3 -m pytest tests/test_config.py
paygate --help
paygate request --help
paygate credentials --help
paygate backend --help
paygate backend doctor --help
paygate backend pay-invoice --help
```

See [docs/dev-setup.md](docs/dev-setup.md) for more local setup notes.
