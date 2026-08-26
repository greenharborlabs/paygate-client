# paygate-client

`paygate-client` is a Rust CLI for calling HTTP services protected by a
Paygate `402 Payment Required` challenge. It validates MPP `Payment` and
optional L402 challenges, enforces local spend policy, pays a BOLT11 invoice
through Breez SDK Spark, and retries the request with a scoped payment
credential.

The production command is the Rust `paygate` binary. Python code remains in
this repository for compatibility testing, historical behavior comparison,
and a legacy package workflow. It is not the primary runtime.

## Status

- Version: `0.1.0`
- Production payer backend: Breez SDK Spark
- Protocols: MPP `Payment` and optional L402
- Native qualification targets: Linux x86_64, Linux ARM64, macOS Intel, and
  macOS Apple Silicon; consult the evidence workflow before claiming a
  particular release is qualified
- Public distribution: source installation only; there is currently no
  crates.io package or prebuilt GitHub Release

The deployment migration to Rust is complete. Fresh installations do not use
migration scripts. The retained migration runbook, Wave plans, and
qualification reports are historical evidence, not installation instructions.

## Install the Rust CLI

The checked-in toolchain selects Rust 1.88.0. The Breez dependency graph also
needs the Protocol Buffer compiler at build time.

Install prerequisites on macOS:

```bash
brew install protobuf
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Install prerequisites on Ubuntu or Debian:

```bash
sudo apt-get update
sudo apt-get install --yes protobuf-compiler
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Build and install from a reviewed checkout:

```bash
git clone https://github.com/greenharborlabs/paygate-client.git
cd paygate-client
git checkout ca087739b98e7f5259096234730d076eb0dc87b4
cargo install --locked --path .
paygate --version
paygate --help
```

The pinned commit above is the first reviewed Rust-only production baseline.
For a newer deployment, replace it with a reviewed commit from `main`. Keep
`--locked`; it makes Cargo use the committed dependency graph. Cargo installs
the executable to `~/.cargo/bin/paygate` unless `CARGO_HOME` is configured
differently.

## Safe first run

Start with the example configuration. Its `test-mode` backend is safe for
config validation and ordinary unpaid HTTP responses, but it is not wired as a
live payer in the production Rust CLI.

```bash
mkdir -p ~/.config/paygate-client
cp examples/paygate-client.yaml ~/.config/paygate-client/config.yaml

paygate backend doctor \
  --config ~/.config/paygate-client/config.yaml \
  --json

paygate request GET https://example.com \
  --config ~/.config/paygate-client/config.yaml
```

Do not use `test-mode`, LND REST, or Phoenixd for a paid Rust CLI request.
Their current support levels are listed in
[Payer backend compatibility](docs/payer-backend-compatibility.md).

## Configure Breez SDK Spark

Breez is the production payment backend. It pays BOLT11 invoices with
`prefer_spark=false`, checks the prepared Lightning fee before submission, and
requires a preimage that hashes to the invoice payment hash.

Create `~/.config/paygate-client/config.yaml`:

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
  api_key_env: BREEZ_API_KEY
  mnemonic_env: BREEZ_MNEMONIC
  network: mainnet
  storage_dir: ~/.local/share/paygate-client/breez
  completion_timeout_secs: 10
```

Provide the wallet secrets through the process environment:

```bash
export BREEZ_API_KEY="replace-with-breez-api-key"
export BREEZ_MNEMONIC="replace-with-wallet-seed-words"

paygate backend doctor \
  --config ~/.config/paygate-client/config.yaml \
  --json
```

For restart-persistent operation, store those two `export` lines in
`~/.config/paygate-client/paygate-env.sh` and set mode `0600`:

```bash
chmod 600 ~/.config/paygate-client/paygate-env.sh
```

Process environment values take precedence over the companion file. The
legacy `voltage-env.sh` filename is read only when `paygate-env.sh` is absent;
the files are never merged.

`backend doctor` does not create or pay an invoice. It must return `ok: true`,
`backendReady: true`, and `maxFeeLimitSupported: true` before any paid command
is considered.

## Request a resource

```bash
paygate request GET "https://api.example.com/protected" \
  --config ~/.config/paygate-client/config.yaml
```

Headers, JSON bodies, and per-phase timeouts are supported:

```bash
paygate request POST "https://api.example.com/protected" \
  --config ~/.config/paygate-client/config.yaml \
  -H "Content-Type: application/json" \
  --body '{"prompt":"hello"}' \
  --timeout 30
```

The command writes one JSON envelope to stdout. Successful unpaid responses
contain `ok: true`, `paid: false`, and `response`. Successful paid responses
also contain `payerBackend`, `amountSats`, `feeSats`, and `paymentHash`.
Failures contain `ok: false`, `paid`, and a redacted `error` object.

### Inspect without paying

`--no-pay` validates the `402` challenge and local policy but does not submit a
payment:

```bash
paygate request GET "https://api.example.com/protected" \
  --config ~/.config/paygate-client/config.yaml \
  --no-pay \
  --trace-json
```

The selected config still needs non-empty values for its referenced environment
variables, but the no-pay path does not create or pay an invoice.

### Tracing and cache controls

```bash
# Human-readable events on stderr.
paygate request GET "https://api.example.com/protected" \
  --config ~/.config/paygate-client/config.yaml \
  --verbose

# Force a new challenge/payment flow instead of using a cached credential.
paygate request GET "https://api.example.com/protected" \
  --config ~/.config/paygate-client/config.yaml \
  --refresh-credential

# Disable credential cache reads and writes for one request.
paygate request GET "https://api.example.com/protected" \
  --config ~/.config/paygate-client/config.yaml \
  --no-cache
```

`--trace-json` writes redacted JSON-line events to stderr. Response bodies and
authorization values are not included in trace fields.

## Credential cache and profiles

Before entering a new payment flow, `paygate request` atomically claims a
matching cached credential. A successful cache reuse reports `paid: false` and
`credentialCache.hit: true`. Single-use credentials are durably consumed
before their bearer value is returned, preventing concurrent reuse.

Credential metadata uses owner-only files. Authorization values use the OS
keyring when available and otherwise fall back to the owner-only state file.

Default paths:

- Credential cache: `~/.config/paygate-client/credentials.json`
- Spend ledger: `~/.local/state/paygate-client/daily-spend-ledger.json`

Profile paths:

- Credential cache:
  `~/.config/paygate-client/profiles/<profile>/credentials.json`
- Spend ledger:
  `~/.local/state/paygate-client/profiles/<profile>/daily-spend-ledger.json`

Use a separate profile whenever multiple agents share a Unix account:

```bash
paygate request GET "https://api.example.com/protected" \
  --config ~/.config/paygate-client/worker-a.yaml \
  --profile worker-a

paygate credentials list --profile worker-a
paygate credentials show <credential-id> --profile worker-a
paygate credentials purge --all --profile worker-a
```

Explicit state paths are useful in containers:

```bash
paygate request GET "https://api.example.com/protected" \
  --config ~/.config/paygate-client/worker-a.yaml \
  --profile worker-a \
  --cache-path /tmp/paygate-worker-a/credentials.json \
  --ledger-path /tmp/paygate-worker-a/daily-spend-ledger.json
```

Do not share a manager profile with less-trusted workers. Cached payment
credentials are bearer credentials even though list/show output redacts them.

## Standalone invoice payment

This command sends a real payment. Use it only after `backend doctor` succeeds
and after reviewing the invoice amount, configured daily budget, and fee cap:

```bash
paygate backend pay-invoice <bolt11> \
  --config ~/.config/paygate-client/config.yaml \
  --max-fee-sats 5 \
  --json
```

The production command supports Breez only. A successful result reports a
redacted preimage, `preimageVerified: true`, and `verificationSource:
"invoice"`. An ambiguous submission is retained as counting spend and must not
be retried automatically.

## Backend support

| Backend | Rust CLI status | Paid production use |
| --- | --- | --- |
| Breez SDK Spark | Production transport is wired for requests, doctor, and standalone invoice payment | Supported with explicit local policy |
| Test mode | Config and doctor compatibility plus test-domain implementation | Not wired as a production request payer |
| LND REST / Voltage | Adapter contract and failure semantics are tested; production HTTP transport is not wired | Unsupported in this release |
| Phoenixd | Fail-closed placeholder | Unsupported in this release |

See [Payer backend compatibility](docs/payer-backend-compatibility.md) for the
full capability and safety matrix.

## Local spend policy

Every paid request must pass all local checks:

- `policy.allowed_hosts` contains the exact target `host:port`.
- `policy.allowed_services` contains the challenge service.
- Invoice amount is no greater than `policy.max_request_sats`.
- The payer can enforce `policy.max_fee_sats` before submission.
- Retained counting spend stays within `policy.daily_budget_sats`.

Empty allowlists fail closed. Wildcards are not supported. Submitted-unknown
payments remain counted because retrying could pay the same obligation twice.

## Protocol reference

MPP `Payment` challenge:

```http
WWW-Authenticate: Payment realm="<service>", id="<challenge-id>", method="lightning", request="<base64url-json>", expires="<unix-seconds>", digest="<digest>", opaque="<base64url-json>"
```

The `request` value is unpadded base64url JSON containing an amount-bearing
BOLT11 invoice, amount, service, and payment hash. Snake-case aliases
`amount_sats` and `payment_hash` are accepted.

MPP retry credential:

```http
Authorization: Payment <base64url-json>
```

L402 challenge and retry credential:

```http
WWW-Authenticate: L402 token="<token>", invoice="lnbc...", version="0"
Authorization: L402 <token-or-macaroon>:<64-lowercase-hex-preimage>
```

L402 is accepted only when `protocol.allow_l402: true`. The Rust client derives
the amount and payment hash from the signed BOLT11 invoice before applying
policy.

## Troubleshooting

`PAYGATE_CONFIG_INVALID`: the YAML file is missing, malformed, contains
duplicate/unsafe keys, names an unknown backend, or omits required fields.

`PAYGATE_SECRET_MISSING`: a selected backend's referenced environment value is
missing from the process environment or companion file.

`PAYER_BACKEND_UNSUPPORTED_FEE_LIMIT`: the selected backend is not wired for
the requested Rust CLI payment operation, or cannot prove pre-submission fee
enforcement.

`policy_denied`: host, service, amount, fee cap, or daily budget policy rejected
the payment.

`payment_submission_unknown`: submission may have reached the payer but its
outcome is unknown. Do not retry automatically; reconcile the wallet and spend
ledger first.

`PAYER_BACKEND_PREIMAGE_VERIFICATION_FAILED` or
`preimage_verification_failed`: the returned preimage does not hash to the
invoice payment hash. Treat the result as unsafe and do not reuse it.

`credential_state_failure`: the credential cache could not durably claim,
store, update, or evict a credential. Authorization is withheld when durable
state cannot be guaranteed.

Exit code `75` with a maintenance-mode message means an installation or
finalization recovery journal is active. Do not delete the journal. Resume the
exact recorded recovery operation.

## Development

Install Rust, `protoc`, and the Python development environment used by the
compatibility suite. Then run:

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked

python3 -m pip install -e ".[dev]"
python3 -m pytest
```

Python commands here test compatibility and release tooling; they do not
install the production Rust runtime. See [Developer setup](docs/dev-setup.md)
for platform prerequisites and focused checks.

## Documentation

- [Documentation index](docs/README.md)
- [Developer setup](docs/dev-setup.md)
- [Payer backend compatibility](docs/payer-backend-compatibility.md)
- [Native platform qualification](docs/platform-qualification.md)
- [Release status and procedures](docs/releasing.md)
- [Historical plans](plans/README.md)
- [Historical reports](reports/README.md)

The migration-era runbooks are retained for audit and recovery context. Do not
use them for a fresh installation.

## License

MIT. See [LICENSE](LICENSE).
