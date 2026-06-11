# paygate-client

`paygate-client` is a Python command-line client for Paygate.

## What it does

This project provides:

- a `paygate` CLI entry point
- typed config loading for Paygate YAML files
- support for `test-mode`, `phoenixd`, and `lnd-rest` payer backends
- redaction helpers for secrets and other sensitive values

## Install

```bash
python3 -m pip install -e ".[dev]"
```

## CLI

Show the built-in help:

```bash
paygate --help
```

Show the installed version:

```bash
paygate --version
```

## Configuration

The client loads a YAML config with these top-level sections:

- `payer`
- `policy`
- `protocol`
- `phoenixd` when using the `phoenixd` backend
- `lnd` when using the `lnd-rest` backend

Minimal example:

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
  allow_l402: false
```

For `phoenixd` and `lnd-rest`, sensitive values are read from environment variables rather than stored directly in the config file.

## Development

See [docs/dev-setup.md](docs/dev-setup.md) for local development and verification commands.
