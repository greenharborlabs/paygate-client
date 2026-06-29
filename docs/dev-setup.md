# Developer Setup

## Development install

The package supports modern editable installs (`python3 -m pip install -e .`).
Older `pip` versions (for example `pip 21.2.4`) do not support PEP 660 editable
install behavior, so developers should upgrade first:

```bash
python3 -m pip install --upgrade pip
python3 -m pip install -e ".[dev]"
```

If you already have an editable checkout installed and dependencies changed,
reinstall it:

```bash
python3 -m pip install -e ".[dev]"
```

The runtime dependencies include `keyring` so cached payment credentials can use
the OS keyring when available. If keyring storage is unavailable, the client
falls back to a `0600` metadata/cache file under
`~/.config/paygate-client/credentials.json` for the default profile, or
`~/.config/paygate-client/profiles/<profile>/credentials.json` when `--profile`
is set.

## Profile-aware local CLI checks

Use `--profile` when testing multi-agent behavior. Each profile gets separate
credential cache metadata, keyring account names, and daily spend ledger state.

```bash
paygate request GET "https://api.example.com/protected" \
  --config ~/.config/paygate-client/worker-a.yaml \
  --profile worker-a \
  --no-pay --trace-json

paygate credentials list --profile worker-a
paygate credentials purge --all --profile worker-a
```

Use explicit paths when tests or containers need disposable state:

```bash
paygate request GET "https://api.example.com/protected" \
  --config ~/.config/paygate-client/worker-a.yaml \
  --profile worker-a \
  --cache-path /tmp/paygate-worker-a/credentials.json \
  --ledger-path /tmp/paygate-worker-a/daily-spend-ledger.json
```

## Verification commands

```bash
poe check
```

Run auto-formatting and safe Ruff fixes before committing:

```bash
poe fix
```

Useful local CLI checks:

```bash
paygate request --help
paygate credentials --help
paygate backend doctor --help
```
