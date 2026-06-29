#!/usr/bin/env bash
set -euo pipefail

CONFIG_DIR="${PAYGATE_CLIENT_CONFIG_DIR:-$HOME/.config/paygate-client}"
CONFIG_PATH="$CONFIG_DIR/config.yaml"
ENV_PATH="$CONFIG_DIR/voltage-env.sh"

DEFAULT_NODE_HOST="greenharborlabs-lightning-node.m.voltageapp.io"
DEFAULT_ALLOWED_HOST="127.0.0.1:8080"
DEFAULT_SERVICE="paygate-reference-service"
DEFAULT_MAX_REQUEST_SATS="10"
DEFAULT_MAX_FEE_SATS="2"
DEFAULT_DAILY_BUDGET_SATS="100"

mkdir -p "$CONFIG_DIR"
umask 077

prompt() {
  local label="$1"
  local default="$2"
  local value

  if [ -n "$default" ]; then
    read -r -p "$label [$default]: " value
    printf '%s' "${value:-$default}"
  else
    read -r -p "$label: " value
    printf '%s' "$value"
  fi
}

prompt_secret() {
  local label="$1"
  local value

  read -r -s -p "$label: " value
  printf '\n' >&2
  printf '%s' "$value"
}

normalize_rest_url() {
  local raw="$1"
  local url="$raw"

  if [[ "$url" != http://* && "$url" != https://* ]]; then
    url="https://$url"
  fi
  if [[ "$url" != *:[0-9]* ]]; then
    url="$url:8080"
  fi
  printf '%s' "$url"
}

require_non_empty() {
  local name="$1"
  local value="$2"

  if [ -z "$value" ]; then
    printf 'Error: %s is required.\n' "$name" >&2
    exit 1
  fi
}

require_non_negative_int() {
  local name="$1"
  local value="$2"

  if ! [[ "$value" =~ ^[0-9]+$ ]]; then
    printf 'Error: %s must be a non-negative integer.\n' "$name" >&2
    exit 1
  fi
}

require_hex() {
  local name="$1"
  local value="$2"

  if ! [[ "$value" =~ ^[0-9a-fA-F]+$ ]]; then
    printf 'Error: %s must be hex encoded.\n' "$name" >&2
    exit 1
  fi
  if (( ${#value} % 2 != 0 )); then
    printf 'Error: %s must have an even number of hex characters.\n' "$name" >&2
    exit 1
  fi
}

printf '\nPaygate Voltage setup wizard\n'
printf 'This writes local config under %s and never writes secrets to the repo.\n\n' "$CONFIG_DIR"

printf 'Checklist before continuing:\n'
printf '  1. Voltage node is mainnet, synced, and unlocked.\n'
printf '  2. You have the node REST endpoint.\n'
printf '  3. You have a payment-capable macaroon hex from Voltage.\n'
printf '  4. The node has or will have outbound liquidity before real payment tests.\n\n'

node_host="$(prompt "Voltage node host or REST URL" "$DEFAULT_NODE_HOST")"
rest_url="$(normalize_rest_url "$node_host")"
macaroon_hex="$(prompt_secret "Voltage macaroon hex (input hidden)")"
tls_cert_path="$(prompt "TLS cert path, blank for Voltage hosted default" "")"
allowed_host="$(prompt "Paygate service host:port allowlist entry" "$DEFAULT_ALLOWED_HOST")"
allowed_service="$(prompt "Paygate service name allowlist entry" "$DEFAULT_SERVICE")"
max_request_sats="$(prompt "Max request sats" "$DEFAULT_MAX_REQUEST_SATS")"
max_fee_sats="$(prompt "Max routing fee sats" "$DEFAULT_MAX_FEE_SATS")"
daily_budget_sats="$(prompt "Daily budget sats" "$DEFAULT_DAILY_BUDGET_SATS")"

require_non_empty "Voltage REST URL" "$rest_url"
require_non_empty "macaroon hex" "$macaroon_hex"
require_hex "macaroon hex" "$macaroon_hex"
require_non_empty "allowed host" "$allowed_host"
require_non_empty "allowed service" "$allowed_service"
require_non_negative_int "max request sats" "$max_request_sats"
require_non_negative_int "max fee sats" "$max_fee_sats"
require_non_negative_int "daily budget sats" "$daily_budget_sats"

if (( max_request_sats > daily_budget_sats )); then
  printf 'Error: max request sats must not exceed daily budget sats.\n' >&2
  exit 1
fi

if [ -f "$CONFIG_PATH" ]; then
  backup="$CONFIG_PATH.bak-$(date +%Y%m%d%H%M%S)"
  cp "$CONFIG_PATH" "$backup"
  printf 'Backed up existing config to %s\n' "$backup"
fi

cat > "$ENV_PATH" <<EOF
export PAYGATE_CLIENT_LND_REST_URL="$rest_url"
export PAYGATE_CLIENT_LND_MACAROON_HEX="$macaroon_hex"
EOF

if [ -n "$tls_cert_path" ]; then
  cat >> "$ENV_PATH" <<EOF
export PAYGATE_CLIENT_LND_TLS_CERT_PATH="$tls_cert_path"
EOF
fi

chmod 600 "$ENV_PATH"

cat > "$CONFIG_PATH" <<EOF
payer:
  backend: lnd-rest

policy:
  max_request_sats: $max_request_sats
  max_fee_sats: $max_fee_sats
  daily_budget_sats: $daily_budget_sats
  allowed_hosts:
    - $allowed_host
  allowed_services:
    - $allowed_service

protocol:
  preferred: Payment
  allow_l402: true

lnd:
  rest_url_env: "PAYGATE_CLIENT_LND_REST_URL"
  macaroon_hex_env: "PAYGATE_CLIENT_LND_MACAROON_HEX"
EOF

if [ -n "$tls_cert_path" ]; then
  cat >> "$CONFIG_PATH" <<EOF
  tls_cert_path_env: "PAYGATE_CLIENT_LND_TLS_CERT_PATH"
EOF
fi

printf '\nWrote:\n'
printf '  Config: %s\n' "$CONFIG_PATH"
printf '  Private env: %s\n' "$ENV_PATH"
printf '\nNext commands:\n'
printf '  paygate backend doctor --config %q --json\n' "$CONFIG_PATH"
printf '\nPaygate will load the generated private env file next to this config.\n'
printf 'To also load these values into your current shell, run: source %q\n' "$ENV_PATH"
printf '\nBefore real Paygate tests, confirm the Voltage node has outbound liquidity.\n'
