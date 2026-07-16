#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="${PAYGATE_CLIENT_VENV:-"$ROOT_DIR/.venv"}"
PYTHON="$VENV_DIR/bin/python"

cd "$ROOT_DIR"

if [[ ! -x "$PYTHON" ]]; then
  echo "Creating virtualenv at $VENV_DIR"
  python3 -m venv "$VENV_DIR"
fi

if ! "$PYTHON" -m pip --version >/dev/null 2>&1; then
  "$PYTHON" -m ensurepip --upgrade
fi

if ! "$PYTHON" -c "import breez_sdk_spark" >/dev/null 2>&1; then
  echo "Installing Breez support into $VENV_DIR"
  "$PYTHON" -m pip install ".[breez]"
fi

if [[ -z "${BREEZ_STORAGE_DIR:-}" ]]; then
  export BREEZ_STORAGE_DIR="$ROOT_DIR/.breez-preimage-doctor"
fi

exec "$PYTHON" "$ROOT_DIR/scripts/breez-payment-history.py" "$@"
