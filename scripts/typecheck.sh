#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="${PAYGATE_CLIENT_TYPECHECK_VENV:-"$ROOT_DIR/.venv-typecheck"}"
PYTHON="$VENV_DIR/bin/python"
DEPS_FINGERPRINT_FILE="$VENV_DIR/.paygate-client-dev-deps.cksum"

cd "$ROOT_DIR"

if [[ ! -x "$PYTHON" ]]; then
  BOOTSTRAP_PYTHON="${PAYGATE_CLIENT_PYTHON:-}"
  if [[ -z "$BOOTSTRAP_PYTHON" ]] && command -v python3.10 >/dev/null 2>&1; then
    BOOTSTRAP_PYTHON="python3.10"
  fi
  if [[ -z "$BOOTSTRAP_PYTHON" && -x "$ROOT_DIR/.venv/bin/python" ]]; then
    BOOTSTRAP_PYTHON="$ROOT_DIR/.venv/bin/python"
  fi
  if [[ -z "$BOOTSTRAP_PYTHON" ]]; then
    echo "Python 3.10 is required to mirror CI. Set PAYGATE_CLIENT_PYTHON to it." >&2
    exit 1
  fi
  if ! "$BOOTSTRAP_PYTHON" -c 'import sys; raise SystemExit(sys.version_info[:2] != (3, 10))'; then
    echo "Python 3.10 is required to mirror CI. Set PAYGATE_CLIENT_PYTHON to it." >&2
    exit 1
  fi

  echo "Creating virtualenv at $VENV_DIR"
  "$BOOTSTRAP_PYTHON" -m venv "$VENV_DIR"
fi

if ! "$PYTHON" -m pip --version >/dev/null 2>&1; then
  "$PYTHON" -m ensurepip --upgrade
fi

current_fingerprint="$(cksum pyproject.toml)"
installed_fingerprint=""
if [[ -f "$DEPS_FINGERPRINT_FILE" ]]; then
  installed_fingerprint="$(<"$DEPS_FINGERPRINT_FILE")"
fi

if [[ "$current_fingerprint" != "$installed_fingerprint" ]]; then
  echo "Installing development dependencies into $VENV_DIR"
  "$PYTHON" -m pip install --upgrade pip
  "$PYTHON" -m pip install -e ".[dev]"
  printf '%s\n' "$current_fingerprint" >"$DEPS_FINGERPRINT_FILE"
fi

exec "$PYTHON" -m mypy --cache-dir "$VENV_DIR/mypy-cache" "$@"
