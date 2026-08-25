#!/usr/bin/env bash
set -euo pipefail

CONFIG_DIR="${PAYGATE_CLIENT_CONFIG_DIR:-$HOME/.config/paygate-client}"
CONFIG_PATH="$CONFIG_DIR/config.yaml"
GENERIC_ENV_PATH="$CONFIG_DIR/paygate-env.sh"
LEGACY_ENV_PATH="$CONFIG_DIR/voltage-env.sh"
CANDIDATE_PATH="${PAYGATE_RUST_CANDIDATE:-}"
PYTHON_LAUNCHER="${PAYGATE_PYTHON_LAUNCHER:-$HOME/.local/bin/paygate}"
use_process_env=false
skip_doctor=false

usage() {
  printf 'usage: %s [--use-process-env] [--skip-doctor] [--config PATH] [--candidate PATH] [--python-launcher PATH]\n' "$0" >&2
  exit 2
}

while (($#)); do
  case "$1" in
    --use-process-env) use_process_env=true; shift ;;
    --skip-doctor) skip_doctor=true; shift ;;
    --config) CONFIG_PATH=${2:?}; CONFIG_DIR=$(dirname "$CONFIG_PATH"); GENERIC_ENV_PATH="$CONFIG_DIR/paygate-env.sh"; LEGACY_ENV_PATH="$CONFIG_DIR/voltage-env.sh"; shift 2 ;;
    --candidate) CANDIDATE_PATH=${2:?}; shift 2 ;;
    --python-launcher) PYTHON_LAUNCHER=${2:?}; shift 2 ;;
    *) usage ;;
  esac
done

if [[ "$skip_doctor" == false && -z "$CANDIDATE_PATH" ]]; then
  printf 'setup: --candidate PATH is required unless --skip-doctor is used\n' >&2
  usage
fi

umask 077
mkdir -p "$CONFIG_DIR"

prompt_secret_twice() {
  local label=$1 first second
  read -r -s -p "$label: " first
  printf '\n' >&2
  read -r -s -p "Confirm $label: " second
  printf '\n' >&2
  [[ -n "$first" ]] || { printf 'setup: %s is required\n' "$label" >&2; exit 1; }
  [[ "$first" == "$second" ]] || { printf 'setup: %s values did not match\n' "$label" >&2; exit 1; }
  printf '%s' "$first"
}

if [[ "$use_process_env" == true ]]; then
  api_key=${BREEZ_API_KEY:-}
  mnemonic=${BREEZ_MNEMONIC:-}
  [[ -n "$api_key" && -n "$mnemonic" ]] || {
    printf 'setup: BREEZ_API_KEY and BREEZ_MNEMONIC must both be exported\n' >&2
    exit 1
  }
else
  api_key=$(prompt_secret_twice 'Breez API key')
  mnemonic=$(prompt_secret_twice 'Breez mnemonic')
fi

validate_secret() {
  local label=$1 value=$2
  case "$value" in
    *$'\n'*|*$'\r'*|*\'*|*\"*)
      printf 'setup: %s contains a character unsupported by the companion env format\n' "$label" >&2
      exit 1
      ;;
  esac
}

validate_secret 'Breez API key' "$api_key"
validate_secret 'Breez mnemonic' "$mnemonic"

declare -a temporary_files=()
cleanup() {
  local temporary
  for temporary in "${temporary_files[@]:-}"; do
    if [[ -n "$temporary" && -f "$temporary" ]]; then
      rm -f -- "$temporary"
    fi
  done
}
trap cleanup EXIT

validate_destination() {
  local destination=$1 link_count
  [[ ! -L "$destination" ]] || { printf 'setup: refusing symlink: %s\n' "$destination" >&2; exit 1; }
  if [[ -e "$destination" ]]; then
    [[ -f "$destination" ]] || { printf 'setup: companion path is not a regular file: %s\n' "$destination" >&2; exit 1; }
    if link_count=$(stat -f '%l' "$destination" 2>/dev/null); then
      : # BSD/macOS stat
    elif link_count=$(stat -c '%h' "$destination" 2>/dev/null); then
      : # GNU/Linux stat
    else
      printf 'setup: could not inspect companion file links: %s\n' "$destination" >&2
      exit 1
    fi
    [[ "$link_count" == 1 ]] || { printf 'setup: companion file has multiple links: %s\n' "$destination" >&2; exit 1; }
  fi
}

update_companion() {
  local destination=$1 temporary line
  validate_destination "$destination"
  temporary=$(mktemp "$CONFIG_DIR/.paygate-env.XXXXXX")
  temporary_files+=("$temporary")
  chmod 600 "$temporary"
  if [[ -f "$destination" ]]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
      case "$line" in
        'export BREEZ_API_KEY='*|'export BREEZ_MNEMONIC='*) ;;
        *) printf '%s\n' "$line" >> "$temporary" ;;
      esac
    done < "$destination"
  fi
  printf "export BREEZ_API_KEY='%s'\n" "$api_key" >> "$temporary"
  printf "export BREEZ_MNEMONIC='%s'\n" "$mnemonic" >> "$temporary"
  mv -f -- "$temporary" "$destination"
  chmod 600 "$destination"
}

update_companion "$GENERIC_ENV_PATH"
update_companion "$LEGACY_ENV_PATH"
api_key=''
mnemonic=''
unset BREEZ_API_KEY BREEZ_MNEMONIC || true

printf 'Updated owner-only companion files:\n  %s\n  %s\n' "$GENERIC_ENV_PATH" "$LEGACY_ENV_PATH"

run_doctor() {
  local label=$1 executable=$2 output status
  [[ -x "$executable" ]] || { printf 'setup: %s is not executable: %s\n' "$label" "$executable" >&2; exit 1; }
  set +e
  output=$(env -i HOME="$HOME" PATH=/usr/bin:/bin "$executable" backend doctor --config "$CONFIG_PATH" --json 2>&1)
  status=$?
  set -e
  printf '%s doctor: %s\n' "$label" "$output"
  [[ $status -eq 0 ]] || { printf 'setup: %s doctor failed\n' "$label" >&2; exit 1; }
  printf '%s' "$output" | python3 -c 'import json,sys; d=json.load(sys.stdin); raise SystemExit(0 if d.get("ok") is True and d.get("backend") == "breez" else 1)' || {
    printf 'setup: %s doctor did not return a successful Breez envelope\n' "$label" >&2
    exit 1
  }
}

if [[ "$skip_doctor" == false ]]; then
  run_doctor 'Rust candidate' "$CANDIDATE_PATH"
  run_doctor 'Python rollback' "$PYTHON_LAUNCHER"
  printf 'Both non-paying Breez doctors passed.\n'
fi

printf 'Keep both files through the rollback window; remove legacy Breez entries only after finalization.\n'
