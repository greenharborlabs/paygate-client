#!/usr/bin/env python3
"""Project independent Python replay observations into the semantic contract."""
import argparse
import json
import sys
from pathlib import Path

SCHEMA_VERSION = 2
CASE_IDS = (
    "credentials.list.success",
    "credentials.show_missing",
    "credentials.show_state",
)


class ContractError(ValueError):
    """A safe, non-diagnostic qualification failure classification."""


def object_at(value: object, *keys: str) -> dict:
    for key in keys:
        if not isinstance(value, dict) or key not in value:
            raise ContractError("invalid replay observation")
        value = value[key]
    if not isinstance(value, dict):
        raise ContractError("invalid replay observation")
    return value


def parse_stdout(observation: dict) -> dict:
    try:
        value = json.loads(observation["stdout"])
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ContractError("invalid replay stdout") from exc
    if not isinstance(value, dict) or not isinstance(value.get("ok"), bool):
        raise ContractError("invalid replay stdout")
    # Error prose may deliberately differ between implementations.  Keep the
    # parsed envelope and classification, but never transport diagnostic text.
    if not value.get("ok", False) and isinstance(value.get("error"), dict):
        value["error"] = {"code": value["error"].get("code")}
    return value


def redacted_credential(credential: dict) -> dict:
    result = dict(credential)
    result.pop("secretStorage", None)
    result["authorization"] = "[REDACTED_CREDENTIAL]"
    return result


def safe_state(value: object) -> dict:
    """Keep only public cache metadata; never export replay credential bytes."""
    if not isinstance(value, dict) or set(value) != {"version", "credentials"}:
        raise ContractError("invalid replay state")
    if value["version"] != 1 or not isinstance(value["credentials"], list):
        raise ContractError("invalid replay state")
    fields = (
        "id", "scope", "createdAt", "expiresAt", "maxUses", "useCount",
        "lastSuccessAt", "lastRejectedAt", "paymentHash", "challengeId",
    )
    credentials = []
    for entry in value["credentials"]:
        if not isinstance(entry, dict) or not all(field in entry for field in fields):
            raise ContractError("invalid replay state")
        credentials.append({
            **{field: entry[field] for field in fields},
            "authorization": None,
            "secretStorage": "keyring",
        })
    return {"version": 1, "credentials": credentials}


def case(argv: list[str], stdout_json: dict, exit_code: int, state: dict) -> dict:
    return {
        "argv": argv,
        "stdout_json": stdout_json,
        "exit_code": exit_code,
        "stderr_class": "empty",
        "state": {"before": state, "after": state},
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("oracle", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        oracle = json.loads(args.oracle.read_text(encoding="utf-8"))
        observations = object_at(oracle, "case_evidence")
        raw_state = object_at(observations, "cache.schema", "observations", "state.cache")
        state = safe_state(json.loads(raw_state["bytes"]))
        if not state["credentials"]:
            raise ContractError("invalid replay state")
        credential = redacted_credential(state["credentials"][0])
        show_found = parse_stdout(object_at(observations, "credentials.show_found", "observations", "credentials.show_found"))
        show_missing = parse_stdout(object_at(observations, "credentials.show_missing", "observations", "credentials.show_missing"))
        cache_arg = ["--profile", "oracle", "--cache-path", "<TEST_CACHE>"]
        cases = {
            "credentials.list.success": case(["credentials", "list", *cache_arg], {"ok": True, "credentials": [credential]}, 0, state),
            "credentials.show_missing": case(["credentials", "show", "missing-id", *cache_arg], show_missing, 1, state),
            "credentials.show_state": case(["credentials", "show", "fixture-id", *cache_arg], show_found, 0, state),
        }
        args.output.write_text(json.dumps({"schema_version": SCHEMA_VERSION, "case_ids": list(CASE_IDS), "producer": "python-replay", "cases": cases}, sort_keys=True), encoding="utf-8")
    except (OSError, KeyError, TypeError, json.JSONDecodeError, ContractError):
        print("python semantic extraction: FAIL: invalid qualification input", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
