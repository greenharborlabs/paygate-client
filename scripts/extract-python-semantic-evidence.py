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
STATE_FIELDS = {
    "id",
    "scope",
    "authorization",
    "createdAt",
    "expiresAt",
    "maxUses",
    "useCount",
    "lastSuccessAt",
    "lastRejectedAt",
    "paymentHash",
    "challengeId",
    "secretStorage",
}
PUBLIC_CREDENTIAL_FIELDS = STATE_FIELDS - {"secretStorage"}
SCOPE_FIELDS = {
    "namespace",
    "requestKey",
    "originHost",
    "service",
    "protocol",
    "payerBackend",
    "policyHash",
}
CASE_FIELDS = {"argv", "stdout_json", "exit_code", "stderr_class", "state"}


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


def parse_stdout(observation: dict, expected_credential: dict | None = None) -> dict:
    try:
        value = json.loads(observation["stdout"])
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ContractError("invalid replay stdout") from exc
    if not isinstance(value, dict) or not isinstance(value.get("ok"), bool):
        raise ContractError("invalid replay stdout")
    if value["ok"]:
        if (
            expected_credential is None
            or set(value) != {"ok", "credential"}
            or safe_public_credential(value["credential"]) != expected_credential
        ):
            raise ContractError("invalid replay stdout")
        # Project from the independently validated state rather than retaining
        # an arbitrary CLI envelope.
        return {"ok": True, "credential": expected_credential}
    if set(value) != {"ok", "error"} or not isinstance(value["error"], dict):
        raise ContractError("invalid replay stdout")
    if set(value["error"]) != {"code", "message"}:
        raise ContractError("invalid replay stdout")
    code = value["error"].get("code")
    if (
        not isinstance(code, str)
        or not code.isascii()
        or not code.replace("_", "").isalpha()
    ):
        raise ContractError("invalid replay stdout")
    # Error prose may deliberately differ between implementations.  Keep only
    # the classification and never transport diagnostic text.
    return {"ok": False, "error": {"code": code}}


def safe_public_credential(value: object) -> dict:
    if not isinstance(value, dict) or set(value) != PUBLIC_CREDENTIAL_FIELDS:
        raise ContractError("invalid replay credential")
    if value["paymentHash"] is not None or value["challengeId"] is not None:
        raise ContractError("invalid replay credential")
    if not isinstance(value["scope"], dict) or set(value["scope"]) != SCOPE_FIELDS:
        raise ContractError("invalid replay credential")
    return {
        "id": value["id"],
        "scope": value["scope"],
        "authorization": "[REDACTED_CREDENTIAL]",
        "createdAt": value["createdAt"],
        "expiresAt": value["expiresAt"],
        "maxUses": value["maxUses"],
        "useCount": value["useCount"],
        "lastSuccessAt": value["lastSuccessAt"],
        "lastRejectedAt": value["lastRejectedAt"],
        "paymentHash": None,
        "challengeId": None,
    }


def safe_state(value: object) -> dict:
    """Keep only public cache metadata; never export replay credential bytes."""
    if not isinstance(value, dict) or set(value) != {"version", "credentials"}:
        raise ContractError("invalid replay state")
    if value["version"] != 1 or not isinstance(value["credentials"], list):
        raise ContractError("invalid replay state")
    credentials = []
    for entry in value["credentials"]:
        if not isinstance(entry, dict) or set(entry) != STATE_FIELDS:
            raise ContractError("invalid replay state")
        public = safe_public_credential(
            {field: entry[field] for field in PUBLIC_CREDENTIAL_FIELDS}
        )
        credentials.append(
            {**public, "authorization": None, "secretStorage": "keyring"}
        )
    return {"version": 1, "credentials": credentials}


def case(argv: list[str], stdout_json: dict, exit_code: int, state: dict) -> dict:
    return {
        "argv": argv,
        "stdout_json": stdout_json,
        "exit_code": exit_code,
        "stderr_class": "empty",
        "state": {"before": state, "after": state},
    }


def validate_shared_case_contract(cases: dict) -> None:
    """Fail closed if this independent producer drifts from the shared contract."""
    if set(cases) != set(CASE_IDS):
        raise ContractError("invalid semantic cases")
    for case_id in CASE_IDS:
        evidence = cases[case_id]
        if set(evidence) != CASE_FIELDS or evidence["stderr_class"] != "empty":
            raise ContractError("invalid semantic case")
        expected_zero = case_id != "credentials.show_missing"
        if (evidence["exit_code"] == 0) != expected_zero:
            raise ContractError("invalid semantic exit evidence")
        if "<TEST_CACHE>" not in evidence["argv"]:
            raise ContractError("unsafe semantic argv")
    if set(cases["credentials.list.success"]["stdout_json"]) != {"ok", "credentials"}:
        raise ContractError("invalid semantic success evidence")
    if set(cases["credentials.show_state"]["stdout_json"]) != {"ok", "credential"}:
        raise ContractError("invalid semantic success evidence")
    if set(cases["credentials.show_missing"]["stdout_json"]) != {"ok", "error"}:
        raise ContractError("invalid semantic error evidence")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("oracle", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        oracle = json.loads(args.oracle.read_text(encoding="utf-8"))
        observations = object_at(oracle, "case_evidence")
        raw_state = object_at(
            observations, "cache.schema", "observations", "state.cache"
        )
        state = safe_state(json.loads(raw_state["bytes"]))
        if not state["credentials"]:
            raise ContractError("invalid replay state")
        credential = safe_public_credential(
            {
                field: state["credentials"][0][field]
                for field in PUBLIC_CREDENTIAL_FIELDS
            }
        )
        show_found = parse_stdout(
            object_at(
                observations,
                "credentials.show_found",
                "observations",
                "credentials.show_found",
            ),
            credential,
        )
        show_missing = parse_stdout(
            object_at(
                observations,
                "credentials.show_missing",
                "observations",
                "credentials.show_missing",
            )
        )
        cache_arg = ["--profile", "oracle", "--cache-path", "<TEST_CACHE>"]
        cases = {
            "credentials.list.success": case(
                ["credentials", "list", *cache_arg],
                {"ok": True, "credentials": [credential]},
                0,
                state,
            ),
            "credentials.show_missing": case(
                ["credentials", "show", "missing-id", *cache_arg],
                show_missing,
                1,
                state,
            ),
            "credentials.show_state": case(
                ["credentials", "show", "fixture-id", *cache_arg], show_found, 0, state
            ),
        }
        validate_shared_case_contract(cases)
        args.output.write_text(
            json.dumps(
                {
                    "schema_version": SCHEMA_VERSION,
                    "case_ids": list(CASE_IDS),
                    "producer": "python-replay",
                    "cases": cases,
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
    except (OSError, KeyError, TypeError, json.JSONDecodeError, ContractError):
        print(
            "python semantic extraction: FAIL: invalid qualification input",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
