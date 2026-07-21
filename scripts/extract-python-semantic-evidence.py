#!/usr/bin/env python3
"""Project independent Python replay observations into the semantic contract."""
import argparse
import json
from pathlib import Path

SCHEMA_VERSION = 2
CASE_IDS = (
    "credentials.list.success",
    "credentials.show_missing",
    "credentials.show_state",
)


def parse_stdout(observation: dict) -> dict:
    value = json.loads(observation["stdout"])
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


def case(argv: list[str], stdout_json: dict, exit_code: int, state: dict) -> dict:
    return {
        "argv": argv,
        "stdout_json": stdout_json,
        "exit_code": exit_code,
        "stderr_class": "empty",
        "state": {"before": state, "after": state},
    }


parser = argparse.ArgumentParser()
parser.add_argument("oracle", type=Path)
parser.add_argument("output", type=Path)
args = parser.parse_args()
oracle = json.loads(args.oracle.read_text(encoding="utf-8"))
observations = oracle["case_evidence"]
state = json.loads(observations["cache.schema"]["observations"]["state.cache"]["bytes"])
credential = redacted_credential(state["credentials"][0])
show_found = parse_stdout(observations["credentials.show_found"]["observations"]["credentials.show_found"])
show_missing = parse_stdout(observations["credentials.show_missing"]["observations"]["credentials.show_missing"])
cache_arg = ["--profile", "oracle", "--cache-path", "<TEST_CACHE>"]
cases = {
    "credentials.list.success": case(
        ["credentials", "list", *cache_arg],
        {"ok": True, "credentials": [credential]},
        0,
        state,
    ),
    "credentials.show_missing": case(
        ["credentials", "show", "missing-id", *cache_arg], show_missing, 1, state
    ),
    "credentials.show_state": case(
        ["credentials", "show", "fixture-id", *cache_arg], show_found, 0, state
    ),
}
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
