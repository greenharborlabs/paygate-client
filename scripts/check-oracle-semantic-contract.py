#!/usr/bin/env python3
"""Fail-closed comparator for independent Python and compiled-CLI evidence."""

import argparse
import datetime as dt
import hashlib
import json
import re
import sys
from pathlib import Path

CASE_IDS = (
    "credentials.list.success",
    "credentials.show_missing",
    "credentials.show_state",
)
CASE_FIELDS = {"argv", "stdout_json", "exit_code", "stderr_class", "state"}
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
APPROVABLE_PATHS = {f"/{field}" for field in CASE_FIELDS}
HASH = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")


class ContractError(ValueError):
    pass


def load(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"invalid JSON: {path.name}") from exc
    if not isinstance(value, dict):
        raise ContractError("JSON object required")
    return value


def digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def pointer(value: object, path: str) -> object:
    if path not in APPROVABLE_PATHS:
        raise ContractError("approval path is not a top-level semantic field")
    return value[path[1:]]


def validate_public_credential(value: object) -> None:
    if (
        not isinstance(value, dict)
        or set(value) != PUBLIC_CREDENTIAL_FIELDS
        or value.get("authorization") != "[REDACTED_CREDENTIAL]"
        or value.get("paymentHash") is not None
        or value.get("challengeId") is not None
        or not isinstance(value.get("scope"), dict)
        or set(value["scope"]) != SCOPE_FIELDS
    ):
        raise ContractError("malformed public credential evidence")


def validate_state(value: object) -> None:
    if (
        not isinstance(value, dict)
        or set(value) != {"version", "credentials"}
        or value.get("version") != 1
        or not isinstance(value.get("credentials"), list)
    ):
        raise ContractError("malformed state evidence")
    for credential in value["credentials"]:
        if (
            not isinstance(credential, dict)
            or set(credential) != STATE_FIELDS
            or credential.get("authorization") is not None
            or credential.get("secretStorage") != "keyring"
        ):
            raise ContractError("malformed state evidence")
        public = {field: credential[field] for field in PUBLIC_CREDENTIAL_FIELDS}
        public["authorization"] = "[REDACTED_CREDENTIAL]"
        validate_public_credential(public)


def validate_stdout(case_id: str, value: object) -> None:
    if not isinstance(value, dict):
        raise ContractError("malformed CLI evidence")
    if case_id == "credentials.list.success":
        if (
            set(value) != {"ok", "credentials"}
            or value.get("ok") is not True
            or not isinstance(value.get("credentials"), list)
        ):
            raise ContractError("malformed CLI evidence")
        for credential in value["credentials"]:
            validate_public_credential(credential)
    elif case_id == "credentials.show_state":
        if set(value) != {"ok", "credential"} or value.get("ok") is not True:
            raise ContractError("malformed CLI evidence")
        validate_public_credential(value.get("credential"))
    elif case_id == "credentials.show_missing":
        error = value.get("error")
        if (
            set(value) != {"ok", "error"}
            or value.get("ok") is not False
            or not isinstance(error, dict)
            or set(error) != {"code"}
            or not isinstance(error.get("code"), str)
            or not error["code"].isascii()
            or not error["code"].replace("_", "").isalpha()
        ):
            raise ContractError("malformed CLI evidence")
    else:
        raise ContractError("unknown semantic case")


def validate_case(case_id: str, case: object) -> None:
    if not isinstance(case, dict) or set(case) != CASE_FIELDS:
        raise ContractError("invalid semantic case fields")
    argv = case["argv"]
    if (
        not isinstance(argv, list)
        or not all(isinstance(arg, str) for arg in argv)
        or "<TEST_CACHE>" not in argv
    ):
        raise ContractError("unsafe argv evidence")
    validate_stdout(case_id, case["stdout_json"])
    if isinstance(case["exit_code"], bool) or not isinstance(case["exit_code"], int):
        raise ContractError("malformed CLI evidence")
    if case["stderr_class"] != "empty":
        raise ContractError("unsafe stderr evidence")
    state = case["state"]
    if not isinstance(state, dict) or set(state) != {"before", "after"}:
        raise ContractError("malformed state evidence")
    validate_state(state["before"])
    validate_state(state["after"])
    expected_zero = case_id != "credentials.show_missing"
    if (case["exit_code"] == 0) != expected_zero:
        raise ContractError("unexpected CLI exit evidence")


def validate_record(value: dict, rust: bool) -> None:
    expected = {"schema_version", "case_ids", "producer", "cases"}
    if rust:
        expected.add("provenance")
    producer = "compiled-paygate-cli" if rust else "python-replay"
    if (
        set(value) != expected
        or value.get("schema_version") != 2
        or value.get("case_ids") != list(CASE_IDS)
        or value.get("producer") != producer
    ):
        raise ContractError("invalid semantic evidence schema")
    cases = value["cases"]
    if not isinstance(cases, dict) or set(cases) != set(CASE_IDS):
        raise ContractError("missing or extra semantic cases")
    for case_id, case in cases.items():
        validate_case(case_id, case)
    if rust:
        provenance = value["provenance"]
        if (
            not isinstance(provenance, dict)
            or set(provenance)
            != {"executable_sha256", "source_commit", "cargo_lock_sha256"}
            or not all(
                HASH.fullmatch(provenance.get(key, ""))
                for key in ("executable_sha256", "cargo_lock_sha256")
            )
            or not COMMIT.fullmatch(provenance.get("source_commit", ""))
        ):
            raise ContractError("forged provenance")


def parse_args(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--oracle", type=Path, required=True)
    parser.add_argument("--rust-evidence", type=Path, required=True)
    parser.add_argument(
        "--registry",
        type=Path,
        default=Path("compat/python_oracle/intentional-differences.json"),
    )
    # These independently computed workflow values are the trust anchor for
    # self-reported Rust provenance.  Without all three, comparison is unsafe.
    parser.add_argument("--expected-binary-sha256", required=True)
    parser.add_argument("--expected-source-commit", required=True)
    parser.add_argument("--expected-cargo-lock-sha256", required=True)
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    oracle, rust, registry = (
        load(args.oracle),
        load(args.rust_evidence),
        load(args.registry),
    )
    validate_record(oracle, False)
    validate_record(rust, True)
    expected = {
        "executable_sha256": args.expected_binary_sha256,
        "source_commit": args.expected_source_commit,
        "cargo_lock_sha256": args.expected_cargo_lock_sha256,
    }
    if (
        not HASH.fullmatch(expected["executable_sha256"])
        or not COMMIT.fullmatch(expected["source_commit"])
        or not HASH.fullmatch(expected["cargo_lock_sha256"])
        or any(rust["provenance"][key] != value for key, value in expected.items())
    ):
        raise ContractError("workflow provenance mismatch")

    approvals = registry.get("approvals")
    if registry.get("schema_version") != 2 or not isinstance(approvals, list):
        raise ContractError("invalid intentional-difference registry")
    seen, used = set(), set()
    for item in approvals:
        required = {
            "case_id",
            "json_pointer",
            "python_value_digest",
            "rust_value_digest",
            "rationale",
            "expires_on",
        }
        if (
            not isinstance(item, dict)
            or set(item) != required
            or not all(isinstance(value, str) and value for value in item.values())
        ):
            raise ContractError("malformed approval")
        case_id, path = item["case_id"], item["json_pointer"]
        key = (case_id, path)
        if case_id not in CASE_IDS or "*" in case_id or "*" in path or key in seen:
            raise ContractError("wildcard or duplicate approval")
        try:
            if dt.date.fromisoformat(item["expires_on"]) < dt.date.today():
                raise ContractError("stale approval")
        except ValueError as exc:
            raise ContractError("malformed approval expiry") from exc
        python_value = pointer(oracle["cases"][case_id], path)
        rust_value = pointer(rust["cases"][case_id], path)
        if (
            digest(python_value) != item["python_value_digest"]
            or digest(rust_value) != item["rust_value_digest"]
        ):
            raise ContractError("approval digest mismatch")
        seen.add(key)
        if python_value != rust_value:
            used.add(key)
    for case_id in CASE_IDS:
        for field in CASE_FIELDS:
            if (
                oracle["cases"][case_id][field] != rust["cases"][case_id][field]
                and (case_id, f"/{field}") not in used
            ):
                raise ContractError("unapproved semantic difference")
    if seen != used:
        raise ContractError("unused approval")
    print("oracle semantic contract: PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ContractError as exc:
        print(f"oracle semantic contract: FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
