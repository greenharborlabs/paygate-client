#!/usr/bin/env python3
"""Compare Python replay evidence with evidence emitted by real Rust code."""
import argparse
import datetime as dt
import json
import sys
from pathlib import Path


class ContractError(ValueError):
    pass


def load(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"invalid JSON: {path}") from exc
    if not isinstance(value, dict):
        raise ContractError(f"JSON object required: {path}")
    return value


def pointer(value: object, path: str) -> object:
    if not path.startswith("/") or "*" in path:
        raise ContractError("JSON Pointer must be concrete")
    current = value
    for token in path[1:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and token in current:
            current = current[token]
        elif isinstance(current, list) and token.isdigit() and int(token) < len(current):
            current = current[int(token)]
        else:
            raise ContractError(f"JSON Pointer does not resolve: {path}")
    return current


def digest(value: object) -> str:
    import hashlib
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--oracle", type=Path, default=Path("compat/python_oracle/golden/evidence.json"))
    parser.add_argument("--rust-evidence", type=Path, required=True)
    parser.add_argument("--registry", type=Path, default=Path("compat/python_oracle/intentional-differences.json"))
    args = parser.parse_args(argv)
    oracle, rust, registry = load(args.oracle), load(args.rust_evidence), load(args.registry)
    py_cases, rs_cases = oracle.get("case_evidence"), rust.get("cases")
    if not isinstance(py_cases, dict) or not isinstance(rs_cases, dict) or rust.get("schema_version") != 1:
        raise ContractError("invalid semantic evidence schema")
    if not set(rs_cases) or not set(rs_cases) <= set(py_cases):
        raise ContractError("Rust evidence must name a non-empty exact subset of Python replay cases")
    approvals = registry.get("approvals")
    if registry.get("schema_version") != 2 or not isinstance(approvals, list):
        raise ContractError("invalid intentional-difference registry")
    seen: set[tuple[str, str]] = set()
    used: set[tuple[str, str]] = set()
    today = dt.date.today()
    for item in approvals:
        required = {"case_id", "json_pointer", "python_value_digest", "rust_value_digest", "rationale", "expires_on"}
        if not isinstance(item, dict) or set(item) != required:
            raise ContractError("malformed approval")
        case, path = item["case_id"], item["json_pointer"]
        if not all(isinstance(v, str) and v for v in item.values()) or "*" in case or "*" in path:
            raise ContractError("wildcard or empty approval")
        key = (case, path)
        if key in seen or case not in rs_cases:
            raise ContractError("duplicate, stale, or unused approval")
        seen.add(key)
        try:
            if dt.date.fromisoformat(item["expires_on"]) < today:
                raise ContractError("expired approval")
        except ValueError as exc:
            raise ContractError("malformed approval expiry") from exc
        py_value = pointer(py_cases[case], path)
        rust_value = pointer(rs_cases[case], path)
        if digest(py_value) != item["python_value_digest"] or digest(rust_value) != item["rust_value_digest"]:
            raise ContractError("approval digest mismatch")
        if py_value != rust_value:
            used.add(key)
    for case in rs_cases:
        for path in ("/semantic_json", "/state", "/exit"):
            py_value = pointer(py_cases[case], path)
            rust_value = pointer(rs_cases[case], path)
            if py_value != rust_value and (case, path) not in used:
                raise ContractError(f"unapproved semantic difference: {case}{path}")
    if used != seen:
        raise ContractError("stale approval")
    print("oracle semantic contract: PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ContractError as exc:
        print(f"oracle semantic contract: FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
