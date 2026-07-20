#!/usr/bin/env python3
"""Validate a runner-produced canary proof offline; never submits a payment."""
import argparse
import json
import re
import sys
from pathlib import Path

HEX64 = re.compile(r"^[0-9a-f]{64}$")
BACKENDS = {"lnd-testnet-canary", "breez-mainnet-canary"}


def fail(message: str) -> None:
    raise ValueError(message)


def validate(record: object, contract: dict) -> None:
    if not isinstance(record, dict) or set(record) != {"backend", "source_commit", "cargo_lock_sha256", "workflow_run_id", "invoice_hash", "payment_hash", "spend_msat", "fee_msat", "cap_msat", "proof", "redaction", "state", "durable_no_retry_proof", "runner_identity", "attestation"}:
        fail("unexpected canary record schema")
    if record["backend"] not in BACKENDS or not re.fullmatch(r"[0-9a-f]{40}", str(record["source_commit"])):
        fail("invalid backend or source identity")
    backend_contract = contract.get("backends", {}).get(record["backend"])
    if not isinstance(backend_contract, dict) or record["cap_msat"] != backend_contract.get("cap_msat"):
        fail("record cap does not match immutable backend contract")
    for field in ("cargo_lock_sha256", "invoice_hash", "payment_hash"):
        if not isinstance(record[field], str) or not HEX64.fullmatch(record[field]): fail(f"invalid {field}")
    if record["invoice_hash"] != record["payment_hash"]: fail("invoice/payment hash binding mismatch")
    if not all(isinstance(record[k], int) and record[k] >= 0 for k in ("spend_msat", "fee_msat", "cap_msat")) or record["spend_msat"] + record["fee_msat"] > record["cap_msat"]:
        fail("cap violated")
    if not isinstance(record["workflow_run_id"], str) or not record["workflow_run_id"]: fail("missing workflow identity")
    if record["redaction"] is not True or record["state"] not in {"succeeded", "definitely_failed", "submitted_unknown_permanent_no_retry"}: fail("redaction or state invalid")
    proof = record["proof"]
    no_retry = record["durable_no_retry_proof"]
    if not isinstance(proof, dict) or not isinstance(no_retry, dict): fail("proof objects required")
    for value in (proof.get("sha256"), no_retry.get("sha256")):
        if not isinstance(value, str) or not HEX64.fullmatch(value): fail("invalid proof digest")
    uri = no_retry.get("runner_owned_uri")
    if not isinstance(uri, str) or not uri.startswith("runner-contract://") or "artifact" in uri or "temp" in uri:
        fail("durable runner-owned no-retry proof required")
    if record["runner_identity"] != backend_contract.get("runner_identity"): fail("protected runner identity required")
    if not isinstance(record["attestation"], dict) or not HEX64.fullmatch(str(record["attestation"].get("sha256", ""))): fail("attestation proof required")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("result", type=Path)
    parser.add_argument("--contract", type=Path, default=Path("security/payment-canary-contract.yaml"))
    args = parser.parse_args(argv)
    try:
        contract = json.loads(args.contract.read_text(encoding="utf-8"))
        if contract.get("schema_version") != 1 or contract.get("durable_ledger", {}).get("submitted_unknown") != "permanent-no-retry":
            fail("invalid permanent no-retry canary contract")
        validate(json.loads(args.result.read_text(encoding="utf-8")), contract)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"canary result: FAIL: {exc}", file=sys.stderr)
        return 1
    print("canary result: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
