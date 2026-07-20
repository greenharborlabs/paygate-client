"""Focused structural tests for fail-closed Wave 5 qualification contracts."""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_oracle_semantic_contract_and_rejections(tmp_path: Path) -> None:
    script = ROOT / "scripts/check-oracle-semantic-contract.py"
    oracle = {"case_evidence": {"cache.schema": {"semantic_json": {"x": 1}, "state": {}, "exit": 0}}}
    rust = {"schema_version": 1, "cases": {"cache.schema": {"semantic_json": {"x": 1}, "state": {}, "exit": 0}}}
    oracle_path, rust_path = tmp_path / "oracle.json", tmp_path / "rust.json"
    oracle_path.write_text(json.dumps(oracle)); rust_path.write_text(json.dumps(rust))
    assert subprocess.run([sys.executable, str(script), "--oracle", str(oracle_path), "--rust-evidence", str(rust_path)], cwd=ROOT).returncode == 0
    registry = tmp_path / "registry.json"
    registry.write_text(json.dumps({"schema_version": 1, "approvals": [{"case": "*", "expected": "must_match", "reason": "bad", "expires_on": "2099-01-01"}]}))
    assert subprocess.run([sys.executable, str(script), "--oracle", str(oracle_path), "--rust-evidence", str(rust_path), "--registry", str(registry)], cwd=ROOT).returncode != 0


def test_canary_validator_requires_durable_runner_proof(tmp_path: Path) -> None:
    script = ROOT / "scripts/check-rust-canary-result.py"
    record = {"backend": "lnd-testnet-canary", "source_commit": "a" * 40, "cargo_lock_sha256": "b" * 64, "workflow_run_id": "9", "invoice_hash": "c" * 64, "payment_hash": "c" * 64, "spend_msat": 1, "fee_msat": 1, "cap_msat": 1000, "proof": {"sha256": "d" * 64}, "redaction": True, "state": "succeeded", "durable_no_retry_proof": {"sha256": "e" * 64, "runner_owned_uri": "runner-contract://ledger/one"}, "runner_identity": "approved-lnd-runner-v1", "attestation": {"sha256": "f" * 64}}
    result = tmp_path / "result.json"
    result.write_text(json.dumps(record))
    assert subprocess.run([sys.executable, str(script), str(result)]).returncode == 0
    record["durable_no_retry_proof"]["runner_owned_uri"] = "github-artifact://temporary"
    result.write_text(json.dumps(record))
    assert subprocess.run([sys.executable, str(script), str(result)]).returncode != 0


def test_payment_canaries_are_separate_protected_fail_closed_jobs() -> None:
    workflow = (ROOT / ".github/workflows/rust-payment-canary.yml").read_text()
    for backend in ("lnd-testnet-canary", "breez-mainnet-canary"):
        assert f"environment: {backend}" in workflow
        assert f"group: paygate-{backend}" in workflow
    assert "runner contract" in workflow.lower()
    assert "secrets:" not in workflow
    assert "exit 1" in workflow
