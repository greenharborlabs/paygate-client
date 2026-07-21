"""Focused structural tests for fail-closed Wave 5 qualification contracts."""
import json
import subprocess
import sys
from copy import deepcopy
from hashlib import sha256
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_python_semantic_extractor_emits_the_shared_case_schema(tmp_path: Path) -> None:
    extractor = ROOT / "scripts/extract-python-semantic-evidence.py"
    oracle_path, output_path = tmp_path / "oracle.json", tmp_path / "semantic.json"
    state = {
        "version": 1,
        "credentials": [{
            "id": "fixture-id", "authorization": "must-not-escape", "secretStorage": "keyring",
            "scope": {"namespace": "oracle"}, "createdAt": 1, "expiresAt": None,
            "maxUses": None, "useCount": 0, "lastSuccessAt": None,
            "lastRejectedAt": None, "paymentHash": None, "challengeId": None,
        }],
    }
    oracle_path.write_text(json.dumps({"case_evidence": {
        "cache.schema": {"observations": {"state.cache": {"bytes": json.dumps(state)}}},
        "credentials.show_found": {"observations": {"credentials.show_found": {"stdout": json.dumps({"ok": True, "credential": {"id": "fixture-id"}})}}},
        "credentials.show_missing": {"observations": {"credentials.show_missing": {"stdout": json.dumps({"ok": False, "error": {"code": "NOT_FOUND", "message": "private detail"}})}}},
    }}))
    assert subprocess.run(
        [sys.executable, str(extractor), str(oracle_path), str(output_path)], cwd=ROOT
    ).returncode == 0
    record = json.loads(output_path.read_text())
    assert record["schema_version"] == 2
    assert record["case_ids"] == [
        "credentials.list.success", "credentials.show_missing", "credentials.show_state"
    ]
    assert record["producer"] == "python-replay"
    assert set(record["cases"]) == set(record["case_ids"])
    assert record["cases"]["credentials.show_missing"]["stdout_json"] == {
        "ok": False, "error": {"code": "NOT_FOUND"}
    }
    credential = record["cases"]["credentials.list.success"]["state"]["before"]["credentials"][0]
    assert credential["authorization"] is None
    assert credential["secretStorage"] == "keyring"
    assert "must-not-escape" not in json.dumps(record)


def test_oracle_semantic_contract_and_rejections(tmp_path: Path) -> None:
    script = ROOT / "scripts/check-oracle-semantic-contract.py"
    ids = ["credentials.list.success", "credentials.show_missing", "credentials.show_state"]
    cases = {
        case_id: {"argv": ["credentials", "list", "<TEST_CACHE>"], "stdout_json": {"ok": True}, "exit_code": 0, "stderr_class": "empty", "state": {"before": {}, "after": {}}}
        for case_id in ids
    }
    cases["credentials.show_missing"]["exit_code"] = 1
    oracle = {"schema_version": 2, "case_ids": ids, "producer": "python-replay", "cases": cases}
    rust = {**oracle, "producer": "compiled-paygate-cli", "provenance": {"executable_sha256": "a" * 64, "source_commit": "b" * 40, "cargo_lock_sha256": "c" * 64}}
    oracle_path, rust_path, registry_path = (tmp_path / name for name in ("oracle.json", "rust.json", "registry.json"))

    def command() -> list[str]:
        return [
            sys.executable, str(script), "--oracle", str(oracle_path), "--rust-evidence", str(rust_path),
            "--registry", str(registry_path), "--expected-binary-sha256", "a" * 64,
            "--expected-source-commit", "b" * 40, "--expected-cargo-lock-sha256", "c" * 64,
        ]

    def run(candidate_oracle=oracle, candidate_rust=rust, registry=None) -> subprocess.CompletedProcess:
        oracle_path.write_text(json.dumps(candidate_oracle))
        rust_path.write_text(json.dumps(candidate_rust))
        registry_path.write_text(json.dumps(registry or {"schema_version": 2, "approvals": []}))
        return subprocess.run(
            command(),
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    assert run().returncode == 0

    old_projection = {"case_evidence": {"cache.schema": {"state": {}}}}
    assert run(old_projection).returncode != 0
    missing_case = deepcopy(rust); missing_case["cases"].pop(ids[-1])
    assert run(candidate_rust=missing_case).returncode != 0
    extra_case = deepcopy(rust); extra_case["cases"]["credentials.extra"] = deepcopy(cases[ids[0]])
    assert run(candidate_rust=extra_case).returncode != 0
    oracle_path.write_text("{")
    rust_path.write_text(json.dumps(rust))
    registry_path.write_text(json.dumps({"schema_version": 2, "approvals": []}))
    assert subprocess.run(command(), cwd=ROOT).returncode != 0
    malformed_state = deepcopy(rust); malformed_state["cases"][ids[0]]["state"] = ["before", "after"]
    assert run(candidate_rust=malformed_state).returncode != 0
    mismatch_exit = deepcopy(rust); mismatch_exit["cases"][ids[1]]["exit_code"] = 0
    assert run(candidate_rust=mismatch_exit).returncode != 0
    mismatch_state = deepcopy(rust); mismatch_state["cases"][ids[0]]["state"]["after"] = {"redacted": True}
    assert run(candidate_rust=mismatch_state).returncode != 0
    forged_provenance = deepcopy(rust); forged_provenance["provenance"]["executable_sha256"] = "d" * 64
    assert run(candidate_rust=forged_provenance).returncode != 0

    wildcard = {"schema_version": 2, "approvals": [{"case_id": ids[0], "json_pointer": "/*", "python_value_digest": "a", "rust_value_digest": "a", "rationale": "redacted", "expires_on": "2099-01-01"}]}
    assert run(registry=wildcard).returncode != 0
    stale = {"schema_version": 2, "approvals": [{"case_id": ids[0], "json_pointer": "/exit_code", "python_value_digest": sha256(b"0").hexdigest(), "rust_value_digest": sha256(b"0").hexdigest(), "rationale": "redacted", "expires_on": "2000-01-01"}]}
    assert run(registry=stale).returncode != 0
    unused = {"schema_version": 2, "approvals": [{"case_id": ids[0], "json_pointer": "/exit_code", "python_value_digest": sha256(b"0").hexdigest(), "rust_value_digest": sha256(b"0").hexdigest(), "rationale": "redacted", "expires_on": "2099-01-01"}]}
    assert run(registry=unused).returncode != 0


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
