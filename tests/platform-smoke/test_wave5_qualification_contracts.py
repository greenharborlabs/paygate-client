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
            "scope": {"namespace": "oracle", "requestKey": "GET https://example.test/resource", "originHost": "example.test:443", "service": "orders", "protocol": "L402", "payerBackend": "test-mode", "policyHash": "2" * 64}, "createdAt": 1, "expiresAt": None,
            "maxUses": None, "useCount": 0, "lastSuccessAt": None,
            "lastRejectedAt": None, "paymentHash": None, "challengeId": None,
        }],
    }
    oracle_path.write_text(json.dumps({"case_evidence": {
        "cache.schema": {"observations": {"state.cache": {"bytes": json.dumps(state)}}},
        "credentials.show_found": {"observations": {"credentials.show_found": {"stdout": json.dumps({"ok": True, "credential": {"id": "fixture-id", "authorization": "[REDACTED_CREDENTIAL]", "scope": {"namespace": "oracle", "requestKey": "GET https://example.test/resource", "originHost": "example.test:443", "service": "orders", "protocol": "L402", "payerBackend": "test-mode", "policyHash": "2" * 64}, "createdAt": 1, "expiresAt": None, "maxUses": None, "useCount": 0, "lastSuccessAt": None, "lastRejectedAt": None, "paymentHash": None, "challengeId": None}})}}},
        "credentials.show_missing": {"observations": {"credentials.show_missing": {"stdout": json.dumps({"ok": False, "error": {"code": "credential_not_found", "message": "private detail"}})}}},
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
        "ok": False, "error": {"code": "credential_not_found"}
    }
    credential = record["cases"]["credentials.list.success"]["state"]["before"]["credentials"][0]
    assert credential["authorization"] is None
    assert credential["secretStorage"] == "keyring"
    assert "must-not-escape" not in json.dumps(record)


def test_python_semantic_extractor_rejects_sensitive_or_unknown_replay_data(
    tmp_path: Path,
) -> None:
    extractor = ROOT / "scripts/extract-python-semantic-evidence.py"
    oracle_path, output_path = tmp_path / "oracle.json", tmp_path / "semantic.json"
    state = {
        "version": 1,
        "credentials": [{
            "id": "fixture-id", "authorization": "credential-secret", "secretStorage": "keyring",
            "scope": {"namespace": "oracle", "requestKey": "GET https://example.test/resource", "originHost": "example.test:443", "service": "orders", "protocol": "L402", "payerBackend": "test-mode", "policyHash": "2" * 64}, "createdAt": 1, "expiresAt": None,
            "maxUses": None, "useCount": 0, "lastSuccessAt": None, "lastRejectedAt": None,
            "paymentHash": "payment-hash-secret", "challengeId": None,
        }],
    }
    observation = {"case_evidence": {
        "cache.schema": {"observations": {"state.cache": {"bytes": json.dumps(state)}}},
        "credentials.show_found": {"observations": {"credentials.show_found": {"stdout": json.dumps({"ok": True, "credential": {"invoice": "lnbc-secret"}})}}},
        "credentials.show_missing": {"observations": {"credentials.show_missing": {"stdout": json.dumps({"ok": False, "error": {"code": "credential_not_found", "message": "preimage-secret"}})}}},
    }}
    oracle_path.write_text(json.dumps(observation))
    result = subprocess.run(
        [sys.executable, str(extractor), str(oracle_path), str(output_path)],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert not output_path.exists()
    assert "payment-hash-secret" not in result.stderr
    assert "credential-secret" not in result.stderr

    state["credentials"][0]["paymentHash"] = None
    oracle_path.write_text(json.dumps(observation))
    result = subprocess.run(
        [sys.executable, str(extractor), str(oracle_path), str(output_path)],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert not output_path.exists()
    assert "lnbc-secret" not in result.stderr
    assert "preimage-secret" not in result.stderr


def test_oracle_semantic_contract_and_rejections(tmp_path: Path) -> None:
    script = ROOT / "scripts/check-oracle-semantic-contract.py"
    ids = ["credentials.list.success", "credentials.show_missing", "credentials.show_state"]
    credential = {
        "id": "fixture-id", "authorization": "[REDACTED_CREDENTIAL]",
        "scope": {"namespace": "oracle", "requestKey": "GET", "originHost": "example.test:443", "service": "orders", "protocol": "L402", "payerBackend": "test-mode", "policyHash": "2" * 64},
        "createdAt": 1, "expiresAt": None, "maxUses": None, "useCount": 0,
        "lastSuccessAt": None, "lastRejectedAt": None, "paymentHash": None,
        "challengeId": None,
    }
    state_credential = {**credential, "authorization": None, "secretStorage": "keyring"}
    state = {"version": 1, "credentials": [state_credential]}
    cases = {
        case_id: {"argv": ["credentials", "list", "<TEST_CACHE>"], "stdout_json": {"ok": True, "credentials": [credential]}, "exit_code": 0, "stderr_class": "empty", "state": {"before": state, "after": state}}
        for case_id in ids
    }
    cases["credentials.show_missing"].update({"stdout_json": {"ok": False, "error": {"code": "credential_not_found"}}, "exit_code": 1})
    cases["credentials.show_state"]["stdout_json"] = {"ok": True, "credential": credential}
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
    malformed_stdout = deepcopy(rust); malformed_stdout["cases"][ids[0]]["stdout_json"] = {"ok": True}
    assert run(candidate_rust=malformed_stdout).returncode != 0
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


def test_workflow_records_attested_bundle_metadata() -> None:
    """The attested bundle is independently identifiable after retention."""
    workflow = (ROOT / ".github/workflows/rust-integration-qualification.yml").read_text()

    assert "semantic-evidence-bundle-metadata.json" in workflow
    assert "archive_subject_sha256" in workflow
    assert "archive subject SHA-256; not a GitHub-attestation ID" in workflow
    assert "retention_days" in workflow
    tar_command = "tar -czf semantic-evidence-bundle.tar.gz python-semantic-evidence.json rust-semantic-evidence.json semantic-contract-result.txt"
    assert tar_command in workflow
    assert "semantic-evidence-bundle-metadata.json" not in tar_command
    assert workflow.index(tar_command) < workflow.index("sha256sum semantic-evidence-bundle.tar.gz")
    assert "bundle_sha256=\"$(awk '{print $1}' semantic-evidence-bundle.sha256)\"" in workflow
    assert '"$bundle_sha256" "$GITHUB_SHA" "$GITHUB_RUN_ID" > semantic-evidence-bundle-metadata.json' in workflow
    assert "recorded-by-github-attestation" not in workflow
    assert "subject-path: |\n            semantic-evidence-bundle.tar.gz\n            semantic-evidence-bundle-metadata.json" in workflow
    assert "semantic-evidence-bundle.sha256" in workflow
    assert "semantic-evidence-bundle-metadata.json" in workflow
    assert "retention-days: 90" in workflow


def test_canary_validator_requires_distinct_result_and_ledger_signatures(tmp_path: Path) -> None:
    script = ROOT / "scripts/check-rust-canary-result.py"
    private, public = tmp_path / "runner.key", tmp_path / "runner.pub"
    ledger_private, ledger_public = tmp_path / "ledger.key", tmp_path / "ledger.pub"
    for secret, pub in ((private, public), (ledger_private, ledger_public)):
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(secret)], check=True)
        subprocess.run(["openssl", "pkey", "-in", str(secret), "-pubout", "-out", str(pub)], check=True)
    contract = json.loads((ROOT / "security/payment-canary-contract.yaml").read_text())
    for purpose, key_id, issuer, pub in (("result", "runner-v1", "reviewed-protected-runner", public), ("ledger", "ledger-v1", "paygate-durable-ledger-v1", ledger_public)):
        ring = {"purpose": contract["keyrings"][purpose]["purpose"], "keys": [{"id": key_id, "issuer": issuer, "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z", "revoked": False, "public_key": str(pub)}]}
        path = tmp_path / f"{purpose}-keyring.json"; path.write_text(json.dumps(ring)); contract["keyrings"][purpose]["path"] = str(path)
    contract_path = tmp_path / "contract.json"; contract_path.write_text(json.dumps(contract))
    record = {"backend": "lnd-testnet-canary", "source_commit": "a" * 40, "cargo_lock_sha256": "b" * 64, "workflow_run_id": "9", "attempt_key": ":".join(("a" * 40, "b" * 64, "lnd-testnet-canary", "9")), "invoice_hash": "c" * 64, "payment_hash": "c" * 64, "spend_msat": 1, "fee_msat": 1, "cap_msat": 1000, "proof": {"version": 1, "kind": "payment-hash-binding", "invoice_hash": "c" * 64, "payment_hash": "c" * 64, "redacted_hash": "d" * 64}, "redaction": True, "state": "succeeded", "runner_identity": "approved-lnd-runner-v1", "issued_at": "2026-07-19T00:00:00Z", "issuer": "reviewed-protected-runner", "key_id": "runner-v1"}
    receipt = {"authority_uri": contract["durable_ledger"]["authority_uri"], "record_version": 1, "attempt_key": record["attempt_key"], "result_digest": sha256(json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest(), "terminal_state": "succeeded", "recorded_at": "2026-07-19T00:00:00Z", "issuer": "paygate-durable-ledger-v1", "key_id": "ledger-v1"}
    receipt_path = tmp_path / "receipt"; receipt_signature = tmp_path / "receipt.sig"; receipt_path.write_bytes(json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode())
    subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", str(ledger_private), "-rawin", "-in", str(receipt_path), "-out", str(receipt_signature)], check=True)
    import base64
    receipt["signature"] = base64.b64encode(receipt_signature.read_bytes()).decode(); record["durable_receipt"] = receipt
    payload = json.dumps({k: ({x: y for x, y in v.items() if x != "signature"} if k == "durable_receipt" else v) for k, v in record.items()}, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    payload_path, signature_path = tmp_path / "payload", tmp_path / "signature"
    payload_path.write_bytes(payload)
    subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", str(private), "-rawin", "-in", str(payload_path), "-out", str(signature_path)], check=True)
    record["signature"] = base64.b64encode(signature_path.read_bytes()).decode()
    result = tmp_path / "result.json"
    result.write_text(json.dumps(record))
    command = [sys.executable, str(script), str(result), "--contract", str(contract_path), "--backend", "lnd-testnet-canary", "--source-commit", "a" * 40, "--cargo-lock-sha256", "b" * 64, "--workflow-run-id", "9"]
    assert subprocess.run(command).returncode == 0
    record["durable_receipt"]["authority_uri"] = "github-artifact://temporary"
    result.write_text(json.dumps(record))
    assert subprocess.run(command).returncode != 0
    record["durable_receipt"]["authority_uri"] = contract["durable_ledger"]["authority_uri"]
    record["spend_msat"] = 2  # canonical signed payload mutation
    result.write_text(json.dumps(record))
    assert subprocess.run(command).returncode != 0


def test_payment_canaries_are_separate_protected_fail_closed_jobs() -> None:
    workflow = (ROOT / ".github/workflows/rust-payment-canary.yml").read_text()
    for backend in ("lnd-testnet-canary", "breez-mainnet-canary"):
        assert f"environment: {backend}" in workflow
    assert "group: paygate-payment-canary" in workflow
    assert "runs-on: [self-hosted, linux, paygate-payment-canary" in workflow
    assert "/opt/paygate/payment-canary-runner/current/payment-canary-runner" in workflow
    assert "--infrastructure-attestation /var/lib/paygate/payment-canary/live-infrastructure-attestation.json" in workflow
    assert "always()" in workflow
    assert "secrets:" not in workflow
    assert "exactly one backend approval is required" in workflow


def test_canary_control_plane_uses_literal_attempt_keys_and_preflight_guards() -> None:
    runner = (ROOT / "infra/payment-canary-runner/payment_canary_runner.py").read_text()
    workflow = (ROOT / ".github/workflows/rust-payment-canary.yml").read_text()
    contract = json.loads((ROOT / "security/payment-canary-contract.yaml").read_text())
    inventory = json.loads((ROOT / "infra/runners/payment-canary.yml").read_text())

    assert 'return ":".join((a.source_commit,a.cargo_lock_sha256,a.backend,a.workflow_run_id))' in runner
    assert "def validate_protected_path" in runner
    assert "os.lstat(current)" in runner
    assert '"--deny-network"' in runner
    assert "stdin=subprocess.DEVNULL" in runner
    assert contract["deployment"] == {k: inventory["deployment"][k] for k in contract["deployment"]}
    assert contract["durable_ledger"]["authority_uri"] == inventory["durable_ledger"]["authority_uri"]
    for backend in ("lnd-testnet-canary", "breez-mainnet-canary"):
        marker = f"--backend {backend}"
        start = workflow.index(marker)
        status = workflow.index("runner_status=$?", start)
        output = workflow.index('echo "invoked=true"', start)
        assert status < output
