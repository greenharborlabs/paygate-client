"""Focused structural tests for fail-closed Wave 5 qualification contracts."""

import base64
import json
import shutil
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
        "credentials": [
            {
                "id": "fixture-id",
                "authorization": "must-not-escape",
                "secretStorage": "keyring",
                "scope": {
                    "namespace": "oracle",
                    "requestKey": "GET https://example.test/resource",
                    "originHost": "example.test:443",
                    "service": "orders",
                    "protocol": "L402",
                    "payerBackend": "test-mode",
                    "policyHash": "2" * 64,
                },
                "createdAt": 1,
                "expiresAt": None,
                "maxUses": None,
                "useCount": 0,
                "lastSuccessAt": None,
                "lastRejectedAt": None,
                "paymentHash": None,
                "challengeId": None,
            }
        ],
    }
    oracle_path.write_text(
        json.dumps(
            {
                "case_evidence": {
                    "cache.schema": {
                        "observations": {"state.cache": {"bytes": json.dumps(state)}}
                    },
                    "credentials.show_found": {
                        "observations": {
                            "credentials.show_found": {
                                "stdout": json.dumps(
                                    {
                                        "ok": True,
                                        "credential": {
                                            "id": "fixture-id",
                                            "authorization": "[REDACTED_CREDENTIAL]",
                                            "scope": {
                                                "namespace": "oracle",
                                                "requestKey": "GET https://example.test/resource",
                                                "originHost": "example.test:443",
                                                "service": "orders",
                                                "protocol": "L402",
                                                "payerBackend": "test-mode",
                                                "policyHash": "2" * 64,
                                            },
                                            "createdAt": 1,
                                            "expiresAt": None,
                                            "maxUses": None,
                                            "useCount": 0,
                                            "lastSuccessAt": None,
                                            "lastRejectedAt": None,
                                            "paymentHash": None,
                                            "challengeId": None,
                                        },
                                    }
                                )
                            }
                        }
                    },
                    "credentials.show_missing": {
                        "observations": {
                            "credentials.show_missing": {
                                "stdout": json.dumps(
                                    {
                                        "ok": False,
                                        "error": {
                                            "code": "credential_not_found",
                                            "message": "private detail",
                                        },
                                    }
                                )
                            }
                        }
                    },
                }
            }
        )
    )
    assert (
        subprocess.run(
            [sys.executable, str(extractor), str(oracle_path), str(output_path)],
            cwd=ROOT,
        ).returncode
        == 0
    )
    record = json.loads(output_path.read_text())
    assert record["schema_version"] == 2
    assert record["case_ids"] == [
        "credentials.list.success",
        "credentials.show_missing",
        "credentials.show_state",
    ]
    assert record["producer"] == "python-replay"
    assert set(record["cases"]) == set(record["case_ids"])
    assert record["cases"]["credentials.show_missing"]["stdout_json"] == {
        "ok": False,
        "error": {"code": "credential_not_found"},
    }
    credential = record["cases"]["credentials.list.success"]["state"]["before"][
        "credentials"
    ][0]
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
        "credentials": [
            {
                "id": "fixture-id",
                "authorization": "credential-secret",
                "secretStorage": "keyring",
                "scope": {
                    "namespace": "oracle",
                    "requestKey": "GET https://example.test/resource",
                    "originHost": "example.test:443",
                    "service": "orders",
                    "protocol": "L402",
                    "payerBackend": "test-mode",
                    "policyHash": "2" * 64,
                },
                "createdAt": 1,
                "expiresAt": None,
                "maxUses": None,
                "useCount": 0,
                "lastSuccessAt": None,
                "lastRejectedAt": None,
                "paymentHash": "payment-hash-secret",
                "challengeId": None,
            }
        ],
    }
    observation = {
        "case_evidence": {
            "cache.schema": {
                "observations": {"state.cache": {"bytes": json.dumps(state)}}
            },
            "credentials.show_found": {
                "observations": {
                    "credentials.show_found": {
                        "stdout": json.dumps(
                            {"ok": True, "credential": {"invoice": "lnbc-secret"}}
                        )
                    }
                }
            },
            "credentials.show_missing": {
                "observations": {
                    "credentials.show_missing": {
                        "stdout": json.dumps(
                            {
                                "ok": False,
                                "error": {
                                    "code": "credential_not_found",
                                    "message": "preimage-secret",
                                },
                            }
                        )
                    }
                }
            },
        }
    }
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
    ids = [
        "credentials.list.success",
        "credentials.show_missing",
        "credentials.show_state",
    ]
    credential = {
        "id": "fixture-id",
        "authorization": "[REDACTED_CREDENTIAL]",
        "scope": {
            "namespace": "oracle",
            "requestKey": "GET",
            "originHost": "example.test:443",
            "service": "orders",
            "protocol": "L402",
            "payerBackend": "test-mode",
            "policyHash": "2" * 64,
        },
        "createdAt": 1,
        "expiresAt": None,
        "maxUses": None,
        "useCount": 0,
        "lastSuccessAt": None,
        "lastRejectedAt": None,
        "paymentHash": None,
        "challengeId": None,
    }
    state_credential = {**credential, "authorization": None, "secretStorage": "keyring"}
    state = {"version": 1, "credentials": [state_credential]}
    cases = {
        case_id: {
            "argv": ["credentials", "list", "<TEST_CACHE>"],
            "stdout_json": {"ok": True, "credentials": [credential]},
            "exit_code": 0,
            "stderr_class": "empty",
            "state": {"before": state, "after": state},
        }
        for case_id in ids
    }
    cases["credentials.show_missing"].update(
        {
            "stdout_json": {"ok": False, "error": {"code": "credential_not_found"}},
            "exit_code": 1,
        }
    )
    cases["credentials.show_state"]["stdout_json"] = {
        "ok": True,
        "credential": credential,
    }
    oracle = {
        "schema_version": 2,
        "case_ids": ids,
        "producer": "python-replay",
        "cases": cases,
    }
    rust = {
        **oracle,
        "producer": "compiled-paygate-cli",
        "provenance": {
            "executable_sha256": "a" * 64,
            "source_commit": "b" * 40,
            "cargo_lock_sha256": "c" * 64,
        },
    }
    oracle_path, rust_path, registry_path = (
        tmp_path / name for name in ("oracle.json", "rust.json", "registry.json")
    )

    def command() -> list[str]:
        return [
            sys.executable,
            str(script),
            "--oracle",
            str(oracle_path),
            "--rust-evidence",
            str(rust_path),
            "--registry",
            str(registry_path),
            "--expected-binary-sha256",
            "a" * 64,
            "--expected-source-commit",
            "b" * 40,
            "--expected-cargo-lock-sha256",
            "c" * 64,
        ]

    def run(
        candidate_oracle=oracle, candidate_rust=rust, registry=None
    ) -> subprocess.CompletedProcess:
        oracle_path.write_text(json.dumps(candidate_oracle))
        rust_path.write_text(json.dumps(candidate_rust))
        registry_path.write_text(
            json.dumps(registry or {"schema_version": 2, "approvals": []})
        )
        return subprocess.run(
            command(),
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    assert run().returncode == 0

    old_projection = {"case_evidence": {"cache.schema": {"state": {}}}}
    assert run(old_projection).returncode != 0
    missing_case = deepcopy(rust)
    missing_case["cases"].pop(ids[-1])
    assert run(candidate_rust=missing_case).returncode != 0
    extra_case = deepcopy(rust)
    extra_case["cases"]["credentials.extra"] = deepcopy(cases[ids[0]])
    assert run(candidate_rust=extra_case).returncode != 0
    oracle_path.write_text("{")
    rust_path.write_text(json.dumps(rust))
    registry_path.write_text(json.dumps({"schema_version": 2, "approvals": []}))
    assert subprocess.run(command(), cwd=ROOT).returncode != 0
    malformed_state = deepcopy(rust)
    malformed_state["cases"][ids[0]]["state"] = ["before", "after"]
    assert run(candidate_rust=malformed_state).returncode != 0
    malformed_stdout = deepcopy(rust)
    malformed_stdout["cases"][ids[0]]["stdout_json"] = {"ok": True}
    assert run(candidate_rust=malformed_stdout).returncode != 0
    mismatch_exit = deepcopy(rust)
    mismatch_exit["cases"][ids[1]]["exit_code"] = 0
    assert run(candidate_rust=mismatch_exit).returncode != 0
    mismatch_state = deepcopy(rust)
    mismatch_state["cases"][ids[0]]["state"]["after"] = {"redacted": True}
    assert run(candidate_rust=mismatch_state).returncode != 0
    forged_provenance = deepcopy(rust)
    forged_provenance["provenance"]["executable_sha256"] = "d" * 64
    assert run(candidate_rust=forged_provenance).returncode != 0

    wildcard = {
        "schema_version": 2,
        "approvals": [
            {
                "case_id": ids[0],
                "json_pointer": "/*",
                "python_value_digest": "a",
                "rust_value_digest": "a",
                "rationale": "redacted",
                "expires_on": "2099-01-01",
            }
        ],
    }
    assert run(registry=wildcard).returncode != 0
    stale = {
        "schema_version": 2,
        "approvals": [
            {
                "case_id": ids[0],
                "json_pointer": "/exit_code",
                "python_value_digest": sha256(b"0").hexdigest(),
                "rust_value_digest": sha256(b"0").hexdigest(),
                "rationale": "redacted",
                "expires_on": "2000-01-01",
            }
        ],
    }
    assert run(registry=stale).returncode != 0
    unused = {
        "schema_version": 2,
        "approvals": [
            {
                "case_id": ids[0],
                "json_pointer": "/exit_code",
                "python_value_digest": sha256(b"0").hexdigest(),
                "rust_value_digest": sha256(b"0").hexdigest(),
                "rationale": "redacted",
                "expires_on": "2099-01-01",
            }
        ],
    }
    assert run(registry=unused).returncode != 0


def test_workflow_records_attested_bundle_metadata() -> None:
    """The attested bundle is independently identifiable after retention."""
    workflow = (
        ROOT / ".github/workflows/rust-integration-qualification.yml"
    ).read_text()

    assert "semantic-evidence-bundle-metadata.json" in workflow
    assert "archive_subject_sha256" in workflow
    assert "digest_scope" in workflow
    assert "archive subject SHA-256; not a GitHub-attestation ID" in workflow
    assert "retention_days" in workflow
    tar_command = (
        "tar -czf semantic-evidence-bundle.tar.gz "
        "python-semantic-evidence.json rust-semantic-evidence.json "
        "semantic-contract-result.txt"
    )
    assert tar_command in workflow
    assert "semantic-evidence-bundle-metadata.json" not in tar_command
    assert workflow.index(tar_command) < workflow.index(
        "sha256sum semantic-evidence-bundle.tar.gz"
    )
    assert (
        "bundle_sha256=\"$(awk '{print $1}' semantic-evidence-bundle.sha256)\""
        in workflow
    )
    assert '"schema_version": 2' in workflow
    assert '"observed_at_epoch": int(sys.argv[4])' in workflow
    assert (
        '"$bundle_sha256" "$GITHUB_SHA" "$GITHUB_RUN_ID" '
        '"$(date -u +%s)" > semantic-evidence-bundle-metadata.json' in workflow
    )
    assert "recorded-by-github-attestation" not in workflow
    assert (
        "subject-path: |\n"
        "            semantic-evidence-bundle.tar.gz\n"
        "            semantic-evidence-bundle-metadata.json" in workflow
    )
    assert "semantic-evidence-bundle.sha256" in workflow
    assert "semantic-evidence-bundle-metadata.json" in workflow
    assert "retention-days: 90" in workflow


def test_canary_validator_requires_distinct_result_and_ledger_signatures(
    tmp_path: Path,
) -> None:
    script = ROOT / "scripts/check-rust-canary-result.py"
    private, public = tmp_path / "runner.key", tmp_path / "runner.pub"
    ledger_private, ledger_public = tmp_path / "ledger.key", tmp_path / "ledger.pub"
    for secret, pub in ((private, public), (ledger_private, ledger_public)):
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(secret)],
            check=True,
        )
        subprocess.run(
            ["openssl", "pkey", "-in", str(secret), "-pubout", "-out", str(pub)],
            check=True,
        )
    contract = json.loads((ROOT / "security/payment-canary-contract.yaml").read_text())
    for purpose, key_id, issuer, pub in (
        ("result", "runner-v1", "reviewed-protected-runner", public),
        ("ledger", "ledger-v1", "paygate-durable-ledger-v1", ledger_public),
    ):
        ring = {
            "purpose": contract["keyrings"][purpose]["purpose"],
            "keys": [
                {
                    "id": key_id,
                    "issuer": issuer,
                    "not_before": "2026-01-01T00:00:00Z",
                    "not_after": "2027-01-01T00:00:00Z",
                    "revoked": False,
                    "public_key": str(pub),
                }
            ],
        }
        path = tmp_path / f"{purpose}-keyring.json"
        path.write_text(json.dumps(ring))
        contract["keyrings"][purpose]["path"] = str(path)
    contract_path = tmp_path / "contract.json"
    contract_path.write_text(json.dumps(contract))
    record = {
        "backend": "lnd-testnet-canary",
        "source_commit": "a" * 40,
        "cargo_lock_sha256": "b" * 64,
        "workflow_run_id": "9",
        "attempt_key": ":".join(("a" * 40, "b" * 64, "lnd-testnet-canary", "9")),
        "invoice_hash": "c" * 64,
        "payment_hash": "c" * 64,
        "spend_msat": 1,
        "fee_msat": 1,
        "cap_msat": 1000,
        "proof": {
            "version": 1,
            "kind": "payment-hash-binding",
            "invoice_hash": "c" * 64,
            "payment_hash": "c" * 64,
            "redacted_hash": "d" * 64,
        },
        "redaction": True,
        "state": "succeeded",
        "runner_identity": "approved-lnd-runner-v1",
        "issued_at": "2026-07-19T00:00:00Z",
        "issuer": "reviewed-protected-runner",
        "key_id": "runner-v1",
    }
    receipt = {
        "authority_uri": contract["durable_ledger"]["authority_uri"],
        "record_version": 1,
        "attempt_key": record["attempt_key"],
        "result_digest": sha256(
            json.dumps(
                record, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode()
        ).hexdigest(),
        "terminal_state": "succeeded",
        "recorded_at": "2026-07-19T00:00:00Z",
        "issuer": "paygate-durable-ledger-v1",
        "key_id": "ledger-v1",
    }
    receipt_path = tmp_path / "receipt"
    receipt_signature = tmp_path / "receipt.sig"
    receipt_path.write_bytes(
        json.dumps(
            receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode()
    )
    subprocess.run(
        [
            "openssl",
            "pkeyutl",
            "-sign",
            "-inkey",
            str(ledger_private),
            "-rawin",
            "-in",
            str(receipt_path),
            "-out",
            str(receipt_signature),
        ],
        check=True,
    )
    import base64

    receipt["signature"] = base64.b64encode(receipt_signature.read_bytes()).decode()
    record["durable_receipt"] = receipt
    payload = json.dumps(
        {
            k: (
                {x: y for x, y in v.items() if x != "signature"}
                if k == "durable_receipt"
                else v
            )
            for k, v in record.items()
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()
    payload_path, signature_path = tmp_path / "payload", tmp_path / "signature"
    payload_path.write_bytes(payload)
    subprocess.run(
        [
            "openssl",
            "pkeyutl",
            "-sign",
            "-inkey",
            str(private),
            "-rawin",
            "-in",
            str(payload_path),
            "-out",
            str(signature_path),
        ],
        check=True,
    )
    record["signature"] = base64.b64encode(signature_path.read_bytes()).decode()
    result = tmp_path / "result.json"
    result.write_text(json.dumps(record))
    command = [
        sys.executable,
        str(script),
        str(result),
        "--contract",
        str(contract_path),
        "--backend",
        "lnd-testnet-canary",
        "--source-commit",
        "a" * 40,
        "--cargo-lock-sha256",
        "b" * 64,
        "--workflow-run-id",
        "9",
    ]
    assert subprocess.run(command).returncode == 0
    record["durable_receipt"]["authority_uri"] = "github-artifact://temporary"
    result.write_text(json.dumps(record))
    assert subprocess.run(command).returncode != 0
    record["durable_receipt"]["authority_uri"] = contract["durable_ledger"][
        "authority_uri"
    ]
    record["spend_msat"] = 2  # canonical signed payload mutation
    result.write_text(json.dumps(record))
    assert subprocess.run(command).returncode != 0


def test_payment_canaries_are_separate_protected_fail_closed_jobs() -> None:
    workflow = (ROOT / ".github/workflows/rust-payment-canary.yml").read_text()
    for backend in ("lnd-testnet-canary", "breez-mainnet-canary"):
        assert f"environment: {backend}" in workflow
    assert "group: paygate-payment-canary" in workflow
    assert "runs-on: [self-hosted, linux, paygate-payment-canary" in workflow
    assert (
        "/opt/paygate/payment-canary-runner/current/payment-canary-runner" in workflow
    )
    assert (
        "--infrastructure-attestation "
        "/var/lib/paygate/payment-canary/live-infrastructure-attestation.json"
        in workflow
    )
    assert "always()" in workflow
    assert "secrets:" not in workflow
    assert "exactly one backend approval is required" in workflow
    assert (
        workflow.count(
            "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
        )
        == 2
    )
    assert "actions/upload-artifact@v4" not in workflow


def test_native_wave5_artifacts_survive_qualification_retention() -> None:
    workflow = (ROOT / ".github/workflows/rust-platform.yml").read_text()
    assert workflow.count("retention-days: 90") >= 2
    assert "name: rust-build-${{ matrix.target }}" in workflow
    assert "name: runtime-evidence-${{ matrix.target }}" in workflow


def test_canary_control_plane_uses_literal_attempt_keys_and_preflight_guards() -> None:
    runner = (ROOT / "infra/payment-canary-runner/payment_canary_runner.py").read_text()
    workflow = (ROOT / ".github/workflows/rust-payment-canary.yml").read_text()
    contract = json.loads((ROOT / "security/payment-canary-contract.yaml").read_text())
    inventory = json.loads((ROOT / "infra/runners/payment-canary.yml").read_text())

    assert (
        'return ":".join((a.source_commit,a.cargo_lock_sha256,'
        "a.backend,a.workflow_run_id))" in runner
    )
    assert "def validate_protected_path" in runner
    assert "os.lstat(current)" in runner
    assert '"--deny-network"' in runner
    assert "stdin=subprocess.DEVNULL" in runner
    assert contract["deployment"] == {
        k: inventory["deployment"][k] for k in contract["deployment"]
    }
    assert (
        contract["durable_ledger"]["authority_uri"]
        == inventory["durable_ledger"]["authority_uri"]
    )
    for backend in ("lnd-testnet-canary", "breez-mainnet-canary"):
        marker = f"--backend {backend}"
        start = workflow.index(marker)
        status = workflow.index("runner_status=$?", start)
        output = workflow.index('echo "invoked=true"', start)
        assert status < output


def _wave5_candidate_fixture(tmp_path: Path) -> Path:
    """A fully local, redacted manifest fixture for the aggregate validator."""
    source, lock = "a" * 40, "b" * 64
    evidence = tmp_path / "evidence"
    evidence.mkdir()

    def artifact(name: str) -> tuple[str, str]:
        path = evidence / name
        path.write_bytes(("redacted-" + name).encode())
        return str(path.relative_to(tmp_path)), sha256(path.read_bytes()).hexdigest()

    integration_path, integration_digest = artifact("integration.tar.gz")
    # Use the real verifier and a real Ed25519 signature; Wave 5 must never
    # treat a producer-supplied boolean as evidence of signature verification.
    checker = tmp_path / "scripts/check-rust-canary-result.py"
    checker.parent.mkdir()
    shutil.copy(ROOT / "scripts/check-rust-canary-result.py", checker)
    result_private, result_public = tmp_path / "result.key", tmp_path / "result.pub"
    ledger_private, ledger_public = tmp_path / "ledger.key", tmp_path / "ledger.pub"
    for private, public in (
        (result_private, result_public),
        (ledger_private, ledger_public),
    ):
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private)],
            check=True,
        )
        subprocess.run(
            ["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)],
            check=True,
        )
    contract = json.loads((ROOT / "security/payment-canary-contract.yaml").read_text())
    for purpose, key_id, issuer, public in (
        ("result", "runner-v1", "reviewed-protected-runner", result_public),
        ("ledger", "ledger-v1", "paygate-durable-ledger-v1", ledger_public),
    ):
        keyring = {
            "purpose": contract["keyrings"][purpose]["purpose"],
            "keys": [
                {
                    "id": key_id,
                    "issuer": issuer,
                    "not_before": "1960-01-01T00:00:00Z",
                    "not_after": "2100-01-01T00:00:00Z",
                    "revoked": False,
                    "public_key": str(public),
                }
            ],
        }
        keyring_path = (
            tmp_path / f"security/payment-canary-trust/{purpose}-keyring.json"
        )
        keyring_path.parent.mkdir(parents=True, exist_ok=True)
        keyring_path.write_text(json.dumps(keyring))
        contract["keyrings"][purpose]["path"] = str(keyring_path.relative_to(tmp_path))
    contract_path = tmp_path / "security/payment-canary-contract.yaml"
    contract_path.write_text(json.dumps(contract))
    gate_logic = {
        "checker": {
            "path": str(checker.relative_to(tmp_path)),
            "sha256": sha256(checker.read_bytes()).hexdigest(),
        },
        "contract": {
            "path": str(contract_path.relative_to(tmp_path)),
            "sha256": sha256(contract_path.read_bytes()).hexdigest(),
        },
        "result_keyring": {
            "path": "security/payment-canary-trust/result-keyring.json",
            "sha256": sha256(
                (
                    tmp_path / "security/payment-canary-trust/result-keyring.json"
                ).read_bytes()
            ).hexdigest(),
        },
        "ledger_keyring": {
            "path": "security/payment-canary-trust/ledger-keyring.json",
            "sha256": sha256(
                (
                    tmp_path / "security/payment-canary-trust/ledger-keyring.json"
                ).read_bytes()
            ).hexdigest(),
        },
    }
    manifest = {
        "schema_version": 3,
        "source_commit": source,
        "cargo_lock_sha256": lock,
        "integration": {
            "record_schema": "wave5-integration-v1",
            "status": "success",
            "workflow": "rust-integration-qualification.yml",
            "workflow_run_id": "101",
            "source_run": {
                "run_id": "101",
                "url": "https://github.com/acme/paygate/actions/runs/101",
                "workflow_name": "Rust integration qualification",
                "workflow_file": "rust-integration-qualification.yml",
                "started_at_epoch": 100,
                "completed_at_epoch": 200,
            },
            "source_commit": source,
            "cargo_lock_sha256": lock,
            "bundle": {"path": integration_path, "sha256": integration_digest},
            "metadata": {
                "schema_version": 2,
                "subject_name": "semantic-evidence-bundle.tar.gz",
                "archive_subject_sha256": integration_digest,
                "digest_scope": "archive subject SHA-256; not a GitHub-attestation ID",
                "retention_days": 90,
                "source_commit": source,
                "workflow_run_id": "101",
                "observed_at_epoch": 150,
            },
        },
        "native_records": [],
        "canary_records": [],
    }
    for index, target in enumerate(
        (
            "x86_64-unknown-linux-gnu",
            "aarch64-unknown-linux-gnu",
            "x86_64-apple-darwin",
            "aarch64-apple-darwin",
        )
    ):
        bundle_path, bundle_digest = artifact(f"native-{index}.tar.gz")
        path, digest = artifact(f"native-{index}.json")
        runtime = {
            "target": target,
            "artifact_sha256": "c" * 64,
            "binary_sha256": "d" * 64,
            "source_commit": source,
            "cargo_lock_sha256": lock,
            "builder_runner_identity": f"native-runner-{index}",
            "workflow_run_id": "202",
            "status": "success",
            "observed_at_epoch": "150",
            "executor_runner_identity": f"executor-runner-{index}",
            "provenance": "github-attestation:slsa-v1",
        }
        (tmp_path / path).write_text(json.dumps(runtime))
        manifest["native_records"].append(
            {
                "record_schema": "wave5-native-v1",
                "status": "success",
                "target": target,
                "workflow": "rust-platform.yml",
                "workflow_run_id": "202",
                "source_commit": source,
                "cargo_lock_sha256": lock,
                "source_run": {
                    "run_id": "202",
                    "url": "https://github.com/acme/paygate/actions/runs/202",
                    "workflow_name": "Rust native platform qualification",
                    "workflow_file": "rust-platform.yml",
                    "started_at_epoch": 100,
                    "completed_at_epoch": 200,
                },
                "runner_identity": f"native-runner-{index}",
                "provenance": "github-attestation:slsa-v1",
                "bundle": {"path": bundle_path, "sha256": bundle_digest},
                "qualification_manifest": {
                    key: runtime[key]
                    for key in (
                        "target",
                        "artifact_sha256",
                        "binary_sha256",
                        "source_commit",
                        "cargo_lock_sha256",
                        "builder_runner_identity",
                        "workflow_run_id",
                    )
                },
                "runtime_evidence": {
                    "path": path,
                    "sha256": sha256((tmp_path / path).read_bytes()).hexdigest(),
                },
            }
        )
    for backend, runner in (
        ("lnd-testnet-canary", "approved-lnd-runner-v1"),
        ("breez-mainnet-canary", "approved-breez-runner-v1"),
    ):
        run = "303" if backend.startswith("lnd") else "404"
        record = {
            "backend": backend,
            "source_commit": source,
            "cargo_lock_sha256": lock,
            "workflow_run_id": run,
            "attempt_key": ":".join((source, lock, backend, run)),
            "invoice_hash": "c" * 64,
            "payment_hash": "c" * 64,
            "spend_msat": 1,
            "fee_msat": 1,
            "cap_msat": 1000,
            "proof": {
                "version": 1,
                "kind": "payment-hash-binding",
                "invoice_hash": "c" * 64,
                "payment_hash": "c" * 64,
                "redacted_hash": "d" * 64,
            },
            "redaction": True,
            "state": "succeeded",
            "runner_identity": runner,
            "issued_at": "1970-01-01T00:02:30Z",
            "issuer": "reviewed-protected-runner",
            "key_id": "runner-v1",
        }
        receipt = {
            "authority_uri": contract["durable_ledger"]["authority_uri"],
            "record_version": 1,
            "attempt_key": record["attempt_key"],
            "result_digest": sha256(
                json.dumps(
                    record, sort_keys=True, separators=(",", ":"), ensure_ascii=True
                ).encode()
            ).hexdigest(),
            "terminal_state": "succeeded",
            "recorded_at": "1970-01-01T00:02:40Z",
            "issuer": "paygate-durable-ledger-v1",
            "key_id": "ledger-v1",
        }
        payload = tmp_path / "payload"
        signature = tmp_path / "signature"
        payload.write_bytes(
            json.dumps(
                receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode()
        )
        subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-inkey",
                str(ledger_private),
                "-rawin",
                "-in",
                str(payload),
                "-out",
                str(signature),
            ],
            check=True,
        )
        receipt["signature"] = base64.b64encode(signature.read_bytes()).decode()
        record["durable_receipt"] = receipt
        signed = {
            k: (
                {x: y for x, y in v.items() if x != "signature"}
                if k == "durable_receipt"
                else v
            )
            for k, v in record.items()
        }
        payload.write_bytes(
            json.dumps(
                signed, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode()
        )
        subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-inkey",
                str(result_private),
                "-rawin",
                "-in",
                str(payload),
                "-out",
                str(signature),
            ],
            check=True,
        )
        record["signature"] = base64.b64encode(signature.read_bytes()).decode()
        result_path = evidence / f"{backend}.json"
        result_path.write_text(json.dumps(record))
        path, digest = (
            str(result_path.relative_to(tmp_path)),
            sha256(result_path.read_bytes()).hexdigest(),
        )
        manifest["canary_records"].append(
            {
                "record_schema": "wave5-canary-v2",
                "status": "succeeded",
                "backend": backend,
                "workflow": "rust-payment-canary.yml",
                "workflow_run_id": "303" if backend.startswith("lnd") else "404",
                "source_commit": source,
                "cargo_lock_sha256": lock,
                "source_run": {
                    "run_id": run,
                    "url": f"https://github.com/acme/paygate/actions/runs/{run}",
                    "workflow_name": (
                        "Rust payment canaries (protected runner control plane)"
                    ),
                    "workflow_file": "rust-payment-canary.yml",
                    "started_at_epoch": 100,
                    "completed_at_epoch": 200,
                },
                "runner_identity": runner,
                "artifact": {"path": path, "sha256": digest},
                "gate_logic": gate_logic,
            }
        )
    path = tmp_path / "candidate.json"
    path.write_text(json.dumps(manifest))
    return path


def test_wave5_candidate_validator_accepts_exact_complete_fixture_and_rejects_tampering(
    tmp_path: Path,
) -> None:
    script = ROOT / "scripts/check-rust-wave5-candidate.py"
    candidate = _wave5_candidate_fixture(tmp_path)
    index = tmp_path / "wave5-evidence-index.json"
    command = [
        sys.executable,
        str(script),
        str(candidate),
        "--evidence-root",
        str(tmp_path),
        "--canary-checker",
        str(tmp_path / "scripts/check-rust-canary-result.py"),
        "--canary-contract",
        str(tmp_path / "security/payment-canary-contract.yaml"),
        "--result-keyring",
        str(tmp_path / "security/payment-canary-trust/result-keyring.json"),
        "--ledger-keyring",
        str(tmp_path / "security/payment-canary-trust/ledger-keyring.json"),
        "--repository",
        "acme/paygate",
        "--now-epoch",
        "86600",
        "--evidence-index-output",
        str(index),
    ]
    validated = subprocess.run(command, cwd=ROOT, capture_output=True)
    assert validated.returncode == 0
    assert json.loads(validated.stdout)["accepted_at_epoch"] == 86600
    first = index.read_bytes()
    assert subprocess.run(command, cwd=ROOT).returncode == 0
    assert index.read_bytes() == first
    accepted = json.loads(first)
    assert [record["id"] for record in accepted["records"]] == [
        "canary:breez-mainnet-canary",
        "canary:lnd-testnet-canary",
        "integration",
        "native:aarch64-apple-darwin",
        "native:aarch64-unknown-linux-gnu",
        "native:x86_64-apple-darwin",
        "native:x86_64-unknown-linux-gnu",
    ]
    # The injected clock makes the acceptance boundary deterministic: age zero
    # and exactly one day are both valid.
    zero_age_command = command.copy()
    zero_age_command[zero_age_command.index("--now-epoch") + 1] = "200"
    assert subprocess.run(zero_age_command, cwd=ROOT).returncode == 0
    fixture = json.loads(candidate.read_text())
    variants = []
    missing = deepcopy(fixture)
    missing["native_records"].pop()
    variants.append(missing)
    duplicate = deepcopy(fixture)
    duplicate["native_records"].append(deepcopy(duplicate["native_records"][0]))
    variants.append(duplicate)
    bad_digest = deepcopy(fixture)
    bad_digest["integration"]["bundle"]["sha256"] = "0" * 64
    variants.append(bad_digest)
    unknown = deepcopy(fixture)
    unknown["canary_records"].append(deepcopy(unknown["canary_records"][0]))
    unknown["canary_records"][-1]["backend"] = "unknown"
    variants.append(unknown)
    stale = deepcopy(fixture)
    stale["canary_records"][0]["status"] = "submitted-unknown"
    variants.append(stale)
    source_mismatch = deepcopy(fixture)
    source_mismatch["native_records"][0]["source_commit"] = "c" * 40
    variants.append(source_mismatch)
    lock_mismatch = deepcopy(fixture)
    lock_mismatch["integration"]["cargo_lock_sha256"] = "c" * 64
    variants.append(lock_mismatch)
    bad_run = deepcopy(fixture)
    bad_run["native_records"][0]["workflow_run_id"] = "not-a-run"
    variants.append(bad_run)
    bad_schema = deepcopy(fixture)
    bad_schema["canary_records"][0]["record_schema"] = "unknown"
    variants.append(bad_schema)
    bad_target = deepcopy(fixture)
    bad_target["native_records"][0]["target"] = "unknown-target"
    variants.append(bad_target)
    boolean_trust = deepcopy(fixture)
    boolean_trust["native_records"][0]["bundle"]["attestation_verified"] = True
    variants.append(boolean_trust)
    runtime_mismatch = deepcopy(fixture)
    runtime_mismatch["native_records"][0]["runner_identity"] = "forged-runner"
    variants.append(runtime_mismatch)
    qualification_mismatch = deepcopy(fixture)
    qualification_mismatch["native_records"][0]["qualification_manifest"]["target"] = (
        "forged-target"
    )
    variants.append(qualification_mismatch)
    unknown_root = deepcopy(fixture)
    unknown_root["untrusted"] = True
    variants.append(unknown_root)
    v1 = deepcopy(fixture)
    v1["schema_version"] = 1
    variants.append(v1)
    boolean_trust = deepcopy(fixture)
    boolean_trust["canary_records"][0]["signature_verified"] = True
    variants.append(boolean_trust)
    unsafe_path = deepcopy(fixture)
    unsafe_path["canary_records"][0]["artifact"]["path"] = "../result.json"
    variants.append(unsafe_path)
    bad_gate = deepcopy(fixture)
    bad_gate["canary_records"][0]["gate_logic"]["checker"]["sha256"] = "0" * 64
    variants.append(bad_gate)
    bad_identity = deepcopy(fixture)
    bad_identity["canary_records"][0]["workflow_run_id"] = "999"
    variants.append(bad_identity)
    wrong_repo = deepcopy(fixture)
    wrong_repo["integration"]["source_run"]["url"] = (
        "https://github.com/other/repo/actions/runs/101"
    )
    variants.append(wrong_repo)
    wrong_workflow = deepcopy(fixture)
    wrong_workflow["native_records"][0]["source_run"]["workflow_file"] = "other.yml"
    variants.append(wrong_workflow)
    bad_interval = deepcopy(fixture)
    bad_interval["canary_records"][0]["source_run"]["started_at_epoch"] = 201
    variants.append(bad_interval)
    future = deepcopy(fixture)
    future["integration"]["source_run"]["completed_at_epoch"] = 86601
    variants.append(future)
    float_epoch = deepcopy(fixture)
    float_epoch["integration"]["source_run"]["started_at_epoch"] = 1.5
    variants.append(float_epoch)
    bool_epoch = deepcopy(fixture)
    bool_epoch["integration"]["source_run"]["started_at_epoch"] = True
    variants.append(bool_epoch)
    stale_run = deepcopy(fixture)
    stale_run["integration"]["source_run"]["completed_at_epoch"] = 199
    variants.append(stale_run)
    for variant in variants:
        candidate.write_text(json.dumps(variant))
        assert subprocess.run(command, cwd=ROOT).returncode != 0
        assert not index.exists()

    # Re-sign the deliberately malformed timestamp so rejection proves that
    # the validator examines genuinely signature-verified canary data.
    candidate.write_text(json.dumps(fixture))
    signed_record = fixture["canary_records"][0]
    signed_path = tmp_path / signed_record["artifact"]["path"]
    signed = json.loads(signed_path.read_text())
    signed["issued_at"] = "1970-01-01 00:02:30Z"
    receipt = signed["durable_receipt"]
    receipt.pop("signature")
    receipt["result_digest"] = sha256(
        json.dumps(
            {
                key: value
                for key, value in signed.items()
                if key != "signature" and key != "durable_receipt"
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode()
    ).hexdigest()
    payload, signature = tmp_path / "payload", tmp_path / "signature"
    payload.write_bytes(
        json.dumps(
            receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode()
    )
    subprocess.run(
        [
            "openssl",
            "pkeyutl",
            "-sign",
            "-inkey",
            str(tmp_path / "ledger.key"),
            "-rawin",
            "-in",
            str(payload),
            "-out",
            str(signature),
        ],
        check=True,
    )
    receipt["signature"] = base64.b64encode(signature.read_bytes()).decode()
    payload.write_bytes(
        json.dumps(
            {
                key: (
                    {k: v for k, v in value.items() if k != "signature"}
                    if key == "durable_receipt"
                    else value
                )
                for key, value in signed.items()
                if key != "signature"
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode()
    )
    subprocess.run(
        [
            "openssl",
            "pkeyutl",
            "-sign",
            "-inkey",
            str(tmp_path / "result.key"),
            "-rawin",
            "-in",
            str(payload),
            "-out",
            str(signature),
        ],
        check=True,
    )
    signed["signature"] = base64.b64encode(signature.read_bytes()).decode()
    signed_path.write_text(json.dumps(signed))
    fixture["canary_records"][0]["artifact"]["sha256"] = sha256(
        signed_path.read_bytes()
    ).hexdigest()
    candidate.write_text(json.dumps(fixture))
    assert subprocess.run(command, cwd=ROOT).returncode != 0


def test_wave5_acceptance_workflow_is_read_only_and_uses_explicit_historical_runs() -> (
    None
):
    workflow = (ROOT / ".github/workflows/rust-wave5-acceptance.yml").read_text()
    assert "actions: read" in workflow
    assert "contents: read" in workflow
    assert "attestations: read" in workflow
    assert "integration_run_id" in workflow and "native_run_id" in workflow
    assert "lnd_canary_run_id" in workflow and "breez_canary_run_id" in workflow
    assert "run-id:" in workflow
    assert "wave5-candidate-acceptance-${{ github.run_id }}" in workflow
    assert "check-rust-wave5-candidate.py" in workflow
    assert "pattern: rust-build-*" in workflow
    assert "pattern: runtime-evidence-*" in workflow
    assert "runtime-bundle-${target}.tar.gz" in workflow
    assert 'gh attestation verify "$bundle" --repo "$GITHUB_REPOSITORY"' in workflow
    assert (
        'rust-platform.yml" --source-digest "$SOURCE_COMMIT" --predicate-type https://slsa.dev/provenance/v1'
        in workflow
    )
    assert 'tarfile.open(bundle, "r:gz")' in workflow
    assert "archive.extractall" not in workflow
    assert '"wave5-canary-v2"' in workflow
    assert '"gate_logic"' in workflow
    assert "--canary-checker scripts/check-rust-canary-result.py" in workflow
    assert 'printf \'"%s":\' "$run" >> source-runs.json' in workflow
    assert 'runs[qualification["workflow_run_id"]]' in workflow
    assert "runs[run]" in workflow
    assert "--evidence-index-output wave5-evidence-index.json" in workflow
    assert "overwrite: false" in workflow
    for name in (
        "wave5-candidate-manifest.json",
        "wave5-evidence-index.json",
        "wave5-acceptance-envelope.json",
        "wave5-validator-result.json",
    ):
        assert name in workflow and name.replace(".json", ".sha256") in workflow
    checksum_source = (
        'write_text(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  '
        '{path.name}\\n", encoding="utf-8")'
    )
    assert checksum_source in workflow
    assert '{path.name}\\\\n", encoding="utf-8")' not in workflow
    assert (
        "for checksum in wave5-candidate-manifest.sha256 "
        "wave5-evidence-index.sha256 wave5-acceptance-envelope.sha256 "
        "wave5-validator-result.sha256; do"
    ) in workflow
    assert 'sha256sum --check "$checksum"' in workflow
    manifest_position = workflow.index(
        'pathlib.Path("wave5-candidate-manifest.json").write_bytes'
    )
    clock_position = workflow.index('now_epoch="$(date -u +%s)"')
    validator_position = workflow.index("python3 scripts/check-rust-wave5-candidate.py")
    assert manifest_position < clock_position < validator_position
    assert '"now_epoch"' not in workflow
    assert '--now-epoch "$now_epoch"' in workflow
    assert 'os.environ["NOW_EPOCH"]' in workflow


def test_wave5_acceptance_checksum_line_is_sha256sum_compatible(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "wave5-evidence-index.json"
    artifact.write_bytes(b'{"schema_version":1}')
    checksum = artifact.with_suffix(".sha256")
    checksum.write_text(
        f"{sha256(artifact.read_bytes()).hexdigest()}  {artifact.name}\n"
    )
    assert checksum.read_bytes().endswith(b"\n")
    assert not checksum.read_bytes().endswith(b"\\n")
    assert (
        subprocess.run(["sha256sum", "--check", checksum.name], cwd=tmp_path).returncode
        == 0
    )


def test_wave5_qualification_report_requires_exact_pending_or_accepted_layout(
    tmp_path: Path,
) -> None:
    script = ROOT / "scripts/check-rust-qualification-report.py"
    artifact = tmp_path / "wave5-candidate-acceptance-123"
    artifact.mkdir()
    report = tmp_path / "report.md"
    index = artifact / "wave5-evidence-index.json"
    checksum = artifact / "wave5-evidence-index.sha256"
    candidate = artifact / "wave5-candidate-manifest.json"
    candidate_checksum = artifact / "wave5-candidate-manifest.sha256"
    envelope = artifact / "wave5-acceptance-envelope.json"
    envelope_checksum = artifact / "wave5-acceptance-envelope.sha256"
    validator_result = artifact / "wave5-validator-result.json"
    validator_checksum = artifact / "wave5-validator-result.sha256"
    command = [sys.executable, str(script), "--report", str(report)]
    report.write_text("No Wave 5 candidate has been accepted.\n")
    assert subprocess.run(command, cwd=ROOT).returncode == 0
    report.write_text(
        "No Wave 5 candidate has been accepted.\n"
        "<!-- BEGIN WAVE5 ACCEPTED EVIDENCE -->\n"
    )
    assert subprocess.run(command, cwd=ROOT).returncode != 0
    repository, accepted = "acme/paygate", 150

    def source_run(run_id: str, kind: str) -> dict:
        names = {
            "integration": (
                "Rust integration qualification",
                "rust-integration-qualification.yml",
            ),
            "native": ("Rust native platform qualification", "rust-platform.yml"),
            "canary": (
                "Rust payment canaries (protected runner control plane)",
                "rust-payment-canary.yml",
            ),
        }
        name, filename = names[kind]
        return {
            "run_id": run_id,
            "url": f"https://github.com/{repository}/actions/runs/{run_id}",
            "workflow_name": name,
            "workflow_file": filename,
            "started_at_epoch": 100,
            "completed_at_epoch": 150,
        }

    records = [
        {
            "id": "integration",
            "evidence_type": "integration",
            "source_run": source_run("1", "integration"),
            "age_at_acceptance_seconds": 0,
            "provenance": {
                "kind": "github-slsa-v1",
                "bundle_sha256": "a" * 64,
                "metadata_sha256": "b" * 64,
                "signer_workflow": "rust-integration-qualification.yml",
            },
        }
    ]
    for number, target in enumerate(
        (
            "x86_64-unknown-linux-gnu",
            "aarch64-unknown-linux-gnu",
            "x86_64-apple-darwin",
            "aarch64-apple-darwin",
        ),
        2,
    ):
        records.append(
            {
                "id": "native:" + target,
                "evidence_type": "native",
                "source_run": source_run(str(number), "native"),
                "age_at_acceptance_seconds": 0,
                "provenance": {
                    "kind": "github-slsa-v1",
                    "bundle_sha256": "c" * 64,
                    "runtime_evidence_sha256": "d" * 64,
                    "signer_workflow": "rust-platform.yml",
                },
            }
        )
    for number, backend in ((6, "lnd-testnet-canary"), (7, "breez-mainnet-canary")):
        records.append(
            {
                "id": "canary:" + backend,
                "evidence_type": "canary",
                "source_run": source_run(str(number), "canary"),
                "age_at_acceptance_seconds": 0,
                "provenance": {
                    "kind": "signed-canary-v1",
                    "result_sha256": "e" * 64,
                    "result_key_id": "result-v1",
                    "ledger_key_id": "ledger-v1",
                    "runner_identity": "protected-runner",
                },
            }
        )
    value = {
        "schema_version": 1,
        "repository": repository,
        "source_commit": "f" * 40,
        "cargo_lock_sha256": "9" * 64,
        "accepted_at_epoch": accepted,
        "records": records,
    }
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    index.write_bytes(payload)
    digest = sha256(payload).hexdigest()
    checksum.write_text(f"{digest}  {index.name}\n")
    candidate_value = {
        "schema_version": 3,
        "source_commit": value["source_commit"],
        "cargo_lock_sha256": value["cargo_lock_sha256"],
    }
    candidate_payload = json.dumps(
        candidate_value, sort_keys=True, separators=(",", ":")
    ).encode()
    candidate.write_bytes(candidate_payload)
    candidate_digest = sha256(candidate_payload).hexdigest()
    candidate_checksum.write_text(f"{candidate_digest}  {candidate.name}\n")
    validator_value = {
        "status": "accepted",
        "candidate_manifest_sha256": candidate_digest,
        "accepted_at_epoch": accepted,
    }
    validator_payload = json.dumps(
        validator_value, sort_keys=True, separators=(",", ":")
    ).encode()
    validator_result.write_bytes(validator_payload)
    validator_digest = sha256(validator_payload).hexdigest()
    validator_checksum.write_text(f"{validator_digest}  {validator_result.name}\n")
    envelope_value = {
        "schema_version": 1,
        "repository": repository,
        "acceptance_run_id": "123",
        "acceptance_run_url": "https://github.com/acme/paygate/actions/runs/123",
        "generated_at_epoch": accepted,
        "candidate_manifest_sha256": candidate_digest,
        "evidence_index_sha256": digest,
        "validator_result_sha256": validator_digest,
    }
    envelope_payload = json.dumps(
        envelope_value, sort_keys=True, separators=(",", ":")
    ).encode()
    envelope.write_bytes(envelope_payload)
    envelope_digest = sha256(envelope_payload).hexdigest()
    envelope_checksum.write_text(f"{envelope_digest}  {envelope.name}\n")
    accepted = (
        b"<!-- BEGIN WAVE5 ACCEPTED EVIDENCE -->\n```json\n"
        + payload
        + b"\n```\n"
        + (
            f"{digest}  {index.name}\n"
            "https://github.com/acme/paygate/actions/runs/123\n"
            "<!-- END WAVE5 ACCEPTED EVIDENCE -->"
        ).encode()
    )
    report.write_bytes(accepted)
    assert (
        subprocess.run(
            command + ["--index", str(index), "--index-sha256", str(checksum)], cwd=ROOT
        ).returncode
        != 0
    )
    accepted_command = command + [
        "--candidate",
        str(candidate),
        "--candidate-sha256",
        str(candidate_checksum),
        "--index",
        str(index),
        "--index-sha256",
        str(checksum),
        "--envelope",
        str(envelope),
        "--envelope-sha256",
        str(envelope_checksum),
        "--validator-result",
        str(validator_result),
        "--validator-result-sha256",
        str(validator_checksum),
        "--publication-epoch",
        "150",
    ]
    assert subprocess.run(accepted_command, cwd=ROOT).returncode == 0

    def write_artifact(path: Path, checksum_path: Path, artifact_value: dict) -> None:
        artifact_payload = json.dumps(
            artifact_value, sort_keys=True, separators=(",", ":")
        ).encode()
        path.write_bytes(artifact_payload)
        checksum_path.write_text(
            f"{sha256(artifact_payload).hexdigest()}  {path.name}\n"
        )

    newly_required = (
        (candidate, candidate_checksum, candidate_value),
        (envelope, envelope_checksum, envelope_value),
        (validator_result, validator_checksum, validator_value),
    )
    for artifact_path, checksum_path, artifact_value in newly_required:
        canonical_payload = artifact_path.read_bytes()
        artifact_path.write_bytes(canonical_payload + b"\n")
        checksum_path.write_text(
            f"{sha256(artifact_path.read_bytes()).hexdigest()}  {artifact_path.name}\n"
        )
        assert subprocess.run(accepted_command, cwd=ROOT).returncode != 0
        write_artifact(artifact_path, checksum_path, artifact_value)
        checksum_path.write_text(
            f"{sha256(artifact_path.read_bytes()).hexdigest()}  {artifact_path.name}\\n"
        )
        assert subprocess.run(accepted_command, cwd=ROOT).returncode != 0
        write_artifact(artifact_path, checksum_path, artifact_value)

    for field, replacement in (
        ("repository", "other/paygate"),
        ("acceptance_run_id", "124"),
        (
            "acceptance_run_url",
            "https://github.com/acme/paygate/actions/runs/124",
        ),
        ("candidate_manifest_sha256", "1" * 64),
        ("evidence_index_sha256", "2" * 64),
        ("validator_result_sha256", "3" * 64),
    ):
        malformed_envelope = deepcopy(envelope_value)
        malformed_envelope[field] = replacement
        write_artifact(envelope, envelope_checksum, malformed_envelope)
        assert subprocess.run(accepted_command, cwd=ROOT).returncode != 0
    write_artifact(envelope, envelope_checksum, envelope_value)

    malformed_candidate = deepcopy(candidate_value)
    malformed_candidate["cargo_lock_sha256"] = "4" * 64
    write_artifact(candidate, candidate_checksum, malformed_candidate)
    assert subprocess.run(accepted_command, cwd=ROOT).returncode != 0
    write_artifact(candidate, candidate_checksum, candidate_value)

    malformed_validator = deepcopy(validator_value)
    malformed_validator["accepted_at_epoch"] = 151
    write_artifact(validator_result, validator_checksum, malformed_validator)
    assert subprocess.run(accepted_command, cwd=ROOT).returncode != 0
    write_artifact(validator_result, validator_checksum, validator_value)

    assert (
        subprocess.run(command + ["--candidate", str(candidate)], cwd=ROOT).returncode
        != 0
    )
    boundary_command = accepted_command.copy()
    boundary_command[-1] = "86550"
    assert subprocess.run(boundary_command, cwd=ROOT).returncode == 0
    boundary_command[-1] = "86551"
    assert subprocess.run(boundary_command, cwd=ROOT).returncode != 0
    boundary_command[-1] = "149"
    assert subprocess.run(boundary_command, cwd=ROOT).returncode != 0
    for invalid_epoch in ("-1", "1.5", "true"):
        boundary_command[-1] = invalid_epoch
        assert subprocess.run(boundary_command, cwd=ROOT).returncode != 0
    downloaded = bytearray(index.read_bytes())
    downloaded[-1] ^= 1
    index.write_bytes(downloaded)
    assert subprocess.run(accepted_command, cwd=ROOT).returncode != 0
    index.write_bytes(payload)

    def materialize(candidate: dict) -> None:
        """Rebuild every integrity layer so mutations reach schema validation."""
        candidate_payload = json.dumps(
            candidate, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
        candidate_digest = sha256(candidate_payload).hexdigest()
        index.write_bytes(candidate_payload)
        checksum.write_text(f"{candidate_digest}  {index.name}\n")
        report.write_bytes(
            b"<!-- BEGIN WAVE5 ACCEPTED EVIDENCE -->\n```json\n"
            + candidate_payload
            + b"\n```\n"
            + (
                f"{candidate_digest}  {index.name}\n"
                "https://github.com/acme/paygate/actions/runs/123\n"
                "<!-- END WAVE5 ACCEPTED EVIDENCE -->"
            ).encode()
        )

    malformed = deepcopy(value)
    malformed["schema_version"] = True
    materialize(malformed)
    assert subprocess.run(accepted_command, cwd=ROOT).returncode != 0

    stale_at_acceptance = deepcopy(value)
    stale_at_acceptance["accepted_at_epoch"] = 86_551
    for record in stale_at_acceptance["records"]:
        record["age_at_acceptance_seconds"] = 86_401
    materialize(stale_at_acceptance)
    assert subprocess.run(accepted_command, cwd=ROOT).returncode != 0

    digest_fields = [
        (None, "cargo_lock_sha256"),
        ("integration", "bundle_sha256"),
        ("integration", "metadata_sha256"),
        ("native:x86_64-unknown-linux-gnu", "bundle_sha256"),
        ("native:x86_64-unknown-linux-gnu", "runtime_evidence_sha256"),
        ("canary:lnd-testnet-canary", "result_sha256"),
    ]
    for record_id, field in digest_fields:
        malformed = deepcopy(value)
        target = (
            malformed
            if record_id is None
            else next(
                record["provenance"]
                for record in malformed["records"]
                if record["id"] == record_id
            )
        )
        target[field] = "0" * 64
        materialize(malformed)
        assert subprocess.run(accepted_command, cwd=ROOT).returncode != 0

    canary_id_fields = ("result_key_id", "ledger_key_id", "runner_identity")
    invalid_identifiers = (
        "placeholder",
        "runner-TODO-v1",
        "ledger_tbd_v1",
        "runner.pending.v1",
        "replace-me",
        "runner-changeme-v1",
        "dummy",
        "runner-example-v1",
        "unknown",
        " runner-v1",
        "runner-v1 ",
        "runner\nidentity",
        "runner-identity-" + "x" * 128,
    )
    for field in canary_id_fields:
        for identifier in invalid_identifiers:
            malformed = deepcopy(value)
            canary = next(
                record
                for record in malformed["records"]
                if record["id"] == "canary:lnd-testnet-canary"
            )
            canary["provenance"][field] = identifier
            materialize(malformed)
            assert subprocess.run(accepted_command, cwd=ROOT).returncode != 0

    materialize(value)
    assert subprocess.run(accepted_command, cwd=ROOT).returncode == 0
    placeholder = json.dumps(
        {
            "schema_version": 1,
            "repository": repository,
            "records": [{"id": "PLACEHOLDER"}] * 7,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    placeholder_digest = sha256(placeholder).hexdigest()
    index.write_bytes(placeholder)
    checksum.write_text(f"{placeholder_digest}  {index.name}\n")
    report.write_bytes(
        b"<!-- BEGIN WAVE5 ACCEPTED EVIDENCE -->\n```json\n"
        + placeholder
        + b"\n```\n"
        + (
            f"{placeholder_digest}  {index.name}\n"
            "https://github.com/acme/paygate/actions/runs/123\n"
            "<!-- END WAVE5 ACCEPTED EVIDENCE -->"
        ).encode()
    )
    assert subprocess.run(accepted_command, cwd=ROOT).returncode != 0
    index.write_bytes(payload)
    checksum.write_text(f"{digest}  {index.name}\n")
    for invalid in (
        accepted.replace(b"/runs/123", b"/runs/0"),
        accepted.replace(b"/runs/123", b"/runs/source-run"),
        accepted.replace(
            b"```\n" + f"{digest}".encode(),
            b"```\n```json\n{}\n```\n" + f"{digest}".encode(),
        ),
        accepted.replace(
            b"```\n" + f"{digest}".encode(), b"```\n\n" + f"{digest}".encode()
        ),
        accepted.replace(b"WAVE5 ACCEPTED EVIDENCE", b"WAVE5-ACCEPTED-EVIDENCE", 1),
    ):
        report.write_bytes(invalid)
        assert subprocess.run(accepted_command, cwd=ROOT).returncode != 0


def test_wave5_evidence_publication_runbook_is_fail_closed_and_docs_only() -> None:
    runbook = (ROOT / "docs/wave5-evidence-publication.md").read_text()

    required_contracts = (
        "wave5-candidate-acceptance-${ACCEPTANCE_RUN_ID}",
        "wave5-candidate-manifest.sha256",
        "wave5-evidence-index.sha256",
        "wave5-acceptance-envelope.sha256",
        "wave5-validator-result.sha256",
        "independent integration reviewer",
        "independent security reviewer",
        "explicit approval",
        "check-rust-qualification-report.py",
        "Wave 5 checkpoint remains blocked",
        "immutable acceptance artifact",
        "acceptance authority",
    )
    for contract in required_contracts:
        assert contract in runbook

    forbidden_instructions = (
        "workflow dispatch",
        "retry the payment",
        "automatically commit",
        "contents: write",
    )
    for instruction in forbidden_instructions:
        assert instruction not in runbook.lower()
