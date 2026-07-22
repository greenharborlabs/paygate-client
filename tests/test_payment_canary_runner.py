"""Offline fakes for the protected payment-canary runner boundary."""
import importlib.util
import json
import subprocess
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest


MODULE = Path(__file__).parents[1] / "infra/payment-canary-runner/payment_canary_runner.py"
SPEC = importlib.util.spec_from_file_location("payment_canary_runner", MODULE)
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


def args():
    return SimpleNamespace(source_commit="a" * 40, cargo_lock_sha256="b" * 64,
                           backend="lnd-testnet-canary", workflow_run_id="9")


def test_ledger_claim_is_exclusive_and_release_is_never_reclaimable(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "LEDGER", tmp_path / "ledger.jsonl")
    monkeypatch.setattr(runner, "validate_protected_path", lambda *a, **k: None)
    record = {"attempt_key": "attempt", "state": "claimed"}
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: runner.transition(record), range(2)))
    assert results.count(True) == 1
    assert runner.transition({"attempt_key": "attempt", "state": "unsubmitted_released"})
    assert not runner.transition(record)
    assert not runner.transition({"attempt_key": "attempt", "state": "succeeded"})


def test_signed_candidate_approval_binds_digest_and_rejects_tampering(monkeypatch):
    approval = {"approved": True, "candidate_sha256": "c" * 64,
                "source_commit": "a" * 40, "cargo_lock_sha256": "b" * 64,
                "attestation_subject": "sha256:" + "c" * 64, "attestation_digest": "c" * 64,
                "approval_id": "approval-1", "approved_backends": ["lnd-testnet-canary"],
                "issuer": "issuer", "key_id": "key", "issued_at": "2026-01-01T00:00:00Z",
                "expires_at": "2099-01-01T00:00:00Z"}
    envelope = {"claims": approval, "signature": "c2ln"}
    keyring = {"purpose": "candidate-approval", "keys": [{"id": "key", "issuer": "issuer",
               "public_key": "/deployment/key.pub", "not_before": "2025-01-01T00:00:00Z",
               "not_after": "2099-01-01T00:00:00Z", "revoked": False}]}
    monkeypatch.setattr(runner, "_read_protected_json", lambda path: envelope if path == runner.APPROVAL else keyring)
    monkeypatch.setattr(runner, "sha256_file", lambda _: "c" * 64)
    monkeypatch.setattr(runner, "validate_protected_path", lambda *args, **kwargs: None)
    verified = []
    def verify(claims, signature, key):
        if signature != "c2ln":
            raise ValueError("signature rejected")
        verified.append((claims, signature, key))
    monkeypatch.setattr(runner, "_verify_approval_signature", verify)
    assert runner.validate_candidate_approval(args())["approval_id"] == "approval-1"
    assert verified == [(approval, "c2ln", "/deployment/key.pub")]
    approval["attestation_digest"] = "e" * 64
    with pytest.raises(ValueError):
        runner.validate_candidate_approval(args())
    approval["attestation_digest"] = "c" * 64
    envelope["signature"] = "tampered"
    with pytest.raises(ValueError):
        runner.validate_candidate_approval(args())
    envelope["signature"] = "c2ln"
    approval["expires_at"] = "2000-01-01T00:00:00Z"
    with pytest.raises(ValueError):
        runner.validate_candidate_approval(args())


@pytest.mark.parametrize("key_change", [
    {"id": "unknown"}, {"revoked": True}, {"issuer": "different"},
])
def test_candidate_approval_rejects_unknown_revoked_or_mismatched_signer(monkeypatch, key_change):
    claims = {"approved": True, "candidate_sha256": "c" * 64,
              "source_commit": "a" * 40, "cargo_lock_sha256": "b" * 64,
              "attestation_subject": "sha256:" + "c" * 64, "attestation_digest": "c" * 64,
              "approval_id": "approval-1", "approved_backends": ["lnd-testnet-canary"],
              "issuer": "issuer", "key_id": "key", "issued_at": "2026-01-01T00:00:00Z",
              "expires_at": "2099-01-01T00:00:00Z"}
    signing_key = {"id": "key", "issuer": "issuer", "public_key": "/deployment/key.pub",
                   "not_before": "2025-01-01T00:00:00Z", "not_after": "2099-01-01T00:00:00Z", "revoked": False}
    signing_key.update(key_change)
    envelope = {"claims": claims, "signature": "c2ln"}
    keyring = {"purpose": "candidate-approval", "keys": [signing_key]}
    monkeypatch.setattr(runner, "_read_protected_json", lambda path: envelope if path == runner.APPROVAL else keyring)
    monkeypatch.setattr(runner, "sha256_file", lambda _: "c" * 64)
    monkeypatch.setattr(runner, "validate_protected_path", lambda *args, **kwargs: None)
    monkeypatch.setattr(runner, "_verify_approval_signature", lambda *args: pytest.fail("untrusted key reached verifier"))
    with pytest.raises(ValueError):
        runner.validate_candidate_approval(args())


def test_policy_refuses_candidate_authority_and_adapter_uses_literal_context(monkeypatch):
    unsafe = {"schema_version": 1, "network": "denied", "inherit_environment": False,
              "mounts": ["credentials"], "forbidden_mounts": ["credentials", "backend", "result", "ledger"],
              "candidate_protocol": "candidate-probe-v1"}
    monkeypatch.setattr(runner, "_read_protected_json", lambda _: unsafe)
    with pytest.raises(ValueError):
        runner.load_sandbox_policy()

    calls = []
    monkeypatch.setattr(runner.subprocess, "run", lambda command, **kwargs: calls.append((command, kwargs)) or SimpleNamespace(returncode=0))
    runner.run_adapter(args(), "key", 1000)
    command, kwargs = calls[0]
    assert command[:3] == [str(runner.ADAPTER), "--protocol", "payment-adapter-v1"]
    assert "--cap-msat" in command and command[command.index("--cap-msat") + 1] == "1000"
    assert kwargs["stdin"] is subprocess.DEVNULL
    assert str(runner.SANDBOX) not in command


def test_candidate_sandbox_uses_fixed_policy_network_and_protocol(monkeypatch):
    calls = []
    monkeypatch.setattr(runner.subprocess, "run", lambda command, **kwargs: calls.append((command, kwargs)) or SimpleNamespace(returncode=0))
    runner.run_candidate()
    command, kwargs = calls[0]
    assert command == [str(runner.SANDBOX), "--policy", str(runner.SANDBOX_POLICY), "--deny-network",
                       "--protocol", "candidate-probe-v1", "--", str(runner.CANDIDATE)]
    assert kwargs["env"] == {"PATH": "/usr/bin:/bin", "LANG": "C", "PAYGATE_NETWORK_DENY": "required"}


def test_local_result_distinguishes_definite_failure_from_ambiguous_record(tmp_path, monkeypatch):
    result = tmp_path / "result.json"
    monkeypatch.setattr(runner, "RESULT", result)
    monkeypatch.setattr(runner, "validate_protected_path", lambda *a, **k: None)
    a = args(); key = runner.attempt_key(a)
    result.write_text(json.dumps({"backend": a.backend, "source_commit": a.source_commit,
                                  "cargo_lock_sha256": a.cargo_lock_sha256,
                                  "workflow_run_id": a.workflow_run_id, "attempt_key": key,
                                  "cap_msat": 1000, "state": "definite_failed"}))
    assert runner.validate_local_result(a, key, 1000) == "definite_failed"
    result.write_text("{}")
    with pytest.raises(ValueError):
        runner.validate_local_result(a, key, 1000)
