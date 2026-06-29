from __future__ import annotations

import json

from typer.testing import CliRunner

from paygate_client.cli import DEFAULT_CONFIG_PATH, app
from paygate_client.config import ConfigError
from paygate_client.session_cache import (
    CachedCredential,
    CredentialScope,
    MemoryCredentialCache,
)


def _config_file(tmp_path) -> str:
    path = tmp_path / "paygate.yaml"
    path.write_text(
        "\n".join(
            [
                "payer:",
                "  backend: test-mode",
                "policy:",
                "  max_request_sats: 100",
                "  max_fee_sats: 7",
                "  daily_budget_sats: 100",
                "  allowed_hosts:",
                "    - example.test:443",
                "  allowed_services:",
                "    - orders",
                "protocol:",
                "  preferred: Payment",
            ]
        ),
        encoding="utf-8",
    )
    return str(path)


def test_request_command_emits_json_and_exits_zero(monkeypatch, tmp_path) -> None:
    seen = {}

    def fake_request_with_paygate(paygate_request, *, config, **kwargs):
        seen["method"] = paygate_request.method
        seen["url"] = paygate_request.url
        seen["headers"] = paygate_request.headers
        seen["body"] = paygate_request.body
        seen["backend"] = config.payer.backend
        seen["no_pay"] = kwargs["no_pay"]
        seen["cache_policy"] = kwargs["cache_policy"]
        return {"ok": True, "paid": False, "response": {"statusCode": 200}}

    monkeypatch.setattr(
        "paygate_client.cli.request_with_paygate",
        fake_request_with_paygate,
    )

    result = CliRunner().invoke(
        app,
        [
            "request",
            "post",
            "https://example.test/resource",
            "--config",
            _config_file(tmp_path),
            "-H",
            "Accept: application/json",
            "--body",
            '{"hello": "world"}',
        ],
    )

    assert result.exit_code == 0
    assert json.loads(result.output) == {
        "ok": True,
        "paid": False,
        "response": {"statusCode": 200},
    }
    assert seen == {
        "method": "POST",
        "url": "https://example.test/resource",
        "headers": {"Accept": "application/json"},
        "body": '{"hello": "world"}',
        "backend": "test-mode",
        "no_pay": False,
        "cache_policy": "challenge-defined",
    }


def test_request_command_exits_nonzero_for_error_envelope(
    monkeypatch, tmp_path
) -> None:
    def fake_request_with_paygate(paygate_request, *, config, **kwargs):
        return {
            "ok": False,
            "paid": False,
            "error": {"code": "policy_denied", "message": "denied"},
        }

    monkeypatch.setattr(
        "paygate_client.cli.request_with_paygate",
        fake_request_with_paygate,
    )

    result = CliRunner().invoke(
        app,
        [
            "request",
            "GET",
            "https://example.test/resource",
            "--config",
            _config_file(tmp_path),
        ],
    )

    assert result.exit_code == 1
    assert json.loads(result.output)["error"]["code"] == "policy_denied"


def test_request_command_rejects_malformed_header(tmp_path) -> None:
    result = CliRunner().invoke(
        app,
        [
            "request",
            "GET",
            "https://example.test/resource",
            "--config",
            _config_file(tmp_path),
            "--header",
            "not-a-header",
        ],
    )

    assert result.exit_code == 1
    assert json.loads(result.output)["error"]["code"] == "invalid_request"


def test_request_command_passes_no_pay_and_trace_flags(monkeypatch, tmp_path) -> None:
    seen = {}

    def fake_request_with_paygate(paygate_request, *, config, **kwargs):
        seen["no_pay"] = kwargs["no_pay"]
        seen["refresh_credential"] = kwargs["refresh_credential"]
        seen["cache_policy"] = kwargs["cache_policy"]
        seen["trace_sink"] = type(kwargs["trace_sink"]).__name__
        return {"ok": False, "paid": False, "wouldPay": True}

    monkeypatch.setattr(
        "paygate_client.cli.request_with_paygate",
        fake_request_with_paygate,
    )

    result = CliRunner().invoke(
        app,
        [
            "request",
            "GET",
            "https://example.test/resource",
            "--config",
            _config_file(tmp_path),
            "--no-pay",
            "--refresh-credential",
            "--cache-policy",
            "until-expiry",
            "--verbose",
            "--trace-json",
        ],
    )

    assert result.exit_code == 1
    assert seen == {
        "no_pay": True,
        "refresh_credential": True,
        "cache_policy": "until-expiry",
        "trace_sink": "MultiTraceSink",
    }


def test_request_command_passes_profile_namespace(monkeypatch, tmp_path) -> None:
    seen = {}

    def fake_request_with_paygate(paygate_request, *, config, **kwargs):
        seen["session_namespace"] = kwargs["session_namespace"]
        seen["cache_namespace"] = kwargs["session_cache"].namespace
        seen["cache_path"] = kwargs["session_cache"].path
        seen["ledger_path"] = kwargs["policy_engine"].ledger.path
        return {"ok": True, "paid": False}

    monkeypatch.setattr(
        "paygate_client.cli.request_with_paygate",
        fake_request_with_paygate,
    )

    result = CliRunner().invoke(
        app,
        [
            "request",
            "GET",
            "https://example.test/resource",
            "--config",
            _config_file(tmp_path),
            "--profile",
            "worker-a",
            "--cache-path",
            str(tmp_path / "credentials.json"),
            "--ledger-path",
            str(tmp_path / "ledger.json"),
        ],
    )

    assert result.exit_code == 0
    assert seen == {
        "session_namespace": "worker-a",
        "cache_namespace": "worker-a",
        "cache_path": tmp_path / "credentials.json",
        "ledger_path": tmp_path / "ledger.json",
    }


def test_request_command_without_config_flag_reaches_config_loading(
    monkeypatch,
) -> None:
    seen = {}

    def fake_load_config(config_path):
        seen["config_path"] = config_path
        raise ConfigError("missing default config sentinel")

    monkeypatch.setattr("paygate_client.cli.load_config", fake_load_config)

    result = CliRunner().invoke(
        app,
        ["request", "GET", "https://example.test/resource"],
    )

    assert result.exit_code == 1
    assert "Usage:" not in result.output
    assert seen == {"config_path": DEFAULT_CONFIG_PATH.expanduser()}
    envelope = json.loads(result.output)
    assert envelope["error"]["code"] == "invalid_request"
    assert envelope["error"]["message"] == "missing default config sentinel"


def test_backend_doctor_command_emits_json(monkeypatch, tmp_path) -> None:
    def fake_backend_doctor(config_path):
        assert str(config_path) == _config_file_path
        return {"ok": True, "backend": "test-mode"}

    monkeypatch.setattr("paygate_client.cli.backend_doctor", fake_backend_doctor)
    _config_file_path = _config_file(tmp_path)

    result = CliRunner().invoke(
        app,
        ["backend", "doctor", "--config", _config_file_path, "--json"],
    )

    assert result.exit_code == 0
    assert json.loads(result.output) == {"ok": True, "backend": "test-mode"}


def test_backend_doctor_command_uses_test_backend_config(tmp_path) -> None:
    result = CliRunner().invoke(
        app,
        ["backend", "doctor", "--config", _config_file(tmp_path), "--json"],
    )

    assert result.exit_code == 0
    envelope = json.loads(result.output)
    assert envelope["ok"] is True
    assert envelope["backend"] == "test-mode"
    assert envelope["capabilities"]["maxFeeLimitSupported"] is True


def test_backend_doctor_missing_config_emits_diagnostic_json(tmp_path) -> None:
    missing = tmp_path / "missing.yaml"

    result = CliRunner().invoke(
        app,
        ["backend", "doctor", "--config", str(missing), "--json"],
    )

    assert result.exit_code == 1
    assert "Usage:" not in result.output
    envelope = json.loads(result.output)
    assert envelope["ok"] is False
    assert envelope["error"]["code"] == "PAYGATE_CONFIG_INVALID"


def test_backend_pay_invoice_command_exits_nonzero_for_missing_preimage(
    monkeypatch, tmp_path
) -> None:
    def fake_backend_pay_invoice(bolt11, *, config_path, max_fee_sats):
        assert bolt11 == "lnbc1diagnostic"
        assert str(config_path) == _config_file_path
        assert max_fee_sats == 5
        return {
            "ok": False,
            "error": {"code": "PAYER_BACKEND_MISSING_PREIMAGE"},
        }

    monkeypatch.setattr(
        "paygate_client.cli.backend_pay_invoice",
        fake_backend_pay_invoice,
    )
    _config_file_path = _config_file(tmp_path)

    result = CliRunner().invoke(
        app,
        [
            "backend",
            "pay-invoice",
            "lnbc1diagnostic",
            "--config",
            _config_file_path,
            "--max-fee-sats",
            "5",
            "--json",
        ],
    )

    assert result.exit_code == 1
    assert (
        json.loads(result.output)["error"]["code"] == "PAYER_BACKEND_MISSING_PREIMAGE"
    )


def test_backend_pay_invoice_missing_config_emits_diagnostic_json(tmp_path) -> None:
    missing = tmp_path / "missing.yaml"

    result = CliRunner().invoke(
        app,
        [
            "backend",
            "pay-invoice",
            "lnbc1diagnostic",
            "--config",
            str(missing),
            "--max-fee-sats",
            "5",
            "--json",
        ],
    )

    assert result.exit_code == 1
    assert "Usage:" not in result.output
    envelope = json.loads(result.output)
    assert envelope["ok"] is False
    assert envelope["error"]["code"] == "PAYGATE_CONFIG_INVALID"


def test_credentials_list_redacts_cached_authorization(monkeypatch) -> None:
    scope = CredentialScope(
        request_key="req",
        origin_host="example.test:443",
        service="orders",
        protocol="Payment",
        payer_backend="test-mode",
        policy_hash="policy",
    )
    cache = MemoryCredentialCache(
        [
            CachedCredential(
                credential_id="cred_123",
                scope=scope,
                authorization="Payment secret",
                created_at=1,
                expires_at=2,
            )
        ]
    )
    monkeypatch.setattr(
        "paygate_client.cli.FileCredentialCache", lambda *args, **kwargs: cache
    )

    result = CliRunner().invoke(app, ["credentials", "list"])

    assert result.exit_code == 0
    envelope = json.loads(result.output)
    assert envelope["credentials"][0]["authorization"] == "[REDACTED_CREDENTIAL]"


def test_credentials_purge_filters_by_host(monkeypatch) -> None:
    class PurgeableMemoryCache(MemoryCredentialCache):
        def purge(self, *, host=None, service=None, all_credentials=False):
            deleted = 0
            for credential in list(self.list()):
                if host is not None and credential.scope.origin_host != host:
                    continue
                self.delete(credential.credential_id)
                deleted += 1
            return deleted

    cache = PurgeableMemoryCache(
        [
            CachedCredential(
                credential_id="cred_123",
                scope=CredentialScope(
                    request_key="req",
                    origin_host="example.test:443",
                    service="orders",
                    protocol="Payment",
                    payer_backend="test-mode",
                    policy_hash="policy",
                ),
                authorization="Payment secret",
                created_at=1,
            )
        ]
    )
    monkeypatch.setattr(
        "paygate_client.cli.FileCredentialCache", lambda *args, **kwargs: cache
    )

    result = CliRunner().invoke(
        app, ["credentials", "purge", "--host", "example.test:443"]
    )

    assert result.exit_code == 0
    assert json.loads(result.output) == {"deleted": 1, "ok": True}
    assert cache.list() == []
