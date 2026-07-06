from dataclasses import asdict
from pathlib import Path

import pytest

from paygate_client.config import (
    MissingConfigError,
    MissingSecretError,
    UnknownBackendError,
    ValidationError,
    load_config,
)


def test_phoenixd_config_resolves_password_only_from_env(monkeypatch, tmp_path):
    monkeypatch.setenv("PAYGATE_CLIENT_PHOENIXD_PASSWORD", "phoenix-secret")
    config_path = tmp_path / "paygate.yml"
    config_path.write_text(
        """
payer:
  backend: phoenixd
phoenixd:
  url: "http://127.0.0.1:9740"
  password_env: "PAYGATE_CLIENT_PHOENIXD_PASSWORD"
policy:
  max_request_sats: 50
  max_fee_sats: 10
  daily_budget_sats: 500
  allowed_hosts:
    - localhost:8080
  allowed_services:
    - paygate-reference-service
protocol:
  preferred: Payment
  allow_l402: true
""",
        encoding="utf-8",
    )

    config = load_config(config_path)

    assert config.payer.backend == "phoenixd"
    assert config.phoenixd.password_env.env_var == "PAYGATE_CLIENT_PHOENIXD_PASSWORD"
    assert config.phoenixd.password_env.resolve() == "phoenix-secret"
    rendered = f"{config!r} {config} {asdict(config)}"
    assert "phoenix-secret" not in rendered
    assert "PAYGATE_CLIENT_PHOENIXD_PASSWORD" in rendered


def test_phoenixd_fee_limit_parameter_defaults_to_none(monkeypatch, tmp_path):
    monkeypatch.setenv("PAYGATE_CLIENT_PHOENIXD_PASSWORD", "phoenix-secret")
    config_path = tmp_path / "paygate.yml"
    config_path.write_text(
        """
payer:
  backend: phoenixd
phoenixd:
  url: "http://127.0.0.1:9740"
  password_env: "PAYGATE_CLIENT_PHOENIXD_PASSWORD"
policy:
  max_request_sats: 50
  max_fee_sats: 10
  daily_budget_sats: 500
  allowed_hosts:
    - localhost:8080
  allowed_services:
    - paygate-reference-service
""",
        encoding="utf-8",
    )

    config = load_config(config_path)

    assert config.phoenixd.fee_limit_parameter is None


def test_phoenixd_fee_limit_parameter_loads_when_configured(monkeypatch, tmp_path):
    monkeypatch.setenv("PAYGATE_CLIENT_PHOENIXD_PASSWORD", "phoenix-secret")
    config_path = tmp_path / "paygate.yml"
    config_path.write_text(
        """
payer:
  backend: phoenixd
phoenixd:
  url: "http://127.0.0.1:9740"
  password_env: "PAYGATE_CLIENT_PHOENIXD_PASSWORD"
  fee_limit_parameter: "maxFeeSat"
policy:
  max_request_sats: 50
  max_fee_sats: 10
  daily_budget_sats: 500
  allowed_hosts:
    - localhost:8080
  allowed_services:
    - paygate-reference-service
""",
        encoding="utf-8",
    )

    config = load_config(config_path)

    assert config.phoenixd.fee_limit_parameter == "maxFeeSat"


def test_breez_config_resolves_secrets_without_leaking_values(tmp_path):
    config_path = tmp_path / "paygate.yml"
    config_path.write_text(
        """
payer:
  backend: breez
breez:
  api_key_env: "BREEZ_API_KEY"
  mnemonic_env: "BREEZ_MNEMONIC"
  network: mainnet
  storage_dir: ".breez-test"
  completion_timeout_secs: 12
policy:
  max_request_sats: 50
  max_fee_sats: 10
  daily_budget_sats: 500
  allowed_hosts:
    - localhost:8080
  allowed_services:
    - paygate-reference-service
""",
        encoding="utf-8",
    )

    config = load_config(
        config_path,
        env={
            "BREEZ_API_KEY": "api-secret",
            "BREEZ_MNEMONIC": "seed words",
        },
    )

    assert config.payer.backend == "breez"
    assert config.breez is not None
    assert config.breez.api_key_env.env_var == "BREEZ_API_KEY"
    assert config.breez.mnemonic_env.env_var == "BREEZ_MNEMONIC"
    assert config.breez.network == "mainnet"
    assert config.breez.storage_dir == ".breez-test"
    assert config.breez.completion_timeout_secs == 12
    rendered = f"{config!r} {config} {asdict(config)}"
    assert "api-secret" not in rendered
    assert "seed words" not in rendered
    assert "BREEZ_API_KEY" in rendered
    assert "BREEZ_MNEMONIC" in rendered


def test_breez_config_defaults_optional_fields(tmp_path):
    config_path = tmp_path / "paygate.yml"
    config_path.write_text(
        """
payer:
  backend: breez
breez:
  api_key_env: "BREEZ_API_KEY"
  mnemonic_env: "BREEZ_MNEMONIC"
policy:
  max_request_sats: 50
  max_fee_sats: 10
  daily_budget_sats: 500
  allowed_hosts:
    - localhost:8080
  allowed_services:
    - paygate-reference-service
""",
        encoding="utf-8",
    )

    config = load_config(
        config_path,
        env={
            "BREEZ_API_KEY": "api-secret",
            "BREEZ_MNEMONIC": "seed words",
        },
    )

    assert config.breez is not None
    assert config.breez.network == "mainnet"
    assert config.breez.storage_dir == "~/.local/share/paygate-client/breez"
    assert config.breez.completion_timeout_secs == 10


def test_breez_missing_secret_env_raises_missing_secret(tmp_path):
    config_path = tmp_path / "paygate.yml"
    config_path.write_text(
        """
payer:
  backend: breez
breez:
  api_key_env: "BREEZ_API_KEY"
  mnemonic_env: "BREEZ_MNEMONIC"
policy:
  max_request_sats: 50
  max_fee_sats: 10
  daily_budget_sats: 500
  allowed_hosts:
    - localhost:8080
  allowed_services:
    - paygate-reference-service
""",
        encoding="utf-8",
    )

    with pytest.raises(MissingSecretError, match="BREEZ_MNEMONIC"):
        load_config(config_path, env={"BREEZ_API_KEY": "api-secret"})


def test_breez_invalid_network_fails_validation(tmp_path):
    config_path = tmp_path / "paygate.yml"
    config_path.write_text(
        """
payer:
  backend: breez
breez:
  api_key_env: "BREEZ_API_KEY"
  mnemonic_env: "BREEZ_MNEMONIC"
  network: mutinynet
policy:
  max_request_sats: 50
  max_fee_sats: 10
  daily_budget_sats: 500
  allowed_hosts:
    - localhost:8080
  allowed_services:
    - paygate-reference-service
""",
        encoding="utf-8",
    )

    with pytest.raises(ValidationError, match="breez.network"):
        load_config(
            config_path,
            env={
                "BREEZ_API_KEY": "api-secret",
                "BREEZ_MNEMONIC": "seed words",
            },
        )


def test_missing_config_file_raises_typed_actionable_error(tmp_path):
    missing = tmp_path / "missing.yml"

    with pytest.raises(MissingConfigError, match="Config file not found"):
        load_config(missing)


def test_unknown_backend_raises_typed_error(tmp_path):
    config_path = tmp_path / "paygate.yml"
    config_path.write_text(
        """
payer:
  backend: lnurl
policy:
  max_request_sats: 50
  max_fee_sats: 10
  daily_budget_sats: 500
  allowed_hosts:
    - localhost:8080
  allowed_services:
    - paygate-reference-service
""",
        encoding="utf-8",
    )

    with pytest.raises(UnknownBackendError, match="payer.backend"):
        load_config(config_path)


def test_missing_phoenixd_password_env_raises_missing_secret(tmp_path):
    config_path = tmp_path / "paygate.yml"
    config_path.write_text(
        """
payer:
  backend: phoenixd
phoenixd:
  url: "http://127.0.0.1:9740"
  password_env: "PAYGATE_CLIENT_PHOENIXD_PASSWORD"
policy:
  max_request_sats: 50
  max_fee_sats: 10
  daily_budget_sats: 500
  allowed_hosts:
    - localhost:8080
  allowed_services:
    - paygate-reference-service
""",
        encoding="utf-8",
    )

    with pytest.raises(MissingSecretError, match="PAYGATE_CLIENT_PHOENIXD_PASSWORD"):
        load_config(config_path, env={})


def test_negative_max_request_sats_fails_before_payer_code(tmp_path):
    config_path = tmp_path / "paygate.yml"
    config_path.write_text(
        """
payer:
  backend: test-mode
policy:
  max_request_sats: -1
  max_fee_sats: 10
  daily_budget_sats: 500
  allowed_hosts:
    - localhost:8080
  allowed_services:
    - paygate-reference-service
""",
        encoding="utf-8",
    )

    with pytest.raises(ValidationError, match="policy.max_request_sats"):
        load_config(config_path)


def test_empty_allowlists_fail_closed(tmp_path):
    config_path = tmp_path / "paygate.yml"
    config_path.write_text(
        """
payer:
  backend: test-mode
policy:
  max_request_sats: 50
  max_fee_sats: 10
  daily_budget_sats: 500
  allowed_hosts: []
  allowed_services: []
""",
        encoding="utf-8",
    )

    with pytest.raises(ValidationError, match="allowed_hosts"):
        load_config(config_path)


def test_protocol_defaults_do_not_enable_l402(tmp_path):
    config_path = tmp_path / "paygate.yml"
    config_path.write_text(
        """
payer:
  backend: test-mode
policy:
  max_request_sats: 50
  max_fee_sats: 10
  daily_budget_sats: 500
  allowed_hosts:
    - localhost:8080
  allowed_services:
    - paygate-reference-service
""",
        encoding="utf-8",
    )

    config = load_config(config_path)

    assert config.protocol.preferred == "Payment"
    assert config.protocol.allow_l402 is False


def test_documented_example_config_loads_without_real_lightning_secrets():
    config = load_config(Path("examples/paygate-client.yaml"), env={})

    assert config.payer.backend == "test-mode"
    assert config.policy.allowed_hosts
    assert config.policy.allowed_services
    assert config.lnd is None
    assert config.phoenixd is None


def test_lnd_config_loads_script_generated_companion_env_file(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        """
payer:
  backend: lnd-rest
policy:
  max_request_sats: 10
  max_fee_sats: 2
  daily_budget_sats: 100
  allowed_hosts:
    - localhost:8080
  allowed_services:
    - paygate-reference-service
lnd:
  rest_url_env: "PAYGATE_CLIENT_LND_REST_URL"
  macaroon_hex_env: "PAYGATE_CLIENT_LND_MACAROON_HEX"
""",
        encoding="utf-8",
    )
    (tmp_path / "voltage-env.sh").write_text(
        """
export PAYGATE_CLIENT_LND_REST_URL="https://node.m.voltageapp.io:8080"
export PAYGATE_CLIENT_LND_MACAROON_HEX="00aa"
""",
        encoding="utf-8",
    )

    config = load_config(config_path, env={})

    assert config.lnd is not None
    assert config.lnd.rest_url_env.env_var == "PAYGATE_CLIENT_LND_REST_URL"
    assert config.lnd.macaroon_hex_env.env_var == "PAYGATE_CLIENT_LND_MACAROON_HEX"
