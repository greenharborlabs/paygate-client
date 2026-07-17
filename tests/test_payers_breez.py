from __future__ import annotations

import os
import subprocess
import sys
import venv
from hashlib import sha256
from importlib.metadata import version
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import pip
from packaging.requirements import Requirement
from packaging.version import Version

from paygate_client.config import BreezConfig, SecretRef
from paygate_client.payers.base import (
    MissingPreimageError,
    PaymentChallenge,
    PreimageVerificationError,
)
from paygate_client.payers.breez import (
    BreezDependencyError,
    BreezFeeLimitExceededError,
    BreezMalformedResponseError,
    BreezPayer,
)

PREIMAGE = "11" * 32
PAYMENT_HASH = sha256(bytes.fromhex(PREIMAGE)).hexdigest()


def _config() -> BreezConfig:
    return BreezConfig(
        api_key_env=SecretRef("BREEZ_API_KEY"),
        mnemonic_env=SecretRef("BREEZ_MNEMONIC"),
        storage_dir=".breez-test",
    )


def _env() -> dict[str, str]:
    return {
        "BREEZ_API_KEY": "api-key",
        "BREEZ_MNEMONIC": "abandon " * 11 + "about",
    }


def _challenge() -> PaymentChallenge:
    return PaymentChallenge(
        invoice="lnbc1breez",
        payment_hash=PAYMENT_HASH,
        amount_sats=5,
    )


class FakeVariant:
    def __init__(self, **kwargs: Any) -> None:
        vars(self).update(kwargs)

    def is_BOLT11_INVOICE(self) -> bool:
        return True


class FakePaymentRequest:
    @staticmethod
    def INPUT(*, input: str) -> object:
        return SimpleNamespace(input=input)


class FakeSeed:
    @staticmethod
    def MNEMONIC(*, mnemonic: str, passphrase: None) -> object:
        return SimpleNamespace(mnemonic=mnemonic, passphrase=passphrase)


class FakeSendPaymentOptions:
    @staticmethod
    def BOLT11_INVOICE(*, prefer_spark: bool, completion_timeout_secs: int) -> object:
        return SimpleNamespace(
            prefer_spark=prefer_spark,
            completion_timeout_secs=completion_timeout_secs,
        )


class FakeBreez:
    PaymentRequest = FakePaymentRequest
    Seed = FakeSeed
    SendPaymentOptions = FakeSendPaymentOptions
    Network = SimpleNamespace(MAINNET="mainnet")

    def __init__(
        self,
        *,
        prepared_fee_sats: int = 3,
        final_fee_sats: int = 3,
        preimage: str | None = PREIMAGE,
        bolt11: bool = True,
    ) -> None:
        self.prepared_fee_sats = prepared_fee_sats
        self.final_fee_sats = final_fee_sats
        self.preimage = preimage
        self.bolt11 = bolt11
        self.sent = False
        self.disconnected = False
        self.send_options: object | None = None

    def default_config(self, *, network: object) -> object:
        return SimpleNamespace(network=network, api_key=None)

    def ConnectRequest(self, **kwargs: object) -> object:
        return SimpleNamespace(**kwargs)

    def PrepareSendPaymentRequest(self, **kwargs: object) -> object:
        return SimpleNamespace(**kwargs)

    def SendPaymentRequest(self, **kwargs: object) -> object:
        self.send_options = kwargs["options"]
        return SimpleNamespace(**kwargs)

    async def connect(self, *, request: object) -> FakeBreez:
        return self

    async def prepare_send_payment(self, *, request: object) -> object:
        payment_method = FakeVariant(lightning_fee_sats=self.prepared_fee_sats)
        if not self.bolt11:
            payment_method.is_BOLT11_INVOICE = lambda: False  # type: ignore[method-assign]
        return SimpleNamespace(payment_method=payment_method)

    async def send_payment(self, *, request: object) -> object:
        self.sent = True
        htlc_details = SimpleNamespace(
            payment_hash=PAYMENT_HASH,
            preimage=self.preimage,
        )
        details = SimpleNamespace(htlc_details=htlc_details)
        return SimpleNamespace(
            payment=SimpleNamespace(
                amount=5,
                fees=self.final_fee_sats,
                details=details,
            )
        )

    async def disconnect(self) -> None:
        self.disconnected = True


def test_breez_success_forces_lightning_and_returns_verified_result() -> None:
    fake_breez = FakeBreez()
    payer = BreezPayer(_config(), env=_env(), sdk_module=fake_breez)

    result = payer.pay(_challenge(), max_fee_sats=5)

    assert result.amount_sats == 5
    assert result.fee_sats == 3
    assert result.payment_hash == PAYMENT_HASH
    assert result.preimage_hex == PREIMAGE
    assert fake_breez.sent is True
    assert fake_breez.disconnected is True
    assert fake_breez.send_options.prefer_spark is False


def test_breez_missing_sdk_is_reported_before_resolving_wallet_secrets(
    monkeypatch,
) -> None:
    resolved: list[str] = []

    def missing_sdk(self: BreezPayer) -> object:
        raise BreezDependencyError(
            "Reinstall the same paygate-client distribution with the Breez extra "
            "enabled (add [breez] to the original install requirement)."
        )

    def resolve_api_key(self: BreezConfig, env: object = None) -> str:
        resolved.append("api-key")
        return "sentinel-api-key"

    def resolve_mnemonic(self: BreezConfig, env: object = None) -> str:
        resolved.append("mnemonic")
        return "sentinel wallet mnemonic"

    monkeypatch.setattr(BreezPayer, "_load_sdk", missing_sdk)
    monkeypatch.setattr(BreezConfig, "resolve_api_key", resolve_api_key)
    monkeypatch.setattr(BreezConfig, "resolve_mnemonic", resolve_mnemonic)

    with pytest.raises(BreezDependencyError, match="same paygate-client distribution"):
        BreezPayer(_config(), env=_env())

    assert resolved == []


def test_readme_breez_source_install_is_pinned_and_pypi_is_future_only() -> None:
    repository = Path(__file__).parents[1]
    readme = repository / "README.md"
    content = readme.read_text(encoding="utf-8")
    requirement_text = (
        "paygate-client[breez] @ "
        "git+https://github.com/greenharborlabs/paygate-client.git@"
        "e687fccb9a0a3d5ae9d3878b6e4fb4853df31901"
    )

    requirement = Requirement(requirement_text)

    assert requirement.name == "paygate-client"
    assert requirement.extras == {"breez"}
    assert requirement.url == (
        "git+https://github.com/greenharborlabs/paygate-client.git@"
        "e687fccb9a0a3d5ae9d3878b6e4fb4853df31901"
    )
    assert requirement_text in content
    bare_pypi_command = 'pipx install --force "paygate-client[breez]"'
    assert content.count(bare_pypi_command) == 1
    bare_command_offset = content.index(bare_pypi_command)
    assert (
        "After paygate-client is published to PyPI"
        in content[bare_command_offset - 200 : bare_command_offset]
    )
    example = (repository / "examples" / "paygate-client.yaml").read_text(
        encoding="utf-8"
    )
    assert requirement_text in example
    assert '"paygate-client[breez]"' not in example


def test_readme_breez_requirement_installs_from_local_pinned_git_without_deps(
    tmp_path: Path,
) -> None:
    repository = Path(__file__).parents[1]
    content = (repository / "README.md").read_text(encoding="utf-8")
    expected_commit = "e687fccb9a0a3d5ae9d3878b6e4fb4853df31901"
    remote_requirement_text = (
        "paygate-client[breez] @ git+https://github.com/greenharborlabs/"
        f"paygate-client.git@{expected_commit}"
    )
    remote_requirement = Requirement(remote_requirement_text)

    assert remote_requirement.url is not None
    assert remote_requirement.url.endswith(expected_commit)
    assert remote_requirement.extras == {"breez"}
    assert remote_requirement_text in content

    environment = tmp_path / "pip-validation"
    venv.EnvBuilder(with_pip=True).create(environment)
    executable = "Scripts/python.exe" if sys.platform == "win32" else "bin/python"
    python = environment / executable
    local_requirement = (
        f"paygate-client[breez] @ git+{repository.as_uri()}@{expected_commit}"
    )
    parsed_local_requirement = Requirement(local_requirement)

    assert parsed_local_requirement.name == remote_requirement.name
    assert parsed_local_requirement.extras == remote_requirement.extras
    assert parsed_local_requirement.url is not None
    assert parsed_local_requirement.url.endswith(expected_commit)

    # ensurepip's bundled tooling can be too old for this PEP 621 project.
    # The dev extra explicitly provides this compatible backend; expose the
    # runner's local site-packages to the otherwise fresh venv rather than
    # downloading build tooling during this offline validation.
    assert Version(version("setuptools")) >= Version("77.0.3")
    pip_package_root = str(Path(pip.__file__).resolve().parents[1])
    python_path = os.environ.get("PYTHONPATH")
    environment_variables = os.environ.copy()
    environment_variables["PYTHONPATH"] = (
        pip_package_root
        if not python_path
        else f"{pip_package_root}{os.pathsep}{python_path}"
    )
    result = subprocess.run(
        [
            str(python),
            "-m",
            "pip",
            "install",
            "--dry-run",
            "--ignore-installed",
            "--no-deps",
            "--no-build-isolation",
            local_requirement,
        ],
        capture_output=True,
        text=True,
        env=environment_variables,
    )
    # A fresh venv intentionally contains only ensurepip's bootstrap tooling.
    # --dry-run still makes pip clone and resolve the pinned local Git reference,
    # without requiring wheel or fetching the Breez extra's dependencies.
    pip_output = result.stdout + result.stderr
    assert result.returncode == 0, pip_output
    assert f"Resolved {repository.as_uri()} to commit {expected_commit}" in pip_output


def test_breez_rejects_prepared_fee_above_limit_before_send() -> None:
    fake_breez = FakeBreez(prepared_fee_sats=6)
    payer = BreezPayer(_config(), env=_env(), sdk_module=fake_breez)

    with pytest.raises(BreezFeeLimitExceededError):
        payer.pay(_challenge(), max_fee_sats=5)

    assert fake_breez.sent is False
    assert fake_breez.disconnected is True


def test_breez_rejects_non_bolt11_prepare_response() -> None:
    fake_breez = FakeBreez(bolt11=False)
    payer = BreezPayer(_config(), env=_env(), sdk_module=fake_breez)

    with pytest.raises(BreezMalformedResponseError):
        payer.pay(_challenge(), max_fee_sats=5)

    assert fake_breez.sent is False


def test_breez_missing_preimage_is_not_success() -> None:
    fake_breez = FakeBreez(preimage=None)
    payer = BreezPayer(_config(), env=_env(), sdk_module=fake_breez)

    with pytest.raises(MissingPreimageError):
        payer.pay(_challenge(), max_fee_sats=5)


def test_breez_preimage_mismatch_is_not_success() -> None:
    fake_breez = FakeBreez(preimage="22" * 32)
    payer = BreezPayer(_config(), env=_env(), sdk_module=fake_breez)

    with pytest.raises(PreimageVerificationError):
        payer.pay(_challenge(), max_fee_sats=5)
