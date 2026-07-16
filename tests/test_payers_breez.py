from __future__ import annotations

from hashlib import sha256
from types import SimpleNamespace
from typing import Any

import pytest

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


def test_breez_readiness_fails_when_sdk_dependency_is_missing(monkeypatch) -> None:
    payer = BreezPayer(_config(), env=_env())

    def missing_sdk() -> object:
        raise BreezDependencyError(
            "Install Breez support first: python -m pip install 'paygate-client[breez]'"
        )

    monkeypatch.setattr(payer, "_load_sdk", missing_sdk)

    with pytest.raises(BreezDependencyError, match=r"paygate-client\[breez\]"):
        payer.check_ready()


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
