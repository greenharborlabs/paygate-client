from __future__ import annotations

from hashlib import sha256

import httpx
import pytest

from paygate_client.config import PhoenixdConfig, SecretRef
from paygate_client.payers.base import (
    FeeLimitUnsupportedError,
    MissingPreimageError,
    PaymentChallenge,
    PaymentRejectedError,
    PreimageVerificationError,
)
from paygate_client.payers.phoenixd import (
    PhoenixdAuthError,
    PhoenixdMalformedResponseError,
    PhoenixdPayer,
    PhoenixdTimeoutError,
)


def _hash_preimage(preimage_hex: str) -> str:
    return sha256(bytes.fromhex(preimage_hex)).hexdigest()


def _challenge(preimage_hex: str = "11" * 32) -> PaymentChallenge:
    return PaymentChallenge(
        invoice="lnbc1phoenixd",
        payment_hash=_hash_preimage(preimage_hex),
        amount_sats=250,
    )


def _config() -> PhoenixdConfig:
    return PhoenixdConfig(
        url="http://phoenixd.test",
        password_env=SecretRef("PHOENIXD_PASSWORD"),
    )


def _payer(
    transport: httpx.MockTransport,
    *,
    fee_limit_parameter: str | None = None,
) -> PhoenixdPayer:
    client = httpx.Client(transport=transport)
    return PhoenixdPayer.from_config(
        _config(),
        env={"PHOENIXD_PASSWORD": "secret"},
        client=client,
        fee_limit_parameter=fee_limit_parameter,
    )


def test_phoenixd_success_normalizes_uppercase_preimage_and_posts_fee_limit() -> None:
    preimage = "AB" * 32
    seen_requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_requests.append(request)
        body = request.content.decode("utf-8")
        assert "invoice=lnbc1phoenixd" in body
        assert "amountSat=250" in body
        assert "maxFeeSat=3" in body
        assert request.headers["Authorization"].startswith("Basic ")
        return httpx.Response(
            200,
            json={
                "type": "payment_sent",
                "recipientAmountSat": 250,
                "routingFeeSat": 2,
                "paymentHash": _hash_preimage(preimage),
                "paymentPreimage": preimage,
            },
        )

    result = _payer(
        httpx.MockTransport(handler),
        fee_limit_parameter="maxFeeSat",
    ).pay(
        _challenge(preimage),
        max_fee_sats=3,
    )

    assert len(seen_requests) == 1
    assert seen_requests[0].url == "http://phoenixd.test/payinvoice"
    assert result.amount_sats == 250
    assert result.fee_sats == 2
    assert result.payment_hash == _hash_preimage(preimage)
    assert result.preimage_hex == preimage.lower()


def test_phoenixd_missing_preimage_marks_backend_unsupported() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "type": "payment_sent",
                "recipientAmountSat": 250,
                "routingFeeSat": 2,
                "paymentHash": _hash_preimage("11" * 32),
            },
        )

    with pytest.raises(MissingPreimageError):
        _payer(
            httpx.MockTransport(handler),
            fee_limit_parameter="maxFeeSat",
        ).pay(_challenge(), max_fee_sats=3)


def test_phoenixd_default_fee_limit_unsupported_refuses_before_posting_invoice() -> None:
    submitted = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal submitted
        submitted = True
        raise AssertionError("must not post invoice without fee limit support")

    payer = _payer(httpx.MockTransport(handler))

    with pytest.raises(FeeLimitUnsupportedError):
        payer.pay(_challenge(), max_fee_sats=3)

    assert submitted is False
    assert payer.supports_max_fee_limit is False


def test_phoenixd_explicit_fee_limit_parameter_advertises_support() -> None:
    payer = _payer(
        httpx.MockTransport(lambda request: httpx.Response(500)),
        fee_limit_parameter="maxFeeSat",
    )

    assert payer.supports_max_fee_limit is True


def test_phoenixd_preimage_mismatch_raises_verification_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "type": "payment_sent",
                "recipientAmountSat": 250,
                "routingFeeSat": 2,
                "paymentHash": _hash_preimage("22" * 32),
                "paymentPreimage": "22" * 32,
            },
        )

    with pytest.raises(PreimageVerificationError):
        _payer(
            httpx.MockTransport(handler),
            fee_limit_parameter="maxFeeSat",
        ).pay(_challenge("11" * 32), max_fee_sats=3)


def test_phoenixd_auth_failure_is_distinct() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, text="Invalid authentication")

    with pytest.raises(PhoenixdAuthError):
        _payer(
            httpx.MockTransport(handler),
            fee_limit_parameter="maxFeeSat",
        ).pay(_challenge(), max_fee_sats=3)


def test_phoenixd_payment_rejected_is_distinct() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "type": "payment_failed",
                "paymentHash": _hash_preimage("11" * 32),
                "reason": "route not found",
            },
        )

    with pytest.raises(PaymentRejectedError):
        _payer(
            httpx.MockTransport(handler),
            fee_limit_parameter="maxFeeSat",
        ).pay(_challenge(), max_fee_sats=3)


def test_phoenixd_malformed_response_is_distinct() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"type": "payment_sent", "routingFeeSat": 2})

    with pytest.raises(PhoenixdMalformedResponseError):
        _payer(
            httpx.MockTransport(handler),
            fee_limit_parameter="maxFeeSat",
        ).pay(_challenge(), max_fee_sats=3)


def test_phoenixd_timeout_is_distinct() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("timed out", request=request)

    with pytest.raises(PhoenixdTimeoutError):
        _payer(
            httpx.MockTransport(handler),
            fee_limit_parameter="maxFeeSat",
        ).pay(_challenge(), max_fee_sats=3)
