from __future__ import annotations

import json
from collections.abc import Callable
from hashlib import sha256

import httpx
import pytest

from paygate_client.config import EnvRef, LndConfig, SecretRef
from paygate_client.payers.base import (
    MissingPreimageError,
    PaymentChallenge,
    PreimageVerificationError,
)
from paygate_client.payers.lnd_rest import (
    InvalidMacaroonError,
    LndMalformedResponseError,
    LndPaymentFailureError,
    LndPaymentTimeoutError,
    LndRestPayer,
    LndTlsCertificateError,
)


def _hash_preimage(preimage_hex: str) -> str:
    return sha256(bytes.fromhex(preimage_hex)).hexdigest()


def _config() -> LndConfig:
    return LndConfig(
        rest_url_env=EnvRef("PAYGATE_CLIENT_LND_REST_URL"),
        macaroon_hex_env=SecretRef("PAYGATE_CLIENT_LND_MACAROON_HEX"),
        tls_cert_path_env=EnvRef("PAYGATE_CLIENT_LND_TLS_CERT_PATH"),
    )


def _env(*, macaroon_hex: str = "ab" * 32) -> dict[str, str]:
    return {
        "PAYGATE_CLIENT_LND_REST_URL": "https://lnd.example.test:8080",
        "PAYGATE_CLIENT_LND_MACAROON_HEX": macaroon_hex,
        "PAYGATE_CLIENT_LND_TLS_CERT_PATH": "/tmp/lnd-tls.cert",
    }


def _challenge(preimage: str, *, amount_sats: int = 1250) -> PaymentChallenge:
    return PaymentChallenge(
        invoice="lnbc1250n1paygate",
        payment_hash=_hash_preimage(preimage),
        amount_sats=amount_sats,
    )


def _json_line(update: dict[str, object]) -> bytes:
    return json.dumps({"result": update}).encode("utf-8") + b"\n"


def _client(
    handler: Callable[[httpx.Request], httpx.Response],
) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_lnd_rest_success_response_returns_normalized_payment_result() -> None:
    preimage = "11" * 32
    challenge = _challenge(preimage)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url == "https://lnd.example.test:8080/v2/router/send"
        assert request.headers["Grpc-Metadata-macaroon"] == "ab" * 32
        body = json.loads(request.content)
        assert body["payment_request"] == challenge.invoice
        return httpx.Response(
            200,
            content=(
                _json_line({"status": "IN_FLIGHT"})
                + _json_line(
                    {
                        "status": "SUCCEEDED",
                        "payment_preimage": preimage.upper(),
                        "payment_hash": challenge.payment_hash,
                        "value_sat": "1250",
                        "fee_sat": "7",
                    }
                )
            ),
        )

    payer = LndRestPayer(_config(), env=_env(), client=_client(handler))

    result = payer.pay(challenge, max_fee_sats=10)

    assert result.amount_sats == 1250
    assert result.fee_sats == 7
    assert result.payment_hash == challenge.payment_hash
    assert result.preimage_hex == preimage


def test_invalid_macaroon_hex_fails_before_http_request() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        raise AssertionError("HTTP request must not be attempted")

    with pytest.raises(InvalidMacaroonError):
        LndRestPayer(
            _config(),
            env=_env(macaroon_hex="not-hex"),
            client=_client(handler),
        )

    assert requests == []


def test_lnd_rest_request_includes_fee_limit_from_max_fee_sats() -> None:
    preimage = "22" * 32
    challenge = _challenge(preimage)
    seen_fee_limits: list[object] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen_fee_limits.append(body.get("fee_limit_sat"))
        return httpx.Response(
            200,
            content=_json_line(
                {
                    "status": "SUCCEEDED",
                    "payment_preimage": preimage,
                    "payment_hash": challenge.payment_hash,
                    "value_sat": 1250,
                    "fee_sat": 10,
                }
            ),
        )

    payer = LndRestPayer(_config(), env=_env(), client=_client(handler))

    payer.pay(challenge, max_fee_sats=10)

    assert seen_fee_limits == [10]


def test_intermediate_update_without_terminal_success_is_not_paid() -> None:
    challenge = _challenge("33" * 32)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=_json_line({"status": "IN_FLIGHT"}))

    payer = LndRestPayer(_config(), env=_env(), client=_client(handler))

    with pytest.raises(LndPaymentTimeoutError):
        payer.pay(challenge, max_fee_sats=10)


def test_preimage_mismatch_raises_preimage_verification_error() -> None:
    challenge = _challenge("44" * 32)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=_json_line(
                {
                    "status": "SUCCEEDED",
                    "payment_preimage": "55" * 32,
                    "payment_hash": challenge.payment_hash,
                    "value_sat": 1250,
                    "fee_sat": 1,
                }
            ),
        )

    payer = LndRestPayer(_config(), env=_env(), client=_client(handler))

    with pytest.raises(PreimageVerificationError):
        payer.pay(challenge, max_fee_sats=10)


def test_terminal_failed_update_raises_payment_failure() -> None:
    challenge = _challenge("66" * 32)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=_json_line(
                {"status": "FAILED", "failure_reason": "FAILURE_REASON_TIMEOUT"}
            ),
        )

    payer = LndRestPayer(_config(), env=_env(), client=_client(handler))

    with pytest.raises(LndPaymentFailureError):
        payer.pay(challenge, max_fee_sats=10)


def test_tls_errors_are_mapped_to_distinct_failure() -> None:
    challenge = _challenge("77" * 32)

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(
            "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed",
            request=request,
        )

    payer = LndRestPayer(_config(), env=_env(), client=_client(handler))

    with pytest.raises(LndTlsCertificateError):
        payer.pay(challenge, max_fee_sats=10)


def test_malformed_stream_response_raises_distinct_failure() -> None:
    challenge = _challenge("88" * 32)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"{not-json}\n")

    payer = LndRestPayer(_config(), env=_env(), client=_client(handler))

    with pytest.raises(LndMalformedResponseError):
        payer.pay(challenge, max_fee_sats=10)


def test_success_without_preimage_raises_missing_preimage() -> None:
    challenge = _challenge("99" * 32)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=_json_line(
                {
                    "status": "SUCCEEDED",
                    "payment_hash": challenge.payment_hash,
                    "value_sat": 1250,
                    "fee_sat": 1,
                }
            ),
        )

    payer = LndRestPayer(_config(), env=_env(), client=_client(handler))

    with pytest.raises(MissingPreimageError):
        payer.pay(challenge, max_fee_sats=10)
