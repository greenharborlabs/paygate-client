from __future__ import annotations

import base64
import json

import pytest

from paygate_client.challenges import (
    ExpiredChallengeError,
    L402Challenge,
    MalformedHeaderError,
    MalformedMPPRequestError,
    MalformedOpaquePayloadError,
    MissingAmountError,
    MissingInvoiceError,
    MissingMPPRequestError,
    MissingTokenError,
    NoSupportedChallengeError,
    PaymentChallenge,
    ProtocolDisabledError,
    parse_challenges,
)
from paygate_client.config import ProtocolConfig


def _b64url_json(payload: object) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _payment_request(
    *,
    invoice: str = "lnbc1test",
    amount_sats: int = 25,
    payment_hash: str = "00" * 32,
    service: str = "orders",
    description: str = "download",
) -> str:
    return _b64url_json(
        {
            "invoice": invoice,
            "amountSats": amount_sats,
            "methodDetails": {"paymentHash": payment_hash},
            "service": service,
            "description": description,
        }
    )


def _payment_header(
    request: str | None = None,
    *,
    opaque: str | None = None,
    expires: int = 4_102_444_800,
) -> str:
    request_param = "" if request is None else f', request="{request}"'
    opaque_param = "" if opaque is None else f", opaque={opaque}"
    return (
        'Payment id=pay_123, realm=orders, method="lightning"'
        f"{request_param}, expires={expires}, digest=sha-256=:abc:{opaque_param}"
    )


def test_dual_protocol_headers_select_preferred_payment() -> None:
    preimage = "11" * 32
    opaque = _b64url_json({"test_preimage": preimage})
    headers = [
        _payment_header(_payment_request(), opaque=opaque),
        'L402 token="tok_123", macaroon="tok_123", invoice="lnbc1l402", version=1',
    ]

    challenge = parse_challenges(headers, ProtocolConfig(preferred="Payment"))

    assert isinstance(challenge, PaymentChallenge)
    assert challenge.id == "pay_123"
    assert challenge.realm == "orders"
    assert challenge.method == "lightning"
    assert challenge.invoice == "lnbc1test"
    assert challenge.amount_sats == 25
    assert challenge.payment_hash == "00" * 32
    assert challenge.service == "orders"
    assert challenge.description == "download"
    assert challenge.digest == "sha-256=:abc:"
    assert challenge.test_preimage == preimage
    assert challenge.auth_params["request"] == challenge.request
    assert challenge.opaque_payload == {"test_preimage": preimage}


def test_payment_request_payload_exposes_payment_hash_for_credentials() -> None:
    payment_hash = "ab" * 32
    challenge = parse_challenges(
        [_payment_header(_payment_request(payment_hash=payment_hash))],
        ProtocolConfig(preferred="Payment"),
    )

    assert isinstance(challenge, PaymentChallenge)
    assert challenge.payment_hash == payment_hash
    assert challenge.method_details == {"paymentHash": payment_hash}
    assert challenge.request_payload["methodDetails"] == {"paymentHash": payment_hash}


def test_payment_request_accepts_reference_app_payload_shape() -> None:
    request = _b64url_json(
        {
            "amount": "10",
            "currency": "BTC",
            "methodDetails": {
                "invoice": "lntb10test",
                "network": "mainnet",
                "paymentHash": "ab" * 32,
            },
        }
    )

    challenge = parse_challenges(
        [
            _payment_header(
                request,
                expires="2026-06-12T03:37:12.085906Z",
            )
        ],
        ProtocolConfig(preferred="Payment"),
        now=1_700_000_000,
    )

    assert isinstance(challenge, PaymentChallenge)
    assert challenge.invoice == "lntb10test"
    assert challenge.amount_sats == 10
    assert challenge.payment_hash == "ab" * 32
    assert challenge.service == "orders"


def test_l402_only_with_l402_disabled_raises_protocol_disabled() -> None:
    with pytest.raises(ProtocolDisabledError):
        parse_challenges(
            ['L402 token="tok_123", macaroon="tok_123", invoice="lnbc1l402"'],
            ProtocolConfig(preferred="Payment", allow_l402=False),
        )


def test_l402_preferred_when_allowed() -> None:
    challenge = parse_challenges(
        [
            _payment_header(_payment_request()),
            'L402 token="tok_123", macaroon="tok_123", invoice="lnbc1l402", version=1',
        ],
        ProtocolConfig(preferred="L402", allow_l402=True),
    )

    assert isinstance(challenge, L402Challenge)
    assert challenge.token == "tok_123"
    assert challenge.macaroon == "tok_123"
    assert challenge.credential_token == "tok_123"
    assert challenge.invoice == "lnbc1l402"
    assert challenge.version == "1"


def test_l402_preferred_ignores_malformed_payment_fallback() -> None:
    malformed_payment = _payment_header(_b64url_json({"amount": "10"}))

    challenge = parse_challenges(
        [
            'L402 token="tok_123", macaroon="tok_123", invoice="lnbc1l402", version=1',
            malformed_payment,
        ],
        ProtocolConfig(preferred="L402", allow_l402=True),
    )

    assert isinstance(challenge, L402Challenge)
    assert challenge.invoice == "lnbc1l402"


def test_l402_keeps_different_token_and_macaroon_values_distinct() -> None:
    challenge = parse_challenges(
        ['L402 token="tok_123", macaroon="mac_456", invoice="lnbc1l402"'],
        ProtocolConfig(preferred="L402", allow_l402=True),
    )

    assert isinstance(challenge, L402Challenge)
    assert challenge.token == "tok_123"
    assert challenge.macaroon == "mac_456"


def test_collapsed_header_does_not_split_payment_auth_params_on_commas() -> None:
    header = (
        _payment_header(_payment_request())
        + ', L402 token="tok_123", macaroon="tok_123", invoice="lnbc1l402"'
    )

    challenge = parse_challenges(
        [header],
        ProtocolConfig(preferred="L402", allow_l402=True),
    )

    assert isinstance(challenge, L402Challenge)
    assert challenge.invoice == "lnbc1l402"


def test_unsupported_scheme_produces_no_supported_challenge() -> None:
    with pytest.raises(NoSupportedChallengeError):
        parse_challenges(
            ['Bearer realm="api"'],
            ProtocolConfig(preferred="Payment"),
        )


@pytest.mark.parametrize(
    "header",
    [
        'Payment id="unterminated, realm=orders',
        f"Payment id=pay_123, realm=orders, request={_payment_request()} junk=1",
    ],
)
def test_malformed_auth_params_raise_malformed_header(header: str) -> None:
    with pytest.raises(MalformedHeaderError):
        parse_challenges([header], ProtocolConfig(preferred="Payment"))


@pytest.mark.parametrize(
    "encoded_request",
    [
        "eyJmb28iOiJiYXIifQ==",
        "not valid base64",
        base64.urlsafe_b64encode(b"not-json").decode("ascii").rstrip("="),
    ],
)
def test_malformed_payment_request_payload_raises_distinct_error(
    encoded_request: str,
) -> None:
    with pytest.raises(MalformedMPPRequestError):
        parse_challenges(
            [_payment_header(encoded_request)],
            ProtocolConfig(preferred="Payment"),
        )


def test_missing_payment_request_raises_distinct_error() -> None:
    with pytest.raises(MissingMPPRequestError):
        parse_challenges(
            [_payment_header(None)],
            ProtocolConfig(preferred="Payment"),
        )


def test_payment_request_without_invoice_raises_distinct_error() -> None:
    request = _b64url_json({"amountSats": 25, "methodDetails": {}})

    with pytest.raises(MissingInvoiceError):
        parse_challenges(
            [_payment_header(request)],
            ProtocolConfig(preferred="Payment"),
        )


def test_payment_request_without_amount_raises_distinct_error() -> None:
    request = _b64url_json({"invoice": "lnbc1test", "methodDetails": {}})

    with pytest.raises(MissingAmountError):
        parse_challenges(
            [_payment_header(request)],
            ProtocolConfig(preferred="Payment"),
        )


def test_payment_request_accepts_snake_case_amount() -> None:
    request = _b64url_json(
        {
            "invoice": "lnbc1test",
            "amount_sats": 25,
            "methodDetails": {},
        }
    )

    challenge = parse_challenges(
        [_payment_header(request)],
        ProtocolConfig(preferred="Payment"),
    )

    assert isinstance(challenge, PaymentChallenge)
    assert challenge.amount_sats == 25


@pytest.mark.parametrize("amount", [True, False, -1, "25", 25.5, None])
def test_payment_request_rejects_malformed_amount(amount: object) -> None:
    request = _b64url_json(
        {
            "invoice": "lnbc1test",
            "amountSats": amount,
            "methodDetails": {},
        }
    )

    with pytest.raises(MalformedMPPRequestError):
        parse_challenges(
            [_payment_header(request)],
            ProtocolConfig(preferred="Payment"),
        )


def test_l402_without_invoice_raises_distinct_error() -> None:
    with pytest.raises(MissingInvoiceError):
        parse_challenges(
            ['L402 token="tok_123"'],
            ProtocolConfig(preferred="L402", allow_l402=True),
        )


def test_l402_without_token_or_macaroon_raises_distinct_error() -> None:
    with pytest.raises(MissingTokenError):
        parse_challenges(
            ['L402 invoice="lnbc1l402"'],
            ProtocolConfig(preferred="L402", allow_l402=True),
        )


def test_malformed_opaque_payload_raises_distinct_error() -> None:
    with pytest.raises(MalformedOpaquePayloadError):
        parse_challenges(
            [_payment_header(_payment_request(), opaque="not_valid_base64!")],
            ProtocolConfig(preferred="Payment"),
        )


def test_expired_payment_challenge_raises_distinct_error() -> None:
    with pytest.raises(ExpiredChallengeError):
        parse_challenges(
            [_payment_header(_payment_request(), expires=100)],
            ProtocolConfig(preferred="Payment"),
            now=101,
        )
