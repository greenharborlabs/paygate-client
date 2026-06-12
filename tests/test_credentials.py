from __future__ import annotations

import base64
import json
from typing import Any

import pytest

from paygate_client.challenges import L402Challenge, PaymentChallenge
from paygate_client.credentials import (
    CredentialError,
    InvalidCredentialTokenError,
    InvalidPreimageError,
    MissingCredentialTokenError,
    UnsupportedCredentialProtocolError,
    build_authorization,
)

ZERO_PREIMAGE = "00" * 32


def _decode_payment_authorization(value: str) -> tuple[dict[str, Any], bytes, str]:
    scheme, blob = value.split(" ", 1)
    assert scheme == "Payment"
    assert "=" not in blob
    padded = blob + ("=" * (-len(blob) % 4))
    raw = base64.urlsafe_b64decode(padded)
    return json.loads(raw), raw, blob


def _mpp_challenge() -> PaymentChallenge:
    request_payload = {
        "amount": 123,
        "method": "bolt11",
        "methodDetails": {
            "invoice": "lnbc1test",
            "paymentHash": "ab" * 32,
        },
    }
    return PaymentChallenge(
        id="challenge-123",
        realm="paygate",
        method="mpp",
        request="request-payload-token",
        invoice="lnbc1test",
        amount_sats=123,
        payment_hash="ab" * 32,
        expires=1_725_000_000,
        digest="sha-256=:abc:",
        description="fixture payment",
        opaque="opaque-token",
        intent="download",
        method_details=request_payload["methodDetails"],
        request_payload=request_payload,
        auth_params={
            "id": "challenge-123",
            "realm": "paygate",
            "method": "mpp",
            "intent": "download",
            "request": "request-payload-token",
            "expires": "1725000000",
            "digest": "sha-256=:abc:",
            "description": "fixture payment",
            "opaque": "opaque-token",
        },
    )


def test_build_l402_authorization_uses_token_and_lowercase_preimage() -> None:
    preimage = "A" * 64
    challenge = L402Challenge(token="abc", macaroon=None, invoice="lnbc1test")

    assert build_authorization(challenge, preimage) == f"L402 abc:{preimage.lower()}"


def test_build_l402_authorization_uses_macaroon_when_token_absent() -> None:
    challenge = L402Challenge(
        token=None, macaroon="macaroon-value", invoice="lnbc1test"
    )

    assert build_authorization(challenge, ZERO_PREIMAGE) == (
        f"L402 macaroon-value:{ZERO_PREIMAGE}"
    )


@pytest.mark.parametrize(
    "token", ["abc\rdef", "abc\ndef", "abc:def", "abc,def", "abc\x7fdef"]
)
def test_build_l402_authorization_rejects_header_unsafe_tokens(token: str) -> None:
    challenge = L402Challenge(token=token, macaroon=None, invoice="lnbc1test")

    with pytest.raises(InvalidCredentialTokenError):
        build_authorization(challenge, ZERO_PREIMAGE)


def test_build_l402_authorization_rejects_missing_token() -> None:
    challenge = L402Challenge(token=None, macaroon=None, invoice="lnbc1test")

    with pytest.raises(MissingCredentialTokenError):
        build_authorization(challenge, ZERO_PREIMAGE)


def test_build_payment_authorization_emits_decodable_mpp_credential() -> None:
    authorization = build_authorization(
        _mpp_challenge(),
        ZERO_PREIMAGE.upper(),
        source="unit-test",
    )

    decoded, raw_json, blob = _decode_payment_authorization(authorization)

    assert blob == blob.rstrip("=")
    assert raw_json == json.dumps(
        decoded, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    assert decoded == {
        "challenge": {
            "description": "fixture payment",
            "digest": "sha-256=:abc:",
            "expires": "1725000000",
            "id": "challenge-123",
            "intent": "download",
            "method": "mpp",
            "opaque": "opaque-token",
            "realm": "paygate",
            "request": "request-payload-token",
        },
        "payload": {"preimage": ZERO_PREIMAGE},
        "source": "unit-test",
    }
    assert decoded["challenge"]["request"] == "request-payload-token"


def test_build_payment_authorization_is_deterministic() -> None:
    challenge = _mpp_challenge()

    assert build_authorization(challenge, ZERO_PREIMAGE) == build_authorization(
        challenge, ZERO_PREIMAGE
    )


def test_build_payment_authorization_falls_back_to_original_request_string() -> None:
    challenge = PaymentChallenge(
        id="challenge-123",
        realm="paygate",
        method="mpp",
        request="request-payload-token",
        invoice="lnbc1test",
        amount_sats=123,
        payment_hash=None,
    )

    decoded, _, _ = _decode_payment_authorization(
        build_authorization(challenge, ZERO_PREIMAGE)
    )

    assert decoded["challenge"]["request"] == "request-payload-token"
    assert "source" not in decoded


@pytest.mark.parametrize(
    "challenge",
    [
        L402Challenge(token="abc", macaroon=None, invoice="lnbc1test"),
        _mpp_challenge(),
    ],
)
@pytest.mark.parametrize("preimage", ["", "00", "g" * 64, "0" * 63, "0" * 65])
def test_build_authorization_rejects_malformed_preimage(
    challenge: L402Challenge | PaymentChallenge,
    preimage: str,
) -> None:
    with pytest.raises(InvalidPreimageError):
        build_authorization(challenge, preimage)


def test_build_authorization_rejects_unsupported_protocol() -> None:
    with pytest.raises(UnsupportedCredentialProtocolError):
        build_authorization(object(), ZERO_PREIMAGE)  # type: ignore[arg-type]


def test_credential_error_subclasses_share_base_type() -> None:
    assert issubclass(InvalidPreimageError, CredentialError)
    assert issubclass(InvalidCredentialTokenError, CredentialError)
    assert issubclass(MissingCredentialTokenError, CredentialError)
    assert issubclass(UnsupportedCredentialProtocolError, CredentialError)
