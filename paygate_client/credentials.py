"""Credential builders for Paygate authenticated retries."""

from __future__ import annotations

import base64
import json
import re
from typing import Any

from paygate_client.challenges import L402Challenge, PaymentChallenge


class CredentialError(Exception):
    """Base class for credential building failures."""


class UnsupportedCredentialProtocolError(CredentialError):
    """Raised when a challenge cannot be converted to retry credentials."""


class MissingCredentialTokenError(CredentialError):
    """Raised when an L402 challenge lacks an emitted token value."""


class InvalidPreimageError(CredentialError):
    """Raised when the supplied payment preimage is malformed."""


class InvalidCredentialTokenError(CredentialError):
    """Raised when an L402 token cannot be safely emitted in a header."""


_PREIMAGE_HEX_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def build_authorization(
    challenge: PaymentChallenge | L402Challenge,
    preimage_hex: str,
    source: str | None = None,
) -> str:
    """Build the Authorization header value for a parsed Paygate challenge."""

    if isinstance(challenge, PaymentChallenge):
        return build_payment_authorization(challenge, preimage_hex, source=source)
    if isinstance(challenge, L402Challenge):
        return build_l402_authorization(challenge, preimage_hex)
    raise UnsupportedCredentialProtocolError("unsupported credential protocol")


def build_l402_authorization(challenge: L402Challenge, preimage_hex: str) -> str:
    """Build an L402 Authorization header value."""

    preimage = _normalize_preimage(preimage_hex)
    token = challenge.token if challenge.token is not None else challenge.macaroon
    if token is None:
        raise MissingCredentialTokenError("L402 challenge is missing token or macaroon")
    _validate_l402_token(token)
    return f"L402 {token}:{preimage}"


def build_payment_authorization(
    challenge: PaymentChallenge,
    preimage_hex: str,
    source: str | None = None,
) -> str:
    """Build an MPP Payment Authorization header value."""

    preimage = _normalize_preimage(preimage_hex)
    credential: dict[str, Any] = {
        "challenge": _payment_challenge_payload(challenge),
        "payload": {"preimage": preimage},
    }
    if source is not None:
        credential["source"] = source
    encoded = _base64url_nopad(
        json.dumps(credential, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    return f"Payment {encoded}"


def _payment_challenge_payload(challenge: PaymentChallenge) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for key in (
        "id",
        "realm",
        "method",
        "intent",
        "expires",
        "digest",
        "description",
        "opaque",
    ):
        value = getattr(challenge, key)
        if value is not None:
            payload[key] = value

    payload["request"] = (
        dict(challenge.request_payload)
        if challenge.request_payload
        else challenge.request
    )
    return payload


def _normalize_preimage(preimage_hex: str) -> str:
    if not isinstance(preimage_hex, str) or _PREIMAGE_HEX_RE.fullmatch(preimage_hex) is None:
        raise InvalidPreimageError("preimage must be exactly 32 bytes of hex")
    return preimage_hex.lower()


def _validate_l402_token(token: str) -> None:
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in token):
        raise InvalidCredentialTokenError("L402 token contains control characters")
    if any(separator in token for separator in (":", ",")):
        raise InvalidCredentialTokenError("L402 token contains header separators")


def _base64url_nopad(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")
