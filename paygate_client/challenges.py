"""Parsing for Paygate Payment and L402 WWW-Authenticate challenges."""

from __future__ import annotations

import base64
import binascii
import json
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Union

from paygate_client.config import ProtocolConfig


class ChallengeError(Exception):
    """Base class for typed challenge parsing failures."""


class NoSupportedChallengeError(ChallengeError):
    """Raised when no Payment or enabled L402 challenge is available."""


class MalformedHeaderError(ChallengeError):
    """Raised when a challenge header cannot be parsed as auth params."""


class MissingInvoiceError(ChallengeError):
    """Raised when a supported challenge omits the required invoice."""


class MissingTokenError(ChallengeError):
    """Raised when an L402 challenge omits both token and macaroon."""


class MissingMPPRequestError(ChallengeError):
    """Raised when a Payment challenge omits the required request payload."""


class MissingAmountError(ChallengeError):
    """Raised when a Payment request payload omits the required amount."""


class MalformedMPPRequestError(ChallengeError):
    """Raised when a Payment request payload is malformed."""


class MalformedOpaquePayloadError(ChallengeError):
    """Raised when a Payment opaque payload is malformed."""


class ExpiredChallengeError(ChallengeError):
    """Raised when a challenge is already expired."""


class ProtocolDisabledError(ChallengeError):
    """Raised when the only available protocol is disabled by config."""


@dataclass(frozen=True)
class PaymentChallenge:
    """Parsed Paygate MPP Payment challenge."""

    id: str | None
    realm: str | None
    method: str | None
    request: str
    invoice: str
    amount_sats: int
    payment_hash: str | None
    expires: int | None = None
    digest: str | None = None
    description: str | None = None
    opaque: str | None = None
    intent: str | None = None
    service: str | None = None
    method_details: Mapping[str, Any] = field(default_factory=dict)
    request_payload: Mapping[str, Any] = field(default_factory=dict)
    opaque_payload: Mapping[str, Any] | None = None
    test_preimage: str | None = None
    auth_params: Mapping[str, str] = field(default_factory=dict)
    scheme: str = "Payment"


@dataclass(frozen=True)
class L402Challenge:
    """Parsed Paygate L402 challenge."""

    token: str | None
    macaroon: str | None
    invoice: str
    version: str | None = None
    auth_params: Mapping[str, str] = field(default_factory=dict)
    scheme: str = "L402"

    @property
    def credential_token(self) -> str:
        """Return the emitted token value suitable for L402 credentials."""

        if self.token is not None:
            return self.token
        if self.macaroon is not None:
            return self.macaroon
        raise MissingTokenError("L402 challenge is missing token or macaroon")


ParsedChallenge = Union[PaymentChallenge, L402Challenge]

_SUPPORTED_SCHEMES = {"payment": "Payment", "l402": "L402"}
_KNOWN_SCHEMES = {"payment", "l402", "basic", "bearer"}


def parse_challenges(
    headers: Mapping[str, object] | Sequence[str] | Iterable[str],
    protocol_config: ProtocolConfig,
    now: datetime | int | float | None = None,
) -> ParsedChallenge:
    """Parse repeated WWW-Authenticate values and select the configured protocol."""

    parsed: list[ParsedChallenge] = []
    disabled_l402 = False
    current_time = _to_epoch_seconds(now) if now is not None else time.time()

    for header_value in _header_values(headers):
        for raw_challenge in _split_challenges(header_value):
            scheme, params = _parse_challenge(raw_challenge)
            if scheme == "Payment":
                parsed.append(_parse_payment(params, current_time))
            elif scheme == "L402":
                if not protocol_config.allow_l402:
                    disabled_l402 = True
                    continue
                parsed.append(_parse_l402(params))

    preferred = protocol_config.preferred
    for challenge in parsed:
        if challenge.scheme == preferred:
            return challenge
    for challenge in parsed:
        return challenge

    if disabled_l402:
        raise ProtocolDisabledError("L402 challenge received but L402 is disabled")
    raise NoSupportedChallengeError("response did not include a supported challenge")


def _header_values(
    headers: Mapping[str, object] | Sequence[str] | Iterable[str],
) -> tuple[str, ...]:
    if isinstance(headers, Mapping):
        for name, value in headers.items():
            if name.lower() == "www-authenticate":
                return _coerce_header_value(value)
        return ()
    return tuple(str(value) for value in headers)


def _coerce_header_value(value: object) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Iterable):
        return tuple(str(item) for item in value)
    return (str(value),)


def _split_challenges(value: str) -> tuple[str, ...]:
    segments: list[str] = []
    start = 0
    index = 0
    in_quote = False
    escaped = False
    while index < len(value):
        char = value[index]
        if escaped:
            escaped = False
        elif char == "\\" and in_quote:
            escaped = True
        elif char == '"':
            in_quote = not in_quote
        elif char == "," and not in_quote and _comma_starts_challenge(value, index):
            segment = value[start:index].strip()
            if segment:
                segments.append(segment)
            start = index + 1
        index += 1
    segment = value[start:].strip()
    if segment:
        segments.append(segment)
    return tuple(segments)


def _comma_starts_challenge(value: str, comma_index: int) -> bool:
    index = comma_index + 1
    while index < len(value) and value[index].isspace():
        index += 1
    start = index
    while index < len(value) and (value[index].isalnum() or value[index] in "-_"):
        index += 1
    token = value[start:index].lower()
    if token not in _KNOWN_SCHEMES:
        return False
    return index < len(value) and value[index].isspace()


def _parse_challenge(raw_challenge: str) -> tuple[str | None, Mapping[str, str]]:
    scheme, separator, rest = raw_challenge.partition(" ")
    normalized_scheme = _SUPPORTED_SCHEMES.get(scheme.lower())
    if normalized_scheme is None:
        return None, {}
    if not separator:
        raise MalformedHeaderError(f"{normalized_scheme} challenge is missing params")
    return normalized_scheme, _parse_auth_params(rest)


def _parse_auth_params(raw_params: str) -> Mapping[str, str]:
    params: dict[str, str] = {}
    index = 0
    while index < len(raw_params):
        while index < len(raw_params) and raw_params[index].isspace():
            index += 1
        key_start = index
        while index < len(raw_params) and (
            raw_params[index].isalnum() or raw_params[index] in "-_"
        ):
            index += 1
        key = raw_params[key_start:index]
        if not key:
            raise MalformedHeaderError("auth param key is required")
        while index < len(raw_params) and raw_params[index].isspace():
            index += 1
        if index >= len(raw_params) or raw_params[index] != "=":
            raise MalformedHeaderError(f"auth param {key!r} is missing '='")
        index += 1
        while index < len(raw_params) and raw_params[index].isspace():
            index += 1
        if index < len(raw_params) and raw_params[index] == '"':
            value, index = _parse_quoted_value(raw_params, index)
        else:
            value_start = index
            while index < len(raw_params) and raw_params[index] != ",":
                index += 1
            value = raw_params[value_start:index].strip()
            if not value:
                raise MalformedHeaderError(f"auth param {key!r} has an empty value")
            if any(char.isspace() for char in value):
                raise MalformedHeaderError(
                    f"auth param {key!r} has a malformed unquoted value"
                )
        params[key] = value
        while index < len(raw_params) and raw_params[index].isspace():
            index += 1
        if index == len(raw_params):
            break
        if raw_params[index] != ",":
            raise MalformedHeaderError("auth params must be comma-delimited")
        index += 1
    return params


def _parse_quoted_value(raw_params: str, quote_index: int) -> tuple[str, int]:
    value_chars: list[str] = []
    index = quote_index + 1
    while index < len(raw_params):
        char = raw_params[index]
        if char == "\\":
            index += 1
            if index >= len(raw_params):
                raise MalformedHeaderError("quoted auth param has trailing escape")
            value_chars.append(raw_params[index])
        elif char == '"':
            index += 1
            while index < len(raw_params) and raw_params[index].isspace():
                index += 1
            if index < len(raw_params) and raw_params[index] != ",":
                raise MalformedHeaderError("quoted auth param has trailing characters")
            return "".join(value_chars), index
        else:
            value_chars.append(char)
        index += 1
    raise MalformedHeaderError("quoted auth param is missing closing quote")


def _parse_payment(params: Mapping[str, str], now: float) -> PaymentChallenge:
    encoded_request = params.get("request")
    if encoded_request is None:
        raise MissingMPPRequestError("Payment challenge is missing request")
    request_payload = _decode_json_payload(
        encoded_request,
        MalformedMPPRequestError,
        "Payment request payload is malformed",
    )
    invoice = _string_field(request_payload, "invoice")
    if invoice is None:
        raise MissingInvoiceError("Payment request payload is missing invoice")

    amount_sats = _amount_sats_field(request_payload)

    method_details = request_payload.get("methodDetails", {})
    if not isinstance(method_details, dict):
        raise MalformedMPPRequestError("Payment methodDetails must be an object")
    payment_hash = _string_field(method_details, "paymentHash")
    if payment_hash is None:
        payment_hash = _string_field(method_details, "payment_hash")

    expires = _optional_int_param(params, "expires")
    if expires is not None and expires <= now:
        raise ExpiredChallengeError("Payment challenge is expired")

    opaque_payload = None
    test_preimage = None
    encoded_opaque = params.get("opaque")
    if encoded_opaque is not None:
        opaque_payload = _decode_json_payload(
            encoded_opaque,
            MalformedOpaquePayloadError,
            "Payment opaque payload is malformed",
        )
        test_preimage = _string_field(opaque_payload, "test_preimage")

    return PaymentChallenge(
        id=params.get("id"),
        realm=params.get("realm"),
        method=params.get("method"),
        request=encoded_request,
        invoice=invoice,
        amount_sats=amount_sats,
        payment_hash=payment_hash,
        expires=expires,
        digest=params.get("digest"),
        description=_string_field(request_payload, "description")
        or params.get("description"),
        opaque=encoded_opaque,
        intent=params.get("intent"),
        service=_string_field(request_payload, "service") or params.get("realm"),
        method_details=method_details,
        request_payload=request_payload,
        opaque_payload=opaque_payload,
        test_preimage=test_preimage,
        auth_params=dict(params),
    )


def _parse_l402(params: Mapping[str, str]) -> L402Challenge:
    invoice = params.get("invoice")
    if invoice is None:
        raise MissingInvoiceError("L402 challenge is missing invoice")
    token = params.get("token")
    macaroon = params.get("macaroon")
    if token is None and macaroon is None:
        raise MissingTokenError("L402 challenge is missing token or macaroon")
    return L402Challenge(
        token=token,
        macaroon=macaroon,
        invoice=invoice,
        version=params.get("version"),
        auth_params=dict(params),
    )


def _decode_json_payload(
    encoded: str,
    error_type: type[ChallengeError],
    message: str,
) -> Mapping[str, Any]:
    raw = _decode_base64url_nopad(encoded, error_type, message)
    try:
        decoded = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise error_type(message) from exc
    if not isinstance(decoded, dict):
        raise error_type(message)
    return decoded


def _decode_base64url_nopad(
    encoded: str,
    error_type: type[ChallengeError],
    message: str,
) -> bytes:
    if "=" in encoded:
        raise error_type(message)
    padding = "=" * (-len(encoded) % 4)
    try:
        return base64.b64decode(
            encoded + padding,
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError) as exc:
        raise error_type(message) from exc


def _string_field(source: Mapping[str, Any], key: str) -> str | None:
    value = source.get(key)
    if isinstance(value, str) and value:
        return value
    return None


def _int_field(source: Mapping[str, Any], key: str) -> int | None:
    value = source.get(key)
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    return None


def _amount_sats_field(source: Mapping[str, Any]) -> int:
    for key in ("amountSats", "amount_sats"):
        if key not in source:
            continue
        value = source[key]
        if isinstance(value, bool) or not isinstance(value, int):
            raise MalformedMPPRequestError(
                f"Payment request payload {key} must be a non-negative integer"
            )
        if value < 0:
            raise MalformedMPPRequestError(
                f"Payment request payload {key} must be non-negative"
            )
        return value
    raise MissingAmountError("Payment request payload is missing amountSats")


def _optional_int_param(params: Mapping[str, str], key: str) -> int | None:
    value = params.get(key)
    if value is None:
        return None
    try:
        return int(value)
    except ValueError as exc:
        raise MalformedHeaderError(f"auth param {key!r} must be an integer") from exc


def _to_epoch_seconds(now: datetime | int | float) -> float:
    if isinstance(now, datetime):
        return now.timestamp()
    return float(now)
