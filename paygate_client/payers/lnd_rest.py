"""LND REST payer backend."""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from typing import Any
from urllib.parse import urljoin

import httpx

from paygate_client.config import LndConfig, MissingSecretError
from paygate_client.payers.base import (
    AbstractPayer,
    BackendUnavailableError,
    FeeLimitUnsupportedError,
    MissingPreimageError,
    PaymentChallenge,
    PaymentRejectedError,
    RawPaymentResult,
)


class LndRestError(Exception):
    """Base class for LND REST payer failures."""


class InvalidMacaroonError(BackendUnavailableError, LndRestError):
    """Raised when the configured LND macaroon is missing or not hex."""


class LndTlsCertificateError(BackendUnavailableError, LndRestError):
    """Raised when LND TLS verification or cert loading fails."""


class LndBackendUnavailableError(BackendUnavailableError, LndRestError):
    """Raised when the LND REST backend cannot be reached."""


class LndPaymentFailureError(PaymentRejectedError, LndRestError):
    """Raised when LND reports terminal payment failure."""


class LndPaymentTimeoutError(PaymentRejectedError, LndRestError):
    """Raised when LND does not report terminal payment success."""


class LndMalformedResponseError(PaymentRejectedError, LndRestError):
    """Raised when LND returns an invalid or unsupported response."""


class LndMissingPreimageError(MissingPreimageError, LndRestError):
    """Raised when LND reports success without a payment preimage."""


class LndRestPayer(AbstractPayer):
    """Sync payer for LND's REST router API."""

    supports_max_fee_limit = True

    def __init__(
        self,
        config: LndConfig,
        *,
        env: Mapping[str, str] | None = None,
        client: httpx.Client | None = None,
        timeout_seconds: float = 60.0,
    ) -> None:
        self._rest_url = config.resolve_rest_url(env).rstrip("/") + "/"
        try:
            macaroon_hex = config.resolve_macaroon_hex(env)
        except MissingSecretError as exc:
            raise InvalidMacaroonError("LND macaroon hex is required") from exc
        self._macaroon_hex = _validate_macaroon_hex(macaroon_hex)
        self._tls_cert_path = config.resolve_tls_cert_path(env)
        self._client = (
            client if client is not None else self._build_client(timeout_seconds)
        )

    def _build_client(self, timeout_seconds: float) -> httpx.Client:
        verify: bool | str = True
        if self._tls_cert_path is not None:
            verify = self._tls_cert_path
        try:
            return httpx.Client(timeout=timeout_seconds, verify=verify)
        except (OSError, httpx.HTTPError) as exc:
            raise LndTlsCertificateError(
                "LND TLS certificate configuration could not be loaded"
            ) from exc

    def _pay_invoice(
        self, challenge: PaymentChallenge, *, max_fee_sats: int
    ) -> RawPaymentResult:
        request_body = _build_send_payment_request(challenge, max_fee_sats=max_fee_sats)
        headers = {"Grpc-Metadata-macaroon": self._macaroon_hex}

        try:
            response = self._client.post(
                urljoin(self._rest_url, "v2/router/send"),
                json=request_body,
                headers=headers,
            )
            response.raise_for_status()
        except httpx.TimeoutException as exc:
            raise LndPaymentTimeoutError("LND payment request timed out") from exc
        except httpx.HTTPStatusError as exc:
            raise LndPaymentFailureError(
                f"LND REST returned HTTP {exc.response.status_code}"
            ) from exc
        except httpx.TransportError as exc:
            if _looks_like_tls_error(exc):
                raise LndTlsCertificateError(
                    "LND TLS certificate verification failed"
                ) from exc
            raise LndBackendUnavailableError("LND REST backend is unreachable") from exc

        terminal_success: Mapping[str, Any] | None = None
        for update in _iter_lnd_updates(response):
            status = _normalize_status(update.get("status"))
            if status == "SUCCEEDED":
                terminal_success = update
                break
            if status == "FAILED":
                raise LndPaymentFailureError("LND reported terminal payment failure")

        if terminal_success is None:
            raise LndPaymentTimeoutError(
                "LND did not return a terminal successful payment update"
            )

        preimage = _optional_string(terminal_success.get("payment_preimage"))
        if preimage is None:
            raise LndMissingPreimageError(
                "LND terminal payment update did not include payment_preimage"
            )

        return RawPaymentResult(
            amount_sats=_required_int(terminal_success, "value_sat"),
            fee_sats=_required_int(terminal_success, "fee_sat"),
            payment_hash=_optional_string(terminal_success.get("payment_hash")),
            preimage_hex=preimage,
        )


def _validate_macaroon_hex(macaroon_hex: str) -> str:
    if macaroon_hex == "":
        raise InvalidMacaroonError("LND macaroon hex is required")
    hex_chars = frozenset("0123456789abcdefABCDEF")
    if not all(char in hex_chars for char in macaroon_hex):
        raise InvalidMacaroonError("LND macaroon must be hex encoded")
    try:
        bytes.fromhex(macaroon_hex)
    except ValueError as exc:
        raise InvalidMacaroonError("LND macaroon must be hex encoded") from exc
    return macaroon_hex.lower()


def _build_send_payment_request(
    challenge: PaymentChallenge, *, max_fee_sats: int
) -> dict[str, object]:
    try:
        fee_limit_sat = int(max_fee_sats)
    except (TypeError, ValueError) as exc:
        raise FeeLimitUnsupportedError("LND fee_limit_sat could not be set") from exc
    if fee_limit_sat != max_fee_sats:
        raise FeeLimitUnsupportedError("LND fee_limit_sat must be an integer")
    return {
        "payment_request": challenge.invoice,
        "fee_limit_sat": fee_limit_sat,
    }


def _iter_lnd_updates(response: httpx.Response) -> Iterator[Mapping[str, Any]]:
    saw_update = False
    for line in response.iter_lines():
        if not line.strip():
            continue
        saw_update = True
        yield _decode_lnd_update(line)

    if not saw_update:
        raise LndMalformedResponseError("LND REST response did not include updates")


def _decode_lnd_update(line: str) -> Mapping[str, Any]:
    try:
        decoded = json.loads(line)
    except json.JSONDecodeError as exc:
        raise LndMalformedResponseError("LND REST returned malformed JSON") from exc
    if not isinstance(decoded, dict):
        raise LndMalformedResponseError("LND REST update must be a JSON object")

    result = decoded.get("result", decoded)
    if not isinstance(result, dict):
        raise LndMalformedResponseError("LND REST update result must be an object")
    return result


def _normalize_status(value: object) -> str:
    if isinstance(value, str):
        return value.upper()
    if isinstance(value, int):
        statuses = {
            1: "IN_FLIGHT",
            2: "SUCCEEDED",
            3: "FAILED",
        }
        return statuses.get(value, "UNKNOWN")
    return "UNKNOWN"


def _required_int(update: Mapping[str, Any], field_name: str) -> int:
    value = update.get(field_name)
    if isinstance(value, bool):
        raise LndMalformedResponseError(f"LND {field_name} must be an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError as exc:
            raise LndMalformedResponseError(
                f"LND {field_name} must be an integer"
            ) from exc
    raise LndMalformedResponseError(f"LND {field_name} is missing")


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise LndMalformedResponseError("LND string field was not a string")
    if value == "":
        return None
    return value


def _looks_like_tls_error(exc: BaseException) -> bool:
    message = str(exc).lower()
    return "ssl" in message or "certificate" in message or "cert verify" in message
