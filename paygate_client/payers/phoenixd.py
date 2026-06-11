"""Phoenixd payer backend."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import httpx

from paygate_client.config import PhoenixdConfig
from paygate_client.payers.base import (
    AbstractPayer,
    BackendUnavailableError,
    FeeLimitUnsupportedError,
    PayerError,
    PaymentChallenge,
    PaymentRejectedError,
    RawPaymentResult,
)


class PhoenixdAuthError(PaymentRejectedError):
    """Raised when Phoenixd rejects HTTP Basic authentication."""


class PhoenixdTimeoutError(BackendUnavailableError):
    """Raised when Phoenixd does not answer before the request timeout."""


class PhoenixdMalformedResponseError(PayerError):
    """Raised when Phoenixd returns an unexpected response shape."""


class PhoenixdPayer(AbstractPayer):
    """Payer backend for Phoenixd's HTTP API."""

    def __init__(
        self,
        *,
        url: str,
        password: str,
        client: httpx.Client | None = None,
        timeout: float = 30.0,
        fee_limit_parameter: str | None = None,
    ) -> None:
        self._url = url.rstrip("/")
        self._password = password
        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None
        self._fee_limit_parameter = fee_limit_parameter
        self.supports_max_fee_limit = fee_limit_parameter is not None

    @classmethod
    def from_config(
        cls,
        config: PhoenixdConfig,
        *,
        env: Mapping[str, str] | None = None,
        client: httpx.Client | None = None,
        timeout: float = 30.0,
        fee_limit_parameter: str | None = None,
    ) -> PhoenixdPayer:
        return cls(
            url=config.url,
            password=config.resolve_password(env),
            client=client,
            timeout=timeout,
            fee_limit_parameter=fee_limit_parameter,
        )

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def _pay_invoice(
        self, challenge: PaymentChallenge, *, max_fee_sats: int
    ) -> RawPaymentResult:
        if self._fee_limit_parameter is None:
            raise FeeLimitUnsupportedError(
                "configured Phoenixd API cannot enforce max_fee_sats before payment"
            )

        form_data = {
            "invoice": challenge.invoice,
            "amountSat": str(challenge.amount_sats),
            self._fee_limit_parameter: str(max_fee_sats),
        }
        try:
            response = self._client.post(
                f"{self._url}/payinvoice",
                data=form_data,
                auth=httpx.BasicAuth("phoenix-cli", self._password),
            )
        except httpx.TimeoutException as exc:
            raise PhoenixdTimeoutError(
                "Phoenixd timed out while paying invoice"
            ) from exc
        except httpx.TransportError as exc:
            raise BackendUnavailableError("Phoenixd is unreachable") from exc

        if response.status_code in {401, 403}:
            raise PhoenixdAuthError("Phoenixd rejected authentication")
        if response.status_code >= 400:
            raise PaymentRejectedError(
                f"Phoenixd rejected payment with HTTP {response.status_code}"
            )

        payload = _response_json(response)
        response_type = payload.get("type")
        if response_type == "payment_failed":
            reason = payload.get("reason")
            if isinstance(reason, str) and reason:
                raise PaymentRejectedError(f"Phoenixd rejected payment: {reason}")
            raise PaymentRejectedError("Phoenixd rejected payment")
        if response_type not in {None, "payment_sent"}:
            raise PhoenixdMalformedResponseError(
                f"Phoenixd returned unexpected response type {response_type!r}"
            )

        return RawPaymentResult(
            amount_sats=_required_int(payload, "recipientAmountSat"),
            fee_sats=_required_int(payload, "routingFeeSat"),
            payment_hash=_optional_str(payload, "paymentHash"),
            preimage_hex=_optional_str(payload, "paymentPreimage")
            or _optional_str(payload, "preimage"),
        )


def _response_json(response: httpx.Response) -> Mapping[str, Any]:
    try:
        payload = response.json()
    except ValueError as exc:
        raise PhoenixdMalformedResponseError(
            "Phoenixd returned non-JSON response"
        ) from exc
    if not isinstance(payload, dict):
        raise PhoenixdMalformedResponseError("Phoenixd response must be a JSON object")
    return payload


def _required_int(payload: Mapping[str, Any], key: str) -> int:
    value = payload.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise PhoenixdMalformedResponseError(
            f"Phoenixd response missing integer field {key!r}"
        )
    if value < 0:
        raise PhoenixdMalformedResponseError(
            f"Phoenixd response field {key!r} must be non-negative"
        )
    return value


def _optional_str(payload: Mapping[str, Any], key: str) -> str | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise PhoenixdMalformedResponseError(
            f"Phoenixd response field {key!r} must be a string"
        )
    return value
