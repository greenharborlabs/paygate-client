"""Breez SDK Spark payer backend."""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Mapping
from pathlib import Path
from types import ModuleType
from typing import Any, cast

from paygate_client.config import BreezConfig, MissingSecretError
from paygate_client.payers.base import (
    AbstractPayer,
    BackendUnavailableError,
    MissingPreimageError,
    PaymentChallenge,
    PaymentRejectedError,
    RawPaymentResult,
)


class BreezError(Exception):
    """Base class for Breez payer failures."""


class BreezDependencyError(BackendUnavailableError, BreezError):
    """Raised when the optional Breez SDK dependency is not installed."""


class BreezAuthError(BackendUnavailableError, BreezError):
    """Raised when required Breez credentials are missing."""


class BreezBackendUnavailableError(BackendUnavailableError, BreezError):
    """Raised when Breez SDK cannot connect or sync."""


class BreezFeeLimitExceededError(PaymentRejectedError, BreezError):
    """Raised when Breez quotes or reports fees above Paygate policy."""


class BreezPaymentRejectedError(PaymentRejectedError, BreezError):
    """Raised when Breez rejects the payment."""


class BreezMalformedResponseError(PaymentRejectedError, BreezError):
    """Raised when Breez returns an unsupported response shape."""


class BreezMissingPreimageError(MissingPreimageError, BreezError):
    """Raised when Breez reports success without a Lightning preimage."""


class BreezPayer(AbstractPayer):
    """Sync payer wrapper around Breez SDK Spark's async API."""

    supports_max_fee_limit = True

    def __init__(
        self,
        config: BreezConfig,
        *,
        env: Mapping[str, str] | None = None,
        sdk_module: ModuleType | Any | None = None,
    ) -> None:
        try:
            self._api_key = config.resolve_api_key(env)
            self._mnemonic = config.resolve_mnemonic(env)
        except MissingSecretError as exc:
            raise BreezAuthError("Breez API key and mnemonic are required") from exc
        self._network = config.network
        self._storage_dir = str(Path(config.storage_dir).expanduser())
        self._completion_timeout_secs = config.completion_timeout_secs
        self._sdk_module = sdk_module

    def _pay_invoice(
        self, challenge: PaymentChallenge, *, max_fee_sats: int
    ) -> RawPaymentResult:
        _ensure_no_running_loop()
        return cast(
            RawPaymentResult,
            _run_sync(self._pay_invoice_async(challenge, max_fee_sats=max_fee_sats)),
        )

    async def _pay_invoice_async(
        self, challenge: PaymentChallenge, *, max_fee_sats: int
    ) -> RawPaymentResult:
        breez = self._load_sdk()
        Path(self._storage_dir).mkdir(parents=True, exist_ok=True)

        config = breez.default_config(network=_network_value(breez, self._network))
        config.api_key = self._api_key
        seed = breez.Seed.MNEMONIC(mnemonic=self._mnemonic, passphrase=None)

        sdk = None
        try:
            sdk = await breez.connect(
                request=breez.ConnectRequest(
                    config=config,
                    seed=seed,
                    storage_dir=self._storage_dir,
                )
            )
            prepare_response = await sdk.prepare_send_payment(
                request=breez.PrepareSendPaymentRequest(
                    payment_request=breez.PaymentRequest.INPUT(input=challenge.invoice),
                    amount=None,
                    token_identifier=None,
                    conversion_options=None,
                    fee_policy=None,
                )
            )
            lightning_fee_sats = _prepared_lightning_fee_sats(prepare_response)
            if lightning_fee_sats > max_fee_sats:
                raise BreezFeeLimitExceededError(
                    "Breez quoted Lightning fee "
                    f"{lightning_fee_sats} sats above max_fee_sats "
                    f"{max_fee_sats}; payment was not submitted"
                )

            send_response = await sdk.send_payment(
                request=breez.SendPaymentRequest(
                    prepare_response=prepare_response,
                    options=breez.SendPaymentOptions.BOLT11_INVOICE(
                        prefer_spark=False,
                        completion_timeout_secs=self._completion_timeout_secs,
                    ),
                    idempotency_key=str(uuid.uuid4()),
                )
            )
        except BreezError:
            raise
        except Exception as exc:
            raise BreezPaymentRejectedError(str(exc)) from exc
        finally:
            if sdk is not None:
                await sdk.disconnect()

        payment = _required_attr(send_response, "payment")
        fee_sats = _required_int(payment, "fees")
        if fee_sats > max_fee_sats:
            raise BreezFeeLimitExceededError(
                "Breez final Lightning fee "
                f"{fee_sats} sats exceeded max_fee_sats {max_fee_sats}"
            )

        return RawPaymentResult(
            amount_sats=_required_int(payment, "amount"),
            fee_sats=fee_sats,
            payment_hash=_find_first_string(payment, "payment_hash"),
            preimage_hex=_find_first_string(payment, "preimage")
            or _raise_missing_preimage(),
        )

    def _load_sdk(self) -> ModuleType | Any:
        if self._sdk_module is not None:
            return self._sdk_module
        try:
            import breez_sdk_spark as breez  # type: ignore[import-untyped]
        except ImportError as exc:
            raise BreezDependencyError(
                "Install Breez support first: python -m pip install "
                "'paygate-client[breez]'"
            ) from exc
        return breez


def _run_sync(coro: Any) -> Any:
    return asyncio.run(coro)


def _ensure_no_running_loop() -> None:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return
    raise BreezBackendUnavailableError(
        "Breez payer cannot run inside an active asyncio event loop"
    )


def _network_value(breez: Any, network_name: str) -> Any:
    attr = network_name.upper()
    if hasattr(breez.Network, attr):
        return getattr(breez.Network, attr)
    raise BreezMalformedResponseError(f"Breez SDK does not expose network {attr}")


def _prepared_lightning_fee_sats(prepare_response: Any) -> int:
    payment_method = _required_attr(prepare_response, "payment_method")
    if not bool(_call_optional(payment_method, "is_BOLT11_INVOICE")):
        raise BreezMalformedResponseError(
            "Breez prepare_send_payment did not return a BOLT11 payment method"
        )
    return _required_int(payment_method, "lightning_fee_sats")


def _required_attr(value: Any, name: str) -> Any:
    candidate = getattr(value, name, None)
    if candidate is None:
        raise BreezMalformedResponseError(f"Breez response missing {name}")
    return candidate


def _required_int(value: Any, name: str) -> int:
    candidate = _required_attr(value, name)
    if isinstance(candidate, bool) or not isinstance(candidate, int):
        raise BreezMalformedResponseError(f"Breez response field {name} must be int")
    if candidate < 0:
        raise BreezMalformedResponseError(
            f"Breez response field {name} must be non-negative"
        )
    return cast(int, candidate)


def _call_optional(value: Any, name: str) -> object:
    method = getattr(value, name, None)
    if method is None:
        return None
    return method()


def _find_first_string(root: Any, field_name: str) -> str | None:
    seen: set[int] = set()
    stack = [root]
    while stack:
        value = stack.pop()
        if id(value) in seen:
            continue
        seen.add(id(value))
        candidate = getattr(value, field_name, None)
        if isinstance(candidate, str) and candidate:
            return candidate
        if isinstance(value, dict):
            dict_candidate = value.get(field_name)
            if isinstance(dict_candidate, str) and dict_candidate:
                return dict_candidate
            stack.extend(value.values())
        elif not isinstance(value, (str, bytes, int, float, bool, type(None))):
            stack.extend(vars(value).values() if hasattr(value, "__dict__") else [])
    return None


def _raise_missing_preimage() -> str:
    raise BreezMissingPreimageError(
        "Breez reported payment success, but no usable Lightning preimage was "
        "returned. Ensure prefer_spark=false and the payment completed over "
        "Lightning."
    )
