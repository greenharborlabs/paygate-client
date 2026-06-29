"""Backend diagnostics for configured payer integrations."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, cast

from paygate_client.config import (
    ConfigError,
    MissingSecretError,
    PaygateConfig,
    load_config,
    load_config_env,
)
from paygate_client.invoices import payment_hash_from_invoice
from paygate_client.orchestrator import payer_from_config
from paygate_client.payers.base import (
    BackendUnavailableError,
    FeeLimitError,
    FeeLimitUnsupportedError,
    MissingPreimageError,
    Payer,
    PayerError,
    PaymentChallenge,
    PaymentRejectedError,
    PaymentResult,
    PreimageVerificationError,
    RawPaymentResult,
    verify_payment_result,
)
from paygate_client.redaction import redact_error_envelope

PayerFactory = Callable[[PaygateConfig], Payer]

_REDACTED_PREIMAGE = "[REDACTED_PREIMAGE]"


def backend_doctor(
    config_path: str | Path,
    *,
    env: Mapping[str, str] | None = None,
    payer_factory: PayerFactory = payer_from_config,
) -> dict[str, Any]:
    """Validate configured payer backend compatibility."""

    try:
        loaded_env = load_config_env(config_path, env=env)
        config = load_config(config_path, env=loaded_env)
        payer = (
            payer_from_config(config, env=loaded_env)
            if payer_factory is payer_from_config
            else payer_factory(config)
        )
        supports_max_fee_limit = bool(getattr(payer, "supports_max_fee_limit", False))
        if not supports_max_fee_limit:
            return _error(
                "PAYER_BACKEND_UNSUPPORTED_FEE_LIMIT",
                "selected payer backend cannot enforce max_fee_sats before payment",
                backend=config.payer.backend,
            )
        return _redact(
            {
                "ok": True,
                "backend": config.payer.backend,
                "configValid": True,
                "envSecretsAvailable": True,
                "capabilities": {
                    "preimageRequired": True,
                    "maxFeeLimitSupported": supports_max_fee_limit,
                },
            }
        )
    except MissingSecretError as exc:
        return _error("PAYGATE_SECRET_MISSING", str(exc))
    except ConfigError as exc:
        return _error("PAYGATE_CONFIG_INVALID", str(exc))
    except Exception as exc:
        return _error("PAYER_BACKEND_SELECTION_FAILED", str(exc))


def backend_pay_invoice(
    bolt11: str,
    *,
    config_path: str | Path,
    max_fee_sats: int,
    env: Mapping[str, str] | None = None,
    payer_factory: PayerFactory = payer_from_config,
) -> dict[str, Any]:
    """Pay a standalone BOLT11 invoice through the configured payer backend."""

    try:
        loaded_env = load_config_env(config_path, env=env)
        config = load_config(config_path, env=loaded_env)
        payer = (
            payer_from_config(config, env=loaded_env)
            if payer_factory is payer_from_config
            else payer_factory(config)
        )
        invoice_payment_hash = payment_hash_from_invoice(bolt11)
        challenge = PaymentChallenge(
            invoice=bolt11,
            payment_hash=invoice_payment_hash,
            amount_sats=0,
            local_synthetic=invoice_payment_hash is None,
        )
        result = _pay_and_verify(payer, challenge, max_fee_sats=max_fee_sats)
        return _redact(
            {
                "ok": True,
                "backend": config.payer.backend,
                "payment": {
                    "amountSats": result.amount_sats,
                    "feeSats": result.fee_sats,
                    "paymentHash": result.payment_hash,
                    "preimage": _REDACTED_PREIMAGE,
                },
                "preimageVerified": True,
                "verificationSource": (
                    "invoice"
                    if challenge.payment_hash is not None
                    else "backend-result"
                ),
            }
        )
    except MissingSecretError as exc:
        return _error("PAYGATE_SECRET_MISSING", str(exc))
    except ConfigError as exc:
        return _error("PAYGATE_CONFIG_INVALID", str(exc))
    except MissingPreimageError as exc:
        return _error("PAYER_BACKEND_MISSING_PREIMAGE", str(exc))
    except PreimageVerificationError as exc:
        return _error("PAYER_BACKEND_PREIMAGE_VERIFICATION_FAILED", str(exc))
    except FeeLimitUnsupportedError as exc:
        return _error("PAYER_BACKEND_UNSUPPORTED_FEE_LIMIT", str(exc))
    except FeeLimitError as exc:
        return _error("PAYER_BACKEND_UNSUPPORTED_FEE_LIMIT", str(exc))
    except BackendUnavailableError as exc:
        return _error(_classify_backend_unavailable(exc), str(exc))
    except PaymentRejectedError as exc:
        return _error(_classify_payment_rejected(exc), str(exc))
    except PayerError as exc:
        return _error(_classify_payer_error(exc), str(exc))
    except ValueError as exc:
        return _error("PAYER_BACKEND_MALFORMED_RESPONSE", str(exc))
    except Exception as exc:
        return _error("PAYER_BACKEND_MALFORMED_RESPONSE", str(exc))


def _pay_and_verify(
    payer: Payer,
    challenge: PaymentChallenge,
    *,
    max_fee_sats: int,
) -> PaymentResult:
    result = payer.pay(challenge, max_fee_sats=max_fee_sats)
    if isinstance(result, PaymentResult):
        if (
            challenge.payment_hash is not None
            and result.payment_hash != challenge.payment_hash
        ):
            raise PreimageVerificationError(
                "payment result did not match invoice payment hash"
            )
        return result
    if isinstance(result, RawPaymentResult):
        return verify_payment_result(challenge, result)
    raise ValueError("payer backend returned an unsupported payment result")


def _classify_backend_unavailable(exc: BackendUnavailableError) -> str:
    name = type(exc).__name__.lower()
    message = str(exc).lower()
    if "timeout" in name or "timedout" in name:
        return "PAYER_BACKEND_TIMEOUT"
    if (
        "auth" in name
        or "macaroon" in name
        or "auth" in message
        or "macaroon" in message
        or "401" in message
        or "403" in message
    ):
        return "PAYER_BACKEND_AUTH_FAILED"
    return "PAYER_BACKEND_UNREACHABLE"


def _classify_payment_rejected(exc: PaymentRejectedError) -> str:
    name = type(exc).__name__.lower()
    message = str(exc).lower()
    if "auth" in name or "auth" in message or "401" in message or "403" in message:
        return "PAYER_BACKEND_AUTH_FAILED"
    if "timeout" in name or "timed out" in message or "timedout" in message:
        return "PAYER_BACKEND_TIMEOUT"
    if "malformed" in name:
        return "PAYER_BACKEND_MALFORMED_RESPONSE"
    return "PAYER_BACKEND_PAYMENT_REJECTED"


def _classify_payer_error(exc: PayerError) -> str:
    name = type(exc).__name__.lower()
    if "malformed" in name:
        return "PAYER_BACKEND_MALFORMED_RESPONSE"
    if "timeout" in name:
        return "PAYER_BACKEND_TIMEOUT"
    return "PAYER_BACKEND_PAYMENT_REJECTED"


def _error(
    code: str,
    message: str,
    *,
    backend: str | None = None,
) -> dict[str, Any]:
    envelope: dict[str, Any] = {
        "ok": False,
        "error": {
            "code": code,
            "message": message,
        },
    }
    if backend is not None:
        envelope["backend"] = backend
    return _redact(envelope)


def _redact(envelope: dict[str, Any]) -> dict[str, Any]:
    return cast(dict[str, Any], redact_error_envelope(envelope, redact_invoices=True))
