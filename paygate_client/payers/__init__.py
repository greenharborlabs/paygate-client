"""Payer backend interfaces and implementations."""

from paygate_client.payers.base import (
    AbstractPayer,
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
    hash_preimage,
    normalize_payment_hash,
    normalize_preimage,
    verify_payment_result,
)
from paygate_client.payers.breez import BreezPayer
from paygate_client.payers.test_mode import TestModePayer

__all__ = [
    "AbstractPayer",
    "BackendUnavailableError",
    "BreezPayer",
    "FeeLimitError",
    "FeeLimitUnsupportedError",
    "MissingPreimageError",
    "PaymentChallenge",
    "PaymentRejectedError",
    "PaymentResult",
    "Payer",
    "PayerError",
    "PreimageVerificationError",
    "RawPaymentResult",
    "TestModePayer",
    "hash_preimage",
    "normalize_payment_hash",
    "normalize_preimage",
    "verify_payment_result",
]
