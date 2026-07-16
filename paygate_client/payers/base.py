"""Shared payer interfaces and payment result validation."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any, Protocol


class PayerError(Exception):
    """Base class for payer failures."""


class PaymentRejectedError(PayerError):
    """Raised when a payer backend rejects a payment."""


class BackendUnavailableError(PayerError):
    """Raised when a payer backend cannot be reached or used."""


class MissingPreimageError(PayerError):
    """Raised when a paid invoice does not return a preimage."""


class PreimageVerificationError(PayerError):
    """Raised when a returned preimage cannot prove the selected challenge."""


class FeeLimitError(PayerError):
    """Raised when the fee limit is missing or invalid."""


class FeeLimitUnsupportedError(FeeLimitError):
    """Raised when a backend cannot enforce a fee limit before payment."""


@dataclass(frozen=True)
class PaymentChallenge:
    """Normalized payment input supplied by challenge parsers."""

    invoice: str
    payment_hash: str | None
    amount_sats: int
    service: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    test_preimage: str | None = None
    local_synthetic: bool = False

    def __post_init__(self) -> None:
        if not self.invoice:
            raise ValueError("payment challenge invoice is required")
        if self.amount_sats < 0:
            raise ValueError("payment challenge amount_sats must be non-negative")
        if self.payment_hash is not None:
            object.__setattr__(
                self,
                "payment_hash",
                normalize_payment_hash(self.payment_hash, field_name="payment_hash"),
            )


@dataclass(frozen=True)
class PaymentResult:
    """Normalized successful payment proof returned by payer backends."""

    amount_sats: int
    fee_sats: int
    payment_hash: str
    preimage_hex: str

    def __post_init__(self) -> None:
        if self.amount_sats < 0:
            raise ValueError("payment result amount_sats must be non-negative")
        if self.fee_sats < 0:
            raise ValueError("payment result fee_sats must be non-negative")
        payment_hash = normalize_payment_hash(
            self.payment_hash, field_name="payment_hash"
        )
        preimage_hex = normalize_preimage(self.preimage_hex)
        if hash_preimage(preimage_hex) != payment_hash:
            raise PreimageVerificationError(
                "payment result preimage does not hash to payment_hash"
            )
        object.__setattr__(self, "payment_hash", payment_hash)
        object.__setattr__(self, "preimage_hex", preimage_hex)


@dataclass(frozen=True)
class RawPaymentResult:
    """Untrusted backend response before central normalization and verification."""

    amount_sats: int
    fee_sats: int
    payment_hash: str | None = None
    preimage_hex: str | None = None


class Payer(Protocol):
    """Protocol implemented by all payer backends."""

    def pay(self, challenge: PaymentChallenge, *, max_fee_sats: int) -> PaymentResult:
        """Pay a challenge invoice and return a verified payment proof."""


class AbstractPayer(ABC):
    """Base payer that enforces fee and preimage verification invariants."""

    supports_max_fee_limit = False

    def check_ready(self) -> None:
        """Validate local backend prerequisites without submitting payment."""

        return None

    def pay(self, challenge: PaymentChallenge, *, max_fee_sats: int) -> PaymentResult:
        self._ensure_fee_limit(max_fee_sats)
        if challenge.payment_hash is None and not challenge.local_synthetic:
            raise PreimageVerificationError(
                "payment challenge did not include an authoritative payment_hash"
            )
        raw_result = self._pay_invoice(challenge, max_fee_sats=max_fee_sats)
        return verify_payment_result(challenge, raw_result)

    def _ensure_fee_limit(self, max_fee_sats: int) -> None:
        if max_fee_sats is None:
            raise FeeLimitError("max_fee_sats is required")
        if max_fee_sats < 0:
            raise FeeLimitError("max_fee_sats must be non-negative")
        if not self.supports_max_fee_limit:
            raise FeeLimitUnsupportedError(
                "selected payer backend cannot enforce max_fee_sats before payment"
            )

    @abstractmethod
    def _pay_invoice(
        self, challenge: PaymentChallenge, *, max_fee_sats: int
    ) -> RawPaymentResult:
        """Submit the invoice to the backend and return its raw response."""


def normalize_preimage(preimage_hex: str | None) -> str:
    if preimage_hex is None or preimage_hex == "":
        raise MissingPreimageError("payer backend did not return a payment preimage")
    if len(preimage_hex) != 64:
        raise PreimageVerificationError("payment preimage must be 32 bytes")
    try:
        bytes.fromhex(preimage_hex)
    except ValueError as exc:
        raise PreimageVerificationError("payment preimage must be hex") from exc
    return preimage_hex.lower()


def normalize_payment_hash(payment_hash: str, *, field_name: str) -> str:
    if len(payment_hash) != 64:
        raise PreimageVerificationError(f"{field_name} must be 32 bytes")
    try:
        bytes.fromhex(payment_hash)
    except ValueError as exc:
        raise PreimageVerificationError(f"{field_name} must be hex") from exc
    return payment_hash.lower()


def hash_preimage(preimage_hex: str) -> str:
    normalized = normalize_preimage(preimage_hex)
    return sha256(bytes.fromhex(normalized)).hexdigest()


def verify_payment_result(
    challenge: PaymentChallenge,
    raw_result: RawPaymentResult,
) -> PaymentResult:
    preimage_hex = normalize_preimage(raw_result.preimage_hex)
    computed_payment_hash = hash_preimage(preimage_hex)

    expected_payment_hash = challenge.payment_hash
    if expected_payment_hash is None:
        if not challenge.local_synthetic:
            raise PreimageVerificationError(
                "payment challenge did not include an authoritative payment_hash"
            )
        expected_payment_hash = computed_payment_hash

    expected_payment_hash = normalize_payment_hash(
        expected_payment_hash, field_name="challenge payment_hash"
    )

    if computed_payment_hash != expected_payment_hash:
        raise PreimageVerificationError(
            "payment preimage does not hash to the selected challenge payment_hash"
        )

    if raw_result.payment_hash is not None:
        backend_payment_hash = normalize_payment_hash(
            raw_result.payment_hash, field_name="backend payment_hash"
        )
        if backend_payment_hash != expected_payment_hash:
            raise PreimageVerificationError(
                "backend payment_hash does not match selected challenge payment_hash"
            )

    return PaymentResult(
        amount_sats=raw_result.amount_sats,
        fee_sats=raw_result.fee_sats,
        payment_hash=expected_payment_hash,
        preimage_hex=preimage_hex,
    )
