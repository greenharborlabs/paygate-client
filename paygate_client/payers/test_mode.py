"""Deterministic payer backend for Paygate test challenges."""

from __future__ import annotations

from hashlib import sha256

from paygate_client.payers.base import (
    AbstractPayer,
    MissingPreimageError,
    PaymentChallenge,
    RawPaymentResult,
    hash_preimage,
)


class TestModePayer(AbstractPayer):
    """Local-only payer for challenges that carry test preimages."""

    supports_max_fee_limit = True

    def _pay_invoice(
        self, challenge: PaymentChallenge, *, max_fee_sats: int
    ) -> RawPaymentResult:
        del max_fee_sats

        if challenge.test_preimage:
            preimage_hex = challenge.test_preimage
            payment_hash = hash_preimage(preimage_hex)
        elif challenge.local_synthetic:
            preimage_hex = _synthetic_preimage(challenge)
            payment_hash = hash_preimage(preimage_hex)
        else:
            raise MissingPreimageError(
                "test-mode requires test_preimage unless local_synthetic is true"
            )

        return RawPaymentResult(
            amount_sats=challenge.amount_sats,
            fee_sats=0,
            payment_hash=payment_hash,
            preimage_hex=preimage_hex,
        )


def _synthetic_preimage(challenge: PaymentChallenge) -> str:
    seed = (
        f"paygate-client:test-mode:{challenge.invoice}:"
        f"{challenge.amount_sats}:{challenge.service or ''}"
    )
    return sha256(seed.encode("utf-8")).hexdigest()
