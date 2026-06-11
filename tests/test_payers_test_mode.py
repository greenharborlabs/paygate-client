from __future__ import annotations

from hashlib import sha256

import pytest

from paygate_client.payers import (
    AbstractPayer,
    FeeLimitUnsupportedError,
    MissingPreimageError,
    PaymentChallenge,
    PaymentResult,
    PreimageVerificationError,
    RawPaymentResult,
    TestModePayer,
    verify_payment_result,
)


def _hash_preimage(preimage_hex: str) -> str:
    return sha256(bytes.fromhex(preimage_hex)).hexdigest()


def test_payment_result_normalizes_uppercase_preimage_hex() -> None:
    preimage = "AB" * 32

    result = PaymentResult(
        amount_sats=100,
        fee_sats=1,
        payment_hash=_hash_preimage(preimage),
        preimage_hex=preimage,
    )

    assert result.preimage_hex == preimage.lower()


@pytest.mark.parametrize("preimage", ["", "aa", "zz" * 32])
def test_payment_result_rejects_missing_malformed_or_non_hex_preimage(
    preimage: str,
) -> None:
    expected_error = (
        MissingPreimageError if preimage == "" else PreimageVerificationError
    )

    with pytest.raises(expected_error):
        PaymentResult(
            amount_sats=100,
            fee_sats=1,
            payment_hash="00" * 32,
            preimage_hex=preimage,
        )


def test_test_mode_payer_uses_test_preimage() -> None:
    preimage = "11" * 32
    challenge = PaymentChallenge(
        invoice="lnbc1test",
        payment_hash=_hash_preimage(preimage),
        amount_sats=250,
        test_preimage=preimage.upper(),
    )

    result = TestModePayer().pay(challenge, max_fee_sats=0)

    assert result.amount_sats == 250
    assert result.fee_sats == 0
    assert result.payment_hash == challenge.payment_hash
    assert result.preimage_hex == preimage


def test_test_mode_payer_rejects_missing_preimage_for_non_synthetic_challenge() -> None:
    challenge = PaymentChallenge(
        invoice="lnbc1test",
        payment_hash="00" * 32,
        amount_sats=250,
    )

    with pytest.raises(MissingPreimageError):
        TestModePayer().pay(challenge, max_fee_sats=0)


def test_payer_layer_raises_missing_preimage_for_backend_response() -> None:
    class MissingPreimagePayer(AbstractPayer):
        supports_max_fee_limit = True

        def _pay_invoice(
            self, challenge: PaymentChallenge, *, max_fee_sats: int
        ) -> RawPaymentResult:
            return RawPaymentResult(
                amount_sats=challenge.amount_sats,
                fee_sats=0,
                payment_hash=challenge.payment_hash,
                preimage_hex=None,
            )

    challenge = PaymentChallenge(
        invoice="lnbc1test",
        payment_hash="00" * 32,
        amount_sats=250,
    )

    with pytest.raises(MissingPreimageError):
        MissingPreimagePayer().pay(challenge, max_fee_sats=0)


def test_payer_layer_raises_preimage_verification_error_for_wrong_preimage() -> None:
    challenge = PaymentChallenge(
        invoice="lnbc1test",
        payment_hash=_hash_preimage("22" * 32),
        amount_sats=250,
        test_preimage="33" * 32,
    )

    with pytest.raises(PreimageVerificationError):
        TestModePayer().pay(challenge, max_fee_sats=0)


def test_pay_fails_closed_on_real_challenge_without_authoritative_hash() -> None:
    class RealPayer(AbstractPayer):
        supports_max_fee_limit = True

        def __init__(self) -> None:
            self.submitted = False

        def _pay_invoice(
            self, challenge: PaymentChallenge, *, max_fee_sats: int
        ) -> RawPaymentResult:
            self.submitted = True
            raise AssertionError("must not submit invoice")

    payer = RealPayer()
    challenge = PaymentChallenge(
        invoice="lnbc1real",
        payment_hash=None,
        amount_sats=250,
    )

    with pytest.raises(PreimageVerificationError):
        payer.pay(challenge, max_fee_sats=0)

    assert payer.submitted is False


def test_verify_payment_result_rejects_missing_hash_for_real_challenge() -> None:
    challenge = PaymentChallenge(
        invoice="lnbc1real",
        payment_hash=None,
        amount_sats=250,
    )

    with pytest.raises(PreimageVerificationError):
        verify_payment_result(
            challenge,
            RawPaymentResult(
                amount_sats=challenge.amount_sats,
                fee_sats=0,
                payment_hash=None,
                preimage_hex="00" * 32,
            ),
        )


def test_real_backends_inherit_abstract_payer() -> None:
    for backend in (TestModePayer,):
        assert issubclass(backend, AbstractPayer)


def test_backend_returned_payment_hash_must_match_challenge_hash() -> None:
    class WrongHashPayer(AbstractPayer):
        supports_max_fee_limit = True

        def _pay_invoice(
            self, challenge: PaymentChallenge, *, max_fee_sats: int
        ) -> RawPaymentResult:
            preimage = "44" * 32
            return RawPaymentResult(
                amount_sats=challenge.amount_sats,
                fee_sats=0,
                payment_hash="55" * 32,
                preimage_hex=preimage,
            )

    challenge = PaymentChallenge(
        invoice="lnbc1test",
        payment_hash=_hash_preimage("44" * 32),
        amount_sats=250,
    )

    with pytest.raises(PreimageVerificationError):
        WrongHashPayer().pay(challenge, max_fee_sats=0)


def test_real_backend_without_fee_enforcement_refuses_before_submission() -> None:
    class UnsafeRealPayer(AbstractPayer):
        supports_max_fee_limit = False

        def __init__(self) -> None:
            self.submitted = False

        def _pay_invoice(
            self, challenge: PaymentChallenge, *, max_fee_sats: int
        ) -> RawPaymentResult:
            self.submitted = True
            raise AssertionError("must not submit invoice")

    payer = UnsafeRealPayer()
    challenge = PaymentChallenge(
        invoice="lnbc1real",
        payment_hash="00" * 32,
        amount_sats=250,
    )

    with pytest.raises(FeeLimitUnsupportedError):
        payer.pay(challenge, max_fee_sats=1)

    assert payer.submitted is False


def test_missing_max_fee_limit_never_submits_invoice() -> None:
    class RealPayer(AbstractPayer):
        supports_max_fee_limit = True

        def __init__(self) -> None:
            self.submitted = False

        def _pay_invoice(
            self, challenge: PaymentChallenge, *, max_fee_sats: int
        ) -> RawPaymentResult:
            self.submitted = True
            raise AssertionError("must not submit invoice")

    payer = RealPayer()
    challenge = PaymentChallenge(
        invoice="lnbc1real",
        payment_hash="00" * 32,
        amount_sats=250,
    )

    with pytest.raises(TypeError):
        payer.pay(challenge)  # type: ignore[call-arg]

    assert payer.submitted is False


def test_test_mode_local_synthetic_fallback_is_deterministic() -> None:
    challenge = PaymentChallenge(
        invoice="local-test-invoice",
        payment_hash=None,
        amount_sats=10,
        local_synthetic=True,
    )

    first = TestModePayer().pay(challenge, max_fee_sats=0)
    second = TestModePayer().pay(challenge, max_fee_sats=0)

    assert first == second
    assert first.payment_hash == _hash_preimage(first.preimage_hex)
