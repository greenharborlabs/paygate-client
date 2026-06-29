from __future__ import annotations

import json
from hashlib import sha256

import pytest

from paygate_client.diagnostics import backend_doctor, backend_pay_invoice
from paygate_client.payers.base import (
    BackendUnavailableError,
    FeeLimitUnsupportedError,
    MissingPreimageError,
    PaymentChallenge,
    PaymentRejectedError,
    PaymentResult,
    PreimageVerificationError,
    RawPaymentResult,
)

_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _config_file(tmp_path) -> str:
    path = tmp_path / "paygate.yaml"
    path.write_text(
        "\n".join(
            [
                "payer:",
                "  backend: test-mode",
                "policy:",
                "  max_request_sats: 100",
                "  max_fee_sats: 7",
                "  daily_budget_sats: 100",
                "  allowed_hosts:",
                "    - example.test:443",
                "  allowed_services:",
                "    - orders",
                "protocol:",
                "  preferred: Payment",
            ]
        ),
        encoding="utf-8",
    )
    return str(path)


def _invalid_config_file(tmp_path) -> str:
    path = tmp_path / "invalid-paygate.yaml"
    path.write_text(
        "\n".join(
            [
                "payer:",
                "  backend: unsupported",
                "policy:",
                "  max_request_sats: 100",
                "  max_fee_sats: 7",
                "  daily_budget_sats: 100",
                "  allowed_hosts:",
                "    - example.test:443",
                "  allowed_services:",
                "    - orders",
            ]
        ),
        encoding="utf-8",
    )
    return str(path)


def _lnd_config_file(tmp_path) -> str:
    path = tmp_path / "lnd-paygate.yaml"
    path.write_text(
        "\n".join(
            [
                "payer:",
                "  backend: lnd-rest",
                "policy:",
                "  max_request_sats: 100",
                "  max_fee_sats: 7",
                "  daily_budget_sats: 100",
                "  allowed_hosts:",
                "    - example.test:443",
                "  allowed_services:",
                "    - orders",
                "lnd:",
                "  rest_url_env: LND_REST_URL",
                "  macaroon_hex_env: LND_MACAROON_HEX",
            ]
        ),
        encoding="utf-8",
    )
    return str(path)


def _hash_preimage(preimage_hex: str) -> str:
    return sha256(bytes.fromhex(preimage_hex)).hexdigest()


def _bolt11_with_payment_hash(payment_hash: str) -> str:
    data = [0] * 7
    payment_hash_words = _convert_bits(list(bytes.fromhex(payment_hash)), 8, 5)
    data.extend([_BECH32_CHARSET.index("p"), 1, 20])
    data.extend(payment_hash_words)
    data.extend([0] * 6)
    return "lnbc1" + "".join(_BECH32_CHARSET[index] for index in data)


def _convert_bits(data: list[int], from_bits: int, to_bits: int) -> list[int]:
    accumulator = 0
    bits = 0
    result: list[int] = []
    max_value = (1 << to_bits) - 1
    for value in data:
        accumulator = (accumulator << from_bits) | value
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            result.append((accumulator >> bits) & max_value)
    if bits:
        result.append((accumulator << (to_bits - bits)) & max_value)
    return result


class RecordingPayer:
    supports_max_fee_limit = True

    def __init__(self, result: PaymentResult | None = None) -> None:
        self.result = result
        self.challenge: PaymentChallenge | None = None
        self.max_fee_sats: int | None = None

    def pay(self, challenge: PaymentChallenge, *, max_fee_sats: int) -> PaymentResult:
        self.challenge = challenge
        self.max_fee_sats = max_fee_sats
        if self.result is None:
            raise MissingPreimageError("backend did not return a preimage")
        return self.result


class ExceptionPayer:
    supports_max_fee_limit = True

    def __init__(self, exc: Exception) -> None:
        self.exc = exc

    def pay(self, challenge: PaymentChallenge, *, max_fee_sats: int) -> PaymentResult:
        raise self.exc


class RawResultPayer:
    supports_max_fee_limit = True

    def __init__(self, result: RawPaymentResult) -> None:
        self.result = result

    def pay(
        self, challenge: PaymentChallenge, *, max_fee_sats: int
    ) -> RawPaymentResult:
        return self.result


class InvalidMacaroonError(BackendUnavailableError):
    pass


class BackendTimeoutError(BackendUnavailableError):
    pass


def test_backend_doctor_reports_preimage_support(tmp_path) -> None:
    payer = RecordingPayer()

    envelope = backend_doctor(
        _config_file(tmp_path),
        payer_factory=lambda config: payer,
    )

    assert envelope["ok"] is True
    assert envelope["backend"] == "test-mode"
    assert envelope["capabilities"] == {
        "preimageRequired": True,
        "maxFeeLimitSupported": True,
    }


def test_backend_pay_invoice_reports_verified_preimage_and_redacts(tmp_path) -> None:
    preimage = "11" * 32
    payer = RecordingPayer(
        PaymentResult(
            amount_sats=123,
            fee_sats=2,
            payment_hash=_hash_preimage(preimage),
            preimage_hex=preimage,
        )
    )

    envelope = backend_pay_invoice(
        "lnbc1diagnostic",
        config_path=_config_file(tmp_path),
        max_fee_sats=5,
        payer_factory=lambda config: payer,
    )

    assert envelope["ok"] is True
    assert envelope["preimageVerified"] is True
    assert envelope["payment"]["preimage"] == "[REDACTED_SECRET]"
    assert preimage not in json.dumps(envelope)
    assert payer.challenge == PaymentChallenge(
        invoice="lnbc1diagnostic",
        payment_hash=None,
        amount_sats=0,
        local_synthetic=True,
    )
    assert payer.max_fee_sats == 5


def test_backend_pay_invoice_verifies_against_invoice_payment_hash(tmp_path) -> None:
    preimage = "22" * 32
    payment_hash = _hash_preimage(preimage)
    bolt11 = _bolt11_with_payment_hash(payment_hash)
    payer = RecordingPayer(
        PaymentResult(
            amount_sats=321,
            fee_sats=1,
            payment_hash=payment_hash,
            preimage_hex=preimage,
        )
    )

    envelope = backend_pay_invoice(
        bolt11,
        config_path=_config_file(tmp_path),
        max_fee_sats=5,
        payer_factory=lambda config: payer,
    )

    assert envelope["ok"] is True
    assert envelope["verificationSource"] == "invoice"
    assert payer.challenge is not None
    assert payer.challenge.payment_hash == payment_hash
    assert payer.challenge.local_synthetic is False


def test_backend_pay_invoice_missing_preimage_is_distinct_failure(tmp_path) -> None:
    envelope = backend_pay_invoice(
        "lnbc1diagnostic",
        config_path=_config_file(tmp_path),
        max_fee_sats=5,
        payer_factory=lambda config: RecordingPayer(),
    )

    assert envelope["ok"] is False
    assert envelope["error"]["code"] == "PAYER_BACKEND_MISSING_PREIMAGE"


def test_backend_doctor_invalid_config_is_distinct_failure(tmp_path) -> None:
    envelope = backend_doctor(_invalid_config_file(tmp_path))

    assert envelope["ok"] is False
    assert envelope["error"]["code"] == "PAYGATE_CONFIG_INVALID"


def test_backend_doctor_missing_env_secret_is_distinct_failure(tmp_path) -> None:
    envelope = backend_doctor(_lnd_config_file(tmp_path), env={})

    assert envelope["ok"] is False
    assert envelope["error"]["code"] == "PAYGATE_SECRET_MISSING"


def test_backend_doctor_loads_script_generated_companion_env_file(tmp_path) -> None:
    config_path = _lnd_config_file(tmp_path)
    (tmp_path / "voltage-env.sh").write_text(
        "\n".join(
            [
                'export LND_REST_URL="https://node.m.voltageapp.io:8080"',
                'export LND_MACAROON_HEX="00aa"',
            ]
        ),
        encoding="utf-8",
    )

    envelope = backend_doctor(config_path, env={})

    assert envelope["ok"] is True
    assert envelope["backend"] == "lnd-rest"


@pytest.mark.parametrize(
    ("exc", "expected_code"),
    [
        (
            BackendUnavailableError("connection refused"),
            "PAYER_BACKEND_UNREACHABLE",
        ),
        (
            InvalidMacaroonError("LND macaroon must be hex encoded"),
            "PAYER_BACKEND_AUTH_FAILED",
        ),
        (
            PaymentRejectedError("backend rejected payment"),
            "PAYER_BACKEND_PAYMENT_REJECTED",
        ),
        (
            BackendTimeoutError("backend timed out"),
            "PAYER_BACKEND_TIMEOUT",
        ),
        (
            FeeLimitUnsupportedError("fee limit cannot be enforced"),
            "PAYER_BACKEND_UNSUPPORTED_FEE_LIMIT",
        ),
        (
            ValueError("backend returned malformed JSON"),
            "PAYER_BACKEND_MALFORMED_RESPONSE",
        ),
        (
            PreimageVerificationError("payment preimage mismatch"),
            "PAYER_BACKEND_PREIMAGE_VERIFICATION_FAILED",
        ),
    ],
)
def test_backend_pay_invoice_distinct_exception_failures(
    tmp_path, exc: Exception, expected_code: str
) -> None:
    envelope = backend_pay_invoice(
        "lnbc1diagnostic",
        config_path=_config_file(tmp_path),
        max_fee_sats=5,
        payer_factory=lambda config: ExceptionPayer(exc),
    )

    assert envelope["ok"] is False
    assert envelope["error"]["code"] == expected_code


def test_backend_pay_invoice_raw_result_verification_failure_is_distinct(
    tmp_path,
) -> None:
    expected_preimage = "33" * 32
    different_preimage = "44" * 32
    bolt11 = _bolt11_with_payment_hash(_hash_preimage(expected_preimage))

    envelope = backend_pay_invoice(
        bolt11,
        config_path=_config_file(tmp_path),
        max_fee_sats=5,
        payer_factory=lambda config: RawResultPayer(
            RawPaymentResult(
                amount_sats=1,
                fee_sats=1,
                preimage_hex=different_preimage,
            )
        ),
    )

    assert envelope["ok"] is False
    assert envelope["error"]["code"] == "PAYER_BACKEND_PREIMAGE_VERIFICATION_FAILED"


def test_backend_pay_invoice_unsupported_result_is_malformed_response(
    tmp_path,
) -> None:
    class UnsupportedResultPayer:
        supports_max_fee_limit = True

        def pay(self, challenge: PaymentChallenge, *, max_fee_sats: int) -> object:
            return object()

    envelope = backend_pay_invoice(
        "lnbc1diagnostic",
        config_path=_config_file(tmp_path),
        max_fee_sats=5,
        payer_factory=lambda config: UnsupportedResultPayer(),
    )

    assert envelope["ok"] is False
    assert envelope["error"]["code"] == "PAYER_BACKEND_MALFORMED_RESPONSE"
