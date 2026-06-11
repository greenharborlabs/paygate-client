from __future__ import annotations

import base64
import json
from hashlib import sha256
from typing import Any

import httpx

from paygate_client.config import (
    EnvRef,
    LndConfig,
    PaygateConfig,
    PayerConfig,
    PolicyConfig,
    ProtocolConfig,
    PhoenixdConfig,
    SecretRef,
)
from paygate_client.credentials import CredentialError
from paygate_client.ledger import DailySpendLedger
from paygate_client.orchestrator import (
    PaygateRequest,
    payer_from_config,
    request_with_paygate,
)
from paygate_client.payers import AbstractPayer, RawPaymentResult, TestModePayer
from paygate_client.payers.lnd_rest import LndRestPayer
from paygate_client.payers.phoenixd import PhoenixdPayer
from paygate_client.policy import PolicyEngine


PREIMAGE = "11" * 32
PAYMENT_HASH = sha256(bytes.fromhex(PREIMAGE)).hexdigest()


class RecordingPayer(AbstractPayer):
    supports_max_fee_limit = True

    def __init__(self, *, preimage: str | None = PREIMAGE) -> None:
        self.calls: list[int] = []
        self.preimage = preimage

    def _pay_invoice(
        self,
        challenge: Any,
        *,
        max_fee_sats: int,
    ) -> RawPaymentResult:
        self.calls.append(max_fee_sats)
        return RawPaymentResult(
            amount_sats=challenge.amount_sats,
            fee_sats=2,
            payment_hash=challenge.payment_hash,
            preimage_hex=self.preimage,
        )


def _b64url_json(payload: object) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _payment_header(
    *,
    amount_sats: int = 25,
    payment_hash: str = PAYMENT_HASH,
    test_preimage: str | None = None,
    receipt: str | None = None,
) -> str:
    request = _b64url_json(
        {
            "invoice": "lnbc1test",
            "amountSats": amount_sats,
            "methodDetails": {"paymentHash": payment_hash},
            "service": "orders",
        }
    )
    opaque = ""
    opaque_payload = {}
    if test_preimage is not None:
        opaque_payload["test_preimage"] = test_preimage
    if receipt is not None:
        opaque_payload["receipt"] = receipt
    if opaque_payload:
        opaque = f', opaque="{_b64url_json(opaque_payload)}"'
    return (
        'Payment id="pay_123", realm="orders", method="lightning", '
        f'request="{request}", expires=4102444800{opaque}'
    )


def _config(*, max_request_sats: int = 100) -> PaygateConfig:
    return PaygateConfig(
        payer=PayerConfig(backend="test-mode"),
        policy=PolicyConfig(
            max_request_sats=max_request_sats,
            max_fee_sats=7,
            daily_budget_sats=100,
            allowed_hosts=("example.test:443",),
            allowed_services=("orders",),
        ),
        protocol=ProtocolConfig(preferred="Payment"),
    )


def _base_policy() -> PolicyConfig:
    return PolicyConfig(
        max_request_sats=100,
        max_fee_sats=7,
        daily_budget_sats=100,
        allowed_hosts=("example.test:443",),
        allowed_services=("orders",),
    )


def _engine(tmp_path, *, max_request_sats: int = 100) -> PolicyEngine:
    return PolicyEngine(
        _config(max_request_sats=max_request_sats).policy,
        ledger=DailySpendLedger(tmp_path / "ledger.json"),
    )


def test_payer_from_config_constructs_test_mode() -> None:
    payer = payer_from_config(_config())

    assert isinstance(payer, TestModePayer)


def test_payer_from_config_constructs_phoenixd_safe_default(monkeypatch) -> None:
    monkeypatch.setenv("PHOENIXD_PASSWORD", "secret")
    config = PaygateConfig(
        payer=PayerConfig(backend="phoenixd"),
        policy=_base_policy(),
        protocol=ProtocolConfig(preferred="Payment"),
        phoenixd=PhoenixdConfig(
            url="http://phoenixd.test",
            password_env=SecretRef("PHOENIXD_PASSWORD"),
        ),
    )

    payer = payer_from_config(config)

    assert isinstance(payer, PhoenixdPayer)
    assert payer.supports_max_fee_limit is False
    payer.close()


def test_payer_from_config_passes_configured_phoenixd_fee_limit_parameter(
    monkeypatch,
) -> None:
    monkeypatch.setenv("PHOENIXD_PASSWORD", "secret")
    config = PaygateConfig(
        payer=PayerConfig(backend="phoenixd"),
        policy=_base_policy(),
        protocol=ProtocolConfig(preferred="Payment"),
        phoenixd=PhoenixdConfig(
            url="http://phoenixd.test",
            password_env=SecretRef("PHOENIXD_PASSWORD"),
            fee_limit_parameter="maxFeeSat",
        ),
    )

    payer = payer_from_config(config)

    assert isinstance(payer, PhoenixdPayer)
    assert payer.supports_max_fee_limit is True
    payer.close()


def test_payer_from_config_constructs_lnd_rest(monkeypatch) -> None:
    monkeypatch.setenv("LND_REST_URL", "https://lnd.test:8080")
    monkeypatch.setenv("LND_MACAROON_HEX", "00")
    config = PaygateConfig(
        payer=PayerConfig(backend="lnd-rest"),
        policy=_base_policy(),
        protocol=ProtocolConfig(preferred="Payment"),
        lnd=LndConfig(
            rest_url_env=EnvRef("LND_REST_URL"),
            macaroon_hex_env=SecretRef("LND_MACAROON_HEX"),
        ),
    )

    payer = payer_from_config(config)

    assert isinstance(payer, LndRestPayer)
    assert payer.supports_max_fee_limit is True


def test_paid_request_retries_with_payment_authorization_and_commits(tmp_path) -> None:
    payer = RecordingPayer()
    seen_authorizations: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_authorizations.append(request.headers.get("authorization"))
        if len(seen_authorizations) == 1:
            return httpx.Response(
                402,
                headers={"WWW-Authenticate": _payment_header()},
                json={"error": "payment required"},
            )
        return httpx.Response(200, json={"ok": True})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    engine = _engine(tmp_path)

    envelope = request_with_paygate(
        PaygateRequest("GET", "https://example.test/resource"),
        config=_config(),
        client=client,
        payer=payer,
        policy_engine=engine,
    )

    assert envelope["ok"] is True
    assert envelope["paid"] is True
    assert envelope["protocol"] == "Payment"
    assert envelope["payerBackend"] == "test-mode"
    assert envelope["amountSats"] == 25
    assert envelope["feeSats"] == 2
    assert envelope["paymentHash"] == PAYMENT_HASH
    assert envelope["response"]["json"] == {"ok": True}
    assert payer.calls == [7]
    assert seen_authorizations == [None, seen_authorizations[1]]
    assert seen_authorizations[1] is not None
    assert seen_authorizations[1].startswith("Payment ")
    assert engine.ledger.spent_today() == 25


def test_test_mode_preimage_from_mpp_opaque_skips_external_payer(tmp_path) -> None:
    payer = RecordingPayer()
    authorizations: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        authorizations.append(request.headers.get("authorization"))
        if len(authorizations) == 1:
            return httpx.Response(
                402,
                headers={"WWW-Authenticate": _payment_header(test_preimage=PREIMAGE)},
            )
        return httpx.Response(200, json={"paid": True})

    envelope = request_with_paygate(
        PaygateRequest("GET", "https://example.test/resource"),
        config=_config(),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        payer=payer,
        policy_engine=_engine(tmp_path),
    )

    assert envelope["ok"] is True
    assert envelope["paid"] is True
    assert payer.calls == []
    assert authorizations[1] is not None
    assert authorizations[1].startswith("Payment ")


def test_policy_denial_does_not_call_payer(tmp_path) -> None:
    payer = RecordingPayer()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(402, headers={"WWW-Authenticate": _payment_header()})

    envelope = request_with_paygate(
        PaygateRequest("GET", "https://example.test/resource"),
        config=_config(max_request_sats=1),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        payer=payer,
        policy_engine=_engine(tmp_path, max_request_sats=1),
    )

    assert envelope["ok"] is False
    assert envelope["error"]["code"] == "policy_denied"
    assert payer.calls == []


def test_preimage_hash_mismatch_does_not_retry(tmp_path) -> None:
    payer = RecordingPayer(preimage="22" * 32)
    request_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal request_count
        request_count += 1
        return httpx.Response(402, headers={"WWW-Authenticate": _payment_header()})

    envelope = request_with_paygate(
        PaygateRequest("GET", "https://example.test/resource"),
        config=_config(),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        payer=payer,
        policy_engine=_engine(tmp_path),
    )

    assert envelope["ok"] is False
    assert envelope["error"]["code"] == "preimage_verification_failed"
    assert request_count == 1


def test_real_paid_retry_rejection_keeps_committed_spend(tmp_path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("authorization") is None:
            return httpx.Response(402, headers={"WWW-Authenticate": _payment_header()})
        return httpx.Response(500, json={"error": "still blocked"})

    engine = _engine(tmp_path)
    envelope = request_with_paygate(
        PaygateRequest("GET", "https://example.test/resource"),
        config=_config(),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        payer=RecordingPayer(),
        policy_engine=engine,
    )

    assert envelope["ok"] is False
    assert envelope["error"]["code"] == "paid_retry_rejected"
    assert engine.ledger.spent_today() == 25


def test_real_paid_credential_failure_keeps_committed_spend(
    monkeypatch, tmp_path
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(402, headers={"WWW-Authenticate": _payment_header()})

    def fail_authorization(*args, **kwargs):
        raise CredentialError("credential build failed")

    monkeypatch.setattr(
        "paygate_client.orchestrator.build_authorization",
        fail_authorization,
    )
    engine = _engine(tmp_path)

    envelope = request_with_paygate(
        PaygateRequest("GET", "https://example.test/resource"),
        config=_config(),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        payer=RecordingPayer(),
        policy_engine=engine,
    )

    assert envelope["ok"] is False
    assert envelope["paid"] is True
    assert envelope["error"]["code"] == "credential_failure"
    assert engine.ledger.spent_today() == 25


def test_test_preimage_retry_rejection_rolls_back_uninvoked_payer_spend(
    tmp_path,
) -> None:
    payer = RecordingPayer()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("authorization") is None:
            return httpx.Response(
                402,
                headers={"WWW-Authenticate": _payment_header(test_preimage=PREIMAGE)},
            )
        return httpx.Response(500, json={"error": "still blocked"})

    engine = _engine(tmp_path)
    envelope = request_with_paygate(
        PaygateRequest("GET", "https://example.test/resource"),
        config=_config(),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        payer=payer,
        policy_engine=engine,
    )

    assert envelope["ok"] is False
    assert envelope["error"]["code"] == "paid_retry_rejected"
    assert payer.calls == []
    assert engine.ledger.spent_today() == 0


def test_configured_payer_factory_failure_returns_error_envelope() -> None:
    config = PaygateConfig(
        payer=PayerConfig(backend="phoenixd"),
        policy=_base_policy(),
        protocol=ProtocolConfig(preferred="Payment"),
        phoenixd=None,
    )

    envelope = request_with_paygate(
        PaygateRequest("GET", "https://example.test/resource"),
        config=config,
        client=httpx.Client(transport=httpx.MockTransport(lambda request: None)),
    )

    assert envelope["ok"] is False
    assert envelope["paid"] is False
    assert envelope["error"]["code"] == "payer_configuration_failed"


def test_success_paid_redacts_untrusted_receipt(tmp_path) -> None:
    secret_receipt = f"receipt:{PREIMAGE}"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("authorization") is None:
            return httpx.Response(
                402,
                headers={"WWW-Authenticate": _payment_header(receipt=secret_receipt)},
            )
        return httpx.Response(200, json={"ok": True})

    envelope = request_with_paygate(
        PaygateRequest("GET", "https://example.test/resource"),
        config=_config(),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        payer=RecordingPayer(),
        policy_engine=_engine(tmp_path),
    )

    assert envelope["ok"] is True
    assert PREIMAGE not in json.dumps(envelope)
    assert envelope["receipt"] == "receipt:[REDACTED_PREIMAGE]"
