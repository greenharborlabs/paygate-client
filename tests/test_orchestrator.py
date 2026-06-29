from __future__ import annotations

import base64
import json
import time
from hashlib import sha256
from typing import Any

import httpx

from paygate_client.config import (
    EnvRef,
    LndConfig,
    PayerConfig,
    PaygateConfig,
    PhoenixdConfig,
    PolicyConfig,
    ProtocolConfig,
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
from paygate_client.session_cache import (
    CachedCredential,
    CredentialScope,
    MemoryCredentialCache,
    build_policy_hash,
    build_request_key,
)

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
    service: str = "orders",
    test_preimage: str | None = None,
    receipt: str | None = None,
) -> str:
    request = _b64url_json(
        {
            "invoice": "lnbc1test",
            "amountSats": amount_sats,
            "methodDetails": {"paymentHash": payment_hash},
            "service": service,
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


def _l402_header(invoice: str = "lnbc1l402") -> str:
    return f'L402 token="tok_123", invoice="{invoice}", version="1"'


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


def _l402_config(*, max_request_sats: int = 100) -> PaygateConfig:
    return PaygateConfig(
        payer=PayerConfig(backend="test-mode"),
        policy=PolicyConfig(
            max_request_sats=max_request_sats,
            max_fee_sats=7,
            daily_budget_sats=100,
            allowed_hosts=("example.test:443",),
            allowed_services=("orders",),
        ),
        protocol=ProtocolConfig(preferred="L402", allow_l402=True),
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


def test_missing_test_preimage_invokes_configured_real_payer(tmp_path) -> None:
    payer = RecordingPayer()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("authorization") is None:
            return httpx.Response(402, headers={"WWW-Authenticate": _payment_header()})
        return httpx.Response(200, json={"paid": True})

    config = PaygateConfig(
        payer=PayerConfig(backend="lnd-rest"),
        policy=_base_policy(),
        protocol=ProtocolConfig(preferred="Payment"),
        lnd=LndConfig(
            rest_url_env=EnvRef("LND_REST_URL"),
            macaroon_hex_env=SecretRef("LND_MACAROON_HEX"),
        ),
    )

    envelope = request_with_paygate(
        PaygateRequest("GET", "https://example.test/resource"),
        config=config,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        payer=payer,
        policy_engine=PolicyEngine(
            config.policy,
            ledger=DailySpendLedger(tmp_path / "ledger.json"),
        ),
    )

    assert envelope["ok"] is True
    assert envelope["paid"] is True
    assert envelope["payerBackend"] == "lnd-rest"
    assert payer.calls == [7]


def test_missing_test_preimage_with_test_mode_fails_before_retry(tmp_path) -> None:
    request_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal request_count
        request_count += 1
        return httpx.Response(402, headers={"WWW-Authenticate": _payment_header()})

    envelope = request_with_paygate(
        PaygateRequest("GET", "https://example.test/resource"),
        config=_config(),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        policy_engine=_engine(tmp_path),
    )

    assert envelope["ok"] is False
    assert envelope["error"]["code"] == "missing_preimage"
    assert request_count == 1


def test_l402_request_retries_with_l402_authorization_and_commits(tmp_path) -> None:
    payer = RecordingPayer()
    authorizations: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        authorizations.append(request.headers.get("authorization"))
        if len(authorizations) == 1:
            return httpx.Response(
                402,
                headers={"WWW-Authenticate": _l402_header()},
                json={"amountSats": 25, "test_preimage": PREIMAGE},
            )
        return httpx.Response(200, json={"paid": True})

    engine = PolicyEngine(
        _l402_config().policy,
        ledger=DailySpendLedger(tmp_path / "ledger.json"),
    )
    envelope = request_with_paygate(
        PaygateRequest("GET", "https://example.test/resource"),
        config=_l402_config(),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        payer=payer,
        policy_engine=engine,
    )

    assert envelope["ok"] is True
    assert envelope["paid"] is True
    assert envelope["protocol"] == "L402"
    assert envelope["amountSats"] == 25
    assert envelope["feeSats"] == 0
    assert envelope["paymentHash"] == PAYMENT_HASH
    assert payer.calls == []
    assert authorizations == [None, f"L402 tok_123:{PREIMAGE}"]
    assert engine.ledger.spent_today() == 25


def test_l402_uses_invoice_amount_before_policy_check(tmp_path) -> None:
    invoice_with_25_sats = "lnbc250n1l402qqqqqq"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("authorization") is None:
            return httpx.Response(
                402,
                headers={"WWW-Authenticate": _l402_header(invoice_with_25_sats)},
                json={"test_preimage": PREIMAGE},
            )
        return httpx.Response(200, json={"paid": True})

    envelope = request_with_paygate(
        PaygateRequest("GET", "https://example.test/resource"),
        config=_l402_config(max_request_sats=24),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        payer=RecordingPayer(),
        policy_engine=PolicyEngine(
            _l402_config(max_request_sats=24).policy,
            ledger=DailySpendLedger(tmp_path / "ledger.json"),
        ),
    )

    assert envelope["ok"] is False
    assert envelope["error"]["code"] == "policy_denied"
    assert "25 sats exceeds" in envelope["error"]["message"]


def test_l402_without_amount_is_rejected_before_payer(tmp_path) -> None:
    payer = RecordingPayer()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            402,
            headers={"WWW-Authenticate": _l402_header()},
            json={"test_preimage": PREIMAGE},
        )

    envelope = request_with_paygate(
        PaygateRequest("GET", "https://example.test/resource"),
        config=_l402_config(),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        payer=payer,
        policy_engine=PolicyEngine(
            _l402_config().policy,
            ledger=DailySpendLedger(tmp_path / "ledger.json"),
        ),
    )

    assert envelope["ok"] is False
    assert envelope["error"]["code"] == "unsupported_402_challenge"
    assert "amount" in envelope["error"]["message"]
    assert payer.calls == []


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


def test_host_denial_does_not_call_payer(tmp_path) -> None:
    payer = RecordingPayer()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(402, headers={"WWW-Authenticate": _payment_header()})

    envelope = request_with_paygate(
        PaygateRequest("GET", "https://blocked.test/resource"),
        config=_config(),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        payer=payer,
        policy_engine=_engine(tmp_path),
    )

    assert envelope["ok"] is False
    assert envelope["error"]["code"] == "policy_denied"
    assert "host" in envelope["error"]["message"]
    assert payer.calls == []


def test_service_denial_does_not_call_payer(tmp_path) -> None:
    payer = RecordingPayer()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            402,
            headers={"WWW-Authenticate": _payment_header(service="billing")},
        )

    envelope = request_with_paygate(
        PaygateRequest("GET", "https://example.test/resource"),
        config=_config(),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        payer=payer,
        policy_engine=_engine(tmp_path),
    )

    assert envelope["ok"] is False
    assert envelope["error"]["code"] == "policy_denied"
    assert "service" in envelope["error"]["message"]
    assert payer.calls == []


def test_daily_budget_denial_does_not_call_payer(tmp_path) -> None:
    payer = RecordingPayer()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(402, headers={"WWW-Authenticate": _payment_header()})

    config = PaygateConfig(
        payer=PayerConfig(backend="test-mode"),
        policy=PolicyConfig(
            max_request_sats=100,
            max_fee_sats=7,
            daily_budget_sats=24,
            allowed_hosts=("example.test:443",),
            allowed_services=("orders",),
        ),
        protocol=ProtocolConfig(preferred="Payment"),
    )
    envelope = request_with_paygate(
        PaygateRequest("GET", "https://example.test/resource"),
        config=config,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        payer=payer,
        policy_engine=PolicyEngine(
            config.policy,
            ledger=DailySpendLedger(tmp_path / "ledger.json"),
        ),
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


def test_no_pay_returns_challenge_without_invoking_payer(tmp_path) -> None:
    payer = RecordingPayer()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(402, headers={"WWW-Authenticate": _payment_header()})

    envelope = request_with_paygate(
        PaygateRequest("GET", "https://example.test/resource"),
        config=_config(),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        payer=payer,
        policy_engine=_engine(tmp_path),
        no_pay=True,
    )

    assert envelope["ok"] is True
    assert envelope["paid"] is False
    assert envelope["wouldPay"] is True
    assert envelope["amountSats"] == 25
    assert envelope["service"] == "orders"
    assert payer.calls == []


def test_cached_credential_is_used_before_payment(tmp_path) -> None:
    payer = RecordingPayer()
    request = PaygateRequest("GET", "https://example.test/resource")
    authorization = "Payment cached"
    scope = CredentialScope(
        request_key=build_request_key(request.method, request.url, request.body),
        origin_host="example.test:443",
        service="orders",
        protocol="Payment",
        payer_backend="test-mode",
        policy_hash=build_policy_hash(_config().policy),
    )
    cache = MemoryCredentialCache(
        [
            CachedCredential(
                credential_id="cred_123",
                scope=scope,
                authorization=authorization,
                created_at=int(time.time()),
                expires_at=4102444800,
            )
        ]
    )
    authorizations: list[str | None] = []

    def handler(http_request: httpx.Request) -> httpx.Response:
        authorizations.append(http_request.headers.get("authorization"))
        return httpx.Response(200, json={"cached": True})

    envelope = request_with_paygate(
        request,
        config=_config(),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        payer=payer,
        policy_engine=_engine(tmp_path),
        session_cache=cache,
    )

    assert envelope["ok"] is True
    assert envelope["paid"] is False
    assert envelope["credentialCache"]["hit"] is True
    assert envelope["response"]["json"] == {"cached": True}
    assert authorizations == [authorization]
    assert payer.calls == []
    assert cache.list()[0].use_count == 1


def test_payment_caches_credential_for_follow_up_request(tmp_path) -> None:
    cache = MemoryCredentialCache()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("authorization") is None:
            return httpx.Response(402, headers={"WWW-Authenticate": _payment_header()})
        return httpx.Response(200, json={"paid": True})

    envelope = request_with_paygate(
        PaygateRequest("GET", "https://example.test/resource"),
        config=_config(),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        payer=RecordingPayer(),
        policy_engine=_engine(tmp_path),
        session_cache=cache,
    )

    assert envelope["ok"] is True
    assert envelope["paid"] is True
    cached = cache.list()
    assert len(cached) == 1
    assert cached[0].authorization.startswith("Payment ")
    assert cached[0].scope.service == "orders"


def test_rejected_cached_credential_is_evicted_then_payment_runs(tmp_path) -> None:
    request = PaygateRequest("GET", "https://example.test/resource")
    scope = CredentialScope(
        request_key=build_request_key(request.method, request.url, request.body),
        origin_host="example.test:443",
        service="orders",
        protocol="Payment",
        payer_backend="test-mode",
        policy_hash=build_policy_hash(_config().policy),
    )
    cache = MemoryCredentialCache(
        [
            CachedCredential(
                credential_id="cred_123",
                scope=scope,
                authorization="Payment stale",
                created_at=int(time.time()),
                expires_at=4102444800,
            )
        ]
    )
    authorizations: list[str | None] = []

    def handler(http_request: httpx.Request) -> httpx.Response:
        authorization = http_request.headers.get("authorization")
        authorizations.append(authorization)
        if authorization == "Payment stale":
            return httpx.Response(402, headers={"WWW-Authenticate": _payment_header()})
        if authorization is None:
            return httpx.Response(402, headers={"WWW-Authenticate": _payment_header()})
        return httpx.Response(200, json={"paid": True})

    envelope = request_with_paygate(
        request,
        config=_config(),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        payer=RecordingPayer(),
        policy_engine=_engine(tmp_path),
        session_cache=cache,
    )

    assert envelope["ok"] is True
    assert envelope["paid"] is True
    assert authorizations[0] == "Payment stale"
    assert authorizations[1] is None
    assert authorizations[2] is not None
    assert authorizations[2] != "Payment stale"
    assert len(cache.list()) == 1
    assert cache.list()[0].credential_id != "cred_123"


def test_refresh_credential_bypasses_cache(tmp_path) -> None:
    request = PaygateRequest("GET", "https://example.test/resource")
    scope = CredentialScope(
        request_key=build_request_key(request.method, request.url, request.body),
        origin_host="example.test:443",
        service="orders",
        protocol="Payment",
        payer_backend="test-mode",
        policy_hash=build_policy_hash(_config().policy),
    )
    cache = MemoryCredentialCache(
        [
            CachedCredential(
                credential_id="cred_123",
                scope=scope,
                authorization="Payment cached",
                created_at=int(time.time()),
                expires_at=4102444800,
            )
        ]
    )
    authorizations: list[str | None] = []

    def handler(http_request: httpx.Request) -> httpx.Response:
        authorizations.append(http_request.headers.get("authorization"))
        if len(authorizations) == 1:
            return httpx.Response(402, headers={"WWW-Authenticate": _payment_header()})
        return httpx.Response(200, json={"paid": True})

    envelope = request_with_paygate(
        request,
        config=_config(),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        payer=RecordingPayer(),
        policy_engine=_engine(tmp_path),
        session_cache=cache,
        refresh_credential=True,
    )

    assert envelope["ok"] is True
    assert envelope["paid"] is True
    assert authorizations[0] is None


def test_trace_sink_receives_key_events(tmp_path) -> None:
    events: list[str] = []

    class RecordingTrace:
        def emit(self, event: str, **fields: Any) -> None:
            events.append(event)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("authorization") is None:
            return httpx.Response(402, headers={"WWW-Authenticate": _payment_header()})
        return httpx.Response(200, json={"paid": True})

    envelope = request_with_paygate(
        PaygateRequest("GET", "https://example.test/resource"),
        config=_config(),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        payer=RecordingPayer(),
        policy_engine=_engine(tmp_path),
        trace_sink=RecordingTrace(),
    )

    assert envelope["ok"] is True
    assert "request.start" in events
    assert "challenge.received" in events
    assert "payment.succeeded" in events
    assert "retry.succeeded" in events
