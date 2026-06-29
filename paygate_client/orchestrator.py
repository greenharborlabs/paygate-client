"""End-to-end Paygate request orchestration."""

from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from typing import Any, cast
from urllib.parse import urlsplit

import httpx

from paygate_client.challenges import (
    ChallengeError,
    MissingAmountError,
    MissingMPPRequestError,
    ParsedChallenge,
    parse_challenges,
)
from paygate_client.challenges import (
    PaymentChallenge as ParsedPaymentChallenge,
)
from paygate_client.config import PaygateConfig
from paygate_client.credentials import CredentialError, build_authorization
from paygate_client.http import (
    HttpRequest,
    PaygateHttpError,
    send_request,
    serialize_response,
)
from paygate_client.invoices import amount_sats_from_invoice, payment_hash_from_invoice
from paygate_client.payers import (
    MissingPreimageError,
    Payer,
    PayerError,
    PaymentChallenge,
    PaymentResult,
    PreimageVerificationError,
    RawPaymentResult,
    TestModePayer,
    hash_preimage,
    verify_payment_result,
)
from paygate_client.payers.lnd_rest import LndRestPayer
from paygate_client.payers.phoenixd import PhoenixdPayer
from paygate_client.policy import PolicyEngine, PolicyError, PolicyRequest
from paygate_client.redaction import redact_error_envelope
from paygate_client.session_cache import (
    DEFAULT_NAMESPACE,
    CachedCredential,
    CredentialCache,
    CredentialScope,
    NullCredentialCache,
    build_credential_id,
    build_policy_hash,
    build_request_key,
    normalize_namespace,
)
from paygate_client.trace import NullTraceSink, TraceSink


@dataclass(frozen=True)
class PaygateRequest:
    """Input accepted by ``paygate request``."""

    method: str
    url: str
    headers: Mapping[str, str] = field(default_factory=dict)
    body: str | bytes | None = None
    timeout: float | None = None


@dataclass(frozen=True)
class _PayableChallenge:
    parsed: ParsedChallenge
    invoice: str
    amount_sats: int
    payment_hash: str | None
    service: str | None
    metadata: Mapping[str, Any]
    test_preimage: str | None


def request_with_paygate(
    request: PaygateRequest,
    *,
    config: PaygateConfig,
    client: httpx.Client | None = None,
    payer: Payer | None = None,
    policy_engine: PolicyEngine | None = None,
    session_cache: CredentialCache | None = None,
    no_pay: bool = False,
    refresh_credential: bool = False,
    cache_policy: str = "challenge-defined",
    session_namespace: str | None = None,
    trace_sink: TraceSink | None = None,
) -> dict[str, Any]:
    """Run the initial request, optional payment, retry, and envelope emission."""

    owns_client = client is None
    active_client = client if client is not None else httpx.Client()
    active_cache = session_cache if session_cache is not None else NullCredentialCache()
    trace = trace_sink if trace_sink is not None else NullTraceSink()
    try:
        active_payer = payer if payer is not None else payer_from_config(config)
        engine = (
            policy_engine if policy_engine is not None else PolicyEngine(config.policy)
        )
    except Exception as exc:
        if owns_client:
            active_client.close()
        return _error("payer_configuration_failed", str(exc), paid=False)

    try:
        return _request_with_paygate(
            request,
            config=config,
            client=active_client,
            payer=active_payer,
            policy_engine=engine,
            session_cache=active_cache,
            no_pay=no_pay,
            refresh_credential=refresh_credential,
            cache_policy=cache_policy,
            session_namespace=normalize_namespace(session_namespace),
            trace_sink=trace,
        )
    finally:
        if owns_client:
            active_client.close()


def _request_with_paygate(
    request: PaygateRequest,
    *,
    config: PaygateConfig,
    client: httpx.Client,
    payer: Payer,
    policy_engine: PolicyEngine,
    session_cache: CredentialCache,
    no_pay: bool,
    refresh_credential: bool,
    cache_policy: str,
    session_namespace: str,
    trace_sink: TraceSink,
) -> dict[str, Any]:
    trace_sink.emit(
        "request.start", method=request.method, host=_host_port(request.url)
    )
    request_key = build_request_key(request.method, request.url, request.body)
    preliminary_scope = _credential_scope(
        request=request,
        config=config,
        request_key=request_key,
        protocol=config.protocol.preferred,
        service=None,
        namespace=session_namespace,
    )

    cached_credential = None
    if not no_pay and not refresh_credential:
        cached_credential = session_cache.get(preliminary_scope)
    trace_sink.emit(
        "cache.lookup",
        hit=cached_credential is not None,
        scope=request_key,
    )
    if cached_credential is not None:
        try:
            cached_response = send_request(
                client,
                _to_http_request(
                    replace(
                        request,
                        headers=_retry_headers(
                            request.headers, cached_credential.authorization
                        ),
                    )
                ),
            )
        except PaygateHttpError as exc:
            return _error("network_failure", str(exc), paid=False)
        if cached_response.status_code >= 200 and cached_response.status_code < 300:
            session_cache.mark_success(cached_credential.credential_id)
            trace_sink.emit("cache.accepted", statusCode=cached_response.status_code)
            return _success_cached(cached_response, cached_credential)
        if cached_response.status_code in (401, 402):
            session_cache.mark_rejected(cached_credential.credential_id)
            session_cache.delete(cached_credential.credential_id)
            trace_sink.emit("cache.rejected", statusCode=cached_response.status_code)
        else:
            return _error(
                "cached_credential_rejected",
                f"cached credential returned HTTP {cached_response.status_code}",
                paid=False,
                response=serialize_response(cached_response),
            )

    try:
        initial_response = send_request(client, _to_http_request(request))
    except PaygateHttpError as exc:
        return _error("network_failure", str(exc), paid=False)

    if initial_response.status_code != 402:
        return _success_unpaid(initial_response)

    try:
        challenge = _parse_challenge(initial_response, config)
    except ChallengeError as exc:
        return _error("unsupported_402_challenge", str(exc), paid=False)

    try:
        payable_challenge = _to_payable_challenge(challenge, initial_response)
    except ChallengeError as exc:
        return _error("unsupported_402_challenge", str(exc), paid=False)

    trace_sink.emit(
        "challenge.received",
        protocol=payable_challenge.parsed.scheme,
        amountSats=payable_challenge.amount_sats,
        service=payable_challenge.service,
    )

    try:
        approval = policy_engine.evaluate(
            PolicyRequest(
                host=_host_port(request.url),
                service=payable_challenge.service,
                amount_sats=payable_challenge.amount_sats,
                payer_backend=payer,
            )
        )
    except PolicyError as exc:
        return _error("policy_denied", str(exc), paid=False)

    trace_sink.emit(
        "policy.approved",
        maxFeeSats=approval.max_fee_sats,
        amountSats=payable_challenge.amount_sats,
    )

    if no_pay:
        approval.rollback()
        trace_sink.emit("payment.skipped", reason="no-pay")
        return _challenge_envelope(
            payable_challenge,
            payer_backend=config.payer.backend,
            max_fee_sats=approval.max_fee_sats,
        )

    payment_result = None
    real_payment_committed = False
    payer_invoked = payable_challenge.test_preimage is None
    try:
        payment_result = _pay(
            payable_challenge, payer=payer, max_fee_sats=approval.max_fee_sats
        )
        if payer_invoked:
            approval.commit()
            real_payment_committed = True
        trace_sink.emit(
            "payment.succeeded",
            amountSats=payment_result.amount_sats,
            feeSats=payment_result.fee_sats,
            paymentHash=payment_result.payment_hash,
        )
        authorization = build_authorization(
            payable_challenge.parsed,
            payment_result.preimage_hex,
            source=config.payer.backend,
        )
        credential_scope = _credential_scope(
            request=request,
            config=config,
            request_key=request_key,
            protocol=payable_challenge.parsed.scheme,
            service=payable_challenge.service,
            namespace=session_namespace,
        )
        cached = _cacheable_credential(
            scope=credential_scope,
            authorization=authorization,
            payable_challenge=payable_challenge,
            payment_hash=payment_result.payment_hash,
            cache_policy=cache_policy,
        )
        if cached is not None:
            session_cache.put(cached)
            trace_sink.emit(
                "credential.cached",
                scope=cached.scope.request_key,
                expires=cached.expires_at,
            )
        retry_response = send_request(
            client,
            _to_http_request(
                replace(
                    request,
                    headers=_retry_headers(request.headers, authorization),
                )
            ),
        )
        if retry_response.status_code < 200 or retry_response.status_code >= 300:
            if cached is not None:
                session_cache.mark_rejected(cached.credential_id)
                session_cache.delete(cached.credential_id)
            if not real_payment_committed:
                approval.rollback()
            return _error(
                "paid_retry_rejected",
                f"paid retry returned HTTP {retry_response.status_code}",
                paid=True,
                response=serialize_response(retry_response),
            )
        if not real_payment_committed:
            approval.commit()
        if cached is not None:
            session_cache.mark_success(cached.credential_id)
        trace_sink.emit("retry.succeeded", statusCode=retry_response.status_code)
        return _success_paid(
            retry_response,
            challenge=payable_challenge.parsed,
            payment_result=payment_result,
            payer_backend=config.payer.backend,
        )
    except MissingPreimageError as exc:
        if not real_payment_committed:
            approval.rollback()
        return _error("missing_preimage", str(exc), paid=False)
    except PreimageVerificationError as exc:
        if not real_payment_committed:
            approval.rollback()
        return _error("preimage_verification_failed", str(exc), paid=False)
    except PayerError as exc:
        if not real_payment_committed:
            approval.rollback()
        return _error("payer_failure", str(exc), paid=False)
    except CredentialError as exc:
        if not real_payment_committed:
            approval.rollback()
        return _error("credential_failure", str(exc), paid=payment_result is not None)
    except PaygateHttpError as exc:
        if not real_payment_committed:
            approval.rollback()
        return _error("retry_failure", str(exc), paid=payment_result is not None)
    except PolicyError as exc:
        return _error(
            "budget_ledger_failure", str(exc), paid=payment_result is not None
        )


def _parse_challenge(
    response: httpx.Response, config: PaygateConfig
) -> ParsedChallenge:
    return parse_challenges(
        response.headers.get_list("www-authenticate"),
        config.protocol,
    )


def _to_payable_challenge(
    challenge: ParsedChallenge,
    response: httpx.Response,
) -> _PayableChallenge:
    body = _json_body(response)
    if isinstance(challenge, ParsedPaymentChallenge):
        payment_challenge = _with_json_test_preimage(challenge, body)
        return _PayableChallenge(
            parsed=payment_challenge,
            invoice=payment_challenge.invoice,
            amount_sats=payment_challenge.amount_sats,
            payment_hash=payment_challenge.payment_hash,
            service=payment_challenge.service,
            metadata=dict(payment_challenge.request_payload),
            test_preimage=payment_challenge.test_preimage,
        )

    amount_sats = amount_sats_from_invoice(challenge.invoice)
    if amount_sats is None:
        amount_sats = _find_amount_sats(body)
    if amount_sats is None:
        raise MissingAmountError("L402 invoice amount could not be determined")

    test_preimage = _find_test_preimage(body)
    payment_hash = payment_hash_from_invoice(challenge.invoice)
    if payment_hash is None and test_preimage is not None:
        payment_hash = hash_preimage(test_preimage)
    if payment_hash is None:
        raise MissingMPPRequestError(
            "L402 invoice payment_hash could not be determined"
        )

    return _PayableChallenge(
        parsed=challenge,
        invoice=challenge.invoice,
        amount_sats=amount_sats,
        payment_hash=payment_hash,
        service=None,
        metadata={"invoice": challenge.invoice, "version": challenge.version},
        test_preimage=test_preimage,
    )


def _json_body(response: httpx.Response) -> Mapping[str, Any] | None:
    try:
        body = response.json()
    except ValueError:
        return None
    if not isinstance(body, dict):
        return None
    return body


def _with_json_test_preimage(
    challenge: ParsedPaymentChallenge,
    body: Mapping[str, Any] | None,
) -> ParsedPaymentChallenge:
    if challenge.test_preimage is not None:
        return challenge
    if body is None:
        return challenge
    test_preimage = _find_test_preimage(body)
    if test_preimage is None:
        return challenge
    return replace(challenge, test_preimage=test_preimage)


def _find_test_preimage(value: object) -> str | None:
    if isinstance(value, dict):
        raw = value.get("test_preimage")
        if isinstance(raw, str) and raw:
            return raw
        for child in value.values():
            found = _find_test_preimage(child)
            if found is not None:
                return found
    if isinstance(value, list):
        for child in value:
            found = _find_test_preimage(child)
            if found is not None:
                return found
    return None


def _find_amount_sats(value: object) -> int | None:
    if isinstance(value, dict):
        for key in ("amountSats", "amount_sats"):
            raw = value.get(key)
            if isinstance(raw, int) and not isinstance(raw, bool) and raw >= 0:
                return raw
        for child in value.values():
            found = _find_amount_sats(child)
            if found is not None:
                return found
    if isinstance(value, list):
        for child in value:
            found = _find_amount_sats(child)
            if found is not None:
                return found
    return None


def _pay(
    challenge: _PayableChallenge,
    *,
    payer: Payer,
    max_fee_sats: int,
) -> PaymentResult:
    payer_challenge = PaymentChallenge(
        invoice=challenge.invoice,
        payment_hash=challenge.payment_hash,
        amount_sats=challenge.amount_sats,
        service=challenge.service,
        metadata=dict(challenge.metadata),
        test_preimage=challenge.test_preimage,
    )
    if challenge.test_preimage is not None:
        return verify_payment_result(
            payer_challenge,
            RawPaymentResult(
                amount_sats=challenge.amount_sats,
                fee_sats=0,
                payment_hash=challenge.payment_hash,
                preimage_hex=challenge.test_preimage,
            ),
        )
    return payer.pay(payer_challenge, max_fee_sats=max_fee_sats)


def _credential_scope(
    *,
    request: PaygateRequest,
    config: PaygateConfig,
    request_key: str,
    protocol: str,
    service: str | None,
    namespace: str = DEFAULT_NAMESPACE,
) -> CredentialScope:
    return CredentialScope(
        namespace=namespace,
        request_key=request_key,
        origin_host=_host_port(request.url),
        service=service,
        protocol=protocol,
        payer_backend=config.payer.backend,
        policy_hash=build_policy_hash(config.policy),
    )


def _cacheable_credential(
    *,
    scope: CredentialScope,
    authorization: str,
    payable_challenge: _PayableChallenge,
    payment_hash: str | None,
    cache_policy: str,
) -> CachedCredential | None:
    expires_at = _challenge_expires(payable_challenge.parsed)
    max_uses = None
    normalized_policy = cache_policy.lower()
    if normalized_policy == "single-use":
        max_uses = 1
    elif normalized_policy == "max-requests":
        max_uses = 1
    elif normalized_policy in ("challenge-defined", "until-expiry"):
        if expires_at is None:
            return None
    else:
        if expires_at is None:
            return None

    return CachedCredential(
        credential_id=build_credential_id(scope, authorization),
        scope=scope,
        authorization=authorization,
        created_at=int(time.time()),
        expires_at=expires_at,
        max_uses=max_uses,
        payment_hash=payment_hash,
        challenge_id=_challenge_id(payable_challenge.parsed),
    )


def _challenge_expires(challenge: ParsedChallenge) -> int | None:
    if isinstance(challenge, ParsedPaymentChallenge):
        return challenge.expires
    return None


def _challenge_id(challenge: ParsedChallenge) -> str | None:
    if isinstance(challenge, ParsedPaymentChallenge):
        return challenge.id
    return None


def _retry_headers(
    original_headers: Mapping[str, str],
    authorization: str,
) -> dict[str, str]:
    headers = {
        name: value
        for name, value in original_headers.items()
        if name.lower() != "authorization"
    }
    headers["Authorization"] = authorization
    return headers


def _to_http_request(request: PaygateRequest) -> HttpRequest:
    return HttpRequest(
        method=request.method,
        url=request.url,
        headers=request.headers,
        body=request.body,
        timeout=request.timeout,
    )


def _host_port(url: str) -> str | None:
    parsed = urlsplit(url)
    if parsed.hostname is None:
        return None
    port = parsed.port
    if port is None and parsed.scheme == "https":
        port = 443
    if port is None and parsed.scheme == "http":
        port = 80
    if port is None:
        return None
    return f"{parsed.hostname}:{port}"


def payer_from_config(
    config: PaygateConfig, *, env: Mapping[str, str] | None = None
) -> Payer:
    """Construct the configured payer backend."""

    if config.payer.backend == "test-mode":
        return TestModePayer()
    if config.payer.backend == "phoenixd":
        if config.phoenixd is None:
            raise ValueError("phoenixd backend selected without phoenixd config")
        return PhoenixdPayer.from_config(
            config.phoenixd,
            env=env,
            fee_limit_parameter=config.phoenixd.fee_limit_parameter,
        )
    if config.payer.backend == "lnd-rest":
        if config.lnd is None:
            raise ValueError("lnd-rest backend selected without lnd config")
        return LndRestPayer(config.lnd, env=env)
    raise ValueError(f"payer backend {config.payer.backend!r} is not implemented")


def _success_unpaid(response: httpx.Response) -> dict[str, Any]:
    return cast(
        dict[str, Any],
        redact_error_envelope(
            {
                "ok": True,
                "paid": False,
                "response": serialize_response(response),
            }
        ),
    )


def _success_cached(
    response: httpx.Response,
    credential: CachedCredential,
) -> dict[str, Any]:
    return cast(
        dict[str, Any],
        redact_error_envelope(
            {
                "ok": True,
                "paid": False,
                "credentialCache": {
                    "hit": True,
                    "credentialId": credential.credential_id,
                    "expiresAt": credential.expires_at,
                },
                "response": serialize_response(response),
            }
        ),
    )


def _success_paid(
    response: httpx.Response,
    *,
    challenge: ParsedChallenge,
    payment_result: PaymentResult,
    payer_backend: str,
) -> dict[str, Any]:
    receipt = None
    if isinstance(challenge, ParsedPaymentChallenge) and challenge.opaque_payload:
        receipt = challenge.opaque_payload.get("receipt")
    envelope: dict[str, Any] = {
        "ok": True,
        "paid": True,
        "protocol": challenge.scheme,
        "payerBackend": payer_backend,
        "amountSats": payment_result.amount_sats,
        "feeSats": payment_result.fee_sats,
        "paymentHash": payment_result.payment_hash,
        "response": serialize_response(response),
    }
    if receipt is not None:
        envelope["receipt"] = redact_error_envelope(receipt)
    return envelope


def _challenge_envelope(
    challenge: _PayableChallenge,
    *,
    payer_backend: str,
    max_fee_sats: int,
) -> dict[str, Any]:
    return cast(
        dict[str, Any],
        redact_error_envelope(
            {
                "ok": True,
                "paid": False,
                "wouldPay": True,
                "payerBackend": payer_backend,
                "protocol": challenge.parsed.scheme,
                "amountSats": challenge.amount_sats,
                "maxFeeSats": max_fee_sats,
                "service": challenge.service,
                "paymentHash": challenge.payment_hash,
                "challenge": {
                    "id": _challenge_id(challenge.parsed),
                    "expiresAt": _challenge_expires(challenge.parsed),
                    "metadata": challenge.metadata,
                },
            },
            redact_invoices=True,
        ),
    )


def _error(
    code: str,
    message: str,
    *,
    paid: bool,
    response: dict[str, Any] | None = None,
) -> dict[str, Any]:
    envelope: dict[str, Any] = {
        "ok": False,
        "paid": paid,
        "error": {
            "code": code,
            "message": message,
        },
    }
    if response is not None:
        envelope["response"] = response
    return cast(dict[str, Any], redact_error_envelope(envelope))
