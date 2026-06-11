from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from paygate_client.challenges import L402Challenge, PaymentChallenge, parse_challenges
from paygate_client.config import ProtocolConfig
from paygate_client.credentials import build_authorization


FIXTURE_DIR = Path(__file__).parent / "fixtures" / "paygate"


def _load_fixture(name: str) -> Mapping[str, Any]:
    path = FIXTURE_DIR / name
    with path.open("r", encoding="utf-8") as fixture_file:
        loaded = json.load(fixture_file)
    if not isinstance(loaded, dict):
        raise AssertionError(f"{name}: fixture root must be an object")
    return loaded


def _require_mapping(
    source: Mapping[str, Any],
    key: str,
    fixture_name: str,
) -> Mapping[str, Any]:
    value = source.get(key)
    if not isinstance(value, dict):
        raise AssertionError(f"{fixture_name}: missing object field {key!r}")
    return value


def _require_list(source: Mapping[str, Any], key: str, fixture_name: str) -> list[Any]:
    value = source.get(key)
    if not isinstance(value, list):
        raise AssertionError(f"{fixture_name}: missing array field {key!r}")
    return value


def _require_string(source: Mapping[str, Any], key: str, fixture_name: str) -> str:
    value = source.get(key)
    if not isinstance(value, str) or not value:
        raise AssertionError(f"{fixture_name}: missing string field {key!r}")
    return value


def _require_int(source: Mapping[str, Any], key: str, fixture_name: str) -> int:
    value = source.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise AssertionError(f"{fixture_name}: missing integer field {key!r}")
    return value


def _decode_base64url_json(encoded: str, field_name: str) -> Mapping[str, Any]:
    if "=" in encoded:
        raise AssertionError(f"{field_name}: base64url value must be unpadded")
    try:
        raw = base64.urlsafe_b64decode(encoded + ("=" * (-len(encoded) % 4)))
    except ValueError as exc:
        raise AssertionError(f"{field_name}: incompatible base64url encoding") from exc
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise AssertionError(f"{field_name}: decoded value must be JSON") from exc
    if not isinstance(decoded, dict):
        raise AssertionError(f"{field_name}: decoded JSON must be an object")
    return decoded


def _parse_payment_fixture(name: str) -> tuple[PaymentChallenge, Mapping[str, Any]]:
    fixture = _load_fixture(name)
    headers = _require_list(fixture, "www_authenticate", name)
    challenge = parse_challenges(headers, ProtocolConfig(preferred="Payment"), now=0)
    if not isinstance(challenge, PaymentChallenge):
        raise AssertionError(f"{name}: expected Payment challenge, got {type(challenge).__name__}")
    return challenge, fixture


def _assert_payment_matches_fixture(
    challenge: PaymentChallenge,
    expected: Mapping[str, Any],
    fixture_name: str,
) -> None:
    expected_request = _require_mapping(expected, "request_payload", fixture_name)
    expected_opaque = _require_mapping(expected, "opaque_payload", fixture_name)

    assert challenge.id == _require_string(expected, "id", fixture_name)
    assert challenge.realm == _require_string(expected, "realm", fixture_name)
    assert challenge.method == _require_string(expected, "method", fixture_name)
    assert challenge.intent == _require_string(expected, "intent", fixture_name)
    assert challenge.invoice == _require_string(expected, "invoice", fixture_name)
    assert challenge.amount_sats == _require_int(expected, "amount_sats", fixture_name)
    assert challenge.payment_hash == _require_string(expected, "payment_hash", fixture_name)
    assert challenge.expires == _require_int(expected, "expires", fixture_name)
    assert challenge.digest == _require_string(expected, "digest", fixture_name)
    assert challenge.description == _require_string(expected, "description", fixture_name)
    assert challenge.service == _require_string(expected, "service", fixture_name)
    assert challenge.test_preimage == _require_string(expected, "test_preimage", fixture_name)
    assert challenge.request_payload == expected_request
    assert challenge.opaque_payload == expected_opaque
    assert _decode_base64url_json(challenge.request, f"{fixture_name}.request") == expected_request
    assert _decode_base64url_json(challenge.opaque or "", f"{fixture_name}.opaque") == expected_opaque


def _assert_l402_matches_fixture(
    challenge: L402Challenge,
    expected: Mapping[str, Any],
    fixture_name: str,
) -> None:
    assert challenge.version == _require_string(expected, "version", fixture_name)
    assert challenge.token == _require_string(expected, "token", fixture_name)
    assert challenge.macaroon == _require_string(expected, "macaroon", fixture_name)
    assert challenge.invoice == _require_string(expected, "invoice", fixture_name)
    assert dict(challenge.auth_params) == _require_mapping(expected, "auth_params", fixture_name)


def test_paygate_mpp_only_fixture_parses_real_wire_format() -> None:
    challenge, fixture = _parse_payment_fixture("mpp_challenge.json")

    _assert_payment_matches_fixture(
        challenge,
        _require_mapping(fixture, "expected", "mpp_challenge.json"),
        "mpp_challenge.json",
    )


def test_paygate_l402_only_fixture_parses_real_wire_format() -> None:
    fixture = _load_fixture("l402_challenge.json")
    headers = _require_list(fixture, "www_authenticate", "l402_challenge.json")

    challenge = parse_challenges(
        headers,
        ProtocolConfig(preferred="L402", allow_l402=True),
    )

    if not isinstance(challenge, L402Challenge):
        raise AssertionError(
            f"l402_challenge.json: expected L402 challenge, got {type(challenge).__name__}"
        )
    _assert_l402_matches_fixture(
        challenge,
        _require_mapping(fixture, "expected", "l402_challenge.json"),
        "l402_challenge.json",
    )


def test_paygate_dual_fixture_selects_preferred_protocol_without_lost_fields() -> None:
    fixture = _load_fixture("dual_challenge.json")
    headers = _require_list(fixture, "www_authenticate", "dual_challenge.json")
    expected = _require_mapping(fixture, "expected", "dual_challenge.json")

    payment = parse_challenges(
        headers,
        ProtocolConfig(preferred="Payment", allow_l402=True),
        now=0,
    )
    l402 = parse_challenges(
        headers,
        ProtocolConfig(preferred="L402", allow_l402=True),
        now=0,
    )

    if not isinstance(payment, PaymentChallenge):
        raise AssertionError(f"dual_challenge.json: expected Payment preferred selection")
    if not isinstance(l402, L402Challenge):
        raise AssertionError(f"dual_challenge.json: expected L402 preferred selection")
    _assert_payment_matches_fixture(
        payment,
        _require_mapping(expected, "payment", "dual_challenge.json"),
        "dual_challenge.json.payment",
    )
    _assert_l402_matches_fixture(
        l402,
        _require_mapping(expected, "l402", "dual_challenge.json"),
        "dual_challenge.json.l402",
    )


def test_paygate_mpp_credential_fixture_matches_builder_wire_format() -> None:
    challenge, _ = _parse_payment_fixture("mpp_challenge.json")
    fixture = _load_fixture("mpp_credential.json")
    source = _require_string(fixture, "source", "mpp_credential.json")
    preimage = _require_string(fixture, "preimage", "mpp_credential.json")

    authorization = build_authorization(challenge, preimage, source=source)
    scheme, blob = authorization.split(" ", 1)
    decoded = _decode_base64url_json(blob, "mpp_credential.json.authorization")

    assert scheme == "Payment"
    assert decoded == _require_mapping(fixture, "expected_decoded", "mpp_credential.json")
