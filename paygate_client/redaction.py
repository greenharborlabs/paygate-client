import copy
import re
from collections.abc import Iterable
from typing import Any

REDACTED_SECRET = "[REDACTED_SECRET]"
REDACTED_CREDENTIAL = "[REDACTED_CREDENTIAL]"
REDACTED_PREIMAGE = "[REDACTED_PREIMAGE]"
REDACTED_INVOICE = "[REDACTED_INVOICE]"

_HEX_64_OR_LONGER_RE = re.compile(r"\b[a-fA-F0-9]{64,}\b")
_INVOICE_RE = re.compile(r"\bln(?:bc|tb|bcrt)[a-z0-9]{20,}\b", re.IGNORECASE)
_AUTH_TEXT_RE = re.compile(
    r"(?P<prefix>\bAuthorization\s*[:=]\s*[\"']?)"
    r"(?P<scheme>Basic|Bearer|Payment|L402)\s+"
    r"(?P<credential>[^\"'\s,}]+)",
    re.IGNORECASE,
)

_SECRET_KEY_GROUPS: tuple[tuple[str, ...], ...] = (
    ("password",),
    ("passwd",),
    ("pwd",),
    ("token",),
    ("access", "token"),
    ("refresh", "token"),
    ("api", "key"),
    ("apikey",),
    ("secret",),
    ("client", "secret"),
    ("macaroon",),
    ("macaroon", "hex"),
    ("authorization",),
    ("proxy", "authorization"),
    ("preimage",),
)

_SAFE_SECRET_KEY_EXACT = {
    "status",
    "message",
    "amount",
    "amounts",
    "amount_sats",
    "invoice",
    "token_count",
    "secretary",
}


def _redact_authorization_value(value: str) -> str:
    match = re.match(r"^\s*(Basic|Bearer|Payment|L402)\s+.+$", value, re.IGNORECASE)
    if not match:
        return REDACTED_CREDENTIAL
    return f"{match.group(1)} {REDACTED_CREDENTIAL}"


def _redact_authorization_text(match: re.Match[str]) -> str:
    return f"{match.group('prefix')}{match.group('scheme')} {REDACTED_CREDENTIAL}"


def _tokenize_key(key: str) -> list[str]:
    split_on_boundaries = re.sub(r"(?<=[a-z])(?=[A-Z])", " ", key)
    split_on_boundaries = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", " ", split_on_boundaries)
    split_on_boundaries = re.sub(r"[^a-zA-Z0-9]+", " ", split_on_boundaries)
    return [token.lower() for token in split_on_boundaries.split() if token]


def _is_secret_key(key: Any) -> bool:
    if not isinstance(key, str):
        return False

    tokens = _tokenize_key(key)
    if not tokens:
        return False

    canonical_key = "_".join(tokens)
    if canonical_key in _SAFE_SECRET_KEY_EXACT:
        return False

    for group in _SECRET_KEY_GROUPS:
        group_size = len(group)
        if group_size == 1 and len(tokens) == 1 and tokens[0] == group[0]:
            return True
        if group_size > 1:
            for idx in range(len(tokens) - group_size + 1):
                if tuple(tokens[idx : idx + group_size]) == group:
                    return True

    return False


def redact_text(
    text: object,
    extra_secrets: Iterable[object] = (),
    redact_invoices: bool = False,
) -> str:
    """Redact sensitive payment material from text intended for logs or errors."""
    redacted = str(text)
    for secret in sorted(
        (str(value) for value in extra_secrets if value), key=len, reverse=True
    ):
        redacted = redacted.replace(secret, REDACTED_SECRET)

    redacted = _AUTH_TEXT_RE.sub(_redact_authorization_text, redacted)
    redacted = _HEX_64_OR_LONGER_RE.sub(REDACTED_PREIMAGE, redacted)
    if redact_invoices:
        redacted = _INVOICE_RE.sub(REDACTED_INVOICE, redacted)
    return redacted


def redact_error_envelope(
    envelope: Any,
    extra_secrets: Iterable[object] = (),
    redact_invoices: bool = False,
) -> Any:
    """Return a redacted copy of a JSON-like error envelope."""
    secrets = tuple(extra_secrets)

    def redact_value(value: Any) -> Any:
        if isinstance(value, dict):
            return {
                key: (
                    _redact_authorization_value(value)
                    if _is_secret_key(key)
                    and "authorization" in _tokenize_key(str(key))
                    and isinstance(value, str)
                    else REDACTED_SECRET
                    if _is_secret_key(key)
                    else redact_value(value)
                )
                for key, value in value.items()
            }
        if isinstance(value, list):
            return [redact_value(item) for item in value]
        if isinstance(value, tuple):
            return tuple(redact_value(item) for item in value)
        if isinstance(value, str):
            return redact_text(
                value, extra_secrets=secrets, redact_invoices=redact_invoices
            )
        return copy.deepcopy(value)

    return redact_value(envelope)
