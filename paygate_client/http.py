"""HTTP helpers for Paygate request orchestration."""

from __future__ import annotations

import base64
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, cast

import httpx

from paygate_client.redaction import redact_error_envelope


class PaygateHttpError(Exception):
    """Raised when the target request cannot be completed."""


@dataclass(frozen=True)
class HttpRequest:
    """Serializable HTTP request input for the Paygate orchestrator."""

    method: str
    url: str
    headers: Mapping[str, str] = field(default_factory=dict)
    body: str | bytes | None = None
    timeout: float | None = None


def send_request(client: httpx.Client, request: HttpRequest) -> httpx.Response:
    """Send a request and normalize transport failures."""

    try:
        return client.request(
            request.method,
            request.url,
            headers=dict(request.headers),
            content=request.body,
            timeout=request.timeout,
        )
    except httpx.TimeoutException as exc:
        raise PaygateHttpError(f"target request timed out: {exc}") from exc
    except httpx.HTTPError as exc:
        raise PaygateHttpError(f"target request failed: {exc}") from exc


def serialize_response(response: httpx.Response) -> dict[str, Any]:
    """Convert an HTTP response into a JSON-safe, redacted structure."""

    envelope: dict[str, Any] = {
        "statusCode": response.status_code,
        "headers": dict(response.headers),
    }
    try:
        envelope["json"] = response.json()
    except ValueError:
        try:
            envelope["body"] = response.content.decode("utf-8")
        except UnicodeDecodeError:
            envelope["bodyBase64"] = base64.b64encode(response.content).decode("ascii")
    return cast(dict[str, Any], redact_error_envelope(envelope))
