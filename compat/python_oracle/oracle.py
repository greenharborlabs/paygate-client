"""Public validation facade for the executable historical replay bundle."""

from __future__ import annotations

import json
import socket
from collections.abc import Mapping
from contextlib import AbstractContextManager
from pathlib import Path
from types import TracebackType
from typing import Any

from compat.python_oracle.replay import (
    BASELINE_COMMIT,
    ReplayViolation,
    replay,
    validate_bundle,
)

OracleViolation = ReplayViolation


def _blocked(*_args: object, **_kwargs: object) -> Any:
    raise OracleViolation("live network access is forbidden by the Python oracle")


class OfflineGuard(AbstractContextManager["OfflineGuard"]):
    """Small in-process guard used by negative acceptance tests."""

    def __enter__(self) -> OfflineGuard:
        self._socket = socket.socket
        self._getaddrinfo = socket.getaddrinfo
        socket.socket = _blocked  # type: ignore[assignment]
        socket.getaddrinfo = _blocked  # type: ignore[assignment]
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        socket.socket = self._socket  # type: ignore[assignment]
        socket.getaddrinfo = self._getaddrinfo  # type: ignore[assignment]

    def real_keyring_get(self, *_args: object, **_kwargs: object) -> None:
        raise OracleViolation("real keyring access is forbidden by the Python oracle")


def run_oracle(
    root: Path,
    *,
    ambient: Mapping[str, str],
    permit_live_network: bool = False,
    permit_real_keyring: bool = False,
    execute: bool = False,
) -> bytes:
    """Validate bundle metadata, or execute qualified replay when requested."""

    del ambient
    if permit_live_network:
        raise OracleViolation("live network access requested")
    if permit_real_keyring:
        raise OracleViolation("real keyring access requested")
    if execute:
        return replay(root)
    validated = validate_bundle(root)
    summary = {
        "baseline_commit": BASELINE_COMMIT,
        "case_count": len(validated["cases"]),
        "inventory_count": len(validated["tree"]),
    }
    return (json.dumps(summary, sort_keys=True, separators=(",", ":")) + "\n").encode()
