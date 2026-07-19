"""Earliest possible deterministic controls for the historical interpreter."""

from __future__ import annotations

import datetime as _datetime
import json
import locale
import os
import socket
import subprocess
import time
import uuid
from datetime import datetime as _real_datetime
from pathlib import Path
from typing import Any


class ForbiddenOracleIO(RuntimeError):
    """Uncontrolled I/O escaped the replay fixtures."""


def _forbidden_network(*_args: object, **_kwargs: object) -> Any:
    raise ForbiddenOracleIO("DNS/socket access is forbidden during oracle replay")


_real_socket = socket.socket


class _BlockedSocket(_real_socket):
    def __init__(
        self, family: int = socket.AF_INET, *args: object, **kwargs: object
    ) -> None:
        if family != socket.AF_UNIX:
            raise ForbiddenOracleIO(
                "DNS/network socket access is forbidden during oracle replay"
            )
        super().__init__(family, *args, **kwargs)


socket.socket = _BlockedSocket
socket.create_connection = _forbidden_network  # type: ignore[assignment]
socket.getaddrinfo = _forbidden_network  # type: ignore[assignment]
socket.gethostbyname = _forbidden_network  # type: ignore[assignment]
socket.gethostbyname_ex = _forbidden_network  # type: ignore[assignment]

_controls_path = os.environ.get("ORACLE_CONTROLS")
if not _controls_path:
    raise ForbiddenOracleIO("deterministic controls fixture path is missing")
_controls = json.loads(Path(_controls_path).read_text(encoding="utf-8"))
_required_controls = {
    "clock",
    "date",
    "home",
    "locale",
    "timezone",
    "uuid_hex",
    "xdg_cache_home",
    "xdg_config_home",
    "xdg_state_home",
}
if set(_controls) != _required_controls:
    raise ForbiddenOracleIO("controls fixture has missing or unused keys")
_fixed_datetime = _real_datetime.fromisoformat(
    str(_controls["clock"]).replace("Z", "+00:00")
)
_fixed_date = _datetime.date.fromisoformat(str(_controls["date"]))
_FIXED_EPOCH = _fixed_datetime.timestamp()
time.time = lambda: _FIXED_EPOCH


class _FrozenDate(_datetime.date):
    @classmethod
    def today(cls) -> _FrozenDate:
        return cls(_fixed_date.year, _fixed_date.month, _fixed_date.day)


class _FrozenDateTime(_datetime.datetime):
    @classmethod
    def now(cls, tz: _datetime.tzinfo | None = None) -> _FrozenDateTime:
        value = cls.fromtimestamp(_FIXED_EPOCH, tz=_datetime.timezone.utc)
        return value if tz is None else value.astimezone(tz)

    @classmethod
    def utcnow(cls) -> _FrozenDateTime:
        return cls.utcfromtimestamp(_FIXED_EPOCH)


_datetime.date = _FrozenDate
_datetime.datetime = _FrozenDateTime

_uuid_counter = int(str(_controls["uuid_hex"]), 16) - 1


def _fixed_uuid4() -> uuid.UUID:
    global _uuid_counter
    _uuid_counter += 1
    return uuid.UUID(int=_uuid_counter)


uuid.uuid4 = _fixed_uuid4
os.environ["TZ"] = str(_controls["timezone"])
if hasattr(time, "tzset"):
    time.tzset()
try:
    locale.setlocale(locale.LC_ALL, str(_controls["locale"]))
except locale.Error as exc:
    raise ForbiddenOracleIO("declared oracle locale is unavailable") from exc


def _install_keyring_fixture() -> None:
    try:
        import keyring
        from keyring.errors import PasswordDeleteError
    except ImportError:
        return
    fixture_path = os.environ.get("ORACLE_KEYRING")
    if not fixture_path:
        raise ForbiddenOracleIO("strict keyring fixture path is missing")
    values = json.loads(Path(fixture_path).read_text(encoding="utf-8"))
    calls: list[list[str]] = []

    def get_password(service: str, account: str) -> str | None:
        calls.append(["get", service, account])
        return values.get(f"{service}.{account}") or values.get(account)

    def set_password(service: str, account: str, secret: str) -> None:
        calls.append(["set", service, account])
        values[f"{service}.{account}"] = secret

    def delete_password(service: str, account: str) -> None:
        calls.append(["delete", service, account])
        key = f"{service}.{account}"
        if key not in values:
            raise PasswordDeleteError("fixture key does not exist")
        del values[key]

    keyring.get_password = get_password
    keyring.set_password = set_password
    keyring.delete_password = delete_password
    keyring._oracle_calls = calls


_install_keyring_fixture()


def _install_http_guard() -> None:
    try:
        import httpx
    except ImportError:
        return

    def forbidden_request(*_args: object, **_kwargs: object) -> Any:
        raise ForbiddenOracleIO("unmatched HTTP/SDK request is forbidden")

    httpx.HTTPTransport.handle_request = forbidden_request
    httpx.AsyncHTTPTransport.handle_async_request = forbidden_request


_install_http_guard()

_real_popen = subprocess.Popen


def _guarded_popen(args: Any, *positional: Any, **kwargs: Any) -> subprocess.Popen[Any]:
    if os.environ.get("ORACLE_SUBPROCESS_GUARD") != "1":
        return _real_popen(args, *positional, **kwargs)
    command = args if isinstance(args, (list, tuple)) else [args]
    if not command or not isinstance(command[0], (str, os.PathLike)):
        raise ForbiddenOracleIO("unapproved subprocess shape")
    executable = Path(os.fspath(command[0])).name.lower()
    approved = (
        executable in {"git", "lsb_release", "uname"}
        or executable.startswith("python")
        or executable.startswith("paygate")
    )
    if not approved:
        raise ForbiddenOracleIO(f"unapproved subprocess: {executable}")
    if executable == "git" and any(
        str(item).startswith(("http://", "https://", "git@")) for item in command[1:]
    ):
        raise ForbiddenOracleIO("remote Git subprocess is forbidden")
    return _real_popen(args, *positional, **kwargs)


subprocess.Popen = _guarded_popen  # type: ignore[assignment]
