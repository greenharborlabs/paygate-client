"""Lock-backed daily spend ledger for local policy enforcement.

The default ledger path is ``$XDG_STATE_HOME/paygate-client/daily-spend-ledger.json``
when ``XDG_STATE_HOME`` is set, otherwise
``~/.local/state/paygate-client/daily-spend-ledger.json``.
"""

from __future__ import annotations

import errno
import fcntl
import json
import os
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from types import TracebackType
from uuid import uuid4


class LedgerError(Exception):
    """Base class for ledger failures."""


class LedgerLockError(LedgerError):
    """Raised when the ledger lock cannot be acquired or released."""


class LedgerReadError(LedgerError):
    """Raised when ledger state cannot be read or decoded."""


class LedgerWriteError(LedgerError):
    """Raised when ledger state cannot be written."""


class LedgerRollbackError(LedgerError):
    """Raised when a reservation rollback cannot be completed."""


class DailyBudgetExceededError(LedgerError):
    """Raised when a reservation would exceed the configured daily budget."""


class LedgerReservationStateError(LedgerError):
    """Raised when a reservation is used after it has been released."""


def default_ledger_path(namespace: str | None = None) -> Path:
    normalized = (
        "default" if namespace is None or not namespace.strip() else namespace.strip()
    )
    state_home = os.environ.get("XDG_STATE_HOME")
    if normalized != "default":
        if "/" in normalized or "\\" in normalized or normalized in (".", ".."):
            raise ValueError("profile must not contain path separators or dot segments")
        if state_home:
            return (
                Path(state_home)
                / "paygate-client"
                / "profiles"
                / normalized
                / "daily-spend-ledger.json"
            )
        return (
            Path.home()
            / ".local"
            / "state"
            / "paygate-client"
            / "profiles"
            / normalized
            / "daily-spend-ledger.json"
        )
    if state_home:
        return Path(state_home) / "paygate-client" / "daily-spend-ledger.json"
    return (
        Path.home() / ".local" / "state" / "paygate-client" / "daily-spend-ledger.json"
    )


@dataclass
class _LedgerEntry:
    committed_sats: int
    reservations: dict[str, int]


class DailySpendLedger:
    """Atomic date-scoped check/reserve/commit ledger."""

    def __init__(
        self,
        path: str | os.PathLike[str] | None = None,
        *,
        today: Callable[[], date] | None = None,
    ) -> None:
        self.path = Path(path) if path is not None else default_ledger_path()
        self._today = today if today is not None else date.today
        self._lock_path = self.path.with_suffix(self.path.suffix + ".lock")

    def reserve(self, *, amount_sats: int, daily_budget_sats: int) -> LedgerReservation:
        if amount_sats < 0:
            raise ValueError("amount_sats must be non-negative")
        if daily_budget_sats < 0:
            raise ValueError("daily_budget_sats must be non-negative")

        reservation_id = uuid4().hex
        ledger_date = self._today()
        date_key = ledger_date.isoformat()
        with self._locked_state() as state:
            entry = self._entry_for(state, date_key)
            total_spend = entry.committed_sats + sum(entry.reservations.values())
            if total_spend + amount_sats > daily_budget_sats:
                raise DailyBudgetExceededError(
                    "daily budget exceeded: "
                    f"{total_spend + amount_sats} sats would exceed "
                    f"{daily_budget_sats} sats for {date_key}"
                )
            entry.reservations[reservation_id] = amount_sats
            state[date_key] = self._render_entry(entry)

        return LedgerReservation(
            ledger=self,
            reservation_id=reservation_id,
            ledger_date=ledger_date,
            amount_sats=amount_sats,
        )

    def spent_today(self) -> int:
        return self.spent_on(self._today())

    def spent_on(self, ledger_date: date) -> int:
        date_key = ledger_date.isoformat()
        with self._locked_state() as state:
            return self._entry_for(state, date_key).committed_sats

    def commit(self, reservation_id: str, ledger_date: date) -> None:
        date_key = ledger_date.isoformat()
        with self._locked_state() as state:
            entry = self._entry_for(state, date_key)
            amount = entry.reservations.pop(reservation_id, None)
            if amount is None:
                raise LedgerReservationStateError(
                    f"reservation {reservation_id} is not pending"
                )
            entry.committed_sats += amount
            state[date_key] = self._render_entry(entry)

    def rollback(self, reservation_id: str, ledger_date: date) -> None:
        date_key = ledger_date.isoformat()
        try:
            with self._locked_state() as state:
                entry = self._entry_for(state, date_key)
                amount = entry.reservations.pop(reservation_id, None)
                if amount is None:
                    raise LedgerReservationStateError(
                        f"reservation {reservation_id} is not pending"
                    )
                state[date_key] = self._render_entry(entry)
        except LedgerReservationStateError:
            raise
        except LedgerError as exc:
            raise LedgerRollbackError(
                f"failed to roll back reservation {reservation_id}"
            ) from exc

    @contextmanager
    def _locked_state(self) -> Iterator[dict[str, object]]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with self._lock_path.open("a+", encoding="utf-8") as lock_file:
                try:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                except OSError as exc:
                    raise LedgerLockError(
                        f"failed to acquire ledger lock {self._lock_path}"
                    ) from exc
                try:
                    state = self._read_state()
                    yield state
                    self._write_state(state)
                finally:
                    try:
                        fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
                    except OSError as exc:
                        raise LedgerLockError(
                            f"failed to release ledger lock {self._lock_path}"
                        ) from exc
        except OSError as exc:
            if exc.errno in {errno.EACCES, errno.EPERM}:
                raise LedgerLockError(
                    f"failed to open ledger lock {self._lock_path}"
                ) from exc
            raise

    def _read_state(self) -> dict[str, object]:
        if not self.path.exists():
            return {}
        try:
            with self.path.open("r", encoding="utf-8") as ledger_file:
                raw = json.load(ledger_file)
        except OSError as exc:
            raise LedgerReadError(f"failed to read ledger {self.path}") from exc
        except json.JSONDecodeError as exc:
            raise LedgerReadError(f"ledger {self.path} contains invalid JSON") from exc
        if not isinstance(raw, dict):
            raise LedgerReadError(f"ledger {self.path} must contain a JSON object")
        return raw

    def _write_state(self, state: dict[str, object]) -> None:
        tmp_path = self.path.with_name(f".{self.path.name}.{uuid4().hex}.tmp")
        try:
            with tmp_path.open("w", encoding="utf-8") as ledger_file:
                json.dump(state, ledger_file, sort_keys=True)
                ledger_file.write("\n")
                ledger_file.flush()
                os.fsync(ledger_file.fileno())
            os.replace(tmp_path, self.path)
        except OSError as exc:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise LedgerWriteError(f"failed to write ledger {self.path}") from exc

    def _entry_for(self, state: dict[str, object], date_key: str) -> _LedgerEntry:
        raw_entry = state.get(date_key, {})
        if not isinstance(raw_entry, dict):
            raise LedgerReadError(f"ledger entry for {date_key} must be an object")
        raw_committed = raw_entry.get("committed_sats", 0)
        if isinstance(raw_committed, bool) or not isinstance(raw_committed, int):
            raise LedgerReadError(f"committed_sats for {date_key} must be an integer")
        if raw_committed < 0:
            raise LedgerReadError(f"committed_sats for {date_key} must be non-negative")
        raw_reservations = raw_entry.get("reservations", {})
        if not isinstance(raw_reservations, dict):
            raise LedgerReadError(f"reservations for {date_key} must be an object")
        reservations: dict[str, int] = {}
        for reservation_id, amount in raw_reservations.items():
            if (
                not isinstance(reservation_id, str)
                or isinstance(amount, bool)
                or not isinstance(amount, int)
            ):
                raise LedgerReadError(
                    f"reservation amounts for {date_key} must be integer sats"
                )
            if amount < 0:
                raise LedgerReadError(
                    f"reservation amounts for {date_key} must be non-negative"
                )
            reservations[reservation_id] = amount
        return _LedgerEntry(
            committed_sats=raw_committed,
            reservations=reservations,
        )

    def _render_entry(self, entry: _LedgerEntry) -> dict[str, object]:
        return {
            "committed_sats": entry.committed_sats,
            "reservations": dict(sorted(entry.reservations.items())),
        }


class LedgerReservation:
    """Pending ledger reservation returned by ``DailySpendLedger.reserve``."""

    def __init__(
        self,
        *,
        ledger: DailySpendLedger,
        reservation_id: str,
        ledger_date: date,
        amount_sats: int,
    ) -> None:
        self.ledger = ledger
        self.reservation_id = reservation_id
        self.ledger_date = ledger_date
        self.amount_sats = amount_sats
        self._state = "pending"

    def commit(self) -> None:
        if self._state == "committed":
            return
        if self._state == "rolled_back":
            raise LedgerReservationStateError(
                f"reservation {self.reservation_id} has already been rolled back"
            )
        self.ledger.commit(self.reservation_id, self.ledger_date)
        self._state = "committed"

    def rollback(self) -> None:
        if self._state == "rolled_back":
            return
        if self._state == "committed":
            return
        self.ledger.rollback(self.reservation_id, self.ledger_date)
        self._state = "rolled_back"

    @property
    def is_pending(self) -> bool:
        return self._state == "pending"

    @property
    def is_committed(self) -> bool:
        return self._state == "committed"

    @property
    def is_rolled_back(self) -> bool:
        return self._state == "rolled_back"

    def __enter__(self) -> LedgerReservation:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del traceback
        if exc_type is not None and self._state == "pending":
            self.rollback()
