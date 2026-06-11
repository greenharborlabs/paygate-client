"""Local payment policy checks performed before payer invocation."""

from __future__ import annotations

from dataclasses import dataclass
from types import TracebackType
from typing import Any, Callable, TypeVar
from urllib.parse import urlsplit

from paygate_client.config import PolicyConfig
from paygate_client.ledger import (
    DailyBudgetExceededError,
    DailySpendLedger,
    LedgerLockError,
    LedgerReadError,
    LedgerReservation,
    LedgerReservationStateError,
    LedgerRollbackError,
    LedgerWriteError,
)

T = TypeVar("T")


class PolicyError(Exception):
    """Base class for local policy failures."""


class HostDeniedError(PolicyError):
    """Raised when a challenge host is absent, ambiguous, or not allowlisted."""


class ServiceDeniedError(PolicyError):
    """Raised when a challenge service identifier is not allowlisted."""


class AmountLimitExceededError(PolicyError):
    """Raised when a challenge exceeds the per-request amount cap."""


class BackendFeeLimitUnsupportedPolicyError(PolicyError):
    """Raised when the selected backend cannot enforce max_fee_sats."""


class DailyBudgetExceededPolicyError(PolicyError):
    """Raised when local daily budget policy rejects a request."""


class PolicyLedgerLockError(PolicyError):
    """Raised when the policy ledger lock cannot be acquired or released."""


class PolicyLedgerReadError(PolicyError):
    """Raised when the policy ledger cannot be read."""


class PolicyLedgerWriteError(PolicyError):
    """Raised when the policy ledger cannot be written."""


class PolicyLedgerRollbackError(PolicyError):
    """Raised when reserved spend cannot be rolled back."""


@dataclass(frozen=True)
class PolicyRequest:
    host: str | None
    service: str | None
    amount_sats: int
    payer_backend: Any


class PolicyEngine:
    """Evaluates configured local payment policy and reserves daily budget."""

    def __init__(
        self,
        config: PolicyConfig,
        *,
        ledger: DailySpendLedger | None = None,
    ) -> None:
        self.config = config
        self.ledger = ledger if ledger is not None else DailySpendLedger()
        self._allowed_hosts = {
            self._normalize_host(allowed_host) for allowed_host in config.allowed_hosts
        }

    def evaluate(self, request: PolicyRequest) -> PolicyApproval:
        normalized_host = self._normalize_host(request.host)
        if normalized_host not in self._allowed_hosts:
            raise HostDeniedError(f"host {request.host!r} is not allowed")

        if (
            request.service is not None
            and request.service not in self.config.allowed_services
        ):
            raise ServiceDeniedError(f"service {request.service!r} is not allowed")

        if request.amount_sats > self.config.max_request_sats:
            raise AmountLimitExceededError(
                f"request amount {request.amount_sats} sats exceeds "
                f"configured cap {self.config.max_request_sats} sats"
            )

        if request.amount_sats < 0:
            raise AmountLimitExceededError("request amount_sats must be non-negative")

        if not bool(getattr(request.payer_backend, "supports_max_fee_limit", False)):
            raise BackendFeeLimitUnsupportedPolicyError(
                "selected payer backend cannot enforce max_fee_sats before payment"
            )

        try:
            reservation = self.ledger.reserve(
                amount_sats=request.amount_sats,
                daily_budget_sats=self.config.daily_budget_sats,
            )
        except DailyBudgetExceededError as exc:
            raise DailyBudgetExceededPolicyError(str(exc)) from exc
        except LedgerLockError as exc:
            raise PolicyLedgerLockError(str(exc)) from exc
        except LedgerReadError as exc:
            raise PolicyLedgerReadError(str(exc)) from exc
        except LedgerWriteError as exc:
            raise PolicyLedgerWriteError(str(exc)) from exc
        return PolicyApproval(
            max_fee_sats=self.config.max_fee_sats,
            reservation=reservation,
        )

    def _normalize_host(self, host: str | None) -> str:
        if host is None or not host.strip():
            raise HostDeniedError("challenge host is required")
        host = host.strip()
        if any(separator in host for separator in (",", "/", "\\", "@")):
            raise HostDeniedError(f"challenge host {host!r} is ambiguous")
        try:
            parsed = urlsplit(f"//{host}")
        except ValueError as exc:
            raise HostDeniedError(f"challenge host {host!r} is invalid") from exc
        if (
            parsed.hostname is None
            or parsed.port is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path
            or parsed.query
            or parsed.fragment
        ):
            raise HostDeniedError(f"challenge host {host!r} must include host and port")
        return f"{parsed.hostname.lower()}:{parsed.port}"


@dataclass(frozen=True)
class PolicyApproval:
    max_fee_sats: int
    reservation: LedgerReservation

    def execute(self, payer_call: Callable[..., T], /, *args: Any, **kwargs: Any) -> T:
        """Invoke only the payer call, then commit reserved spend.

        The callable must not include credential construction, retry orchestration,
        or other post-payment work. Use manual ``commit``/``rollback`` or the
        context manager for broader lifecycles.
        """
        return self.execute_payer(payer_call, *args, **kwargs)

    def execute_payer(
        self,
        payer_call: Callable[..., T],
        /,
        *args: Any,
        **kwargs: Any,
    ) -> T:
        """Invoke the payer with ``max_fee_sats`` and commit only after success."""

        try:
            result = payer_call(*args, max_fee_sats=self.max_fee_sats, **kwargs)
        except BaseException:
            self.rollback()
            raise
        self.commit()
        return result

    def commit(self) -> None:
        try:
            self.reservation.commit()
        except LedgerLockError as exc:
            raise PolicyLedgerLockError(str(exc)) from exc
        except LedgerReadError as exc:
            raise PolicyLedgerReadError(str(exc)) from exc
        except LedgerWriteError as exc:
            raise PolicyLedgerWriteError(str(exc)) from exc

    def rollback(self) -> None:
        try:
            self.reservation.rollback()
        except LedgerReservationStateError as exc:
            raise PolicyLedgerRollbackError(str(exc)) from exc
        except LedgerRollbackError as exc:
            raise PolicyLedgerRollbackError(str(exc)) from exc
        except LedgerLockError as exc:
            raise PolicyLedgerLockError(str(exc)) from exc
        except LedgerReadError as exc:
            raise PolicyLedgerReadError(str(exc)) from exc
        except LedgerWriteError as exc:
            raise PolicyLedgerWriteError(str(exc)) from exc

    def __enter__(self) -> PolicyApproval:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        del exc_type, exc, traceback
        if self.reservation.is_pending:
            self.rollback()
        return False
