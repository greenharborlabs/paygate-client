from __future__ import annotations

from dataclasses import replace

import pytest

from paygate_client.config import PolicyConfig
from paygate_client.ledger import (
    DailySpendLedger,
    LedgerLockError,
    LedgerReadError,
    LedgerReservationStateError,
    LedgerRollbackError,
    LedgerWriteError,
)
from paygate_client.policy import (
    AmountLimitExceededError,
    BackendFeeLimitUnsupportedPolicyError,
    DailyBudgetExceededPolicyError,
    HostDeniedError,
    PolicyApproval,
    PolicyEngine,
    PolicyLedgerLockError,
    PolicyLedgerReadError,
    PolicyLedgerRollbackError,
    PolicyLedgerWriteError,
    PolicyRequest,
    ServiceDeniedError,
)


class FeeCapablePayer:
    supports_max_fee_limit = True


class UnsafePayer:
    supports_max_fee_limit = False


class CredentialFailure(Exception):
    pass


class RetryExhausted(Exception):
    pass


class PayerFailure(Exception):
    pass


@pytest.fixture
def policy_config() -> PolicyConfig:
    return PolicyConfig(
        max_request_sats=50,
        max_fee_sats=10,
        daily_budget_sats=500,
        allowed_hosts=("localhost:8080",),
        allowed_services=("paygate-reference-service",),
    )


@pytest.fixture
def engine(tmp_path, policy_config) -> PolicyEngine:
    return PolicyEngine(
        policy_config,
        ledger=DailySpendLedger(tmp_path / "ledger.json"),
    )


def request(**overrides: object) -> PolicyRequest:
    base = PolicyRequest(
        host="localhost:8080",
        service="paygate-reference-service",
        amount_sats=20,
        payer_backend=FeeCapablePayer(),
    )
    return replace(base, **overrides)


def test_rejects_host_with_unlisted_port_before_payer_invocation(engine) -> None:
    with pytest.raises(HostDeniedError, match="localhost:8081"):
        engine.evaluate(request(host="localhost:8081"))


def test_rejects_absent_or_ambiguous_hosts(engine) -> None:
    for host in (None, "", "localhost:8080,localhost:8081", "localhost:8080/path"):
        with pytest.raises(HostDeniedError):
            engine.evaluate(request(host=host))


def test_service_identifier_is_enforced_when_present(engine) -> None:
    with pytest.raises(ServiceDeniedError, match="unknown-service"):
        engine.evaluate(request(service="unknown-service"))


def test_missing_service_identifier_is_not_checked(engine) -> None:
    approval = engine.evaluate(request(service=None))
    approval.rollback()


def test_request_amount_cap_is_checked_before_reservation(engine) -> None:
    with pytest.raises(AmountLimitExceededError, match="51"):
        engine.evaluate(request(amount_sats=51))


def test_backend_must_support_configured_fee_limit(engine) -> None:
    with pytest.raises(BackendFeeLimitUnsupportedPolicyError):
        engine.evaluate(request(payer_backend=UnsafePayer()))


def test_approval_exposes_fee_limit_and_commits_spend(engine) -> None:
    approval = engine.evaluate(request(amount_sats=20))

    assert approval.max_fee_sats == 10
    approval.commit()

    assert engine.ledger.spent_today() == 20


def test_approval_manual_rollback_releases_spend(engine) -> None:
    approval = engine.evaluate(request(amount_sats=20))

    approval.rollback()

    assert engine.ledger.spent_today() == 0


def test_execute_passes_fee_limit_and_commits_on_success(engine) -> None:
    seen: dict[str, int] = {}

    def payer(*, max_fee_sats: int) -> str:
        seen["max_fee_sats"] = max_fee_sats
        return "paid"

    approval = engine.evaluate(request(amount_sats=20))

    assert approval.execute(payer) == "paid"
    assert seen == {"max_fee_sats": 10}
    assert engine.ledger.spent_today() == 20
    assert approval.reservation.is_committed


def test_execute_payer_passes_fee_limit_and_commits_on_success(engine) -> None:
    seen: dict[str, int] = {}

    def payer(*, max_fee_sats: int) -> str:
        seen["max_fee_sats"] = max_fee_sats
        return "paid"

    approval = engine.evaluate(request(amount_sats=20))

    assert approval.execute_payer(payer) == "paid"
    assert seen == {"max_fee_sats": 10}
    assert engine.ledger.spent_today() == 20
    assert approval.reservation.is_committed


def test_execute_rolls_back_on_generic_payer_failure(engine) -> None:
    def payer(*, max_fee_sats: int) -> None:
        raise PayerFailure("payer failed")

    approval = engine.evaluate(request(amount_sats=20))

    with pytest.raises(PayerFailure):
        approval.execute(payer)

    assert engine.ledger.spent_today() == 0
    assert approval.reservation.is_rolled_back


def test_context_manager_rolls_back_on_credential_failure_before_payment(engine) -> None:
    with pytest.raises(CredentialFailure):
        with engine.evaluate(request(amount_sats=20)) as approval:
            assert approval.reservation.is_pending
            raise CredentialFailure("credential failed")

    assert engine.ledger.spent_today() == 0
    assert approval.reservation.is_rolled_back


def test_manual_reservation_rolls_back_on_retry_exhaustion_before_payment(engine) -> None:
    approval = engine.evaluate(request(amount_sats=20))

    with pytest.raises(RetryExhausted):
        try:
            raise RetryExhausted("retries exhausted")
        except RetryExhausted:
            approval.rollback()
            raise

    assert engine.ledger.spent_today() == 0
    assert approval.reservation.is_rolled_back


def test_post_payment_exception_after_execute_keeps_committed_spend(engine) -> None:
    def payer(*, max_fee_sats: int) -> str:
        assert max_fee_sats == 10
        return "paid"

    approval = engine.evaluate(request(amount_sats=20))

    with pytest.raises(CredentialFailure):
        approval.execute(payer)
        raise CredentialFailure("credential failed after payment")

    assert engine.ledger.spent_today() == 20
    assert approval.reservation.is_committed


def test_execute_rolls_back_on_keyboard_interrupt(engine) -> None:
    def payer(*, max_fee_sats: int) -> None:
        raise KeyboardInterrupt

    approval = engine.evaluate(request(amount_sats=20))

    with pytest.raises(KeyboardInterrupt):
        approval.execute(payer)

    assert engine.ledger.spent_today() == 0
    assert approval.reservation.is_rolled_back


def test_context_manager_rolls_back_pending_approval(engine) -> None:
    with engine.evaluate(request(amount_sats=20)) as approval:
        assert approval.reservation.is_pending

    assert engine.ledger.spent_today() == 0
    assert approval.reservation.is_rolled_back


def test_context_manager_keeps_committed_spend(engine) -> None:
    with engine.evaluate(request(amount_sats=20)) as approval:
        approval.commit()

    assert engine.ledger.spent_today() == 20
    assert approval.reservation.is_committed


def test_daily_budget_exceeded_maps_to_policy_error(engine) -> None:
    engine.ledger.reserve(amount_sats=490, daily_budget_sats=500).commit()

    with pytest.raises(DailyBudgetExceededPolicyError):
        engine.evaluate(request(amount_sats=20))


class FailingReserveLedger:
    def __init__(self, exc: Exception) -> None:
        self.exc = exc

    def reserve(self, *, amount_sats: int, daily_budget_sats: int) -> object:
        raise self.exc


@pytest.mark.parametrize(
    ("ledger_error", "policy_error"),
    (
        (LedgerLockError("lock failed"), PolicyLedgerLockError),
        (LedgerReadError("read failed"), PolicyLedgerReadError),
        (LedgerWriteError("write failed"), PolicyLedgerWriteError),
    ),
)
def test_ledger_reserve_failures_map_to_distinct_policy_errors(
    policy_config,
    ledger_error,
    policy_error,
) -> None:
    engine = PolicyEngine(policy_config, ledger=FailingReserveLedger(ledger_error))

    with pytest.raises(policy_error):
        engine.evaluate(request())


class FailingRollbackReservation:
    is_pending = True

    def commit(self) -> None:
        raise AssertionError("commit should not be called")

    def rollback(self) -> None:
        raise LedgerRollbackError("rollback failed")


class StateErrorRollbackReservation:
    is_pending = True

    def commit(self) -> None:
        raise AssertionError("commit should not be called")

    def rollback(self) -> None:
        raise LedgerReservationStateError("reservation is not pending")


def test_rollback_failure_maps_to_policy_rollback_error() -> None:
    approval = PolicyApproval(max_fee_sats=10, reservation=FailingRollbackReservation())

    with pytest.raises(PolicyLedgerRollbackError):
        approval.rollback()


def test_reservation_state_error_during_rollback_maps_to_policy_rollback_error() -> None:
    approval = PolicyApproval(
        max_fee_sats=10,
        reservation=StateErrorRollbackReservation(),
    )

    with pytest.raises(PolicyLedgerRollbackError):
        approval.rollback()
