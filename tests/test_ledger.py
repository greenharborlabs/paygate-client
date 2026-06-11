from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import date

import pytest

from paygate_client.ledger import (
    DailyBudgetExceededError,
    DailySpendLedger,
    LedgerReadError,
    LedgerReservationStateError,
)


def test_successful_reservation_commit_is_date_scoped(tmp_path) -> None:
    ledger = DailySpendLedger(tmp_path / "ledger.json", today=lambda: date(2026, 6, 11))

    reservation = ledger.reserve(amount_sats=20, daily_budget_sats=500)
    reservation.commit()

    assert ledger.spent_on(date(2026, 6, 11)) == 20
    assert ledger.spent_on(date(2026, 6, 12)) == 0


def test_rollback_releases_reserved_spend(tmp_path) -> None:
    ledger = DailySpendLedger(tmp_path / "ledger.json")

    reservation = ledger.reserve(amount_sats=20, daily_budget_sats=500)
    reservation.rollback()

    assert ledger.spent_today() == 0


def test_daily_budget_rejects_prior_spend_plus_new_amount(tmp_path) -> None:
    ledger = DailySpendLedger(tmp_path / "ledger.json")
    ledger.reserve(amount_sats=490, daily_budget_sats=500).commit()

    with pytest.raises(DailyBudgetExceededError):
        ledger.reserve(amount_sats=20, daily_budget_sats=500)


def test_two_concurrent_reservations_cannot_exceed_daily_budget(tmp_path) -> None:
    ledger = DailySpendLedger(tmp_path / "ledger.json")
    ledger.reserve(amount_sats=470, daily_budget_sats=500).commit()

    def reserve_twenty() -> bool:
        try:
            ledger.reserve(amount_sats=20, daily_budget_sats=500).commit()
        except DailyBudgetExceededError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: reserve_twenty(), range(2)))

    assert sorted(results) == [False, True]
    assert ledger.spent_today() == 490


def test_commit_and_rollback_are_idempotent_where_practical(tmp_path) -> None:
    ledger = DailySpendLedger(tmp_path / "ledger.json")

    reservation = ledger.reserve(amount_sats=20, daily_budget_sats=500)
    reservation.commit()
    reservation.commit()
    reservation.rollback()

    assert ledger.spent_today() == 20


def test_rollback_after_manual_release_raises_distinct_error(tmp_path) -> None:
    ledger = DailySpendLedger(tmp_path / "ledger.json")

    reservation = ledger.reserve(amount_sats=20, daily_budget_sats=500)
    reservation.rollback()

    with pytest.raises(LedgerReservationStateError):
        reservation.commit()


@pytest.mark.parametrize(
    "entry",
    [
        {"committed_sats": -1, "reservations": {}},
        {"committed_sats": 0, "reservations": {"reservation-1": -1}},
    ],
)
def test_negative_values_read_from_disk_raise_read_error(tmp_path, entry) -> None:
    ledger_path = tmp_path / "ledger.json"
    ledger_path.write_text(
        json.dumps({date.today().isoformat(): entry}),
        encoding="utf-8",
    )
    ledger = DailySpendLedger(ledger_path)

    with pytest.raises(LedgerReadError):
        ledger.spent_today()
