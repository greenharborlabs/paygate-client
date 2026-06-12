from paygate_client.invoices import amount_sats_from_invoice


def test_amount_sats_from_invoice_parses_common_units() -> None:
    assert amount_sats_from_invoice("lnbc1qqqqqq") is None
    assert amount_sats_from_invoice("lnbc250n1qqqqqq") == 25
    assert amount_sats_from_invoice("lnbc1u1qqqqqq") == 100
    assert amount_sats_from_invoice("lnbc1m1qqqqqq") == 100_000


def test_amount_sats_from_invoice_rounds_msats_up_for_policy() -> None:
    assert amount_sats_from_invoice("lnbc1p1qqqqqq") == 1
