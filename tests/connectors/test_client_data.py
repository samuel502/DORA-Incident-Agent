"""Client data lookups: get_client_impact, get_daily_averages, get_bank_profile.

The ratios below are worked out only to check that the data lands on the side of each
threshold that docs/case-library.md expects. The real comparison belongs to the rules
engine (block 4). Fractions are used so that "exactly 10%" really is exactly 10%.
"""

from dataclasses import replace
from datetime import date, datetime, timedelta
from fractions import Fraction

import pytest

from dora_agent.config import connector_limits
from dora_agent.connectors import InvalidQuery, get_bank_profile, get_client_impact, get_daily_averages


def impact(service_id, start, days=1):
    """The one impact record overlapping a window that starts at `start`."""
    begin = datetime.fromisoformat(start)
    result = get_client_impact(service_id, begin, begin + timedelta(days=days))
    assert result.service_known is True
    assert len(result.impacts) == 1, [i.impact_id for i in result.impacts]
    return result.impacts[0]


def baseline(service_id, start):
    return get_daily_averages(service_id, start[:10])


def share(part, whole):
    return Fraction(part, whole)


# ---------- the brief's example and the constructed cases ----------


def test_brief_online_banking_140000_clients():
    i, b = impact("SVC-OLB", "2026-05-26T07:10:00Z"), baseline("SVC-OLB", "2026-05-26")
    assert i.affected_clients > 100_000  # T1-b
    assert share(i.affected_tx_count, b.daily_avg_tx_count) > Fraction(1, 10)  # T1-d


def test_n02_three_percent_of_clients_and_small_payments_share():
    i, b = impact("SVC-OLB", "2026-03-17T13:00:00Z"), baseline("SVC-OLB", "2026-03-17")
    assert share(i.affected_clients, b.total_clients_using_service) == Fraction(3, 100)
    assert i.affected_clients <= 100_000
    assert share(i.affected_tx_count, b.daily_avg_tx_count) <= Fraction(1, 10)
    assert share(i.affected_tx_value_eur, b.daily_avg_tx_value_eur) <= Fraction(1, 10)
    assert i.affected_member_states == ("DE",)
    assert i.relevant_parties_affected == "no"


def test_n03_four_percent_of_daily_payments():
    i, b = impact("SVC-SEPA", "2026-04-14T08:00:00Z"), baseline("SVC-SEPA", "2026-04-14")
    assert share(i.affected_tx_count, b.daily_avg_tx_count) == pytest.approx(0.04, abs=1e-6)
    assert share(i.affected_clients, b.total_clients_using_service) <= Fraction(1, 10)
    assert i.affected_member_states == ("DE",)


def test_n05_card_outage_small_shares():
    i, b = impact("SVC-CARD", "2026-06-13T10:00:00Z"), baseline("SVC-CARD", "2026-06-13")
    assert i.affected_clients <= 100_000
    assert share(i.affected_clients, b.total_clients_using_service) <= Fraction(1, 10)
    assert share(i.affected_tx_count, b.daily_avg_tx_count) <= Fraction(1, 10)


def test_n06_exactly_ten_percent_of_mobile_clients():
    i, b = impact("SVC-MOB", "2026-08-04T09:00:00Z"), baseline("SVC-MOB", "2026-08-04")
    assert share(i.affected_clients, b.total_clients_using_service) == Fraction(1, 10)  # not MORE than 10%
    assert i.affected_clients <= 100_000
    assert share(i.affected_tx_count, b.daily_avg_tx_count) <= Fraction(1, 10)


# ---------- real cases ----------


def test_c01_over_100000_clients_using_2024_snapshot():
    i, b = impact("SVC-OLB", "2025-02-15T21:00:00Z"), baseline("SVC-OLB", "2025-02-15")
    assert i.affected_clients > 100_000
    assert b.client_base_as_of == date(2024, 12, 31)
    assert b.month_used == "2025-01"


def test_c02_affected_clients_unknown_not_zero():
    i = impact("SVC-OLB", "2025-09-06T20:00:00Z")
    assert i.affected_clients is None
    assert i.affected_tx_count is None


def test_c03_payments_and_counterparts_above_thresholds():
    i, b = impact("SVC-HVP", "2026-02-26T08:00:00Z"), baseline("SVC-HVP", "2026-02-26")
    assert share(i.affected_tx_count, b.daily_avg_tx_count) > Fraction(1, 10)  # T1-d
    assert share(i.affected_tx_value_eur, b.daily_avg_tx_value_eur) > Fraction(1, 10)  # T1-e
    assert share(i.affected_counterparts, b.active_counterparts) > Fraction(3, 10)  # T1-c
    assert set(i.affected_member_states) == {"DE", "AT"}


def test_c04_t1_only_through_payments():
    i, b = impact("SVC-OLB", "2026-03-30T05:30:00Z"), baseline("SVC-OLB", "2026-03-30")
    assert share(i.affected_clients, b.total_clients_using_service) <= Fraction(1, 10)
    assert i.affected_clients <= 100_000
    assert share(i.affected_tx_count, b.daily_avg_tx_count) > Fraction(1, 10)


def test_c05_just_over_ten_percent_and_marked_estimate():
    i, b = impact("SVC-CARD", "2026-06-01T12:35:00Z"), baseline("SVC-CARD", "2026-06-01")
    ratio = share(i.affected_tx_count, b.daily_avg_tx_count)
    assert Fraction(1, 10) < ratio < Fraction(11, 100)
    assert i.is_estimate is True and i.estimate_basis
    assert len(i.affected_member_states) >= 2  # T4


def test_c06_counterparts_above_30_percent():
    i, b = impact("SVC-SEC", "2026-05-12T01:00:00Z"), baseline("SVC-SEC", "2026-05-12")
    assert share(i.affected_counterparts, b.active_counterparts) > Fraction(3, 10)


@pytest.mark.parametrize(
    "service_id, start",
    [
        ("SVC-DERIV", "2026-02-02T06:00:00Z"),  # C07
        ("SVC-OLB", "2026-04-30T14:30:00Z"),  # C08
        ("SVC-MFT", "2026-09-28T00:00:00Z"),  # C13
        ("SVC-SEPA", "2026-10-01T07:30:00Z"),  # C14
        ("SVC-OLB", "2026-10-21T10:00:00Z"),  # C15
    ],
)
def test_cases_where_client_numbers_are_unknown(service_id, start):
    i = impact(service_id, start)
    assert i.affected_clients is None
    assert i.affected_tx_count is None
    assert i.affected_member_states is None


def test_c09_wrong_balances_without_client_count():
    i = impact("SVC-OLB", "2026-08-18T15:00:00Z")
    assert i.accounts_with_balance_errors > 0
    assert i.affected_clients is None


def test_c10_estimated_clients_over_100000():
    i = impact("SVC-LOAN", "2026-07-20T00:00:00Z", days=2)
    assert i.affected_clients > 100_000
    assert i.is_estimate is True


def test_c11_over_100000_clients_no_client_base_for_file_transfer():
    i = impact("SVC-MFT", "2026-06-01T00:00:00Z")
    assert i.affected_clients > 100_000  # T1-b
    b = baseline("SVC-MFT", "2026-06-05")
    assert b.service_known is True
    assert b.total_clients_using_service is None
    assert b.daily_avg_tx_count is None


def test_c17_variant_b_two_member_states():
    assert set(impact("SVC-PAYOPS", "2026-07-16T04:10:00Z").affected_member_states) == {"DE", "AT"}


def test_bank_profile_branch_in_austria():
    profile = get_bank_profile().profile
    assert profile.home_member_state == "DE"
    assert [b.member_state for b in profile.branches] == ["AT"]
    assert profile.microenterprise is False  # open question 3


# ---------- daily averages: method (open question 6) ----------


def test_uses_previous_calendar_month():
    assert get_daily_averages("SVC-OLB", "2026-05-26").month_used == "2026-04"
    assert get_daily_averages("SVC-OLB", date(2026, 3, 1)).days_counted == 28  # February 2026


def test_january_uses_december_of_previous_year():
    result = get_daily_averages("SVC-CARD", "2026-01-15")
    assert result.month_used == "2025-12"
    assert result.daily_avg_tx_count is not None


def test_latest_snapshot_on_or_before_incident_date():
    assert get_daily_averages("SVC-OLB", "2025-12-31").client_base_as_of == date(2025, 12, 31)
    assert get_daily_averages("SVC-OLB", "2025-12-30").client_base_as_of == date(2024, 12, 31)


def test_before_any_data_returns_nothing_rather_than_a_guess():
    result = get_daily_averages("SVC-OLB", "2024-06-01")
    assert result.daily_avg_tx_count is None
    assert result.client_base_as_of is None
    assert result.source.record_ids == ()


def test_result_states_its_method_and_sources():
    result = get_daily_averages("SVC-OLB", "2026-05-26")
    assert "previous calendar month" in result.method
    assert len(result.source.record_ids) == 2  # one average row, one snapshot


def test_unknown_service_is_flagged():
    assert get_daily_averages("SVC-NOPE", "2026-05-26").service_known is False
    assert get_client_impact("SVC-NOPE", "2026-05-26T00:00:00Z", "2026-05-27T00:00:00Z").service_known is False


# ---------- client impact: lookup behaviour ----------


def test_quiet_window_returns_nothing():
    result = get_client_impact("SVC-OLB", "2026-06-10T00:00:00Z", "2026-06-20T00:00:00Z")
    assert result.impacts == ()


def test_window_overlap_counts_at_the_edge():
    # Brief example window ends 2026-05-26 12:40 UTC.
    assert len(get_client_impact("SVC-OLB", "2026-05-26T12:40:00Z", "2026-05-26T13:00:00Z").impacts) == 1
    assert get_client_impact("SVC-OLB", "2026-05-26T12:41:00Z", "2026-05-26T13:00:00Z").impacts == ()


def test_result_names_its_source():
    result = get_client_impact("SVC-HVP", "2026-02-26T00:00:00Z", "2026-02-27T00:00:00Z")
    assert result.source.system == "Rheinbank core banking (simulated)"
    assert result.source.record_ids == (result.impacts[0].impact_id,)


def test_number_of_impacts_is_capped(monkeypatch):
    from dora_agent.connectors import _store, client_data

    olb = impact("SVC-OLB", "2026-05-26T07:10:00Z")
    record = next(i for i in _store.client_impacts() if i.impact_id == olb.impact_id)
    copies = tuple(record.model_copy(update={"impact_id": f"IMP-99{n:02d}"}) for n in range(4))
    monkeypatch.setattr(_store, "client_impacts", lambda: copies)
    monkeypatch.setattr(client_data, "connector_limits", lambda: replace(connector_limits(), max_results=2))
    result = get_client_impact("SVC-OLB", "2026-05-26T00:00:00Z", "2026-05-27T00:00:00Z")
    assert len(result.impacts) == 2
    assert result.more_available is True


# ---------- bad inputs ----------


@pytest.mark.parametrize(
    "start, end",
    [
        ("2026-05-27T00:00:00Z", "2026-05-26T00:00:00Z"),  # end before start
        ("2026-05-26T00:00:00Z", "2026-05-26T00:00:00Z"),  # empty window
        ("2025-01-01T00:00:00Z", "2026-01-03T00:00:00Z"),  # longer than 366 days
        ("2026-05-26T00:00:00", "2026-05-27T00:00:00Z"),  # no time zone
        ("last week", "today"),
        (None, None),
    ],
)
def test_impact_rejects_bad_windows(start, end):
    with pytest.raises(InvalidQuery):
        get_client_impact("SVC-OLB", start, end)


@pytest.mark.parametrize(
    "bad_date",
    ["2026-05-26T07:10:00Z", datetime(2026, 5, 26, 7, 10), "26.05.2026", "2026-13-01", "1999-12-31", "", 20260526, None],
)
def test_averages_reject_bad_dates(bad_date):
    with pytest.raises(InvalidQuery):
        get_daily_averages("SVC-OLB", bad_date)


@pytest.mark.parametrize("bad_id", ["online banking", "SVC-olb", None])
def test_reject_bad_service_ids(bad_id):
    with pytest.raises(InvalidQuery):
        get_daily_averages(bad_id, "2026-05-26")
    with pytest.raises(InvalidQuery):
        get_client_impact(bad_id, "2026-05-26T00:00:00Z", "2026-05-27T00:00:00Z")
