"""Monitoring lookups: get_outage_timeline.

The helpers below work out a few durations only to check that the data fits each
case in docs/case-library.md. The real calculation belongs to the rules engine (block 4).
"""

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from dora_agent.config import connector_limits
from dora_agent.connectors import InvalidQuery, get_outage_timeline

UTC = timezone.utc


def one_problem(service_id, around, hours=24):
    result = get_outage_timeline(service_id, around, hours)
    assert result.service_known is True
    assert len(result.problems) == 1, [p.problem_id for p in result.problems]
    return result.problems[0]


def first(problem, *event_types):
    times = [e.timestamp for e in problem.events if e.event_type in event_types]
    return min(times) if times else None


def downtime_hours(problem):
    start = first(problem, "unavailable_full", "unavailable_partial")
    end = first(problem, "backlog_cleared") or first(problem, "restored")
    return (end - start) / timedelta(hours=1)


def duration_hours(problem):
    start = first(problem, "incident_start") or first(problem, "detected")
    return (first(problem, "resolved") - start) / timedelta(hours=1)


# ---------- the brief's example and the constructed cases ----------


def test_brief_online_banking_down_since_0910():
    problem = one_problem("SVC-OLB", "2026-05-26T09:10:00+02:00")
    assert first(problem, "unavailable_full") == datetime(2026, 5, 26, 7, 10, tzinfo=UTC)
    assert downtime_hours(problem) > 2  # T3-b


def test_n01_hr_portal_slow_morning():
    problem = one_problem("SVC-HR", "2026-03-10T08:00:00Z")
    assert first(problem, "unavailable_partial") is not None


def test_n02_blip_is_40_minutes():
    assert downtime_hours(one_problem("SVC-OLB", "2026-03-17T13:00:00Z")) == pytest.approx(40 / 60)


def test_n03_payments_down_exactly_3_hours():
    problem = one_problem("SVC-SEPA", "2026-04-14T08:00:00Z")
    assert downtime_hours(problem) == 3  # over 2 h: T3-b is the only threshold
    assert duration_hours(problem) < 24


def test_n05_card_outage_90_minutes():
    assert downtime_hours(one_problem("SVC-CARD", "2026-06-13T10:00:00Z")) == 1.5  # under 2 h


def test_n06_mobile_login_70_minutes():
    assert downtime_hours(one_problem("SVC-MOB", "2026-08-04T09:00:00Z")) == pytest.approx(70 / 60)


# ---------- real cases ----------


def test_c01_migration_lasts_months():
    problem = one_problem("SVC-OLB", "2025-02-15T22:00:00Z")
    assert duration_hours(problem) > 24 * 30  # T3-a


def test_c02_detected_hours_after_start():
    problem = one_problem("SVC-OLB", "2025-09-07T08:00:00Z")
    assert first(problem, "detected") - first(problem, "incident_start") > timedelta(hours=10)
    assert duration_hours(problem) > 24


def test_c03_backlog_extends_downtime():
    problem = one_problem("SVC-HVP", "2026-02-26T09:00:00Z")
    assert first(problem, "backlog_cleared") > first(problem, "restored")
    assert downtime_hours(problem) == 13.5


def test_c04_three_day_fault():
    assert duration_hours(one_problem("SVC-OLB", "2026-03-30T07:30:00+02:00")) > 24


def test_c05_card_outage_about_10_hours():
    assert downtime_hours(one_problem("SVC-CARD", "2026-06-01T12:35:00Z")) > 10


def test_c06_no_start_in_monitoring_start_comes_from_security_logs():
    problem = one_problem("SVC-SEC", "2026-05-12T01:10:00Z")
    assert first(problem, "incident_start") is None
    assert first(problem, "detected") is not None


def test_c07_vendor_outage_several_days():
    problem = one_problem("SVC-DERIV", "2026-02-02T07:00:00Z")
    assert duration_hours(problem) > 24
    assert downtime_hours(problem) > 2


def test_c08_ddos_hits_three_services():
    assert duration_hours(one_problem("SVC-OLB", "2026-04-30T16:30:00+02:00")) > 24
    one_problem("SVC-ATM", "2026-04-30T15:00:00Z")
    one_problem("SVC-CARD", "2026-04-30T15:00:00Z")


def test_c09_glitch_on_three_channels():
    for service_id in ("SVC-OLB", "SVC-MOB", "SVC-PHONE"):
        assert downtime_hours(one_problem(service_id, "2026-08-18T15:00:00Z")) > 2


def test_c12_first_read_as_hardware_fault():
    problem = one_problem("SVC-CORE", "2026-08-26T06:00:00Z")
    detected = next(e for e in problem.events if e.event_type == "detected")
    assert "hardware" in detected.note


def test_c14_backlog_runs_for_days():
    problem = one_problem("SVC-SEPA", "2026-10-01T09:30:00+02:00")
    assert first(problem, "backlog_cleared") - first(problem, "restored") > timedelta(days=3)
    assert downtime_hours(problem) > 24


def test_c15_online_banking_and_email_down():
    assert downtime_hours(one_problem("SVC-OLB", "2026-10-21T10:00:00Z")) > 2
    one_problem("SVC-MAIL", "2026-10-21T10:00:00Z")


def test_c16_variant_a_app_back_inside_announced_window():
    problem = one_problem("SVC-MOB", "2026-09-13T12:00:00Z")
    planned = [e for e in problem.events if e.event_type.startswith("planned_")]
    assert planned and all(e.announced is True for e in planned)
    assert first(problem, "restored") <= first(problem, "planned_maintenance_end")


def test_c16_variant_b_online_banking_overruns_window():
    problem = one_problem("SVC-OLB", "2026-09-13T12:00:00Z")
    overrun = first(problem, "restored") - first(problem, "planned_maintenance_end")
    assert overrun > timedelta(hours=2)


def test_c17_laptops_4_hours_payment_workstations_5_hours():
    assert downtime_hours(one_problem("SVC-OFFICE", "2026-07-16T06:10:00+02:00")) == 4
    assert downtime_hours(one_problem("SVC-PAYOPS", "2026-07-16T06:10:00+02:00")) == 5


# ---------- lookup behaviour ----------


def test_quiet_period_returns_no_problems():
    result = get_outage_timeline("SVC-LOAN", "2026-07-21T07:00:00Z", 72)
    assert result.service_known is True
    assert result.problems == ()
    assert result.source.record_ids == ()


def test_unknown_service_is_flagged():
    result = get_outage_timeline("SVC-NOPE", "2026-05-26T07:10:00Z")
    assert result.service_known is False
    assert result.problems == ()


def test_window_edges_are_respected():
    # Brief example resolved 2026-05-26 13:00 UTC. 48 h later with a 24 h window: nothing.
    assert get_outage_timeline("SVC-OLB", "2026-05-28T13:01:00Z", 24).problems == ()
    # Exactly 24 h later with a 24 h window: the edge counts.
    assert len(get_outage_timeline("SVC-OLB", "2026-05-27T13:00:00Z", 24).problems) == 1


def test_long_problem_is_returned_whole():
    # Searching in the middle of a months-long incident still returns its start and resolution.
    problem = one_problem("SVC-OLB", "2025-04-01T00:00:00Z")
    assert first(problem, "incident_start").year == 2025
    assert first(problem, "resolved") == datetime(2025, 7, 31, 15, 0, tzinfo=UTC)


def test_times_come_back_in_utc():
    problem = one_problem("SVC-OLB", datetime(2026, 5, 26, 9, 10, tzinfo=timezone(timedelta(hours=2))))
    assert all(e.timestamp.utcoffset() == timedelta(0) for e in problem.events)


def test_search_window_is_reported_in_utc():
    result = get_outage_timeline("SVC-OLB", "2026-05-26T09:10:00+02:00", 2)
    assert result.searched_from == datetime(2026, 5, 26, 5, 10, tzinfo=UTC)
    assert result.searched_to == datetime(2026, 5, 26, 9, 10, tzinfo=UTC)


def test_result_names_its_source():
    result = get_outage_timeline("SVC-HVP", "2026-02-26T09:00:00Z")
    assert result.source.system == "Rheinbank monitoring (simulated)"
    assert result.source.record_ids == (result.problems[0].problem_id,)


def test_number_of_problems_is_capped(monkeypatch):
    from dora_agent.connectors import _store, monitoring

    real = _store.monitoring_problems()
    olb = [p for p in real if p.service_id == "SVC-OLB" and p.first_time.year == 2026][0]
    copies = tuple(olb.model_copy(update={"problem_id": f"PRB-99{n:02d}"}) for n in range(5))
    monkeypatch.setattr(_store, "monitoring_problems", lambda: copies)
    monkeypatch.setattr(monitoring, "connector_limits", lambda: replace(connector_limits(), max_results=3))
    result = get_outage_timeline("SVC-OLB", olb.first_time, 1)
    assert len(result.problems) == 3
    assert result.more_available is True


# ---------- bad inputs ----------


@pytest.mark.parametrize("bad_hours", [0, -1, 73, 1000, True, "24", 1.5, None])
def test_rejects_bad_window(bad_hours):
    with pytest.raises(InvalidQuery):
        get_outage_timeline("SVC-OLB", "2026-05-26T07:10:00Z", bad_hours)


@pytest.mark.parametrize(
    "bad_time",
    [
        "2026-05-26T09:10:00",  # no time zone
        datetime(2026, 5, 26, 9, 10),  # no time zone
        "yesterday at 9",
        "9:10",
        "",
        "2026-05-26T09:10:00Z" + " " * 40,  # too long
        "1999-12-31T23:00:00Z",
        "9999-12-31T23:00:00-14:00",  # runs past the end of the calendar when turned into UTC
        "0001-01-01T00:30:00+14:00",  # runs before the start of the calendar
        12345,
        None,
    ],
)
def test_rejects_bad_times(bad_time):
    with pytest.raises(InvalidQuery):
        get_outage_timeline("SVC-OLB", bad_time)


def test_rejects_bad_service_id():
    with pytest.raises(InvalidQuery):
        get_outage_timeline("online banking", "2026-05-26T07:10:00Z")
