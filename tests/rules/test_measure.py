"""Duration and downtime, measured per RTS-C Art. 3 (docs/dora-rules.md section 3, T3) and open question 8."""

from datetime import datetime, timedelta, timezone

import pytest

from dora_agent.rules import Fact, IncidentFacts
from dora_agent.rules.measure import measure_downtime, measure_duration

UTC = timezone.utc
AS_OF = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)


def t(day, hour, minute=0):
    return datetime(2026, 5, day, hour, minute, tzinfo=UTC)


def at(value, source="monitoring", **extra):
    return Fact[datetime](value=value, source=source, **extra)


def planned(confirmed=True):
    return Fact[bool](value=True, source="human" if confirmed else "ai_suggestion",
                      confirmed_by="Sam" if confirmed else None)


# ---------- duration: start (Art. 3(1)) ----------


def test_duration_from_incident_start_to_resolution():
    m = measure_duration(IncidentFacts(incident_start=at(t(26, 7)), resolved_at=at(t(27, 9))), AS_OF)
    assert m.length == timedelta(hours=26)
    assert (m.start_basis, m.end_basis, m.ongoing) == ("incident_start", "resolved_at", False)


def test_duration_start_unknown_uses_detection_time():
    m = measure_duration(IncidentFacts(detected_at=at(t(26, 8)), resolved_at=at(t(26, 10))), AS_OF)
    assert m.start_basis == "detected_at"
    assert m.length == timedelta(hours=2)


def test_duration_logs_showing_earlier_start_win_over_detection():
    facts = IncidentFacts(detected_at=at(t(26, 8)), earliest_log_at=at(t(26, 6)), resolved_at=at(t(26, 10)))
    m = measure_duration(facts, AS_OF)
    assert m.start_basis == "earliest_log_at"
    assert m.length == timedelta(hours=4)


def test_duration_later_log_time_does_not_replace_detection():
    facts = IncidentFacts(detected_at=at(t(26, 8)), earliest_log_at=at(t(26, 9)), resolved_at=at(t(26, 10)))
    assert measure_duration(facts, AS_OF).start_basis == "detected_at"


def test_duration_known_incident_start_is_used_as_given():
    facts = IncidentFacts(incident_start=at(t(26, 7)), detected_at=at(t(26, 8)),
                          earliest_log_at=at(t(26, 6)), resolved_at=at(t(26, 10)))
    assert measure_duration(facts, AS_OF).start_basis == "incident_start"


def test_duration_no_start_at_all_cannot_be_measured():
    m = measure_duration(IncidentFacts(resolved_at=at(t(26, 10))), AS_OF)
    assert m.length is None
    assert m.problem == "start time unknown"


# ---------- duration: end ----------


def test_duration_not_resolved_is_ongoing_up_to_as_of():
    m = measure_duration(IncidentFacts(detected_at=at(t(31, 12))), AS_OF)
    assert m.ongoing
    assert m.end_basis == "as_of"
    assert m.length == timedelta(hours=24)  # a minimum, never a guess


def test_duration_estimated_end_is_used_and_marked():
    facts = IncidentFacts(detected_at=at(t(26, 8)),
                          resolved_at=at(t(27, 12), source="human", confirmed_by="Sam", is_estimate=True))
    m = measure_duration(facts, AS_OF)
    assert m.length == timedelta(hours=28)
    assert m.is_estimate and not m.ongoing


def test_duration_unconfirmed_ai_end_is_ignored():
    facts = IncidentFacts(detected_at=at(t(31, 12)), resolved_at=at(t(31, 13), source="ai_suggestion"))
    m = measure_duration(facts, AS_OF)
    assert m.ongoing and m.end_basis == "as_of"


def test_duration_end_before_start_is_reported_not_guessed():
    m = measure_duration(IncidentFacts(incident_start=at(t(26, 10)), resolved_at=at(t(26, 9))), AS_OF)
    assert m.length is None
    assert "before the start" in m.problem


def test_as_of_must_be_utc():
    with pytest.raises(ValueError):
        measure_duration(IncidentFacts(), datetime(2026, 6, 1, 12))
    with pytest.raises(ValueError):
        measure_downtime(IncidentFacts(), datetime(2026, 6, 1, 12, tzinfo=timezone(timedelta(hours=2))))


# ---------- downtime (Art. 3(2)) ----------


def test_downtime_from_unavailable_to_restored():
    m = measure_downtime(IncidentFacts(downtime_start=at(t(26, 7, 10)), service_restored_at=at(t(26, 9, 40))), AS_OF)
    assert m.length == timedelta(hours=2, minutes=30)
    assert (m.start_basis, m.end_basis) == ("downtime_start", "service_restored_at")


def test_downtime_start_unknown_uses_detection_time():
    m = measure_downtime(IncidentFacts(detected_at=at(t(26, 8)), service_restored_at=at(t(26, 9))), AS_OF)
    assert m.start_basis == "detected_at"


def test_downtime_does_not_use_log_time():
    # Art. 3(2) names only the detection time as the fallback, not logs.
    facts = IncidentFacts(earliest_log_at=at(t(26, 6)), detected_at=at(t(26, 8)), service_restored_at=at(t(26, 9)))
    assert measure_downtime(facts, AS_OF).length == timedelta(hours=1)


def test_downtime_runs_until_backlog_cleared():
    # C14-style: service back, but delayed payments still being processed.
    facts = IncidentFacts(downtime_start=at(t(26, 8)), service_restored_at=at(t(26, 9)),
                          backlog_cleared_at=at(t(26, 13)))
    m = measure_downtime(facts, AS_OF)
    assert m.length == timedelta(hours=5)
    assert m.end_basis == "backlog_cleared_at"


def test_backlog_time_before_restoration_is_ignored():
    facts = IncidentFacts(downtime_start=at(t(26, 8)), service_restored_at=at(t(26, 9)),
                          backlog_cleared_at=at(t(26, 8, 30)))
    assert measure_downtime(facts, AS_OF).end_basis == "service_restored_at"


def test_downtime_not_restored_is_ongoing():
    m = measure_downtime(IncidentFacts(downtime_start=at(t(31, 10))), AS_OF)
    assert m.ongoing and m.length == timedelta(hours=26)


def test_downtime_no_start_cannot_be_measured():
    m = measure_downtime(IncidentFacts(service_restored_at=at(t(26, 9))), AS_OF)
    assert m.length is None and m.problem == "start time unknown"


# ---------- planned window that overran (open question 8) ----------

# C16-B data (data/rheinbank/monitoring_events.json, PRB-0029): window ends 14 Sep 04:00 UTC,
# online banking restored 09:30, resolved 10:00.
C16B_AS_OF = datetime(2026, 9, 14, 12, 0, tzinfo=UTC)


def c16b(**extra):
    base = dict(
        planned_and_announced=planned(),
        planned_window_end=at(datetime(2026, 9, 14, 4, 0, tzinfo=UTC)),
        downtime_start=at(datetime(2026, 9, 12, 16, 0, tzinfo=UTC)),
        service_restored_at=at(datetime(2026, 9, 14, 9, 30, tzinfo=UTC)),
        incident_start=at(datetime(2026, 9, 12, 16, 0, tzinfo=UTC)),
        resolved_at=at(datetime(2026, 9, 14, 10, 0, tzinfo=UTC)),
    )
    base.update(extra)
    return IncidentFacts(**base)


def test_c16b_overrun_downtime_starts_at_planned_end():
    m = measure_downtime(c16b(), C16B_AS_OF)
    assert m.start_basis == "planned_window_end"
    assert m.length == timedelta(hours=5, minutes=30)


def test_c16b_overrun_duration_starts_at_planned_end():
    m = measure_duration(c16b(), C16B_AS_OF)
    assert m.start_basis == "planned_window_end"
    assert m.length == timedelta(hours=6)


def test_restored_inside_window_gives_zero_overrun():
    # C16-A shape: restored before the window ended.
    facts = c16b(service_restored_at=at(datetime(2026, 9, 14, 3, 40, tzinfo=UTC)),
                 resolved_at=at(datetime(2026, 9, 14, 3, 40, tzinfo=UTC)))
    assert measure_downtime(facts, C16B_AS_OF).length == timedelta(0)
    assert measure_duration(facts, C16B_AS_OF).length == timedelta(0)


def test_still_inside_window_and_ongoing_gives_zero_so_far():
    facts = c16b(service_restored_at=Fact[datetime](), resolved_at=Fact[datetime]())
    early = datetime(2026, 9, 14, 2, 0, tzinfo=UTC)
    m = measure_downtime(facts, early)
    assert m.length == timedelta(0) and m.ongoing


def test_overrun_ongoing_counts_from_planned_end():
    facts = c16b(service_restored_at=Fact[datetime](), resolved_at=Fact[datetime]())
    m = measure_downtime(facts, C16B_AS_OF)
    assert m.ongoing and m.length == timedelta(hours=8)


def test_unconfirmed_planned_answer_measures_normally():
    # Section 7: "planned" is a judgment call. Unconfirmed, it is unknown, so no overrun rule.
    m = measure_downtime(c16b(planned_and_announced=planned(confirmed=False)), C16B_AS_OF)
    assert m.start_basis == "downtime_start"
    assert m.length == timedelta(hours=41, minutes=30)


def test_planned_but_window_end_unknown_cannot_be_measured():
    facts = c16b(planned_window_end=Fact[datetime]())
    assert measure_downtime(facts, C16B_AS_OF).length is None
    assert measure_duration(facts, C16B_AS_OF).length is None


def test_planned_answer_no_measures_normally():
    facts = c16b(planned_and_announced=Fact[bool](value=False, source="human", confirmed_by="Sam"))
    assert measure_downtime(facts, C16B_AS_OF).start_basis == "downtime_start"
