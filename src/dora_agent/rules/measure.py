"""Measure duration and service downtime from timestamps.

Rules: docs/dora-rules.md section 3, T3 "How to measure" (RTS-C Art. 3), and open question 8.
This module only measures. Comparing against 24 hours or 2 hours happens in thresholds.py.

If the end is not known yet, the time so far (up to `as_of`) is returned and marked as ongoing.
That number is a minimum: the real length can only be longer. Nothing is guessed.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from dora_agent.rules.facts import Frozen, IncidentFacts, UtcTime


class Measurement(Frozen):
    """One measured length, with the reasons behind it (for the trace and the log)."""

    start: UtcTime | None
    start_basis: str | None  # which fact the start came from
    end: UtcTime | None
    end_basis: str | None  # which fact the end came from, or "as_of" if still ongoing
    length: timedelta | None  # None = cannot be measured
    ongoing: bool  # True: no end yet, length is a minimum up to as_of
    is_estimate: bool  # True if any time used was an estimate
    problem: str | None = None  # why it could not be measured, in plain words


def _overrun_start(facts: IncidentFacts) -> datetime | None:
    """Open question 8: for a planned window that overran, both lengths start at the planned end.

    Used only when a human confirmed the downtime was planned and announced (section 7, open question 5).
    """
    if facts.usable("planned_and_announced") is True:
        return facts.usable("planned_window_end")
    return None


def _planned_but_no_window_end(facts: IncidentFacts) -> bool:
    return facts.usable("planned_and_announced") is True and facts.usable("planned_window_end") is None


def _estimated(facts: IncidentFacts, *names: str | None) -> bool:
    return any(getattr(facts, name).is_estimate for name in names if name and name != "as_of")


def _finish(facts, start, start_basis, end, end_basis, ongoing, as_of) -> Measurement:
    if start_basis == "planned_window_end" and end <= start:
        # Open question 8: ended (or so far still) inside the planned window, so no overrun yet.
        return Measurement(
            start=start, start_basis=start_basis, end=end, end_basis=end_basis, length=timedelta(0),
            ongoing=ongoing, is_estimate=_estimated(facts, end_basis),
        )
    if start is None:
        return Measurement(
            start=None, start_basis=None, end=end, end_basis=end_basis, length=None,
            ongoing=ongoing, is_estimate=False, problem="start time unknown",
        )
    if end < start:
        problem = (
            f"as_of ({as_of.isoformat()}) is before the start" if ongoing
            else f"end ({end_basis}) is before the start ({start_basis})"
        )
        return Measurement(
            start=start, start_basis=start_basis, end=end, end_basis=end_basis, length=None,
            ongoing=ongoing, is_estimate=False, problem=problem,
        )
    return Measurement(
        start=start, start_basis=start_basis, end=end, end_basis=end_basis, length=end - start,
        ongoing=ongoing, is_estimate=_estimated(facts, start_basis, end_basis),
    )


def _check_as_of(as_of: datetime) -> None:
    if as_of.tzinfo is None or as_of.utcoffset() != timedelta(0):
        raise ValueError("as_of must be a UTC time")


def measure_duration(facts: IncidentFacts, as_of: datetime) -> Measurement:
    """How long the incident lasted. RTS-C Art. 3(1), dora-rules.md section 3 T3, open question 8.

    Start: when the incident happened. If unknown, the detection time, or the log time if logs show
    it started earlier than detection. For an overrun: the planned end of the window.
    End: when it was resolved (an estimate is allowed). If not known: ongoing, measured up to as_of.
    """
    _check_as_of(as_of)

    if _planned_but_no_window_end(facts):
        return _finish(facts, None, None, as_of, "as_of", True, as_of)

    overrun = _overrun_start(facts)
    if overrun is not None:
        start, start_basis = overrun, "planned_window_end"
    elif facts.usable("incident_start") is not None:
        start, start_basis = facts.usable("incident_start"), "incident_start"
    else:
        # Art. 3(1): start unknown -> detection time; logs showing an earlier start win.
        candidates = [
            (facts.usable(name), name)
            for name in ("detected_at", "earliest_log_at")
            if facts.usable(name) is not None
        ]
        start, start_basis = min(candidates) if candidates else (None, None)

    resolved = facts.usable("resolved_at")
    if resolved is not None:
        return _finish(facts, start, start_basis, resolved, "resolved_at", False, as_of)
    return _finish(facts, start, start_basis, as_of, "as_of", True, as_of)


def measure_downtime(facts: IncidentFacts, as_of: datetime) -> Measurement:
    """How long the service was fully or partly down. RTS-C Art. 3(2), section 3 T3, open question 8.

    Start: when the service became fully or partly unavailable. If unknown, the detection time.
    For an overrun: the planned end of the window (downtime inside the window does not count).
    End: when normal service was restored, or later, when a backlog was fully cleared.
    If neither is known: ongoing, measured up to as_of.
    """
    _check_as_of(as_of)

    if _planned_but_no_window_end(facts):
        return _finish(facts, None, None, as_of, "as_of", True, as_of)

    overrun = _overrun_start(facts)
    if overrun is not None:
        start, start_basis = overrun, "planned_window_end"
    elif facts.usable("downtime_start") is not None:
        start, start_basis = facts.usable("downtime_start"), "downtime_start"
    elif facts.usable("detected_at") is not None:
        start, start_basis = facts.usable("detected_at"), "detected_at"  # Art. 3(2): start unknown
    else:
        start, start_basis = None, None

    # Art. 3(2): if a backlog continues after restoration, downtime runs until it is cleared.
    ends = [
        (facts.usable(name), name)
        for name in ("service_restored_at", "backlog_cleared_at")
        if facts.usable(name) is not None
    ]
    if ends:
        end, end_basis = max(ends)
        return _finish(facts, start, start_basis, end, end_basis, False, as_of)
    return _finish(facts, start, start_basis, as_of, "as_of", True, as_of)
