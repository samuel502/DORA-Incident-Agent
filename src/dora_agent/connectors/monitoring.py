"""Monitoring connector: a read-only stand-in for a monitoring tool such as Dynatrace.

Facts it provides (docs/dora-rules.md, section 6), as raw times only:
- incident start, detection, resolution  -> duration for T3-a (RTS-C Art. 9(3)(a), Art. 3(1))
- unavailable, restored, backlog cleared -> downtime for T3-b (RTS-C Art. 9(3)(b), Art. 3(2))
- planned maintenance windows, announced -> planned vs unplanned (DORA Art. 3(8), open question 5)
- detection time                         -> when the bank became aware (reporting deadline)
It never works out durations or decides anything. The rules engine does that.
"""

from __future__ import annotations

from datetime import timedelta

from ..config import connector_limits
from . import _store
from ._guards import cap_text, check_hours, check_service_id, check_time
from .schemas import EventView, OutageTimelineResult, ProblemView, Source

SYSTEM = "Rheinbank monitoring (simulated)"


def get_outage_timeline(service_id: object, around: object, window_hours: object = 24) -> OutageTimelineResult:
    """Problems on one service that overlap [around - window_hours, around + window_hours].

    A problem is returned whole, with all its events, even if it runs for months
    beyond the search window. That way a long incident's resolution time is never cut off.
    """
    limits = connector_limits()
    wanted = check_service_id(service_id)
    centre = check_time(around, "around")
    hours = check_hours(window_hours, "window_hours", limits.max_timeline_window_hours)
    start, end = centre - timedelta(hours=hours), centre + timedelta(hours=hours)

    hits = [
        problem
        for problem in _store.monitoring_problems()
        if problem.service_id == wanted and problem.first_time <= end and problem.last_time >= start
    ]
    hits.sort(key=lambda problem: (problem.first_time, problem.problem_id))
    shown = hits[: limits.max_results]

    views = tuple(
        ProblemView(
            problem_id=problem.problem_id,
            title=problem.title,
            events=tuple(
                EventView(
                    event_id=event.event_id,
                    event_type=event.event_type,
                    timestamp=event.timestamp,
                    announced=event.announced,
                    note=cap_text(event.note, limits.max_text_chars),
                )
                for event in problem.events
            ),
        )
        for problem in shown
    )
    return OutageTimelineResult(
        service_known=wanted in _store.service_ids(),
        problems=views,
        more_available=len(hits) > len(shown),
        searched_from=start,
        searched_to=end,
        source=Source(system=SYSTEM, record_ids=tuple(problem.problem_id for problem in shown)),
    )
