"""Checks on data/rheinbank/monitoring_events.json itself."""

import json
import re
from datetime import timedelta

import pytest

from dora_agent.config import DATA_DIR
from dora_agent.connectors import _store
from dora_agent.connectors.schemas import MonitoringFile

RAW = (DATA_DIR / "monitoring_events.json").read_text(encoding="utf-8")
CASE_ID = re.compile(r"\b[CN]\d{2}\b")


def test_monitoring_file_loads():
    assert len(_store.monitoring_problems()) == 32


def test_file_is_marked_synthetic_and_has_no_case_ids():
    assert "SYNTHETIC DATA" in RAW
    assert CASE_ID.search(RAW) is None


def test_all_stored_times_are_utc():
    for problem in _store.monitoring_problems():
        for event in problem.events:
            assert event.timestamp.utcoffset() == timedelta(0)


def test_every_problem_has_downtime_start_and_restore():
    for problem in _store.monitoring_problems():
        types = {e.event_type for e in problem.events}
        assert types & {"unavailable_full", "unavailable_partial"}, problem.problem_id
        assert "restored" in types, problem.problem_id


def test_problems_on_one_service_never_overlap():
    # Overlapping problems would make a lookup ambiguous.
    by_service = {}
    for problem in _store.monitoring_problems():
        by_service.setdefault(problem.service_id, []).append(problem)
    for service_id, problems in by_service.items():
        problems.sort(key=lambda p: p.first_time)
        for earlier, later in zip(problems, problems[1:]):
            assert earlier.last_time < later.first_time, service_id


def _mutated(change):
    doc = json.loads(RAW)
    change(doc["problems"][0])
    return json.dumps(doc)


@pytest.mark.parametrize(
    "change",
    [
        lambda p: p["events"].reverse(),  # out of time order
        lambda p: p["events"][0].update(timestamp="2025-02-15T22:00:00+01:00"),  # not UTC
        lambda p: p["events"][0].update(announced=True),  # 'announced' on an unplanned event
        lambda p: p["events"][0].update(event_type="exploded"),  # unknown event type
        lambda p: p.update(extra_field="x"),  # unknown field
        lambda p: p.update(events=[]),  # no events
    ],
)
def test_schema_rejects_broken_data(change):
    with pytest.raises(ValueError):
        MonitoringFile.model_validate_json(_mutated(change))
