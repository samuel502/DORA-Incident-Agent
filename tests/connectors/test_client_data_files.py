"""Checks on the client data files themselves."""

import calendar
import json
import re

import pytest

from dora_agent.config import DATA_DIR
from dora_agent.connectors import _store
from dora_agent.connectors.schemas import ClientImpactFile, DailyAveragesFile

FILES = ["bank_profile.json", "client_base.json", "daily_averages.json", "client_impact.json"]
CASE_ID = re.compile(r"\b[CN]\d{2}\b")
IBAN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{12,30}\b")
EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")


def raw(name):
    return (DATA_DIR / name).read_text(encoding="utf-8")


def test_files_load_with_expected_sizes():
    assert len(_store.client_base()) == 22
    assert len(_store.daily_averages()) == 198
    assert len(_store.client_impacts()) == 20
    assert _store.bank_profile().name == "Rheinbank AG"


@pytest.mark.parametrize("name", FILES)
def test_marked_synthetic_no_case_ids_no_personal_data(name):
    text = raw(name)
    assert "SYNTHETIC DATA" in text
    assert CASE_ID.search(text) is None
    assert IBAN.search(text) is None
    assert EMAIL.search(text) is None


def test_averages_cover_every_month_without_gaps():
    months = {f"{y}-{m:02d}" for y in (2025, 2026) for m in range(1, 13)} - {"2026-11", "2026-12"}
    by_service = {}
    for row in _store.daily_averages():
        by_service.setdefault(row.service_id, set()).add(row.month)
    assert len(by_service) == 9
    for service_id, covered in by_service.items():
        assert covered == months, service_id


def test_days_counted_matches_the_calendar():
    for row in _store.daily_averages():
        year, month = map(int, row.month.split("-"))
        assert row.days_counted == calendar.monthrange(year, month)[1], row.average_id


def test_impacts_on_one_service_never_overlap():
    by_service = {}
    for i in _store.client_impacts():
        by_service.setdefault(i.service_id, []).append(i)
    for service_id, impacts in by_service.items():
        impacts.sort(key=lambda i: i.window_start)
        for earlier, later in zip(impacts, impacts[1:]):
            assert earlier.window_end < later.window_start, service_id


def test_every_impact_matches_a_monitoring_problem_or_a_security_case():
    # Impacts without a monitoring outage are the data breaches (no downtime).
    problems = _store.monitoring_problems()
    no_outage = set()
    for i in _store.client_impacts():
        overlapping = [
            p for p in problems
            if p.service_id == i.service_id and p.first_time <= i.window_end and p.last_time >= i.window_start
        ]
        if not overlapping:
            no_outage.add(i.service_id)
    assert no_outage == {"SVC-LOAN", "SVC-MFT"}


def _broken(file_name, key, change):
    doc = json.loads(raw(file_name))
    change(doc[key][0])
    return json.dumps(doc)


@pytest.mark.parametrize(
    "change",
    [
        lambda i: i.update(is_estimate=True, estimate_basis=None),  # estimate without a basis
        lambda i: i.update(window_end="2020-01-01T00:00:00Z"),  # ends before it starts
        lambda i: i.update(affected_clients=-5),  # negative count
        lambda i: i.update(affected_clients="many"),  # not a number
        lambda i: i.update(relevant_parties_affected="maybe"),  # not yes/no/unknown
        lambda i: i.update(client_name="Max Mustermann"),  # unknown field: no client records allowed
    ],
)
def test_impact_schema_rejects_broken_data(change):
    with pytest.raises(ValueError):
        ClientImpactFile.model_validate_json(_broken("client_impact.json", "impacts", change))


@pytest.mark.parametrize(
    "change",
    [
        lambda r: r.update(month="2026-13"),
        lambda r: r.update(days_counted=40),
        lambda r: r.update(daily_avg_tx_count=1.5),
    ],
)
def test_averages_schema_rejects_broken_data(change):
    with pytest.raises(ValueError):
        DailyAveragesFile.model_validate_json(_broken("daily_averages.json", "averages", change))
