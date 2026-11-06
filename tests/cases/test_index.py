"""The test index (cases/scenarios/index.json) against the case library and the bank data.

Three things are checked:
1. Every case in docs/case-library.md has an entry, with the same expected result.
2. Every entry is well formed: valid service, UTC time, clean ticket text.
3. The bank data for each entry can be found through the read-only lookups, and
   exactly the systems the entry lists hold something about it.
"""

import json
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Literal

import pytest
from pydantic import AwareDatetime, BaseModel, ConfigDict

from dora_agent.agent.questions import QUESTIONS, interpret_answer
from dora_agent.config import DATA_DIR, PROJECT_ROOT
from dora_agent.connectors import (
    _store,
    get_client_impact,
    get_outage_timeline,
    get_security_alerts,
    get_supplier_notices,
    get_suppliers_for_service,
)

INDEX_PATH = PROJECT_ROOT / "cases" / "scenarios" / "index.json"
LIBRARY_PATH = PROJECT_ROOT / "docs" / "case-library.md"
CONNECTORS_DIR = PROJECT_ROOT / "src" / "dora_agent" / "connectors"

Result = Literal[
    "major", "not_major", "depends", "depends_on_gate", "depends_on_human", "not_an_incident", "classify_overrun"
]
Source = Literal["monitoring", "client_impact", "security_alerts", "supplier_notices"]


class Scenario(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    scenario_id: str
    case_id: str
    variant: Literal["A", "B"] | None
    title: str
    real_case: str | None
    ticket: str
    service_id: str
    around: AwareDatetime
    expected_result: Result
    why: str
    data_sources: tuple[Source, ...]
    human_answers: dict[str, Any]  # block 5: the scripted human's answers to fixed questions


RAW = json.loads(INDEX_PATH.read_text(encoding="utf-8"))
SCENARIOS = [Scenario.model_validate(entry) for entry in RAW["scenarios"]]
BY_ID = {s.scenario_id: s for s in SCENARIOS}


def library_summary():
    """Rows of the summary table in docs/case-library.md section 1: {case_id: expected result text}."""
    rows = {}
    for line in LIBRARY_PATH.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^\| ([CN]\d{2}) \| [^|]+ \| [^|]+ \| ([^|]+) \| [^|]+ \|$", line)
        if match:
            rows[match.group(1)] = match.group(2).strip()
    return rows


# How the library's wording maps to the index's result codes.
LIBRARY_WORDING = {
    "Major": {None: "major"},
    "Not major": {None: "not_major"},
    "Depends on gate": {None: "depends_on_gate"},
    "Depends": {None: "depends"},
    "Not an incident, or classify": {"A": "not_an_incident", "B": "classify_overrun"},
    "Variant A not major, variant B major": {"A": "not_major", "B": "major"},
}


# ---------- 1. against the case library ----------


def test_library_table_was_read():
    assert len(library_summary()) == 23  # 17 real + 6 constructed


def test_every_library_case_has_an_entry_and_nothing_extra():
    in_index = {s.case_id for s in SCENARIOS if s.case_id[0] in "CN"}
    assert in_index == set(library_summary())


def test_expected_results_match_the_library():
    for case_id, wording in library_summary().items():
        expected = LIBRARY_WORDING[wording]  # KeyError here means new wording in the library
        found = {s.variant: s.expected_result for s in SCENARIOS if s.case_id == case_id}
        assert found == expected, case_id


def test_brief_examples_are_included():
    assert {"B01", "B03"} <= set(BY_ID)


# ---------- 2. well formed ----------


def test_scenario_ids_are_unique_and_match_case_and_variant():
    assert len(BY_ID) == len(SCENARIOS) == 27
    for s in SCENARIOS:
        assert s.scenario_id == s.case_id + (f"-{s.variant}" if s.variant else "")


def test_only_c16_and_c17_have_variants():
    assert {s.case_id for s in SCENARIOS if s.variant} == {"C16", "C17"}


def test_every_service_exists():
    for s in SCENARIOS:
        assert s.service_id in _store.service_ids(), s.scenario_id


def test_times_are_utc():
    for s in SCENARIOS:
        assert s.around.utcoffset() == timedelta(0), s.scenario_id


def test_real_case_named_for_real_cases_only():
    for s in SCENARIOS:
        if s.case_id.startswith("N"):
            assert s.real_case is None, s.scenario_id
        else:
            assert s.real_case, s.scenario_id


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.scenario_id)
def test_ticket_text_is_short_and_clean(scenario, real_names):
    assert 10 <= len(scenario.ticket) <= 500
    for name in real_names:
        assert re.search(rf"\b{re.escape(name)}\b", scenario.ticket) is None, name
    assert re.search(r"\b[BCN]\d{2}\b", scenario.ticket) is None  # no answer-key IDs in tickets


def test_index_is_out_of_the_agents_reach():
    # The answer key lives outside the bank data, and no connector refers to it.
    assert DATA_DIR not in INDEX_PATH.parents
    for path in CONNECTORS_DIR.glob("*.py"):
        source = path.read_text(encoding="utf-8")
        assert "index.json" not in source and "cases" not in source, path.name


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.scenario_id)
def test_human_answers_fit_the_fixed_questions(scenario):
    # Block 5: every scripted answer is a valid answer to one fixed question (questions.py).
    for name, entry in scenario.human_answers.items():
        question = QUESTIONS[name]  # KeyError: no fixed question for this fact
        if isinstance(entry, dict):
            assert set(entry) == {"answer", "estimate"}, name
            assert question.meaning is None, f"{name}: yes/no answers are plain text"
            assert not entry["estimate"] or question.allows_estimate, name
            answer = entry["answer"]
        else:
            assert question.meaning is not None and entry in ("yes", "no"), name  # never "unsure" in the key
            answer = entry
        assert interpret_answer(name, answer) is not None, name


# ---------- 3. against the bank data ----------


def found_sources(s):
    """Which simulated systems hold something about this scenario."""
    t = s.around
    found = set()
    if get_outage_timeline(s.service_id, t, 24).problems:
        found.add("monitoring")
    if get_client_impact(s.service_id, t - timedelta(days=7), t + timedelta(days=7)).impacts:
        found.add("client_impact")
    if get_security_alerts(t - timedelta(days=2), t + timedelta(days=5), s.service_id).alerts:
        found.add("security_alerts")
    for supplier in get_suppliers_for_service(s.service_id).suppliers:
        if get_supplier_notices(supplier.supplier_id, t - timedelta(days=7), t + timedelta(days=7)).notices:
            found.add("supplier_notices")
    return found


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.scenario_id)
def test_data_sources_match_the_bank_data(scenario):
    assert found_sources(scenario) == set(scenario.data_sources)


def test_n01_has_nothing_beyond_a_slow_portal():
    # Brief: "HR portal is slow" is solved in two steps (service list, then rules).
    # The only other trace in the bank's systems is the slowness itself in monitoring.
    assert BY_ID["N01"].data_sources == ("monitoring",)
