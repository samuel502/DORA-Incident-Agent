"""Fields of the initial notification that code fills in (docs/dora-rules.md section 10)."""

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from dora_agent.notification.entity import SYNTHETIC_LEI_NOTE, reporting_entity
from dora_agent.notification.fields import (
    CATALOGUE,
    CRITERIA,
    DISCOVERY_CHOICES,
    FIELD_NUMBERS,
    NotMajor,
    code_fields,
)
from dora_agent.rules import Fact, IncidentFacts, classify

UTC = timezone.utc
AS_OF = datetime(2026, 11, 5, 12, 0, tzinfo=UTC)
CLASSIFIED = datetime(2026, 11, 5, 10, 30, tzinfo=UTC)
RULE_SHEET = Path(__file__).resolve().parents[2] / "docs" / "dora-rules.md"


def system(value, source="service_list", **extra):
    return Fact(value=value, source=source, **extra)


def human(value):
    return Fact(value=value, source="human", confirmed_by="test-human")


def short_outage():
    """30 minutes down, resolved after an hour: T3 is not met (RTS-C Art. 9(3))."""
    return dict(
        incident_start=system(datetime(2026, 11, 5, 8, 0, tzinfo=UTC), source="monitoring"),
        downtime_start=system(datetime(2026, 11, 5, 8, 0, tzinfo=UTC), source="monitoring"),
        service_restored_at=system(datetime(2026, 11, 5, 8, 30, tzinfo=UTC), source="monitoring"),
        resolved_at=system(datetime(2026, 11, 5, 9, 0, tzinfo=UTC), source="monitoring"),
    )


def t5b_facts(**extra):
    """Major through T5-b alone: confirmed malicious access to own systems that may cause data loss."""
    base = dict(
        service_id="SVC-OLB",
        critical_or_important=system(True),
        malicious_access=human(True),
        access_on_own_systems=human(True),
        access_may_cause_data_loss=human(True),
        detected_at=system(datetime(2026, 11, 5, 8, 0, tzinfo=UTC), source="security_alerts"),
        **short_outage(),
    )
    base.update(extra)
    return IncidentFacts(**base)


def t1_t4_facts(states=("DE", "AT")):
    """Major through T1 (over 100,000 clients) and T4 (two Member States)."""
    return IncidentFacts(
        service_id="SVC-OLB",
        critical_or_important=system(True),
        malicious_access=human(False),
        affected_clients=system(150_000, source="client_data"),
        total_clients=system(1_000_000, source="client_data"),
        affected_member_states=system(tuple(states), source="client_data"),
        detected_at=system(datetime(2026, 11, 5, 8, 0, tzinfo=UTC), source="monitoring"),
        **short_outage(),
    )


def build(facts, run_id="abc123def456", classified_at=CLASSIFIED):
    result = classify(facts, AS_OF)
    assert result.result == "major", result.summary
    return {f.number: f for f in code_fields(result, run_id=run_id, classified_at=classified_at,
                                             entity=reporting_entity(), entity_type="credit_institution")}


# ---------- only for major incidents ----------


def test_not_major_gives_no_fields():
    facts = IncidentFacts(service_id="SVC-OLB", critical_or_important=system(False),
                          regulated_service=system(False), malicious_access=human(False))
    result = classify(facts, AS_OF)
    assert result.result == "not_major"
    with pytest.raises(NotMajor):
        code_fields(result, run_id="abc", classified_at=CLASSIFIED, entity=reporting_entity(),
                    entity_type="credit_institution")


def test_undetermined_gives_no_fields():
    result = classify(IncidentFacts(service_id="SVC-OLB"), AS_OF)
    assert result.result == "undetermined"
    with pytest.raises(NotMajor):
        code_fields(result, run_id="abc", classified_at=CLASSIFIED, entity=reporting_entity(),
                    entity_type="credit_institution")


# ---------- every field, in order ----------


def test_all_25_fields_in_regulation_order():
    fields = build(t5b_facts())
    assert list(fields) == list(FIELD_NUMBERS)
    assert len(fields) == 25


def test_catalogue_matches_rule_sheet_section_10():
    section = RULE_SHEET.read_text(encoding="utf-8").split("## 10. Content of the initial notification")[1]
    for number, name, mandatory, _ in CATALOGUE:
        row = next((line for line in section.splitlines()
                    if re.match(rf"^\| {re.escape(number)}( |, | to )", line)
                    or re.match(rf"^\| [\d.]+ to [\d.]+ \|", line) and _in_range(line, number)
                    or re.match(rf"^\| [\d.]+, {re.escape(number)} \|", line)), None)
        assert row, f"field {number} not in rule sheet section 10"
        assert ("| Mandatory |" in row) == mandatory, number


def _in_range(line, number):
    low, high = re.match(r"^\| ([\d.]+) to ([\d.]+) \|", line).groups()
    section, n = number.split(".")
    return low.split(".")[0] == section and int(low.split(".")[1]) <= int(n) <= int(high.split(".")[1])


def test_choice_lists_match_rule_sheet():
    text = RULE_SHEET.read_text(encoding="utf-8")
    row_25 = next(line for line in text.splitlines() if line.startswith("| 2.5 |"))
    row_27 = next(line for line in text.splitlines() if line.startswith("| 2.7 |"))
    for criterion in CRITERIA:
        assert criterion in row_25, criterion
    for choice in DISCOVERY_CHOICES:
        assert choice in row_27, choice
    assert len(CRITERIA) == 7 and len(DISCOVERY_CHOICES) == 11


# ---------- section 1 ----------


def test_section_1_from_synthetic_entity_file():
    f = build(t5b_facts())
    assert f["1.1"].value == "initial notification"
    assert f["1.2"].value == "Rheinbank AG"
    assert f["1.3"].value == "FAKE00RHEINBANK00000"
    assert f["1.3"].note == SYNTHETIC_LEI_NOTE
    assert "SYNTHETIC" in f["1.3"].note
    assert f["1.4"].value == "credit institution"
    assert f["1.8"].value.endswith(".example")
    assert f["1.9"].value.startswith("+49 0")
    assert f["1.12"].value.startswith("+49 0")
    assert f["1.15"].value == "EUR"
    for number in ("1.5", "1.6", "1.13", "1.14"):
        assert f[number].status == "not_applicable" and f[number].value is None
    for number in [n for n in FIELD_NUMBERS if n.startswith("1.")]:
        assert f[number].filled_by == "code"


# ---------- section 2 ----------


def test_reference_and_times():
    f = build(t5b_facts())
    assert f["2.1"].value == "RHB-abc123def456"
    assert f["2.2"].value == "2026-11-05T08:00:00Z"
    assert "security_alerts" in f["2.2"].source
    assert f["2.3"].value == "2026-11-05T10:30:00Z"
    assert "rules engine" in f["2.3"].source
    assert "1.3" in f["2.3"].note  # rule version


def test_estimated_detection_time_is_marked():
    f = build(t5b_facts(detected_at=system(datetime(2026, 11, 5, 8, 0, tzinfo=UTC), source="monitoring",
                                           is_estimate=True)))
    assert "estimate" in f["2.2"].note


def test_unknown_detection_time_waits_for_human():
    facts = t5b_facts(detected_at=Fact[datetime]())
    f = build(facts)
    assert f["2.2"].status == "waiting" and f["2.2"].value is None


def test_t5b_major_criteria():
    f = build(t5b_facts())
    assert f["2.5"].value == ("data losses", "critical services affected")
    assert f["2.5"].filled_by == "code"


def test_t1_t4_major_criteria_and_member_states():
    f = build(t1_t4_facts())
    assert f["2.5"].value == ("clients, financial counterparts and transactions affected",
                              "geographical spread", "critical services affected")
    assert f["2.6"].status == "filled"
    assert f["2.6"].value == ("AT", "DE")


def test_member_states_outside_eu_are_left_out_and_noted():
    f = build(t1_t4_facts(states=("DE", "AT", "CH")))
    assert f["2.6"].value == ("AT", "DE")
    assert "CH" in f["2.6"].note


def test_member_states_not_applicable_without_t4():
    f = build(t5b_facts())
    assert f["2.6"].status == "not_applicable"


def test_ai_and_human_fields_wait_empty():
    f = build(t5b_facts())
    assert f["2.4"].filled_by == "ai_draft" and f["2.4"].status == "waiting" and f["2.4"].value is None
    for number in ("2.7", "2.8", "2.9", "2.10"):
        assert f[number].filled_by == "human"
        assert f[number].status == "waiting" and f[number].value is None
    assert "under investigation" in f["2.4"].note


def test_fields_are_frozen():
    f = build(t5b_facts())
    with pytest.raises(Exception):
        f["2.3"].value = "2026-01-01T00:00:00Z"


# ---------- bad input ----------


def test_non_utc_classification_time_is_refused():
    with pytest.raises(Exception):
        build(t5b_facts(), classified_at=CLASSIFIED.astimezone(timezone(timedelta(hours=1))))


@pytest.mark.parametrize("run_id", ["", "abc def", "abc\n123", "x" * 41, "../log"])
def test_bad_run_id_is_refused(run_id):
    with pytest.raises(ValueError, match="run_id"):
        build(t5b_facts(), run_id=run_id)


def test_unknown_entity_type_is_refused():
    result = classify(t5b_facts(), AS_OF)
    with pytest.raises(ValueError, match="entity type"):
        code_fields(result, run_id="abc", classified_at=CLASSIFIED, entity=reporting_entity(), entity_type="bank")


# ---------- plain Python only ----------


def test_fields_module_imports_no_llm_agent_or_connectors():
    import ast
    path = Path(__file__).resolve().parents[2] / "src" / "dora_agent" / "notification" / "fields.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    modules = [a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names]
    modules += [n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
    for module in modules:
        assert not module.startswith(("dora_agent.llm", "dora_agent.agent", "dora_agent.connectors")), module
