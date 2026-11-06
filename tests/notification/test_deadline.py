"""Initial notification deadline (docs/dora-rules.md section 5, RTS-R Art. 5)."""

import ast
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from dora_agent.notification.deadline import initial_notification_deadline

UTC = timezone.utc
BANK = "credit_institution"


def t(day, hour, minute=0):
    # November 2026: the 7th is a Saturday, the 8th a Sunday.
    return datetime(2026, 11, day, hour, minute, tzinfo=UTC)


def deadline(aware, classified, now=None, entity=BANK):
    return initial_notification_deadline(aware, classified, now or classified, entity)


# ---------- Art. 5(1)(a): 4 hours after classification, at most 24 hours after awareness ----------


def test_four_hours_after_classification():
    d = deadline(t(5, 8), t(5, 10))
    assert d.due_at == t(5, 14)
    assert not d.late_classification
    assert "Art. 5(1)(a)" in d.rule


def test_24_hour_limit_wins_when_earlier():
    # Aware 08:00 Thursday, classified 06:00 Friday: 4 hours would be 10:00, but 24 hours ends at 08:00.
    d = deadline(t(5, 8), t(6, 6))
    assert d.due_at == t(6, 8)
    assert not d.late_classification


def test_classified_at_exactly_24_hours_is_not_late():
    # Art. 5(2) is for "not classified within 24 hours". Exactly 24 hours is within, so 5(1)(a) applies.
    d = deadline(t(5, 8), t(6, 8))
    assert not d.late_classification
    assert d.due_at == t(6, 8)


def test_classified_at_same_moment_as_awareness():
    d = deadline(t(5, 8), t(5, 8))
    assert d.due_at == t(5, 12)


# ---------- Art. 5(2): late classification ----------


def test_late_classification_gets_four_hours_from_classification():
    d = deadline(t(5, 8), t(6, 10))
    assert d.late_classification
    assert d.due_at == t(6, 14)
    assert "Art. 5(2)" in d.rule


def test_one_minute_past_24_hours_is_late():
    d = deadline(t(5, 8), t(6, 8, 1))
    assert d.late_classification
    assert d.due_at == t(6, 12, 1)


# ---------- Art. 5(3): overdue ----------


def test_overdue_when_now_is_past_deadline():
    d = deadline(t(5, 8), t(5, 10), now=t(5, 14, 1))
    assert d.overdue
    assert "Art. 5(3)" in d.overdue_note


def test_not_overdue_at_the_deadline_itself():
    d = deadline(t(5, 8), t(5, 10), now=t(5, 14))
    assert not d.overdue
    assert d.overdue_note is None


# ---------- Art. 5(4) and 5(5): weekends and bank holidays ----------


def test_bank_deadline_on_a_saturday_is_not_moved():
    # Due Saturday 7 November 14:00. A credit institution gets no extension (Art. 5(5)).
    d = deadline(t(7, 8), t(7, 10))
    assert d.due_at == t(7, 14)
    assert d.due_at.weekday() == 5
    assert "Art. 5(5)" in d.weekend_note
    assert "credit institution" in d.weekend_note
    assert "holds on weekends and bank holidays" in d.weekend_note


@pytest.mark.parametrize("entity", ["central_counterparty", "trading_venue"])
def test_other_entities_named_in_art_5_5_also_get_no_extension(entity):
    d = deadline(t(7, 8), t(7, 10), entity=entity)
    assert d.due_at == t(7, 14)
    assert "Art. 5(5)" in d.weekend_note


def test_other_entity_gets_not_handled_warning():
    d = deadline(t(7, 8), t(7, 10), entity="other")
    assert d.due_at == t(7, 14)  # not moved: the tool does not apply Art. 5(4)
    assert "not handled" in d.weekend_note
    assert "Art. 5(4)" in d.weekend_note


# ---------- bad input ----------


def test_classified_before_aware_is_refused():
    with pytest.raises(ValueError, match="before"):
        deadline(t(5, 10), t(5, 8))


@pytest.mark.parametrize("field", ["aware", "classified", "now"])
def test_non_utc_time_is_refused(field):
    berlin = timezone(timedelta(hours=1))
    times = {"aware": t(5, 8), "classified": t(5, 10), "now": t(5, 10)}
    times[field] = times[field].replace(tzinfo=berlin)
    with pytest.raises(ValueError, match="UTC"):
        initial_notification_deadline(times["aware"], times["classified"], times["now"], BANK)


def test_time_without_zone_is_refused():
    with pytest.raises(ValueError, match="UTC"):
        initial_notification_deadline(datetime(2026, 11, 5, 8), t(5, 10), t(5, 10), BANK)


def test_unknown_entity_type_is_refused():
    with pytest.raises(ValueError, match="entity type"):
        deadline(t(5, 8), t(5, 10), entity="bank")


def test_deadline_is_frozen():
    d = deadline(t(5, 8), t(5, 10))
    with pytest.raises(Exception):
        d.due_at = t(9, 9)


# ---------- plain Python only (CLAUDE.md hard rule 1) ----------


def test_deadline_module_imports_no_llm_agent_or_connectors():
    path = Path(__file__).resolve().parents[2] / "src" / "dora_agent" / "notification" / "deadline.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    modules = [a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names]
    modules += [n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
    for module in modules:
        top = module.split(".")[0]
        assert top in {"__future__", "datetime", "typing", "dora_agent"}, module
        if top == "dora_agent":
            assert module.startswith("dora_agent.rules"), module
