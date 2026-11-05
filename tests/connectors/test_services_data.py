"""Checks on data/rheinbank/services.json itself."""

import re

from dora_agent.config import DATA_DIR, connector_limits
from dora_agent.connectors import _store

CASE_ID = re.compile(r"\b[CN]\d{2}\b")


def test_service_list_loads_and_has_17_services():
    assert len(_store.services()) == 17


def test_file_is_marked_synthetic():
    assert "SYNTHETIC DATA" in (DATA_DIR / "services.json").read_text(encoding="utf-8")


def test_data_does_not_contain_case_ids():
    # The answer key lives in the test index only, so the agent can't read it from bank data.
    assert CASE_ID.search((DATA_DIR / "services.json").read_text(encoding="utf-8")) is None


def test_every_unknown_criticality_has_a_note():
    for record in _store.services():
        if record.critical_or_important == "unknown":
            assert record.criticality_note, record.service_id


def test_aliases_are_unique_per_service():
    for record in _store.services():
        lowered = [alias.lower() for alias in record.aliases]
        assert len(lowered) == len(set(lowered)), record.service_id


def test_mix_supports_gate_cases():
    # Need critical, not critical and unknown services, and regulated and not regulated ones.
    critical = {r.critical_or_important for r in _store.services()}
    regulated = {r.regulated_service for r in _store.services()}
    assert critical == {"yes", "no", "unknown"}
    assert {"yes", "no"} <= regulated


def test_config_limits_are_positive():
    limits = connector_limits()
    assert limits.max_query_chars >= 1
    assert limits.max_find_results >= 1
    assert limits.max_text_chars >= 1
