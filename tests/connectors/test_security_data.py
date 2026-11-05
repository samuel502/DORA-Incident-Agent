"""Checks on data/rheinbank/security_alerts.json itself."""

import json
import re
from datetime import timedelta

import pytest

from dora_agent.config import DATA_DIR
from dora_agent.connectors import _store
from dora_agent.connectors.schemas import SecurityAlertsFile

RAW = (DATA_DIR / "security_alerts.json").read_text(encoding="utf-8")
CASE_ID = re.compile(r"\b[CN]\d{2}\b")


def test_alerts_file_loads():
    assert len(_store.security_alerts()) == 11


def test_marked_synthetic_and_no_case_ids():
    assert "SYNTHETIC DATA" in RAW
    assert CASE_ID.search(RAW) is None


def test_all_times_utc_and_ids_in_detection_order():
    alerts = _store.security_alerts()
    for alert in alerts:
        assert alert.detected_at.utcoffset() == timedelta(0)
        if alert.first_evidence_at:
            assert alert.first_evidence_at.utcoffset() == timedelta(0)
    assert [a.alert_id for a in alerts] == sorted(a.alert_id for a in alerts)
    assert [a.detected_at for a in alerts] == sorted(a.detected_at for a in alerts)


def test_data_covers_every_access_outcome_and_location():
    alerts = _store.security_alerts()
    assert {a.access_successful for a in alerts} == {"yes", "no", "blocked", "unknown"}
    assert {"own_systems", "supplier_systems"} <= {a.where for a in alerts}


def _broken(change):
    doc = json.loads(RAW)
    change(doc["alerts"][1])  # an own-systems alert
    return json.dumps(doc)


@pytest.mark.parametrize(
    "change",
    [
        lambda a: a.update(where="supplier_systems"),  # supplier breach without supplier_id
        lambda a: a.update(supplier_id="SUP-CLRP"),  # supplier_id on an own-systems alert
        lambda a: a.update(first_evidence_at="2026-12-31T00:00:00Z"),  # evidence after detection
        lambda a: a.update(access_successful="probably"),
        lambda a: a.update(data_impact={"availability": "lots", "authenticity": "none",
                                        "integrity": "none", "confidentiality": "none"}),
        lambda a: a.update(service_ids=[]),
        lambda a: a.update(detected_at="2026-03-17T14:05:00+01:00"),  # not UTC
        lambda a: a.update(attacker_ip="203.0.113.7"),  # unknown field
    ],
)
def test_schema_rejects_broken_data(change):
    with pytest.raises(ValueError):
        SecurityAlertsFile.model_validate_json(_broken(change))
