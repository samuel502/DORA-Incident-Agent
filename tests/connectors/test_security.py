"""Security alert lookups: get_security_alerts.

Each case test checks that the alert signals fit docs/case-library.md. Whether access
counts as G-c / T5-b is decided by the rules engine after a human confirms (block 4-5).
"""

from dataclasses import replace
from datetime import datetime, timedelta

import pytest

from dora_agent.config import connector_limits
from dora_agent.connectors import InvalidQuery, get_outage_timeline, get_security_alerts


def alerts_around(service_id, around, days_before=2, days_after=5):
    centre = datetime.fromisoformat(around)
    return get_security_alerts(centre - timedelta(days=days_before), centre + timedelta(days=days_after), service_id)


def one_alert(service_id, around):
    result = alerts_around(service_id, around)
    assert result.service_known is True
    assert len(result.alerts) == 1, [a.alert_id for a in result.alerts]
    return result.alerts[0]


# ---------- attacks on Rheinbank's own systems ----------


def test_c06_ransomware_on_own_systems_with_earlier_log_evidence():
    alert = one_alert("SVC-SEC", "2026-05-12T01:10:00Z")
    assert (alert.alert_type, alert.where, alert.access_successful, alert.malicious_suspected) == (
        "ransomware", "own_systems", "yes", "yes"
    )
    assert alert.first_evidence_at < alert.detected_at  # duration starts at log time (RTS-C Art. 3(1))


def test_c10_breach_found_four_months_after_it_started():
    alert = one_alert("SVC-LOAN", "2026-07-21T07:00:00Z")
    assert alert.where == "own_systems" and alert.access_successful == "yes"
    assert alert.data_impact.confidentiality == "confirmed"
    assert alert.detected_at - alert.first_evidence_at > timedelta(days=90)


def test_c12_alert_comes_after_the_hardware_reading():
    alert = one_alert("SVC-CORE", "2026-08-26T06:00:00Z")
    problem = get_outage_timeline("SVC-CORE", "2026-08-26T06:00:00Z").problems[0]
    detected = next(e.timestamp for e in problem.events if e.event_type == "detected")
    assert alert.detected_at > detected  # first read as hardware, re-classified later
    assert alert.alert_type == "ransomware" and alert.access_successful == "yes"
    assert alert.detected_at - alert.first_evidence_at > timedelta(days=90)


# ---------- malicious, but not successful access ----------


def test_c08_ddos_is_malicious_but_no_access():
    for service_id in ("SVC-OLB", "SVC-ATM", "SVC-CARD"):  # one alert, three services
        alert = one_alert(service_id, "2026-04-30T14:30:00Z")
        assert alert.alert_type == "ddos"
        assert alert.malicious_suspected == "yes"
        assert alert.access_successful == "no"


def test_n04_phishing_click_blocked():
    alert = one_alert("SVC-MAIL", "2026-05-20T09:15:00Z")
    assert alert.access_successful == "blocked"
    assert all(level == "none" for level in alert.data_impact.model_dump().values())


# ---------- supplier systems (open question 4) ----------


@pytest.mark.parametrize(
    "service_id, around, supplier_id, confidentiality",
    [
        ("SVC-DERIV", "2026-02-02T07:00:00Z", "SUP-CLRP", "unknown"),  # C07
        ("SVC-MFT", "2026-06-05T09:00:00Z", "SUP-SDRP", "confirmed"),  # C11
        ("SVC-MFT", "2026-10-07T08:00:00Z", "SUP-FNSW", "unknown"),  # C13
    ],
)
def test_supplier_breaches_are_marked_supplier_systems(service_id, around, supplier_id, confidentiality):
    alert = one_alert(service_id, around)
    assert alert.where == "supplier_systems"
    assert alert.supplier_id == supplier_id
    assert alert.data_impact.confidentiality == confidentiality


# ---------- the brief's 2 a.m. transfer: needs a human ----------


def test_brief_night_transfer_access_unknown():
    alert = one_alert("SVC-LOAN", "2026-09-02T00:05:00Z")
    assert alert.alert_type == "data_exfiltration"
    assert alert.access_successful == "unknown"  # the agent must ask the human
    assert alert.malicious_suspected == "yes"
    assert alert.data_impact.confidentiality == "suspected"
    assert alert.destination_country == "SG" and alert.data_volume_mb > 0


# ---------- not attacks ----------


def test_c17_crashes_flagged_but_not_malicious():
    for service_id in ("SVC-OFFICE", "SVC-PAYOPS"):
        alert = one_alert(service_id, "2026-07-16T04:10:00Z")
        assert alert.alert_type == "endpoint_anomaly"
        assert alert.malicious_suspected == "no"


def test_n02_false_positive_during_outage():
    alert = one_alert("SVC-OLB", "2026-03-17T13:00:00Z")
    assert alert.status == "false_positive"
    assert alert.access_successful == "no"


@pytest.mark.parametrize(
    "service_id, around",
    [
        ("SVC-HVP", "2026-02-26T08:00:00Z"),  # C03: ECB said not a cyber attack
        ("SVC-CARD", "2026-06-01T12:35:00Z"),  # C05: hardware fault
        ("SVC-OLB", "2026-08-18T15:00:00Z"),  # C09: bank said not a cyber attack
        ("SVC-SEPA", "2026-10-01T07:30:00Z"),  # C14: cyber attack ruled out
        ("SVC-OLB", "2026-05-26T07:10:00Z"),  # brief: "security alerts (nothing)"
        ("SVC-HR", "2026-03-10T06:30:00Z"),  # N01
    ],
)
def test_cases_with_no_alerts(service_id, around):
    assert alerts_around(service_id, around).alerts == ()


# ---------- lookup behaviour ----------


def test_without_service_filter_returns_all_alerts_in_window():
    result = get_security_alerts("2026-07-01T00:00:00Z", "2026-07-31T00:00:00Z")
    assert [a.alert_id for a in result.alerts] == ["ALR-0007", "ALR-0008"]
    assert result.service_known is None


def test_window_uses_detection_time_and_includes_edges():
    assert len(get_security_alerts("2026-05-20T09:15:00Z", "2026-05-20T09:16:00Z").alerts) == 1
    assert get_security_alerts("2026-05-20T09:15:01Z", "2026-05-20T10:00:00Z").alerts == ()


def test_unknown_service_is_flagged():
    result = get_security_alerts("2026-05-01T00:00:00Z", "2026-05-31T00:00:00Z", "SVC-NOPE")
    assert result.service_known is False
    assert result.alerts == ()


def test_result_names_its_source():
    result = get_security_alerts("2026-05-12T00:00:00Z", "2026-05-13T00:00:00Z", "SVC-SEC")
    assert result.source.system == "Rheinbank security alerts (simulated SIEM)"
    assert result.source.record_ids == ("ALR-0004",)


def test_number_of_alerts_is_capped(monkeypatch):
    from dora_agent.connectors import security

    monkeypatch.setattr(security, "connector_limits", lambda: replace(connector_limits(), max_results=1))
    result = get_security_alerts("2026-07-01T00:00:00Z", "2026-07-31T00:00:00Z")
    assert [a.alert_id for a in result.alerts] == ["ALR-0007"]
    assert result.more_available is True


def test_long_analyst_notes_are_cut(monkeypatch):
    from dora_agent.connectors import _store

    alert = _store.security_alerts()[0]
    long_note = alert.model_copy(update={"analyst_note": "x" * 1500})
    monkeypatch.setattr(_store, "security_alerts", lambda: (long_note,))
    result = get_security_alerts("2026-02-01T00:00:00Z", "2026-02-03T00:00:00Z")
    assert len(result.alerts[0].analyst_note) == connector_limits().max_text_chars


# ---------- bad inputs ----------


@pytest.mark.parametrize(
    "start, end",
    [
        ("2026-01-01T00:00:00Z", "2026-02-02T00:00:01Z"),  # longer than 31 days
        ("2026-02-02T00:00:00Z", "2026-02-01T00:00:00Z"),  # end before start
        ("2026-02-01T00:00:00", "2026-02-02T00:00:00Z"),  # no time zone
        ("yesterday", "now"),
        ("9999-12-31T22:00:00-14:00", "9999-12-31T23:00:00-14:00"),  # past the end of the calendar
    ],
)
def test_rejects_bad_windows(start, end):
    with pytest.raises(InvalidQuery):
        get_security_alerts(start, end)


@pytest.mark.parametrize("bad_id", ["", "SVC-sec", "all", 1, True])
def test_rejects_bad_service_ids(bad_id):
    with pytest.raises(InvalidQuery):
        get_security_alerts("2026-05-01T00:00:00Z", "2026-05-02T00:00:00Z", bad_id)
