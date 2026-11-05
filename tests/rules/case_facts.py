"""Hand-built fact sets for every scenario in cases/scenarios/index.json.

Two kinds of facts, kept apart on purpose:

1. System facts, read directly from data/rheinbank/ for the records named per case below
   (service list, monitoring problem, client impact, client totals, daily averages, security alert).
   Client totals: latest yearly snapshot on or before the incident date (open question 7).
   Daily averages: previous calendar month (open question 6).
2. Scripted human answers for the judgment calls (section 7), taken only from what
   docs/case-library.md marks "Met" or "Not met". "Likely" and "Unknown" stay unknown.

Block 4 tests the rules engine only. The agent that collects these facts is block 5.
"""

from __future__ import annotations

import json
from datetime import date, datetime
from pathlib import Path

from dora_agent.rules import Fact, IncidentFacts

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data" / "rheinbank"
INDEX = ROOT / "cases" / "scenarios" / "index.json"

# Time of the check: after every scenario has ended.
AS_OF = datetime.fromisoformat("2026-11-05T12:00:00+00:00")

TESTER = "test-human"  # stands in for the person who confirms judgment calls


def _load(name: str) -> dict:
    return json.loads((DATA / name).read_text(encoding="utf-8"))


def _time(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def human(value, estimate=False):
    if isinstance(value, bool):
        return Fact[bool](value=value, source="human", confirmed_by=TESTER)
    return Fact[int](value=value, source="human", confirmed_by=TESTER, is_estimate=estimate)


def scenarios() -> list[dict]:
    return json.loads(INDEX.read_text(encoding="utf-8"))["scenarios"]


# ---------- system facts ----------


def _service_facts(service_id: str) -> dict:
    service = next(s for s in _load("services.json")["services"] if s["service_id"] == service_id)
    out = {}
    for field in ("critical_or_important", "regulated_service"):
        if service[field] in ("yes", "no"):
            out[field] = Fact[bool](value=service[field] == "yes", source="service_list")
    return out


EVENT_TO_FACT = {
    "incident_start": "incident_start",
    "detected": "detected_at",
    "unavailable_full": "downtime_start",
    "unavailable_partial": "downtime_start",
    "restored": "service_restored_at",
    "backlog_cleared": "backlog_cleared_at",
    "resolved": "resolved_at",
    "planned_maintenance_end": "planned_window_end",
}


def _monitoring_facts(problem_id: str) -> dict:
    problem = next(p for p in _load("monitoring_events.json")["problems"] if p["problem_id"] == problem_id)
    out = {}
    for event in problem["events"]:
        name = EVENT_TO_FACT.get(event["event_type"])
        if name and name not in out:  # first event of each kind
            out[name] = Fact[datetime](value=_time(event["timestamp"]), source="monitoring")
    return out


def _alert_facts(alert_id: str) -> dict:
    alerts = _load("security_alerts.json")
    records = next(v for k, v in alerts.items() if k != "about")
    alert = next(a for a in records if a["alert_id"] == alert_id)
    if alert["first_evidence_at"]:
        # RTS-C Art. 3(1): logs showing an earlier start.
        return {"earliest_log_at": Fact[datetime](value=_time(alert["first_evidence_at"]), source="security_alerts")}
    return {}


def _impact_facts(impact_id: str, service_id: str, around: datetime) -> dict:
    impact = next(i for i in _load("client_impact.json")["impacts"] if i["impact_id"] == impact_id)
    est = impact["is_estimate"]
    out = {}
    for field in ("affected_clients", "affected_counterparts", "affected_tx_count", "affected_tx_value_eur"):
        if impact[field] is not None:
            out[field] = Fact[int](value=impact[field], source="client_data", is_estimate=est)
    if impact["affected_member_states"] is not None:
        out["affected_member_states"] = Fact[tuple[str, ...]](
            value=tuple(impact["affected_member_states"]), source="client_data", is_estimate=est)
    if impact["relevant_parties_affected"] in ("yes", "no"):
        # A judgment call (section 7): the engine ignores it until a human confirms.
        out["relevant_parties_affected"] = Fact[bool](
            value=impact["relevant_parties_affected"] == "yes", source="client_data")

    # Open question 7: latest yearly snapshot on or before the incident date.
    snaps = [s for s in _load("client_base.json")["snapshots"]
             if s["service_id"] == service_id and date.fromisoformat(s["as_of"]) <= around.date()]
    if snaps:
        snap = max(snaps, key=lambda s: s["as_of"])
        if snap["total_clients_using_service"] is not None:
            out["total_clients"] = Fact[int](value=snap["total_clients_using_service"], source="client_data")
        if snap["active_counterparts"] is not None:
            out["total_counterparts"] = Fact[int](value=snap["active_counterparts"], source="client_data")

    # Open question 6: daily average over the previous calendar month.
    year, month = (around.year, around.month - 1) if around.month > 1 else (around.year - 1, 12)
    key = f"{year:04d}-{month:02d}"
    avg = next((a for a in _load("daily_averages.json")["averages"]
                if a["service_id"] == service_id and a["month"] == key), None)
    if avg:
        out["daily_avg_tx_count"] = Fact[int](value=avg["daily_avg_tx_count"], source="client_data")
        out["daily_avg_tx_value_eur"] = Fact[int](value=avg["daily_avg_tx_value_eur"], source="client_data")
    return out


# ---------- per-case records and human answers ----------

T2_MEDIA = {"media_coverage": human(True)}
T2_ALL_NO = {name: human(False) for name in
             ("media_coverage", "repeated_complaints", "regulatory_requirements_impact", "client_loss_impact")}
NO_DATA_IMPACT = {name: human(False) for name in
                  ("data_availability_impact", "data_authenticity_impact",
                   "data_integrity_impact", "data_confidentiality_impact")}
NO_ATTACK = {"malicious_access": human(False)}
OWN_SYSTEMS_ATTACK = {"malicious_access": human(True), "access_on_own_systems": human(True),
                      "access_may_cause_data_loss": human(True)}
SUPPLIER_ATTACK = {"malicious_access": human(True), "access_on_own_systems": human(False)}  # open question 4
# Constructed cases say "nothing else": the human confirms no relevant parties and no counterparts hit.
NOTHING_ELSE_T1 = {"relevant_parties_affected": human(False), "affected_counterparts": human(0)}

# scenario_id: (monitoring problem, client impact, security alert, human answers)
CASES: dict[str, tuple[str | None, str | None, str | None, dict]] = {
    # C01: T2-a, T2-b; T6 "redress alone far over EUR 100,000" (estimate).
    "C01": ("PRB-0002", "IMP-0001", None,
            {**T2_MEDIA, "repeated_complaints": human(True), "costs_eur": human(1_000_000, estimate=True)}),
    # C02: T2-a, T2-b. T6 only likely, so unknown.
    "C02": ("PRB-0005", "IMP-0002", None, {**T2_MEDIA, "repeated_complaints": human(True)}),
    # C03: T5-a not met (no data loss). T2 and T6 unknown.
    "C03": ("PRB-0007", "IMP-0004", None, {**NO_DATA_IMPACT, **NO_ATTACK}),
    # C04: T2-a; T6 compensation far over EUR 100,000 (estimate).
    "C04": ("PRB-0012", "IMP-0007", None, {**T2_MEDIA, "costs_eur": human(5_000_000, estimate=True)}),
    # C05: T2-a. T5-a not met. T6 only likely.
    "C05": ("PRB-0019", "IMP-0013", None, {**T2_MEDIA, **NO_DATA_IMPACT}),
    # C06: G-c and T5-b, confirmed by a human.
    "C06": ("PRB-0017", "IMP-0010", "ALR-0004", dict(OWN_SYSTEMS_ATTACK)),
    # C07: supplier's systems, not the bank's (open question 4). T2-a.
    "C07": ("PRB-0006", "IMP-0003", None, {**SUPPLIER_ATTACK, **T2_MEDIA}),
    # C08: DDoS is not access (G-c / T5-b not met). T2-a.
    "C08": ("PRB-0014", "IMP-0009", None, {**NO_ATTACK, **T2_MEDIA}),
    # C09: T2-a and T2-c. T5-a only likely.
    "C09": ("PRB-0025", "IMP-0017", None, {**T2_MEDIA, "regulatory_requirements_impact": human(True)}),
    # C10: G-c and T5-b.
    "C10": (None, "IMP-0006", "ALR-0008", dict(OWN_SYSTEMS_ATTACK)),
    # C11: supplier's systems; T2-a. Gate (is SVC-MFT critical?) left open: the service list says "unknown".
    "C11": (None, "IMP-0012", None, {**SUPPLIER_ATTACK, **T2_MEDIA}),
    # C12: G-c and T5-b.
    "C12": ("PRB-0027", None, "ALR-0009", dict(OWN_SYSTEMS_ATTACK)),
    # C13: supplier's systems. Everything else unknown.
    "C13": (None, "IMP-0018", None, dict(SUPPLIER_ATTACK)),
    # C14: T2-a and T2-b.
    "C14": ("PRB-0030", "IMP-0019", None, {**T2_MEDIA, "repeated_complaints": human(True)}),
    # C15: T2-a.
    "C15": ("PRB-0032", "IMP-0020", None, dict(T2_MEDIA)),
    # C16-A and C16-B: the human confirms the window was planned and announced.
    "C16-A": ("PRB-0028", None, None, {"planned_and_announced": human(True)}),
    "C16-B": ("PRB-0029", None, None, {"planned_and_announced": human(True)}),
    # C17-A: not an attack (ALR-0007 says no access).
    "C17-A": ("PRB-0021", None, None, dict(NO_ATTACK)),
    # C17-B: T3 and T4 from the data.
    "C17-B": ("PRB-0022", "IMP-0015", None, dict(NO_ATTACK)),
    # N01: HR, no attack.
    "N01": ("PRB-0009", None, None, dict(NO_ATTACK)),
    # N02: no media, a handful of complaints (not "repeated" in the T2-b sense), no data loss, about EUR 5,000.
    "N02": ("PRB-0010", "IMP-0005", None,
            {**NO_ATTACK, **T2_ALL_NO, **NO_DATA_IMPACT, **NOTHING_ELSE_T1, "costs_eur": human(5_000)}),
    # N03: only T3-b; no media, no data loss, about EUR 20,000, Germany only.
    "N03": ("PRB-0013", "IMP-0008", None,
            {**NO_ATTACK, **T2_ALL_NO, **NO_DATA_IMPACT, **NOTHING_ELSE_T1, "costs_eur": human(20_000)}),
    # N04: phishing, login blocked: no successful access.
    "N04": (None, None, None, dict(NO_ATTACK)),
    # N05: T2-a and T6 about EUR 140,000 (estimate).
    "N05": ("PRB-0020", "IMP-0014", None,
            {**NO_ATTACK, **T2_MEDIA, "costs_eur": human(140_000, estimate=True)}),
    # N06: exactly 10% of clients; nothing else.
    "N06": ("PRB-0023", "IMP-0016", None, {**NO_ATTACK, **T2_ALL_NO, **NO_DATA_IMPACT, **NOTHING_ELSE_T1}),
    # B01: system facts only.
    "B01": ("PRB-0018", "IMP-0011", None, {}),
    # B03: SOC alert ALR-0010 says malicious, success unknown. Not yet confirmed by a human.
    "B03": (None, None, None, {"malicious_access": Fact[bool](value=True, source="security_alerts"),
                               "access_on_own_systems": Fact[bool](value=True, source="security_alerts")}),
}


def build_facts(scenario: dict, extra: dict | None = None) -> IncidentFacts:
    problem_id, impact_id, alert_id, answers = CASES[scenario["scenario_id"]]
    around = _time(scenario["around"])
    facts: dict = {}
    facts.update(_service_facts(scenario["service_id"]))
    if problem_id:
        facts.update(_monitoring_facts(problem_id))
    if alert_id:
        facts.update(_alert_facts(alert_id))
    if impact_id:
        facts.update(_impact_facts(impact_id, scenario["service_id"], around))
    facts.update(answers)
    facts.update(extra or {})
    return IncidentFacts(service_id=scenario["service_id"], **facts)
