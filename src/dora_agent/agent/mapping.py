"""Plain code that turns connector results into facts. The LLM is not involved here.

Each function takes one record a connector returned and writes system facts into the store,
with the system as the source. The rules for which field feeds which fact follow
docs/dora-rules.md section 6 ("Facts the agent must collect").

Judgment calls (section 7) such as "malicious access" are written as system signals only:
the engine ignores them until a human confirms. Everything a system does not know stays unknown.

Deliberately NOT mapped (shown to the LLM as information only, never turned into facts):
- supplier register and supplier notices: they describe the supplier's incident, not the bank's.
  The LLM may suggest a fact from them, which a human then confirms.
- the bank profile.
"""

from __future__ import annotations

from dora_agent.agent.fact_store import FactStore
from dora_agent.connectors.schemas import AlertView, DailyAveragesResult, ImpactView, ProblemView, ServiceView

# Monitoring event types -> facts (RTS-C Art. 3, section 3 T3; open question 8 for the planned end).
# The first event of each kind in the record is used.
EVENT_FACTS = {
    "incident_start": "incident_start",  # Art. 3(1)
    "detected": "detected_at",  # Art. 3(1), 3(2): fallback start
    "unavailable_full": "downtime_start",  # Art. 3(2)
    "unavailable_partial": "downtime_start",  # Art. 3(2): partly unavailable also starts downtime
    "restored": "service_restored_at",  # Art. 3(2)
    "backlog_cleared": "backlog_cleared_at",  # Art. 3(2)
    "resolved": "resolved_at",  # Art. 3(1)
    "planned_maintenance_end": "planned_window_end",  # open question 8
}

_YES_NO = {"yes": True, "no": False}  # "unknown" -> stays unknown


def map_service(store: FactStore, service: ServiceView) -> list[str]:
    """Service list -> gate facts G-a and G-b (section 2, RTS-C Art. 6(a), (b)); also used by T3-b."""
    store.record_service(service.service_id)
    return _record(store, "service_list", {
        "critical_or_important": _YES_NO.get(service.critical_or_important),
        "regulated_service": _YES_NO.get(service.regulated_service),
    })


def map_problem(store: FactStore, problem: ProblemView) -> list[str]:
    """Monitoring -> incident and downtime times (T3), and the planned window (open questions 5 and 8)."""
    values: dict = {}
    for event in problem.events:
        name = EVENT_FACTS.get(event.event_type)
        if name and name not in values:
            values[name] = event.timestamp
    planned = [e for e in problem.events if e.event_type.startswith("planned_")]
    if planned:
        # Signal only: "planned and announced" is a judgment call a human confirms (section 7).
        values["planned_and_announced"] = all(e.announced for e in planned)
    return _record(store, "monitoring", values)


def map_impact(store: FactStore, impact: ImpactView) -> list[str]:
    """Client data -> T1 counts (RTS-C Art. 9(1), Art. 1) and T4 Member States (Art. 9(4))."""
    estimate = impact.is_estimate  # RTS-C Art. 1(5): estimates are marked
    note = f"estimate: {impact.estimate_basis}" if estimate and impact.estimate_basis else None
    names = _record(store, "client_data", {
        "affected_clients": impact.affected_clients,
        "affected_counterparts": impact.affected_counterparts,
        "affected_tx_count": impact.affected_tx_count,
        "affected_tx_value_eur": impact.affected_tx_value_eur,
        "affected_member_states": impact.affected_member_states,
    }, is_estimate=estimate, note=note)
    # Signals for judgment calls (a human confirms): T1-f, and the integrity part of T5-a (RTS-C Art. 5).
    signals = {"relevant_parties_affected": _YES_NO.get(impact.relevant_parties_affected)}
    if impact.accounts_with_balance_errors:
        signals["data_integrity_impact"] = True
    return names + _record(store, "client_data", signals)


def map_daily_averages(store: FactStore, result: DailyAveragesResult) -> list[str]:
    """Client data baseline -> T1 denominators. The connector already applies open questions 6 and 7."""
    note = f"daily average from {result.month_used}; client base as of {result.client_base_as_of}"
    return _record(store, "client_data", {
        "total_clients": result.total_clients_using_service,
        "total_counterparts": result.active_counterparts,
        "daily_avg_tx_count": result.daily_avg_tx_count,
        "daily_avg_tx_value_eur": result.daily_avg_tx_value_eur,
    }, note=note)


# Security alert access result -> malicious access signal (G-c, T5-b). A human always confirms.
_ACCESS = {"yes": True, "no": False, "blocked": False}
_WHERE = {"own_systems": True, "supplier_systems": False}  # open question 4
_DATA_IMPACT = {"confirmed": True, "none": False}  # "suspected" and "unknown" stay unknown


def map_alert(store: FactStore, alert: AlertView) -> list[str]:
    """Security alerts -> signals for G-c, T5-b, open question 4 and T5-a, and the log start time (Art. 3(1))."""
    malicious = None
    if alert.status == "false_positive":
        malicious = False
    elif _ACCESS.get(alert.access_successful) is False:
        malicious = False  # not successful: no G-c, no T5-b (case N04)
    elif alert.access_successful == "yes" and alert.malicious_suspected == "yes":
        malicious = True
    values = {
        "malicious_access": malicious,
        "access_on_own_systems": _WHERE.get(alert.where),
        "earliest_log_at": alert.first_evidence_at,
        "data_availability_impact": _DATA_IMPACT.get(alert.data_impact.availability),
        "data_authenticity_impact": _DATA_IMPACT.get(alert.data_impact.authenticity),
        "data_integrity_impact": _DATA_IMPACT.get(alert.data_impact.integrity),
        "data_confidentiality_impact": _DATA_IMPACT.get(alert.data_impact.confidentiality),
    }
    # The alert's detection time is used only if monitoring has not given one.
    if not store.has_value("detected_at"):
        values["detected_at"] = alert.detected_at
    return _record(store, "security_alerts", values)


def _record(store: FactStore, source: str, values: dict, *, is_estimate: bool = False,
            note: str | None = None) -> list[str]:
    recorded = []
    for name, value in values.items():
        if value is not None:
            store.record_system(name, value, source, is_estimate=is_estimate, note=note)
            recorded.append(name)
    return recorded
