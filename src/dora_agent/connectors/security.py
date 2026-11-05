"""Security alerts connector: a read-only stand-in for a SIEM such as Splunk or Sentinel.

Facts it provides (docs/dora-rules.md, section 6), as signals for a human to confirm:
- access successful, malicious, on own systems -> G-c (RTS-C Art. 6(c)) and T5-b (RTS-C Art. 9(5)(b))
- where: own systems or a supplier's           -> open question 4 (supplier breaches are not G-c/T5-b)
- the four data impacts                        -> T5-a (RTS-C Art. 9(5)(a), Art. 5)
- first evidence in the logs                   -> duration start (RTS-C Art. 3(1))
Alerts are signals, not decisions. A human must confirm malicious access (section 7).
"""

from __future__ import annotations

from ..config import connector_limits
from . import _store
from ._guards import cap_text, check_service_id, check_window
from .schemas import AlertView, SecurityAlertsResult, Source

SYSTEM = "Rheinbank security alerts (simulated SIEM)"


def get_security_alerts(start: object, end: object, service_id: object = None) -> SecurityAlertsResult:
    """Alerts detected between start and end, optionally only those touching one service."""
    limits = connector_limits()
    begin, finish = check_window(start, end, limits.max_alert_window_days)
    wanted = None if service_id is None else check_service_id(service_id)

    hits = [
        alert
        for alert in _store.security_alerts()
        if begin <= alert.detected_at <= finish and (wanted is None or wanted in alert.service_ids)
    ]
    hits.sort(key=lambda alert: (alert.detected_at, alert.alert_id))
    shown = hits[: limits.max_results]

    views = tuple(
        AlertView(
            alert_id=a.alert_id,
            detected_at=a.detected_at,
            first_evidence_at=a.first_evidence_at,
            severity=a.severity,
            alert_type=a.alert_type,
            service_ids=a.service_ids,
            where=a.where,
            supplier_id=a.supplier_id,
            access_successful=a.access_successful,
            malicious_suspected=a.malicious_suspected,
            data_impact=a.data_impact,
            data_volume_mb=a.data_volume_mb,
            destination_country=a.destination_country,
            status=a.status,
            analyst_note=cap_text(a.analyst_note, limits.max_text_chars),
        )
        for a in shown
    )
    return SecurityAlertsResult(
        service_known=None if wanted is None else wanted in _store.service_ids(),
        alerts=views,
        more_available=len(hits) > len(shown),
        source=Source(system=SYSTEM, record_ids=tuple(a.alert_id for a in shown)),
    )
