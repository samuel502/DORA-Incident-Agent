"""Client data connector: a read-only stand-in for the core banking system.

Facts it provides (docs/dora-rules.md, section 6):
- clients and counterparts using a service   -> denominators for T1-a, T1-c (RTS-C Art. 9(1)(a), (c))
- daily average number and value of payments -> base for T1-d, T1-e (RTS-C Art. 9(1)(d), (e))
- affected clients, counterparts, transactions -> T1-a to T1-e (RTS-C Art. 1)
- relevant clients or counterparts affected  -> T1-f (RTS-C Art. 1(3)); a human must confirm
- affected Member States, branches            -> T4 (RTS-C Art. 4)
- accounts with wrong balances                -> integrity signal for T5-a (RTS-C Art. 5)
Only counts, yes/no values and country codes. Never client records.
It never compares anything with a threshold. The rules engine does that.
"""

from __future__ import annotations

from datetime import date

from ..config import connector_limits
from . import _store
from ._guards import cap_text, check_date, check_service_id, check_window
from .schemas import BankProfileResult, ClientImpactResult, DailyAveragesResult, ImpactView, Source

SYSTEM = "Rheinbank core banking (simulated)"
AVERAGE_METHOD = (
    "Daily average over the previous calendar month: that month's total divided by its number of days "
    "(docs/dora-rules.md, open question 6). Client base: latest yearly snapshot on or before the incident date "
    "(open question 7)."
)


def get_bank_profile() -> BankProfileResult:
    """Basic facts about Rheinbank: home Member State, branches, total clients."""
    return BankProfileResult(profile=_store.bank_profile(), source=Source(system=SYSTEM, record_ids=("bank_profile",)))


def get_client_impact(service_id: object, start: object, end: object) -> ClientImpactResult:
    """Impact records for one service whose window overlaps [start, end]."""
    limits = connector_limits()
    wanted = check_service_id(service_id)
    begin, finish = check_window(start, end, limits.max_impact_window_days)

    hits = [
        impact
        for impact in _store.client_impacts()
        if impact.service_id == wanted and impact.window_start <= finish and impact.window_end >= begin
    ]
    hits.sort(key=lambda impact: (impact.window_start, impact.impact_id))
    shown = hits[: limits.max_results]

    views = tuple(
        ImpactView(
            impact_id=i.impact_id,
            window_start=i.window_start,
            window_end=i.window_end,
            affected_clients=i.affected_clients,
            affected_counterparts=i.affected_counterparts,
            affected_tx_count=i.affected_tx_count,
            affected_tx_value_eur=i.affected_tx_value_eur,
            accounts_with_balance_errors=i.accounts_with_balance_errors,
            relevant_parties_affected=i.relevant_parties_affected,
            affected_member_states=i.affected_member_states,
            is_estimate=i.is_estimate,
            estimate_basis=cap_text(i.estimate_basis, limits.max_text_chars),
        )
        for i in shown
    )
    return ClientImpactResult(
        service_known=wanted in _store.service_ids(),
        impacts=views,
        more_available=len(hits) > len(shown),
        source=Source(system=SYSTEM, record_ids=tuple(i.impact_id for i in shown)),
    )


def _previous_month(day: date) -> str:
    year, month = (day.year - 1, 12) if day.month == 1 else (day.year, day.month - 1)
    return f"{year}-{month:02d}"


def get_daily_averages(service_id: object, incident_date: object) -> DailyAveragesResult:
    """Daily averages from the previous calendar month, plus the client base, for one service.

    Method approved in docs/dora-rules.md, open question 6.
    """
    wanted = check_service_id(service_id)
    day = check_date(incident_date, "incident_date")
    month = _previous_month(day)

    average = next((a for a in _store.daily_averages() if a.service_id == wanted and a.month == month), None)
    snapshots = [s for s in _store.client_base() if s.service_id == wanted and s.as_of <= day]
    snapshot = max(snapshots, key=lambda s: s.as_of) if snapshots else None

    record_ids = tuple(r for r in (average and average.average_id, snapshot and snapshot.snapshot_id) if r)
    return DailyAveragesResult(
        service_known=wanted in _store.service_ids(),
        month_used=month,
        method=AVERAGE_METHOD,
        days_counted=average.days_counted if average else None,
        daily_avg_tx_count=average.daily_avg_tx_count if average else None,
        daily_avg_tx_value_eur=average.daily_avg_tx_value_eur if average else None,
        client_base_as_of=snapshot.as_of if snapshot else None,
        total_clients_using_service=snapshot.total_clients_using_service if snapshot else None,
        active_counterparts=snapshot.active_counterparts if snapshot else None,
        source=Source(system=SYSTEM, record_ids=record_ids),
    )
