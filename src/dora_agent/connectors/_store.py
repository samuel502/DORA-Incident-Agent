"""Loads Rheinbank's simulated data files. Read-only.

CLAUDE.md hard rule 3: no tool may write, change or delete data.
- Files are only ever opened for reading.
- Each file is parsed once, checked against its fixed schema, and cached.
- The cached records are frozen objects in tuples, so no caller can change them.
"""

from __future__ import annotations

from functools import lru_cache

from ..config import DATA_DIR
from .schemas import (
    BankProfile,
    BankProfileFile,
    ClientBaseFile,
    ClientBaseSnapshot,
    ClientImpact,
    ClientImpactFile,
    DailyAverage,
    DailyAveragesFile,
    MonitoringFile,
    MonitoringProblem,
    SecurityAlert,
    SecurityAlertsFile,
    ServiceRecord,
    ServicesFile,
    SupplierNotice,
    SupplierNoticesFile,
    SupplierRecord,
    SuppliersFile,
)


def _read_text(file_name: str) -> str:
    path = DATA_DIR / file_name
    with path.open("r", encoding="utf-8") as handle:
        return handle.read()


@lru_cache(maxsize=1)
def services() -> tuple[ServiceRecord, ...]:
    records = ServicesFile.model_validate_json(_read_text("services.json")).services
    ids = [record.service_id for record in records]
    if len(ids) != len(set(ids)):
        raise ValueError("services.json contains a duplicate service_id")
    return records


def service_ids() -> frozenset[str]:
    return frozenset(record.service_id for record in services())


@lru_cache(maxsize=1)
def monitoring_problems() -> tuple[MonitoringProblem, ...]:
    problems = MonitoringFile.model_validate_json(_read_text("monitoring_events.json")).problems
    problem_ids = [p.problem_id for p in problems]
    event_ids = [e.event_id for p in problems for e in p.events]
    _check_references("monitoring_events.json", problem_ids + event_ids, {p.service_id for p in problems})
    return problems


def _check_references(file_name: str, record_ids: list[str], used_service_ids: set[str]) -> None:
    """Every record ID is unique, and every service it mentions exists in services.json."""
    if len(record_ids) != len(set(record_ids)):
        raise ValueError(f"{file_name} contains a duplicate record ID")
    if used_service_ids - service_ids():
        raise ValueError(f"{file_name} refers to services missing from services.json")


@lru_cache(maxsize=1)
def bank_profile() -> BankProfile:
    return BankProfileFile.model_validate_json(_read_text("bank_profile.json")).profile


@lru_cache(maxsize=1)
def client_base() -> tuple[ClientBaseSnapshot, ...]:
    snapshots = ClientBaseFile.model_validate_json(_read_text("client_base.json")).snapshots
    _check_references("client_base.json", [s.snapshot_id for s in snapshots], {s.service_id for s in snapshots})
    keys = [(s.service_id, s.as_of) for s in snapshots]
    if len(keys) != len(set(keys)):
        raise ValueError("client_base.json has two snapshots for the same service and date")
    return snapshots


@lru_cache(maxsize=1)
def daily_averages() -> tuple[DailyAverage, ...]:
    rows = DailyAveragesFile.model_validate_json(_read_text("daily_averages.json")).averages
    _check_references("daily_averages.json", [r.average_id for r in rows], {r.service_id for r in rows})
    keys = [(r.service_id, r.month) for r in rows]
    if len(keys) != len(set(keys)):
        raise ValueError("daily_averages.json has two rows for the same service and month")
    return rows


@lru_cache(maxsize=1)
def client_impacts() -> tuple[ClientImpact, ...]:
    impacts = ClientImpactFile.model_validate_json(_read_text("client_impact.json")).impacts
    _check_references("client_impact.json", [i.impact_id for i in impacts], {i.service_id for i in impacts})
    return impacts


@lru_cache(maxsize=1)
def security_alerts() -> tuple[SecurityAlert, ...]:
    alerts = SecurityAlertsFile.model_validate_json(_read_text("security_alerts.json")).alerts
    used = {service_id for alert in alerts for service_id in alert.service_ids}
    _check_references("security_alerts.json", [a.alert_id for a in alerts], used)
    if {a.supplier_id for a in alerts if a.supplier_id} - supplier_ids():
        raise ValueError("security_alerts.json refers to suppliers missing from suppliers.json")
    return alerts


@lru_cache(maxsize=1)
def suppliers() -> tuple[SupplierRecord, ...]:
    """Load the supplier register and check it agrees with the service list, both ways."""
    records = SuppliersFile.model_validate_json(_read_text("suppliers.json")).suppliers
    used = {service_id for record in records for service_id in record.services_provided}
    _check_references("suppliers.json", [r.supplier_id for r in records], used)
    from_register = {(r.supplier_id, s) for r in records for s in r.services_provided}
    from_services = {(sup, s.service_id) for s in services() for sup in s.supplier_ids}
    if from_register != from_services:
        raise ValueError("suppliers.json and services.json disagree about which supplier runs which service")
    return records


def supplier_ids() -> frozenset[str]:
    return frozenset(record.supplier_id for record in suppliers())


@lru_cache(maxsize=1)
def supplier_notices() -> tuple[SupplierNotice, ...]:
    notices = SupplierNoticesFile.model_validate_json(_read_text("supplier_notices.json")).notices
    _check_references("supplier_notices.json", [n.notice_id for n in notices], set())
    if {n.supplier_id for n in notices} - supplier_ids():
        raise ValueError("supplier_notices.json refers to suppliers missing from suppliers.json")
    return notices
