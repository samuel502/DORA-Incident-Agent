"""Supplier register connector: a read-only stand-in for DORA's register of ICT third-party
providers (DORA Art. 28(3)), plus the notices those suppliers send.

Facts it provides (docs/dora-rules.md, section 6):
- outside provider involved, its country     -> initial notification draft
- market infrastructure, Member States hit   -> T4 (RTS-C Art. 4(c))
- cyber attack yes/no, bank data involved    -> signals for T5-a and open question 4
Supplier names are made up. The contract reference is never returned (data minimisation).
"""

from __future__ import annotations

from ..config import connector_limits
from . import _store
from ._guards import cap_text, check_service_id, check_supplier_id, check_window
from .schemas import (
    GetSupplierResult,
    NoticeView,
    Source,
    SupplierNoticesResult,
    SupplierRecord,
    SuppliersForServiceResult,
    SupplierView,
)

SYSTEM = "Rheinbank register of ICT third-party providers (simulated)"


def _view(record: SupplierRecord) -> SupplierView:
    return SupplierView(
        supplier_id=record.supplier_id,
        name=record.name,
        function_provided=record.function_provided,
        country=record.country,
        services_provided=record.services_provided,
        member_states_served=record.member_states_served,
        is_market_infrastructure=record.is_market_infrastructure,
        supports_critical_function=record.supports_critical_function,
    )


def get_suppliers_for_service(service_id: object) -> SuppliersForServiceResult:
    """The outside companies that run or support one service."""
    wanted = check_service_id(service_id)
    hits = sorted(
        (r for r in _store.suppliers() if wanted in r.services_provided),
        key=lambda r: r.supplier_id,
    )
    return SuppliersForServiceResult(
        service_known=wanted in _store.service_ids(),
        suppliers=tuple(_view(r) for r in hits),
        source=Source(system=SYSTEM, record_ids=tuple(r.supplier_id for r in hits)),
    )


def get_supplier(supplier_id: object) -> GetSupplierResult:
    """One supplier by its ID, for example the supplier_id named in a security alert."""
    wanted = check_supplier_id(supplier_id)
    record = next((r for r in _store.suppliers() if r.supplier_id == wanted), None)
    if record is None:
        return GetSupplierResult(found=False, supplier=None, source=Source(system=SYSTEM, record_ids=()))
    return GetSupplierResult(found=True, supplier=_view(record), source=Source(system=SYSTEM, record_ids=(wanted,)))


def get_supplier_notices(supplier_id: object, start: object, end: object) -> SupplierNoticesResult:
    """Notices from one supplier about incidents overlapping [start, end].

    A notice with no end is treated as still running.
    """
    limits = connector_limits()
    wanted = check_supplier_id(supplier_id)
    begin, finish = check_window(start, end, limits.max_notice_window_days)

    hits = [
        n
        for n in _store.supplier_notices()
        if n.supplier_id == wanted and n.start <= finish and (n.end is None or n.end >= begin)
    ]
    hits.sort(key=lambda n: (n.start, n.notice_id))
    shown = hits[: limits.max_results]

    views = tuple(
        NoticeView(
            notice_id=n.notice_id,
            supplier_id=n.supplier_id,
            received_at=n.received_at,
            start=n.start,
            end=n.end,
            notice_type=n.notice_type,
            cyber_attack=n.cyber_attack,
            bank_data_involved=n.bank_data_involved,
            member_states_affected=n.member_states_affected,
            note=cap_text(n.note, limits.max_text_chars),
        )
        for n in shown
    )
    return SupplierNoticesResult(
        supplier_known=wanted in _store.supplier_ids(),
        notices=views,
        more_available=len(hits) > len(shown),
        source=Source(system=SYSTEM, record_ids=tuple(n.notice_id for n in shown)),
    )
