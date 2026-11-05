"""Service list connector: a read-only stand-in for a CMDB such as ServiceNow.

Facts it provides (docs/dora-rules.md, section 6):
- critical_or_important -> gate G-a (RTS-C Art. 6(a)) and T3-b (RTS-C Art. 9(3)(b))
- regulated_service     -> gate G-b (RTS-C Art. 6(b))
It provides facts only. It never decides anything.
"""

from __future__ import annotations

import re

from ..config import connector_limits
from . import _store
from ._guards import cap_text, check_query_text, check_service_id
from .schemas import FindServiceResult, GetServiceResult, ServiceMatch, ServiceView, Source

SYSTEM = "Rheinbank service list (simulated CMDB)"

_NON_WORD = re.compile(r"[^\w\-]+")


def _normalise(text: str) -> str:
    """Lowercase, and turn punctuation into spaces, so 'Online-Banking!' and 'online-banking' match."""
    return " ".join(_NON_WORD.sub(" ", text.lower()).split())


def _matches(query: str, candidate: str) -> bool:
    """Whole-word match in either direction.

    'online banking is down' matches the alias 'online banking'.
    'banking' matches the alias 'online banking' (query of 3+ characters inside an alias).
    'application' does not match the alias 'app' (whole words only).
    """
    if not query or not candidate:
        return False
    padded_query, padded_candidate = f" {query} ", f" {candidate} "
    return padded_candidate in padded_query or (len(query) >= 3 and padded_query in padded_candidate)


def find_service(text: object) -> FindServiceResult:
    """Find services whose name or alias matches a short search text."""
    limits = connector_limits()
    query = _normalise(check_query_text(text, limits.max_query_chars))
    hits = [
        record
        for record in _store.services()
        if any(_matches(query, _normalise(candidate)) for candidate in (record.name, *record.aliases))
    ]
    hits.sort(key=lambda record: record.service_id)
    shown = hits[: limits.max_find_results]
    return FindServiceResult(
        matches=tuple(ServiceMatch(service_id=r.service_id, name=r.name) for r in shown),
        more_available=len(hits) > len(shown),
        source=Source(system=SYSTEM, record_ids=tuple(r.service_id for r in shown)),
    )


def get_service(service_id: object) -> GetServiceResult:
    """Look up one service by its ID."""
    wanted = check_service_id(service_id)
    record = next((r for r in _store.services() if r.service_id == wanted), None)
    if record is None:
        return GetServiceResult(found=False, service=None, source=Source(system=SYSTEM, record_ids=()))
    view = ServiceView(
        service_id=record.service_id,
        name=record.name,
        function_supported=record.function_supported,
        critical_or_important=record.critical_or_important,
        criticality_note=cap_text(record.criticality_note, connector_limits().max_text_chars),
        regulated_service=record.regulated_service,
        client_facing=record.client_facing,
        member_states_served=record.member_states_served,
        supplier_ids=record.supplier_ids,
    )
    return GetServiceResult(found=True, service=view, source=Source(system=SYSTEM, record_ids=(record.service_id,)))
