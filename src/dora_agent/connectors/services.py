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


def _match_words(query: str, candidate: str) -> int:
    """How many words of the name or alias matched (0 = no match). Whole words only, in either direction.

    'online banking is down' matches the alias 'online banking' (2 words).
    'banking' matches the alias 'online banking' (query of 3+ characters inside an alias; 1 word).
    'application' does not match the alias 'app' (whole words only).
    'online or mobile banking' matches 'online banking' AND 'mobile banking': every word of the alias
    is in the text, even if other words sit between them (C01 live test, approved by Sam).
    """
    if not query or not candidate:
        return 0
    query_words, candidate_words = set(query.split()), set(candidate.split())
    if candidate_words <= query_words:  # also covers the alias appearing as one phrase in the text
        return len(candidate_words)
    if len(query) >= 3 and f" {query} " in f" {candidate} ":
        return len(query_words)
    return 0


def find_service(text: object) -> FindServiceResult:
    """Find services whose name or alias matches the search text, best matches first.

    Ranking (C01 live test, 15 November 2026): a service named by a longer alias comes before one that only
    shares a single word. Before, matches were cut at max_find_results in service-ID order, so the general
    word 'payments' (an alias of three services) could push 'online banking' out of the list. Equal
    matches stay in service-ID order. The ranking only orders the list; it decides nothing.
    """
    limits = connector_limits()
    query = _normalise(check_query_text(text, limits.max_query_chars))
    scored = []
    for record in _store.services():
        best = max(_match_words(query, _normalise(candidate)) for candidate in (record.name, *record.aliases))
        if best:
            scored.append((-best, record.service_id, record))
    scored.sort(key=lambda item: item[:2])
    hits = [record for _, _, record in scored]
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
