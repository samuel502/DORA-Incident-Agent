"""Turn a raw value (from the LLM, or typed by a human) into the right type for one fact.

Everything that enters the fact store from outside plain code passes through `parse_value`.
It accepts only what the fact can hold and says plainly what is wrong otherwise.
It never guesses: "unsure" or a value of the wrong kind is refused, not converted.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Literal

from dora_agent.rules.facts import MAX_NUMBER, IncidentFacts

Kind = Literal["yes_no", "count", "euros", "time", "member_states"]

# What kind of value each fact holds (docs/dora-rules.md section 6). A test checks this covers every fact.
FACT_KINDS: dict[str, Kind] = {
    "planned_and_announced": "yes_no",
    "planned_window_end": "time",
    "critical_or_important": "yes_no",
    "regulated_service": "yes_no",
    "malicious_access": "yes_no",
    "access_on_own_systems": "yes_no",
    "access_may_cause_data_loss": "yes_no",
    "affected_clients": "count",
    "total_clients": "count",
    "affected_counterparts": "count",
    "total_counterparts": "count",
    "affected_tx_count": "count",
    "daily_avg_tx_count": "count",
    "affected_tx_value_eur": "euros",
    "daily_avg_tx_value_eur": "euros",
    "relevant_parties_affected": "yes_no",
    "media_coverage": "yes_no",
    "repeated_complaints": "yes_no",
    "regulatory_requirements_impact": "yes_no",
    "client_loss_impact": "yes_no",
    "incident_start": "time",
    "detected_at": "time",
    "earliest_log_at": "time",
    "resolved_at": "time",
    "downtime_start": "time",
    "service_restored_at": "time",
    "backlog_cleared_at": "time",
    "affected_member_states": "member_states",
    "data_availability_impact": "yes_no",
    "data_authenticity_impact": "yes_no",
    "data_integrity_impact": "yes_no",
    "data_confidentiality_impact": "yes_no",
    "data_impact_adverse": "yes_no",
    "costs_eur": "euros",
}

MAX_STATES = 60
_STATE = re.compile(r"^[A-Z]{2}$")


class ValueProblem(ValueError):
    """The value does not fit the fact. The message is plain and safe to show."""


def fact_names() -> list[str]:
    return [name for name in IncidentFacts.model_fields if name != "service_id"]


def kind_of(fact_name: str) -> Kind:
    if fact_name not in FACT_KINDS:
        raise ValueProblem(f"not a known fact: {fact_name[:60]!r}")
    return FACT_KINDS[fact_name]


def parse_value(fact_name: str, raw: Any) -> Any:
    """Return the value in the fact's own type, or raise ValueProblem."""
    kind = kind_of(fact_name)
    if kind == "yes_no":
        if isinstance(raw, bool):
            return raw
        raise ValueProblem(f"{fact_name} needs true or false")
    if kind in ("count", "euros"):
        if isinstance(raw, bool) or not isinstance(raw, int):
            raise ValueProblem(f"{fact_name} needs a whole number")
        if not 0 <= raw <= MAX_NUMBER:
            raise ValueProblem(f"{fact_name} must be between 0 and {MAX_NUMBER:,}")
        return raw
    if kind == "time":
        return _parse_time(fact_name, raw)
    return _parse_states(fact_name, raw)


def _parse_time(fact_name: str, raw: Any) -> datetime:
    if isinstance(raw, datetime):
        value = raw
    elif isinstance(raw, str) and len(raw) <= 40:
        try:
            value = datetime.fromisoformat(raw.strip().replace("Z", "+00:00"))
        except ValueError:
            raise ValueProblem(f"{fact_name} needs a date and time like 2026-05-26T07:10:00Z") from None
    else:
        raise ValueProblem(f"{fact_name} needs a date and time like 2026-05-26T07:10:00Z")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueProblem(f"{fact_name} needs a time zone (for example Z for UTC)")
    return value.astimezone(timezone.utc)  # stored in UTC; a German time with +01:00 is converted, not guessed


def _parse_states(fact_name: str, raw: Any) -> tuple[str, ...]:
    if not isinstance(raw, (list, tuple)) or len(raw) > MAX_STATES:
        raise ValueProblem(f"{fact_name} needs a list of up to {MAX_STATES} two-letter country codes")
    if not all(isinstance(code, str) and _STATE.match(code) for code in raw):
        raise ValueProblem(f"{fact_name} needs two-letter country codes in capitals, like DE or AT")
    return tuple(dict.fromkeys(raw))  # duplicates removed, order kept
