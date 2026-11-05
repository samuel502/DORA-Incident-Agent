"""The facts the rules engine works on: one incident, one set of facts.

Each fact holds a value, where it came from, whether it is an estimate and who confirmed it.
A value of None always means "unknown". It never means zero or "no" (docs/dora-rules.md section 7:
the tool never guesses silently).

This module must not import the connectors, the LLM or anything that touches the network.
The engine sees only these facts. That is why a few small types are defined here again.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Annotated, Generic, Literal, TypeVar

from pydantic import AfterValidator, AwareDatetime, BaseModel, ConfigDict, Field, StringConstraints, model_validator


class Frozen(BaseModel):
    """Base for all models: immutable, strict types, no extra fields."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)


def _must_be_utc(value: datetime) -> datetime:
    if value.utcoffset() != timedelta(0):
        raise ValueError("times must be UTC")
    return value


UtcTime = Annotated[AwareDatetime, AfterValidator(_must_be_utc)]
# Upper bounds stop absurd input from crashing the engine (security framework, "Bad input"):
# a 5,000-digit number cannot even be printed by Python. 10**15 is far above any real count or euro amount.
MAX_NUMBER = 10**15
Count = Annotated[int, Field(ge=0, le=MAX_NUMBER)]
Euros = Annotated[int, Field(ge=0, le=MAX_NUMBER)]
MemberState = Annotated[str, StringConstraints(pattern=r"^[A-Z]{2}$")]
# No control characters (line breaks, tabs, escape codes): these texts end up in logs and on screen,
# and a line break could fake an extra log line (hard rule 9 needs a log that can be trusted).
_NO_CONTROL_CHARS = r"^[^\x00-\x1f\x7f]+$"
PersonName = Annotated[str, StringConstraints(min_length=1, max_length=80, strip_whitespace=True,
                                              pattern=_NO_CONTROL_CHARS)]
NoteText = Annotated[str, StringConstraints(min_length=1, max_length=500, pattern=_NO_CONTROL_CHARS)]
# A list of affected countries never needs more entries than there are countries.
StateList = Annotated[tuple[MemberState, ...], Field(max_length=60)]

# Where a fact came from (CLAUDE.md hard rule 9: log where each fact came from).
# The system names follow docs/dora-rules.md section 6, column "Where Rheinbank keeps it".
Source = Literal[
    "ticket",
    "service_list",
    "monitoring",
    "client_data",
    "security_alerts",
    "supplier_register",
    "human",  # a person gave the answer
    "ai_suggestion",  # the AI proposed it; never used until a human confirms it (section 7)
]

T = TypeVar("T")


class Fact(Frozen, Generic[T]):
    """One fact. value None = unknown."""

    value: T | None = None
    source: Source | None = None
    # Open question 2 and RTS-C Art. 1(5), 3(1), 7(3): estimates are allowed but must be marked.
    is_estimate: bool = False
    # Section 7: who confirmed a judgment call. Logged with the decision.
    confirmed_by: PersonName | None = None
    note: NoteText | None = None

    @property
    def known(self) -> bool:
        return self.value is not None

    @model_validator(mode="after")
    def _consistent(self):
        if self.value is not None and self.source is None:
            raise ValueError("a known value must say where it came from")
        if self.value is None and self.is_estimate:
            raise ValueError("an unknown value cannot be an estimate")
        if self.source == "human" and self.value is not None and self.confirmed_by is None:
            raise ValueError("a human answer must name the person who gave it")
        return self


YesNo = Fact[bool]
Number = Fact[Count]
Money = Fact[Euros]
Time = Fact[UtcTime]
States = Fact[StateList]


def _unknown(fact_type):
    return Field(default_factory=fact_type)


# Section 7: judgment calls. A human must confirm these before the engine uses them,
# whatever their source. Field names refer to IncidentFacts below.
HUMAN_CONFIRMED: frozenset[str] = frozenset(
    {
        "planned_and_announced",  # open question 5, DORA Art. 3(8)
        "malicious_access",  # G-c, T5-b
        "access_on_own_systems",  # open question 4, RTS-C Art. 6(c)
        "access_may_cause_data_loss",  # T5-b, RTS-C Art. 9(5)(b)
        "relevant_parties_affected",  # T1-f, RTS-C Art. 1(3)
        "media_coverage",  # T2-a
        "repeated_complaints",  # T2-b
        "regulatory_requirements_impact",  # T2-c
        "client_loss_impact",  # T2-d
        "data_availability_impact",  # T5-a, RTS-C Art. 5
        "data_authenticity_impact",  # T5-a
        "data_integrity_impact",  # T5-a
        "data_confidentiality_impact",  # T5-a
        "data_impact_adverse",  # T5-a: adverse impact on business objectives or regulatory requirements
    }
)


class IncidentFacts(Frozen):
    """All facts for one incident, following the checklist in docs/dora-rules.md section 6.

    Every fact starts as unknown. The agent (block 5) fills in what it finds.
    """

    service_id: Annotated[str, StringConstraints(pattern=r"^SVC-[A-Z]{2,8}$")] | None = None

    # Is it an incident at all? DORA Art. 3(8), open questions 5 and 8.
    planned_and_announced: YesNo = _unknown(YesNo)
    planned_window_end: Time = _unknown(Time)

    # Gate, section 2 (RTS-C Art. 6).
    critical_or_important: YesNo = _unknown(YesNo)  # G-a, also T3-b
    regulated_service: YesNo = _unknown(YesNo)  # G-b
    malicious_access: YesNo = _unknown(YesNo)  # G-c, T5-b: successful, malicious, unauthorised access
    access_on_own_systems: YesNo = _unknown(YesNo)  # open question 4: the bank's own systems?
    access_may_cause_data_loss: YesNo = _unknown(YesNo)  # T5-b

    # T1, section 3 (RTS-C Art. 9(1), Art. 1).
    affected_clients: Number = _unknown(Number)
    total_clients: Number = _unknown(Number)  # open question 7
    affected_counterparts: Number = _unknown(Number)
    total_counterparts: Number = _unknown(Number)  # open question 7
    affected_tx_count: Number = _unknown(Number)
    daily_avg_tx_count: Number = _unknown(Number)  # open question 6
    affected_tx_value_eur: Money = _unknown(Money)
    daily_avg_tx_value_eur: Money = _unknown(Money)  # open question 6
    relevant_parties_affected: YesNo = _unknown(YesNo)  # T1-f

    # T2, section 3 (RTS-C Art. 9(2), Art. 2).
    media_coverage: YesNo = _unknown(YesNo)  # T2-a
    repeated_complaints: YesNo = _unknown(YesNo)  # T2-b
    regulatory_requirements_impact: YesNo = _unknown(YesNo)  # T2-c
    client_loss_impact: YesNo = _unknown(YesNo)  # T2-d

    # T3, section 3 (RTS-C Art. 9(3), Art. 3).
    incident_start: Time = _unknown(Time)
    detected_at: Time = _unknown(Time)
    earliest_log_at: Time = _unknown(Time)  # Art. 3(1): logs may show an earlier start
    resolved_at: Time = _unknown(Time)  # an estimate is allowed if not resolved yet
    downtime_start: Time = _unknown(Time)
    service_restored_at: Time = _unknown(Time)
    backlog_cleared_at: Time = _unknown(Time)  # Art. 3(2): downtime runs until the backlog is cleared

    # T4, section 3 (RTS-C Art. 9(4), Art. 4).
    affected_member_states: States = _unknown(States)

    # T5-a, section 3 (RTS-C Art. 9(5)(a), Art. 5).
    data_availability_impact: YesNo = _unknown(YesNo)
    data_authenticity_impact: YesNo = _unknown(YesNo)
    data_integrity_impact: YesNo = _unknown(YesNo)
    data_confidentiality_impact: YesNo = _unknown(YesNo)
    data_impact_adverse: YesNo = _unknown(YesNo)

    # T6, section 3 (RTS-C Art. 9(6), Art. 7). Gross: recoveries are not subtracted.
    costs_eur: Money = _unknown(Money)

    def usable(self, name: str):
        """The value the engine may use, or None (unknown).

        Section 7: an AI suggestion, or any judgment call, counts only once a human confirmed it.
        Otherwise the engine treats it as unknown.
        """
        if name == "service_id" or name not in type(self).model_fields:
            raise KeyError(f"not a fact: {name}")
        fact: Fact = getattr(self, name)
        if not fact.known:
            return None
        if fact.confirmed_by is None and (fact.source == "ai_suggestion" or name in HUMAN_CONFIRMED):
            return None
        return fact.value

    def pending_confirmations(self) -> list[str]:
        """Facts that have a value but still wait for a human. Shown to the user, not used."""
        return [
            name
            for name in type(self).model_fields
            if name != "service_id" and getattr(self, name).known and self.usable(name) is None
        ]
