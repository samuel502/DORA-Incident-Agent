"""Holds the facts for one incident while the agent works, and decides who may write what.

Three doors, one per kind of writer (docs/dora-rules.md section 7, security framework):

1. System facts: plain code that maps connector results (step 3). Source = the system's name.
2. Suggestions: the LLM, through `AgentFactView`. Always stored as "ai_suggestion" with a reason.
   The engine ignores them until a human confirms. The LLM cannot set "confirmed by".
3. Human answers: only through `HumanDesk`, which the interface (block 6) and the test harness hold.
   This is the only place "confirmed_by" is ever set.

Who wins when two writers disagree:
- A human answer is never overwritten by a system or a suggestion.
- A system fact beats an LLM suggestion.

Every write, and every write that was refused or ignored, is recorded as an event for the log (hard rule 9).
"""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, TypeAdapter, ValidationError

from dora_agent.agent.questions import AnswerProblem, interpret_answer, question_for
from dora_agent.agent.values import ValueProblem, kind_of, parse_value
from dora_agent.rules.facts import Fact, IncidentFacts, PersonName

# Systems that may write facts directly (dora-rules.md section 6, "Where Rheinbank keeps it").
SYSTEM_SOURCES = frozenset({"service_list", "monitoring", "client_data", "security_alerts", "supplier_register"})

MAX_REASON_CHARS = 300
_CONTROL = re.compile(r"[\x00-\x1f\x7f]+")
_NAME = TypeAdapter(PersonName)

Action = Literal[
    "system", "system_ignored", "suggested", "suggestion_ignored",
    "answered", "answered_unsure", "confirmed", "corrected", "rejected", "conflict",
]


class Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class FactEvent(Frozen):
    """One change (or refused change) to the facts, for the decision log."""

    seq: int
    fact_name: str
    action: Action
    value: str | None  # short text form, for the log
    source: str | None
    by: str | None  # who confirmed, for human actions
    note: str | None = None


class Conflict(Frozen):
    """A system says something different from what a human confirmed. The human answer is used;
    both are shown so the human can correct their answer if the system is right (Sam, block 5 step 2)."""

    fact_name: str
    kept_value: str  # the human-confirmed value the engine uses
    kept_source: str  # "human" or "ticket"
    kept_by: str  # who confirmed it
    system_value: str
    system_source: str

    def describe(self) -> str:
        return (f"{self.fact_name}: using {self.kept_value} (confirmed by {self.kept_by}, source {self.kept_source}), "
                f"but {self.system_source} says {self.system_value}. Please check and correct if needed.")


class ReviewItem(Frozen):
    """One suggestion read from the ticket, waiting for the human's review."""

    fact_name: str
    suggested_value: Any
    reason: str
    question: str | None  # the fixed question text, if there is one, to help the human


class ReviewDecision(Frozen):
    """The human's decision on one suggestion."""

    fact_name: str
    action: Literal["confirm", "correct", "reject"]
    value: Any = None  # only for "correct"
    is_estimate: bool = False


class StoreProblem(ValueError):
    """A write that is not allowed. Plain message, safe to show."""


def _clean(text: str, limit: int) -> str:
    return _CONTROL.sub(" ", text).strip()[:limit]


def _short(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, tuple):
        return ", ".join(value)[:100]
    return str(value)[:100]


def _check_name(confirmed_by: str) -> str:
    try:
        return _NAME.validate_python(confirmed_by)
    except ValidationError:
        raise StoreProblem("confirmed_by must be a name of 1 to 80 characters, without line breaks") from None


class FactStore:
    def __init__(self) -> None:
        self._facts: dict[str, Fact] = {}
        self._service_id: str | None = None
        self._events: list[FactEvent] = []
        # The latest value each system reported, even when a human answer is kept instead (for conflicts).
        self._system_values: dict[str, tuple[Any, str]] = {}

    # ---------- reading ----------

    def conflicts(self) -> list[Conflict]:
        """Every fact where a human-confirmed value differs from what a system reported.

        Worked out fresh each time, so a conflict disappears once the human corrects their answer.
        """
        found = []
        for name, (system_value, system_source) in self._system_values.items():
            fact = self._facts.get(name)
            if fact is not None and fact.confirmed_by is not None and fact.value != system_value:
                found.append(Conflict(fact_name=name, kept_value=_short(fact.value), kept_source=fact.source,
                                      kept_by=fact.confirmed_by, system_value=_short(system_value),
                                      system_source=system_source))
        return found

    def has_value(self, name: str) -> bool:
        """True if the fact holds a value from a system or a human (suggestions do not count)."""
        fact = self._facts.get(name)
        return fact is not None and fact.source != "ai_suggestion"

    def snapshot(self) -> IncidentFacts:
        """The facts as the rules engine sees them. Checked again in full on every snapshot."""
        return IncidentFacts(service_id=self._service_id, **self._facts)

    @property
    def events(self) -> tuple[FactEvent, ...]:
        return tuple(self._events)

    def review_items(self) -> list[ReviewItem]:
        """All suggestions still waiting for the human, as one list (reviewed in one go)."""
        items = []
        for name, fact in self._facts.items():
            if fact.source == "ai_suggestion" and fact.confirmed_by is None:
                question = question_for(name).text if _has_question(name) else None
                items.append(ReviewItem(fact_name=name, suggested_value=fact.value,
                                        reason=fact.note or "", question=question))
        return items

    def agent_view(self) -> "AgentFactView":
        return AgentFactView(self)

    def human_desk(self) -> "HumanDesk":
        return HumanDesk(self)

    # ---------- door 1: systems (plain code only) ----------

    def record_service(self, service_id: str) -> None:
        self._service_id = IncidentFacts(service_id=service_id).service_id

    def record_system(self, name: str, value: Any, source: str, *, is_estimate: bool = False,
                      note: str | None = None) -> None:
        if source not in SYSTEM_SOURCES:
            raise StoreProblem(f"{source!r} is not a system source")
        if value is None:
            return  # the system does not know: the fact stays unknown
        value = parse_value(name, value)
        self._system_values[name] = (value, source)
        current = self._facts.get(name)
        if current is not None and current.confirmed_by is not None:
            # A human answer is never overwritten. If the system disagrees, flag it (Sam, block 5 step 2).
            if current.value != value:
                self._flag_conflict(name)
            else:
                self._event(name, "system_ignored", value, source, None, "same as the human answer")
            return
        self._facts[name] = _make(name, value=value, source=source, is_estimate=is_estimate,
                                  note=_clean(note, 500) if note else None)
        self._event(name, "system", value, source, None)

    # ---------- door 2: the LLM's suggestions (through AgentFactView) ----------

    def _record_suggestion(self, name: str, raw: Any, reason: str) -> str:
        value = parse_value(name, raw)  # raises ValueProblem with a plain message
        reason = _clean(str(reason), MAX_REASON_CHARS) or "no reason given"
        current = self._facts.get(name)
        if current is not None and current.source != "ai_suggestion":
            self._event(name, "suggestion_ignored", value, "ai_suggestion", None,
                        f"already known from {current.source}")
            return f"{name}: already known from {current.source}; suggestion not stored"
        self._facts[name] = _make(name, value=value, source="ai_suggestion", note=reason)
        self._event(name, "suggested", value, "ai_suggestion", None, reason)
        return f"{name}: suggestion stored; a human will confirm or correct it"

    # ---------- door 3: the human (through HumanDesk) ----------

    def _record_answer(self, name: str, answer: Any, confirmed_by: str, is_estimate: bool) -> FactEvent:
        confirmed_by = _check_name(confirmed_by)
        question = question_for(name)
        if is_estimate and not question.allows_estimate:
            raise StoreProblem(f"{name} cannot be an estimate")
        value = interpret_answer(name, answer)
        if value is None:  # "unsure": nothing changes, the fact stays unknown to the engine
            return self._event(name, "answered_unsure", None, "human", confirmed_by)
        self._facts[name] = _make(name, value=value, source="human", confirmed_by=confirmed_by,
                                  is_estimate=is_estimate)
        event = self._event(name, "answered", value, "human", confirmed_by)
        self._flag_conflict(name)
        return event

    def _apply_review(self, decisions: list[ReviewDecision], confirmed_by: str) -> list[FactEvent]:
        confirmed_by = _check_name(confirmed_by)
        pending = {item.fact_name: item for item in self.review_items()}
        decided = [d.fact_name for d in decisions]
        if len(decided) != len(set(decided)):
            raise StoreProblem("each suggestion may be decided only once")
        if set(decided) != set(pending):
            missing = sorted(set(pending) - set(decided))
            extra = sorted(set(decided) - set(pending))
            raise StoreProblem(f"review must cover every pending suggestion in one go; "
                               f"missing: {missing or 'none'}, not pending: {extra or 'none'}")
        # Check everything first, then write: a review is applied fully or not at all.
        planned: list[tuple[ReviewDecision, Any]] = []
        for decision in decisions:
            if decision.action == "correct":
                try:
                    planned.append((decision, parse_value(decision.fact_name, decision.value)))
                except ValueProblem as problem:
                    raise StoreProblem(str(problem)) from None
            else:
                planned.append((decision, None))
        events = []
        for decision, corrected in planned:
            name, item = decision.fact_name, pending[decision.fact_name]
            if decision.action == "confirm":
                # Confirmed reading of the ticket: source is the ticket, the reason is kept as a note.
                self._facts[name] = _make(name, value=item.suggested_value, source="ticket",
                                          confirmed_by=confirmed_by, is_estimate=decision.is_estimate,
                                          note=item.reason)
                events.append(self._event(name, "confirmed", item.suggested_value, "ticket", confirmed_by))
            elif decision.action == "correct":
                self._facts[name] = _make(name, value=corrected, source="human", confirmed_by=confirmed_by,
                                          is_estimate=decision.is_estimate)
                events.append(self._event(name, "corrected", corrected, "human", confirmed_by,
                                          f"suggested was {_short(item.suggested_value)}"))
                self._flag_conflict(name)
            else:
                del self._facts[name]
                events.append(self._event(name, "rejected", None, None, confirmed_by,
                                          f"suggested was {_short(item.suggested_value)}"))
        return events

    # ---------- helpers ----------

    def _flag_conflict(self, name: str) -> None:
        """Record a 'conflict' event in the trace if a system disagrees with the human answer now held."""
        conflict = next((c for c in self.conflicts() if c.fact_name == name), None)
        if conflict is not None:
            self._event(name, "conflict", conflict.kept_value, conflict.kept_source, conflict.kept_by,
                        conflict.describe())

    def _event(self, name, action, value, source, by, note=None) -> FactEvent:
        event = FactEvent(seq=len(self._events) + 1, fact_name=name, action=action, value=_short(value),
                          source=source, by=by, note=note)
        self._events.append(event)
        return event


def _has_question(name: str) -> bool:
    try:
        question_for(name)
        return True
    except AnswerProblem:
        return False


def _make(name: str, **fields) -> Fact:
    """Build the fact with the exact type its field needs, so every rule in facts.py is checked."""
    fact_type = IncidentFacts.model_fields[name].annotation
    return fact_type(**fields)


class AgentFactView:
    """What the LLM's tools get: read the facts and make suggestions. Nothing else.

    There is no way through this object to set a system fact or "confirmed_by".
    """

    __slots__ = ("_store",)

    def __init__(self, store: FactStore):
        self._store = store

    def snapshot(self) -> IncidentFacts:
        return self._store.snapshot()

    def review_items(self) -> list[ReviewItem]:
        return self._store.review_items()

    def suggest(self, fact_name: str, value: Any, reason: str) -> str:
        """Store a suggestion read from the ticket. Returns a short message for the LLM."""
        kind_of(fact_name)  # unknown fact names are refused with a plain message
        return self._store._record_suggestion(fact_name, value, reason)


class HumanDesk:
    """The only way to record a human answer. Held by the interface and the test harness, never by the LLM."""

    __slots__ = ("_store",)

    def __init__(self, store: FactStore):
        self._store = store

    def answer(self, fact_name: str, answer: Any, *, confirmed_by: str, is_estimate: bool = False) -> FactEvent:
        """Answer one fixed question (see questions.py)."""
        return self._store._record_answer(fact_name, answer, confirmed_by, is_estimate)

    def review(self, decisions: list[ReviewDecision], *, confirmed_by: str) -> list[FactEvent]:
        """Confirm, correct or reject ALL pending ticket suggestions in one go."""
        return self._store._apply_review(decisions, confirmed_by)
