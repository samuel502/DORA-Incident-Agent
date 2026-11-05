"""The rules engine: decides major / not major. Plain Python only (CLAUDE.md hard rule 1).

The big rule, docs/dora-rules.md section 1 (RTS-C Art. 8(1)):

    major = gate AND (T5-b OR at least 2 of T1, T2, T3, T4, T5-a, T6)

Before that, step 0 asks: is it an incident at all? (DORA Art. 3(8), open questions 5 and 8.)

Four possible results:
    major            the rule is met
    not_major        the rule cannot be met, whatever the unknown facts turn out to be
    undetermined     the unknown facts decide it; `missing` lists exactly which ones (section 7)
    not_an_incident  fully planned and announced downtime that stayed inside its window

Out of scope here: recurring incidents (section 4, version 1) and reporting deadlines
(section 5, handled in the notification block).
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from dora_agent.rules.facts import Frozen, IncidentFacts, UtcTime
from dora_agent.rules.measure import Measurement, measure_downtime, measure_duration
from dora_agent.rules.thresholds import (
    MET,
    NOT_MET,
    UNKNOWN,
    Status,
    Threshold,
    all_of,
    check_gate,
    check_t1,
    check_t2,
    check_t3,
    check_t4,
    check_t5a,
    check_t5b,
    check_t6,
)
from dora_agent.rules.version import RULE_VERSION

Result = Literal["major", "not_major", "undetermined", "not_an_incident"]

# Section 1: at least this many of the "other" thresholds (RTS-C Art. 8(1)(b)).
MIN_OTHER_THRESHOLDS = 2


class Classification(Frozen):
    """The engine's answer, with everything needed to explain and log it (CLAUDE.md hard rule 9)."""

    result: Result
    summary: str  # one plain sentence with the article
    reasons: tuple[str, ...]  # one line per gate and threshold, with articles
    rule_version: str
    as_of: UtcTime
    overrun: bool  # True: a planned window overran and only the overrun is classified (open question 8)
    gate: Threshold | None
    t5b: Threshold | None
    other_thresholds: tuple[Threshold, ...]  # T1, T2, T3, T4, T5-a, T6 in that order
    thresholds_met: tuple[str, ...]  # of the six others
    missing: tuple[str, ...]  # facts that would decide an undetermined result
    pending_confirmations: tuple[str, ...]  # facts with a value that still wait for a human (section 7)
    facts: IncidentFacts  # every fact with its source, estimate flag and confirmer


def _check_as_of(as_of: datetime) -> None:
    if as_of.tzinfo is None or as_of.utcoffset() is None or as_of.utcoffset().total_seconds() != 0:
        raise ValueError("as_of must be a UTC time")


# ---------- Step 0: is it an incident at all? ----------


def _is_incident(facts: IncidentFacts, as_of: datetime) -> tuple[Status, bool, str, tuple[str, ...]]:
    """Returns (status, overrun, reason, missing).

    DORA Art. 3(8): an incident is an event unplanned by the financial entity.
    Open question 5: a human confirms whether the downtime was planned and announced.
    Open question 8: if a planned window overran, the overrun is an incident.

    If nobody has said "planned" and there is no planned window on record, the event is treated as
    unplanned: it was reported as an incident. If a planned window IS on record, the human must answer.
    """
    planned = facts.usable("planned_and_announced")
    if planned is False:
        return MET, False, "Not planned: an ICT-related incident (DORA Art. 3(8))", ()
    if planned is None:
        if facts.planned_window_end.known:
            return (UNKNOWN, False,
                    "A planned window is on record; a human must confirm whether this downtime was "
                    "planned and announced (DORA Art. 3(8), open question 5)", ("planned_and_announced",))
        return MET, False, "No planned window on record: treated as an unplanned incident (DORA Art. 3(8))", ()

    # Planned and announced, confirmed by a human.
    if facts.usable("planned_window_end") is None:
        return (UNKNOWN, False, "Planned and announced, but the end of the planned window is unknown "
                "(open question 8)", ("planned_window_end",))
    lengths: list[Measurement] = [measure_downtime(facts, as_of), measure_duration(facts, as_of)]
    if any(m.length is not None and m.length.total_seconds() > 0 for m in lengths):
        return (MET, True, "Planned and announced, but it ran past the planned window: the overrun is an "
                "incident and is classified from the planned end (DORA Art. 3(8), open question 8)", ())
    if any(m.ongoing for m in lengths):
        return (UNKNOWN, False, "Planned and announced, and still inside the planned window: not an "
                "incident unless it runs past the window (open questions 5 and 8)", ("service_restored_at",))
    if all(m.length is not None for m in lengths):
        return (NOT_MET, False, "Planned and announced, and back inside the planned window: not an "
                "ICT-related incident (DORA Art. 3(8), open question 5)", ())
    return (UNKNOWN, False, "Planned and announced, but the times are incomplete, so an overrun cannot be "
            "ruled out (open question 8)", ("service_restored_at", "resolved_at"))


# ---------- Reasons ----------


def _line(threshold: Threshold) -> str:
    word = {MET: "met", NOT_MET: "not met", UNKNOWN: "unknown"}[threshold.status]
    if threshold.threshold_id == "gate":
        word = {MET: "passed", NOT_MET: "not passed", UNKNOWN: "unknown"}[threshold.status]
    shown = [c for c in threshold.checks if c.status == threshold.status] or list(threshold.checks)
    details = " | ".join(f"{c.check_id}: {c.reason} ({c.article})" for c in shown)
    return f"{threshold.threshold_id} {threshold.name}: {word} ({threshold.article}). {details}"


def _dedupe(names) -> tuple[str, ...]:
    out: list[str] = []
    for name in names:
        if name not in out:
            out.append(name)
    return tuple(out)


# ---------- The classification ----------


def classify(facts: IncidentFacts, as_of: datetime) -> Classification:
    """Apply docs/dora-rules.md to one incident.

    as_of: the time of the check (UTC). Only used to measure incidents that are still ongoing.
    """
    _check_as_of(as_of)
    pending = tuple(facts.pending_confirmations())

    incident, overrun, incident_reason, incident_missing = _is_incident(facts, as_of)
    if incident != MET:
        result: Result = "not_an_incident" if incident == NOT_MET else "undetermined"
        return Classification(
            result=result, summary=incident_reason, reasons=(incident_reason,), rule_version=RULE_VERSION,
            as_of=as_of, overrun=False, gate=None, t5b=None, other_thresholds=(), thresholds_met=(),
            missing=incident_missing, pending_confirmations=pending, facts=facts,
        )

    gate = check_gate(facts)
    t5b = check_t5b(facts)
    others = (check_t1(facts), check_t2(facts), check_t3(facts, as_of), check_t4(facts),
              check_t5a(facts), check_t6(facts))
    met = tuple(t.threshold_id for t in others if t.status == MET)
    unknown = [t for t in others if t.status == UNKNOWN]

    # Section 1, second half: T5-b (Art. 8(1)(a)) OR at least two other thresholds (Art. 8(1)(b)).
    # Each threshold counts once (open question 1).
    if t5b.status == MET or len(met) >= MIN_OTHER_THRESHOLDS:
        second = MET
    elif t5b.status == NOT_MET and len(met) + len(unknown) < MIN_OTHER_THRESHOLDS:
        second = NOT_MET  # even if every unknown threshold were met, it could not reach two
    else:
        second = UNKNOWN

    # Section 1: major = gate AND second half (RTS-C Art. 8(1)).
    decision = all_of([gate.status, second])

    missing: list[str] = list(incident_missing)
    if decision == UNKNOWN:
        if gate.status == UNKNOWN:
            missing += gate.missing
        if second == UNKNOWN:
            if t5b.status == UNKNOWN:
                missing += t5b.missing
            for threshold in unknown:
                missing += threshold.missing

    if decision == MET:
        result = "major"
        route = ("T5-b alone (RTS-C Art. 8(1)(a))" if t5b.status == MET
                 else f"{len(met)} other thresholds: {', '.join(met)} (RTS-C Art. 8(1)(b))")
        summary = f"Major: the gate is passed and {route}."
    elif decision == NOT_MET:
        result = "not_major"
        if gate.status == NOT_MET:
            summary = "Not major: no critical services affected, so the gate is not passed (RTS-C Art. 6, Art. 8(1))."
        else:
            summary = (f"Not major: T5-b is not met and only {len(met)} other threshold(s) "
                       f"{'(' + ', '.join(met) + ') ' if met else ''}can be met; at least "
                       f"{MIN_OTHER_THRESHOLDS} are needed (RTS-C Art. 8(1)).")
    else:
        result = "undetermined"
        summary = (f"Undetermined: {len(_dedupe(missing))} fact(s) still decide the result. "
                   f"Nothing has been guessed (dora-rules.md section 7).")

    if overrun:
        summary += " Only the overrun past the planned window was classified (open question 8)."

    reasons = (incident_reason, _line(gate), _line(t5b), *(_line(t) for t in others))
    return Classification(
        result=result, summary=summary, reasons=reasons, rule_version=RULE_VERSION, as_of=as_of,
        overrun=overrun, gate=gate, t5b=t5b, other_thresholds=others, thresholds_met=met,
        missing=_dedupe(missing), pending_confirmations=pending, facts=facts,
    )
