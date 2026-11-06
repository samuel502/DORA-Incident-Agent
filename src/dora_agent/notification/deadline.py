"""Deadline for the initial notification. Plain Python, no LLM (CLAUDE.md hard rule 1).

Rules from docs/dora-rules.md section 5 (RTS-R = Commission Delegated Regulation (EU) 2025/301):

    classified within 24 h of awareness:  due = earlier of (classified + 4 h) and (aware + 24 h)   Art. 5(1)(a)
    classified later than that:           due = classified + 4 h                                   Art. 5(2)

"Aware" is the detection time of ITS-R Annex II field 2.2 (section 5, last paragraph).
All times are UTC. This module only calculates. It sends nothing and writes nothing.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Literal

from dora_agent.rules.facts import Frozen, UtcTime

# Section 5, RTS-R Art. 5(1)(a): within 4 hours of classification as major ...
HOURS_AFTER_CLASSIFICATION = 4
# ... and no later than 24 hours after becoming aware of the incident.
HOURS_AFTER_AWARENESS = 24

# Entity types the tool knows about. Rheinbank is a credit institution (section 8, open question 3).
EntityType = Literal["credit_institution", "central_counterparty", "trading_venue", "other"]

# Section 5, RTS-R Art. 5(5): the weekend and bank holiday extension of Art. 5(4) does not apply
# to the initial notifications of these entities. (Art. 5(5) also names entities that are essential
# or important under Directive (EU) 2022/2555; the tool cannot tell that from the type, so "other"
# gets the "not handled" note instead.)
NO_WEEKEND_EXTENSION: frozenset[str] = frozenset({"credit_institution", "central_counterparty", "trading_venue"})

_ENTITY_WORDS = {
    "credit_institution": "a credit institution",
    "central_counterparty": "a central counterparty",
    "trading_venue": "a trading venue operator",
}

RULE_NORMAL = (f"Within {HOURS_AFTER_CLASSIFICATION} hours of classification as major, and no later than "
               f"{HOURS_AFTER_AWARENESS} hours after becoming aware, as early as possible (RTS-R Art. 5(1)(a)).")
RULE_LATE = (f"Classified as major more than {HOURS_AFTER_AWARENESS} hours after becoming aware: within "
             f"{HOURS_AFTER_CLASSIFICATION} hours of classification (RTS-R Art. 5(2)).")
OVERDUE_NOTE = ("The deadline has passed. Tell the competent authority without undue delay and explain "
                "the reasons for the delay (RTS-R Art. 5(3)).")
OTHER_ENTITY_NOTE = ("Weekend and bank holiday rules are not handled: for this kind of entity, RTS-R Art. 5(4) "
                     "may move a deadline on a weekend or bank holiday to noon of the next working day. "
                     "The tool does not apply this. Check it by hand.")


def _no_extension_note(entity_type: str) -> str:
    return (f"This deadline holds on weekends and bank holidays too. The extension to noon of the next "
            f"working day (RTS-R Art. 5(4)) does not apply to the initial notification of "
            f"{_ENTITY_WORDS[entity_type]} (RTS-R Art. 5(5)).")


class Deadline(Frozen):
    """The initial notification deadline, with the rule that set it and the notes to show."""

    aware_at: UtcTime
    classified_at: UtcTime
    due_at: UtcTime
    late_classification: bool  # True: Art. 5(2) applied
    rule: str  # which rule set the deadline, with the article
    overdue: bool  # True: `now` is past `due_at`
    overdue_note: str | None  # Art. 5(3), only when overdue
    weekend_note: str  # Art. 5(4) and 5(5): what happens on weekends and bank holidays


def initial_notification_deadline(aware_at: datetime, classified_at: datetime, now: datetime,
                                  entity_type: EntityType) -> Deadline:
    """Work out when the initial notification is due (docs/dora-rules.md section 5).

    aware_at: when the bank became aware (detection time, field 2.2).
    classified_at: when the incident was classified as major (field 2.3).
    now: the current time, used only to say whether the deadline has passed.
    All three must be UTC. Raises ValueError for bad input.
    """
    for name, value in (("aware_at", aware_at), ("classified_at", classified_at), ("now", now)):
        if not isinstance(value, datetime) or value.utcoffset() != timedelta(0):
            raise ValueError(f"{name} must be a UTC time")
    if entity_type not in ("credit_institution", "central_counterparty", "trading_venue", "other"):
        raise ValueError("unknown entity type")
    if classified_at < aware_at:
        raise ValueError("classified_at is before aware_at: an incident cannot be classified before the bank knew of it")

    awareness_limit = aware_at + timedelta(hours=HOURS_AFTER_AWARENESS)
    after_classification = classified_at + timedelta(hours=HOURS_AFTER_CLASSIFICATION)
    # Art. 5(2) is for incidents "not classified within 24 hours". Classified at exactly 24 hours is within.
    late = classified_at > awareness_limit
    if late:
        due_at, rule = after_classification, RULE_LATE  # Art. 5(2)
    else:
        due_at, rule = min(after_classification, awareness_limit), RULE_NORMAL  # Art. 5(1)(a)

    overdue = now > due_at
    weekend_note = _no_extension_note(entity_type) if entity_type in NO_WEEKEND_EXTENSION else OTHER_ENTITY_NOTE
    return Deadline(
        aware_at=aware_at, classified_at=classified_at, due_at=due_at, late_classification=late, rule=rule,
        overdue=overdue, overdue_note=OVERDUE_NOTE if overdue else None, weekend_note=weekend_note,
    )
