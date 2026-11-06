"""Fields of the initial notification, and the ones code fills in. Plain Python, no LLM.

Field numbers, names and mandatory/conditional status come from docs/dora-rules.md section 10
(ITS-R = Commission Implementing Regulation (EU) 2025/302, Annex II; RTS-R = 2025/301, Art. 1 and 2).

Who fills what (block 5b plan, approved by Sam on 6 November 2026):
- code:     1.1 to 1.15, 2.1, 2.2, 2.3, 2.5, 2.6, from the reporting entity file and confirmed facts
- AI draft: 2.4 (description), built in a later step
- human:    2.7, 2.8, 2.9, 2.10, in the approval step

This module only builds data. It sends nothing and writes nothing.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Literal

from dora_agent.notification.entity import SYNTHETIC_LEI_NOTE, ReportingEntity
from dora_agent.rules.engine import Classification
from dora_agent.rules.facts import Frozen, UtcTime
from dora_agent.rules.thresholds import EU_MEMBER_STATES, MET

FilledBy = Literal["code", "ai_draft", "human"]
# filled: has a value. not_applicable: a conditional field whose condition is not met.
# waiting: no value yet (for the AI draft step or the human).
FieldStatus = Literal["filled", "not_applicable", "waiting"]
FieldValue = str | bool | tuple[str, ...] | None


class NotificationField(Frozen):
    number: str  # ITS-R Annex II field number, for example "2.3"
    name: str
    mandatory: bool  # "mandatory for initial notification" in ITS-R Annex II (section 10)
    filled_by: FilledBy
    status: FieldStatus
    value: FieldValue = None
    source: str  # where the value came from (CLAUDE.md hard rule 9)
    note: str | None = None


# (number, name, mandatory, filled_by): docs/dora-rules.md section 10, ITS-R Annex II.
CATALOGUE: tuple[tuple[str, str, bool, FilledBy], ...] = (
    ("1.1", "Type of submission", True, "code"),  # RTS-R Art. 1(a)
    ("1.2", "Name of the entity submitting the report", True, "code"),  # RTS-R Art. 1(c)
    ("1.3", "Identification code of the entity submitting the report", True, "code"),  # RTS-R Art. 1(c)
    ("1.4", "Type of the affected financial entity", True, "code"),  # RTS-R Art. 1(b)
    ("1.5", "Name of the financial entity affected", False, "code"),  # RTS-R Art. 1(b), (d)
    ("1.6", "LEI code of the financial entity affected", False, "code"),  # RTS-R Art. 1(b), (d)
    ("1.7", "Primary contact person name", True, "code"),  # RTS-R Art. 1(e)
    ("1.8", "Primary contact person email", True, "code"),  # RTS-R Art. 1(e)
    ("1.9", "Primary contact person telephone", True, "code"),  # RTS-R Art. 1(e)
    ("1.10", "Second contact person name", True, "code"),  # RTS-R Art. 1(e)
    ("1.11", "Second contact person email", True, "code"),  # RTS-R Art. 1(e)
    ("1.12", "Second contact person telephone", True, "code"),  # RTS-R Art. 1(e)
    ("1.13", "Name of the ultimate parent undertaking", False, "code"),  # RTS-R Art. 1(f)
    ("1.14", "LEI code of the ultimate parent undertaking", False, "code"),  # RTS-R Art. 1(f)
    ("1.15", "Reporting currency", True, "code"),  # RTS-R Art. 1(g)
    ("2.1", "Incident reference code assigned by the financial entity", True, "code"),  # RTS-R Art. 2(a)
    ("2.2", "Date and time of detection of the ICT-related incident", True, "code"),  # RTS-R Art. 2(b)
    ("2.3", "Date and time of classification of the incident as major", True, "code"),  # RTS-R Art. 2(b)
    ("2.4", "Description of the ICT-related incident", True, "ai_draft"),  # RTS-R Art. 2(c)
    ("2.5", "Classification criteria that triggered the incident report", True, "code"),  # RTS-R Art. 2(d)
    ("2.6", "EEA Member States impacted (geographical spread)", False, "code"),  # RTS-R Art. 2(e)
    ("2.7", "Discovery of the major ICT-related incident", True, "human"),  # RTS-R Art. 2(f)
    ("2.8", "Origin in a third-party provider or another financial entity", False, "human"),  # RTS-R Art. 2(g)
    ("2.9", "Activation of business continuity plan", True, "human"),  # RTS-R Art. 2(h)
    ("2.10", "Other relevant information", False, "human"),  # RTS-R Art. 2(i), (j)
)
FIELD_NUMBERS: tuple[str, ...] = tuple(row[0] for row in CATALOGUE)

# Field 1.1 choice. Only "initial notification" is in scope (section 10, status line).
SUBMISSION_TYPE = "initial notification"

# Field 1.4: DORA Art. 2(1) type, in the wording of ITS-R Annex II.
ENTITY_TYPE_WORDS = {"credit_institution": "credit institution"}

# Field 2.5 choice list, ITS-R Annex II (section 10), in the order of the regulation.
CRITERIA: tuple[str, ...] = (
    "clients, financial counterparts and transactions affected",
    "reputational impact",
    "duration and service downtime",
    "geographical spread",
    "data losses",
    "critical services affected",
    "economic impact",
)
# Which engine threshold stands for which criterion (RTS-C Art. 1 to 7, docs/dora-rules.md sections 2 and 3).
# T5-a (RTS-C Art. 9(5)(a)) and T5-b (Art. 9(5)(b)) are both the data losses criterion (RTS-C Art. 5).
# The gate is the critical services criterion (RTS-C Art. 6). It is always met for a major incident.
THRESHOLD_TO_CRITERION = {
    "T1": "clients, financial counterparts and transactions affected",
    "T2": "reputational impact",
    "T3": "duration and service downtime",
    "T4": "geographical spread",
    "T5-a": "data losses",
    "T5-b": "data losses",
    "gate": "critical services affected",
    "T6": "economic impact",
}

# Field 2.7 choice list, ITS-R Annex II (section 10). Used in the human approval step.
DISCOVERY_CHOICES: tuple[str, ...] = (
    "IT security",
    "staff",
    "internal audit",
    "external audit",
    "clients",
    "financial counterparts",
    "third-party provider",
    "attacker",
    "monitoring systems",
    "authority/agency/law enforcement body",
    "other",
)

_RUN_ID = re.compile(r"^[A-Za-z0-9]{1,40}$")


class NotMajor(ValueError):
    """Raised when a draft is asked for an incident the rules engine did not classify as major."""


def iso_utc(value: datetime) -> str:
    """ITS-R Annex II, fields 2.2 and 2.3: ISO 8601, UTC."""
    if value.utcoffset() != timedelta(0):
        raise ValueError("times must be UTC")
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


class _Builder:
    def __init__(self) -> None:
        self.fields: dict[str, NotificationField] = {}

    def add(self, number: str, status: FieldStatus, source: str, value: FieldValue = None,
            note: str | None = None) -> None:
        row = next(r for r in CATALOGUE if r[0] == number)
        self.fields[number] = NotificationField(number=number, name=row[1], mandatory=row[2], filled_by=row[3],
                                                status=status, value=value, source=source, note=note)


class _Classified(Frozen):
    at: UtcTime


def criteria_met(classification: Classification) -> tuple[str, ...]:
    """Field 2.5: the criteria the engine found met, in the order of the ITS-R choice list."""
    met: set[str] = set()
    if classification.gate is not None and classification.gate.status == MET:
        met.add(THRESHOLD_TO_CRITERION["gate"])
    if classification.t5b is not None and classification.t5b.status == MET:
        met.add(THRESHOLD_TO_CRITERION["T5-b"])
    for threshold_id in classification.thresholds_met:
        met.add(THRESHOLD_TO_CRITERION[threshold_id])
    return tuple(c for c in CRITERIA if c in met)


def code_fields(classification: Classification, *, run_id: str, classified_at: datetime,
                entity: ReportingEntity, entity_type: str) -> tuple[NotificationField, ...]:
    """Build every field of the initial notification. Code fills its own fields; the rest wait.

    classification: the rules engine result. Must be "major", else NotMajor is raised.
    run_id: the agent run; field 2.1 is built from it, so the draft links to the decision log.
    classified_at: when the rules engine first returned "major" (Sam's choice for field 2.3).
    entity, entity_type: from reporting_entity.json and bank_profile.json.
    """
    if classification.result != "major":
        raise NotMajor(f"no initial notification: the result is {classification.result}, not major")
    if not _RUN_ID.match(run_id):
        raise ValueError("run_id must be 1 to 40 letters or digits")
    if entity_type not in ENTITY_TYPE_WORDS:
        raise ValueError("unknown entity type")
    classified = _Classified(at=classified_at).at  # refuses times that are not UTC
    facts = classification.facts
    b = _Builder()
    entity_src = "reporting_entity.json (synthetic)"

    # ---- Section 1: general information (RTS-R Art. 1) ----
    b.add("1.1", "filled", "code", SUBMISSION_TYPE)
    b.add("1.2", "filled", entity_src, entity.legal_name)
    b.add("1.3", "filled", entity_src, entity.lei, note=SYNTHETIC_LEI_NOTE)
    b.add("1.4", "filled", "bank_profile.json (synthetic)", ENTITY_TYPE_WORDS[entity_type])
    not_aggregated = "Rheinbank reports for itself, not in an aggregated report (ITS-R Annex II, 1.5 and 1.6)."
    b.add("1.5", "not_applicable", "code", note=not_aggregated)
    b.add("1.6", "not_applicable", "code", note=not_aggregated)
    for start, contact in (("1.7", entity.primary_contact), ("1.10", entity.second_contact)):
        first = int(start.split(".")[1])
        b.add(f"1.{first}", "filled", entity_src, contact.name)
        b.add(f"1.{first + 1}", "filled", entity_src, contact.email)
        b.add(f"1.{first + 2}", "filled", entity_src, contact.telephone)
    if entity.parent_undertaking is None:
        no_group = "Rheinbank is not part of a group (ITS-R Annex II, 1.13 and 1.14)."
        b.add("1.13", "not_applicable", entity_src, note=no_group)
        b.add("1.14", "not_applicable", entity_src, note=no_group)
    else:
        b.add("1.13", "filled", entity_src, entity.parent_undertaking.name)
        b.add("1.14", "filled", entity_src, entity.parent_undertaking.lei, note=SYNTHETIC_LEI_NOTE)
    b.add("1.15", "filled", entity_src, entity.reporting_currency)

    # ---- Section 2: content of the initial notification (RTS-R Art. 2) ----
    b.add("2.1", "filled", "code (agent run ID)", f"RHB-{run_id}")

    detected = facts.detected_at
    if facts.usable("detected_at") is None:
        b.add("2.2", "waiting", "human", note="Detection time unknown. A human must give it before approval.")
    else:
        estimate = " Marked as an estimate (ITS-R Art. 1(3))." if detected.is_estimate else ""
        b.add("2.2", "filled", f"fact detected_at, from {detected.source}", iso_utc(detected.value),
              note=("Detection = when the bank became aware (ITS-R Annex II, 2.2)." + estimate))

    b.add("2.3", "filled", "rules engine (time it returned major)", iso_utc(classified),
          note=f"Rule version {classification.rule_version}.")

    b.add("2.4", "waiting", "ai_draft", note="Drafted in a later step. Causes stay 'under investigation' "
                                              "unless a human types them.")

    b.add("2.5", "filled", "rules engine", criteria_met(classification),
          note=classification.summary)

    if "T4" in classification.thresholds_met:
        # The same Member States the engine counted for T4 (RTS-C Art. 9(4)); EL is written GR as there.
        states = facts.usable("affected_member_states")
        counted = tuple(sorted({"GR" if s == "EL" else s for s in states if s in EU_MEMBER_STATES}))
        left_out = sorted({s for s in states if s not in EU_MEMBER_STATES})
        b.add("2.6", "filled", f"fact affected_member_states, from {facts.affected_member_states.source}",
              counted, note=(f"Not listed, outside the EU: {', '.join(left_out)}." if left_out else None))
    else:
        b.add("2.6", "not_applicable", "rules engine",
              note="Only needed when the geographical spread threshold (T4) is met (ITS-R Annex II, 2.6).")

    b.add("2.7", "waiting", "human", note="Pick one: " + "; ".join(DISCOVERY_CHOICES) + ".")
    b.add("2.8", "waiting", "human", note="Only if the incident started at a third-party provider or "
                                          "another financial entity: its name and identification code.")
    b.add("2.9", "waiting", "human", note="Yes or no: was the business continuity plan activated?")
    b.add("2.10", "waiting", "human", note="Optional: other relevant information.")

    return tuple(b.fields[n] for n in FIELD_NUMBERS)
