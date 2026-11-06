"""Build the draft initial notification for a major incident. For human approval only: nothing is sent.

Steps (block 5b plan, approved by Sam on 6 November 2026):
1. Only a "major" result from the rules engine gets a draft (CLAUDE.md hard rule 1).
2. Field 2.3, the classification time, is the FIRST time the rules engine returned "major" in the run,
   read from the run's decision log. Later re-checks never move it (the stricter choice, Sam's decision).
3. Code fills its fields (fields.py), the AI drafts field 2.4 (description.py), and code works out the
   deadline (deadline.py, docs/dora-rules.md section 5).
4. The draft is logged. A human approves it in approval.py.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from dora_agent.audit.log import DecisionLog
from dora_agent.connectors import get_bank_profile
from dora_agent.llm.provider import LlmProvider
from dora_agent.notification.deadline import Deadline, initial_notification_deadline
from dora_agent.notification.description import describe_incident, description_field
from dora_agent.notification.entity import reporting_entity
from dora_agent.notification.fields import NotificationField, NotMajor, code_fields
from dora_agent.rules.engine import Classification
from dora_agent.rules.facts import Frozen, UtcTime

# Shown on every draft and every approved notification.
BANNER = ("SYNTHETIC DRAFT. Rheinbank AG is a fictional bank. This initial notification is for human review "
          "only and is never sent to any authority by this tool.")

# Log records in which the rules engine's result is written by code (agent/loop.py).
_ENGINE_RECORDS = frozenset({"rules_check", "result", "paused"})


class DraftProblem(ValueError):
    """The draft can't be built from what the run holds."""


def first_major_at(trace: tuple[dict[str, Any], ...] | list[dict[str, Any]]) -> datetime | None:
    """When the rules engine first returned "major" in this run, from the decision log. None if never.

    Only records the loop itself writes about the engine's result count. The LLM can't write log records.
    """
    for record in trace:
        if record.get("kind") in _ENGINE_RECORDS and record.get("result") == "major":
            at = datetime.fromisoformat(str(record["at"]))
            if at.utcoffset() is None:
                raise DraftProblem("log time without a time zone")
            return at.astimezone(timezone.utc)
    return None


class Draft(Frozen):
    """The draft initial notification, waiting for a human."""

    banner: str
    run_id: str
    status: str  # always "draft: waiting for human approval"
    created_at: UtcTime
    classified_at: UtcTime  # field 2.3: first time the engine returned major
    rule_version: str
    summary: str  # the engine's one-line reason, with articles
    fields: tuple[NotificationField, ...]
    deadline: Deadline | None  # None while the detection time (field 2.2) is unknown

    def field(self, number: str) -> NotificationField:
        return next(f for f in self.fields if f.number == number)


def prepare_draft(run_id: str, classification: Classification, trace, provider: LlmProvider, *,
                  causes: str | None = None, log: DecisionLog | None = None,
                  now: datetime | None = None) -> Draft:
    """Build the draft for one agent run (run_id, classification and trace from its RunResult).

    causes: possible causes typed by a human, or None ("under investigation").
    now: the current time (UTC); only for tests and the overdue check.
    Raises NotMajor if the result is not major, DraftProblem if the log shows no major result.
    """
    if classification.result != "major":
        raise NotMajor(f"no initial notification: the result is {classification.result}, not major")
    now = now or datetime.now(timezone.utc)
    classified_at = first_major_at(trace)
    if classified_at is None:
        raise DraftProblem("the decision log shows no major result for this run")

    entity_type = get_bank_profile().profile.entity_type
    fields = code_fields(classification, run_id=run_id, classified_at=classified_at,
                         entity=reporting_entity(), entity_type=entity_type)
    description = describe_incident(classification, provider, causes=causes, log=log)
    fields = tuple(description_field(description) if f.number == "2.4" else f for f in fields)

    detected = classification.facts.usable("detected_at")
    deadline = None
    if detected is not None:
        if detected > classified_at:
            raise DraftProblem("the detection time (field 2.2) is after the classification time (field 2.3): "
                               "check the facts")
        deadline = initial_notification_deadline(detected, classified_at, now, entity_type)

    draft = Draft(banner=BANNER, run_id=run_id, status="draft: waiting for human approval", created_at=now,
                  classified_at=classified_at, rule_version=classification.rule_version,
                  summary=classification.summary, fields=fields, deadline=deadline)
    if log is not None:
        log.write("notification_draft", classified_at=classified_at.isoformat(),
                  due_at=deadline.due_at.isoformat() if deadline else None,
                  overdue=deadline.overdue if deadline else None,
                  description_by=description.written_by,
                  waiting=[f.number for f in fields if f.status == "waiting"], sent=False)
    return draft
