"""Human approval of the draft initial notification. Nothing is ever sent (build contract, out of scope).

- Only a human approves. The approver's name comes from the person using the tool, through this
  function's `approved_by` argument, never from LLM output: this module does not import the LLM or the
  agent, and no agent tool can reach it (tested). Same rule as `confirmed_by` for facts.
- The human gives the fields only they know: 2.7 (how it was discovered) and 2.9 (business continuity
  plan activated), and may give 2.8 (third-party origin) and 2.10 (other information). They may also
  replace the description (2.4) with their own words.
- Approval is refused while a mandatory field is empty (ITS-R Annex II, docs/dora-rules.md section 10).
- The log records who approved and when they accepted, next to the classification time (field 2.3,
  the first time the engine returned major). These are two different moments, and both are kept.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Annotated

from pydantic import StringConstraints, TypeAdapter, ValidationError, field_validator

from dora_agent.audit.log import DecisionLog
from dora_agent.config import notification_settings
from dora_agent.notification.deadline import Deadline
from dora_agent.notification.draft import Draft
from dora_agent.notification.fields import DISCOVERY_CHOICES, NotificationField
from dora_agent.rules.facts import Frozen, PersonName, UtcTime

NOT_SENT = "Approved for submission by a human. NOT SENT: this tool never sends anything."

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_NAME = TypeAdapter(PersonName)
ShortHumanText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=300)]
LongHumanText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=1000)]


class ApprovalProblem(ValueError):
    """The draft can't be approved yet. The message says what is missing."""


class HumanFields(Frozen):
    """What only the human can give. Checked before anything is used."""

    discovery: str  # field 2.7, one of DISCOVERY_CHOICES
    business_continuity_plan_activated: bool  # field 2.9
    third_party_origin: ShortHumanText | None = None  # field 2.8, name and identification code
    other_information: LongHumanText | None = None  # field 2.10
    description: str | None = None  # replaces field 2.4 if given

    @field_validator("discovery")
    @classmethod
    def _discovery(cls, value: str) -> str:
        if value not in DISCOVERY_CHOICES:
            raise ValueError("2.7 must be one of: " + "; ".join(DISCOVERY_CHOICES))
        return value

    @field_validator("third_party_origin", "other_information")
    @classmethod
    def _no_control(cls, value: str | None) -> str | None:
        if value is not None and _CONTROL.search(value):
            raise ValueError("no control characters or line breaks")
        return value

    @field_validator("description")
    @classmethod
    def _description(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        text = " ".join(value.split())
        if _CONTROL.search(text):
            raise ValueError("no control characters")
        limit = notification_settings().max_description_chars
        if len(text) > limit:
            raise ValueError(f"the description must be at most {limit} characters")
        return text


class ApprovedNotification(Frozen):
    banner: str
    run_id: str
    status: str  # NOT_SENT
    classified_at: UtcTime  # field 2.3: first time the engine returned major
    accepted_at: UtcTime  # when the human approved
    approved_by: PersonName
    rule_version: str
    fields: tuple[NotificationField, ...]
    deadline: Deadline | None

    def field(self, number: str) -> NotificationField:
        return next(f for f in self.fields if f.number == number)


def _human(field: NotificationField, by: str, value, note: str | None = None) -> NotificationField:
    return field.model_copy(update={"filled_by": "human", "status": "filled", "value": value,
                                    "source": f"human: {by}", "note": note})


def _not_given(field: NotificationField, by: str, note: str) -> NotificationField:
    return field.model_copy(update={"filled_by": "human", "status": "not_applicable", "value": None,
                                    "source": f"human: {by}", "note": note})


def approve(draft: Draft, human: HumanFields, *, approved_by: str, log: DecisionLog | None = None,
            now: datetime | None = None) -> ApprovedNotification:
    """Turn a draft into an approved notification. Raises ApprovalProblem if something is missing."""
    try:
        name = _NAME.validate_python(approved_by)
    except ValidationError as error:
        raise ApprovalProblem("the approver's name must be 1 to 80 characters, with no line breaks") from error
    accepted_at = now or datetime.now(timezone.utc)
    if accepted_at.utcoffset() is None or accepted_at.utcoffset().total_seconds() != 0:
        raise ApprovalProblem("the approval time must be UTC")

    fields: list[NotificationField] = []
    for f in draft.fields:
        if f.number == "2.4" and human.description is not None:
            f = _human(f, name, human.description, note=f"Description written or edited by {name}.")
        elif f.number == "2.7":
            f = _human(f, name, human.discovery)
        elif f.number == "2.8":
            f = (_human(f, name, human.third_party_origin) if human.third_party_origin else
                 _not_given(f, name, "No third-party provider or other financial entity named as the origin."))
        elif f.number == "2.9":
            f = _human(f, name, human.business_continuity_plan_activated)
        elif f.number == "2.10":
            f = (_human(f, name, human.other_information) if human.other_information else
                 _not_given(f, name, "No other information given."))
        fields.append(f)

    missing = [f"{f.number} {f.name}" for f in fields if f.mandatory and f.status != "filled"]
    if missing:
        raise ApprovalProblem("these mandatory fields are still empty: " + "; ".join(missing))

    approved = ApprovedNotification(
        banner=draft.banner, run_id=draft.run_id, status=NOT_SENT, classified_at=draft.classified_at,
        accepted_at=accepted_at, approved_by=name, rule_version=draft.rule_version, fields=tuple(fields),
        deadline=draft.deadline,
    )
    if log is not None:
        log.write("notification_approved", approved_by=name, accepted_at=accepted_at.isoformat(),
                  classified_at=draft.classified_at.isoformat(),
                  due_at=draft.deadline.due_at.isoformat() if draft.deadline else None,
                  accepted_after_deadline=bool(draft.deadline and accepted_at > draft.deadline.due_at),
                  filled_by={f.number: f.filled_by for f in fields if f.status == "filled"},
                  description_by=approved.field("2.4").filled_by, sent=False)
    return approved


def render_text(notification: Draft | ApprovedNotification) -> str:
    """Plain text for the screen or a copy-paste. Shows who filled each field."""
    lines = [notification.banner, ""]
    if isinstance(notification, ApprovedNotification):
        lines += [notification.status,
                  f"Approved by {notification.approved_by} at {notification.accepted_at:%Y-%m-%d %H:%M UTC}.", ""]
    else:
        lines += [notification.status, ""]
    deadline = notification.deadline
    if deadline is None:
        lines += ["Deadline: unknown until the detection time (field 2.2) is known.", ""]
    else:
        lines += [f"Deadline: {deadline.due_at:%Y-%m-%d %H:%M UTC}. {deadline.rule}", deadline.weekend_note]
        if deadline.overdue_note:
            lines.append(deadline.overdue_note)
        lines.append("")
    for f in notification.fields:
        if f.status == "filled":
            value = "; ".join(f.value) if isinstance(f.value, tuple) else (
                ("Yes" if f.value else "No") if isinstance(f.value, bool) else f.value)
        else:
            value = "(not applicable)" if f.status == "not_applicable" else "(waiting)"
        lines.append(f"{f.number} {f.name}: {value}   [{f.source}]")  # the source names who filled it
        if f.note:
            lines.append(f"      Note: {f.note}")
    return "\n".join(lines)
