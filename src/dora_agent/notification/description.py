"""Field 2.4, the description of the incident: drafted by the AI, checked by code.

ITS-R (2025/302) Annex II field 2.4, RTS-R (2025/301) Art. 2(c): a high-level overview of possible causes,
immediate impacts and systems affected (docs/dora-rules.md section 10).

How ticket text is kept out (block 5b plan, approved by Sam on 6 November 2026):
1. The AI never sees the ticket or free text from any tool. Its input is a fact list built here by code
   from facts the rules engine may use (confirmed facts only). Fact notes and confirmer names are left
   out, because they are free text.
2. The AI writes this one field only. Code fills every other field.
3. Code checks the AI's text: not empty, not too long, plain text, no links, no email addresses,
   no markup, no tool calls, and every number in it must appear in the fact list.
   If any check fails, or the AI can't be reached, a description written by code is used instead.
4. Possible causes stay "under investigation" unless a human types them.

This module sends nothing to anyone except the one LLM call through the provider interface (hard rule 7).
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Literal

from dora_agent.audit.log import DecisionLog
from dora_agent.config import NotificationSettings, notification_settings
from dora_agent.connectors import get_service
from dora_agent.llm.provider import LlmError, LlmProvider, Message
from dora_agent.notification.fields import NotificationField, NotMajor, criteria_met
from dora_agent.notification.prompts import DESCRIPTION_SYSTEM_PROMPT, DESCRIPTION_USER_PROMPT
from dora_agent.rules.engine import Classification
from dora_agent.rules.facts import Frozen
from dora_agent.rules.thresholds import EEA_MEMBER_STATES

UNDER_INVESTIGATION = "under investigation"
WrittenBy = Literal["ai_draft", "code_fallback"]

_CONTROL = re.compile(r"[\x00-\x09\x0b-\x1f\x7f]")  # every control character except a line break
_LINK = re.compile(r"(https?:|ftp:|www\.|://|\b[\w-]+\.(com|net|org|io|de|eu|info|example)\b)", re.IGNORECASE)
_EMAIL = re.compile(r"@")
_MARKUP = re.compile(r"[<>`*#\[\]{}|\\]|^\s*[-+]\s", re.MULTILINE)
_THOUSANDS = re.compile(r"(?<=\d)[,  '](?=\d{3}\b)")
_NUMBER = re.compile(r"\d+")


class Description(Frozen):
    """What goes into field 2.4, and how it was made."""

    text: str
    written_by: WrittenBy
    problems: tuple[str, ...]  # why the AI text was not used (empty if it was)
    causes_from_human: bool
    fact_lines: tuple[str, ...]  # exactly what the AI was given (logged, hard rule 9)


# ---------- the fact list, built by code ----------


def _time(value: datetime) -> str:
    return value.strftime("%Y-%m-%d %H:%M UTC")


def _count(value: int) -> str:
    return f"{value:,}"


def _estimate(facts, name: str) -> str:
    return " (estimate)" if getattr(facts, name).is_estimate else ""


def check_causes(causes: str | None, settings: NotificationSettings) -> str | None:
    """A human's possible causes: trimmed, one line, length-capped. None or blank means not given."""
    if causes is None or not causes.strip():
        return None
    text = " ".join(causes.split())
    if _CONTROL.search(text):
        raise ValueError("possible causes must not contain control characters")
    if len(text) > settings.max_causes_chars:
        raise ValueError(f"possible causes must be at most {settings.max_causes_chars} characters")
    return text


def fact_lines(classification: Classification, causes: str | None = None) -> tuple[str, ...]:
    """The AI's whole input: one line per confirmed fact. Only values the rules engine may use."""
    facts = classification.facts
    use = facts.usable
    lines: list[str] = []

    if facts.service_id is not None:
        found = get_service(facts.service_id)
        name = found.service.name if found.found else None
        lines.append(f"System or service affected: {name} ({facts.service_id})" if name
                     else f"System or service affected: {facts.service_id}")
    if use("critical_or_important") is True:
        lines.append("The service supports a critical or important function: yes")

    for label, name in (("Incident started", "incident_start"), ("Incident detected", "detected_at"),
                        ("Service downtime started", "downtime_start"),
                        ("Normal service restored", "service_restored_at"),
                        ("Backlog cleared", "backlog_cleared_at"), ("Incident resolved", "resolved_at")):
        if use(name) is not None:
            lines.append(f"{label}: {_time(use(name))}{_estimate(facts, name)}")
    if use("resolved_at") is None:
        lines.append("Incident resolved: not yet")

    if use("affected_clients") is not None:
        of = f" of {_count(use('total_clients'))} clients using the service" if use("total_clients") else ""
        lines.append(f"Clients affected: {_count(use('affected_clients'))}{of}{_estimate(facts, 'affected_clients')}")
    if use("affected_counterparts") is not None:
        lines.append(f"Financial counterparts affected: {_count(use('affected_counterparts'))}"
                     f"{_estimate(facts, 'affected_counterparts')}")
    if use("affected_tx_count") is not None:
        lines.append(f"Transactions affected: {_count(use('affected_tx_count'))}{_estimate(facts, 'affected_tx_count')}")
    if use("affected_tx_value_eur") is not None:
        lines.append(f"Value of transactions affected: EUR {_count(use('affected_tx_value_eur'))}"
                     f"{_estimate(facts, 'affected_tx_value_eur')}")
    if use("relevant_parties_affected") is True:
        lines.append("Relevant clients or financial counterparts affected: yes")

    states = use("affected_member_states")
    if states:
        eea = sorted({"GR" if s == "EL" else s for s in states if s in EEA_MEMBER_STATES})
        if eea:
            lines.append(f"EEA Member States affected: {', '.join(eea)}")

    reputation = [label for label, name in (("media coverage", "media_coverage"),
                                            ("repeated client complaints", "repeated_complaints"),
                                            ("impact on regulatory requirements", "regulatory_requirements_impact"),
                                            ("likely loss of clients", "client_loss_impact"))
                  if use(name) is True]
    if reputation:
        lines.append(f"Reputational impact: {', '.join(reputation)}")

    if use("malicious_access") is True:
        own = " to Rheinbank's own systems" if use("access_on_own_systems") is True else ""
        lines.append(f"Successful, malicious and unauthorised access{own}: confirmed")
    data = [label for label, name in (("availability", "data_availability_impact"),
                                      ("authenticity", "data_authenticity_impact"),
                                      ("integrity", "data_integrity_impact"),
                                      ("confidentiality", "data_confidentiality_impact")) if use(name) is True]
    if data:
        lines.append(f"Data affected in: {', '.join(data)}")

    if use("costs_eur") is not None:
        lines.append(f"Costs and losses so far: EUR {_count(use('costs_eur'))}{_estimate(facts, 'costs_eur')}")

    lines.append(f"Classification criteria met: {'; '.join(criteria_met(classification))}")
    lines.append(f"Possible causes: {causes if causes else UNDER_INVESTIGATION}")
    return tuple(lines)


# ---------- checks on the AI's text ----------


def _numbers(text: str) -> set[str]:
    """Every whole number in the text, with thousands separators removed and leading zeros ignored.

    Kept as text, not converted with int(): a number thousands of digits long from the AI would make
    int() raise, and the check must never crash (it falls back to code instead).
    """
    return {n.lstrip("0") or "0" for n in _NUMBER.findall(_THOUSANDS.sub("", text))}


def check_ai_text(text: str, lines: tuple[str, ...], settings: NotificationSettings) -> tuple[str, list[str]]:
    """Return the cleaned text and the list of problems. No problems means the text may be used."""
    problems: list[str] = []
    cleaned = text.strip()
    if not cleaned:
        return "", ["empty"]
    if _CONTROL.search(cleaned):
        problems.append("control_characters")
    cleaned = " ".join(cleaned.split())
    if len(cleaned) > settings.max_description_chars:
        problems.append("too_long")
    if _LINK.search(cleaned):
        problems.append("link")
    if _EMAIL.search(cleaned):
        problems.append("email")
    if _MARKUP.search(text):
        problems.append("markup")
    unknown = _numbers(cleaned) - _numbers("\n".join(lines))
    if unknown:
        problems.append("number_not_in_facts")
    return cleaned, problems


# ---------- the description written by code ----------


def fallback_text(lines: tuple[str, ...]) -> str:
    """Plain sentences from the same fact list. Used when the AI text can't be used.

    Who wrote it is shown in the field's note and source, not in the text itself.
    """
    return " ".join(f"{line}." for line in lines)


# ---------- putting it together ----------


def describe_incident(classification: Classification, provider: LlmProvider, *, causes: str | None = None,
                      log: DecisionLog | None = None,
                      settings: NotificationSettings | None = None) -> Description:
    """Draft field 2.4. Only for a major incident. Never raises because of the AI: it falls back to code."""
    if classification.result != "major":
        raise NotMajor(f"no initial notification: the result is {classification.result}, not major")
    settings = settings or notification_settings()
    human_causes = check_causes(causes, settings)
    lines = fact_lines(classification, human_causes)

    messages = [
        Message(role="system", content=DESCRIPTION_SYSTEM_PROMPT.format(max_chars=settings.max_description_chars)),
        Message(role="user", content=DESCRIPTION_USER_PROMPT.format(facts="\n".join(f"- {line}" for line in lines))),
    ]
    problems: list[str]
    try:
        response = provider.chat(messages, [])  # no tools: the AI can only write text
        cleaned, problems = check_ai_text(response.text, lines, settings)
        if response.tool_calls:
            problems.append("tool_call")
    except LlmError as error:
        cleaned, problems = "", [f"llm_error: {error.code or 'unavailable'}"]

    if problems:
        description = Description(text=fallback_text(lines), written_by="code_fallback", problems=tuple(problems),
                                  causes_from_human=human_causes is not None, fact_lines=lines)
    else:
        description = Description(text=cleaned, written_by="ai_draft", problems=(),
                                  causes_from_human=human_causes is not None, fact_lines=lines)
    if log is not None:
        log.write("notification_description", field="2.4", written_by=description.written_by,
                  problems=list(description.problems), causes_from_human=description.causes_from_human,
                  fact_lines=list(lines), text=description.text, provider=getattr(provider, "name", "unknown"))
    return description


def description_field(description: Description) -> NotificationField:
    """Field 2.4, ready to replace the waiting placeholder from fields.code_fields()."""
    if description.written_by == "ai_draft":
        filled_by, source = "ai_draft", "AI draft from confirmed facts (no ticket text)"
        note = "AI draft. Check every sentence against the facts before approving."
    else:
        filled_by, source = "code", "written by code from confirmed facts"
        note = ("Written by code from confirmed facts. The AI draft was not used ("
                + ", ".join(description.problems) + ").")
    return NotificationField(number="2.4", name="Description of the ICT-related incident", mandatory=True,
                             filled_by=filled_by, status="filled", value=description.text, source=source, note=note)
