"""Turns run results, the trace and notification drafts into plain text and table rows for the page.

No Gradio here, so every view can be tested on its own (block 6 plan, step 2).

Safety rules (block 6 plan, section 6; security framework, "Unsafe output"):
- Every view returns plain text (str) or table rows of plain text. Nothing is HTML or Markdown.
  The page puts these into read-only plain-text boxes only, so `<script>` or `**bold**` from a ticket
  shows as those exact characters.
- Text is never HTML-escaped here: escaping would show "&lt;" in a plain-text box. The box does the job.
- Text from the ticket, the AI, tools or a person that must sit on ONE line (trace lines, table cells,
  question labels) is passed through `one_line()`. It removes line breaks, other control characters and
  the invisible Unicode characters that can flip or hide text (bidi controls, zero-width characters),
  so a ticket can't fake an extra trace line or make a line read differently from what it holds.
- Views only read. They never change a run, a fact or a draft, and they never decide anything:
  every result shown is the rules engine's (CLAUDE.md hard rule 1).
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any

from dora_agent.agent.fact_store import Conflict, ReviewItem
from dora_agent.agent.loop import PendingQuestion, RunResult
from dora_agent.notification.approval import ApprovedNotification, render_text
from dora_agent.notification.draft import Draft
from dora_agent.rules.engine import Classification
from dora_agent.rules.facts import HUMAN_CONFIRMED, Fact, IncidentFacts

# Line breaks and other C0/C1 control characters, Unicode line and paragraph separators, bidi controls
# (U+202A-U+202E, U+2066-U+2069, U+200E/F, U+061C), zero-width characters and the byte order mark.
_UNSAFE_ON_ONE_LINE = re.compile(
    "[\x00-\x1f\x7f-\x9f  ‪-‮⁦-⁩​-‏؜﻿]+")
_SPACES = re.compile(r"\s+")

# Longest text a trace line shows from one free-text field. The full text is in the raw JSON tab.
TRACE_TEXT_CHARS = 200
# Longest text one table cell or label shows.
CELL_CHARS = 300

RESULT_WORDS = {
    "major": "MAJOR",
    "not_major": "NOT MAJOR",
    "undetermined": "UNDETERMINED",
    "not_an_incident": "NOT AN INCIDENT",
}
STATUS_WORDS = {
    "finished": "Finished",
    "needs_human": "Waiting for you: please answer the questions and review the suggestions",
    "stopped": "Stopped early",
}
SOURCE_WORDS = {
    "ticket": "ticket",
    "service_list": "service list",
    "monitoring": "monitoring",
    "client_data": "client data",
    "security_alerts": "security alerts",
    "supplier_register": "supplier register",
    "human": "a person",
    "ai_suggestion": "AI suggestion (not used until a person confirms it)",
}

# Fixed text (block 6 plan, section 7). Shown next to the deadline of a replayed sample that was
# classified more than 24 hours after detection. The deadline itself is not changed.
LATE_SAMPLE_NOTE = (
    "This sample replays an incident detected on {detected}. The tool classifies it now, so classification "
    "comes more than 24 hours after detection, and RTS-R Art. 5(2) gives 4 hours from classification. "
    "In a live incident, classification happens within hours of detection and RTS-R Art. 5(1)(a) applies."
)

FACT_HEADERS = ("Fact", "Value", "Source", "Estimate", "Confirmed by", "Used by the rules")


# ---------- small helpers ----------


def one_line(value: Any, limit: int = CELL_CHARS) -> str:
    """Any value as one safe line of plain text, at most `limit` characters ("..." marks a cut)."""
    text = _SPACES.sub(" ", _UNSAFE_ON_ONE_LINE.sub(" ", _plain(value))).strip()
    return text if len(text) <= limit else text[: max(limit - 3, 0)].rstrip() + "..."


def _plain(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, datetime):
        return format_time(value)
    if isinstance(value, int):
        return f"{value:,}"
    if isinstance(value, (tuple, list)):
        return ", ".join(_plain(v) for v in value)
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, default=str, sort_keys=True)
    return str(value)


def format_time(value: datetime | str | None) -> str:
    """A UTC time as "2026-11-05 08:00 UTC". Text that isn't a time is returned as one line."""
    if value is None:
        return "unknown"
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return one_line(value)
    if value.utcoffset() is None:
        return value.strftime("%Y-%m-%d %H:%M") + " (no time zone)"
    return value.strftime("%Y-%m-%d %H:%M UTC")


def _value(name: str, fact: Fact) -> str:
    if not fact.known:
        return "unknown"
    if name.endswith("_eur") and isinstance(fact.value, int) and not isinstance(fact.value, bool):
        return f"EUR {fact.value:,}"
    return one_line(fact.value)


# ---------- the result ----------


def headline(result: RunResult) -> str:
    """One line: the rules engine's result and where the run is."""
    word = RESULT_WORDS[result.classification.result]
    return f"Result from the rules engine: {word}. Status: {STATUS_WORDS[result.status]}."


def result_text(result: RunResult) -> str:
    """The result panel: summary, reasons with articles, what is missing, conflicts and run limits."""
    c = result.classification
    lines = [headline(result), "", c.summary, "", result.message, ""]
    lines += reasons_lines(c)
    lines += ["", *missing_lines(c)]
    if result.conflicts:
        lines += ["", "Conflicts between a system and a person's answer (the person's answer is used):"]
        lines += [f"- {one_line(x.describe())}" for x in result.conflicts]
    lines += ["", f"Run {result.run_id}: {result.steps_used} AI step(s), {result.tool_calls_used} tool call(s), "
              f"{result.human_rounds} round(s) of questions, {result.seconds_used:.0f} s of working time "
              f"(time spent waiting for you not counted). Stop reason: {result.stop_reason}. "
              f"Rule version {c.rule_version}, measured at {format_time(c.as_of)}."]
    return "\n".join(lines)


def reasons_lines(c: Classification) -> list[str]:
    """One line per step of the rule: incident or not, the gate, T5-b and the six other thresholds."""
    return ["Reasons (docs/dora-rules.md, with articles):", *(f"- {one_line(r, 2000)}" for r in c.reasons)]


def missing_lines(c: Classification) -> list[str]:
    lines = []
    if c.missing:
        lines.append("Still missing, and these decide the result: " + ", ".join(c.missing) + ".")
    else:
        lines.append("Nothing is missing that would change the result.")
    if c.pending_confirmations:
        lines.append("Waiting for a person to confirm (not used until then): "
                     + ", ".join(c.pending_confirmations) + ".")
    return lines


def fact_rows(facts: IncidentFacts) -> list[list[str]]:
    """Every known fact: value, source, estimate flag, who confirmed it, and whether the rules use it yet.

    Unknown facts are left out here. The ones that decide the result are listed under "Still missing".
    """
    rows: list[list[str]] = []
    if facts.service_id:
        rows.append(["service_id", one_line(facts.service_id), "service list", "", "", "yes"])
    for name in type(facts).model_fields:
        if name == "service_id":
            continue
        fact: Fact = getattr(facts, name)
        if not fact.known:
            continue
        used = facts.usable(name) is not None
        needs = " (judgment call, needs a person)" if not used and name in HUMAN_CONFIRMED else ""
        rows.append([
            name,
            _value(name, fact),
            one_line(SOURCE_WORDS.get(fact.source or "", fact.source)),
            "estimate" if fact.is_estimate else "",
            one_line(fact.confirmed_by),
            "yes" if used else "not yet" + needs,
        ])
    return rows


def conflict_lines(conflicts: tuple[Conflict, ...]) -> list[str]:
    return [one_line(x.describe()) for x in conflicts]


# ---------- questions and ticket review ----------


def question_label(question: PendingQuestion) -> str:
    """The fixed question with its legal basis, for the label next to the answer box."""
    hint = " An estimate is allowed: tick the box if it is one." if question.allows_estimate else ""
    return one_line(f"{question.text} (Basis: {question.basis}){hint}", 600)


def review_label(item: ReviewItem) -> str:
    """One AI suggestion from the ticket, for a person to accept or reject. Never used until confirmed."""
    value = one_line(item.suggested_value, 120)
    reason = one_line(item.reason, CELL_CHARS)
    return f"The AI read from the ticket: {item.fact_name} = {value}. Its reason: {reason}"


# ---------- the trace ----------


def trace_text(trace: tuple[dict, ...] | list[dict]) -> str:
    """Every logged record in order, one line each."""
    return "\n".join(trace_line(record) for record in trace)


def trace_line(record: dict) -> str:
    seq = record.get("seq", "?")
    kind = one_line(record.get("kind", "unknown"), 40)
    detail = _DETAILS.get(kind, _other)(record)
    return one_line(f"#{seq} {format_time(record.get('at'))} {kind}: {detail}", 1000)


def trace_json(trace: tuple[dict, ...] | list[dict]) -> str:
    """The raw records as JSON text, for the collapsible tab and the download. Line breaks are escaped."""
    return json.dumps(list(trace), indent=2, default=str)


def _t(value: Any) -> str:
    return one_line(value, TRACE_TEXT_CHARS)


def _run_started(r: dict) -> str:
    ticket = r.get("ticket") or ""
    return (f"ticket received ({len(ticket)} characters), reported at {format_time(r.get('reported_at'))}, "
            f"measured at {format_time(r.get('as_of'))}, provider {_t(r.get('provider'))}"
            + (f", model {_t(r.get('model'))}" if r.get("model") else "")
            + f", rule version {_t(r.get('rule_version'))}")


def _llm_step(r: dict) -> str:
    proposed = [_t(p.get("tool")) for p in r.get("proposed") or [] if isinstance(p, dict)]
    text = f' wrote "{_t(r.get("text"))}"' if r.get("text") else ""
    tools = f" proposed {', '.join(proposed)}" if proposed else " proposed no tool"
    return (f"AI step {r.get('step')}:{text}{tools} "
            f"({r.get('input_tokens', 0)} tokens in, {r.get('output_tokens', 0)} out)")


def _llm_error(r: dict) -> str:
    return f"the AI call failed: {_t(r.get('error'))}"


def _tool_call(r: dict) -> str:
    by = r.get("by")
    who = "" if by == "llm" else f" (run by {_t(by)})"
    outcome = "ok" if r.get("ok") else f"refused: {_t(r.get('error'))}"
    repeat = ", repeat answered from memory" if r.get("repeat") else ""
    facts = r.get("facts_recorded") or []
    return (f"{_t(r.get('tool'))}{who} with {_t(r.get('arguments'))}: {outcome}{repeat}"
            + (f"; facts recorded: {_t(facts)}" if facts else ""))


def _fact(r: dict) -> str:
    by = f", by {_t(r.get('by'))}" if r.get("by") else ""
    note = f" ({_t(r.get('note'))})" if r.get("note") else ""
    return (f"{_t(r.get('fact_name'))} = {_t(r.get('value')) or 'no value'} "
            f"({_t(r.get('action'))}, source {_t(r.get('source')) or 'none'}{by}){note}")


def _human_input(r: dict) -> str:
    unanswered = r.get("unanswered") or []
    return (f"{_t(r.get('by'))} answered {_t(r.get('answers') or {})}; estimates: {_t(r.get('estimates')) or 'none'}; "
            f"reviewed {len(r.get('review') or [])} suggestion(s)"
            + (f"; left unanswered: {_t(unanswered)}" if unanswered else ""))


def _rules_check(r: dict) -> str:
    first = r.get("check_first") or []
    return (f"rules engine says {_t(r.get('result'))}, {r.get('missing', 0)} fact(s) missing"
            + (f"; check first: {_t(first)}" if first else ""))


def _note(r: dict) -> str:
    extra = r.get("asked") or r.get("already_asked")
    return _t(r.get("note")) + (f": {_t(extra)}" if extra else "")


def _end(r: dict) -> str:
    return (f"{_t(r.get('status'))} ({_t(r.get('stop_reason'))}), result {_t(r.get('result'))}: "
            f"{_t(r.get('summary'))}")


def _description(r: dict) -> str:
    problems = r.get("problems") or []
    return (f"field 2.4 written by {_t(r.get('written_by'))}"
            + (f"; problems found: {_t(problems)}" if problems else ""))


def _draft(r: dict) -> str:
    return (f"draft prepared, classified at {format_time(r.get('classified_at'))}, due "
            f"{format_time(r.get('due_at')) if r.get('due_at') else 'unknown'}, overdue {_t(r.get('overdue'))}; "
            f"waiting fields: {_t(r.get('waiting')) or 'none'}; sent: no")


def _approved(r: dict) -> str:
    return (f"approved by {_t(r.get('approved_by'))} at {format_time(r.get('accepted_at'))}, classified at "
            f"{format_time(r.get('classified_at'))}; sent: no")


def _other(r: dict) -> str:
    return "see the raw JSON tab"


_DETAILS = {
    "run_started": _run_started, "llm_step": _llm_step, "llm_error": _llm_error, "tool_call": _tool_call,
    "fact": _fact, "human_input": _human_input, "rules_check": _rules_check, "human_only": _note,
    "gate_check": _note, "repeat_limit": _note, "result": _end, "paused": _end,
    "notification_description": _description, "notification_draft": _draft,
    "notification_approved": _approved,
}


# ---------- the notification ----------


def late_sample_note(draft: Draft | ApprovedNotification, *, sample: bool) -> str | None:
    """The fixed "why is this late" note, for a replayed sample classified more than 24 h after detection."""
    deadline = draft.deadline
    if not sample or deadline is None or not deadline.late_classification:
        return None
    return LATE_SAMPLE_NOTE.format(detected=format_time(deadline.aware_at))


def notification_text(notification: Draft | ApprovedNotification, *, sample: bool = False) -> str:
    """The draft or approved notification as plain text (render_text), plus the late note for samples."""
    text = render_text(notification)
    note = late_sample_note(notification, sample=sample)
    return text + ("\n\n" + note if note else "")


def notification_json(notification: Draft | ApprovedNotification) -> str:
    """The draft or approved notification as JSON text, for the download button."""
    return notification.model_dump_json(indent=2)
