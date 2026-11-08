"""What each button on the page does, in plain Python. No Gradio here, so it can be tested directly.

The page (app.py) only lays out the boxes and calls these functions. Each function takes the session
and what the person typed, and gives back a `Screen`: plain text and table rows for every box.

Rules (block 6 plan, CLAUDE.md hard rules):
- The result is always the rules engine's (hard rule 1). Nothing here decides anything.
- The person's name for answers and approval comes only from what they type here, never from the AI.
- Samples come only from cases/samples.json (no answers, no real names), never from the answer key.
- Every run is measured at "now", the time of the run (Sam, 8 November 2026).
- Error messages shown on the page are fixed, plain texts. Unexpected errors show a fixed message
  only; the details go to the notebook's log output, never to the page.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from dora_agent.agent.fact_store import ReviewDecision, ReviewItem
from dora_agent.agent.loop import AgentRun, PendingQuestion, RunProblem, RunResult
from dora_agent.agent.questions import QUESTIONS
from dora_agent.agent.values import FACT_KINDS
from dora_agent.config import PROJECT_ROOT, agent_limits
from dora_agent.llm.provider import LlmError, LlmProvider
from dora_agent.notification.approval import ApprovalProblem, ApprovedNotification, HumanFields, approve
from dora_agent.notification.draft import Draft, DraftProblem, prepare_draft
from dora_agent.notification.fields import NotMajor
from dora_agent.rules.facts import MAX_NUMBER
from dora_agent.ui import views

log = logging.getLogger(__name__)

SAMPLES_PATH = PROJECT_ROOT / "cases" / "samples.json"
# Decision logs and approved notifications of runs made on the page (git-ignored, like all of logs/).
RUN_LOG_DIR = PROJECT_ROOT / "logs" / "runs"

UNEXPECTED = ("Something went wrong. Nothing was decided or sent. The details are in the notebook's "
              "output below the launch cell, not on this page.")
NO_KEY_HINT = ("Add your Groq key in Colab Secrets as GROQ_API_KEY, switch on notebook access, and run the "
               "key cell again. See Troubleshooting at the top of the notebook.")
# A reported time may be a little ahead of this machine's clock, but not more.
CLOCK_TOLERANCE = timedelta(minutes=5)
YES_NO = {"yes": True, "no": False}
_WHOLE_NUMBER = re.compile(r"\d+|\d{1,3}(?:([,. '])\d{3})(?:\1\d{3})*")


@dataclass(frozen=True)
class Sample:
    sample_id: str
    title: str
    ticket: str
    reported_at: str


@dataclass
class Session:
    """One person's page: the current run and what was drafted. Kept per browser session by the page."""

    run: AgentRun | None = None
    result: RunResult | None = None
    provider: LlmProvider | None = None
    sample: bool = False  # True: an unchanged sample ticket, replayed (for the late-classification note)
    draft: Draft | None = None
    approved: ApprovedNotification | None = None
    downloads: tuple[str, str] | None = None  # text and JSON file of the approved notification


@dataclass(frozen=True)
class Screen:
    """Everything the page shows, as plain text. Built only by `screen()`."""

    status: str = ""
    headline: str = ""
    result: str = ""
    facts: list[list[str]] = field(default_factory=list)
    trace: str = ""
    trace_json: str = "[]"
    questions: tuple[PendingQuestion, ...] = ()
    review: tuple[ReviewItem, ...] = ()
    review_labels: dict[str, str] = field(default_factory=dict)
    reset_inputs: bool = False  # True: a new round of questions, so old answers are cleared
    can_draft: bool = False
    draft: str = ""
    can_approve: bool = False
    approved: str = ""
    downloads: tuple[str, str] | None = None


# ---------- samples ----------


@lru_cache(maxsize=1)
def samples() -> tuple[Sample, ...]:
    data = json.loads(SAMPLES_PATH.read_text(encoding="utf-8"))
    if "SYNTHETIC DATA" not in data.get("about", ""):
        raise ValueError("cases/samples.json must be marked as synthetic data")
    return tuple(Sample(s["sample_id"], s["title"], s["ticket"], s["reported_at"]) for s in data["samples"])


def sample_choices() -> list[tuple[str, str]]:
    """(label, sample_id) pairs for the picker."""
    return [(f"{s.sample_id}: {s.title}", s.sample_id) for s in samples()]


def load_sample(sample_id: str | None) -> tuple[str, str]:
    """The ticket and reported time of one sample, or two empty texts."""
    sample = next((s for s in samples() if s.sample_id == sample_id), None)
    return (sample.ticket, sample.reported_at) if sample else ("", "")


def _is_unchanged_sample(sample_id: str | None, ticket: str, reported_at: datetime) -> bool:
    sample = next((s for s in samples() if s.sample_id == sample_id), None)
    return bool(sample and sample.ticket == ticket and parse_reported_at(sample.reported_at, None) == reported_at)


# ---------- what the person typed ----------


class InputProblem(ValueError):
    """What was typed doesn't fit. The message is plain and safe to show."""


def parse_reported_at(text: str, now: datetime | None) -> datetime:
    """A reported time as typed, in UTC. A time without a zone is read as UTC (the box says UTC)."""
    text = (text or "").strip()
    if not text or len(text) > 40:
        raise InputProblem("Give the reported time in UTC, like 2026-11-08T09:30Z.")
    try:
        value = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise InputProblem("Give the reported time in UTC, like 2026-11-08T09:30Z.") from None
    value = value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
    if now is not None and value > now + CLOCK_TOLERANCE:
        raise InputProblem("The reported time is in the future. Check the date and time (UTC).")
    return value


def typed_value(fact_name: str, text: str) -> Any:
    """A typed answer in the form the agent expects. The agent checks it again (values.parse_value)."""
    text = (text or "").strip()
    kind = FACT_KINDS.get(fact_name)
    if kind == "yes_no":
        if text.lower() not in YES_NO:
            raise InputProblem(f"{fact_name}: type yes or no.")
        return YES_NO[text.lower()]
    if kind in ("count", "euros"):
        number = re.sub(r"(?i)^(eur|€)\s*|\s*(eur|€)$", "", text)
        # Separators only between groups of three digits: "150,000" or "150.000", but never "1.5".
        if not _WHOLE_NUMBER.fullmatch(number):
            raise InputProblem(f"{fact_name}: type a whole number, like 150000 or 150,000.")
        digits = re.sub(r"\D", "", number)
        if len(digits) > len(str(MAX_NUMBER)):
            raise InputProblem(f"{fact_name}: the number is too large.")
        return int(digits)
    if kind == "member_states":
        codes = [c.upper() for c in re.split(r"[\s,;]+", text) if c]
        if not codes:
            raise InputProblem(f"{fact_name}: type country codes, like DE, AT.")
        return codes
    return text  # a time: the agent reads it and says plainly if it doesn't fit


# ---------- the screen ----------


def screen(session: Session, status: str = "", *, reset_inputs: bool = False) -> Screen:
    result = session.result
    if result is None:
        return Screen(status=status)
    waiting = result.status == "needs_human"
    major_done = result.classification.result == "major" and result.status != "needs_human"
    approved = session.approved
    return Screen(
        status=status or result.message,
        headline=views.headline(result),
        result=views.result_text(result),
        facts=views.fact_rows(result.classification.facts),
        trace=views.trace_text(session.run.log.records),
        trace_json=views.trace_json(session.run.log.records),
        questions=result.questions if waiting else (),
        review=result.review_items if waiting else (),
        review_labels={i.fact_name: views.review_label(i) for i in result.review_items} if waiting else {},
        reset_inputs=reset_inputs,
        can_draft=major_done and approved is None,
        draft=views.notification_text(session.draft, sample=session.sample) if session.draft else "",
        can_approve=session.draft is not None and approved is None,
        approved=views.notification_text(approved, sample=session.sample) if approved else "",
        downloads=session.downloads,
    )


def _guarded(action: Callable[[], Screen], session: Session) -> Screen:
    """Run one button's action. Known problems show their plain message; anything else a fixed one."""
    try:
        return action()
    except (InputProblem, RunProblem, ApprovalProblem, DraftProblem, NotMajor) as problem:
        return screen(session, f"Not done: {problem}")
    except LlmError as error:
        return screen(session, f"Not done: the AI could not be used ({error}).")
    except ValidationError as error:
        first = error.errors()[0]
        where = ".".join(str(p) for p in first.get("loc", ())) or "input"
        return screen(session, f"Not done: {where}: {first.get('msg', 'not valid')}.")
    except Exception:  # noqa: BLE001 - the page must never show raw error text
        log.exception("unexpected error on the page")
        return screen(session, UNEXPECTED)


# ---------- the buttons ----------


def start(session: Session, ticket: str, reported_text: str, sample_id: str | None,
          provider_factory: Callable[[], LlmProvider], *, now: datetime | None = None,
          log_dir: Path | None = RUN_LOG_DIR) -> Screen:
    """Run: a new agent run for this ticket, measured at now. Replaces any earlier run on this page."""

    def action() -> Screen:
        moment = now or datetime.now(timezone.utc)
        text = ticket or ""
        if not text.strip():
            raise InputProblem("Paste a ticket or pick a sample first.")
        if len(text) > agent_limits().max_ticket_chars:
            raise InputProblem(f"The ticket is longer than {agent_limits().max_ticket_chars} characters.")
        reported_at = parse_reported_at(reported_text, moment)
        try:
            provider = provider_factory()
        except LlmError as error:
            raise LlmError(f"{error}. {NO_KEY_HINT}") from None
        run = AgentRun(text, reported_at, provider, as_of=moment, log_dir=log_dir)
        session.run, session.provider, session.result = run, provider, None
        session.sample = _is_unchanged_sample(sample_id, text, reported_at)
        session.draft = session.approved = session.downloads = None
        session.result = run.start()
        return screen(session, reset_inputs=True)

    return _guarded(action, session)


def send_answers(session: Session, name: str, answers: dict[str, tuple[Any, bool]],
                 review: dict[str, tuple[str | None, str, bool]]) -> Screen:
    """Send answers: the person's answers and their decision on every ticket suggestion, then go on.

    answers: fact_name -> (yes/no/unsure or typed text, estimate ticked). Only asked questions are used;
    an empty answer leaves the question unanswered.
    review: fact_name -> (confirm/correct/reject or None, corrected value as text, estimate ticked).
    """

    def action() -> Screen:
        result = session.result
        if session.run is None or result is None or result.status != "needs_human":
            raise InputProblem("There is nothing to answer right now.")
        if not (name or "").strip():
            raise InputProblem("Type your name first. It is recorded with your answers.")
        given: dict[str, Any] = {}
        estimates: set[str] = set()
        for question in result.questions:
            raw, estimate = answers.get(question.fact_name, (None, False))
            if raw is None or (isinstance(raw, str) and not raw.strip()):
                continue  # left unanswered
            given[question.fact_name] = raw if question.choices else typed_value(question.fact_name, raw)
            if estimate and question.allows_estimate:
                estimates.add(question.fact_name)
        decisions = []
        for item in result.review_items:
            choice, value, estimate = review.get(item.fact_name, (None, "", False))
            if choice not in ("confirm", "correct", "reject"):
                raise InputProblem(f"Decide every suggestion from the ticket: {item.fact_name} has no decision.")
            corrected = typed_value(item.fact_name, value) if choice == "correct" else None
            decisions.append(ReviewDecision(fact_name=item.fact_name, action=choice, value=corrected,
                                            is_estimate=bool(estimate) and choice != "reject"))
        session.result = session.run.resume(confirmed_by=name.strip(), answers=given, estimates=estimates,
                                            review=decisions)
        return screen(session, reset_inputs=True)

    return _guarded(action, session)


def make_draft(session: Session, causes: str) -> Screen:
    """Prepare draft: the initial notification for a major result. Typed causes go into field 2.4."""

    def action() -> Screen:
        result = session.result
        if session.run is None or result is None or result.status == "needs_human":
            raise InputProblem("Finish the run first.")
        if session.approved is not None:
            raise InputProblem("This notification is already approved. Start a new run to draft again.")
        session.draft = prepare_draft(result.run_id, result.classification, session.run.log.records,
                                      session.provider, causes=(causes or "").strip() or None,
                                      log=session.run.log)
        return screen(session, "Draft prepared. Fill in the fields below, then approve. Nothing is sent.")

    return _guarded(action, session)


def approve_draft(session: Session, approver: str, discovery: str | None, plan_activated: str | None,
                  third_party: str, other: str, description: str, *,
                  out_dir: Path | None = RUN_LOG_DIR) -> Screen:
    """Approve: the person approves the draft. Nothing is sent. Text and JSON files are offered to download."""

    def action() -> Screen:
        if session.draft is None or session.run is None:
            raise InputProblem("Prepare the draft first.")
        if session.approved is not None:
            raise InputProblem("This notification is already approved.")
        if plan_activated not in YES_NO:
            raise InputProblem("2.9: say whether the business continuity plan was activated (yes or no).")
        if not discovery:
            raise InputProblem("2.7: pick how the incident was discovered.")
        human = HumanFields(discovery=discovery, business_continuity_plan_activated=YES_NO[plan_activated],
                            third_party_origin=(third_party or "").strip() or None,
                            other_information=(other or "").strip() or None,
                            description=(description or "").strip() or None)
        session.approved = approve(session.draft, human, approved_by=(approver or "").strip(),
                                   log=session.run.log)
        if out_dir is not None:
            session.downloads = _write_downloads(session.approved, out_dir, sample=session.sample)
        return screen(session, "Approved. NOT SENT: this tool never sends anything.")

    return _guarded(action, session)


def _write_downloads(approved: ApprovedNotification, out_dir: Path, *, sample: bool) -> tuple[str, str]:
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = f"initial-notification-{approved.run_id}"
    text_path, json_path = out_dir / f"{stem}.txt", out_dir / f"{stem}.json"
    text_path.write_text(views.notification_text(approved, sample=sample) + "\n", encoding="utf-8")
    json_path.write_text(views.notification_json(approved) + "\n", encoding="utf-8")
    return str(text_path), str(json_path)


# Every question and every possible ticket suggestion gets its own fixed place on the page.
QUESTION_NAMES: tuple[str, ...] = tuple(QUESTIONS)
REVIEW_NAMES: tuple[str, ...] = tuple(FACT_KINDS)
