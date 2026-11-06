"""The agent loop: the LLM picks tools until the facts are in, a human is needed, or a limit is hit.

Who does what (CLAUDE.md hard rules 1, 4, 8, 9):
- The LLM proposes tool calls. Plain code checks and runs them (tools.py).
- The result is ALWAYS worked out by plain code at the end: classify() on the stored facts.
  Whatever the LLM writes in its text is logged and never used as the result.
- Hard limits from config.toml [agent]: steps, tool calls (per run and per step), human rounds.
- Every step goes to the decision log (audit/log.py).

Gate check (Sam, block 5 step 3): if the gate depends only on G-c (service not critical, not regulated),
plain code checks the security alerts (if the LLM has not), and if no successful access is confirmed,
it asks the human the one malicious-access question, shown in the same round as the ticket review.
A missing security alert alone never rules out G-c.

A run can pause for the human: `start()` or `resume()` return status "needs_human" with the fixed
questions and the list of ticket suggestions to review. The interface (block 6) or the test harness
answers through `resume()`. The LLM never sees the human desk.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from dora_agent.agent.fact_store import Conflict, FactStore, ReviewDecision, ReviewItem, StoreProblem
from dora_agent.agent.prompts import (REPAIR_MESSAGE, new_marker_code, system_prompt, task_message,
                                      tool_message)
from dora_agent.agent.questions import AnswerProblem, QUESTIONS, interpret_answer
from dora_agent.agent.tools import RunContext, Toolbox
from dora_agent.audit import DecisionLog
from dora_agent.config import AgentLimits, agent_limits, llm_settings
from dora_agent.llm.provider import LlmError, LlmProvider, Message, ToolCall
from dora_agent.rules import RULE_VERSION, Classification, classify
from dora_agent.rules.thresholds import NOT_MET, UNKNOWN

FINAL = {"major", "not_major", "not_an_incident"}

Status = Literal["finished", "needs_human", "stopped"]
StopReason = Literal["final_result", "needs_human", "llm_finished", "step_limit", "tool_call_limit",
                     "human_round_limit", "llm_error"]


class RunProblem(ValueError):
    """Bad input to a run (ticket, time, answers). Plain message, safe to show."""


class PendingQuestion(BaseModel):
    model_config = ConfigDict(frozen=True)

    fact_name: str
    text: str
    basis: str
    choices: tuple[str, ...] | None  # yes / no / unsure, or None for a number or time
    allows_estimate: bool


class RunResult(BaseModel):
    """What one start() or resume() gives back. The classification always comes from the rules engine."""

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    run_id: str
    status: Status
    stop_reason: StopReason
    message: str
    classification: Classification
    questions: tuple[PendingQuestion, ...] = ()
    review_items: tuple[ReviewItem, ...] = ()
    conflicts: tuple[Conflict, ...] = ()
    tool_path: tuple[str, ...] = ()
    steps_used: int = 0
    tool_calls_used: int = 0
    human_rounds: int = 0
    trace: tuple[dict, ...] = ()


class AgentRun:
    def __init__(self, ticket: str, reported_at: datetime, provider: LlmProvider, *,
                 as_of: datetime | None = None, limits: AgentLimits | None = None,
                 log_dir: Path | None = None, run_id: str | None = None):
        self._limits = limits or agent_limits()
        if not isinstance(ticket, str) or not ticket.strip():
            raise RunProblem("the ticket is empty")
        if len(ticket) > self._limits.max_ticket_chars:
            raise RunProblem(f"the ticket is longer than {self._limits.max_ticket_chars} characters")
        for name, value in (("reported_at", reported_at), ("as_of", as_of)):
            if value is not None and (value.tzinfo is None or value.utcoffset() != timedelta(0)):
                raise RunProblem(f"{name} must be a UTC time")

        self.run_id = run_id or uuid.uuid4().hex[:12]
        self._provider = provider
        self._store = FactStore()
        self._context = RunContext(reported_at=reported_at, as_of=as_of or reported_at)
        self._toolbox = Toolbox(self._store, self._context, self._limits.max_tool_result_chars)
        self._code = new_marker_code()
        self._messages = [
            Message(role="system", content=system_prompt(self._code)),
            Message(role="user", content=task_message(ticket, reported_at.isoformat(), self._code)),
        ]
        self._log = DecisionLog(self.run_id, log_dir / f"{self.run_id}.jsonl" if log_dir else None)
        self._steps = self._tool_calls = self._human_rounds = 0
        self._repairing = False  # True right after a refused, unreadable tool call (one retry only)
        self._tool_path: list[str] = []
        self._logged_events = 0
        self._state: Status | None = None
        self._log.write(
            "run_started", ticket=ticket, ticket_sha256=hashlib.sha256(ticket.encode()).hexdigest(),
            reported_at=reported_at, as_of=self._context.as_of, provider=provider.name,
            model=llm_settings().model if provider.name == "groq" else None,
            rule_version=RULE_VERSION, limits=vars(self._limits),
        )

    # ---------- for the interface and the test harness (never given to the LLM) ----------

    @property
    def human_desk(self):
        return self._store.human_desk()

    def start(self) -> RunResult:
        if self._state is not None:
            raise RunProblem("this run has already started")
        self._state = "stopped"
        return self._loop()

    def resume(self, *, confirmed_by: str, answers: dict[str, Any] | None = None,
               estimates: set[str] | frozenset[str] = frozenset(),
               review: list[ReviewDecision] | None = None) -> RunResult:
        """Give the human's answers and the full ticket review, then continue."""
        if self._state != "needs_human":
            raise RunProblem("this run is not waiting for a human")
        answers = answers or {}
        # Check everything before writing anything.
        queued = set(self._context.pending_questions)
        not_asked = sorted(set(answers) - queued)
        if not_asked:
            raise RunProblem(f"these were not asked: {', '.join(n[:60] for n in not_asked)}")
        for name, answer in answers.items():
            try:
                interpret_answer(name, answer)
            except AnswerProblem as problem:
                raise RunProblem(str(problem)) from None
            if name in estimates and not QUESTIONS[name].allows_estimate:
                raise RunProblem(f"{name} cannot be an estimate")
        desk = self._store.human_desk()
        try:
            if self._store.review_items() or review:
                desk.review(review or [], confirmed_by=confirmed_by)  # all or nothing
            for name, answer in answers.items():
                desk.answer(name, answer, confirmed_by=confirmed_by, is_estimate=name in estimates)
        except StoreProblem as problem:
            raise RunProblem(str(problem)) from None
        self._human_rounds += 1
        self._log.write("human_input", by=confirmed_by, answers=answers, estimates=sorted(estimates),
                        review=[d.model_dump() for d in review or []],
                        unanswered=sorted(queued - set(answers)))
        self._log_new_events()
        self._context.pending_questions.clear()

        current = classify(self._store.snapshot(), self._context.as_of)
        if current.result in FINAL:
            return self._end("finished", "final_result")
        self._messages.append(Message(role="user", content=(
            "The human has answered and reviewed the suggestions. Facts confirmed by a human are now used. "
            "Check run_rules and look up what is still missing, or stop if nothing more can help.")))
        return self._loop()

    # ---------- the loop ----------

    def _loop(self) -> RunResult:
        limits = self._limits
        while True:
            if self._steps >= limits.max_steps:
                return self._end("stopped", "step_limit")
            try:
                response = self._provider.chat(self._messages, self._toolbox.specs())
            except LlmError as error:
                self._log.write("llm_error", error=str(error), code=error.code)
                if error.code == "tool_use_failed" and not self._repairing:
                    # The provider refused an unreadable tool call. Say so once and let the LLM try again.
                    # The failed call counts as a step, so the step limit still applies (hard rule 8).
                    self._steps += 1
                    self._repairing = True
                    self._messages.append(Message(role="user", content=REPAIR_MESSAGE))
                    continue
                return self._end("stopped", "llm_error", str(error))
            self._repairing = False
            self._steps += 1
            self._log.write("llm_step", step=self._steps, text=response.text[:1000],
                            proposed=[{"tool": c.name[:60], "arguments": c.raw_arguments[:500] or c.arguments}
                                      for c in response.tool_calls],
                            input_tokens=response.usage.input_tokens, output_tokens=response.usage.output_tokens)
            self._messages.append(Message(role="assistant", content=response.text,
                                          tool_calls=response.tool_calls))
            if not response.tool_calls:
                return self._settle()  # the LLM thinks it is done

            limit_hit = False
            for index, call in enumerate(response.tool_calls):
                if self._tool_calls >= limits.max_tool_calls:
                    limit_hit = True
                    self._reply(call, {"error": "not run: tool call limit for this run reached"})
                    continue
                if index >= limits.max_tool_calls_per_step:
                    self._reply(call, {"error": "not run: too many tool calls in one step"})
                    continue
                self._run_tool(call, by="llm")
            if limit_hit:
                return self._end("stopped", "tool_call_limit")
            last = self._context.last_classification
            if last is not None and last.result in FINAL and any(c.name == "run_rules" for c in response.tool_calls):
                return self._end("finished", "final_result")
            if self._context.pending_questions:
                return self._settle()

    def _run_tool(self, call: ToolCall, by: str) -> None:
        outcome = self._toolbox.run(call)
        self._tool_calls += 1
        label = call.name[:60] + ("" if by == "llm" else f" ({by})") + ("" if outcome.ok else " [refused]")
        self._tool_path.append(label)
        self._log.write("tool_call", by=by, tool=call.name[:60], arguments=call.arguments,
                        ok=outcome.ok, error=outcome.error, facts_recorded=list(outcome.facts_recorded))
        self._log_new_events()
        if by == "llm":
            self._reply(call, outcome.content)

    def _reply(self, call: ToolCall, content: dict) -> None:
        self._messages.append(Message(role="tool", tool_call_id=call.call_id, content=tool_message(content, self._code)))

    def _settle(self) -> RunResult:
        """The LLM is done or wants a human. Apply the gate check, then pause, finish or stop."""
        current = classify(self._store.snapshot(), self._context.as_of)
        if current.result in FINAL:
            return self._end("finished", "final_result")
        self._gate_check(current)
        if self._context.pending_questions or self._store.review_items():
            if self._human_rounds >= self._limits.max_human_rounds:
                return self._end("stopped", "human_round_limit")
            return self._end("needs_human", "needs_human")
        return self._end("finished", "llm_finished")

    def _gate_check(self, current: Classification) -> None:
        """If the gate depends only on G-c, make sure the alerts were checked and the human is asked."""
        gate = current.gate
        if gate is None or gate.status != UNKNOWN:
            return
        status = {c.check_id: c.status for c in gate.checks}
        if status.get("G-a") != NOT_MET or status.get("G-b") != NOT_MET:
            return  # the gate does not depend only on G-c
        if not self._context.alerts_checked:
            start = self._context.reported_at - timedelta(days=self._limits.gate_check_alert_days_before)
            end = self._context.reported_at + timedelta(days=self._limits.gate_check_alert_days_after)
            arguments = {"start": start.isoformat(), "end": end.isoformat()}
            if self._context.incident_service:
                arguments["service_id"] = self._context.incident_service
            self._log.write("gate_check", note="gate depends only on G-c: checking security alerts")
            self._run_tool(ToolCall(call_id="gate-check", name="get_security_alerts", arguments=arguments,
                                    raw_arguments=""), by="gate check")
        facts = self._store.snapshot()
        if facts.usable("malicious_access") is None and "malicious_access" not in self._context.pending_questions:
            # No confirmed answer yet: a missing or unconfirmed alert never rules out G-c. Ask the human.
            self._context.pending_questions.append("malicious_access")
            self._log.write("gate_check", note="no confirmed answer on malicious access: asking the human")

    def _log_new_events(self) -> None:
        events = self._store.events
        for event in events[self._logged_events:]:
            self._log.write("fact", **event.model_dump())
        self._logged_events = len(events)

    def _end(self, status: Status, reason: StopReason, detail: str | None = None) -> RunResult:
        # The result is ALWAYS the rules engine's, on the facts held right now (hard rule 1).
        classification = classify(self._store.snapshot(), self._context.as_of)
        self._state = status
        conflicts = tuple(self._store.conflicts())
        questions = tuple(_pending(name) for name in self._context.pending_questions) if status == "needs_human" else ()
        review = tuple(self._store.review_items()) if status == "needs_human" else ()
        message = {
            "final_result": f"Result: {classification.result}. {classification.summary}",
            "needs_human": "Waiting for the human: answer the questions and review the ticket suggestions.",
            "llm_finished": f"The agent found nothing more to look up. {classification.summary}",
            "step_limit": f"Stopped: step limit reached. {classification.summary}",
            "tool_call_limit": f"Stopped: tool call limit reached. {classification.summary}",
            "human_round_limit": f"Stopped: too many rounds of questions. {classification.summary}",
            "llm_error": f"Stopped: the LLM could not be reached ({detail}). {classification.summary}",
        }[reason]
        if conflicts:
            message += f" {len(conflicts)} conflict(s) between a system and a human answer: please check."
        self._log.write(
            "result" if status != "needs_human" else "paused", status=status, stop_reason=reason,
            result=classification.result, summary=classification.summary, reasons=list(classification.reasons),
            thresholds_met=list(classification.thresholds_met), missing=list(classification.missing),
            waiting_for_human=list(classification.pending_confirmations),
            conflicts=[c.model_dump() for c in conflicts],
            questions=[q.fact_name for q in questions], review=[r.fact_name for r in review],
            facts=classification.facts.model_dump(mode="json"), rule_version=classification.rule_version,
            steps=self._steps, tool_calls=self._tool_calls, tool_path=self._tool_path,
        )
        return RunResult(
            run_id=self.run_id, status=status, stop_reason=reason, message=message,
            classification=classification, questions=questions, review_items=review, conflicts=conflicts,
            tool_path=tuple(self._tool_path), steps_used=self._steps, tool_calls_used=self._tool_calls,
            human_rounds=self._human_rounds, trace=tuple(self._log.records),
        )


def _pending(name: str) -> PendingQuestion:
    question = QUESTIONS[name]
    return PendingQuestion(fact_name=name, text=question.text, basis=question.basis,
                           choices=tuple(question.meaning) if question.meaning else None,
                           allows_estimate=question.allows_estimate)
