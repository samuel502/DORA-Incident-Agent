"""The agent loop: the LLM picks tools until the facts are in, a human is needed, or a limit is hit.

Who does what (CLAUDE.md hard rules 1, 4, 8, 9):
- The LLM proposes tool calls. Plain code checks and runs them (tools.py).
- The result is ALWAYS worked out by plain code at the end: classify() on the stored facts.
  Whatever the LLM writes in its text is logged and never used as the result.
- Hard limits from config.toml [agent]: steps, tool calls (per run and per step), human rounds,
  and a total time limit (max_run_seconds).
- Every step goes to the decision log (audit/log.py).

Time limit (block 6 step 3, approved by Sam): the run's clock counts the agent's own working time, from
start() or resume() until the run pauses or ends. Time spent waiting for a person does not count.
The clock is checked before every LLM call and every tool call, and each LLM call gets the time left
(`time_left`), so the provider doesn't wait or keep a request open past it. When time runs out, the run
stops with stop reason "time_limit" and the rules engine gives its result on the facts so far.

Gate check (Sam, block 5 step 3): if the gate depends only on G-c (service not critical, not regulated),
plain code checks the security alerts (if the LLM has not), and if no successful access is confirmed,
it asks the human the one malicious-access question, shown in the same round as the ticket review.
A missing security alert alone never rules out G-c.

After every step (block 5 step 5, approved by Sam):
- Plain code runs the rules engine on the stored facts. A final result (major, not major, not an incident)
  ends the run at once. Otherwise code adds a short status for the LLM: the result, what to check first,
  where to find each missing fact, and what is known (tools.status). run_rules is no longer an LLM tool
  (C01 live test, approved by Sam on 13 November 2026).
- If every fact that still decides the result can only come from a human (its system lookups have all
  run, per where_to_find), code asks the fixed questions itself. It does not wait for the LLM to do it.
- No question is asked twice in one run. If the only help left is a question already asked
  (for example, answered "unsure"), the run ends with the result open: stop reason "no_more_sources".
- Repeated identical lookups are answered from memory (tools.py). After max_repeated_calls repeats,
  the LLM is not asked again: the run goes to the human questions, or ends.

Lookups (C01 live test, approved by Sam on 13 November 2026): the LLM lists the bank lookups it wants in one
`lookups` call. Each listed lookup is run and logged like a single tool call, and counts against the same
limits (per answer and per run). The LLM chooses every lookup; code only runs them, get_service first, then
the outage timeline, then the rest in the LLM's order. While no incident service is chosen, get_service for
two different services in one answer is refused: the LLM must pick one, or ask the human (service question).

A run can pause for the human: `start()` or `resume()` return status "needs_human" with the fixed
questions and the list of ticket suggestions to review. The interface (block 6) or the test harness
answers through `resume()`. The LLM never sees the human desk.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from dora_agent.agent.fact_store import Conflict, FactStore, ReviewDecision, ReviewItem, StoreProblem
from dora_agent.agent.prompts import (REPAIR_MESSAGE, new_marker_code, system_prompt, task_message,
                                      tool_message)
from dora_agent.agent.questions import (AnswerProblem, QUESTIONS, SERVICE_QUESTION, SERVICE_QUESTION_BASIS,
                                        SERVICE_QUESTION_TEXT, interpret_answer)
from dora_agent.agent.tools import RUN_FIRST, WHERE_TO_FIND, RunContext, Toolbox, ToolOutcome, check_first
from dora_agent.agent.tools import status as rules_status
from dora_agent.audit import DecisionLog
from dora_agent.config import AgentLimits, agent_limits, llm_settings
from dora_agent.llm.provider import TIME_LIMIT, LlmError, LlmProvider, Message, ToolCall
from dora_agent.rules import RULE_VERSION, Classification, classify
from dora_agent.rules.thresholds import NOT_MET, UNKNOWN

FINAL = {"major", "not_major", "not_an_incident"}

Status = Literal["finished", "needs_human", "stopped"]
StopReason = Literal["final_result", "needs_human", "llm_finished", "step_limit", "tool_call_limit",
                     "human_round_limit", "llm_error", "repeat_limit", "no_more_sources", "time_limit"]

# Tools through which only a human can supply a fact: a fixed question, or a ticket suggestion a human confirms.
HUMAN_TOOLS = frozenset({"ask_human", "suggest_facts"})
HumanOnly = Literal["not_yet", "ask", "done"]

# What an older status is cut to in the conversation once a newer one arrives (shorter prompts).
OLD_STATUS = "(older status, replaced by a newer one below)"
STATUS_INTRO = "Status after this step, from the rules engine (plain code):\n"
TWO_SERVICES = ("not run: get_service for more than one service in one answer. Pick the one service whose records "
                f'show this incident, or ask_human with ["{SERVICE_QUESTION}"] if the records do not tell them apart.')


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
    seconds_used: float = 0.0  # the agent's own working time so far, not counting time waiting for a person
    trace: tuple[dict, ...] = ()


class AgentRun:
    def __init__(self, ticket: str, reported_at: datetime, provider: LlmProvider, *,
                 as_of: datetime | None = None, limits: AgentLimits | None = None,
                 log_dir: Path | None = None, run_id: str | None = None,
                 clock: Callable[[], float] = time.monotonic):
        """clock: only for tests, to pass a stand-in for the time limit's clock."""
        self._limits = limits or agent_limits()
        self._clock = clock
        self._worked = 0.0  # working seconds of the segments that have ended
        self._segment_start: float | None = None  # set while the agent works (start or resume until it returns)
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
        self._toolbox = Toolbox(self._store, self._context, self._limits.max_tool_result_chars,
                                self._limits.client_impact_default_days)
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
        self._last_status: int | None = None  # where the newest status message is in _messages
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

    @property
    def log(self) -> DecisionLog:
        """This run's decision log, so the notification draft and approval are written to the same log
        (block 6, option A, approved by Sam). Read-only: the run's log can't be swapped for another one."""
        return self._log

    def start(self) -> RunResult:
        if self._state is not None:
            raise RunProblem("this run has already started")
        self._state = "stopped"
        self._segment_start = self._clock()  # the run's clock starts
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
        service = answers.get(SERVICE_QUESTION)
        if SERVICE_QUESTION in answers and service not in self._context.candidates:
            raise RunProblem(f"{SERVICE_QUESTION} must be one of: {', '.join(self._context.candidates)}")
        if SERVICE_QUESTION in estimates:
            raise RunProblem(f"{SERVICE_QUESTION} cannot be an estimate")
        fact_answers = {name: answer for name, answer in answers.items() if name != SERVICE_QUESTION}
        for name, answer in fact_answers.items():
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
            for name, answer in fact_answers.items():
                desk.answer(name, answer, confirmed_by=confirmed_by, is_estimate=name in estimates)
        except StoreProblem as problem:
            raise RunProblem(str(problem)) from None
        self._segment_start = self._clock()  # the run's clock goes on: the person has answered
        self._human_rounds += 1
        self._log.write("human_input", by=confirmed_by, answers=answers, estimates=sorted(estimates),
                        review=[d.model_dump() for d in review or []],
                        unanswered=sorted(queued - set(answers)))
        self._log_new_events()
        self._context.pending_questions.clear()
        if service is not None:
            # The human picked the service: code runs get_service for it, so it becomes the incident service
            # and its service list facts are recorded (source: service list). The LLM does not choose it.
            self._run_tool(ToolCall(call_id="service-answer", name="get_service",
                                    arguments={"service_id": service}, raw_arguments=""), by="human answer")

        current = self._rules_check()
        if current.result in FINAL:
            return self._end("finished", "final_result")
        only_human = self._human_only(current)
        if only_human == "ask":
            return self._settle(current)
        if only_human == "done":
            return self._end("finished", "no_more_sources")
        chosen = f" The human chose {service} as the incident service." if service is not None else ""
        self._messages.append(Message(role="user", content=(
            "The human has answered and reviewed the suggestions. Facts confirmed by a human are now used."
            f"{chosen} Look up what is still missing (see the status below), or stop if nothing more can help.")))
        self._add_status(current)
        return self._loop()

    # ---------- the loop ----------

    def _seconds_used(self) -> float:
        running = self._clock() - self._segment_start if self._segment_start is not None else 0.0
        return self._worked + running

    def _time_left(self) -> float:
        """Seconds of working time this run has left (config.toml [agent] max_run_seconds)."""
        return self._limits.max_run_seconds - self._seconds_used()

    def _loop(self) -> RunResult:
        limits = self._limits
        while True:
            if self._steps >= limits.max_steps:
                return self._end("stopped", "step_limit")
            time_left = self._time_left()
            if time_left <= 0:
                return self._end("stopped", "time_limit")
            try:
                response = self._provider.chat(self._messages, self._toolbox.specs(), time_left=time_left)
            except LlmError as error:
                self._log.write("llm_error", error=str(error), code=error.code, status=error.status)
                if error.code == TIME_LIMIT:
                    return self._end("stopped", "time_limit")
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

            time_hit, limit_hit = self._run_answer(response.tool_calls)
            if time_hit:
                return self._end("stopped", "time_limit")
            if limit_hit:
                return self._end("stopped", "tool_call_limit")
            # The rules engine after every step, in code: a final result ends the run at once.
            current = self._rules_check()
            if current.result in FINAL:
                return self._end("finished", "final_result")
            if self._context.pending_questions:
                return self._settle(current)
            if self._context.repeats >= limits.max_repeated_calls:
                self._log.write("repeat_limit", repeats=self._context.repeats,
                                note="the LLM repeated identical lookups: not asking it again")
                return self._settle(current, quiet_end="repeat_limit")
            only_human = self._human_only(current)
            if only_human == "ask":
                return self._settle(current)
            if only_human == "done":
                return self._end("finished", "no_more_sources")
            self._add_status(current)  # the run goes on: the LLM gets the engine's status for its next choice

    def _run_answer(self, calls: tuple[ToolCall, ...]) -> tuple[bool, bool]:
        """Run every tool call in one LLM answer. Returns (time limit hit, tool call limit hit).

        A `lookups` call is unpacked into the lookups it lists; each one is run, logged and counted like a
        single call. The per-answer limit counts single lookups in the LLM's order. Run order: get_service
        first, then the outage timeline, then the rest in the LLM's order (tools.RUN_FIRST). Replies go back
        in the LLM's order: one reply per call, and a `lookups` reply holds one result per listed lookup.
        """
        limits = self._limits
        expanded: dict[int, list[ToolCall] | ToolOutcome] = {}
        flat: list[tuple[int, int, ToolCall]] = []  # (call index, position in its lookups list, single call)
        for index, call in enumerate(calls):
            if call.name == "lookups":
                expanded[index] = self._toolbox.expand(call)
                if isinstance(expanded[index], list):
                    flat += [(index, position, single) for position, single in enumerate(expanded[index])]
            else:
                flat.append((index, 0, call))
        services = {c.arguments.get("service_id") for _, _, c in flat
                    if c.name == "get_service" and c.arguments_valid and isinstance(c.arguments, dict)}
        two_services = self._context.incident_service is None and len(services) > 1

        results: dict[tuple[int, int], dict] = {}
        time_hit = limit_hit = False
        order = sorted(range(len(flat)), key=lambda n: RUN_FIRST.get(flat[n][2].name, len(RUN_FIRST)))
        for n in order:
            index, position, call = flat[n]
            if time_hit or self._time_left() <= 0:
                time_hit = True
                results[index, position] = {"error": "not run: time limit for this run reached"}
            elif self._tool_calls >= limits.max_tool_calls:
                limit_hit = True
                results[index, position] = {"error": "not run: tool call limit for this run reached"}
            elif n >= limits.max_tool_calls_per_step:
                results[index, position] = {"error": "not run: too many tool calls in one step"}
            elif two_services and call.name == "get_service":
                results[index, position] = {"error": TWO_SERVICES}
                self._log.write("tool_call", by="llm", tool="get_service", arguments=call.arguments, ok=False,
                                error="two services in one answer", facts_recorded=[], repeat=False,
                                before_service=False)
            else:
                results[index, position] = self._run_tool(call, by="llm")
        for index, call in enumerate(calls):
            unpacked = expanded.get(index)
            if isinstance(unpacked, ToolOutcome):  # a malformed lookups call: refused, nothing run
                self._tool_path.append("lookups [refused]")
                self._log.write("tool_call", by="llm", tool="lookups", arguments=call.arguments, ok=False,
                                error=unpacked.error, facts_recorded=[], repeat=False, before_service=False)
                content = unpacked.content
            elif unpacked is not None:
                content = {"results": [{"tool": single.name, **results[index, position]}
                                       for position, single in enumerate(unpacked)]}
            else:
                content = results[index, 0]
            self._messages.append(Message(role="tool", tool_call_id=call.call_id,
                                          content=tool_message(content, self._code)))
        return time_hit, limit_hit

    def _add_status(self, current: Classification) -> None:
        """Give the LLM the engine's status for its next choice. An older status is cut to one line."""
        if self._last_status is not None:
            old = self._messages[self._last_status]
            self._messages[self._last_status] = old.model_copy(update={"content": OLD_STATUS})
        self._last_status = len(self._messages)
        content = rules_status(self._store, self._context, current)
        self._messages.append(Message(role="user", content=STATUS_INTRO + tool_message(content, self._code)))

    def _run_tool(self, call: ToolCall, by: str) -> dict:
        """Run one tool call and log it. Returns what goes back to the LLM; the caller sends it."""
        outcome = self._toolbox.run(call)
        self._tool_calls += 1  # a repeat answered from memory counts too
        label = (call.name[:60] + ("" if by == "llm" else f" ({by})") + (" (repeat)" if outcome.repeat else "")
                 + ("" if outcome.ok else " [refused]"))
        self._tool_path.append(label)
        self._log.write("tool_call", by=by, tool=call.name[:60], arguments=call.arguments,
                        ok=outcome.ok, error=outcome.error, facts_recorded=list(outcome.facts_recorded),
                        repeat=outcome.repeat, before_service=outcome.before_service)
        self._log_new_events()
        return outcome.content

    def _rules_check(self) -> Classification:
        """Run the rules engine on the stored facts (plain code, hard rule 1) and log the result."""
        current = classify(self._store.snapshot(), self._context.as_of)
        self._log.write("rules_check", result=current.result, missing=len(current.missing),
                        check_first=check_first(current))
        return current

    def _settle(self, current: Classification | None = None, quiet_end: StopReason = "llm_finished") -> RunResult:
        """The LLM is done, wants a human, or is not asked again. Apply the checks, then pause, finish or stop."""
        current = current or self._rules_check()
        if current.result in FINAL:
            return self._end("finished", "final_result")
        if self._time_left() <= 0:  # the gate check may run a tool: not past the time limit
            return self._end("stopped", "time_limit")
        blocked = self._gate_check(current)
        if not self._context.pending_questions and self._human_only(current) == "done":
            blocked = True
        if self._context.pending_questions or self._store.review_items():
            if self._human_rounds >= self._limits.max_human_rounds:
                return self._end("stopped", "human_round_limit")
            return self._end("needs_human", "needs_human")
        return self._end("finished", "no_more_sources" if blocked else quiet_end)

    def _human_only(self, current: Classification) -> HumanOnly:
        """Can the facts that still decide the result only come from a human now? If so, ask them.

        Targets: check_first if it is not empty, otherwise everything missing. A target is human-only once
        every system lookup where_to_find names for it has run in this run. If all targets are human-only,
        their fixed questions are queued ("ask"). If they were all asked already, nothing is left ("done").
        """
        targets = check_first(current) or list(current.missing)
        if not targets:
            return "not_yet"
        for name in targets:
            systems = [t for t in WHERE_TO_FIND.get(name, ("suggest_facts",)) if t not in HUMAN_TOOLS]
            if not all(self._context.lookup_done(t) for t in systems):
                return "not_yet"  # a system may still know it
        askable = [name for name in targets if name in QUESTIONS]
        if "malicious_access" in askable and self._store.snapshot().usable("malicious_access") is None:
            # G-c and T5-b need a successful malicious access first (RTS-C Art. 6(c), Art. 9(5)(b)).
            # Where it happened and possible data loss only matter after a "yes", so ask that question first.
            askable = ["malicious_access"]
        if not askable:
            return "not_yet"  # facts without a fixed question: the LLM may still find them in the ticket
        queued = [name for name in askable if self._context.queue_question(name)]
        if queued:
            self._log.write("human_only", note="only a human can supply what is still missing: asking",
                            asked=queued)
            return "ask"
        self._log.write("human_only", note="only a human can help, and these were already asked in this run",
                        already_asked=askable)
        return "done"

    def _gate_check(self, current: Classification) -> bool:
        """If the gate depends only on G-c, make sure the alerts were checked and the human is asked.

        Returns True if the question was needed but had already been asked in this run (never asked twice).
        """
        gate = current.gate
        if gate is None or gate.status != UNKNOWN:
            return False
        status = {c.check_id: c.status for c in gate.checks}
        if status.get("G-a") != NOT_MET or status.get("G-b") != NOT_MET:
            return False  # the gate does not depend only on G-c
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
            # No confirmed answer yet: a missing or unconfirmed alert never rules out G-c. Ask the human, once.
            if not self._context.queue_question("malicious_access"):
                self._log.write("gate_check", note="malicious access was already asked in this run: not again")
                return True
            self._log.write("gate_check", note="no confirmed answer on malicious access: asking the human")
        return False

    def _log_new_events(self) -> None:
        events = self._store.events
        for event in events[self._logged_events:]:
            data = event.model_dump()
            # The fact store's own counter is kept as event_seq, so it never takes the log's seq.
            data["event_seq"] = data.pop("seq")
            self._log.write("fact", **data)
        self._logged_events = len(events)

    def _end(self, status: Status, reason: StopReason, detail: str | None = None) -> RunResult:
        # The result is ALWAYS the rules engine's, on the facts held right now (hard rule 1).
        classification = classify(self._store.snapshot(), self._context.as_of)
        self._state = status
        # The run's clock stops here: a pause waits for a person, and that time does not count.
        self._worked = self._seconds_used()
        self._segment_start = None
        conflicts = tuple(self._store.conflicts())
        questions = tuple(self._pending(name) for name in self._context.pending_questions) \
            if status == "needs_human" else ()
        review = tuple(self._store.review_items()) if status == "needs_human" else ()
        message = {
            "final_result": f"Result: {classification.result}. {classification.summary}",
            "needs_human": "Waiting for the human: answer the questions and review the ticket suggestions.",
            "llm_finished": f"The agent found nothing more to look up. {classification.summary}",
            "step_limit": f"Stopped: step limit reached. {classification.summary}",
            "tool_call_limit": f"Stopped: tool call limit reached. {classification.summary}",
            "human_round_limit": f"Stopped: too many rounds of questions. {classification.summary}",
            "llm_error": f"Stopped: the LLM could not be reached ({detail}). {classification.summary}",
            "repeat_limit": f"Stopped asking the LLM: it kept repeating the same lookups. {classification.summary}",
            "no_more_sources": ("Nothing more can be found: what is still missing can only come from a human, "
                                f"and it was already asked. {classification.summary}"),
            "time_limit": (f"Stopped: the time limit of {self._limits.max_run_seconds} seconds for this run was "
                           f"reached. {classification.summary}"),
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
            seconds_used=round(self._worked, 1),
        )
        return RunResult(
            run_id=self.run_id, status=status, stop_reason=reason, message=message,
            classification=classification, questions=questions, review_items=review, conflicts=conflicts,
            tool_path=tuple(self._tool_path), steps_used=self._steps, tool_calls_used=self._tool_calls,
            human_rounds=self._human_rounds, seconds_used=round(self._worked, 1), trace=tuple(self._log.records),
        )

    def _pending(self, name: str) -> PendingQuestion:
        if name == SERVICE_QUESTION:
            # Fixed wording; the choices are only the services find_service returned (names from the service list).
            names = ", ".join(f"{sid} = {label}" for sid, label in self._context.candidates.items())
            return PendingQuestion(fact_name=name, text=f"{SERVICE_QUESTION_TEXT} ({names})",
                                   basis=SERVICE_QUESTION_BASIS, choices=tuple(self._context.candidates),
                                   allows_estimate=False)
        return _pending(name)


def _pending(name: str) -> PendingQuestion:
    question = QUESTIONS[name]
    return PendingQuestion(fact_name=name, text=question.text, basis=question.basis,
                           choices=tuple(question.meaning) if question.meaning else None,
                           allows_estimate=question.allows_estimate)
