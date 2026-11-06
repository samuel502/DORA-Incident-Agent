"""Case runner: drives each scenario in cases/scenarios/index.json through the agent and answers its questions.

How one case runs:
1. A new AgentRun gets the scenario's ticket, with the scenario's time as the reported time.
2. Whenever the run pauses for a human, the scripted human answers from the scenario's human_answers
   (the answer key, copied from the block 4 hand-checked facts) and reviews every ticket suggestion.
3. The final result is always the rules engine's (hard rule 1). It is compared with expected_result
   using the same mapping as the block 4 tests (tests/rules/test_case_library.py).

The scripted human knows only what the answer key says:
- A yes/no question not in the key is answered "unsure", so the fact stays unknown (section 7: never guessed).
- A number or time question not in the key is left unanswered.
- A ticket suggestion is confirmed if the key holds the same value, corrected if the key holds another
  value, and rejected if the key says nothing about it.

The agent's own limits (config.toml [agent]) still apply, including the limit on human rounds.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dora_agent.agent.fact_store import ReviewDecision, ReviewItem
from dora_agent.agent.loop import AgentRun, PendingQuestion, RunResult
from dora_agent.agent.questions import QUESTIONS, interpret_answer
from dora_agent.config import PROJECT_ROOT, AgentLimits
from dora_agent.llm.provider import LlmProvider
from dora_agent.rules import Classification

INDEX_PATH = PROJECT_ROOT / "cases" / "scenarios" / "index.json"

# Who the scripted human is, as written to the decision log ("confirmed by").
SCRIPTED_HUMAN = "scripted-human"

# Time of the check: after every scenario has ended. Same as block 4 (tests/rules/case_facts.py).
AS_OF = datetime(2026, 11, 5, 12, 0, tzinfo=timezone.utc)

# How expected results in the index map to engine results (same as tests/rules/test_case_library.py).
EXACT = frozenset({"major", "not_major", "not_an_incident"})
DEPENDS = frozenset({"depends", "depends_on_gate", "depends_on_human"})


@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    title: str
    ticket: str
    service_id: str
    around: datetime
    expected_result: str
    data_sources: tuple[str, ...]
    human_answers: dict[str, Any] = field(default_factory=dict)


def load_scenarios(path: Path = INDEX_PATH) -> list[Scenario]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return [
        Scenario(
            scenario_id=s["scenario_id"], title=s["title"], ticket=s["ticket"], service_id=s["service_id"],
            around=datetime.fromisoformat(s["around"].replace("Z", "+00:00")),
            expected_result=s["expected_result"], data_sources=tuple(s["data_sources"]),
            human_answers=dict(s.get("human_answers", {})),
        )
        for s in raw["scenarios"]
    ]


class ScriptedHuman:
    """Answers the agent's fixed questions and reviews ticket suggestions from one scenario's answer key."""

    def __init__(self, answers: dict[str, Any]):
        self._answers = answers

    def _key(self, fact_name: str) -> tuple[Any, bool] | None:
        """(answer, is_estimate) from the key, or None if the key says nothing."""
        entry = self._answers.get(fact_name)
        if entry is None:
            return None
        if isinstance(entry, dict):
            return entry["answer"], bool(entry.get("estimate", False))
        return entry, False

    def answer(self, questions: Iterable[PendingQuestion]) -> tuple[dict[str, Any], set[str]]:
        answers: dict[str, Any] = {}
        estimates: set[str] = set()
        for question in questions:
            key = self._key(question.fact_name)
            if key is None:
                if question.choices:  # yes / no / unsure
                    answers[question.fact_name] = "unsure"
                continue  # a number or time nobody knows: left unanswered
            answers[question.fact_name], is_estimate = key
            if is_estimate:
                estimates.add(question.fact_name)
        return answers, estimates

    def review(self, items: Iterable[ReviewItem]) -> list[ReviewDecision]:
        decisions = []
        for item in items:
            key = self._key(item.fact_name)
            value = interpret_answer(item.fact_name, key[0]) if key and item.fact_name in QUESTIONS else None
            if value is None:
                decisions.append(ReviewDecision(fact_name=item.fact_name, action="reject"))
            elif value == item.suggested_value:
                decisions.append(ReviewDecision(fact_name=item.fact_name, action="confirm", is_estimate=key[1]))
            else:
                decisions.append(ReviewDecision(fact_name=item.fact_name, action="correct", value=value,
                                                is_estimate=key[1]))
        return decisions


def matches(expected: str, classification: Classification) -> bool:
    """Does the engine's result match the index's expected result? Same mapping as block 4."""
    if expected in EXACT:
        return classification.result == expected and (expected == "not_an_incident" or not classification.missing)
    if expected in DEPENDS:
        return classification.result == "undetermined" and bool(classification.missing)
    if expected == "classify_overrun":
        return bool(classification.overrun) and classification.result != "not_an_incident" \
            and classification.gate is not None
    raise ValueError(f"unknown expected result {expected!r}")


@dataclass(frozen=True)
class CaseOutcome:
    """What one scenario did. Safe to write to a report: no secrets, no raw LLM text."""

    scenario_id: str
    expected: str
    result: str
    matched: bool
    status: str
    stop_reason: str
    tool_path: tuple[str, ...]
    questions_asked: tuple[str, ...]
    review: tuple[str, ...]  # "fact_name: action"
    human_rounds: int
    steps: int
    tool_calls: int
    thresholds_met: tuple[str, ...]
    missing: tuple[str, ...]
    conflicts: int
    input_tokens: int
    output_tokens: int
    run_id: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def run_case(scenario: Scenario, provider: LlmProvider, *, as_of: datetime = AS_OF,
             limits: AgentLimits | None = None, log_dir: Path | None = None) -> CaseOutcome:
    human = ScriptedHuman(scenario.human_answers)
    run = AgentRun(scenario.ticket, scenario.around, provider, as_of=as_of, limits=limits, log_dir=log_dir)
    asked: list[str] = []
    review_log: list[str] = []
    result: RunResult = run.start()
    while result.status == "needs_human":  # bounded by max_human_rounds inside the loop
        answers, estimates = human.answer(result.questions)
        decisions = human.review(result.review_items)
        asked += [q.fact_name for q in result.questions]
        review_log += [f"{d.fact_name}: {d.action}" for d in decisions]
        result = run.resume(confirmed_by=SCRIPTED_HUMAN, answers=answers, estimates=estimates, review=decisions)

    steps = [r for r in result.trace if r["kind"] == "llm_step"]
    c = result.classification
    return CaseOutcome(
        scenario_id=scenario.scenario_id, expected=scenario.expected_result, result=c.result,
        matched=matches(scenario.expected_result, c), status=result.status, stop_reason=result.stop_reason,
        tool_path=result.tool_path, questions_asked=tuple(asked), review=tuple(review_log),
        human_rounds=result.human_rounds, steps=result.steps_used, tool_calls=result.tool_calls_used,
        thresholds_met=c.thresholds_met, missing=c.missing, conflicts=len(result.conflicts),
        input_tokens=sum(r.get("input_tokens") or 0 for r in steps),
        output_tokens=sum(r.get("output_tokens") or 0 for r in steps),
        run_id=result.run_id,
    )


def run_cases(scenarios: Iterable[Scenario], provider_for: Callable[[Scenario], LlmProvider], *,
              log_dir: Path | None = None, between: Callable[[], None] | None = None) -> list[CaseOutcome]:
    """Run several scenarios. `provider_for` gives the LLM for each one; `between` runs between cases (a pause)."""
    outcomes = []
    for index, scenario in enumerate(scenarios):
        if index and between:
            between()
        outcomes.append(run_case(scenario, provider_for(scenario), log_dir=log_dir))
    return outcomes


def summary(outcomes: list[CaseOutcome]) -> dict[str, Any]:
    return {
        "cases": len(outcomes),
        "matched": sum(o.matched for o in outcomes),
        "distinct_tool_paths": len({o.tool_path for o in outcomes}),
        "stopped_early": sorted(o.scenario_id for o in outcomes if o.status == "stopped"),
        "not_matched": sorted(o.scenario_id for o in outcomes if not o.matched),
    }


def write_report(outcomes: list[CaseOutcome], path: Path, *, provider: str, model: str | None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "written_at": datetime.now(timezone.utc).isoformat(),
        "provider": provider, "model": model, "as_of": AS_OF.isoformat(),
        "summary": summary(outcomes),
        "cases": [o.to_dict() for o in outcomes],
    }
    path.write_text(json.dumps(report, indent=2, default=str) + "\n", encoding="utf-8")


def table(outcomes: list[CaseOutcome]) -> str:
    """A short plain-text table, one line per case."""
    lines = [f"{'case':7} {'expected':17} {'result':16} ok  steps tools rounds  path"]
    for o in outcomes:
        lines.append(f"{o.scenario_id:7} {o.expected:17} {o.result:16} {'yes' if o.matched else 'NO ':3} "
                     f"{o.steps:5} {o.tool_calls:5} {o.human_rounds:6}  {' > '.join(o.tool_path)}")
    return "\n".join(lines)
