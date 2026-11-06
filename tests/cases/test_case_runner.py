"""The case runner drives all 27 scenarios through the full agent, with the scripted human (offline).

Proves:
- every scenario reaches its expected result through the agent (tools, mapping, gate check,
  questions, review, rules engine), when the LLM makes good choices (ideal_llm.py),
- the scripted human answers only from the answer key, and the key matches the block 4 facts,
- the harness stays outside the agent,
- reports hold no secrets.
What the real Groq model chooses is recorded by the opt-in live tests in tests/live/.
"""

import json
import sys
from pathlib import Path

import pytest
from ideal_llm import IdealLlm

from dora_agent.agent.fact_store import ReviewItem
from dora_agent.agent.loop import PendingQuestion
from dora_agent.agent.questions import QUESTIONS, interpret_answer
from dora_agent.config import PROJECT_ROOT
from dora_agent.evaluation.case_runner import (
    AS_OF,
    SCRIPTED_HUMAN,
    ScriptedHuman,
    load_scenarios,
    run_case,
    run_cases,
    summary,
    write_report,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "rules"))
from case_facts import AS_OF as BLOCK4_AS_OF  # noqa: E402
from case_facts import CASES  # noqa: E402

SCENARIOS = load_scenarios()
IDS = [s.scenario_id for s in SCENARIOS]


# ---------- every scenario through the agent ----------


@pytest.mark.parametrize("scenario", SCENARIOS, ids=IDS)
def test_scenario_reaches_its_expected_result_through_the_agent(scenario):
    outcome = run_case(scenario, IdealLlm(scenario))
    assert outcome.matched, (f"{scenario.scenario_id}: expected {outcome.expected}, got {outcome.result}; "
                             f"stop {outcome.stop_reason}; missing {outcome.missing}")
    assert outcome.status in ("finished", "stopped")


def test_all_cases_and_many_different_paths():
    outcomes = run_cases(SCENARIOS, IdealLlm)
    result = summary(outcomes)
    assert result["cases"] == 27 and result["matched"] == 27
    assert result["distinct_tool_paths"] >= 10  # measured: 17


def test_nobody_but_the_engine_gives_the_result():
    # The ideal LLM never states a result. The outcome is the engine's result in the decision log.
    scenario = next(s for s in SCENARIOS if s.scenario_id == "N01")
    outcome = run_case(scenario, IdealLlm(scenario))
    assert outcome.result == "not_major"
    assert outcome.tool_path[-1] == "get_security_alerts (gate check)"
    assert outcome.questions_asked.count("malicious_access") == 1


def test_scripted_human_is_logged_as_who_confirmed(tmp_path):
    scenario = next(s for s in SCENARIOS if s.scenario_id == "N03")
    outcome = run_case(scenario, IdealLlm(scenario), log_dir=tmp_path)
    records = [json.loads(line) for line in
               (tmp_path / f"{outcome.run_id}.jsonl").read_text(encoding="utf-8").splitlines()]
    humans = [r for r in records if r["kind"] == "human_input"]
    assert humans and all(r["by"] == SCRIPTED_HUMAN for r in humans)
    assert records[-1]["kind"] == "result" and records[-1]["result"] == "not_major"


def test_same_check_time_as_block_4():
    assert AS_OF == BLOCK4_AS_OF


# ---------- the answer key ----------


@pytest.mark.parametrize("scenario", SCENARIOS, ids=IDS)
def test_answer_key_matches_the_block_4_facts(scenario):
    # Every human answer in the index gives exactly the fact block 4 hand-checked, and nothing more.
    block4 = {name: fact for name, fact in CASES[scenario.scenario_id][3].items() if fact.source == "human"}
    assert set(scenario.human_answers) == set(block4)
    for name, entry in scenario.human_answers.items():
        answer, estimate = (entry["answer"], entry["estimate"]) if isinstance(entry, dict) else (entry, False)
        assert interpret_answer(name, answer) == block4[name].value, name
        assert estimate == block4[name].is_estimate, name


def question(name):
    q = QUESTIONS[name]
    return PendingQuestion(fact_name=name, text=q.text, basis=q.basis,
                           choices=tuple(q.meaning) if q.meaning else None, allows_estimate=q.allows_estimate)


def test_scripted_human_answers_only_from_the_key():
    human = ScriptedHuman({"media_coverage": "yes", "costs_eur": {"answer": 140000, "estimate": True}})
    answers, estimates = human.answer([question("media_coverage"), question("costs_eur"),
                                       question("repeated_complaints"), question("affected_clients")])
    # Not in the key: yes/no -> "unsure" (stays unknown), number -> left unanswered.
    assert answers == {"media_coverage": "yes", "costs_eur": 140000, "repeated_complaints": "unsure"}
    assert estimates == {"costs_eur"}


def test_scripted_human_reviews_every_suggestion():
    human = ScriptedHuman({"media_coverage": "yes", "repeated_complaints": "no",
                           "access_may_cause_data_loss": "no"})
    items = [ReviewItem(fact_name="media_coverage", suggested_value=True, reason="r", question=None),
             ReviewItem(fact_name="repeated_complaints", suggested_value=True, reason="r", question=None),
             ReviewItem(fact_name="client_loss_impact", suggested_value=True, reason="r", question=None),
             ReviewItem(fact_name="access_may_cause_data_loss", suggested_value=True, reason="r", question=None),
             ReviewItem(fact_name="incident_start", suggested_value="2026-01-01T00:00:00+00:00", reason="r",
                        question=None)]
    decisions = {d.fact_name: (d.action, d.value) for d in human.review(items)}
    assert decisions == {
        "media_coverage": ("confirm", None),  # key agrees
        "repeated_complaints": ("correct", False),  # key disagrees
        "client_loss_impact": ("reject", None),  # key says nothing
        "access_may_cause_data_loss": ("confirm", None),  # "can't rule out" = may cause loss = True
        "incident_start": ("reject", None),  # no fixed question: never confirmed by the script
    }


def test_review_through_a_real_run_confirms_corrects_and_rejects():
    # The LLM suggests three facts from the ticket; the scripted human decides each from the key.
    from dora_agent.agent.loop import AgentRun
    from dora_agent.llm.fake_provider import FakeProvider, call, say

    scenario = next(s for s in SCENARIOS if s.scenario_id == "N05")  # key: media yes, costs 140000 (estimate)
    fake = FakeProvider([
        call("get_service", service_id="SVC-CARD"),
        call("suggest_facts", suggestions=[
            {"fact": "media_coverage", "value": True, "reason": "National news covered it."},
            {"fact": "costs_eur", "value": 90000, "reason": "guess"},
            {"fact": "client_loss_impact", "value": True, "reason": "guess"}]),
        say("done"), say("done"), say("done"),
    ])
    run = AgentRun(scenario.ticket, scenario.around, fake, as_of=AS_OF)
    paused = run.start()
    decisions = ScriptedHuman(scenario.human_answers).review(paused.review_items)
    assert {d.fact_name: d.action for d in decisions} == {
        "media_coverage": "confirm", "costs_eur": "correct", "client_loss_impact": "reject"}
    answers, estimates = ScriptedHuman(scenario.human_answers).answer(paused.questions)
    result = run.resume(confirmed_by=SCRIPTED_HUMAN, answers=answers, estimates=estimates, review=decisions)
    facts = result.classification.facts
    assert facts.costs_eur.value == 140000 and facts.costs_eur.is_estimate
    assert facts.media_coverage.source == "ticket" and facts.client_loss_impact.value is None


# ---------- the harness stays outside the agent; reports hold no secrets ----------


def test_agent_code_never_uses_the_harness_or_the_answer_key():
    for package in ("agent", "connectors", "llm", "rules", "audit", "notification", "ui"):
        for path in (PROJECT_ROOT / "src" / "dora_agent" / package).glob("*.py"):
            source = path.read_text(encoding="utf-8")
            assert "evaluation" not in source and "index.json" not in source, path


def test_report_holds_no_api_key(tmp_path, monkeypatch):
    fake_key = "TEST-ONLY-placeholder-key-1122334455"
    monkeypatch.setenv("GROQ_API_KEY", fake_key)
    scenario = next(s for s in SCENARIOS if s.scenario_id == "B01")
    outcomes = [run_case(scenario, IdealLlm(scenario), log_dir=tmp_path)]
    write_report(outcomes, tmp_path / "report.json", provider="fake", model=None)
    for path in tmp_path.iterdir():
        found = fake_key in path.read_text(encoding="utf-8")
        assert not found, path.name
    report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert report["summary"]["matched"] == 1
