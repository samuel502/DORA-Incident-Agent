"""Scenario briefings for the sample cases, like a tabletop exercise (Sam, 16 November 2026).

Proves:
- cases/briefings.json is generated from the index's human_answers and matches it exactly (not hand-edited),
- it holds only the briefing sentences: no expected results, reasons, real case names or service IDs,
- every fixed question has a briefing sentence, and each sentence says what that question's answer means,
- the briefing starts with the role line and ends with "Anything not listed: answer unsure.",
- picking a sample shows its briefing in a read-only box; a pasted or edited ticket gets none,
- the briefing box is never an input of any button, so the page can't pass it on,
- for EVERY sample, run through the page to the end (and the draft for major ones): no briefing text appears
  in any AI request (messages or tools) or in the decision log, in memory or on disk,
- the agent, the tools, the AI provider and the notification code never name the briefings or the answer key.
"""

import json
import sys
from pathlib import Path

import gradio as gr
import pytest

from dora_agent.agent.questions import QUESTIONS
from dora_agent.evaluation import briefings as b
from dora_agent.evaluation.case_runner import ScriptedHuman, load_scenarios
from dora_agent.llm.fake_provider import FakeProvider, say
from dora_agent.ui import app as page
from dora_agent.ui import controller as c

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "cases"))
from ideal_llm import IdealLlm  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src" / "dora_agent"
SCENARIOS = {s.scenario_id: s for s in load_scenarios()}
INDEX = json.loads(b.INDEX_PATH.read_text(encoding="utf-8"))


def briefing_pieces(sample_id):
    """Every line of a sample's briefing, without the "- " list mark: none of it may reach the AI or the log."""
    return [line.removeprefix("- ") for line in c.briefing_for(sample_id).splitlines()]


# ---------- the generated file ----------


def test_briefings_file_matches_the_index_exactly():
    on_disk = json.loads(c.BRIEFINGS_PATH.read_text(encoding="utf-8"))
    assert on_disk == b.build(), "cases/briefings.json is out of date: run python -m dora_agent.evaluation.briefings"
    assert c.BRIEFINGS_PATH == b.BRIEFINGS_PATH == ROOT / "cases" / "briefings.json"


def test_briefings_file_holds_only_briefing_sentences():
    data = json.loads(c.BRIEFINGS_PATH.read_text(encoding="utf-8"))
    assert set(data) == {"about", "briefings"} and "SYNTHETIC DATA" in data["about"]
    assert list(data["briefings"]) == [s["scenario_id"] for s in INDEX["scenarios"]]
    assert set(data["briefings"]) == {sample_id for _, sample_id in c.sample_choices()}
    text = json.dumps(data["briefings"])
    for scenario in INDEX["scenarios"]:
        for secret in (scenario["real_case"], scenario["service_id"], scenario["why"]):
            if secret:  # some cases have no real case
                assert secret not in text, secret
    for word in ("major", "MAJOR", "not_major", "undetermined", "expected", "SVC-"):
        assert word not in text, word


def test_every_fixed_question_has_a_briefing_sentence():
    assert set(b.YES_NO) | set(b.VALUES) == set(QUESTIONS)
    assert not set(b.YES_NO) & set(b.VALUES)
    for name, (yes, no) in b.YES_NO.items():
        assert QUESTIONS[name].meaning is not None and yes != no, name
    for name in b.VALUES:
        assert QUESTIONS[name].meaning is None, name


def test_sentences_follow_the_question_meaning():
    # "Can you rule out that data could have been affected?" answered "no" means data loss can't be ruled out.
    assert b.sentence("access_may_cause_data_loss", "no") == ("You cannot rule out that data could have been "
                                                              "affected by this access.")
    assert b.sentence("media_coverage", "yes") == "The incident has been reported in the media."
    assert b.sentence("costs_eur", {"answer": 1_000_000, "estimate": True}) == (
        "Costs and losses so far are about 1,000,000 euros, counted gross (an estimate).")
    assert b.sentence("costs_eur", {"answer": 20_000, "estimate": False}) == (
        "Costs and losses so far are 20,000 euros, counted gross.")
    assert b.sentence("affected_counterparts", {"answer": 0, "estimate": False}) == (
        "0 financial counterparts with a contract with Rheinbank were affected.")


@pytest.mark.parametrize("name, entry", [("media_coverage", "unsure"), ("media_coverage", True),
                                         ("not_a_question", "yes")])
def test_an_answer_without_a_sentence_is_refused_not_guessed(name, entry):
    with pytest.raises(b.BriefingProblem):
        b.sentence(name, entry)


def test_each_briefing_has_the_role_one_line_per_answer_and_the_closing():
    for scenario in INDEX["scenarios"]:
        lines = c.briefing_for(scenario["scenario_id"]).splitlines()
        answers = scenario.get("human_answers") or {}
        assert lines[0] == "Your role: incident manager at Rheinbank. What you know so far:"
        assert lines[-1].startswith("Anything not listed: answer unsure.")
        assert len(lines) == len(answers) + 3
        assert lines[1] == f"- {b.service_sentence(scenario['service_id'])}"
        assert lines[2:-1] == [f"- {b.sentence(n, e)}" for n, e in answers.items()]


@pytest.mark.parametrize("service_id, name", [("SVC-OLB", "Online banking"), ("SVC-MOB", "Mobile banking app"),
                                               ("SVC-HR", "HR portal")])
def test_service_is_named_by_its_plain_name_from_the_service_list(service_id, name):
    from dora_agent.connectors import get_service

    assert get_service(service_id).service.name == name
    assert b.service_sentence(service_id) == f"The affected service is {name}."
    assert service_id not in b.service_sentence(service_id)  # the plain name, never the ID


def test_unknown_service_is_refused_not_guessed():
    with pytest.raises(b.BriefingProblem):
        b.service_sentence("SVC-NOPE")


def test_c01_briefing():
    assert c.briefing_for("C01") == (
        "Your role: incident manager at Rheinbank. What you know so far:\n"
        "- The affected service is Online banking.\n"
        "- The incident has been reported in the media.\n"
        "- Different clients or counterparts have complained repeatedly about it.\n"
        "- Costs and losses so far are about 1,000,000 euros, counted gross (an estimate).\n"
        "Anything not listed: answer unsure. For a number or a time, leave the box empty.")


# ---------- the page ----------


def test_picking_a_sample_gives_its_briefing_and_nothing_else_does():
    ticket, reported, text = c.pick_sample("C01")
    assert (ticket, reported) == c.load_sample("C01") and text == c.briefing_for("C01")
    assert c.pick_sample(None) == ("", "", "") and c.pick_sample("nope") == ("", "", "")


def test_unchanged_sample_run_keeps_the_briefing_pasted_or_edited_ticket_gets_none(tmp_path):
    ticket, reported = c.load_sample("C01")
    session = c.Session()
    shown = c.start(session, ticket, reported, "C01", lambda: IdealLlm(SCENARIOS["C01"]), log_dir=tmp_path)
    assert shown.briefing == c.briefing_for("C01")

    edited = c.start(c.Session(), ticket + " More.", reported, "C01", lambda: IdealLlm(SCENARIOS["C01"]),
                     log_dir=tmp_path)
    assert edited.briefing == ""
    pasted = c.start(c.Session(), "Online banking down.", "2026-11-08T09:30Z", None,
                     lambda: FakeProvider([say("done")]), log_dir=tmp_path)
    assert pasted.briefing == ""


def briefing_box(demo):
    (box,) = [x for x in demo.blocks.values()
              if isinstance(x, gr.Textbox) and x.label == "Scenario briefing (for you only, never given to the AI)"]
    return box


def test_briefing_box_is_read_only_hidden_and_never_an_input():
    demo = page.build_app(lambda: FakeProvider([say("done")]))
    box = briefing_box(demo)
    assert box.interactive is False and box.visible is False
    assert all(box not in fn.inputs for fn in demo.fns.values())  # no button can read it


def test_typing_in_the_ticket_box_hides_the_briefing():
    demo = page.build_app(lambda: FakeProvider([say("done")]))
    box = briefing_box(demo)
    ticket = next(x for x in demo.blocks.values() if isinstance(x, gr.Textbox) and x.label.startswith("Incident ticket"))
    (edit,) = [fn for fn in demo.fns.values() if any(t[0] == ticket._id and t[1] == "input" for t in fn.targets)]
    assert edit.outputs == [box] and edit.fn() == {"__type__": "update", "value": "", "visible": False}


# ---------- the briefing never reaches the AI, the tools or the decision log ----------


class Recording:
    """Wraps the stand-in AI and keeps every request it gets: all messages and all tool specs."""

    name = "fake"

    def __init__(self, inner):
        self.inner = inner
        self.requests = []

    def chat(self, messages, tools, time_left=None):
        self.requests.append(json.dumps([m.model_dump(mode="json") for m in messages]
                                        + [t.model_dump(mode="json") for t in tools]))
        return self.inner.chat(messages, tools, time_left=time_left)


def as_typed(value):
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (tuple, list)):
        return ", ".join(value)
    return str(value)


@pytest.mark.parametrize("sample_id", list(SCENARIOS))
def test_no_briefing_text_in_any_ai_request_or_the_decision_log(sample_id, tmp_path):
    scenario = SCENARIOS[sample_id]
    recorders = []

    def provider():
        recorders.append(Recording(IdealLlm(scenario)))
        return recorders[-1]

    session = c.Session()
    ticket, reported = c.load_sample(sample_id)
    shown = c.start(session, ticket, reported, sample_id, provider, log_dir=tmp_path)
    assert shown.briefing == c.briefing_for(sample_id)  # shown to the person
    human = ScriptedHuman(scenario.human_answers, scenario.service_id)
    while session.result.status == "needs_human":
        answers, estimates = human.answer(session.result.questions)
        given = {n: (a if a in ("yes", "no", "unsure") or n == "incident_service" else as_typed(a), n in estimates)
                 for n, a in answers.items()}
        review = {d.fact_name: (d.action, as_typed(d.value) if d.value is not None else "", d.is_estimate)
                  for d in human.review(session.result.review_items)}
        before = session.result
        c.send_answers(session, "Sam Tester", given, review)
        assert session.result is not before, "the page refused the answers"
    if session.result.classification.result == "major":
        draft_ai = Recording(FakeProvider([say("Online banking was unavailable for clients.")]))
        session.provider = draft_ai
        c.make_draft(session, "")
        recorders.append(draft_ai)

    requests = [r for rec in recorders for r in rec.requests]
    assert requests  # the AI was really asked
    log_text = json.dumps(list(session.run.log.records), default=str)
    log_file = (tmp_path / f"{session.result.run_id}.jsonl").read_text(encoding="utf-8")
    for piece in briefing_pieces(sample_id):
        for request in requests:
            assert piece not in request and json.dumps(piece)[1:-1] not in request, (sample_id, piece)
        assert piece not in log_text and piece not in log_file, (sample_id, piece)


def test_agent_tools_ai_and_notification_code_never_name_the_briefings():
    for package in ("agent", "connectors", "llm", "rules", "audit", "notification"):
        for path in (SRC / package).glob("*.py"):
            source = path.read_text(encoding="utf-8").lower()
            assert "briefing" not in source and "index.json" not in source, path
    # On the page, only the controller reads the file, and only the app shows it.
    for path in (SRC / "ui").glob("*.py"):
        source = path.read_text(encoding="utf-8")
        assert "index.json" not in source, path
        if path.name not in ("controller.py", "app.py"):
            assert "briefing" not in source.lower(), path
