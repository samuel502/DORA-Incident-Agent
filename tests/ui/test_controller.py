"""ui/controller.py: what each button on the page does (block 6 step 4). No browser, no key, no network.

Proves:
- samples come from cases/samples.json only, and an unchanged sample is marked as a replay,
- every run is measured at "now" (Sam, 8 November 2026),
- typed times and numbers are read strictly: "150.000" is 150,000, but "1.5" is refused, never guessed,
- a full run through the page's steps: questions, ticket review, draft, approval, downloads, NOT SENT,
- the names for answers and approval come only from what the person typed,
- problems show a plain message; unexpected errors show a fixed message, never the error's own text,
- a hostile ticket comes out as literal text.
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from dora_agent.evaluation.case_runner import ScriptedHuman, load_scenarios
from dora_agent.llm.fake_provider import FakeProvider, say
from dora_agent.llm.provider import LlmError
from dora_agent.notification.approval import NOT_SENT
from dora_agent.notification.draft import BANNER
from dora_agent.ui import controller as c

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "cases"))
from ideal_llm import IdealLlm  # noqa: E402

UTC = timezone.utc
NOW = datetime(2026, 11, 8, 12, 0, tzinfo=UTC)
SCENARIOS = {s.scenario_id: s for s in load_scenarios()}
HOSTILE = "<script>alert(1)</script> <img src=x onerror=alert(1)> **bold** [link](http://evil.example)"


def ideal(sample_id):
    return lambda: IdealLlm(SCENARIOS[sample_id])


def started(sample_id, tmp_path, *, ticket=None, reported=None):
    session = c.Session()
    sample_ticket, sample_time = c.load_sample(sample_id)
    shown = c.start(session, ticket if ticket is not None else sample_ticket, reported or sample_time, sample_id,
                    ideal(sample_id), now=NOW, log_dir=tmp_path)
    return session, shown


def as_typed(value):
    """A value the way a person would type it on the page."""
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (tuple, list)):
        return ", ".join(value)
    return str(value)


def answer_like_the_answer_key(session, scenario_id, name="Sam Tester"):
    """Fill the page's boxes from the scenario's answer key, then press Send answers."""
    human = ScriptedHuman(SCENARIOS[scenario_id].human_answers)
    result = session.result
    answers, estimates = human.answer(result.questions)
    given = {n: (a if isinstance(a, str) and a in ("yes", "no", "unsure") else as_typed(a), n in estimates)
             for n, a in answers.items()}
    review = {d.fact_name: (d.action, as_typed(d.value) if d.value is not None else "", d.is_estimate)
              for d in human.review(result.review_items)}
    return c.send_answers(session, name, given, review)


# ---------- samples ----------


def test_samples_come_from_the_samples_file_only():
    assert len(c.sample_choices()) == 27
    assert c.SAMPLES_PATH.name == "samples.json" and "scenarios" not in str(c.SAMPLES_PATH)
    ticket, reported = c.load_sample("C01")
    assert ticket.startswith("Since the platform migration") and reported == "2025-02-15T21:00:00Z"
    assert c.load_sample("nope") == ("", "") and c.load_sample(None) == ("", "")


def test_unchanged_sample_is_a_replay_and_an_edited_one_is_not(tmp_path):
    session, _ = started("C01", tmp_path)
    assert session.sample is True
    edited, _ = started("C01", tmp_path, ticket=c.load_sample("C01")[0] + " More detail.")
    assert edited.sample is False


# ---------- typed input ----------


@pytest.mark.parametrize("text, expected", [
    ("2026-11-08T09:30Z", datetime(2026, 11, 8, 9, 30, tzinfo=UTC)),
    ("2026-11-08T09:30", datetime(2026, 11, 8, 9, 30, tzinfo=UTC)),  # no zone: the box says UTC
    ("2026-11-08T10:30+01:00", datetime(2026, 11, 8, 9, 30, tzinfo=UTC)),  # converted, not guessed
])
def test_reported_time_is_read_as_utc(text, expected):
    assert c.parse_reported_at(text, NOW) == expected


@pytest.mark.parametrize("text", ["", "yesterday", "2026-11-09T12:00Z", "x" * 41])
def test_bad_or_future_reported_time_is_refused(text):
    with pytest.raises(c.InputProblem):
        c.parse_reported_at(text, NOW)


@pytest.mark.parametrize("fact, text, expected", [
    ("costs_eur", "150000", 150_000), ("costs_eur", "150,000", 150_000), ("costs_eur", "150.000", 150_000),
    ("costs_eur", "EUR 1 250 000", 1_250_000), ("costs_eur", "2.500.000 €", 2_500_000),
    ("affected_clients", "0", 0), ("media_coverage", "Yes", True), ("media_coverage", "no", False),
    ("affected_member_states", "de, at; NO", ["DE", "AT", "NO"]),
    ("resolved_at", " 2026-11-08T09:30Z ", "2026-11-08T09:30Z"),
])
def test_typed_values(fact, text, expected):
    assert c.typed_value(fact, text) == expected


@pytest.mark.parametrize("fact, text", [
    ("costs_eur", "1.5"), ("costs_eur", "-5"), ("costs_eur", "15,00"), ("costs_eur", "1,000.000"),
    ("costs_eur", "about 100k"), ("costs_eur", ""), ("costs_eur", "9" * 17),
    ("media_coverage", "maybe"), ("affected_member_states", "  "),
])
def test_typed_values_that_are_refused_not_guessed(fact, text):
    with pytest.raises(c.InputProblem):
        c.typed_value(fact, text)


# ---------- a run ----------


def test_run_is_measured_at_now_and_shows_the_engine_result(tmp_path):
    session, shown = started("C01", tmp_path)
    assert session.result.classification.as_of == NOW
    assert shown.headline == "Result from the rules engine: MAJOR. Status: Finished."
    assert shown.can_draft and not shown.can_approve and not shown.questions
    assert shown.facts and shown.trace.startswith("#1 ")
    assert (tmp_path / f"{session.result.run_id}.jsonl").exists()  # the decision log is written


def test_empty_ticket_is_refused_before_any_ai_is_made(tmp_path):
    made = []
    shown = c.start(c.Session(), "  ", "2026-11-08T09:30Z", None, lambda: made.append(1), now=NOW, log_dir=tmp_path)
    assert shown.status == "Not done: Paste a ticket or pick a sample first." and made == []


def test_too_long_ticket_is_refused(tmp_path):
    shown = c.start(c.Session(), "x" * 2001, "2026-11-08T09:30Z", None, ideal("C01"), now=NOW, log_dir=tmp_path)
    assert shown.status.startswith("Not done: The ticket is longer than 2000")


def test_missing_key_gives_a_plain_hint(tmp_path):
    def no_key():
        raise LlmError("No API key: set the environment variable GROQ_API_KEY")

    shown = c.start(c.Session(), "Online banking down.", "2026-11-08T09:30Z", None, no_key, now=NOW,
                    log_dir=tmp_path)
    assert "No API key" in shown.status and "Colab Secrets" in shown.status


def test_unexpected_error_shows_only_a_fixed_message(tmp_path, caplog):
    def broken():
        raise RuntimeError("internal detail that must not reach the page")

    shown = c.start(c.Session(), "Online banking down.", "2026-11-08T09:30Z", None, broken, now=NOW,
                    log_dir=tmp_path)
    assert shown.status == c.UNEXPECTED
    assert "internal detail" in caplog.text  # it goes to the notebook's log output instead


def test_hostile_ticket_comes_out_as_literal_text(tmp_path):
    ticket = f"Online banking down.\n{HOSTILE}"
    session = c.Session()
    shown = c.start(session, ticket, "2026-11-08T09:30Z", None, lambda: FakeProvider([say(f"Done. {HOSTILE}")]),
                    now=NOW, log_dir=tmp_path)
    assert HOSTILE in shown.trace and "&lt;" not in shown.trace
    assert shown.trace.count("\n") == len(session.run.log.records) - 1
    assert json.loads(shown.trace_json)[0]["ticket"] == ticket  # the raw JSON keeps the ticket exactly


# ---------- questions, review, draft and approval ----------


def test_full_path_questions_review_draft_approval(tmp_path):
    session, shown = started("C02", tmp_path)
    assert shown.questions and shown.headline.endswith("Status: Waiting for you: please answer the questions "
                                                       "and review the suggestions.")
    assert not shown.can_draft

    nameless = answer_like_the_answer_key(session, "C02", name="  ")
    assert nameless.status == "Not done: Type your name first. It is recorded with your answers."
    assert session.result.status == "needs_human"  # nothing was sent to the agent

    shown = answer_like_the_answer_key(session, "C02")
    assert shown.headline.startswith("Result from the rules engine: MAJOR.") and shown.reset_inputs
    assert session.result.classification.facts.malicious_access.confirmed_by in (None, "Sam Tester")
    human_records = [r for r in session.run.log.records if r["kind"] == "human_input"]
    assert human_records and all(r["by"] == "Sam Tester" for r in human_records)

    shown = c.make_draft(session, "")
    assert shown.draft.startswith(BANNER) and shown.can_approve
    assert "This sample replays an incident" in shown.draft  # unchanged sample: the late note

    refused = c.approve_draft(session, "Sam Approver", None, "no", "", "", "", out_dir=tmp_path)
    assert refused.status.startswith("Not done: 2.7") and session.approved is None
    nameless = c.approve_draft(session, " ", "IT security", "no", "", "", "", out_dir=tmp_path)
    assert nameless.status.startswith("Not done: the approver's name") and session.approved is None

    shown = c.approve_draft(session, "Sam Approver", "IT security", "no", "", "", "", out_dir=tmp_path)
    assert session.approved.approved_by == "Sam Approver"
    assert NOT_SENT in shown.approved and shown.status.startswith("Approved. NOT SENT")
    text_file, json_file = (Path(p) for p in shown.downloads)
    assert NOT_SENT in text_file.read_text(encoding="utf-8")
    assert json.loads(json_file.read_text(encoding="utf-8"))["approved_by"] == "Sam Approver"
    assert not shown.can_draft and not shown.can_approve

    again = c.approve_draft(session, "Someone Else", "IT security", "no", "", "", "", out_dir=tmp_path)
    assert again.status == "Not done: This notification is already approved."
    assert session.approved.approved_by == "Sam Approver"


def suggesting_ai():
    """The AI looks up the HR portal and reads two facts from the ticket, one with a hostile reason."""
    from dora_agent.llm.fake_provider import call
    from dora_agent.llm.provider import LlmResponse

    lookups = LlmResponse(tool_calls=(
        call("get_service", call_id="c1", service_id="SVC-HR").tool_calls[0],
        call("suggest_facts", call_id="c2", suggestions=[
            {"fact": "media_coverage", "value": False, "reason": f"nothing about media\n#2 fake line {HOSTILE}"},
            {"fact": "costs_eur", "value": 5000, "reason": "the ticket says about 5k"},
        ]).tool_calls[0],
    ))
    return FakeProvider([lookups, say("done"), say("done")])


def test_ticket_review_on_the_page(tmp_path):
    session = c.Session()
    shown = c.start(session, "HR portal is slow this morning.", "2026-03-10T06:40:00Z", None, suggesting_ai,
                    now=NOW, log_dir=tmp_path)
    assert {i.fact_name for i in shown.review} == {"media_coverage", "costs_eur"}
    label = shown.review_labels["media_coverage"]
    assert label.startswith("The AI read from the ticket: media_coverage = no.")
    assert "\n" not in label and HOSTILE in label  # one line, characters kept literally

    questions = {q.fact_name: ("no", False) for q in shown.questions}
    half = c.send_answers(session, "Sam Tester", questions, {"media_coverage": ("confirm", "", False)})
    assert half.status == "Not done: Decide every suggestion from the ticket: costs_eur has no decision."
    assert session.result.status == "needs_human"  # all or nothing: nothing was written

    bad = c.send_answers(session, "Sam Tester", questions,
                         {"media_coverage": ("confirm", "", False), "costs_eur": ("correct", "1.5", True)})
    assert bad.status.startswith("Not done: costs_eur: type a whole number")

    c.send_answers(session, "Sam Tester", questions,
                   {"media_coverage": ("reject", "", True), "costs_eur": ("correct", "12.000", True)})
    facts = session.result.classification.facts
    assert facts.costs_eur.value == 12_000 and facts.costs_eur.is_estimate
    assert facts.costs_eur.confirmed_by == "Sam Tester" and facts.costs_eur.source == "human"
    assert not facts.media_coverage.known  # rejected: gone
    assert not facts.media_coverage.is_estimate


def test_draft_needs_a_finished_major_run(tmp_path):
    session, _ = started("N01", tmp_path)
    shown = c.make_draft(session, "")
    assert shown.status.startswith("Not done:") and session.draft is None
    assert c.make_draft(c.Session(), "").status == "Not done: Finish the run first."


def test_nothing_to_answer_without_a_waiting_run():
    shown = c.send_answers(c.Session(), "Sam", {}, {})
    assert shown.status == "Not done: There is nothing to answer right now."


def test_question_and_review_places_cover_every_question_and_fact():
    from dora_agent.agent.questions import QUESTIONS
    from dora_agent.agent.values import fact_names

    assert set(c.QUESTION_NAMES) == set(QUESTIONS)
    assert set(c.REVIEW_NAMES) == set(fact_names())
