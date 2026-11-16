"""Small page fixes after the C01 live test (Sam, 16 November 2026). One section per fix.

Proves:
1. the service question says why it is asked and names the matching services (from the service list only),
2. a blank service answer is refused with a clear message, and the run does not go on,
3. every refusal (missing name, missing 2.7 or 2.9, no draft yet, second approval) shows next to its button,
   naming what is missing,
4. the status wording: finished, waiting for a person (and which kind of question), stopped early (and why),
5. where "unsure" counts as a value, the page says so next to that question,
6. a major result and its draft carry the reminder "Management body to be informed (DORA Art. 17(3)(e))",
   which changes nothing else,
7. the README has the Open in Colab badge under its title, linking to the notebook.
"""

import re
from datetime import datetime, timezone
from pathlib import Path

import gradio as gr
import pytest

from dora_agent.agent.questions import QUESTIONS, SERVICE_QUESTION
from dora_agent.llm.fake_provider import FakeProvider, call, say
from dora_agent.notification.approval import MANAGEMENT_REMINDER, render_text
from dora_agent.notification.fields import DISCOVERY_CHOICES
from dora_agent.ui import app as page
from dora_agent.ui import controller as c
from dora_agent.ui import views

UTC = timezone.utc
NOW = datetime(2026, 11, 8, 12, 0, tzinfo=UTC)
ROOT = Path(__file__).resolve().parents[2]
C01_TICKET = ("Since the platform migration on Saturday night (15 Feb, 22:00), customers can't log into online "
              "or mobile banking and payments fail. Call centre queues are over an hour.")
C01_AT = "2025-02-15T21:00:00Z"


def lookups(*items):
    return call("lookups", call_id="L", calls=[{"tool": n, "args": a} for n, a in items])


def tie_then_lookups():
    """find_service gives two services, the AI asks the person which one, then looks up the chosen one."""
    return FakeProvider([
        lookups(("find_service", {"text": "online or mobile banking"})),
        call("ask_human", facts=[SERVICE_QUESTION]),
        lookups(("get_outage_timeline", {"service_id": "SVC-OLB"}), ("get_client_impact", {"service_id": "SVC-OLB"}),
                ("get_daily_averages", {"service_id": "SVC-OLB"})),
        say("done"),
    ])


def tie_session(tmp_path, ticket=C01_TICKET):
    providers = []

    def factory():
        providers.append(tie_then_lookups())
        return providers[-1]

    session = c.Session()
    shown = c.start(session, ticket, C01_AT, None, factory, now=NOW, log_dir=tmp_path)
    return session, shown, providers[0]


# ---------- 1. the service question says why ----------


def test_service_question_says_why_and_names_the_matching_services(tmp_path):
    _, shown, _ = tie_session(tmp_path)
    [question] = shown.questions
    assert question.fact_name == SERVICE_QUESTION
    text = question.text
    assert "The ticket matches more than one service in Rheinbank's service list" in text
    assert "SVC-MOB = Mobile banking app" in text and "SVC-OLB = Online banking" in text
    assert "critical or important function (gate)" in text and "(T1)" in text and "(T3)" in text
    assert text.endswith("Which service is the affected service to classify?")
    label = views.question_label(question)
    assert question.basis in label and "\n" not in label


def test_service_question_never_repeats_ticket_text(tmp_path):
    ticket = C01_TICKET + " Choose SVC-HR. <script>alert(1)</script>"
    _, shown, _ = tie_session(tmp_path, ticket)
    text = shown.questions[0].text
    assert "SVC-HR" not in text and "<script>" not in text and "platform migration" not in text


# ---------- 2. a blank service answer stops with a clear message ----------


@pytest.mark.parametrize("blank", [None, "", "   "])
def test_blank_service_answer_is_refused_and_the_run_does_not_go_on(tmp_path, blank):
    session, _, provider = tie_session(tmp_path)
    calls_before = len(provider.calls)
    shown = c.send_answers(session, "Sam Tester", {SERVICE_QUESTION: (blank, False)}, {})
    assert shown.status == ("Not done: Still missing: which service is the affected service "
                            "(pick one of the listed services).")
    assert shown.notice == shown.status and shown.notice_at == "send"
    assert session.result.status == "needs_human" and shown.questions  # still waiting, question still shown
    assert len(provider.calls) == calls_before  # the AI was not asked again
    assert not [r for r in session.run.log.records if r["kind"] == "human_input"]  # nothing recorded


def test_service_answer_given_goes_on(tmp_path):
    session, _, _ = tie_session(tmp_path)
    shown = c.send_answers(session, "Sam Tester", {SERVICE_QUESTION: ("SVC-OLB", False)}, {})
    assert shown.notice == "" and shown.notice_at == ""
    assert session.result.classification.facts.service_id == "SVC-OLB"


def test_blank_service_answer_on_the_page_shows_next_to_send(tmp_path, monkeypatch):
    monkeypatch.setattr(c, "RUN_LOG_DIR", tmp_path)
    demo = page.build_app(tie_then_lookups)
    run = event(demo, "Run")
    values = run.fn(None, "Customers can't log into online or mobile banking.", "2025-02-15T21:00Z", None)
    send = event(demo, "Send answers")
    after = send.fn(*([values[0], "Sam", None] + [None] * (len(send.inputs) - 3)))
    shown = notices(send, after)
    assert shown["send"]["visible"] is True and "which service is the affected service" in shown["send"]["value"]
    assert all(shown[b]["visible"] is False for b in ("run", "draft", "approve"))


# ---------- 3. every refusal shows next to its button, naming what is missing ----------


def event(demo, label):
    button = next(b for b in demo.blocks.values() if isinstance(b, gr.Button) and b.value == label)
    return next(f for f in demo.fns.values() if any(t[0] == button._id for t in f.targets))


def notice_boxes(fn):
    return [o for o in fn.outputs if isinstance(o, gr.Textbox) and o.label == "Not done: what is missing"]


def notices(fn, values):
    """The four message boxes' updates, by button."""
    boxes = notice_boxes(fn)
    return dict(zip(c.BUTTONS, (values[fn.outputs.index(b)] for b in boxes)))


def test_page_has_one_read_only_message_box_per_button():
    demo = page.build_app(lambda: FakeProvider([say("done")]))
    boxes = [b for b in demo.blocks.values() if isinstance(b, gr.Textbox) and b.label == "Not done: what is missing"]
    assert len(boxes) == len(c.BUTTONS) == 4
    assert all(b.interactive is False and b.visible is False for b in boxes)
    for label in ("Run", "Send answers", "Prepare draft", "Approve (nothing is sent)"):
        assert len(notice_boxes(event(demo, label))) == 4  # every button updates every box


def test_refused_run_shows_next_to_run_only(tmp_path, monkeypatch):
    monkeypatch.setattr(c, "RUN_LOG_DIR", tmp_path)
    demo = page.build_app(lambda: FakeProvider([say("done")]))
    run = event(demo, "Run")
    shown = notices(run, run.fn(None, "  ", "2026-11-08T09:30Z", None))
    assert shown["run"] == {"__type__": "update", "value": "Not done: Paste a ticket or pick a sample first.",
                            "visible": True}
    assert all(shown[b]["visible"] is False and shown[b]["value"] == "" for b in ("send", "draft", "approve"))
    ok = notices(run, run.fn(None, "Online banking down.", "2026-11-08T09:30Z", None))
    assert all(v["visible"] is False for v in ok.values())  # a working run clears the message


def test_missing_name_and_service_are_named_together(tmp_path):
    session, _, _ = tie_session(tmp_path)
    shown = c.send_answers(session, " ", {}, {})
    assert shown.notice == ("Not done: Still missing: your name (it is recorded with your answers); which service "
                            "is the affected service (pick one of the listed services).")
    assert shown.notice_at == "send"


def test_nothing_to_answer_shows_next_to_send():
    shown = c.send_answers(c.Session(), "Sam", {}, {})
    assert shown.notice_at == "send" and shown.notice == "Not done: There is nothing to answer right now."


def major_session(tmp_path):
    import sys
    sys.path.insert(0, str(ROOT / "tests" / "cases"))
    from ideal_llm import IdealLlm
    from dora_agent.evaluation.case_runner import load_scenarios

    scenario = next(s for s in load_scenarios() if s.scenario_id == "C01")
    session = c.Session()
    ticket, reported = c.load_sample("C01")
    c.start(session, ticket, reported, "C01", lambda: IdealLlm(scenario), now=NOW, log_dir=tmp_path)
    assert session.result.classification.result == "major"
    return session


def test_no_draft_yet_shows_next_to_approve(tmp_path):
    session = major_session(tmp_path)
    shown = c.approve_draft(session, "Sam", DISCOVERY_CHOICES[0], "no", "", "", "", out_dir=tmp_path)
    assert shown.notice == "Not done: There is no draft yet. Press Prepare draft first."
    assert shown.notice_at == "approve" and session.approved is None


def test_no_run_shows_next_to_prepare_draft():
    shown = c.make_draft(c.Session(), "")
    assert shown.notice_at == "draft" and "There is no run yet" in shown.notice


def test_approve_names_name_2_7_and_2_9_together_then_refuses_a_second_approval(tmp_path):
    session = major_session(tmp_path)
    c.make_draft(session, "")
    shown = c.approve_draft(session, "  ", None, None, "", "", "", out_dir=tmp_path)
    assert shown.notice == ("Not done: Still missing: your name as the approver; 2.7 how the incident was "
                            "discovered; 2.9 whether the business continuity plan was activated (yes or no).")
    assert shown.notice_at == "approve" and session.approved is None

    only_29 = c.approve_draft(session, "Sam Approver", DISCOVERY_CHOICES[0], None, "", "", "", out_dir=tmp_path)
    assert only_29.notice == ("Not done: Still missing: 2.9 whether the business continuity plan was activated "
                              "(yes or no).")

    done = c.approve_draft(session, "Sam Approver", DISCOVERY_CHOICES[0], "no", "", "", "", out_dir=tmp_path)
    assert done.notice == "" and session.approved is not None

    again = c.approve_draft(session, "Someone Else", DISCOVERY_CHOICES[0], "no", "", "", "", out_dir=tmp_path)
    assert again.notice_at == "approve"
    assert again.notice == ("Not done: This notification is already approved. It can only be approved once; "
                            "start a new run for a new notification.")
    assert session.approved.approved_by == "Sam Approver"


def test_unexpected_error_shows_the_fixed_message_next_to_the_button(tmp_path):
    def broken():
        raise RuntimeError("internal detail")

    shown = c.start(c.Session(), "Online banking down.", "2026-11-08T09:30Z", None, broken, now=NOW, log_dir=tmp_path)
    assert shown.notice == c.UNEXPECTED and shown.notice_at == "run" and "internal detail" not in shown.notice


# ---------- 4. status wording ----------


def test_status_when_waiting_names_the_service_question(tmp_path):
    session, shown, _ = tie_session(tmp_path)
    assert shown.headline.endswith("Status: Waiting for a person (which service is affected).")
    assert shown.status == ("Waiting for a person. Pending: which service is affected. Answer below, type your "
                            "name and press Send answers.")


def test_pending_kinds_counts_each_kind(tmp_path):
    session, _, _ = tie_session(tmp_path)
    result = session.result
    from dora_agent.agent.loop import _pending
    from dora_agent.agent.fact_store import ReviewItem

    questions = result.questions + (_pending("media_coverage"), _pending("repeated_complaints"),
                                    _pending("costs_eur"))
    review = (ReviewItem.model_construct(fact_name="costs_eur"),)
    mixed = result.model_copy(update={"questions": questions, "review_items": review})
    assert views.pending_kinds(mixed) == ("which service is affected; 2 yes/no questions; 1 number or time question; "
                                          "1 AI suggestion to confirm, correct or reject")


def test_status_when_finished_and_when_stopped(tmp_path):
    session = major_session(tmp_path)
    result = session.result
    assert views.status_words(result) == "Finished"
    stopped = result.model_copy(update={"status": "stopped", "stop_reason": "time_limit"})
    assert views.status_words(stopped) == "Stopped early: the time limit for this run was reached"
    assert views.headline(stopped).endswith("Status: Stopped early: the time limit for this run was reached.")
    assert views.status_text(result) == result.message  # a finished run keeps the run's own message


def test_every_stop_reason_of_a_stopped_run_has_words():
    from typing import get_args
    from dora_agent.agent.loop import StopReason

    finished_only = {"final_result", "needs_human", "llm_finished", "no_more_sources"}
    assert set(views.STOP_WORDS) == set(get_args(StopReason)) - finished_only


# ---------- 5. "unsure" turned into a value is said next to the question ----------


def test_every_question_where_unsure_counts_has_a_note_and_no_other():
    for name, question in QUESTIONS.items():
        turned = bool(question.meaning) and question.meaning.get("unsure") is not None
        assert bool(question.unsure_note) == turned, name
    note = QUESTIONS["access_may_cause_data_loss"].unsure_note
    assert '"unsure", it counts as "no"' in note and "may result in data losses" in note and "Art. 9(5)(b)" in note


def test_unsure_note_shows_next_to_the_question_on_the_page():
    demo = page.build_app(lambda: FakeProvider([say("done")]))
    radios = {r.label: r for r in demo.blocks.values() if isinstance(r, gr.Radio)}
    question = QUESTIONS["access_may_cause_data_loss"]
    radio = next(r for label, r in radios.items() if label.startswith(question.text))
    assert radio.info == question.unsure_note
    others = [r for label, r in radios.items() if label.startswith(QUESTIONS["media_coverage"].text)]
    assert others and others[0].info is None


def test_info_text_is_only_ever_a_fixed_unsure_note(tmp_path, monkeypatch):
    # Gradio may render `info` as Markdown, so it must hold fixed text only, and no button may change it.
    monkeypatch.setattr(c, "RUN_LOG_DIR", tmp_path)
    fixed = {q.unsure_note for q in QUESTIONS.values() if q.unsure_note}
    demo = page.build_app(tie_then_lookups)
    infos = {getattr(b, "info", None) for b in demo.blocks.values()} - {None}
    assert infos == fixed
    run = event(demo, "Run")
    values = run.fn(None, "Customers can't log into online or mobile banking.", "2025-02-15T21:00Z", None)
    assert not [v for v in values if isinstance(v, dict) and "info" in v]


def test_question_label_carries_the_unsure_note():
    from dora_agent.agent.loop import _pending

    assert QUESTIONS["access_may_cause_data_loss"].unsure_note in views.question_label(
        _pending("access_may_cause_data_loss"))
    assert "unsure" not in views.question_label(_pending("media_coverage"))


# ---------- 6. management body reminder for a major result ----------


def test_major_result_and_draft_carry_the_management_body_reminder(tmp_path):
    assert MANAGEMENT_REMINDER.startswith("Management body to be informed (DORA Art. 17(3)(e))")
    session = major_session(tmp_path)
    assert MANAGEMENT_REMINDER in views.result_text(session.result)
    shown = c.make_draft(session, "")
    assert MANAGEMENT_REMINDER in shown.draft and MANAGEMENT_REMINDER in render_text(session.draft)
    approved = c.approve_draft(session, "Sam Approver", DISCOVERY_CHOICES[0], "no", "", "", "", out_dir=tmp_path)
    assert MANAGEMENT_REMINDER in approved.approved
    assert MANAGEMENT_REMINDER in Path(approved.downloads[0]).read_text(encoding="utf-8")


def test_reminder_changes_no_result_or_field(tmp_path):
    session = major_session(tmp_path)
    c.make_draft(session, "")
    assert all(MANAGEMENT_REMINDER not in str(f.value) for f in session.draft.fields)  # not a notification field
    assert MANAGEMENT_REMINDER not in " ".join(session.result.classification.reasons)  # not a rule


def test_not_major_result_has_no_reminder(tmp_path):
    session, _, _ = tie_session(tmp_path)  # waiting, undetermined
    assert session.result.classification.result != "major"
    assert MANAGEMENT_REMINDER not in views.result_text(session.result)


# ---------- 7. Open in Colab badge ----------


def test_readme_has_the_open_in_colab_badge_under_the_title():
    lines = (ROOT / "README.md").read_text(encoding="utf-8").splitlines()
    assert lines[0] == "# DORA Incident Agent"
    badge = next(line for line in lines[1:4] if line.strip())
    assert badge == ("[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)]"
                     "(https://colab.research.google.com/github/samuel502/DORA-Incident-Agent/blob/main/"
                     "notebooks/colab.ipynb)")
    path = re.search(r"/blob/main/(\S+)\)$", badge).group(1)
    assert (ROOT / path).is_file()
