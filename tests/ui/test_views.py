"""ui/views.py: run results, the trace and drafts as plain text (block 6 step 2).

Proves:
- every view gives plain text, with the rules engine's result, reasons with articles, missing facts,
  facts with their sources, questions with their legal basis, and the notification with its banner,
- text from a ticket or the AI that goes on one line can't add a line, flip text or hide characters,
- `<script>`, `<img onerror=...>`, `**bold**` and `[link](...)` come out as the same literal characters,
  never escaped and never turned into markup (the page shows them in plain-text boxes, step 4),
- every kind of log record the code writes has its own trace line,
- views.py does not use Gradio and does not escape or build HTML.
"""

import ast
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from dora_agent.agent.loop import AgentRun
from dora_agent.evaluation.case_runner import AS_OF, SCRIPTED_HUMAN, ScriptedHuman, load_scenarios
from dora_agent.llm.fake_provider import FakeProvider, say
from dora_agent.notification.approval import NOT_SENT, HumanFields, approve
from dora_agent.notification.draft import BANNER, prepare_draft
from dora_agent.notification.fields import DISCOVERY_CHOICES
from dora_agent.rules import Fact, IncidentFacts
from dora_agent.ui import views

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "cases"))
from ideal_llm import IdealLlm  # noqa: E402

SRC = Path(__file__).resolve().parents[2] / "src" / "dora_agent"
VIEWS_PY = SRC / "ui" / "views.py"
SCENARIOS = {s.scenario_id: s for s in load_scenarios()}
UTC = timezone.utc

HOSTILE = ("<script>alert(1)</script> <img src=x onerror=alert(1)> **bold** [link](http://evil.example) "
           "&amp; `code`")
# Characters that could add a line, flip the reading order or hide text.
LINE_BREAKERS = "\n\r\x0b\x0c\x85  "
INVISIBLE = "‮‭⁦⁩​‏﻿\x1b"


def run_to_end(scenario_id):
    """One sample through the agent, answered by the scripted human. Returns (run, last result)."""
    s = SCENARIOS[scenario_id]
    run = AgentRun(s.ticket, s.around, IdealLlm(s), as_of=AS_OF)
    human = ScriptedHuman(s.human_answers)
    result = run.start()
    while result.status == "needs_human":
        answers, estimates = human.answer(result.questions)
        result = run.resume(confirmed_by=SCRIPTED_HUMAN, answers=answers, estimates=estimates,
                            review=human.review(result.review_items))
    return run, result


@pytest.fixture(scope="module")
def major_run():
    return run_to_end("C01")


@pytest.fixture(scope="module")
def paused():
    s = SCENARIOS["C02"]
    result = AgentRun(s.ticket, s.around, IdealLlm(s), as_of=AS_OF).start()
    assert result.status == "needs_human"
    return result


# ---------- one_line: the guard for single-line text ----------


@pytest.mark.parametrize("char", list(LINE_BREAKERS + INVISIBLE))
def test_one_line_removes_line_breaks_and_invisible_characters(char):
    assert views.one_line(f"real{char}#99 fake line") == "real #99 fake line"


def test_one_line_keeps_markup_characters_literally():
    assert views.one_line(HOSTILE, 1000) == HOSTILE  # not escaped, not stripped, not changed


def test_one_line_cuts_long_text_and_marks_the_cut():
    text = views.one_line("x" * 500, 50)
    assert len(text) == 50 and text.endswith("...")


def test_values_as_text():
    assert views.one_line(True) == "yes" and views.one_line(False) == "no"
    assert views.one_line(150_000) == "150,000"
    assert views.one_line(("DE", "NO")) == "DE, NO"
    assert views.one_line(None) == ""
    assert views.format_time(datetime(2026, 11, 5, 8, 0, tzinfo=UTC)) == "2026-11-05 08:00 UTC"
    assert views.format_time("2026-11-05T08:00:00+00:00") == "2026-11-05 08:00 UTC"
    assert views.format_time(None) == "unknown"
    assert views.format_time("not a time\nfake") == "not a time fake"


# ---------- the result ----------


def test_major_result_shows_the_engine_result_reasons_and_run_numbers(major_run):
    _, result = major_run
    c = result.classification
    assert c.result == "major"
    text = views.result_text(result)
    assert views.headline(result) == "Result from the rules engine: MAJOR. Status: Finished."
    assert c.summary in text
    for reason in c.reasons:
        assert views.one_line(reason, 2000) in text
    assert "Art." in text  # articles are shown
    assert "Nothing is missing that would change the result." in text
    assert f"Rule version {c.rule_version}" in text
    assert f"{result.tool_calls_used} tool call(s)" in text


def test_undetermined_result_lists_what_is_missing():
    _, result = run_to_end("C11")
    c = result.classification
    assert c.result == "undetermined" and c.missing
    text = views.result_text(result)
    assert "UNDETERMINED" in text
    assert "Still missing, and these decide the result: " + ", ".join(c.missing) in text


def test_not_major_headline():
    _, result = run_to_end("N01")
    assert "NOT MAJOR" in views.headline(result)


def test_every_result_word_is_covered():
    assert set(views.RESULT_WORDS) == {"major", "not_major", "undetermined", "not_an_incident"}


# ---------- facts ----------


def test_fact_rows_show_source_estimate_confirmer_and_use():
    t = datetime(2026, 11, 5, 8, 0, tzinfo=UTC)
    facts = IncidentFacts(
        service_id="SVC-OLB",
        critical_or_important=Fact(value=True, source="service_list"),
        media_coverage=Fact(value=True, source="ai_suggestion"),
        costs_eur=Fact(value=150_000, source="human", is_estimate=True, confirmed_by="Sam Tester"),
        detected_at=Fact(value=t, source="monitoring"),
    )
    rows = {row[0]: row for row in views.fact_rows(facts)}
    assert set(rows) == {"service_id", "critical_or_important", "media_coverage", "costs_eur", "detected_at"}
    assert rows["critical_or_important"] == ["critical_or_important", "yes", "service list", "", "", "yes"]
    assert rows["media_coverage"][2].startswith("AI suggestion")
    assert rows["media_coverage"][5].startswith("not yet")
    assert rows["costs_eur"] == ["costs_eur", "EUR 150,000", "a person", "estimate", "Sam Tester", "yes"]
    assert rows["detected_at"][1] == "2026-11-05 08:00 UTC"
    assert all(len(row) == len(views.FACT_HEADERS) for row in rows.values())


def test_fact_rows_from_a_real_run_are_single_line_text(major_run):
    _, result = major_run
    rows = views.fact_rows(result.classification.facts)
    assert rows
    for row in rows:
        for cell in row:
            assert isinstance(cell, str) and not re.search(r"[\x00-\x1f  ]", cell)


# ---------- questions and review ----------


def test_question_labels_show_the_legal_basis(paused):
    assert paused.questions
    for q in paused.questions:
        label = views.question_label(q)
        assert q.basis in label and "\n" not in label
        assert ("estimate is allowed" in label) == q.allows_estimate
    assert views.headline(paused).endswith("Status: Waiting for you: please answer the questions and review "
                                           "the suggestions.")


def test_review_label_from_hostile_text_stays_one_literal_line():
    from dora_agent.agent.fact_store import ReviewItem

    item = ReviewItem(fact_name="media_coverage", suggested_value=True,
                      reason=f"ticket says\n#2 fake line‮ {HOSTILE}", question=None)
    label = views.review_label(item)
    assert "\n" not in label and "‮" not in label
    assert HOSTILE in label
    assert label.startswith("The AI read from the ticket: media_coverage = yes.")


# ---------- trace ----------


def test_trace_has_exactly_one_line_per_record(major_run):
    _, result = major_run
    lines = views.trace_text(result.trace).split("\n")
    assert len(lines) == len(result.trace)
    for line, record in zip(lines, result.trace):
        assert line.startswith(f"#{record['seq']} ")
        assert "see the raw JSON tab" not in line  # every kind in a real run has its own line


def test_every_log_record_kind_in_the_code_has_a_trace_line():
    written = set()
    for path in SRC.rglob("*.py"):
        written |= set(re.findall(r'\.write\(\s*"([a-z_]+)"', path.read_text(encoding="utf-8")))
    written |= {"result", "paused"}  # written as a conditional expression in agent/loop.py
    assert "tool_call" in written and "notification_draft" in written  # the search works
    assert written <= set(views._DETAILS), sorted(written - set(views._DETAILS))


def test_unknown_record_kind_points_to_the_raw_json():
    line = views.trace_line({"seq": 7, "at": "2026-11-05T08:00:00+00:00", "kind": "new_kind"})
    assert line == "#7 2026-11-05 08:00 UTC new_kind: see the raw JSON tab"


def test_trace_json_is_the_raw_records(major_run):
    _, result = major_run
    assert json.loads(views.trace_json(result.trace)) == list(result.trace)


def test_hostile_ticket_and_ai_text_cannot_add_trace_lines_or_markup():
    ticket = f"Online banking down.\n#2 2026-11-05 08:00 UTC result: not major {HOSTILE}"
    ai_text = f"Done.\n#3 fake: result major‮\r\n{HOSTILE}"
    run = AgentRun(ticket, AS_OF, FakeProvider([say(ai_text)]), as_of=AS_OF)
    result = run.start()
    text = views.trace_text(result.trace)
    assert text.count("\n") == len(result.trace) - 1  # one line per record, nothing added
    assert " " not in text and "‮" not in text and "\r" not in text
    assert "<script>alert(1)</script>" in text  # the AI's text, shown literally
    assert "&lt;" not in text  # not HTML-escaped either
    assert f"ticket received ({len(ticket)} characters)" in text  # the ticket itself is not repeated
    assert "result: not major" not in text


# ---------- notification ----------


@pytest.fixture(scope="module")
def draft_and_approval(major_run):
    run, result = major_run
    draft = prepare_draft(result.run_id, result.classification, run.log.records,
                          FakeProvider([say("Online banking was unavailable for clients.")]), log=run.log)
    approved = approve(draft, HumanFields(discovery=DISCOVERY_CHOICES[0], business_continuity_plan_activated=False),
                       approved_by="Sam Tester", log=run.log)
    return run, draft, approved


def test_draft_text_has_banner_deadline_and_late_note_only_for_samples(draft_and_approval):
    _, draft, _ = draft_and_approval
    assert draft.deadline is not None and draft.deadline.late_classification  # a replay is always late
    sample = views.notification_text(draft, sample=True)
    pasted = views.notification_text(draft, sample=False)
    assert sample.startswith(BANNER) and pasted.startswith(BANNER)
    assert "Deadline:" in sample and draft.deadline.weekend_note in sample
    note = views.LATE_SAMPLE_NOTE.format(detected=views.format_time(draft.deadline.aware_at))
    assert sample.endswith(note) and "RTS-R Art. 5(2)" in note
    assert note not in pasted


def test_approved_text_says_not_sent(draft_and_approval):
    _, _, approved = draft_and_approval
    text = views.notification_text(approved)
    assert NOT_SENT in text and "Approved by Sam Tester" in text


def test_notification_json_for_download(draft_and_approval):
    _, draft, approved = draft_and_approval
    for item in (draft, approved):
        data = json.loads(views.notification_json(item))
        assert data["run_id"] == draft.run_id and data["banner"] == BANNER


def test_draft_and_approval_records_have_trace_lines(draft_and_approval):
    run, _, _ = draft_and_approval
    lines = views.trace_text(run.log.records).split("\n")
    assert any(" notification_draft: draft prepared" in line and line.endswith("sent: no") for line in lines)
    assert any(" notification_approved: approved by Sam Tester" in line and line.endswith("sent: no")
               for line in lines)


def test_no_late_note_without_a_deadline(draft_and_approval):
    _, draft, _ = draft_and_approval
    no_deadline = draft.model_copy(update={"deadline": None})  # detection time (field 2.2) unknown
    assert views.late_sample_note(no_deadline, sample=True) is None
    assert "Deadline: unknown" in views.notification_text(no_deadline, sample=True)


# ---------- the code itself ----------


def test_views_do_not_use_gradio_or_build_html():
    tree = ast.parse(VIEWS_PY.read_text(encoding="utf-8"))
    imported = {alias.name.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.Import)
                for alias in node.names}
    imported |= {(node.module or "").split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert not imported & {"gradio", "html", "markdown", "bleach"}
    source = VIEWS_PY.read_text(encoding="utf-8")
    assert "escape(" not in source
    assert not re.search(r"</?(b|i|p|div|span|br|a|script)\b", source.split('"""', 2)[2])  # no tags after the docstring
