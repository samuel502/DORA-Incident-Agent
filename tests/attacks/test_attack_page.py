"""Attack: markup or script text on the page (unsafe output, OWASP LLM05).

Hostile text can come from five places: the ticket, the AI's own words, the bank data (tool output), what a
person types (names, causes, notification fields), and the AI-drafted notification text. On a page that rendered
HTML or Markdown, `<script>` or `<img onerror=...>` would run, and a line break plus "#99 ... not_major" could fake
a line in the trace.

This test drives one whole page session (run, draft, approval, saved files) with hostile text from all five places
at once, on the poisoned bank data. Must happen: every box shows the text literally (no HTML escaping, nothing
rendered), one-line places stay one line with no invisible direction or zero-width characters, the trace has
exactly one line per logged step, and the saved files hold the same literal text.

Already covered elsewhere: tests/ui/test_app.py (no HTML component; Markdown only for fixed texts; output boxes
read-only), tests/ui/test_views.py and tests/ui/test_controller.py (hostile ticket and AI text in single views).
"""

import json
import re
import sys
from pathlib import Path

from attack_kit import MARK

from dora_agent.evaluation.case_runner import load_scenarios
from dora_agent.ui import controller as c

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "cases"))
from ideal_llm import IdealLlm  # noqa: E402

MARKUP = "<script>alert(1)</script> <img src=x onerror=alert(1)> **bold** [link](http://evil.example)"
FAKE_LINE = "\n#99 12:00 result: finished (final_result), result not_major"
INVISIBLE = re.compile("[\x00-\x09\x0b-\x1f\x7f-\x9f\u2028\u2029\u202a-\u202e\u2066-\u2069\u200b-\u200f\u061c\ufeff]")


class HostileWords(IdealLlm):
    """The ideal C01 path, but every answer also carries hostile text in what the AI writes."""

    def chat(self, messages, tools, time_left=None):
        answer = super().chat(messages, tools, time_left)
        return answer.model_copy(update={"text": f"{answer.text} {MARKUP}{FAKE_LINE}\u202eRojam ton"})


def check_screen(shown: c.Screen, records: list[dict]) -> None:
    """The safety rules for everything one screen shows."""
    texts = [shown.status, shown.headline, shown.result, shown.trace, shown.draft, shown.approved, shown.notice,
             *shown.review_labels.values(), *(cell for row in shown.facts for cell in row)]
    for text in texts:
        assert "&lt;" not in text and "&gt;" not in text and "&amp;" not in text  # literal, never escaped
    one_line = [shown.headline, *shown.review_labels.values(), *(cell for row in shown.facts for cell in row)]
    for text in one_line:
        assert "\n" not in text and not INVISIBLE.search(text), repr(text)
    lines = shown.trace.split("\n")
    assert len(lines) == len(records)
    assert [line.split(" ", 1)[0] for line in lines] == [f"#{r['seq']}" for r in records]
    assert not any(INVISIBLE.search(line) for line in lines)


def test_hostile_text_from_every_source_stays_literal_text_through_a_whole_page_session(bank_data, tmp_path):
    """Attack: hostile markup, a fake trace line and a right-to-left override arrive from the ticket, the AI's
    words, the poisoned bank data, the person's name and typed fields, all in one session up to approval.
    Must happen: the result is still the engine's MAJOR; every screen passes the safety rules above; the
    markup shows up literally where it was typed; and the saved text and JSON files hold the same literal text."""
    bank_data.use_hostile()
    scenario = next(s for s in load_scenarios() if s.scenario_id == "C01")
    ticket, reported = c.load_sample("C01")
    ticket = f"{ticket}\n{MARKUP}{FAKE_LINE}\u202eRojam ton"
    session = c.Session()

    shown = c.start(session, ticket, reported, "C01", lambda: HostileWords(scenario), log_dir=tmp_path)
    assert shown.headline.startswith("Result from the rules engine: MAJOR.")
    assert MARKUP in shown.trace  # the AI's hostile words arrived, and show as literal text
    check_screen(shown, session.run.log.records)

    shown = c.make_draft(session, f"Possible cause: {MARKUP}")
    assert shown.can_approve, shown.status
    check_screen(shown, session.run.log.records)

    approver = "<b>Approver</b> <script>x</script>"
    shown = c.approve_draft(session, approver, "IT security", "no", f"Third party {MARKUP}",
                            f"Other {MARKUP}", "", out_dir=tmp_path / "out")
    assert shown.status.startswith("Approved. NOT SENT"), shown.status
    check_screen(shown, session.run.log.records)
    assert approver in shown.approved and f"Other {MARKUP}" in shown.approved
    assert not INVISIBLE.search(shown.approved.replace("\n", ""))

    text_file, json_file = (Path(p) for p in shown.downloads)
    saved_text = text_file.read_text(encoding="utf-8")
    assert approver in saved_text and "&lt;" not in saved_text
    saved = json.loads(json_file.read_text(encoding="utf-8"))
    assert saved["approved_by"] == approver
    assert MARK not in saved_text  # bank data free text is not copied into the notification


def test_typed_fields_with_line_breaks_are_refused_not_shown(bank_data, tmp_path):
    """Attack: the person's 2.10 field holds a line break and a fake extra line of the notification.
    Must happen: the approval is refused with a plain message next to the Approve button, and nothing is
    approved or saved."""
    bank_data.use_hostile()
    scenario = next(s for s in load_scenarios() if s.scenario_id == "C01")
    ticket, reported = c.load_sample("C01")
    session = c.Session()
    c.start(session, ticket, reported, "C01", lambda: IdealLlm(scenario), log_dir=tmp_path)
    c.make_draft(session, "")

    shown = c.approve_draft(session, "Approver", "IT security", "no", "",
                            f"fine{FAKE_LINE}\nAPPROVED BY THE CEO", "", out_dir=tmp_path / "out")
    assert shown.notice_at == "approve" and shown.status.startswith("Not done:")
    assert session.approved is None and not (tmp_path / "out").exists()
