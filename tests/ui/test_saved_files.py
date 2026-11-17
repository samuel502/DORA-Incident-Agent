"""Approved notification files saved in the Colab runtime (live Colab test, Sam, 16 November 2026).

The download buttons don't download inside Colab: the page sits in an embedded frame that may not start
downloads. So the files are also saved in a fixed runtime folder, and the page names them.

Proves:
- the fixed folder is /content/dora_outputs, read when Approve is pressed (tests point it at a temp folder),
- after approval, the text and JSON files are in that folder, the buttons still offer the same files,
  and the page shows the exact file names with the note about the Files panel, as plain text,
- nothing is saved or shown before approval, or when approval is refused,
- the saved files hold the approved notification (NOT SENT) and nothing else,
- the page's "Saved files" box is a read-only plain-text box, shown only when there are files,
- the server only serves that folder, never the decision logs (tests/ui/test_launch.py).
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

import gradio as gr
import pytest

from dora_agent.evaluation.case_runner import load_scenarios
from dora_agent.notification.approval import NOT_SENT
from dora_agent.notification.fields import DISCOVERY_CHOICES
from dora_agent.ui import app as page
from dora_agent.ui import controller as c

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "cases"))
from ideal_llm import IdealLlm  # noqa: E402

NOW = datetime(2026, 11, 8, 12, 0, tzinfo=timezone.utc)
C01 = next(s for s in load_scenarios() if s.scenario_id == "C01")
NOTE = "Download it from the Files panel on the left (right-click, Download)."


@pytest.fixture
def outputs(tmp_path, monkeypatch):
    folder = tmp_path / "dora_outputs"
    monkeypatch.setattr(c, "OUTPUT_DIR", folder)
    monkeypatch.setattr(c, "RUN_LOG_DIR", tmp_path / "runs")
    return folder


def drafted(tmp_path):
    session = c.Session()
    ticket, reported = c.load_sample("C01")
    c.start(session, ticket, reported, "C01", lambda: IdealLlm(C01), now=NOW, log_dir=tmp_path / "runs")
    c.make_draft(session, "")
    assert session.draft is not None
    return session


def approve(session, name="Sam Approver", plan="no"):
    return c.approve_draft(session, name, DISCOVERY_CHOICES[0], plan, "", "", "")  # no out_dir: the fixed folder


def test_the_fixed_folder_and_note():
    assert c.OUTPUT_DIR == Path("/content/dora_outputs")
    assert c.FILES_PANEL_NOTE == NOTE


def test_approval_saves_both_files_in_the_fixed_folder_and_names_them(tmp_path, outputs):
    session = drafted(tmp_path)
    shown = approve(session)
    stem = f"initial-notification-{session.approved.run_id}"
    text_file, json_file = outputs / f"{stem}.txt", outputs / f"{stem}.json"
    assert text_file.is_file() and json_file.is_file()
    assert shown.downloads == (str(text_file), str(json_file))  # the buttons offer the same files
    assert shown.saved == (f"Saved in this Colab runtime:\n{text_file.as_posix()}\n{json_file.as_posix()}\n"
                           f"{NOTE} Synthetic data only; nothing is sent. The files are deleted when the runtime ends.")


def test_saved_files_hold_the_approved_notification(tmp_path, outputs):
    session = drafted(tmp_path)
    shown = approve(session)
    text = Path(shown.downloads[0]).read_text(encoding="utf-8")
    data = json.loads(Path(shown.downloads[1]).read_text(encoding="utf-8"))
    assert NOT_SENT in text and text == shown.approved + "\n"
    assert data["approved_by"] == "Sam Approver" and data["run_id"] == session.approved.run_id
    assert sorted(p.name for p in outputs.iterdir()) == sorted(Path(p).name for p in shown.downloads)


def test_nothing_saved_or_shown_before_approval_or_when_refused(tmp_path, outputs):
    session = drafted(tmp_path)
    assert c.screen(session).saved == ""
    refused = approve(session, name=" ")
    assert refused.notice_at == "approve" and refused.saved == "" and refused.downloads is None
    assert not outputs.exists()  # nothing written


def test_new_run_clears_the_saved_files_from_the_page(tmp_path, outputs):
    session = drafted(tmp_path)
    approve(session)
    ticket, reported = c.load_sample("C01")
    shown = c.start(session, ticket, reported, "C01", lambda: IdealLlm(C01), now=NOW, log_dir=tmp_path / "runs")
    assert shown.saved == "" and shown.downloads is None


def test_saved_text_names_posix_paths_on_one_line_each():
    shown = c.saved_text(("/content/dora_outputs/initial-notification-abc.txt",
                          "/content/dora_outputs/initial-notification-abc.json"))
    lines = shown.splitlines()
    assert lines[1] == "/content/dora_outputs/initial-notification-abc.txt"
    assert lines[2] == "/content/dora_outputs/initial-notification-abc.json"
    assert NOTE in lines[3]
    assert c.saved_text(None) == ""
    # The fixed folder joined with a file name gives the exact Colab path.
    assert PurePosixPath(c.OUTPUT_DIR.as_posix()) / "x.txt" == PurePosixPath("/content/dora_outputs/x.txt")


def test_page_shows_the_saved_files_in_a_plain_read_only_box(tmp_path, outputs):
    demo = page.build_app(lambda: IdealLlm(C01))
    box = next(b for b in demo.blocks.values()
               if isinstance(b, gr.Textbox) and b.label == "Saved files (if the buttons don't download)")
    assert box.interactive is False and box.visible is False

    def event(label):
        button = next(b for b in demo.blocks.values() if isinstance(b, gr.Button) and b.value == label)
        return next(f for f in demo.fns.values() if any(t[0] == button._id for t in f.targets))

    run = event("Run")
    ticket, reported = c.load_sample("C01")
    values = run.fn(None, ticket, reported, "C01")
    assert values[run.outputs.index(box)] == {"__type__": "update", "value": "", "visible": False}
    session = values[0]
    draft = event("Prepare draft")
    values = draft.fn(session, "")
    approve_fn = event("Approve (nothing is sent)")
    values = approve_fn.fn(session, "Sam Approver", DISCOVERY_CHOICES[0], "no", "", "", "")
    update = values[approve_fn.outputs.index(box)]
    assert update["visible"] is True and NOTE in update["value"]
    assert (outputs / f"initial-notification-{session.approved.run_id}.txt").as_posix() in update["value"]
    buttons = [o for o in approve_fn.outputs if isinstance(o, gr.DownloadButton)]
    assert len(buttons) == 2
    assert all(values[approve_fn.outputs.index(b)]["visible"] is True for b in buttons)  # buttons kept
