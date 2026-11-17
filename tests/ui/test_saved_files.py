"""Approved notification files: saved in the runtime, downloaded by a notebook cell (Sam, 16 November 2026).

Download buttons don't work inside the Colab frame, so the page has none, and no saved-files box either.
The text leaves the page through the approved box's copy button, and the files through the notebook cell
"Download your last approved notification" (launch.download_last_approved, google.colab.files.download).

Proves:
- the page has no download buttons and no saved-files box, and the approved box has a copy button,
- approval still saves the text and JSON files in /content/dora_outputs (tests use a temp folder),
- the status after approval points to the copy button and the notebook cell, by its exact title,
- the download picks the newest approved notification's .txt and .json, from the same run,
- with nothing approved yet it downloads nothing and says so clearly,
- outside Colab it refuses plainly,
- the notebook has the cell, titled exactly, right after the launch cell, and it calls the download function.
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import gradio as gr
import pytest

from dora_agent.evaluation.case_runner import load_scenarios
from dora_agent.notification.approval import NOT_SENT
from dora_agent.notification.fields import DISCOVERY_CHOICES
from dora_agent.ui import app as page
from dora_agent.ui import controller as c
from dora_agent.ui import launch as launcher

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "cases"))
from ideal_llm import IdealLlm  # noqa: E402

NOW = datetime(2026, 11, 8, 12, 0, tzinfo=timezone.utc)
C01 = next(s for s in load_scenarios() if s.scenario_id == "C01")
NOTEBOOK = Path(__file__).resolve().parents[2] / "notebooks" / "colab.ipynb"
TITLE = "Download your last approved notification"


class StandInFiles:
    """Stands in for google.colab.files: records what would be downloaded."""

    def __init__(self):
        self.downloaded = []

    def download(self, path):
        self.downloaded.append(path)


@pytest.fixture
def outputs(tmp_path, monkeypatch):
    folder = tmp_path / "dora_outputs"
    monkeypatch.setattr(c, "OUTPUT_DIR", folder)
    monkeypatch.setattr(c, "RUN_LOG_DIR", tmp_path / "runs")
    return folder


def approved_session(tmp_path):
    session = c.Session()
    ticket, reported = c.load_sample("C01")
    c.start(session, ticket, reported, "C01", lambda: IdealLlm(C01), now=NOW, log_dir=tmp_path / "runs")
    c.make_draft(session, "")
    shown = c.approve_draft(session, "Sam Approver", DISCOVERY_CHOICES[0], "no", "", "", "")  # the fixed folder
    assert session.approved is not None
    return session, shown


# ---------- the page ----------


def test_page_has_no_download_buttons_and_no_saved_files_box():
    demo = page.build_app(lambda: IdealLlm(C01))
    blocks = list(demo.blocks.values())
    assert not [b for b in blocks if isinstance(b, (gr.DownloadButton, gr.File, gr.UploadButton))]
    assert not [b for b in blocks if isinstance(b, gr.Textbox) and "Saved files" in (b.label or "")]


def test_approved_box_is_read_only_with_a_copy_button():
    demo = page.build_app(lambda: IdealLlm(C01))
    (box,) = [b for b in demo.blocks.values()
              if isinstance(b, gr.Textbox) and b.label == "Approved initial notification: NOT SENT"]
    assert box.interactive is False and "copy" in box.buttons


def test_approval_still_saves_both_files_and_points_to_copy_and_the_cell(tmp_path, outputs):
    session, shown = approved_session(tmp_path)
    stem = f"initial-notification-{session.approved.run_id}"
    text_file, json_file = outputs / f"{stem}.txt", outputs / f"{stem}.json"
    assert NOT_SENT in text_file.read_text(encoding="utf-8")
    assert json.loads(json_file.read_text(encoding="utf-8"))["approved_by"] == "Sam Approver"
    assert shown.status == c.APPROVED_STATUS
    assert shown.status.startswith("Approved. NOT SENT") and "copy button" in shown.status
    assert f'"{TITLE}"' in shown.status and c.DOWNLOAD_CELL == TITLE


def test_page_approval_through_the_real_button(tmp_path, outputs):
    demo = page.build_app(lambda: IdealLlm(C01))

    def event(label):
        button = next(b for b in demo.blocks.values() if isinstance(b, gr.Button) and b.value == label)
        return next(f for f in demo.fns.values() if any(t[0] == button._id for t in f.targets))

    ticket, reported = c.load_sample("C01")
    session = event("Run").fn(None, ticket, reported, "C01")[0]
    event("Prepare draft").fn(session, "")
    approve = event("Approve (nothing is sent)")
    values = approve.fn(session, "Sam Approver", DISCOVERY_CHOICES[0], "no", "", "", "")
    assert len(values) == len(approve.outputs)  # the wiring matches without the removed components
    assert len(list(outputs.glob("*.txt"))) == 1 and len(list(outputs.glob("*.json"))) == 1


# ---------- the download cell ----------


def write_pair(folder, run_id, when):
    folder.mkdir(parents=True, exist_ok=True)
    paths = []
    for suffix in (".txt", ".json"):
        path = folder / f"initial-notification-{run_id}{suffix}"
        path.write_text("synthetic", encoding="utf-8")
        os.utime(path, (when, when))
        paths.append(path)
    return paths


def test_download_gets_the_newest_txt_and_json_of_the_same_run(tmp_path, capsys):
    folder = tmp_path / "dora_outputs"
    write_pair(folder, "aaa", 1_000)
    newest = write_pair(folder, "bbb", 3_000)
    write_pair(folder, "ccc", 2_000)
    files = StandInFiles()
    assert launcher.download_last_approved(colab_files=files, folder=folder) is None
    assert files.downloaded == [str(p) for p in newest]
    out = capsys.readouterr().out
    assert "Downloading initial-notification-bbb.txt" in out and "initial-notification-bbb.json" in out


def test_download_with_the_real_approved_files(tmp_path, outputs):
    session, _ = approved_session(tmp_path)
    files = StandInFiles()
    launcher.download_last_approved(colab_files=files)  # default folder: controller.OUTPUT_DIR
    stem = f"initial-notification-{session.approved.run_id}"
    assert [Path(p).name for p in files.downloaded] == [f"{stem}.txt", f"{stem}.json"]


@pytest.mark.parametrize("make", ["missing", "empty", "other files"])
def test_nothing_approved_yet_gives_a_clear_message_and_downloads_nothing(tmp_path, capsys, make):
    folder = tmp_path / "dora_outputs"
    if make != "missing":
        folder.mkdir()
    if make == "other files":
        (folder / "notes.txt").write_text("not a notification", encoding="utf-8")
    files = StandInFiles()
    launcher.download_last_approved(colab_files=files, folder=folder)
    assert files.downloaded == []
    assert capsys.readouterr().out.strip() == launcher.NO_APPROVED_YET
    assert launcher.NO_APPROVED_YET.startswith("No approved notification yet.")


def test_download_outside_colab_refuses_plainly(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "google.colab", None)  # import fails, as outside Colab
    with pytest.raises(RuntimeError, match="Colab only"):
        launcher.download_last_approved(folder=tmp_path)


def test_notebook_has_the_download_cell_right_after_the_launch_cell():
    cells = json.loads(NOTEBOOK.read_text(encoding="utf-8"))["cells"]
    sources = ["".join(cell["source"]) for cell in cells]
    launch_at = next(i for i, s in enumerate(sources) if s.strip().endswith("launch()")
                     and cells[i]["cell_type"] == "code")
    title, code = cells[launch_at + 1], cells[launch_at + 2]
    assert title["cell_type"] == "markdown" and sources[launch_at + 1].startswith(f"## {TITLE}\n")
    assert code["cell_type"] == "code"
    lines = [line for line in sources[launch_at + 2].splitlines() if line.strip() and not line.startswith("#")]
    assert lines == ["from dora_agent.ui.launch import download_last_approved", "download_last_approved()"]
    assert "files.download" in Path(launcher.__file__).read_text(encoding="utf-8")
