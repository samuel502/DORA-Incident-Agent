"""ui/launch.py: starting the page in Colab (block 6 step 5). No Colab and no server needed.

Proves, with stand-ins for the page and for google.colab.output:
- the launch settings are exactly Sam's OSINT ones: share=False, server_name 0.0.0.0, inline=False,
  prevent_thread_lock=True, ssr_mode=False, and error details hidden,
- the page is shown with serve_kernel_port_as_iframe on the same port,
- running the launch cell again closes the old server first,
- launch() returns nothing, so Colab prints no Blocks object,
- outside Colab it refuses before starting anything (no local launch),
- the key never shows in what launch() prints,
- the notebook's launch cell calls launch() as its last line.
"""

import json
from pathlib import Path

import pytest

from dora_agent.ui import controller, launch as launcher

NOTEBOOK = Path(__file__).resolve().parents[2] / "notebooks" / "colab.ipynb"


class StandInPage:
    def __init__(self, events):
        self.events = events
        self.launched_with = None

    def launch(self, **settings):
        self.launched_with = settings
        self.events.append(("launch", self))

    def close(self, verbose=True):
        self.events.append(("close", self))


class StandInOutput:
    def __init__(self, events):
        self.events = events

    def serve_kernel_port_as_iframe(self, port, **options):
        self.events.append(("iframe", port, options))


@pytest.fixture(autouse=True)
def fresh(monkeypatch, tmp_path):
    monkeypatch.setattr(launcher, "_running", None)
    monkeypatch.setattr(controller, "RUN_LOG_DIR", tmp_path / "runs")


def start(events):
    pages = []

    def build():
        pages.append(StandInPage(events))
        return pages[-1]

    returned = launcher.launch(build=build, colab_output=StandInOutput(events))
    return returned, pages[-1]


def test_launch_settings_are_the_osint_ones():
    events = []
    _, page = start(events)
    settings = page.launched_with
    assert settings["share"] is False
    assert settings["server_name"] == "0.0.0.0"
    assert settings["inline"] is False
    assert settings["prevent_thread_lock"] is True
    assert settings["ssr_mode"] is False
    assert settings["show_error"] is False
    assert "api" not in settings["footer_links"]
    assert settings["server_port"] == launcher.PORT
    assert settings["allowed_paths"] == [str(controller.RUN_LOG_DIR)]
    assert not {"auth", "share_server_address", "mcp_server"} & set(settings)


def test_page_is_shown_with_colabs_own_forwarding_after_the_server_starts():
    events = []
    start(events)
    assert [e[0] for e in events] == ["launch", "iframe"]
    assert events[1][1] == launcher.PORT


def test_launch_returns_nothing():
    returned, _ = start([])
    assert returned is None


def test_running_the_cell_again_closes_the_old_server_first():
    events = []
    _, first = start(events)
    _, second = start(events)
    assert [(e[0], e[1] if e[0] != "iframe" else None) for e in events] == [
        ("launch", first), ("iframe", None), ("close", first), ("launch", second), ("iframe", None)]


def test_outside_colab_nothing_starts(monkeypatch):
    built = []
    with pytest.raises(RuntimeError, match="Google Colab only"):
        launcher.launch(build=lambda: built.append(1))  # google.colab isn't installed here
    assert built == []


def test_the_key_never_shows_in_what_launch_prints(monkeypatch, capsys):
    key = "TEST-ONLY-placeholder-not-a-key-1234567890"
    monkeypatch.setenv("GROQ_API_KEY", key)
    start([])
    printed = capsys.readouterr().out
    assert key not in printed and "running below" in printed
    monkeypatch.delenv("GROQ_API_KEY")
    start([])
    assert "No Groq key is loaded yet" in capsys.readouterr().out


def test_the_real_page_builds_with_these_settings_without_starting():
    from dora_agent.ui.app import build_app

    demo = build_app()
    assert demo.api_open is False  # the real page is what launch() starts


def test_notebook_launch_cell_calls_launch_last():
    cells = json.loads(NOTEBOOK.read_text(encoding="utf-8"))["cells"]
    sources = ["".join(cell["source"]) for cell in cells if cell["cell_type"] == "code"]
    (cell,) = [s for s in sources if "launch()" in s]
    lines = [line for line in cell.strip().splitlines() if line.strip() and not line.lstrip().startswith("#")]
    assert lines[-1] == "launch()"  # last line returns None: Colab prints nothing for it
    assert "share=True" not in "".join(sources)
