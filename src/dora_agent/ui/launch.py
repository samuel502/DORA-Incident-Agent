"""Start the page in Google Colab (block 6 step 5). Colab only: there is no local launch.

The same method as Sam's OSINT project (build contract, lessons built into the interface):
- launch() with share=False (no public link), server_name="0.0.0.0", inline=False,
  prevent_thread_lock=True and ssr_mode=False,
- the page is shown inside the notebook with google.colab.output.serve_kernel_port_as_iframe,
  Colab's own forwarding, so only the person running the notebook can open it,
- running the launch cell again closes the old server first,
- launch() returns nothing, so Colab does not print the Blocks object under the cell.

server_name="0.0.0.0" lets Colab's forwarding reach the page inside the Colab machine. That machine has
no public address, and nothing here creates a public link.

Also: no API page in the footer, error details hidden from the page (they go to the notebook output),
and downloads served only from logs/runs/ (the approved notifications).
"""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any

from dora_agent.config import llm_settings
from dora_agent.ui import controller

PORT = 7860
FRAME_HEIGHT = 1400  # pixels of notebook space for the page

NOT_COLAB = ("This tool runs in Google Colab only. Open notebooks/colab.ipynb in Colab and run its cells "
             "from the top.")

# Exactly what launch() passes to Gradio. A test checks these, so they can't drift.
LAUNCH_SETTINGS: dict[str, Any] = {
    "share": False,
    "server_name": "0.0.0.0",
    "server_port": PORT,
    "inline": False,
    "prevent_thread_lock": True,
    "ssr_mode": False,
    "show_error": False,
    "quiet": True,
    "footer_links": ["settings"],  # no link to an API page
}

_running = None  # the page started by the last launch() in this runtime


def _colab_output():
    try:
        from google.colab import output  # only exists inside Colab
    except ImportError:
        raise RuntimeError(NOT_COLAB) from None
    return output


def launch(*, build: Callable[[], Any] | None = None, colab_output: Any = None) -> None:
    """Start the page and show it in the notebook. Returns nothing.

    build, colab_output: only for tests, to pass stand-ins for the page and for google.colab.output.
    """
    global _running
    output = colab_output or _colab_output()  # refuse outside Colab before anything starts
    if _running is not None:
        _running.close(verbose=False)  # re-running the cell: the old server goes first
        _running = None
    if build is None:
        from dora_agent.ui.app import build_app

        build = build_app
    demo = build()
    controller.RUN_LOG_DIR.mkdir(parents=True, exist_ok=True)
    demo.launch(**LAUNCH_SETTINGS, allowed_paths=[str(controller.RUN_LOG_DIR)])
    _running = demo
    key_loaded = bool(os.environ.get(llm_settings().api_key_env, "").strip())
    print("The page is running below. Re-run this cell to restart it."
          + ("" if key_loaded else " No Groq key is loaded yet: run the key cell first, or Run will say so."))
    output.serve_kernel_port_as_iframe(PORT, height=FRAME_HEIGHT)
