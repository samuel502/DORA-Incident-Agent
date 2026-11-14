"""ui/app.py: the Gradio page's safety rules (block 6 step 4). The page is built, never launched.

Proves:
- no gr.HTML; every gr.Markdown shows one of the fixed TEXTS, both in the code and on the built page,
- no button ever writes to a Markdown component,
- the facts table shows plain-text cells only (no Markdown, no HTML),
- every button is hidden from the API and its clients, the REST routes are closed, one request at a time,
- pressing Run on the real page, with a hostile ticket, gives back the same characters as plain text,
- the page gives each box a value in the right order (the wiring matches the outputs).
"""

import ast
from pathlib import Path

import gradio as gr

from dora_agent.llm.fake_provider import FakeProvider, say
from dora_agent.ui import app as page
from dora_agent.ui import controller as c

APP_PY = Path(page.__file__)
HOSTILE = "<script>alert(1)</script> <img src=x onerror=alert(1)> **bold** [link](http://evil.example)"


def built(provider_factory=lambda: FakeProvider([say("done")])):
    return page.build_app(provider_factory)


def components(demo, kind):
    return [b for b in demo.blocks.values() if isinstance(b, kind)]


def event(demo, button_label):
    button = next(b for b in components(demo, gr.Button) if b.value == button_label)
    return next(f for f in demo.fns.values() if any(t[0] == button._id for t in f.targets))


# ---------- what may render as markup ----------


def test_no_html_component_anywhere():
    assert components(built(), gr.HTML) == []
    used = {n.attr for n in ast.walk(ast.parse(APP_PY.read_text(encoding="utf-8"))) if isinstance(n, ast.Attribute)}
    assert not used & {"HTML", "Chatbot", "HighlightedText"}  # components that render markup


def test_markdown_shows_only_the_fixed_texts():
    demo = built()
    shown = [m.value for m in components(demo, gr.Markdown)]
    assert shown and set(shown) <= set(page.TEXTS.values())


def test_markdown_in_the_code_takes_only_a_fixed_text():
    tree = ast.parse(APP_PY.read_text(encoding="utf-8"))
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
             and n.func.attr == "Markdown"]
    assert calls
    for call in calls:
        (argument,) = call.args
        assert not call.keywords
        assert (isinstance(argument, ast.Subscript) and isinstance(argument.value, ast.Name)
                and argument.value.id == "TEXTS" and isinstance(argument.slice, ast.Constant)), ast.dump(call)


def test_no_button_writes_to_markdown_or_to_a_label():
    demo = built()
    markdown_ids = {m._id for m in components(demo, gr.Markdown)}
    for fn in demo.fns.values():
        assert not {o._id for o in fn.outputs} & markdown_ids


def test_facts_table_has_plain_text_cells_and_cannot_be_edited():
    (table,) = components(built(), gr.Dataframe)
    assert table.datatype == "str" and table.interactive is False


def test_boxes_that_show_run_output_are_read_only():
    demo = built()
    by_label = {b.label: b for b in components(demo, gr.Textbox)}
    for label in ("Status", "Result from the rules engine", "Reasons, with articles",
                  "Trace, one line per logged step", "Draft initial notification",
                  "Approved initial notification: NOT SENT", "Suggestion read from the ticket by the AI"):
        assert by_label[label].interactive is False, label
    (raw,) = components(demo, gr.Code)
    assert raw.interactive is False


# ---------- API and queue ----------


def test_every_event_is_private_and_the_rest_routes_are_closed():
    demo = built()
    assert len(demo.fns) == 5
    assert {f.api_visibility for f in demo.fns.values()} == {"private"}
    assert demo.api_open is False
    assert demo._queue.default_concurrency_limit == 1


# ---------- pressing the buttons on the built page ----------


def test_run_on_the_page_with_a_hostile_ticket_gives_literal_text(tmp_path, monkeypatch):
    monkeypatch.setattr(c, "RUN_LOG_DIR", tmp_path)
    demo = built(lambda: FakeProvider([say(f"Done. {HOSTILE}")]))
    run = event(demo, "Run")
    ticket = f"Online banking down.\n{HOSTILE}"
    values = run.fn(None, ticket, "2026-11-08T09:30Z", None)
    assert len(values) == len(run.outputs)
    by_output = {getattr(o, "label", None): v for o, v in zip(run.outputs, values) if getattr(o, "label", None)}
    assert isinstance(values[0], c.Session)
    assert by_output["Result from the rules engine"].startswith("Result from the rules engine: UNDETERMINED")
    trace = by_output["Trace, one line per logged step"]
    assert HOSTILE in trace and "&lt;" not in trace
    for component, value in zip(run.outputs, values):
        if isinstance(component, gr.Textbox) and isinstance(value, str):
            assert "&lt;" not in value and "&amp;" not in value  # nothing escaped by our code


def test_sample_picker_fills_ticket_and_time():
    demo = built()
    (pick,) = [f for f in demo.fns.values() if len(f.outputs) == 2]
    assert pick.fn("C01") == c.load_sample("C01")


def test_every_button_returns_one_value_per_box(tmp_path, monkeypatch):
    monkeypatch.setattr(c, "RUN_LOG_DIR", tmp_path)
    demo = built()
    session = event(demo, "Run").fn(None, "Online banking down.", "2026-11-08T09:30Z", None)[0]
    for label, args in (("Send answers", (session, "Sam") + (None,) * (len(event(demo, "Send answers").inputs) - 2)),
                        ("Prepare draft", (session, "")),
                        ("Approve (nothing is sent)", (session, "Sam", None, None, "", "", ""))):
        fn = event(demo, label)
        values = fn.fn(*args)
        assert len(values) == len(fn.outputs), label
        assert values[1].startswith("Not done:"), (label, values[1])  # nothing waiting, nothing to draft


def test_gradio_accepts_every_value_the_buttons_give(tmp_path, monkeypatch):
    """Gradio's own postprocess step, which runs before values reach the browser (no server needed)."""
    monkeypatch.setattr(c, "RUN_LOG_DIR", tmp_path)
    demo = built()
    for ticket in ("", "Online banking down."):  # an error screen and a finished run
        run = event(demo, "Run")
        for component, value in zip(run.outputs, run.fn(None, ticket, "2026-11-08T09:30Z", None)):
            if isinstance(value, dict) or isinstance(component, gr.State):
                continue  # gr.update(...) and the session are handled by Gradio separately
            component.postprocess(value)


# ---------- the service question (C01 live test, approved by Sam on 13 November 2026) ----------


def test_service_question_shows_its_choices_and_the_answer_goes_through(tmp_path, monkeypatch):
    from dora_agent.llm.fake_provider import call

    def lookups(*items):
        return call("lookups", call_id="L", calls=[{"tool": n, "args": a} for n, a in items])

    monkeypatch.setattr(c, "RUN_LOG_DIR", tmp_path)
    demo = built(lambda: FakeProvider([
        lookups(("find_service", {"text": "online or mobile banking"})),
        call("ask_human", facts=["incident_service"]),
        lookups(("get_outage_timeline", {"service_id": "SVC-OLB"}), ("get_client_impact", {"service_id": "SVC-OLB"}),
                ("get_daily_averages", {"service_id": "SVC-OLB"})),
    ]))
    run = event(demo, "Run")
    ticket = "Customers can't log into online or mobile banking."
    values = run.fn(None, ticket, "2025-02-15T21:00Z", None)
    radio = next(o for o in run.outputs if isinstance(o, gr.Radio) and o.label == "Which service is the affected service?")
    shown = values[run.outputs.index(radio)]
    group = values[run.outputs.index(radio) - 1]
    assert group["visible"] is True
    assert shown["choices"] == ["SVC-MOB", "SVC-OLB"] and "SVC-OLB = Online banking" in shown["label"]

    send = event(demo, "Send answers")
    assert send.inputs[2] is radio  # the answer box is read when the person sends
    args = [values[0], "Sam", "SVC-OLB"] + [None] * (len(send.inputs) - 3)
    after = send.fn(*args)
    assert after[2].startswith("Result from the rules engine: MAJOR")
