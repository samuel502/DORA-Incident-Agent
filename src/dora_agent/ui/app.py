"""The Gradio page (block 6 step 4). Only layout and wiring: what the buttons do is in controller.py.

Safety rules (block 6 plan, section 6; security framework, "Unsafe output"):
- Anything from the ticket, the AI, tools, facts, the trace or a person goes only into read-only plain-text
  boxes (gr.Textbox), the facts table with plain-text cells (datatype "str") or gr.Code. These show
  text as text: `<script>` stays the characters `<script>`.
- gr.Markdown holds only the fixed texts in TEXTS below, and no button ever writes to it. gr.HTML is
  not used. Labels are fixed texts from this file or from the fixed questions in agent/questions.py.
  The one exception: the service question's label also lists the matching services' IDs and names, which
  come from the (synthetic) service list, never from the ticket or the AI. Its choices are those IDs.
- Every button is hidden from Gradio's API page and its client libraries (api_visibility="private"),
  the REST routes that skip the queue are closed (api_open=False), and one request runs at a time.
- Tests check all of this (tests/ui/test_app.py).

Starting the page in Colab (share=False, Colab's own forwarding) comes in step 5 (launch.py).
"""

from __future__ import annotations

from collections.abc import Callable

import gradio as gr

from dora_agent.agent.questions import QUESTIONS, SERVICE_QUESTION
from dora_agent.config import agent_limits, notification_settings
from dora_agent.llm import get_provider
from dora_agent.llm.provider import LlmProvider
from dora_agent.notification.fields import DISCOVERY_CHOICES
from dora_agent.ui import controller as c
from dora_agent.ui import views
from dora_agent.ui.views import FACT_HEADERS

TITLE = "Rheinbank DORA incident check"

# The only texts gr.Markdown may show. Fixed, written here, never filled from a run.
TEXTS = {
    "intro": (
        "# Rheinbank DORA incident check\n\n"
        "**Synthetic data only.** Rheinbank is a made-up bank. Paste an incident ticket or pick a sample. "
        "The AI collects facts from the simulated bank systems; fixed rules from DORA decide whether the "
        "incident is major. The AI never decides. Nothing is ever sent to anyone. Not legal advice."
    ),
    "time": (
        "Every run is measured at the time you press Run. A run stops after at most 10 minutes of the agent's "
        "own work; time you spend answering does not count."
    ),
    "human": (
        "## Your answers\n\n"
        "The agent needs a person. Answer what you can: an empty answer stays unknown and is never guessed. "
        "Decide every suggestion the AI read from the ticket: confirm it, correct it, or reject it. "
        "Nothing the AI suggests is used until you confirm it."
    ),
    "result": "## Result",
    "trace": "Every logged step of this run, in order. The raw JSON is below.",
    "draft": (
        "## Draft initial notification\n\n"
        "For a major incident only. Review the draft, fill in the fields only you know, and approve. "
        "**Nothing is sent: there is no send button.** A sample replays an old incident, so its "
        "classification comes late and its deadline has usually passed (RTS-R Art. 5(2)); "
        "the note under the draft explains this."
    ),
}


def _hidden_group():
    return gr.Group(visible=False)


def build_app(provider_factory: Callable[[], LlmProvider] = get_provider) -> gr.Blocks:
    """The page. provider_factory gives the AI for each run (tests pass a stand-in)."""
    max_ticket = agent_limits().max_ticket_chars
    notes = notification_settings()

    with gr.Blocks(title=TITLE, analytics_enabled=False) as demo:
        state = gr.State(None)
        gr.Markdown(TEXTS["intro"])

        # ---------- 1. ticket or sample ----------
        sample = gr.Dropdown(choices=c.sample_choices(), value=None, label="Pick a sample case (synthetic)")
        ticket = gr.Textbox(label=f"Incident ticket (at most {max_ticket} characters)", lines=6,
                            max_length=max_ticket)
        reported = gr.Textbox(label="Reported at (UTC), for example 2026-11-08T09:30Z", max_length=40)
        gr.Markdown(TEXTS["time"])
        run_button = gr.Button("Run", variant="primary")
        status = gr.Textbox(label="Status", interactive=False, lines=2)
        headline = gr.Textbox(label="Result from the rules engine", interactive=False)

        # ---------- 2. questions and ticket review ----------
        with _hidden_group() as human_panel:
            gr.Markdown(TEXTS["human"])
            name = gr.Textbox(label="Your name (recorded with your answers)", max_length=80)
            # Which service to classify, when several match and their records do not tell them apart.
            # The choices are filled in per run: the service IDs find_service returned.
            with _hidden_group() as service_group:
                service_answer = gr.Radio(choices=[], value=None, label="Which service is the affected service?")
            question_boxes = {}
            for fact_name in c.QUESTION_NAMES:
                question = QUESTIONS[fact_name]
                label = f"{question.text} (Basis: {question.basis})"
                with _hidden_group() as group:
                    if question.meaning:
                        answer = gr.Radio(choices=["yes", "no", "unsure"], value=None, label=label)
                    else:
                        answer = gr.Textbox(label=label, max_length=40)
                    estimate = gr.Checkbox(label="This is an estimate", value=False,
                                           visible=question.allows_estimate)
                question_boxes[fact_name] = (group, answer, estimate)
            review_boxes = {}
            for fact_name in c.REVIEW_NAMES:
                with _hidden_group() as group:
                    text = gr.Textbox(label="Suggestion read from the ticket by the AI", interactive=False)
                    choice = gr.Radio(choices=["confirm", "correct", "reject"], value=None, label="Your decision")
                    value = gr.Textbox(label="Corrected value (only if you chose correct)", max_length=200)
                    estimate = gr.Checkbox(label="This is an estimate", value=False)
                review_boxes[fact_name] = (group, text, choice, value, estimate)
            send_button = gr.Button("Send answers", variant="primary")

        # ---------- 3. result and 4. trace ----------
        gr.Markdown(TEXTS["result"])
        result = gr.Textbox(label="Reasons, with articles", interactive=False, lines=16)
        facts = gr.Dataframe(headers=list(FACT_HEADERS), datatype="str", interactive=False,
                             label="Facts, with where each came from", wrap=True)
        with gr.Accordion("Trace", open=False):
            gr.Markdown(TEXTS["trace"])
            trace = gr.Textbox(label="Trace, one line per logged step", interactive=False, lines=20)
            with gr.Accordion("Raw JSON", open=False):
                trace_json = gr.Code(label="Decision log records", language="json", interactive=False)

        # ---------- 5. notification draft and approval ----------
        with _hidden_group() as draft_panel:
            gr.Markdown(TEXTS["draft"])
            causes = gr.Textbox(label="Possible causes, if known (goes into the description, field 2.4)",
                                max_length=notes.max_causes_chars)
            draft_button = gr.Button("Prepare draft")
            draft = gr.Textbox(label="Draft initial notification", interactive=False, lines=20)
            with _hidden_group() as approve_panel:
                discovery = gr.Dropdown(choices=list(DISCOVERY_CHOICES), value=None,
                                        label="2.7 How the incident was discovered")
                plan = gr.Radio(choices=["yes", "no"], value=None,
                                label="2.9 Was the business continuity plan activated?")
                third_party = gr.Textbox(label="2.8 Third-party provider or financial entity at the origin, "
                                               "with its identification code (optional)", max_length=300)
                other = gr.Textbox(label="2.10 Other relevant information (optional)", max_length=1000)
                description = gr.Textbox(label="2.4 Your own description instead of the draft's (optional)",
                                         max_length=notes.max_description_chars, lines=4)
                approver = gr.Textbox(label="Your name (recorded as the approver)", max_length=80)
                approve_button = gr.Button("Approve (nothing is sent)", variant="primary")
            approved = gr.Textbox(label="Approved initial notification: NOT SENT", interactive=False, lines=20,
                                  buttons=["copy"])
            download_text = gr.DownloadButton("Download as text", visible=False)
            download_json = gr.DownloadButton("Download as JSON", visible=False)

        outputs = [state, status, headline, human_panel, service_group, service_answer]
        for group, answer, estimate in question_boxes.values():
            outputs += [group, answer, estimate]
        for group, text, choice, value, estimate in review_boxes.values():
            outputs += [group, text, choice, value, estimate]
        outputs += [result, facts, trace, trace_json, draft_panel, draft, approve_panel, approved,
                    download_text, download_json]

        def render(session: c.Session, shown: c.Screen) -> list:
            reset = shown.reset_inputs
            asked = {q.fact_name for q in shown.questions}
            values: list = [session, shown.status, shown.headline,
                            gr.update(visible=bool(shown.questions or shown.review))]
            service_question = next((q for q in shown.questions if q.fact_name == SERVICE_QUESTION), None)
            if service_question is not None:
                values += [gr.update(visible=True),
                           gr.update(choices=list(service_question.choices or ()), value=None,
                                     label=views.question_label(service_question))]
            else:
                values += [gr.update(visible=False), gr.update(value=None) if reset else gr.update()]
            for fact_name, (_, answer, _) in question_boxes.items():
                values += [gr.update(visible=fact_name in asked),
                           gr.update(value=None if isinstance(answer, gr.Radio) else "") if reset else gr.update(),
                           gr.update(value=False) if reset else gr.update()]
            for fact_name in review_boxes:
                label = shown.review_labels.get(fact_name)
                values += [gr.update(visible=label is not None), label or "",
                           gr.update(value=None) if reset else gr.update(),
                           gr.update(value="") if reset else gr.update(),
                           gr.update(value=False) if reset else gr.update()]
            files = shown.downloads
            values += [shown.result, shown.facts, shown.trace, shown.trace_json,
                       gr.update(visible=shown.can_draft or bool(shown.draft)), shown.draft,
                       gr.update(visible=shown.can_approve), shown.approved,
                       gr.update(value=files[0], visible=True) if files else gr.update(value=None, visible=False),
                       gr.update(value=files[1], visible=True) if files else gr.update(value=None, visible=False)]
            return values

        def session_of(value) -> c.Session:
            return value if isinstance(value, c.Session) else c.Session()

        def on_run(state_value, ticket_text, reported_text, sample_id):
            session = c.Session()  # every run starts a fresh session: nothing carries over
            return render(session, c.start(session, ticket_text, reported_text, sample_id, provider_factory))

        answer_inputs = [component for _, answer, estimate in question_boxes.values() for component in (answer, estimate)]
        review_inputs = [component for _, _, choice, value, estimate in review_boxes.values()
                         for component in (choice, value, estimate)]

        def on_send(state_value, name_text, service_value, *values):
            session = session_of(state_value)
            given = dict(zip(c.QUESTION_NAMES, zip(values[0:len(answer_inputs):2], values[1:len(answer_inputs):2])))
            given[SERVICE_QUESTION] = (service_value, False)
            rest = values[len(answer_inputs):]
            review = dict(zip(c.REVIEW_NAMES, zip(rest[0::3], rest[1::3], rest[2::3])))
            return render(session, c.send_answers(session, name_text, given, review))

        def on_draft(state_value, causes_text):
            session = session_of(state_value)
            return render(session, c.make_draft(session, causes_text))

        def on_approve(state_value, approver_text, discovery_value, plan_value, third_text, other_text, own_text):
            session = session_of(state_value)
            return render(session, c.approve_draft(session, approver_text, discovery_value, plan_value,
                                                   third_text, other_text, own_text))

        private = {"api_visibility": "private"}
        sample.change(c.load_sample, [sample], [ticket, reported], **private)
        run_button.click(on_run, [state, ticket, reported, sample], outputs, **private)
        send_button.click(on_send, [state, name, service_answer, *answer_inputs, *review_inputs], outputs,
                          **private)
        draft_button.click(on_draft, [state, causes], outputs, **private)
        approve_button.click(on_approve, [state, approver, discovery, plan, third_party, other, description],
                             outputs, **private)

    demo.queue(default_concurrency_limit=1, api_open=False)
    return demo
