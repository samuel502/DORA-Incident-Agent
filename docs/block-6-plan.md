# Block 6 plan: the Gradio interface

Status: plan approved by Sam on 6 November 2026. Updated 8 November 2026 for Colab only and the lessons from Sam's OSINT project.

## What it does

A page where you paste a ticket or pick a sample case. You watch the agent work, answer its questions, and see the result with reasons and articles. For a major incident you review and approve the notification draft. The page only displays. Every decision still comes from the rules engine, and nothing is sent.

## 1. Pasting a ticket or picking a sample

- A text box for the ticket (2000-character cap) and the time it was reported (UTC, default "now").
- A sample picker that reads only `cases/samples.json` (no answers, no real names). Never `cases/scenarios/index.json`.
- "Run" starts the agent. One run at a time per browser session.

## 2. Questions and ticket review

When the agent needs a person, a panel shows:

- Each question with its legal basis. Yes/no questions get choices including "unsure". Number questions get a number box and an "estimate" tick box.
- Each AI suggestion from the ticket, with accept or reject.
- The name of the person answering, typed in. It never comes from the AI.
- "Send answers" continues the run. The agent's limits still apply, including at most 3 rounds of questions.

## 3. The result

- The result and the rules engine's one-line summary.
- One line per gate and threshold, with its article.
- What is still missing and what still waits for a person.
- Every fact, with its source, the estimate flag and who confirmed it.

## 4. The trace

Every logged step in order, as plain text, one line per record, plus the raw JSON on a collapsible tab.

## 5. Notification draft and approval (major only)

- "Prepare draft" shows the draft as plain text, with the banner, the deadline and the weekend note.
- A form for 2.7, 2.9, and optionally 2.8, 2.10, the causes and an edited description.
- "Approve": the approver is the typed name. Empty mandatory fields are named. The approved text shows "NOT SENT", with download buttons for the text and JSON.
- There is no send button.

## 6. Nothing renders as HTML or Markdown

- Anything from the ticket, the AI, tools, facts, the trace or a person goes only into read-only plain-text boxes or `gr.JSON`.
- `gr.Markdown` holds only fixed text written in the code. `gr.HTML` is not used.
- A code test fails if a Markdown component gets anything but fixed text.
- An attack test runs a ticket with `<script>`, `<img onerror=...>`, `**bold**` and `[link](...)` and checks they come out as literal characters.

## 7. Why demo cases show as late

Fixed text next to the deadline, shown when detection was more than 24 hours before classification: the sample replays an old incident, so RTS-R Art. 5(2) applies. The deadline itself is not changed.

## 8. The shared log

Done in step 1 (option A): `AgentRun.log`, read-only. The page passes it to `prepare_draft` and `approve`.

## 9. Hard total time limit per run (new, 8 November 2026)

- New setting in `config.toml` `[agent]`: `max_run_seconds` = 600 (10 minutes). Value and the `loop.py` change approved by Sam on 8 November 2026. The slowest measured live run took 7 min 13 s (B03, 6 November 2026), mostly pacing waits for the Groq free tier.
- The clock counts the agent's working time across all rounds. Time spent waiting for a person to answer does not count.
- The loop checks the clock before every LLM call and every tool call. Each LLM call, and its waits for rate limits, is cut short to the time left, so the limit is hard, not "finish the current call first".
- When time runs out, the run stops with stop reason `time_limit`. The rules engine gives its result on the facts so far, and the missing facts are listed, as with the other limits.
- This changes `src/dora_agent/agent/loop.py` and the LLM call path. Tests: a fake clock, a run that hits the limit, and a slow fake LLM call cut short.
- Built in step 3: the provider interface's `chat()` takes an optional `time_left`. The Groq provider skips any pacing or retry wait that would pass it, cuts each request's timeout to it, and switches off the Groq client's own hidden retry when the time left can't hold it (that retry can wait up to 60 seconds by itself). Each run's working time is shown in the result and recorded in the case reports, for block 8.

## 10. Running it: Colab only, no public link

- `notebooks/colab.ipynb` is the only way to run the tool. No local launch, no `__main__.py`, no login code.
- Cells: (1) clone the repo and install the pinned requirements, (2) read the key from Colab Secrets into memory, (3) start the page, (4) optional live tests.
- All four cells exist (step 5). The setup cell prints how long it took, and asks for a session restart if Colab had already loaded an older copy of a pinned package.
- The first markdown cell has the troubleshooting section (cookies, fresh runtime, re-running only the launch cell, the key secret with notebook access, VPN errors).

The launch function in `src/dora_agent/ui/launch.py`:

- calls `launch()` with `share=False`, `server_name="0.0.0.0"`, `inline=False`, `prevent_thread_lock=True`, `ssr_mode=False`
- shows the page with `google.colab.output.serve_kernel_port_as_iframe`, Colab's own forwarding, so only the person running the notebook sees it
- closes the old server first if the cell is run again
- returns nothing, so Colab does not print the Blocks object
- turns off the "use via API" page, hides error details from the page (they go to the log), and runs one request at a time
- If the key is missing, the page says so plainly and shows no part of any key.

`server_name="0.0.0.0"` is needed so Colab's forwarding can reach the page inside the Colab machine. That machine has no public address, and there is no local launch, so this does not expose the page.

Tests (no Colab needed, with a stand-in for Gradio and `google.colab`): the launch settings are exactly the ones above, `share` is never on, a second launch closes the first, the function returns `None`, and the key never appears in the page or the log.

## 11. Requirements

- Gradio is added to `requirements.txt` at one exact version, together with every package it pulls in, each at an exact version.
- Done in step 5: Gradio 6.30.0 fits all earlier pins; nothing had to move. 60 exact pins, resolved for Linux on Python 3.12 and 3.13, each with a ready-built wheel. Two platform markers: audioop-lts (Python 3.13+) and colorama (Windows only).
- Fix after step 5: tzdata was pinned for Windows only, but python-dateutil 4.0.0 needs it on Linux too, so Colab would have installed an unpinned tzdata. The marker is gone; tzdata==2026.6 now installs everywhere. Checked by reading each pinned package's Linux dependencies for Python 3.12 and 3.13: no unpinned package left.

## Files

| File | What it does |
|---|---|
| `src/dora_agent/ui/views.py` | Turns run results, the trace and drafts into plain text and tables. No Gradio, so it's easy to test |
| `src/dora_agent/ui/controller.py` | What each button does, in plain Python. No Gradio, so it's easy to test (added in step 4) |
| `src/dora_agent/ui/app.py` | The Gradio page: layout and wiring only |
| `src/dora_agent/ui/launch.py` | The Colab launch with the settings in section 10 |
| `src/dora_agent/agent/loop.py`, LLM call path, `config.toml` | The total time limit (section 9) |
| `cases/samples.json` | Sample tickets only, no answers (done in step 1) |
| `notebooks/colab.ipynb` | Colab start, troubleshooting, live tests |
| `requirements.txt` | Gradio and its packages, exact versions |
| `tests/ui/` | Views, escaping, attack tests, launch settings, sample file |

## Steps (stop after each for Sam's test and approval)

1. Done: `AgentRun.log` and `samples.json`.
2. `views.py` with tests.
3. The total time limit per run, with tests.
4. The Gradio page.
5. The launch function and the notebook's launch cell. Sam runs it in Colab.
6. Sam tests it by hand, then the security review.

## Decided for step 4

Replayed samples are measured at "now" (the time of the run), so every sample incident is measured in full, as in the hand-checked case tests. Pasted tickets are measured at "now" too. Decided by Sam on 8 November 2026.
