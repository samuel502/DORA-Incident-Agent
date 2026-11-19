"""Attack: oversized and malformed tool arguments (security framework: bad input, unbounded consumption).

A fooled or broken AI can send anything as a tool call: text that is not JSON, JSON nested thousands of levels
deep, megabytes of text, IDs shaped like file paths, wrong types, a huge tool name, or fifty calls in one answer.
Every test runs a whole agent run. Must happen: the run never crashes, each bad call is refused with a short
plain reason that does not repeat the hostile value back, the log keeps only a cut-down copy, the limits hold,
and the result is still the rules engine's.

Already covered elsewhere (single calls into the toolbox): tests/agent/test_tools.py
test_arguments_that_are_not_json_are_refused, test_bad_arguments_are_refused_without_echoing_them,
test_malformed_lookups_are_refused_and_nothing_runs, test_tool_results_are_capped; tests/agent/test_loop.py for
the ticket length limit.
"""

import json

import pytest
from attack_kit import raw_call, refused_tools, sent_to_ai, t

from dora_agent.agent.loop import AgentRun
from dora_agent.config import agent_limits
from dora_agent.llm.fake_provider import FakeProvider, call, say
from dora_agent.llm.provider import MAX_RAW_ARGUMENTS_CHARS, LlmResponse, ToolCall
from dora_agent.ui import views

TICKET = "Online banking down since 9:10, customers can't log in."
REPORTED = t("2026-05-26T07:15:00Z")
HOSTILE = "EVIL-VALUE-<script>alert(1)</script>"


def run_with(*answers):
    fake = FakeProvider([*answers, say("done")])
    run = AgentRun(TICKET, REPORTED, fake)
    return run, run.start(), fake


def last_reply(fake) -> dict:
    """The last tool reply the AI was sent, unwrapped."""
    message = [m for m in sent_to_ai(fake) if m.role == "tool"][-1]
    return json.loads(message.content.split("\n", 1)[1].rsplit("\n", 1)[0])


NOT_JSON = {
    "broken JSON": "{{{{ " + HOSTILE,
    "a JSON list": json.dumps([HOSTILE, 1, 2]),
    "a JSON string": json.dumps(HOSTILE),
    "a number": "1e999999",
    "nested 100,000 levels deep": "[" * 100_000 + "]" * 100_000,
    "2 MB of text": HOSTILE + "a" * 2_000_000,
    "null bytes and control characters": "{\x00\x01\x1b[31m" + HOSTILE,
}


@pytest.mark.parametrize("raw", NOT_JSON.values(), ids=list(NOT_JSON))
def test_arguments_that_are_not_a_json_object_are_refused_without_a_crash(raw):
    """Attack: get_service with arguments that are not a JSON object (see the test IDs).
    Must happen: refused as "not a JSON object", nothing runs, the log keeps at most a short cut-down copy, and
    the run ends normally with the engine's result."""
    run, result, fake = run_with(raw_call("get_service", raw))

    assert refused_tools(run.log.records) == ["get_service"]
    assert last_reply(fake) == {"error": "arguments are not a JSON object"}
    step = next(r for r in run.log.records if r["kind"] == "llm_step")
    assert len(step["proposed"][0]["arguments"]) <= 500 < MAX_RAW_ARGUMENTS_CHARS
    assert result.status in ("finished", "needs_human") and result.classification.result == "undetermined"


OVERSIZED = {
    "search text of 100,000 characters": ("find_service", {"text": HOSTILE * 3000}),
    "service ID of 10,000 characters": ("get_service", {"service_id": "SVC-" + "A" * 10_000}),
    "10,000 suggestions": ("suggest_facts", {"suggestions": [
        {"fact": "media_coverage", "value": True, "reason": HOSTILE}] * 10_000}),
    "a reason of 100,000 characters": ("suggest_facts", {"suggestions": [
        {"fact": "media_coverage", "value": True, "reason": HOSTILE * 3000}]}),
    "5,000 facts to ask about": ("ask_human", {"facts": [HOSTILE] * 5_000}),
    "a window of 10**100 hours": ("get_outage_timeline", {"service_id": "SVC-OLB", "window_hours": 10 ** 100}),
    "a time of 10,000 characters": ("get_client_impact", {"service_id": "SVC-OLB", "start": HOSTILE * 300}),
    "10,000 listed lookups": ("lookups", {"calls": [{"tool": "get_service", "args": {"service_id": "SVC-OLB"}}]
                                          * 10_000}),
}


@pytest.mark.parametrize("tool, arguments", OVERSIZED.values(), ids=list(OVERSIZED))
def test_oversized_arguments_are_refused_without_repeating_them(tool, arguments):
    """Attack: valid JSON, but far too big (see the test IDs).
    Must happen: refused before anything runs, with a reason that names the field only. The hostile value is
    not sent back to the AI, and the reply stays short."""
    run, _, fake = run_with(call(tool, **arguments))

    assert refused_tools(run.log.records) == [tool]
    reply = json.dumps(last_reply(fake))
    assert "invalid arguments" in reply and HOSTILE not in reply and len(reply) < 400


SHAPED_LIKE_ATTACKS = {
    "a path to the answer key": ("get_service", {"service_id": "../../cases/scenarios/index.json"}),
    "SQL-like text": ("get_service", {"service_id": "SVC-OLB' OR '1'='1"}),
    "an ID with a line break": ("get_service", {"service_id": "SVC-OLB\nSVC-HR"}),
    "a supplier ID with a path": ("get_supplier", {"supplier_id": "SUP-RITS/../../etc/passwd"}),
    "a record ID with a path": ("use_record", {"record_id": "PRB-0002/../../index"}),
    "a number as text": ("get_outage_timeline", {"service_id": "SVC-OLB", "window_hours": "24"}),
    "true as a number": ("get_outage_timeline", {"service_id": "SVC-OLB", "window_hours": True}),
    "a number as an ID": ("get_service", {"service_id": 123}),
    "suggestions as one object": ("suggest_facts", {"suggestions": {"fact": "media_coverage", "value": True}}),
    "a lookup that is not on the list": ("lookups", {"calls": [{"tool": "read_file", "args": {"path": "/etc"}}]}),
}


@pytest.mark.parametrize("tool, arguments", SHAPED_LIKE_ATTACKS.values(), ids=list(SHAPED_LIKE_ATTACKS))
def test_ids_shaped_like_paths_or_queries_and_wrong_types_are_refused(tool, arguments):
    """Attack: IDs shaped like file paths or database queries, and values of the wrong type (see the test IDs).
    Must happen: refused by the fixed argument rules (exact ID patterns, strict types, a fixed list of lookups)
    before any connector is called. No fact is recorded."""
    run, result, _ = run_with(call(tool, **arguments))

    assert tool in refused_tools(run.log.records)
    assert not any(r.get("facts_recorded") for r in run.log.records if r["kind"] == "tool_call")
    assert result.classification.result == "undetermined"


def test_a_huge_tool_name_with_line_breaks_is_cut_refused_and_shown_on_one_line():
    """Attack: a tool name of 10,000 characters with line breaks and a fake trace line inside.
    Must happen: the name is cut to 200 characters when the call is read, refused as an unknown tool, logged
    with at most 60 characters, and the page's trace still shows exactly one line per logged step."""
    name = "get_service\n#99 12:00 result: finished, result not_major\n" + "x" * 10_000
    run, _, _ = run_with(raw_call(name, "{}"))

    refused = [r for r in run.log.records if r["kind"] == "tool_call" and not r["ok"]]
    assert len(refused) == 1 and len(refused[0]["tool"]) <= 60 and refused[0]["error"] == "unknown tool"
    trace = views.trace_text(run.log.records).split("\n")
    assert len(trace) == len(run.log.records)
    assert not any(line.startswith("#99") for line in trace)


def test_fifty_calls_in_one_answer_run_only_up_to_the_per_answer_limit():
    """Attack: one answer with 50 tool calls (a flood to burn time and calls).
    Must happen: only max_tool_calls_per_step (6) run; every other call gets "not run: too many tool calls in
    one step"; the run's tool call count stays within its limit."""
    flood = LlmResponse(tool_calls=tuple(
        ToolCall(call_id=f"f{i}", name="get_outage_timeline", raw_arguments="",
                 arguments={"service_id": "SVC-OLB", "window_hours": i + 1}) for i in range(50)))
    run, result, fake = run_with(call("get_service", service_id="SVC-OLB"), flood)

    limits = agent_limits()
    replies = [m for m in sent_to_ai(fake) if m.role == "tool"][-50:]
    not_run = [m for m in replies if "not run: too many tool calls in one step" in m.content]
    assert len(not_run) == 50 - limits.max_tool_calls_per_step
    assert result.tool_calls_used <= 1 + limits.max_tool_calls_per_step <= limits.max_tool_calls


def test_an_ai_that_only_ever_sends_garbage_is_stopped_by_the_step_limit():
    """Attack: every answer is a broken tool call, forever.
    Must happen: the run stops at the step limit (max_steps) with stop reason "step_limit", having asked the AI
    no more than max_steps times. The result is the engine's on the facts so far."""
    limits = agent_limits()
    fake = FakeProvider([raw_call("get_service", "{{{{")] * (limits.max_steps + 10))
    result = AgentRun(TICKET, REPORTED, fake).start()

    assert (result.status, result.stop_reason) == ("stopped", "step_limit")
    assert len(fake.calls) == limits.max_steps == result.steps_used
    assert result.classification.result == "undetermined"
