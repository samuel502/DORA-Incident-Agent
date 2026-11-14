"""A scripted stand-in for a well-behaved LLM, used to drive all 27 scenarios offline.

It is NOT the real model. It shows that the agent's plumbing (tools, mapping, gate check, questions,
human review, rules engine) gets each case right when the LLM makes good choices:
- one lookups call: get_service plus only the lookups where the scenario has data (index "data_sources"),
  with the client impact window left out (code follows the outage times),
- then, from the status code adds after each step, ask_human for every missing fact with a fixed question.
What the real Groq model chooses is recorded by the opt-in live tests (tests/live/).
"""

from __future__ import annotations

import json
from datetime import timedelta

from dora_agent.agent.loop import STATUS_INTRO
from dora_agent.agent.questions import QUESTIONS
from dora_agent.evaluation.case_runner import Scenario
from dora_agent.llm.provider import LlmResponse, Message, ToolCall, ToolSpec


def _call(name: str, **arguments) -> ToolCall:
    return ToolCall(call_id=f"c-{name}", name=name, arguments=arguments, raw_arguments="")


def _answer(*calls: ToolCall) -> LlmResponse:
    return LlmResponse(tool_calls=tuple(c.model_copy(update={"call_id": f"c{i}-{c.name}"})
                                        for i, c in enumerate(calls)))


def data_content(text: str) -> dict:
    """The JSON inside wrapped data: ...<data-xxx kind="tool_result">, a line break, {...}, </data-xxx>."""
    inner = text.split('kind="tool_result">\n', 1)[1]
    return json.loads(inner.rsplit("\n</data-", 1)[0])


def latest_status(messages: list[Message]) -> dict | None:
    """The status code added after the last step, if the conversation ends with one."""
    last = messages[-1]
    if last.role == "user" and STATUS_INTRO in last.content:
        return data_content(last.content)
    return None


class IdealLlm:
    name = "fake"

    def __init__(self, scenario: Scenario):
        self._s = scenario
        self._stage = 0
        self._asked: set[str] = set()
        self.calls = 0

    def chat(self, messages: list[Message], tools: list[ToolSpec], time_left: float | None = None) -> LlmResponse:
        self.calls += 1
        if self._stage == 0:
            self._stage = 1
            return _answer(_call("lookups", calls=self._lookups()))
        content = latest_status(messages)
        if content is not None and "where_to_find" in content:  # a full status, not final
            # where_to_find holds every missing fact (a separate "missing" list is not sent).
            missing = [f for facts in content["where_to_find"].values() for f in facts]
            wanted = missing + list(content.get("waiting_for_human", []))
            ask = [f for f in dict.fromkeys(wanted) if f in QUESTIONS and f not in self._asked]
            if ask:
                self._asked.update(ask)
                return _answer(_call("ask_human", facts=ask))
        return LlmResponse(text="Nothing more I can look up.")

    def _lookups(self) -> list[dict]:
        s, t = self._s, self._s.around
        calls = [{"tool": "get_service", "args": {"service_id": s.service_id}}]
        if "monitoring" in s.data_sources:
            calls.append({"tool": "get_outage_timeline",
                          "args": {"service_id": s.service_id, "around": t.isoformat()}})
        if "client_impact" in s.data_sources:
            calls.append({"tool": "get_client_impact", "args": {"service_id": s.service_id}})
            calls.append({"tool": "get_daily_averages", "args": {"service_id": s.service_id}})
        if "security_alerts" in s.data_sources:
            calls.append({"tool": "get_security_alerts",
                          "args": {"service_id": s.service_id, "start": (t - timedelta(days=2)).isoformat(),
                                   "end": (t + timedelta(days=5)).isoformat()}})
        if "supplier_notices" in s.data_sources:
            calls.append({"tool": "get_suppliers_for_service", "args": {"service_id": s.service_id}})
        return calls
