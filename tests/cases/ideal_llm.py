"""A scripted stand-in for a well-behaved LLM, used to drive all 27 scenarios offline.

It is NOT the real model. It shows that the agent's plumbing (tools, mapping, gate check, questions,
human review, rules engine) gets each case right when the LLM makes good choices:
- get_service first, then only the lookups where the scenario has data (index "data_sources"),
- then run_rules, and ask_human for every missing fact that has a fixed question.
What the real Groq model chooses is recorded by the opt-in live tests (tests/live/).
"""

from __future__ import annotations

import json
from datetime import timedelta

from dora_agent.agent.questions import QUESTIONS
from dora_agent.evaluation.case_runner import Scenario
from dora_agent.llm.provider import LlmResponse, Message, ToolCall, ToolSpec


def _call(name: str, **arguments) -> ToolCall:
    return ToolCall(call_id=f"c-{name}", name=name, arguments=arguments, raw_arguments="")


def _answer(*calls: ToolCall) -> LlmResponse:
    return LlmResponse(tool_calls=tuple(c.model_copy(update={"call_id": f"c{i}-{c.name}"})
                                        for i, c in enumerate(calls)))


def _tool_content(message: Message) -> dict:
    """The JSON inside a wrapped tool result: <data-xxx kind="tool_result">\\n{...}\\n</data-xxx>."""
    return json.loads(message.content.split("\n", 1)[1].rsplit("\n", 1)[0])


class IdealLlm:
    name = "fake"

    def __init__(self, scenario: Scenario):
        self._s = scenario
        self._stage = 0
        self._asked: set[str] = set()
        self.calls = 0

    def chat(self, messages: list[Message], tools: list[ToolSpec], time_left: float | None = None) -> LlmResponse:
        self.calls += 1
        s = self._s
        if self._stage == 0:
            self._stage = 1
            return _answer(_call("get_service", service_id=s.service_id))
        if self._stage == 1:
            self._stage = 2
            return _answer(*self._lookups())
        if self._stage == 2:
            self._stage = 3
            return _answer(_call("run_rules"))
        last = messages[-1]
        if last.role == "tool":
            content = _tool_content(last)
            if "result" in content and "where_to_find" in content:  # a full run_rules result, not final
                # where_to_find holds every missing fact (the separate "missing" list is no longer sent).
                missing = [f for facts in content["where_to_find"].values() for f in facts]
                wanted = missing + list(content.get("waiting_for_human", []))
                ask = [f for f in dict.fromkeys(wanted) if f in QUESTIONS and f not in self._asked]
                if ask:
                    self._asked.update(ask)
                    return _answer(_call("ask_human", facts=ask))
                return LlmResponse(text="Nothing more I can look up.")
        return _answer(_call("run_rules"))  # e.g. after the human answered

    def _lookups(self) -> list[ToolCall]:
        s, t = self._s, self._s.around
        calls = []
        if "monitoring" in s.data_sources:
            calls.append(_call("get_outage_timeline", service_id=s.service_id, around=t.isoformat()))
        if "client_impact" in s.data_sources:
            calls.append(_call("get_client_impact", service_id=s.service_id,
                               start=(t - timedelta(days=7)).isoformat(), end=(t + timedelta(days=7)).isoformat()))
            calls.append(_call("get_daily_averages", service_id=s.service_id))
        if "security_alerts" in s.data_sources:
            calls.append(_call("get_security_alerts", service_id=s.service_id,
                               start=(t - timedelta(days=2)).isoformat(), end=(t + timedelta(days=5)).isoformat()))
        if "supplier_notices" in s.data_sources:
            calls.append(_call("get_suppliers_for_service", service_id=s.service_id))
        return calls
