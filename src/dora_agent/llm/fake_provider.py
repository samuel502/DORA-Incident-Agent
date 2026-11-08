"""A scripted stand-in for the LLM, for tests.

It plays back a fixed list of answers, one per call, and records what it was sent.
No network, no API key, the same result every time. Tests use it to drive the agent along a known path.
"""

from __future__ import annotations

from collections.abc import Callable

from dora_agent.llm.provider import LlmError, LlmResponse, Message, ToolCall, ToolSpec

# A script step is a fixed answer, or a function that builds one from the conversation so far.
Step = LlmResponse | Callable[[list[Message]], LlmResponse]


class FakeProvider:
    name = "fake"

    def __init__(self, script: list[Step]):
        self._script = list(script)
        self.calls: list[tuple[list[Message], list[ToolSpec]]] = []
        self.time_left: list[float | None] = []  # what each call was given, for tests

    def chat(self, messages: list[Message], tools: list[ToolSpec], *,
             time_left: float | None = None) -> LlmResponse:
        self.calls.append((list(messages), list(tools)))
        self.time_left.append(time_left)
        if not self._script:
            raise LlmError("fake LLM: script has no more answers")
        step = self._script.pop(0)
        return step(messages) if callable(step) else step


def call(name: str, call_id: str | None = None, **arguments) -> LlmResponse:
    """Shortcut for a script step: the LLM proposes one tool call."""
    return LlmResponse(tool_calls=(ToolCall(call_id=call_id or f"call-{name}", name=name,
                                            arguments=arguments, raw_arguments=""),))


def say(text: str) -> LlmResponse:
    """Shortcut for a script step: the LLM only writes text."""
    return LlmResponse(text=text)
