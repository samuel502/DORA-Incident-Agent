"""The one LLM provider interface (CLAUDE.md hard rule 7: the LLM must be swappable).

Every LLM call in this project goes through `LlmProvider.chat`. The agent only ever sees the
types in this file, never a vendor's own types, so a bank could plug in its own approved model
by writing one new class.

The LLM proposes tool calls and writes text. It never decides the classification (hard rule 1).
"""

from __future__ import annotations

import json
from typing import Any, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

# Longest raw tool-argument text kept when the LLM sends something that is not valid JSON.
MAX_RAW_ARGUMENTS_CHARS = 2000


class Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class LlmError(Exception):
    """Any failure talking to the LLM: missing key, timeout, network, refused request.

    The message is always short and plain. It never contains the API key or the provider's raw error text.
    `code` is a short error code from a fixed list (e.g. "rate_limit_exceeded", "tool_use_failed"),
    "other" for anything not on the list, or None if the provider sent none.
    """

    def __init__(self, message: str, code: str | None = None):
        super().__init__(message)
        self.code = code


class ToolSpec(Frozen):
    """A tool the LLM may ask for: name, what it does, and a JSON schema for its parameters."""

    name: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    description: str = Field(min_length=1, max_length=1000)
    parameters: dict[str, Any]


class ToolCall(Frozen):
    """One tool call proposed by the LLM. It is only a proposal: the agent checks it before running anything.

    If the LLM sent arguments that are not a JSON object, `arguments` is None and `raw_arguments`
    keeps a cut-down copy for the log.
    """

    call_id: str = Field(min_length=1, max_length=200)
    name: str = Field(max_length=200)
    arguments: dict[str, Any] | None
    raw_arguments: str = Field(max_length=MAX_RAW_ARGUMENTS_CHARS)

    @property
    def arguments_valid(self) -> bool:
        return self.arguments is not None

    @classmethod
    def from_raw(cls, call_id: str, name: str, raw: str | None) -> "ToolCall":
        """Build a ToolCall from the raw JSON text a provider returns. Never raises on bad JSON."""
        raw = raw or ""
        try:
            parsed = json.loads(raw) if raw.strip() else {}
        except (ValueError, RecursionError):
            parsed = None
        if not isinstance(parsed, dict):
            parsed = None
        return cls(call_id=call_id[:200], name=name[:200], arguments=parsed,
                   raw_arguments=raw[:MAX_RAW_ARGUMENTS_CHARS])


class Message(Frozen):
    """One message in the conversation.

    system:    the agent's instructions
    user:      the task, with the ticket wrapped as untrusted data
    assistant: what the LLM said, and the tool calls it proposed
    tool:      a tool result sent back to the LLM, as untrusted data
    """

    role: Literal["system", "user", "assistant", "tool"]
    content: str = ""
    tool_calls: tuple[ToolCall, ...] = ()
    tool_call_id: str | None = None  # only for role "tool"


class Usage(Frozen):
    input_tokens: int = 0
    output_tokens: int = 0


class LlmResponse(Frozen):
    """What the LLM gave back: some text, zero or more proposed tool calls, and token counts."""

    text: str = ""
    tool_calls: tuple[ToolCall, ...] = ()
    usage: Usage = Usage()


@runtime_checkable
class LlmProvider(Protocol):
    """Anything with this method can be the agent's LLM."""

    name: str

    def chat(self, messages: list[Message], tools: list[ToolSpec]) -> LlmResponse:
        """Send the conversation and the allowed tools. Raise LlmError on any failure."""
        ...
