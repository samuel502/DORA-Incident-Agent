"""Groq as the LLM provider. Default model: openai/gpt-oss-120b (config.toml [llm]).

This is the only file in the project that imports the groq package (checked by a test).

Secrets (CLAUDE.md hard rule 5, security framework "Secret leak"):
- The key is read from the environment variable named in config.toml, nowhere else.
- It is handed straight to the Groq client and not stored on this object.
- Error messages name the error type and HTTP status only, never the provider's raw text,
  so nothing the provider echoes back can end up on screen or in the log.
"""

from __future__ import annotations

import json
import os

import groq

from dora_agent.config import LlmSettings
from dora_agent.llm.provider import LlmError, LlmResponse, Message, ToolCall, ToolSpec, Usage


class GroqProvider:
    name = "groq"

    def __init__(self, settings: LlmSettings, client=None):
        """client: only for tests, to pass a stand-in instead of the real Groq client."""
        self._settings = settings
        if client is not None:
            self._client = client
            return
        key = os.environ.get(settings.api_key_env, "").strip()
        if not key:
            raise LlmError(f"No API key: set the environment variable {settings.api_key_env}")
        self._client = groq.Groq(api_key=key, timeout=settings.timeout_seconds, max_retries=settings.max_retries)

    def __repr__(self) -> str:
        return f"GroqProvider(model={self._settings.model!r})"

    def chat(self, messages: list[Message], tools: list[ToolSpec]) -> LlmResponse:
        request = {
            "model": self._settings.model,
            "messages": [_to_wire(m) for m in messages],
            "temperature": self._settings.temperature,
            "max_completion_tokens": self._settings.max_output_tokens,
        }
        if tools:
            request["tools"] = [_tool_to_wire(t) for t in tools]
            request["tool_choice"] = "auto"
        try:
            response = self._client.chat.completions.create(**request)
        except groq.APITimeoutError:
            raise LlmError(f"LLM call timed out after {self._settings.timeout_seconds} s") from None
        except groq.APIStatusError as error:
            raise LlmError(f"LLM call refused: {type(error).__name__} (HTTP {error.status_code})") from None
        except groq.GroqError as error:  # base of every groq error, including connection errors
            raise LlmError(f"LLM call failed: {type(error).__name__}") from None
        return _from_wire(response)


def _to_wire(message: Message) -> dict:
    wire: dict = {"role": message.role, "content": message.content}
    if message.role == "assistant" and message.tool_calls:
        wire["tool_calls"] = [
            {
                "id": call.call_id,
                "type": "function",
                "function": {
                    "name": call.name,
                    "arguments": json.dumps(call.arguments) if call.arguments is not None else call.raw_arguments,
                },
            }
            for call in message.tool_calls
        ]
    if message.role == "tool":
        wire["tool_call_id"] = message.tool_call_id
    return wire


def _tool_to_wire(tool: ToolSpec) -> dict:
    return {"type": "function",
            "function": {"name": tool.name, "description": tool.description, "parameters": tool.parameters}}


def _from_wire(response) -> LlmResponse:
    try:
        choice = response.choices[0].message
    except (AttributeError, IndexError, TypeError):
        raise LlmError("LLM returned no answer") from None
    calls = tuple(
        ToolCall.from_raw(str(call.id), str(call.function.name), call.function.arguments)
        for call in (choice.tool_calls or [])
    )
    usage = getattr(response, "usage", None)
    return LlmResponse(
        text=choice.content or "",
        tool_calls=calls,
        usage=Usage(input_tokens=getattr(usage, "prompt_tokens", 0) or 0,
                    output_tokens=getattr(usage, "completion_tokens", 0) or 0),
    )
