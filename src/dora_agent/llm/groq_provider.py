"""Groq as the LLM provider. Default model: openai/gpt-oss-120b (config.toml [llm]).

This is the only file in the project that imports the groq package (checked by a test).

Secrets (CLAUDE.md hard rule 5, security framework "Secret leak"):
- The key is read from the environment variable named in config.toml, nowhere else.
- It is handed straight to the Groq client and not stored on this object.
- Error messages name the error type and HTTP status only, never the provider's raw text,
  so nothing the provider echoes back can end up on screen or in the log.
- The only thing read from an error body is Groq's short error code, and only if it is on a fixed list.

Rate limits (block 5 step 5, config.toml [llm]):
- Before each call, a TokenPacer waits if the call would go over tokens_per_minute.
- On HTTP 429 the call waits (Groq's suggested time if sent, else 2, 4, 8 ... s) and tries again,
  at most rate_limit_retries times and at most rate_limit_max_wait_seconds in total.
"""

from __future__ import annotations

import json
import math
import os
import time
from collections.abc import Callable

import groq

from dora_agent.config import LlmSettings
from dora_agent.llm.pacing import TokenPacer, estimate_tokens
from dora_agent.llm.provider import LlmError, LlmResponse, Message, ToolCall, ToolSpec, Usage

# Groq error codes that may be shown and logged. Anything else becomes "other" (never the raw text).
ERROR_CODES = frozenset({
    "rate_limit_exceeded", "tool_use_failed", "context_length_exceeded", "json_validate_failed",
    "request_too_large", "model_not_found", "model_decommissioned", "invalid_api_key", "service_unavailable",
})


class GroqProvider:
    name = "groq"

    def __init__(self, settings: LlmSettings, client=None, *, sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic):
        """client, sleep, clock: only for tests, to pass stand-ins instead of the real ones."""
        self._settings = settings
        self._sleep = sleep
        self._pacer = TokenPacer(settings.tokens_per_minute, clock=clock, sleep=sleep)
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
        estimate = estimate_tokens([request["messages"], request.get("tools")])
        self._pacer.wait_for(estimate)
        response = self._create_with_retries(request)
        result = _from_wire(response)
        self._pacer.record(result.usage.input_tokens or estimate, result.usage.output_tokens)
        return result

    def _create_with_retries(self, request: dict):
        settings = self._settings
        waited, retries = 0.0, 0
        while True:
            try:
                return self._client.chat.completions.create(**request)
            except groq.RateLimitError as error:
                pause = _retry_after(error) or float(2 ** (retries + 1))
                if retries >= settings.rate_limit_retries or waited + pause > settings.rate_limit_max_wait_seconds:
                    raise LlmError(f"LLM call refused: RateLimitError (HTTP 429, {_error_code(error) or 'no code'}) "
                                   f"after {retries} retries and {waited:.0f} s waiting",
                                   code=_error_code(error) or "rate_limit_exceeded") from None
                self._sleep(pause)
                waited += pause
                retries += 1
            except groq.APITimeoutError:
                raise LlmError(f"LLM call timed out after {settings.timeout_seconds} s") from None
            except groq.APIStatusError as error:
                code = _error_code(error)
                raise LlmError(f"LLM call refused: {type(error).__name__} (HTTP {error.status_code}"
                               f"{', ' + code if code else ''})", code=code) from None
            except groq.GroqError as error:  # base of every groq error, including connection errors
                raise LlmError(f"LLM call failed: {type(error).__name__}") from None


def _error_code(error: "groq.APIStatusError") -> str | None:
    """Groq's short error code if it is on the fixed list, "other" if not, None if there is none."""
    body = getattr(error, "body", None)
    if isinstance(body, dict) and isinstance(body.get("error"), dict):
        body = body["error"]
    code = body.get("code") if isinstance(body, dict) else None
    if not isinstance(code, str) or not code:
        return None
    return code if code in ERROR_CODES else "other"


def _retry_after(error: "groq.APIStatusError") -> float | None:
    """Seconds to wait from the retry-after header, if it is a sensible number."""
    try:
        value = float(error.response.headers.get("retry-after", ""))
    except (AttributeError, TypeError, ValueError):
        return None
    return value if math.isfinite(value) and 0 < value <= 600 else None


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
