"""The Groq provider, tested with a stand-in client: no network, no real key, no API cost.

Checks: the request sent, the answer read back, errors turned into short safe messages,
and the key never showing up anywhere (CLAUDE.md hard rule 5).
"""

import json
from types import SimpleNamespace

import groq
import httpx
import pytest

from dora_agent.config import llm_settings
from dora_agent.llm import LlmError, Message, ToolCall, ToolSpec
from dora_agent.llm.groq_provider import GroqProvider

FAKE_KEY = "TEST-ONLY-placeholder-not-a-key-1234567890"
REQUEST = httpx.Request("POST", "https://api.groq.com/openai/v1/chat/completions")


class StandInClient:
    """Looks like groq.Groq to the provider. Records the request; returns or raises what it is told."""

    def __init__(self, answer=None, error=None):
        self.requests = []
        self._answer, self._error = answer, error
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **request):
        self.requests.append(request)
        if self._error:
            raise self._error
        return self._answer


def answer(content="", tool_calls=None, prompt_tokens=10, completion_tokens=5):
    calls = [SimpleNamespace(id=c[0], function=SimpleNamespace(name=c[1], arguments=c[2])) for c in tool_calls or []]
    message = SimpleNamespace(content=content, tool_calls=calls or None)
    return SimpleNamespace(choices=[SimpleNamespace(message=message)],
                           usage=SimpleNamespace(prompt_tokens=prompt_tokens, completion_tokens=completion_tokens))


TOOL = ToolSpec(name="get_service", description="Look up one service.",
                parameters={"type": "object", "properties": {"service_id": {"type": "string"}}})


# ---------- the request ----------


def test_request_uses_configured_model_and_limits():
    client = StandInClient(answer("ok"))
    GroqProvider(llm_settings(), client=client).chat([Message(role="user", content="hi")], [TOOL])
    sent = client.requests[0]
    assert sent["model"] == "openai/gpt-oss-120b"
    assert sent["temperature"] == 0
    assert sent["max_completion_tokens"] == llm_settings().max_output_tokens
    assert sent["tools"][0]["function"]["name"] == "get_service"
    assert sent["tool_choice"] == "auto"


def test_no_tools_means_no_tool_fields():
    client = StandInClient(answer("ok"))
    GroqProvider(llm_settings(), client=client).chat([Message(role="user", content="hi")], [])
    assert "tools" not in client.requests[0]


def test_tool_round_trip_is_sent_in_groq_format():
    client = StandInClient(answer("ok"))
    proposed = ToolCall(call_id="c1", name="get_service", arguments={"service_id": "SVC-OLB"}, raw_arguments="")
    GroqProvider(llm_settings(), client=client).chat(
        [Message(role="assistant", tool_calls=(proposed,)),
         Message(role="tool", tool_call_id="c1", content='{"critical": "yes"}')], [TOOL])
    assistant, tool = client.requests[0]["messages"]
    assert assistant["tool_calls"][0]["id"] == "c1"
    assert json.loads(assistant["tool_calls"][0]["function"]["arguments"]) == {"service_id": "SVC-OLB"}
    assert tool == {"role": "tool", "content": '{"critical": "yes"}', "tool_call_id": "c1"}


# ---------- the answer ----------


def test_answer_with_tool_call_is_read_back():
    client = StandInClient(answer(tool_calls=[("c9", "get_service", '{"service_id": "SVC-HR"}')]))
    result = GroqProvider(llm_settings(), client=client).chat([Message(role="user", content="x")], [TOOL])
    assert result.tool_calls[0].name == "get_service"
    assert result.tool_calls[0].arguments == {"service_id": "SVC-HR"}
    assert (result.usage.input_tokens, result.usage.output_tokens) == (10, 5)


def test_answer_with_broken_arguments_is_kept_as_invalid():
    client = StandInClient(answer(tool_calls=[("c9", "get_service", "{oops")]))
    result = GroqProvider(llm_settings(), client=client).chat([Message(role="user", content="x")], [TOOL])
    assert not result.tool_calls[0].arguments_valid


def test_empty_answer_raises_llm_error():
    client = StandInClient(SimpleNamespace(choices=[], usage=None))
    with pytest.raises(LlmError):
        GroqProvider(llm_settings(), client=client).chat([Message(role="user", content="x")], [])


# ---------- errors: short, safe, never the provider's raw text ----------


def status_error(cls, code, body=None, headers=None):
    response = httpx.Response(code, request=REQUEST, headers=headers or {})
    return cls(f"provider said something containing {FAKE_KEY}", response=response, body=body)


def no_sleep(seconds):
    pass


@pytest.mark.parametrize(
    "error, expected",
    [
        (groq.APITimeoutError(request=REQUEST), "timed out"),
        (status_error(groq.AuthenticationError, 401), "HTTP 401"),
        (status_error(groq.RateLimitError, 429), "HTTP 429"),
        (groq.APIConnectionError(message=f"conn {FAKE_KEY}", request=REQUEST), "APIConnectionError"),
    ],
)
def test_provider_errors_become_short_llm_errors_without_raw_text(error, expected):
    client = StandInClient(error=error)
    with pytest.raises(LlmError) as caught:
        GroqProvider(llm_settings(), client=client, sleep=no_sleep).chat([Message(role="user", content="x")], [])
    assert expected in str(caught.value)
    assert FAKE_KEY not in str(caught.value)
    assert caught.value.__cause__ is None  # raw provider error not chained into tracebacks


# ---------- the key ----------


def test_missing_key_gives_a_clear_error(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    with pytest.raises(LlmError, match="GROQ_API_KEY"):
        GroqProvider(llm_settings())


def test_blank_key_counts_as_missing(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "   ")
    with pytest.raises(LlmError):
        GroqProvider(llm_settings())


def test_key_is_not_stored_on_the_provider_or_shown(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", FAKE_KEY)
    provider = GroqProvider(llm_settings())  # builds a real client, makes no call
    assert FAKE_KEY not in repr(provider)
    assert FAKE_KEY not in str(vars(provider).get("_settings"))
    assert all(value != FAKE_KEY for value in vars(provider).values())


def test_real_client_gets_timeout_and_retries(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", FAKE_KEY)
    client = GroqProvider(llm_settings())._client
    assert client.timeout == llm_settings().timeout_seconds
    assert client.max_retries == llm_settings().max_retries


# ---------- rate limits: wait and retry (block 5 step 5) ----------


class Flaky(StandInClient):
    """Raises the given errors first, then answers."""

    def __init__(self, errors, final):
        super().__init__(answer=final)
        self._errors = list(errors)

    def _create(self, **request):
        self.requests.append(request)
        if self._errors:
            raise self._errors.pop(0)
        return self._answer


def test_rate_limit_waits_and_retries_then_succeeds():
    slept = []
    client = Flaky([status_error(groq.RateLimitError, 429), status_error(groq.RateLimitError, 429)], answer("ok"))
    result = GroqProvider(llm_settings(), client=client, sleep=slept.append).chat(
        [Message(role="user", content="x")], [])
    assert result.text == "ok" and len(client.requests) == 3
    assert slept == [2.0, 4.0]  # no retry-after header: 2, 4, 8 ... seconds


def test_rate_limit_uses_the_providers_suggested_wait():
    slept = []
    client = Flaky([status_error(groq.RateLimitError, 429, headers={"retry-after": "7.5"})], answer("ok"))
    GroqProvider(llm_settings(), client=client, sleep=slept.append).chat([Message(role="user", content="x")], [])
    assert slept == [7.5]


def test_rate_limit_gives_up_after_the_configured_retries():
    slept = []
    client = StandInClient(error=status_error(groq.RateLimitError, 429,
                                              body={"error": {"code": "rate_limit_exceeded", "message": FAKE_KEY}}))
    with pytest.raises(LlmError) as caught:
        GroqProvider(llm_settings(), client=client, sleep=slept.append).chat([Message(role="user", content="x")], [])
    settings = llm_settings()
    assert len(slept) == settings.rate_limit_retries and sum(slept) <= settings.rate_limit_max_wait_seconds
    assert caught.value.code == "rate_limit_exceeded"
    assert "HTTP 429" in str(caught.value) and FAKE_KEY not in str(caught.value)


def test_rate_limit_never_waits_past_the_total_cap():
    slept = []
    client = StandInClient(error=status_error(groq.RateLimitError, 429, headers={"retry-after": "500"}))
    with pytest.raises(LlmError):
        GroqProvider(llm_settings(), client=client, sleep=slept.append).chat([Message(role="user", content="x")], [])
    assert slept == []  # 500 s is over the cap, so it gives up at once


@pytest.mark.parametrize("body, code", [
    ({"error": {"code": "tool_use_failed", "message": f"bad call {FAKE_KEY}"}}, "tool_use_failed"),
    ({"code": "tool_use_failed"}, "tool_use_failed"),
    ({"error": {"code": f"weird-{FAKE_KEY}"}}, "other"),  # not on the list: never shown as is
    ({"error": {"message": "no code"}}, None),
    (None, None),
])
def test_error_code_comes_only_from_the_fixed_list(body, code):
    client = StandInClient(error=status_error(groq.BadRequestError, 400, body=body))
    with pytest.raises(LlmError) as caught:
        GroqProvider(llm_settings(), client=client).chat([Message(role="user", content="x")], [])
    assert caught.value.code == code
    assert "HTTP 400" in str(caught.value) and FAKE_KEY not in str(caught.value)


def test_calls_are_paced_to_the_tokens_per_minute_limit():
    clock = {"now": 0.0}
    slept = []

    def sleep(seconds):
        slept.append(seconds)
        clock["now"] += seconds

    client = StandInClient(answer("ok", prompt_tokens=5000, completion_tokens=500))
    provider = GroqProvider(llm_settings(), client=client, sleep=sleep, clock=lambda: clock["now"])
    provider.chat([Message(role="user", content="x")], [])
    assert slept == []  # first call: nothing used yet
    provider.chat([Message(role="user", content="x")], [])  # 5,500 used + ~500 expected: fits in 8,000
    assert slept == []
    provider.chat([Message(role="user", content="x")], [])  # 11,000 used: must wait for the minute to pass
    assert len(slept) == 1 and 59 < slept[0] <= 60.2
