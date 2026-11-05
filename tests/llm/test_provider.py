"""The provider interface, the fake LLM, settings, and the "one door" rule (CLAUDE.md hard rule 7)."""

import ast
from pathlib import Path

import pytest
from pydantic import ValidationError

from dora_agent.config import llm_settings
from dora_agent.llm import LlmError, LlmProvider, Message, ToolCall, ToolSpec, get_provider
from dora_agent.llm.fake_provider import FakeProvider, call, say

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src" / "dora_agent"


# ---------- tool calls from the LLM are only proposals; bad input never crashes ----------


def test_tool_call_parses_json_arguments():
    tc = ToolCall.from_raw("c1", "get_service", '{"service_id": "SVC-OLB"}')
    assert tc.arguments == {"service_id": "SVC-OLB"}
    assert tc.arguments_valid


@pytest.mark.parametrize("raw", ["not json", "[1, 2]", '"text"', "{broken", "1" * 10])
def test_tool_call_with_bad_arguments_is_marked_invalid_not_crashing(raw):
    tc = ToolCall.from_raw("c1", "get_service", raw)
    assert tc.arguments is None
    assert not tc.arguments_valid


def test_tool_call_empty_arguments_means_no_arguments():
    assert ToolCall.from_raw("c1", "list_tools", "").arguments == {}
    assert ToolCall.from_raw("c1", "list_tools", None).arguments == {}


def test_tool_call_raw_text_is_cut_for_the_log():
    tc = ToolCall.from_raw("c1", "x", "a" * 50_000)
    assert len(tc.raw_arguments) == 2000


def test_deeply_nested_json_does_not_crash():
    tc = ToolCall.from_raw("c1", "x", "[" * 100_000 + "]" * 100_000)
    assert tc.arguments is None


def test_tool_names_must_be_simple():
    with pytest.raises(ValidationError):
        ToolSpec(name="Get Service!", description="x", parameters={})
    assert ToolSpec(name="get_service", description="x", parameters={}).name == "get_service"


def test_messages_cannot_be_changed_after_creation():
    message = Message(role="user", content="hello")
    with pytest.raises(ValidationError):
        message.content = "changed"


def test_unknown_message_role_rejected():
    with pytest.raises(ValidationError):
        Message(role="admin", content="x")


# ---------- the fake LLM ----------


def test_fake_provider_plays_its_script_in_order_and_records_calls():
    fake = FakeProvider([call("get_service", service_id="SVC-OLB"), say("done")])
    first = fake.chat([Message(role="user", content="t")], [])
    assert first.tool_calls[0].name == "get_service"
    assert first.tool_calls[0].arguments == {"service_id": "SVC-OLB"}
    assert fake.chat([], []).text == "done"
    assert len(fake.calls) == 2


def test_fake_provider_raises_when_script_runs_out():
    with pytest.raises(LlmError):
        FakeProvider([]).chat([], [])


def test_fake_provider_meets_the_interface():
    assert isinstance(FakeProvider([]), LlmProvider)


# ---------- settings ----------


def test_llm_settings_from_config():
    settings = llm_settings()
    assert settings.provider == "groq"
    assert settings.model == "openai/gpt-oss-120b"
    assert settings.api_key_env == "GROQ_API_KEY"
    assert settings.timeout_seconds > 0


def test_config_holds_no_key():
    text = (ROOT / "config.toml").read_text(encoding="utf-8")
    assert "gsk_" not in text  # Groq keys start with gsk_
    assert "api_key =" not in text


def test_unknown_provider_is_refused():
    from dataclasses import replace

    with pytest.raises(LlmError):
        get_provider(replace(llm_settings(), provider="mystery"))


# ---------- one door: only groq_provider.py may import groq (hard rule 7) ----------


def imports(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            yield from (alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            yield node.module


VENDOR_PACKAGES = {"groq", "openai", "anthropic", "httpx", "requests"}


def test_only_the_groq_provider_imports_an_llm_or_http_package():
    offenders = []
    for path in SRC.rglob("*.py"):
        if path.name == "groq_provider.py":
            continue
        for module in imports(path):
            if module.split(".")[0] in VENDOR_PACKAGES:
                offenders.append(f"{path.relative_to(SRC)} imports {module}")
    assert offenders == []


def test_groq_is_pinned_in_requirements_and_pyproject():
    requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
    assert "groq==1.7.0" in requirements
    assert '"groq==1.7.0"' in (ROOT / "pyproject.toml").read_text(encoding="utf-8")
