"""Shared pieces for the offline attack tests (block 7 step d1, docs/security-framework.md section 4).

The attack tests assume the worst: the AI is FULLY fooled and does whatever the hostile text says. The fake AI
(llm/fake_provider.py) plays that fooled AI from a script, so the tests need no key and no network. What is
tested is the plain code around the AI: the rules engine decides, tools only read and check their input, the
fact store keeps "confirmed by" for people, and the limits stop a runaway run.

Synthetic data only (CLAUDE.md hard rule 6): the hostile texts below are made up for these tests.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from dora_agent.agent.fact_store import SYSTEM_SOURCES
from dora_agent.connectors import _store
from dora_agent.llm.fake_provider import call
from dora_agent.llm.provider import LlmResponse, Message, ToolCall
from dora_agent.redteam.poison import INJECTION, MARK, clear_bank_caches, write_hostile_copy

__all__ = ["INJECTION", "MARK", "clear_bank_caches", "write_hostile_copy"]  # used by the attack tests


def t(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def many(*responses: LlmResponse) -> LlmResponse:
    """One AI answer proposing several tool calls at once."""
    return LlmResponse(tool_calls=tuple(r.tool_calls[0].model_copy(update={"call_id": f"c{i}"})
                                        for i, r in enumerate(responses)))


def lookups(*items: tuple[str, dict]) -> LlmResponse:
    """One AI answer with one lookups call listing (tool, arguments) pairs."""
    return call("lookups", call_id="L", calls=[{"tool": name, "args": args} for name, args in items])


def raw_call(name: str, raw: str, call_id: str = "raw") -> LlmResponse:
    """One AI answer with a tool call whose arguments are raw text, exactly as a provider passes them on."""
    return LlmResponse(tool_calls=(ToolCall.from_raw(call_id, name, raw),))


# ---------- poisoned bank data (shared with the red team notebook: dora_agent/redteam/poison.py) ----------


class BankData:
    """Switches the connectors between the real bank data and a poisoned copy, inside one test."""

    def __init__(self, monkeypatch, tmp_path: Path):
        self._monkeypatch = monkeypatch
        self.real = _store.DATA_DIR
        self.hostile_dir = tmp_path / "hostile-bank-data"
        self.changed = write_hostile_copy(self.hostile_dir)

    def use_hostile(self) -> None:
        self._monkeypatch.setattr(_store, "DATA_DIR", self.hostile_dir)
        clear_bank_caches()

    def use_real(self) -> None:
        self._monkeypatch.setattr(_store, "DATA_DIR", self.real)
        clear_bank_caches()


# ---------- checks ----------


def sent_to_ai(provider) -> list[Message]:
    """The whole conversation as the AI last saw it (each call gets the full conversation so far)."""
    return provider.calls[-1][0] if provider.calls else []


def outside_markers(text: str, code: str) -> str:
    """The parts of a message that are NOT between this run's data markers."""
    pieces, rest = [], text
    while f"<data-{code} " in rest:
        before, _, after = rest.partition(f"<data-{code} ")
        pieces.append(before)
        _, _, rest = after.partition(f"</data-{code}>")
    pieces.append(rest)
    return "".join(pieces)


def assert_hostile_text_stays_data(messages: list[Message], code: str, marks: tuple[str, ...] = (MARK,)) -> None:
    """Hostile text may reach the AI only inside this run's data markers, never as instructions.

    - The system message (the agent's instructions) holds none of it.
    - Every tool reply is one wrapped block: it opens and closes with this run's markers, exactly once each.
    - In the task and status messages, hostile text sits only between the markers.
    The hostile text never knows the run's marker code, so a forged closing marker cannot end the block.
    """
    assert messages and messages[0].role == "system"
    for mark in marks:
        assert mark not in messages[0].content
    for message in messages[1:]:
        if message.role == "tool":
            body = message.content
            assert body.startswith(f'<data-{code} kind="tool_result">') and body.endswith(f"</data-{code}>")
            assert body.count(f"<data-{code} ") == 1 and body.count(f"</data-{code}>") == 1
        elif message.role == "user":
            for mark in marks:
                assert mark not in outside_markers(message.content, code)


def fact_table(facts) -> dict[str, tuple]:
    """Every fact that has a value: (value, source, confirmed_by, is_estimate). For comparing two runs."""
    table = {}
    for name in type(facts).model_fields:
        fact = getattr(facts, name)
        if fact is not None and getattr(fact, "value", None) is not None:
            table[name] = (fact.value, fact.source, fact.confirmed_by, fact.is_estimate)
    return table


def assert_no_ai_confirmation(facts) -> None:
    """Without a person's answer, no fact is confirmed by anyone, and every source is a system or the AI's
    suggestion (which the rules ignore until a person confirms it)."""
    for name, (_, source, confirmed_by, _) in fact_table(facts).items():
        assert confirmed_by is None, f"{name} has confirmed_by={confirmed_by!r} without a person"
        assert source in SYSTEM_SOURCES | {"ai_suggestion"}, f"{name} has source {source!r} without a person"


def refused_tools(log_records) -> list[str]:
    """Tool calls the decision log shows as refused, in order."""
    return [r["tool"] for r in log_records if r.get("kind") == "tool_call" and not r.get("ok")]
