"""Block 5: the one LLM provider interface (CLAUDE.md hard rule 7).

Use `get_provider()` to get the configured LLM. Nothing else in the project talks to an LLM directly.
"""

from __future__ import annotations

from dora_agent.config import LlmSettings, llm_settings
from dora_agent.llm.provider import LlmError, LlmProvider, LlmResponse, Message, ToolCall, ToolSpec, Usage


def get_provider(settings: LlmSettings | None = None) -> LlmProvider:
    """The LLM named in config.toml [llm] provider. Raises LlmError if it cannot be set up."""
    settings = settings or llm_settings()
    if settings.provider == "groq":
        from dora_agent.llm.groq_provider import GroqProvider

        return GroqProvider(settings)
    raise LlmError(f"Unknown LLM provider in config.toml: {settings.provider!r}")


__all__ = ["LlmError", "LlmProvider", "LlmResponse", "Message", "ToolCall", "ToolSpec", "Usage", "get_provider"]
