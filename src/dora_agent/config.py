"""Settings loaded from config.toml at the project root.

No secrets live in this file or in config.toml (CLAUDE.md hard rule 5).
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, fields
from functools import lru_cache
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = PROJECT_ROOT / "config.toml"
DATA_DIR = PROJECT_ROOT / "data" / "rheinbank"


@dataclass(frozen=True)
class ConnectorLimits:
    """Caps that keep connector inputs and outputs small (security framework, section 1)."""

    max_query_chars: int
    max_find_results: int
    max_text_chars: int
    max_results: int
    max_timeline_window_hours: int
    max_impact_window_days: int
    max_alert_window_days: int
    max_notice_window_days: int


@lru_cache(maxsize=1)
def connector_limits() -> ConnectorLimits:
    """Read the [connectors] section once. Every value must be a positive whole number."""
    with CONFIG_PATH.open("rb") as handle:
        section = tomllib.load(handle)["connectors"]
    values = {}
    for field in fields(ConnectorLimits):
        value = section[field.name]
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise ValueError(f"config.toml [connectors] {field.name} must be a positive integer")
        values[field.name] = value
    return ConnectorLimits(**values)


@dataclass(frozen=True)
class LlmSettings:
    """The [llm] section. Names where the key lives, never the key itself (hard rule 5)."""

    provider: str
    model: str
    api_key_env: str
    timeout_seconds: int
    max_retries: int
    max_output_tokens: int
    temperature: float


@lru_cache(maxsize=1)
def llm_settings() -> LlmSettings:
    """Read the [llm] section once and check every value."""
    with CONFIG_PATH.open("rb") as handle:
        section = tomllib.load(handle)["llm"]
    for name in ("provider", "model", "api_key_env"):
        if not isinstance(section[name], str) or not section[name].strip():
            raise ValueError(f"config.toml [llm] {name} must be a non-empty text")
    for name in ("timeout_seconds", "max_output_tokens"):
        value = section[name]
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise ValueError(f"config.toml [llm] {name} must be a positive integer")
    retries = section["max_retries"]
    if not isinstance(retries, int) or isinstance(retries, bool) or not 0 <= retries <= 5:
        raise ValueError("config.toml [llm] max_retries must be a whole number from 0 to 5")
    temperature = section["temperature"]
    if not isinstance(temperature, (int, float)) or isinstance(temperature, bool) or not 0 <= temperature <= 2:
        raise ValueError("config.toml [llm] temperature must be between 0 and 2")
    return LlmSettings(
        provider=section["provider"], model=section["model"], api_key_env=section["api_key_env"],
        timeout_seconds=section["timeout_seconds"], max_retries=retries,
        max_output_tokens=section["max_output_tokens"], temperature=float(temperature),
    )


@dataclass(frozen=True)
class AgentLimits:
    """The [agent] section: hard limits on the agent loop (CLAUDE.md hard rule 8)."""

    max_steps: int
    max_tool_calls: int
    max_tool_calls_per_step: int
    max_human_rounds: int
    max_ticket_chars: int
    max_tool_result_chars: int
    gate_check_alert_days_before: int
    gate_check_alert_days_after: int


@lru_cache(maxsize=1)
def agent_limits() -> AgentLimits:
    """Read the [agent] section once. Every value must be a positive whole number."""
    with CONFIG_PATH.open("rb") as handle:
        section = tomllib.load(handle)["agent"]
    values = {}
    for field in fields(AgentLimits):
        value = section[field.name]
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise ValueError(f"config.toml [agent] {field.name} must be a positive integer")
        values[field.name] = value
    if values["gate_check_alert_days_before"] + values["gate_check_alert_days_after"] > 31:
        raise ValueError("config.toml [agent] gate check alert window must be at most 31 days (connector limit)")
    return AgentLimits(**values)
