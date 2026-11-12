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
    rate_limit_retries: int  # waits and retries on HTTP 429
    rate_limit_max_wait_seconds: int  # most seconds one call may wait on rate limits and connections, in total
    connection_retries: int  # waits and retries on a dropped connection
    tokens_per_minute: int  # pace calls to stay under this; 0 = no pacing
    reasoning_effort: str = ""  # "low", "medium" or "high" for reasoning models; "" = not sent


REASONING_EFFORTS = ("", "low", "medium", "high")


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
    limits = {}
    for name, low, high in (("rate_limit_retries", 0, 10), ("rate_limit_max_wait_seconds", 1, 600),
                            ("connection_retries", 0, 10),
                            ("tokens_per_minute", 0, 10_000_000)):
        value = section[name]
        if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
            raise ValueError(f"config.toml [llm] {name} must be a whole number from {low} to {high}")
        limits[name] = value
    # Groq SDK 1.7.0 (types/chat/completion_create_params.py): "openai/gpt-oss-20b and openai/gpt-oss-120b
    # support 'low', 'medium', or 'high'. 'medium' is the default value." Empty text = the field is not sent.
    effort = section.get("reasoning_effort", "")
    if effort not in REASONING_EFFORTS:
        raise ValueError('config.toml [llm] reasoning_effort must be "low", "medium", "high" or ""')
    return LlmSettings(
        provider=section["provider"], model=section["model"], api_key_env=section["api_key_env"],
        timeout_seconds=section["timeout_seconds"], max_retries=retries,
        max_output_tokens=section["max_output_tokens"], temperature=float(temperature),
        reasoning_effort=effort, **limits,
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
    max_repeated_calls: int
    max_run_seconds: int  # hard total working time per run (block 6 step 3)


# Upper bound for max_run_seconds, so a typo can't switch the time limit off in practice.
MAX_RUN_SECONDS_CAP = 3600


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
    if values["max_run_seconds"] > MAX_RUN_SECONDS_CAP:
        raise ValueError(f"config.toml [agent] max_run_seconds must be at most {MAX_RUN_SECONDS_CAP}")
    return AgentLimits(**values)


@dataclass(frozen=True)
class NotificationSettings:
    """The [notification] section: limits for the draft initial notification (block 5b)."""

    max_description_chars: int
    max_causes_chars: int


@lru_cache(maxsize=1)
def notification_settings() -> NotificationSettings:
    """Read the [notification] section once. Every value must be a whole number from 1 to 10,000."""
    with CONFIG_PATH.open("rb") as handle:
        section = tomllib.load(handle)["notification"]
    values = {}
    for field in fields(NotificationSettings):
        value = section[field.name]
        if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 10_000:
            raise ValueError(f"config.toml [notification] {field.name} must be a whole number from 1 to 10000")
        values[field.name] = value
    return NotificationSettings(**values)
