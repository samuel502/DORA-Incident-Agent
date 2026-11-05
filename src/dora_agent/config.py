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
