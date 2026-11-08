"""The decision log: one JSON Lines record per thing that happened in a run (CLAUDE.md hard rule 9).

It records the ticket, every LLM step, every tool call, every fact change with its source,
every human input with who gave it, any conflicts, the rule version and the result.

Safe by design:
- Each record is one line of JSON. Line breaks inside text are escaped by the JSON encoder,
  so text from a ticket cannot fake an extra log line.
- No API key is ever passed to the log. As a second line of defence, any text equal to the
  current value of the configured key variable is masked before writing (tested).
- Records are kept in memory as the trace for the interface; writing to a file is optional.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dora_agent.config import llm_settings

MASK = "[REDACTED]"
# Fields every record gets from the log itself.
RESERVED = frozenset({"run_id", "seq", "at", "kind"})


class DecisionLog:
    def __init__(self, run_id: str, path: Path | None = None):
        self.run_id = run_id
        self._path = path
        self._records: list[dict[str, Any]] = []
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def records(self) -> list[dict[str, Any]]:
        """A copy of everything logged so far: the trace."""
        return [dict(r) for r in self._records]

    def write(self, kind: str, **data: Any) -> dict[str, Any]:
        # The log's own fields can't be overwritten by the data: run_id, seq (1, 2, 3 ... without gaps),
        # at and kind always come from the log itself (block 6 step 2 fix, approved by Sam).
        clash = sorted(RESERVED & set(data))
        if clash:
            raise ValueError(f"log data may not set the log's own fields: {', '.join(clash)}")
        record = {
            "run_id": self.run_id,
            "seq": len(self._records) + 1,
            "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "kind": kind,
            **data,
        }
        line = _redact(json.dumps(record, default=str))  # ASCII only: every line break, even Unicode ones, is escaped
        record = json.loads(line)
        self._records.append(record)
        if self._path is not None:
            with self._path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        return record


def _redact(line: str) -> str:
    """Mask the API key if it ever appears (it should not: no code passes it here)."""
    key = os.environ.get(llm_settings().api_key_env, "").strip()
    if len(key) >= 8 and key in line:
        line = line.replace(key, MASK)
    return line
