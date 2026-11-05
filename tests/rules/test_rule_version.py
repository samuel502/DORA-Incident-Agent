"""The code's rule version must match the rule sheet, so the log never shows the wrong version."""

import re
from pathlib import Path

from dora_agent.rules import RULE_VERSION

RULE_SHEET = Path(__file__).resolve().parents[2] / "docs" / "dora-rules.md"


def test_rule_version_matches_rule_sheet():
    text = RULE_SHEET.read_text(encoding="utf-8")
    match = re.search(r"^Rule version: (\d+\.\d+) ", text, flags=re.MULTILINE)
    assert match, "no 'Rule version:' line in docs/dora-rules.md"
    assert RULE_VERSION == match.group(1)
