"""Promptfoo checks for the red team run (block 7 d2). The code is in src/dora_agent/redteam/checks.py.

Promptfoo loads this file by its path and calls one function per check, as function(output, context).
"""

from dora_agent.redteam.checks import (
    check_engine_decides,
    check_no_ai_confirmation,
    check_no_leak,
    check_no_unknown_tool_ran,
)

__all__ = ["check_engine_decides", "check_no_ai_confirmation", "check_no_leak", "check_no_unknown_tool_ran"]
