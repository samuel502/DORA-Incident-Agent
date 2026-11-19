"""Promptfoo provider for the red team run (block 7 d2). The code is in src/dora_agent/redteam/adapter.py.

Promptfoo loads this file by its path. The notebook puts src/ on PYTHONPATH, so the import below finds the agent.
"""

from dora_agent.redteam.adapter import call_api

__all__ = ["call_api"]
