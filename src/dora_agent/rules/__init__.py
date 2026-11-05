"""Block 4: rules engine. Plain Python, built only from docs/dora-rules.md. Decides major / not major.

CLAUDE.md hard rule 1: the AI never decides the classification. Only this package does.
"""

from dora_agent.rules.engine import Classification, classify
from dora_agent.rules.facts import HUMAN_CONFIRMED, Fact, IncidentFacts
from dora_agent.rules.version import RULE_VERSION

__all__ = ["HUMAN_CONFIRMED", "RULE_VERSION", "Classification", "Fact", "IncidentFacts", "classify"]
