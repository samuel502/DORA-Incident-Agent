"""The rules engine stays plain Python (CLAUDE.md hard rule 1).

It must not import the LLM, the connectors, the agent or anything that reaches the network.
Checked by reading the import lines of every file in src/dora_agent/rules/.
"""

import ast
from pathlib import Path

RULES_DIR = Path(__file__).resolve().parents[2] / "src" / "dora_agent" / "rules"

ALLOWED_TOP_LEVEL = {"__future__", "dataclasses", "datetime", "decimal", "enum", "typing", "pydantic", "dora_agent"}
ALLOWED_OWN = "dora_agent.rules"


def imported_modules(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name
        elif isinstance(node, ast.ImportFrom):
            yield node.module or ""


def test_rules_files_exist():
    assert list(RULES_DIR.glob("*.py"))


def test_rules_import_only_plain_python():
    for path in RULES_DIR.glob("*.py"):
        for module in imported_modules(path):
            top = module.split(".")[0]
            assert top in ALLOWED_TOP_LEVEL, f"{path.name} imports {module}"
            if top == "dora_agent":
                assert module.startswith(ALLOWED_OWN), f"{path.name} imports {module}"
