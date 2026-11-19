"""Block 7 step c: every pin in both requirements files is exact and carries SHA-256 hashes.

Offline: reads the files only. The hashes themselves are checked by pip (--require-hashes) in CI and Colab.
"""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PIN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*==[A-Za-z0-9.!+_-]+\s*(;.*)?$")
HASH = re.compile(r"^--hash=sha256:[0-9a-f]{64}$")


def pins_with_hashes(path: Path) -> dict[str, list[str]]:
    """Join continuation lines, then map each requirement to its list of --hash options."""
    text = re.sub(r"\\\n", " ", path.read_text(encoding="utf-8"))
    result = {}
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        requirement, _, options = line.partition(" --")
        result[requirement.strip()] = ("--" + options).split() if options else []
    return result


@pytest.mark.parametrize("name", ["requirements.txt", "requirements-ci.txt"])
def test_every_pin_is_exact_and_hashed(name):
    pins = pins_with_hashes(ROOT / name)
    assert pins, f"no pins found in {name}"
    for requirement, hashes in pins.items():
        assert PIN.match(requirement), f"{name}: not an exact pin: {requirement!r}"
        assert hashes, f"{name}: no hashes for {requirement}"
        for option in hashes:
            assert HASH.match(option), f"{name}: bad hash option for {requirement}: {option!r}"


@pytest.mark.parametrize("name", ["requirements.txt", "requirements-ci.txt"])
def test_hashes_are_not_shared_between_pins(name):
    seen = {}
    for requirement, hashes in pins_with_hashes(ROOT / name).items():
        for option in hashes:
            assert option not in seen, f"{name}: {requirement} and {seen[option]} list the same file"
            seen[option] = requirement


def test_ci_and_colab_install_with_require_hashes():
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "pip install --require-hashes --only-binary=:all: -r requirements.txt" in ci
    assert "pip install --require-hashes --no-deps --only-binary=:all: -r requirements-ci.txt" in ci
    # scripts/hash_requirements.py talks to PyPI, so both code scanners must cover it (Sam, 19 November 2026).
    assert "run: bandit -r src scripts\n" in ci
    assert "--error src notebooks scripts\n" in ci
    notebook = (ROOT / "notebooks" / "colab.ipynb").read_text(encoding="utf-8")
    assert '\\"--require-hashes\\", \\"--only-binary=:all:\\"' in notebook
