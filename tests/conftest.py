"""Shared test helpers."""

import pytest

# Decision 3 (approved by Sam): made-up supplier names only. Real firms named in
# docs/case-library.md must never appear in bank data or in ticket texts.
# They may appear only in the real_case field of cases/scenarios/index.json.
REAL_NAMES = [
    "TSB", "Postbank", "Deutsche Bank", "TARGET", "T2S", "Eurosystem", "ECB", "Barclays", "Visa",
    "ICBC", "LockBit", "Citrix", "ION", "ABN Amro", "Intesa", "OP Pohjola", "Pohjola", "Bank of Ireland",
    "Capital One", "Flagstar", "MOVEit", "Fiserv", "Evolve", "Wise", "Affirm", "Finastra", "Helaba",
    "FI-TS", "Finanz Informatik", "Sparkasse", "DKB", "CrowdStrike", "Microsoft",
]


@pytest.fixture
def real_names():
    return REAL_NAMES
