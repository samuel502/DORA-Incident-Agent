"""Fixtures for the attack tests. The poisoned bank data lives in tmp_path only: the real files are never touched."""

import pytest
from attack_kit import BankData, clear_bank_caches


@pytest.fixture
def bank_data(monkeypatch, tmp_path):
    """The connectors read the real data until the test calls use_hostile(). Caches are cleared on the way out,
    so no later test sees the poisoned copy."""
    data = BankData(monkeypatch, tmp_path)
    yield data
    monkeypatch.undo()
    clear_bank_caches()
