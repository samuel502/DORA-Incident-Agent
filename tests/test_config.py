"""config.toml [agent]: the client impact default window (C01 live test, approved by Sam on 13 November 2026)."""

import pytest

from dora_agent import config


def test_client_impact_default_days_is_read_from_the_config():
    assert config.agent_limits().client_impact_default_days == 7


@pytest.mark.parametrize("value, problem", [(0, "positive integer"), (184, "at most 183")])
def test_client_impact_default_days_must_be_sensible(tmp_path, monkeypatch, value, problem):
    text = config.CONFIG_PATH.read_text(encoding="utf-8").replace(
        "client_impact_default_days = 7", f"client_impact_default_days = {value}")
    path = tmp_path / "config.toml"
    path.write_text(text, encoding="utf-8")
    monkeypatch.setattr(config, "CONFIG_PATH", path)
    config.agent_limits.cache_clear()
    try:
        with pytest.raises(ValueError, match=problem):
            config.agent_limits()
    finally:
        config.agent_limits.cache_clear()  # the next test reads the real file again
