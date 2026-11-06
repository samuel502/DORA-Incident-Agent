"""cases/samples.json: the sample tickets the interface offers (block 6).

The interface reads this file, never the answer key in cases/scenarios/index.json.
"""

import json
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SAMPLES = ROOT / "cases" / "samples.json"
INDEX = ROOT / "cases" / "scenarios" / "index.json"


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_marked_synthetic():
    assert "SYNTHETIC DATA" in load(SAMPLES)["about"]


def test_every_case_in_the_index_is_a_sample_with_the_same_ticket_and_time():
    samples = {s["sample_id"]: s for s in load(SAMPLES)["samples"]}
    index = load(INDEX)["scenarios"]
    assert len(samples) == len(index) == 27
    for case in index:
        sample = samples[case["scenario_id"]]
        assert sample["ticket"] == case["ticket"]
        assert sample["title"] == case["title"]
        assert sample["reported_at"] == case["around"]


def test_samples_hold_no_answers():
    for sample in load(SAMPLES)["samples"]:
        assert set(sample) == {"sample_id", "title", "ticket", "reported_at"}
    text = SAMPLES.read_text(encoding="utf-8")
    for word in ("expected_result", "human_answers", "real_case", "why", "major"):
        assert word not in text, word


def test_samples_name_no_real_company(real_names):
    text = SAMPLES.read_text(encoding="utf-8")
    for name in real_names:
        assert name not in text, name


def test_reported_times_are_utc():
    for sample in load(SAMPLES)["samples"]:
        assert sample["reported_at"].endswith("Z")
        assert datetime.fromisoformat(sample["reported_at"].replace("Z", "+00:00")).utcoffset().total_seconds() == 0


def test_tickets_fit_the_ticket_limit():
    from dora_agent.config import agent_limits
    for sample in load(SAMPLES)["samples"]:
        assert 0 < len(sample["ticket"]) <= agent_limits().max_ticket_chars
