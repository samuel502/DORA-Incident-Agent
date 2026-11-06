"""Opt-in live tests: the scenarios through the agent with the REAL Groq model.

Skipped unless BOTH are set:
    GROQ_API_KEY      the key (never printed or logged; the decision log masks it)
    RUN_LIVE_TESTS=1  explicit opt-in, so a plain `pytest` never spends tokens by accident
Optional:
    LIVE_CASES=C01,N01,B03   run only these scenarios (default: all 27)
    LIVE_PAUSE_SECONDS=60    pause between cases, to stay under Groq rate limits (default 60)

Before any case, a free access check (no tokens) asks Groq for the model's details. If access is
refused (key, model permissions, or a network block such as a VPN), all tests stop with a plain message.

What these tests check: the runs complete, the result always comes from the rules engine,
the key never reaches a log or the report, and the real model takes different tool paths.
What they RECORD (not assert): which result each case got and which tools the model chose.
The report goes to logs/live/ (git-ignored). The full measured run with numbers is block 8.
"""

import json
import os
import time
from datetime import datetime, timezone

import pytest

from dora_agent.config import PROJECT_ROOT, llm_settings
from dora_agent.evaluation.case_runner import load_scenarios, run_cases, summary, table, write_report
from dora_agent.llm import LlmError, get_provider
from dora_agent.rules import RULE_VERSION

KEY_ENV = llm_settings().api_key_env
LIVE = os.environ.get("RUN_LIVE_TESTS") == "1" and bool(os.environ.get(KEY_ENV, "").strip())

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(not LIVE, reason=f"live Groq tests are opt-in: set RUN_LIVE_TESTS=1 and {KEY_ENV}"),
]

OUT_DIR = PROJECT_ROOT / "logs" / "live"


def _selected():
    scenarios = load_scenarios()
    wanted = [x.strip() for x in os.environ.get("LIVE_CASES", "").split(",") if x.strip()]
    if not wanted:
        return scenarios
    unknown = set(wanted) - {s.scenario_id for s in scenarios}
    if unknown:
        raise ValueError(f"LIVE_CASES has unknown scenarios: {sorted(unknown)}")
    return [s for s in scenarios if s.scenario_id in wanted]


@pytest.fixture(scope="module")
def live_run():
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = OUT_DIR / stamp
    pause = float(os.environ.get("LIVE_PAUSE_SECONDS", "60"))
    provider = get_provider()  # one Groq client for all cases
    try:
        provider.check_access()  # uses no tokens
    except LlmError as error:
        pytest.fail(f"Groq access check failed before any case ran: {error}", pytrace=False)
    outcomes = run_cases(_selected(), lambda scenario: provider, log_dir=run_dir / "decision_logs",
                         between=lambda: time.sleep(pause))
    report = run_dir / "report.json"
    write_report(outcomes, report, provider=provider.name, model=llm_settings().model)
    print("\n" + table(outcomes) + "\n" + json.dumps(summary(outcomes)) + f"\nReport: {report}")
    return outcomes, run_dir


def test_every_case_ran_to_an_end_without_llm_errors(live_run):
    outcomes, _ = live_run
    assert outcomes
    for o in outcomes:
        assert o.status in ("finished", "stopped"), o.scenario_id
        assert o.stop_reason != "llm_error", f"{o.scenario_id}: the LLM call failed (rate limit or network?)"


def test_every_case_used_tools(live_run):
    # A case that used no tools proves nothing, even if its result happens to fit (B03, 6 Nov 2026).
    outcomes, _ = live_run
    idle = [o.scenario_id for o in outcomes if o.tool_calls == 0]
    assert not idle, f"no tools used in: {idle}"


def test_every_run_is_fully_logged_with_the_engine_result(live_run):
    outcomes, run_dir = live_run
    for o in outcomes:
        lines = (run_dir / "decision_logs" / f"{o.run_id}.jsonl").read_text(encoding="utf-8").splitlines()
        records = [json.loads(line) for line in lines]
        assert records[0]["kind"] == "run_started" and records[0]["provider"] == "groq"
        final = records[-1]
        assert final["kind"] == "result" and final["rule_version"] == RULE_VERSION
        assert final["result"] == o.result  # the outcome is the engine's result, nothing else


def test_api_key_never_reaches_a_log_or_the_report(live_run):
    _, run_dir = live_run
    key = os.environ.get(KEY_ENV, "").strip()
    for path in run_dir.rglob("*"):
        if path.is_file():
            found = key in path.read_text(encoding="utf-8")
            assert not found, f"API key found in {path.name}"  # the key itself is never shown


def test_real_model_takes_different_paths_for_different_incidents(live_run):
    outcomes, _ = live_run
    if len(outcomes) < 2:
        pytest.skip("needs at least two cases")
    assert len({o.tool_path for o in outcomes}) >= 2
