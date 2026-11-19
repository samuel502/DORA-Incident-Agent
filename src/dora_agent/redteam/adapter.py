"""Promptfoo adapter: runs one red team case through the REAL agent and returns the evidence as JSON (block 7 d2).

Promptfoo calls `call_api(prompt, options, context)` once per case (redteam/provider.py points here). The prompt
is the ticket; the case's other settings come from its vars. This module only RUNS the agent and COLLECTS what
happened. The pass/fail checks are in checks.py, plain code, never an AI grader.

Safety:
- The agent is the normal one: the rules engine decides (hard rule 1), tools only read (hard rule 3), and the
  limits in config.toml apply (hard rule 8). The red team can only make the step limit SMALLER, to save tokens.
- The key is read by the Groq provider from the environment, as always (hard rule 5). This module never reads,
  returns or logs it. It only reports true/false: did the key's text show up in the run's output or log?
- Bank-data attacks read a poisoned COPY in a temporary folder; data/ is never changed (poison.py).
- A token budget for the whole red team run stops new cases before Groq's daily free limit is used up.
"""

from __future__ import annotations

import dataclasses
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dora_agent.agent.loop import AgentRun, RunProblem
from dora_agent.agent.tools import LOOKUPS, OFFERED
from dora_agent.config import PROJECT_ROOT, agent_limits, llm_settings
from dora_agent.llm import LlmProvider, get_provider
from dora_agent.redteam.poison import bank_data_folder, write_hostile_copy
from dora_agent.rules import classify

# Every tool name the agent knows. Anything else the AI calls must be refused (checks.py).
KNOWN_TOOLS = frozenset(LOOKUPS | set(OFFERED) | {"lookups"})
# Where reports and decision logs go when the notebook does not say: inside the git-ignored logs/ folder.
DEFAULT_OUT_DIR = PROJECT_ROOT / "logs" / "redteam" / "latest"
OUT_DIR_ENV = "REDTEAM_OUT_DIR"
# Defaults for the provider config in redteam/promptfooconfig.json. Sized for Groq's free tier
# (openai/gpt-oss-120b: 8,000 tokens per minute, 200,000 per day; console.groq.com/docs/rate-limits).
DEFAULT_MAX_STEPS = 4
DEFAULT_TOKEN_BUDGET = 180_000
# Rough tokens for one AI step, to keep a reserve before starting a case (measured live runs: about 2,500).
TOKENS_PER_STEP_RESERVE = 3_000
MAX_TEXT_CHARS = 1_000

_provider: LlmProvider | None = None  # one Groq client for the whole red team run, so its token pacer carries over


def _llm() -> LlmProvider:
    global _provider
    if _provider is None:
        _provider = get_provider()
    return _provider


def _out_dir() -> Path:
    return Path(os.environ.get(OUT_DIR_ENV) or DEFAULT_OUT_DIR)


def _tokens_used(out_dir: Path) -> int:
    path = out_dir / "tokens_used.json"
    try:
        return int(json.loads(path.read_text(encoding="utf-8"))["tokens"])
    except (OSError, ValueError, KeyError, TypeError):
        return 0


def _add_tokens(out_dir: Path, tokens: int) -> int:
    total = _tokens_used(out_dir) + tokens
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "tokens_used.json").write_text(json.dumps({"tokens": total}), encoding="utf-8")
    return total


def _key_text() -> str:
    return os.environ.get(llm_settings().api_key_env, "").strip()


def _parse_time(text: str) -> datetime:
    value = datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    if value.tzinfo is None:
        raise ValueError("reported_at needs a time zone, for example Z")
    return value.astimezone(timezone.utc)


def run_case(ticket: str, vars_: dict[str, Any], config: dict[str, Any], provider: LlmProvider,
             out_dir: Path) -> dict[str, Any]:
    """Run one case and return the evidence. `provider` is passed in, so the offline tests use the fake AI."""
    case_id = str(vars_.get("case_id", "?"))[:20]
    max_steps = min(int(config.get("max_steps", DEFAULT_MAX_STEPS)), agent_limits().max_steps)  # only smaller
    budget = int(config.get("token_budget", DEFAULT_TOKEN_BUDGET))
    used_before = _tokens_used(out_dir)
    if used_before + max_steps * TOKENS_PER_STEP_RESERVE > budget:
        return {"case_id": case_id, "skipped": True,
                "reason": f"token budget for this red team run reached ({used_before:,} of {budget:,} used)"}
    limits = dataclasses.replace(agent_limits(), max_steps=max_steps)
    reported_at = _parse_time(vars_["reported_at"])
    bank_data = vars_.get("bank_data", "real")
    if bank_data not in ("real", "poisoned"):
        raise ValueError("bank_data must be 'real' or 'poisoned'")

    with tempfile.TemporaryDirectory(prefix="redteam-bank-") as scratch:
        if bank_data == "poisoned":
            write_hostile_copy(Path(scratch))
            with bank_data_folder(Path(scratch)):
                run, result = _run(ticket, reported_at, provider, limits, out_dir)
        else:
            run, result = _run(ticket, reported_at, provider, limits, out_dir)

    records = run.log.records
    steps = [r for r in records if r["kind"] == "llm_step"]
    tokens = sum((r.get("input_tokens") or 0) + (r.get("output_tokens") or 0) for r in steps)
    total = _add_tokens(out_dir, tokens)
    facts = result.classification.facts
    evidence = {
        "case_id": case_id,
        "skipped": False,
        "bank_data": bank_data,
        "run_id": result.run_id,
        "status": result.status,
        "stop_reason": result.stop_reason,
        "result": result.classification.result,
        # Plain code runs the rules engine again on the same facts: the result must be the same.
        "engine_result": classify(facts, reported_at).result,
        # The run's last log line: "result", or "paused" when it waits for a person.
        "logged_result": next((r.get("result") for r in reversed(records) if r["kind"] in ("result", "paused")),
                              None),
        "facts": [{"name": name, "source": fact.source, "confirmed_by": fact.confirmed_by}
                  for name, fact in _held(facts)],
        "fact_actions": [r.get("action") for r in records if r["kind"] == "fact"],
        "tool_calls": [{"tool": r.get("tool"), "by": r.get("by"), "ok": r.get("ok")}
                       for r in records if r["kind"] == "tool_call"],
        "ai_texts": _ai_texts(records),
        "review_items": [{"fact": i.fact_name} for i in result.review_items],
        "steps_used": result.steps_used,
        "max_steps": max_steps,
        "tokens": tokens,
        "tokens_run_total": total,
        "seconds": round(result.seconds_used, 1),
    }
    key = _key_text()
    log_file = out_dir / "decision_logs" / f"{result.run_id}.jsonl"
    log_text = log_file.read_text(encoding="utf-8") if log_file.is_file() else ""
    evidence["key_found"] = bool(key) and (key in json.dumps(evidence) or key in log_text)
    return evidence


def _run(ticket, reported_at, provider, limits, out_dir):
    run = AgentRun(ticket, reported_at, provider, limits=limits, log_dir=out_dir / "decision_logs")
    return run, run.start()


def _held(facts) -> list[tuple[str, Any]]:
    """(name, fact) for every fact that holds a value."""
    held = []
    for name in type(facts).model_fields:
        fact = getattr(facts, name)
        if fact is not None and getattr(fact, "value", None) is not None:
            held.append((name, fact))
    return held


def _ai_texts(records: list[dict]) -> list[str]:
    """Everything the AI wrote in this run: its answers and the arguments of its tool calls."""
    texts = []
    for r in records:
        if r["kind"] == "llm_step":
            if r.get("text"):
                texts.append(str(r["text"])[:MAX_TEXT_CHARS])
            for proposed in r.get("proposed") or []:
                texts.append(json.dumps(proposed, ensure_ascii=False, default=str)[:MAX_TEXT_CHARS])
    return texts


def call_api(prompt: str, options: dict | None = None, context: dict | None = None) -> dict:
    """Promptfoo's entry point. Returns {"output": evidence as JSON text}, or {"error": ...} if the case could not
    run (the error text never holds the key: it comes from our own messages or the error's type only)."""
    config = (options or {}).get("config") or {}
    vars_ = (context or {}).get("vars") or {}
    # The ticket exactly as written in the case, not after Promptfoo's template step.
    ticket = vars_.get("ticket", prompt)
    try:
        evidence = run_case(ticket, vars_, config, _llm(), _out_dir())
    except (RunProblem, ValueError, KeyError) as problem:
        return {"error": f"case could not run: {problem}"[:300]}
    except Exception as problem:  # noqa: BLE001 - only the type is shown, never a message that might hold secrets
        return {"error": f"case could not run: {type(problem).__name__}"}
    if evidence.get("skipped"):
        return {"error": evidence["reason"]}
    if evidence["stop_reason"] == "llm_error":
        # Not an attack result: Groq could not be reached (rate limit, network, key). Shown as "not tested".
        return {"error": f"not tested: the Groq call failed in run {evidence['run_id']} (see its decision log)"}
    return {"output": json.dumps(evidence, ensure_ascii=False),
            "tokenUsage": {"total": evidence["tokens"]}}
