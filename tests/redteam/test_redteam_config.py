"""The red team set-up (block 7 d2): the Promptfoo config, the pinned install, the locked-down environment and the
notebook. Offline: nothing here runs Promptfoo, Node or Groq. The live run is notebooks/redteam.ipynb only."""

import importlib.util
import io
import json
import re
import tarfile
import urllib.request
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from dora_agent.config import PROJECT_ROOT, agent_limits
from dora_agent.redteam import notebook as rt
from dora_agent.redteam.adapter import DEFAULT_MAX_STEPS, DEFAULT_TOKEN_BUDGET

CONFIG = json.loads(rt.CONFIG_FILE.read_text(encoding="utf-8"))
CASES = CONFIG["tests"]
CHECKS = ["engine_decides", "no_ai_confirmation", "no_unknown_tool_ran", "no_leak"]
CATEGORIES = {"ticket_injection", "bank_data_injection", "change_classification", "leak_instructions",
              "unknown_tools_or_confirmation"}
GROQ_DAILY_FREE_TOKENS = 200_000  # openai/gpt-oss-120b free tier, console.groq.com/docs/rate-limits


# ---------- the cases ----------


def test_about_fifteen_cases_with_unique_ids_that_name_their_description():
    ids = [case["vars"]["case_id"] for case in CASES]
    assert 12 <= len(CASES) <= 16
    assert len(set(ids)) == len(ids)
    for case in CASES:
        assert re.fullmatch(r"[A-Z]{2}-\d{1,2}", case["vars"]["case_id"])
        assert case["description"].startswith(case["vars"]["case_id"] + ": ")  # the notebook's CASES filter


def test_every_attack_type_asked_for_is_covered():
    by_category = {}
    for case in CASES:
        by_category.setdefault(case["vars"]["category"], []).append(case)
    assert set(by_category) == CATEGORIES
    assert all(len(cases) >= 2 for cases in by_category.values())
    poisoned = [c for c in CASES if c["vars"]["bank_data"] == "poisoned"]
    assert {c["vars"]["category"] for c in poisoned} == {"bank_data_injection"} and len(poisoned) >= 3


@pytest.mark.parametrize("case", CASES, ids=[c["vars"]["case_id"] for c in CASES])
def test_each_case_is_a_valid_ticket_the_agent_accepts(case):
    v = case["vars"]
    assert v["bank_data"] in ("real", "poisoned")
    assert 0 < len(v["ticket"]) <= agent_limits().max_ticket_chars
    assert "{{" not in v["ticket"] and "{%" not in v["ticket"]  # Promptfoo's template step must not touch it
    reported = datetime.fromisoformat(v["reported_at"].replace("Z", "+00:00"))
    assert reported.utcoffset() == timedelta(0)
    assert v["attack"] and v["must"]


def test_no_case_holds_a_real_looking_key():
    text = rt.CONFIG_FILE.read_text(encoding="utf-8")
    assert not re.search(r"gsk_[A-Za-z0-9]{20,}", text)


# ---------- the checks and the provider: plain code, no AI grader, nothing generated ----------


def test_every_case_runs_the_four_plain_code_checks_and_nothing_else():
    asserts = CONFIG["defaultTest"]["assert"]
    assert [a["metric"] for a in asserts] == CHECKS
    assert all(a["type"] == "python" and a["value"] == f"file://checks.py:check_{a['metric']}" for a in asserts)
    assert all("assert" not in case and "options" not in case for case in CASES)  # no case swaps the checks
    shim = _load(rt.REDTEAM_DIR / "checks.py")
    assert all(callable(getattr(shim, f"check_{name}")) for name in CHECKS)


def test_no_ai_grader_no_remote_generation_and_no_sharing_in_the_config():
    text = json.dumps(CONFIG).lower()
    for word in ("llm-rubric", "model-graded", "g-eval", "factuality", "\"redteam\":", "provider\": \"openai",
                 "sharing", "\"share\""):
        assert word not in text
    assert set(CONFIG) == {"description", "prompts", "providers", "defaultTest", "evaluateOptions", "tests"}


def test_provider_is_our_adapter_one_case_at_a_time_and_within_the_free_tier():
    (provider,) = CONFIG["providers"]
    assert provider["id"] == "file://provider.py"
    assert callable(_load(rt.REDTEAM_DIR / "provider.py").call_api)
    config = provider["config"]
    assert config["workers"] == 1 and CONFIG["evaluateOptions"]["maxConcurrency"] == 1
    assert config["max_steps"] == DEFAULT_MAX_STEPS <= agent_limits().max_steps
    assert config["token_budget"] == DEFAULT_TOKEN_BUDGET < GROQ_DAILY_FREE_TOKENS
    # Promptfoo must not give up on a case before the agent's own hard time limit can end it.
    assert config["timeout"] > agent_limits().max_run_seconds * 1000


# ---------- the pinned install ----------


def test_promptfoo_is_pinned_to_one_exact_version_everywhere():
    package = json.loads((rt.REDTEAM_DIR / "package.json").read_text(encoding="utf-8"))
    lock = json.loads((rt.REDTEAM_DIR / "package-lock.json").read_text(encoding="utf-8"))
    assert package["dependencies"] == {"promptfoo": rt.PROMPTFOO_VERSION} == lock["packages"][""]["dependencies"]
    assert lock["packages"]["node_modules/promptfoo"]["version"] == rt.PROMPTFOO_VERSION
    assert package.get("private") is True and "scripts" not in package


def test_every_locked_package_has_an_exact_version_a_sha512_and_comes_from_npm():
    packages = json.loads((rt.REDTEAM_DIR / "package-lock.json").read_text(encoding="utf-8"))["packages"]
    assert len(packages) > 100
    for name, entry in packages.items():
        if not name:
            continue
        assert re.fullmatch(r"\d+\.\d+\.\d+(-[\w.]+)?", entry["version"]), name
        assert entry["integrity"].startswith("sha512-"), name
        assert entry["resolved"].startswith("https://registry.npmjs.org/"), name
    assert "node_modules/@libsql/linux-x64-gnu" in packages  # the Linux build Colab needs is locked too


def test_install_runs_npm_ci_without_package_scripts():
    assert rt.npm_ci_command() == ["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"]


@pytest.mark.parametrize("text, ok", [("v22.22.0", True), ("v22.23.5\n", True), ("v24.1.0", True),
                                      ("v22.21.9", False), ("v20.19.0", False), ("", False), ("node", False)])
def test_node_version_check(text, ok):
    assert rt.node_version_ok(text) is ok


def test_pinned_node_download_is_refused_unless_its_sha256_matches(tmp_path):
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w:xz") as tar:
        info = tarfile.TarInfo("node-v0/bin/node")
        info.size = 4
        tar.addfile(info, io.BytesIO(b"evil"))
    with pytest.raises(ValueError, match="SHA-256"):
        rt.install_node(tmp_path / "node", download=lambda: archive.getvalue())
    assert not (tmp_path / "node").exists()  # nothing unpacked
    assert rt.NODE_URL == f"https://nodejs.org/dist/v{rt.NODE_VERSION}/node-v{rt.NODE_VERSION}-linux-x64.tar.xz"
    assert re.fullmatch(r"[0-9a-f]{64}", rt.NODE_SHA256)
    assert rt.node_version_ok("v" + rt.NODE_VERSION)


def test_node_is_only_downloaded_from_the_pinned_nodejs_org_address():
    import inspect

    source = inspect.getsource(rt._download)
    assert "open(NODE_URL," in source and rt.NODE_URL.startswith("https://nodejs.org/dist/")


def test_the_downloader_opens_https_only(tmp_path):
    import urllib.error

    secret = tmp_path / "secret.txt"
    secret.write_text("not for download", encoding="utf-8")
    opener = rt._https_only_opener()
    for address in (secret.as_uri(), "http://nodejs.org/dist/", "ftp://example.com/x"):
        with pytest.raises(urllib.error.URLError, match="unknown url type"):
            opener.open(address, timeout=1)
    assert not any(isinstance(h, urllib.request.HTTPRedirectHandler) for h in opener.handlers)


def test_node_modules_are_never_committed():
    assert "redteam/node_modules/" in (PROJECT_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()


# ---------- the environment and the command: nothing goes to Promptfoo's servers ----------


def test_environment_switches_promptfoo_off_and_blocks_its_web_requests(tmp_path):
    base = {"PATH": "/usr/bin", "GROQ_API_KEY": "test-key-value"}
    env = rt.promptfoo_env(base, tmp_path)
    for name, value in rt.OFF_SWITCHES.items():
        assert env[name] == value
    assert env["PROMPTFOO_DISABLE_TELEMETRY"] == "1" and env["PROMPTFOO_DISABLE_REMOTE_GENERATION"] == "true"
    assert env["PROMPTFOO_DISABLE_REDTEAM_REMOTE_GENERATION"] == "true"
    for name in rt.PROXY_NAMES:
        assert env[name] == "http://127.0.0.1:9"
    assert env["NO_PROXY"] == env["no_proxy"] == "api.groq.com"  # only the agent's own Groq calls get through
    assert env["PYTHONPATH"] == str(PROJECT_ROOT / "src")
    assert env["REDTEAM_OUT_DIR"] == str(tmp_path)
    assert Path(env["PROMPTFOO_CONFIG_DIR"]).parent == tmp_path  # Promptfoo's own files stay in the run's folder
    assert env["GROQ_API_KEY"] == "test-key-value"  # passed through untouched for the agent, never copied
    assert base == {"PATH": "/usr/bin", "GROQ_API_KEY": "test-key-value"}  # the runtime's own env is not changed


def test_groq_calls_bypass_the_dead_proxy_and_other_hosts_do_not(tmp_path, monkeypatch):
    for name, value in rt.promptfoo_env({}, tmp_path).items():
        if name.lower() in {"no_proxy", "http_proxy", "https_proxy", "all_proxy"}:
            monkeypatch.setenv(name, value)
    assert urllib.request.proxy_bypass_environment("api.groq.com")
    assert not urllib.request.proxy_bypass_environment("r.promptfoo.app")
    assert not urllib.request.proxy_bypass_environment("api.promptfoo.app")


def test_command_is_a_plain_eval_with_no_cache_no_share_and_no_results_database(tmp_path):
    command = rt.promptfoo_command(tmp_path)
    assert command[0].endswith(str(Path("redteam") / "node_modules" / ".bin" / "promptfoo"))
    assert command[1] == "eval" and "generate" not in command and "redteam" not in command[1:2]
    for flag in ("--no-cache", "--no-share", "--no-write", "--no-table"):
        assert flag in command
    assert command[command.index("--max-concurrency") + 1] == "1"
    assert command[command.index("-o") + 1] == str(tmp_path / "report.json")


def test_case_filter_accepts_only_case_ids():
    assert rt.case_filter("") == []
    assert rt.case_filter(" ti-1, BD-2 ") == ["--filter-pattern", "^(TI-1|BD-2):"]
    for hostile in ("TI-1; rm -rf /", ".*", "TI-1|.*", "--no-share"):
        with pytest.raises(ValueError):
            rt.case_filter(hostile)


# ---------- the notebook ----------


NOTEBOOK = json.loads((PROJECT_ROOT / "notebooks" / "redteam.ipynb").read_text(encoding="utf-8"))
CODE = ["".join(c["source"]) for c in NOTEBOOK["cells"] if c["cell_type"] == "code"]


def test_notebook_reads_the_key_only_from_colab_secrets_and_never_prints_it():
    joined = "\n".join(CODE)
    assert 'userdata.get("GROQ_API_KEY")' in joined
    assert joined.count('os.environ["GROQ_API_KEY"] =') == 1
    for line in joined.splitlines():
        if "print(" in line:
            assert "_key" not in line.split("print(", 1)[1] and "environ" not in line.split("print(", 1)[1]
    assert "gsk_" not in joined


def test_notebook_installs_and_runs_only_through_the_tested_helpers():
    joined = "\n".join(CODE)
    assert "rt.npm_ci_command()" in joined and "rt.promptfoo_command(OUT_DIR, CASES)" in joined
    assert "env=rt.promptfoo_env(os.environ, OUT_DIR)" in joined
    assert "rt.installed_promptfoo_version() != rt.PROMPTFOO_VERSION" in joined  # no run on a wrong version
    assert "--require-hashes" in joined
    for forbidden in ("npx", "npm install", "redteam generate", "redteam run", "promptfoo share", "shell=True"):
        assert forbidden not in joined


def test_notebook_saves_results_in_the_git_ignored_logs_folder():
    joined = "\n".join(CODE)
    assert 'rt.PROJECT_ROOT / "logs" / "redteam"' in joined
    assert "logs/" in (PROJECT_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()


def test_red_team_never_runs_in_ci():
    workflows = "\n".join(p.read_text(encoding="utf-8") for p in (PROJECT_ROOT / ".github" / "workflows").glob("*.y*ml"))
    for word in ("redteam", "promptfoo", "npm "):
        assert word not in workflows.lower()


def _load(path: Path):
    spec = importlib.util.spec_from_file_location(f"redteam_shim_{path.stem}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

