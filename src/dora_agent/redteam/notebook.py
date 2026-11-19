"""What notebooks/redteam.ipynb runs: settings for Promptfoo, the command, and the plain summary (block 7 d2).

Kept here, not in the notebook, so the offline tests can check it (tests/redteam/).

Nothing goes to Promptfoo's servers:
- Telemetry, update checks, sharing and remote attack generation are switched off by their own settings.
- Promptfoo 0.125.1 still sends one "telemetry disabled" message even when telemetry is off (checked in its
  code, dist/src/telemetry-*.js, 19 November 2026). So Promptfoo's own web requests are also sent to a proxy
  address where nothing listens, and fail. Promptfoo routes all its requests through that proxy setting.
- Only api.groq.com is exempt from that proxy (NO_PROXY), so the agent's own Groq calls still work.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import sys
import tarfile
import urllib.request
from collections.abc import Callable, Mapping
from pathlib import Path

from dora_agent.config import PROJECT_ROOT
from dora_agent.redteam.adapter import OUT_DIR_ENV

PROMPTFOO_VERSION = "0.125.1"  # exact pin, also in redteam/package.json and redteam/package-lock.json
MIN_NODE = (22, 22)  # Promptfoo 0.125.1 needs Node 22.22 or newer (its package.json, "engines")
REDTEAM_DIR = PROJECT_ROOT / "redteam"
CONFIG_FILE = REDTEAM_DIR / "promptfooconfig.json"
DEAD_PROXY = "http://127.0.0.1:9"  # port 9 ("discard"): nothing answers, so every request through it fails
GROQ_HOST = "api.groq.com"

OFF_SWITCHES = {
    "PROMPTFOO_DISABLE_TELEMETRY": "1",
    "PROMPTFOO_DISABLE_UPDATE": "1",
    "PROMPTFOO_DISABLE_SHARING": "1",
    "PROMPTFOO_DISABLE_SHARE_EMAIL_REQUEST": "1",
    "PROMPTFOO_DISABLE_REMOTE_GENERATION": "true",
    "PROMPTFOO_DISABLE_REDTEAM_REMOTE_GENERATION": "true",
    "PROMPTFOO_CACHE_ENABLED": "false",
}
PROXY_NAMES = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")


def node_version_ok(version_text: str) -> bool:
    """True if `node --version` output (like "v22.22.1") is new enough for the pinned Promptfoo."""
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)\s*", version_text or "")
    return bool(match) and (int(match[1]), int(match[2])) >= MIN_NODE


def installed_promptfoo_version() -> str | None:
    """The Promptfoo version npm ci put in redteam/node_modules, or None if it is not installed."""
    try:
        package = json.loads((REDTEAM_DIR / "node_modules" / "promptfoo" / "package.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return package.get("version")


def npm_ci_command() -> list[str]:
    """Install exactly what redteam/package-lock.json lists (every package with its SHA-512), and run none of
    the packages' own install scripts."""
    return ["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"]


# Used only if Colab's own Node is older than MIN_NODE. Official build; SHA-256 from
# https://nodejs.org/dist/v22.23.5/SHASUMS256.txt (security release of 11 November 2026, checked 19 November 2026).
NODE_VERSION = "22.23.5"
NODE_FILE = f"node-v{NODE_VERSION}-linux-x64.tar.xz"
NODE_URL = f"https://nodejs.org/dist/v{NODE_VERSION}/{NODE_FILE}"
NODE_SHA256 = "cdeb8670a0c81f51b4dc4ac61919f9b1ad917b304bf8221eb939570663d240f8"


def _https_only_opener() -> urllib.request.OpenerDirector:
    """A downloader that can open https addresses and nothing else: no file://, no http://, no redirects.
    Any answer other than 200 OK is an error. (urllib's usual opener can also open files on disk.)"""
    opener = urllib.request.OpenerDirector()
    # UnknownHandler turns every other address type into an error ("unknown url type") instead of nothing.
    for handler in (urllib.request.HTTPSHandler(), urllib.request.UnknownHandler(),
                    urllib.request.HTTPDefaultErrorHandler(), urllib.request.HTTPErrorProcessor()):
        opener.add_handler(handler)
    return opener


def _download() -> bytes:
    """Fetch the pinned Node from its fixed address (NODE_URL; a test checks it is the only address here).
    Not httpx: only the Groq provider may import an HTTP package (tests/llm/test_provider.py, hard rule 7)."""
    with _https_only_opener().open(NODE_URL, timeout=120) as response:
        if response.status != 200:
            raise ValueError(f"Node download refused: answer {response.status}, not 200")
        return response.read()


def install_node(target: Path, download: Callable[[], bytes] = _download) -> Path:
    """Download the pinned Node into target, check its SHA-256 BEFORE unpacking, and return its bin folder.
    A file with any other hash is refused and nothing is unpacked."""
    data = download()
    digest = hashlib.sha256(data).hexdigest()
    if digest != NODE_SHA256:
        raise ValueError(f"Node download refused: SHA-256 {digest[:16]}... is not the pinned {NODE_SHA256[:16]}...")
    target.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:xz") as archive:
        archive.extractall(target, filter="data")  # "data": no links out of target, no special files
    return target / f"node-v{NODE_VERSION}-linux-x64" / "bin"


def promptfoo_env(base: Mapping[str, str], out_dir: Path) -> dict[str, str]:
    """The environment for the Promptfoo process. It inherits the runtime's environment (so the agent's Python
    can read the key, as always), with the off switches, the dead proxy, and our own folders added."""
    env = dict(base)
    env.update(OFF_SWITCHES)
    for name in PROXY_NAMES:
        env[name] = DEAD_PROXY
    env["NO_PROXY"] = env["no_proxy"] = GROQ_HOST
    env["PROMPTFOO_PYTHON"] = sys.executable  # the same Python that has the pinned requirements
    env["PYTHONPATH"] = str(PROJECT_ROOT / "src")
    env[OUT_DIR_ENV] = str(out_dir)
    env["PROMPTFOO_CONFIG_DIR"] = str(out_dir / "promptfoo-home")  # Promptfoo's own files stay in this run's folder
    return env


_CASE_ID = re.compile(r"[A-Z]{2}-\d{1,2}")


def case_filter(cases: str) -> list[str]:
    """Promptfoo arguments to run only some cases, from text like "TI-1, BD-1". Empty text = all cases.
    Only IDs of the form AB-1 are accepted, so the text can't add anything else to the command."""
    ids = [c.strip().upper() for c in (cases or "").split(",") if c.strip()]
    bad = [c for c in ids if not _CASE_ID.fullmatch(c)]
    if bad:
        raise ValueError(f"not a case ID: {', '.join(bad)} (use IDs like TI-1, BD-2)")
    return ["--filter-pattern", "^(" + "|".join(ids) + "):"] if ids else []


def promptfoo_command(out_dir: Path, cases: str = "") -> list[str]:
    """The eval command: our fixed cases only (no `redteam generate`), no cache, no sharing, no results database,
    one case at a time, report as JSON in this run's folder."""
    binary = REDTEAM_DIR / "node_modules" / ".bin" / "promptfoo"
    return [str(binary), "eval", "-c", str(CONFIG_FILE), "-o", str(out_dir / "report.json"),
            "--no-cache", "--no-share", "--no-write", "--no-table", "--no-progress-bar",
            "--max-concurrency", "1", *case_filter(cases)]


def files_holding(out_dir: Path, secret: str) -> list[str]:
    """Names of the files under out_dir that contain secret. Only names are returned, never the secret."""
    if not secret:
        return []
    found = []
    for path in sorted(Path(out_dir).rglob("*")):
        if path.is_file():
            try:
                if secret in path.read_text(encoding="utf-8", errors="ignore"):
                    found.append(str(path.relative_to(out_dir)))
            except OSError:
                continue
    return found


def summary_rows(report: dict) -> list[dict]:
    """One row per case from Promptfoo's JSON report: verdict and, for a failed check, its reason."""
    rows = []
    for item in report.get("results", {}).get("results", []):
        vars_ = item.get("vars") or (item.get("testCase") or {}).get("vars") or {}
        output = (item.get("response") or {}).get("output")
        try:
            evidence = json.loads(output) if isinstance(output, str) else {}
        except ValueError:
            evidence = {}
        error = item.get("error") or (item.get("response") or {}).get("error")
        checks = ((item.get("gradingResult") or {}).get("componentResults")) or []
        failed = [f"{(c.get('assertion') or {}).get('metric', '?')}: {c.get('reason', '')}"
                  for c in checks if not c.get("pass")]
        if item.get("failureReason") == 2 or (not evidence and error):  # 2 = Promptfoo's "error", not a failed check
            verdict = "NOT TESTED"
        else:
            verdict = "PASS" if checks and not failed else "FAIL"
        rows.append({
            "case": vars_.get("case_id", "?"), "category": vars_.get("category", ""),
            "attack": vars_.get("attack", ""), "verdict": verdict, "result": evidence.get("result", "-"),
            "steps": evidence.get("steps_used", "-"), "tokens": evidence.get("tokens", 0),
            "why": "; ".join(failed) if failed else (str(error)[:200] if verdict == "NOT TESTED" else ""),
        })
    return rows


def summary_text(rows: list[dict], key_files: list[str]) -> str:
    """The plain summary the notebook prints."""
    lines = [f"{'Case':6} {'Verdict':11} {'Result':15} {'Steps':5} {'Tokens':>7}  Attack"]
    for r in rows:
        lines.append(f"{r['case']:6} {r['verdict']:11} {str(r['result']):15} {str(r['steps']):5} "
                     f"{r['tokens']:>7,}  {r['attack']}")
        if r["why"]:
            lines.append(f"{'':6} why: {r['why']}")
    counts = {v: sum(r["verdict"] == v for r in rows) for v in ("PASS", "FAIL", "NOT TESTED")}
    lines.append("")
    lines.append(f"{len(rows)} cases: {counts['PASS']} passed, {counts['FAIL']} failed, "
                 f"{counts['NOT TESTED']} not tested. Tokens used: {sum(r['tokens'] for r in rows):,}.")
    lines.append("Key check: " + ("FOUND in " + ", ".join(key_files) if key_files
                                  else "the key's text is in none of the saved files."))
    return "\n".join(lines)
