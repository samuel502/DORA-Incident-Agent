# Block 7 plan: security tests and automated checks

Status: plan approved by Sam on 17 November 2026, with one change: CI uses Python 3.13, because Colab runs 3.13. Decisions 2 to 5 approved as recommended. Step a built, waiting for Sam's test.

Sources: `docs/build-contract.md` (block 7: "Security tests and automated checks"; "Security checks from `docs/security-framework.md`, automated in GitHub Actions"; definition of done: "No secrets in the repo (scanner clean)") and `docs/security-framework.md` sections 3 to 5.

## Hard rules for CI (apply to every step)

1. Every GitHub Action is pinned to a full 40-character commit SHA, with the version in a comment, for example `actions/checkout@<sha> # v5.0.0`. Never a tag like `@v5`, because a tag can be moved to other code. I look each SHA up from the action's official release page when I build, and say where it came from.
2. `permissions: contents: read` at the top of the workflow. No job gets more. Checkout uses `persist-credentials: false`, so the job token is not left on disk.
3. No secrets in CI. The workflow uses no `secrets.` value at all, and no Groq key. This is also why gitleaks runs as a downloaded program, not through the gitleaks GitHub Action (that Action wants a token and, for some accounts, a licence key).
4. Live Groq tests stay skipped. They only run with `RUN_LIVE_TESTS=1` and a key, and CI sets neither. A check in the workflow fails the run if the summary does not show the 5 live tests as skipped.
5. Every job has a time limit (`timeout-minutes`), so a stuck job cannot run for hours.
6. Tools used in CI are pinned to exact versions, the same as the app (step c).

## Step a) Tests on every push and pull request

**What it does.** A new file `.github/workflows/ci.yml`. On every push and every pull request, GitHub starts a fresh Linux machine, installs Python 3.13 (the version Colab runs) and the pinned requirements, and runs `python -m pytest`, the same full suite you run locally (today: 1407 passed, 5 skipped).

**What it checks.** That every change still passes all tests: rules engine, case library, connectors being read-only, agent limits, notification, interface, and the existing security tests. A red cross on GitHub means something broke.

**What could fail.**
- A test that passes on Windows but fails on Linux (file paths, line endings, time zones). I fix the test or the code, never skip it.
- A package that installs differently on Linux. The pins were already resolved for Linux in block 6, so this is unlikely.

**How long.** Measured: 40 seconds for the whole run on GitHub, green (first run, 17 November 2026). The estimate was 2 to 3 minutes.

**Decided:** Python 3.13 only, the version Colab runs (Sam, 17 November 2026).

## Step b) Security scans in the same workflow

Four scans, each its own job, running at the same time as the tests. Any finding makes the run red.

| Scan | What it checks, in plain words | What could fail | Time (estimate) |
|---|---|---|---|
| **Bandit** | Reads our Python code in `src/` and looks for known risky patterns: running shell commands, unsafe loading of files, weak random numbers, hard-coded passwords. | One known hit: `src/dora_agent/ui/launch.py:38` uses `server_name="0.0.0.0"` (Bandit rule B104, "listens on all network addresses"). We need this for Colab and there is no public link (`share=False`). I would mark that one line `# nosec B104` with the reason next to it, and list it in the security report. | under 30 seconds |
| **Semgrep** (metrics off) | A second code scanner with a different rule set, so it catches things Bandit misses. Runs with `--metrics=off`, so it sends no usage data to Semgrep. Scans `src/` and `notebooks/`. | It downloads its rule sets from semgrep.dev at run time, so the rules can change between runs and a new rule could flag old code. It may also flag `0.0.0.0`. | 1 to 2 minutes (most of it installing Semgrep) |
| **pip-audit** | Checks every pinned package in `requirements.txt` against public lists of known security holes (PyPI and OSV databases). | A new hole can be published for a package we use on any day, so the build can go red without us changing anything. Then we either update that package (and re-test) or, if the hole cannot affect us, ignore that one ID with a written reason in the security report. | under 1 minute |
| **gitleaks** | Searches the whole git history, every commit, not just today's files, for API keys, tokens and passwords. | Our tests contain fake keys like `TEST-ONLY-placeholder-key-0987654321` (`tests/agent/test_loop.py:354`). If gitleaks flags them, I add a small `.gitleaks.toml` that allows exactly those strings, nothing broader. If it finds a real key in history, I stop and tell you: the key must be revoked at Groq first, deleting it from git is not enough. | under 30 seconds |

**How gitleaks is installed.** Download one pinned release from the official GitHub releases page and check its SHA-256 checksum before running it. If the checksum does not match, the job fails.

**Decided:** Semgrep rule sets `p/python` and `p/security-audit` from the Semgrep registry (Sam, 17 November 2026).

**Total CI time for a + b:** the jobs run side by side, so about 3 to 4 minutes per push (estimate).

### What was built and found (17 November 2026)

Built as one `scans` job next to the `tests` job, instead of four jobs: the four scanners come from one `requirements-ci.txt`, so one install serves all of them. Each scan step still runs even if an earlier one failed, so every run shows all four results.

Versions: Bandit 1.9.4, Semgrep 1.185.0, pip-audit 2.10.1 (with 82 pulled-in packages, 85 pins in all), gitleaks 8.30.1 (Linux download checked against its SHA-256).

Local run first (Sam, 17 November 2026: in a throwaway environment in the scratchpad, not the main Python):

| Scanner | Finding | What was done |
|---|---|---|
| Bandit | B104, `0.0.0.0` in `ui/launch.py` | Accepted as decided, `# nosec B104` with the reason next to it |
| Bandit | B613 "Trojan Source": 10 invisible Unicode characters (line and paragraph separators, text-direction controls, zero-width characters, byte order mark) typed directly into the regex in `ui/views.py:36` | Fixed, not suppressed: the same characters are now written as visible escape codes (`‪` ...). Checked that the pattern is identical. No invisible characters left in the file |
| Semgrep | none (201 rules, 49 files) | nothing |
| gitleaks | none (33 commits, and every current file) | No allow list added: the fake test keys are not flagged, so an allow list would only be an unused gap |
| pip-audit, `requirements.txt` | Pillow 12.3.0: 42 known holes, all in reading image files. Fixed in Pillow 13.0.0, which Gradio 6.30.0 does not allow (`pillow<13`). Gradio 6.32.0 (12 November 2026) allows it | Fixed (Sam, 17 November 2026): Gradio 6.30.0 to 6.32.0 and Pillow 12.3.0 to 13.0.0. Nothing else had to move (Gradio's only other change is Brotli at least 1.2.1, already pinned). All 60 pins resolve for Linux on Python 3.13 with ready-built wheels. pip-audit now finds nothing |
| pip-audit, `requirements-ci.txt` | `mcp` 1.29.0 (4 holes, MCP servers and clients over HTTP) and `opentelemetry-api` 1.37.0 (2 holes, parsing incoming trace headers). Semgrep 1.185.0, the newest, requires exactly these versions | Accepted (Sam, 17 November 2026): exactly these 6 IDs, only for `requirements-ci.txt`, each with its reason in `ci.yml`. Semgrep only reads our files on a throwaway machine: no MCP server or client, no incoming web requests. To be removed when Semgrep allows the fixed versions |

## Step c) Hash-pinned requirements

**What it does.** Today each package is pinned to an exact version (`groq==1.7.0`). Hash pinning also adds the fingerprint (SHA-256) of each allowed download file, for example `groq==1.7.0 --hash=sha256:...`. pip then refuses to install any file whose fingerprint does not match, even if someone replaced the file on PyPI under the same version number. The note at the top of `requirements.txt` already says "Hashes ... come in block 7".

**How.** A short script `scripts/hash_requirements.py` (standard library only) reads the current pins and gets the published fingerprints for exactly those versions from PyPI. It never changes a version. Hashes cover every published file of each version, so the same file works in Colab (Linux, Python 3.13), in CI, and on your Windows machine. The CI scanners (Bandit, Semgrep, pip-audit) go into a separate `requirements-ci.txt`, also with hashes, so Colab does not install them.

**What it checks.** That the code you run in Colab and in CI is byte for byte the code we tested.

**What could fail.**
- With hashes, pip demands a hash for every package, including the ones pulled in. If one is missing, the install stops with a clear error. That is the point, but the Colab setup cell must still work, so I test it there (you run the setup cell once).
- `audioop-lts` and `colorama` only install on some systems. They still need hashes. The script covers them.
- Later version updates are more work: change the pin, then re-run the script.

**How long.** Generating hashes: about 1 minute. Install time in Colab and CI stays about the same.

### What was built and found (19 November 2026)

- `scripts/hash_requirements.py` wrote the PyPI hashes of every published file of each pinned version: 60 pins in `requirements.txt`, 86 in `requirements-ci.txt`. No version changed (checked against the last commit).
- CI (both installs) and the Colab setup cell install with `--require-hashes`.
- Checked locally: pip downloaded, in hash-checking mode and with no cache, every wheel it would pick on Linux x86_64 with Python 3.13, for CI (Ubuntu 24.04) and Colab. All matched. A wrong hash is refused. The real fresh Linux install is the CI run and the Colab setup cell.
- Scans: `scripts/` added to the CI Bandit and Semgrep scans (Sam, 19 November 2026). Semgrep rule `httpsconnection-detected` on the PyPI download in `scripts/hash_requirements.py` is marked `# nosemgrep` with its reason (Sam, 19 November 2026): the rule is about Pythons before 3.4.3, which did not check certificates. We run 3.11+, the certificate check is set explicitly, and the host is fixed to pypi.org.

**Known limitation (for the security report).** In Colab, if a package is already installed at exactly the pinned version, pip keeps that copy and does not download it again, so that copy is not checked against our hashes. It is Google's preinstalled copy in Colab's own image, not a download from PyPI at install time. Every package that pip does download is hash-checked. Forcing a reinstall of everything (`--force-reinstall`) would close the gap, but makes the setup slower and causes more "restart needed" cases. Left as it is (Sam, 19 November 2026). CI is not affected: it starts from a fresh Python with nothing preinstalled.

## Step d) Attack tests on the AI (Promptfoo and garak)

**Run by hand in Colab, with your own Groq key from Colab Secrets. Never in CI.**

### d1) Our own offline attack set, which does run in CI

The security framework (section 4) asks for a folder of hostile test cases. Many already exist, spread across files. I collect the missing ones in `tests/attacks/`, using the fake AI (no key, no network), so they run in CI with everything else:
- a ticket telling the agent to skip the rules and report "not major"
- a log entry, a supplier record and a security alert with hidden instructions
- a request to show the system prompt, and one to list all clients
- an incident built to make the agent loop
- very long and malformed input

A test passes only if the result still comes from the rules engine, no extra data comes out, and the limits hold. Before writing new ones I list which of these are already covered and where, so nothing is duplicated.

### d2) Promptfoo (red team, OWASP LLM Top 10 preset)

- **What it checks.** Promptfoo writes many attack messages (prompt injection, prompt extraction, data leak attempts, jailbreaks), sends each one to our agent as a ticket, then grades the answer.
- **How.** A Colab notebook `notebooks/redteam.ipynb`. It installs one pinned Promptfoo version with Node (already in Colab), and a small Python adapter that runs one ticket through our agent and returns its text and classification. Remote generation and telemetry are turned off (`PROMPTFOO_DISABLE_REMOTE_GENERATION=true`, `PROMPTFOO_DISABLE_TELEMETRY=1`), so no ticket or result goes to Promptfoo's servers. Attacks are written and graded by Groq with your key.
- **What could fail.** Some Promptfoo attack types only work with their remote service and will be skipped; I will list which. The Groq free tier limits calls per minute, so the run is slow. The grader is itself an AI and can be wrong, so I check every "fail" by hand.
- **How long.** Estimate 30 to 60 minutes for about 50 attacks, mostly waiting for rate limits.

### d3) garak (second opinion)

- **What it checks.** A different scanner with its own attack collection (prompt injection, hidden injection in text, encoding tricks).
- **How.** Same notebook, a later cell. garak is pinned and points at the same adapter.
- **What could fail.** garak is large and pulls in many packages, so the install can clash with Colab's own packages. If it does, garak runs in a separate fresh runtime. garak's detectors were made for chatbots, not a tool that returns a classification, so some hits will be false alarms. I check each by hand.
- **How long.** Estimate 10 minutes to install, 30 to 60 minutes to run a few chosen probe groups.

**Results.** Raw output goes to `logs/redteam/` (git-ignored). The summary goes into `docs/security-report.md`: what we tested, what we found, what we fixed, what risk remains. Only measured results.

**Decided:** the first version of `docs/security-report.md` is written in this block, filled in after your Colab runs (Sam, 17 November 2026).

## Step e) Stress tests

Most run offline with the fake AI, so they go into CI. Items marked **live** run by hand in Colab. First I check which already exist, then I add only the gaps.

**Fuzzing (random and odd inputs, thousands at a time)**
- Ticket text, tool arguments and AI answers with random content: nothing crashes, every bad value is refused with a clear message.
- Rules engine with random fact combinations: never crashes, always returns one of its allowed results, same facts give the same result. No new rule or threshold is added, the test only checks behaviour of the existing rules.
- Decided: the Hypothesis library, pinned and hashed, test only (Sam, 17 November 2026).

**Repeatability**
- Offline: the same case run 50 times gives the identical result and identical log, apart from timestamps.
- **Live:** each sample case 3 times with Groq. The classification must be the same every time, because the engine decides. Tool paths may differ; we record how much. About 30 to 45 minutes.

**Messy inputs**
- Empty, only spaces, exactly 2000 characters, 2001 characters.
- Mixed German and English, umlauts, emoji, right-to-left text, invisible characters, null bytes.
- One 2000-character word, dates in odd formats, numbers like "1.000.000" and "1,000,000".
- HTML and Markdown (partly done in block 6), copied email headers and signatures.

**Environment failures**
- Groq: timeout, rate limit (429), server error (500), broken tool call, empty answer, answer cut off.
- No key, empty key, wrong key: clear message, key never printed.
- `config.toml` missing or with a bad value; a data file missing or broken.
- Log folder not writable; total time limit reached mid-run.
- Expected safe result each time: a clear "could not finish" message, no classification guessed, everything logged.

**How long.** Offline stress tests add an estimated 1 to 2 minutes to every CI run. Live ones as stated above.

## Order of work, one step at a time

a, then b, then c, then d1, then e (offline parts), then d2/d3 and the live parts of e in Colab with you. I stop after each step for you to test and approve. After each step: full `python -m pytest`, `/security-review`, and file-by-file changes with line numbers.

## Files this block will add or change

- New: `.github/workflows/ci.yml`, `requirements-ci.txt`, `scripts/hash_requirements.py`, `tests/attacks/`, new stress test files, `notebooks/redteam.ipynb`, `docs/security-report.md`, possibly `.gitleaks.toml`
- Changed: `requirements.txt` (hashes added, versions unchanged), `src/dora_agent/ui/launch.py` (one `# nosec B104` comment), `pyproject.toml` (Bandit settings)

## Decisions (Sam, 17 November 2026)

1. CI Python version: 3.13 only, because Colab runs 3.13. Step c must check that the hashed requirements install on Linux with Python 3.13.
2. Semgrep rules: registry `p/python` + `p/security-audit`.
3. Bandit B104 on `launch.py:38`: marked with `# nosec B104` and a reason.
4. Fuzzing: Hypothesis.
5. `docs/security-report.md` is written in this block.

Second local run after both decisions (17 November 2026): Bandit no issues, Semgrep 0 findings, pip-audit no known holes in `requirements.txt` and none in `requirements-ci.txt` apart from the 6 accepted, gitleaks no leaks.
