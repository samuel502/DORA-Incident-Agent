# Build contract

Status: APPROVED by Sam, 4 November 2026.

## Goal

A working prototype of a DORA incident classification agent for a simulated bank, built to portfolio quality: tested, secure, honest about its limits.

## In scope

- Gradio interface: paste an incident or pick a sample
- Agent loop with the tools listed in `docs/project-brief.md`
- Simulated Rheinbank systems behind connectors (read-only)
- Rules engine in plain Python, built only from `docs/dora-rules.md`
- Output: facts with sources, classification with reasons and article numbers, step trace
- Draft initial notification for major incidents, for human approval only
- Case library based on real, documented incidents, plus variations
- Test suite: correctness tests and security tests
- Security checks from `docs/security-framework.md`, automated in GitHub Actions
- README with measured results and honest limits

## Out of scope

- Real bank data or real customer data
- Sending anything to a regulator or anyone else
- Intermediate and final reports (only the initial notification is drafted)
- Training or fine-tuning a model
- User accounts, logins, deployment as a hosted service
- Write access of any kind to the simulated systems

## Decisions (confirmed)

- Runs in Google Colab only, like Sam's OSINT project: open the notebook, add your own Groq key in Colab Secrets, run the cells. No local launch. The key is never saved anywhere. The offline pytest suite still runs on a development machine. Live tests run from a Colab notebook cell. Changed 6 November 2026, approved by Sam (replaces "runs locally and in Google Colab from the same code").
- LLM: Groq, `openai/gpt-oss-120b`, behind a swappable provider interface
- Output as described above
- Out-of-scope list as above

## Build order

Each block is built, explained, tested by Sam and approved before the next one starts.

1. Rule sheet (`docs/dora-rules.md`), from official texts with article references. Sam spot-checks.
2. Case library: real incidents mapped to DORA, with sources.
3. Simulated bank data and connectors.
4. Rules engine plus its tests.
5. Agent loop with tools, limits and logging.
5b. Draft initial notification (major incidents only, for human approval), with the initial notification deadline and a warning that the weekend and bank holiday rules are not handled. Added 5 November 2026, approved by Sam.
6. Gradio interface with trace view.
7. Security tests and automated checks.
8. Full test run, results recorded.
9. README and repo cleanup.

## Definition of done

- Rules engine passes every hand-checked case in the library
- Agent picks different tool paths for different incidents, shown in tests
- All security tests pass, including prompt injection hidden in tickets and logs
- No secrets in the repo (scanner clean)
- Runs in Colab with the documented steps (short Colab guide in the README)
- README states measured results, how to run it, and its limits
- Sam has reviewed and approved every block

## Lessons from the previous project, built in

- Scope is locked here first. Changes go through this file.
- No dependence on outside websites that can block or rate-limit us.
- "Works" is defined by tests with known answers.
- The README is written last, from what actually works. A short placeholder README (what the tool is, work in progress, Colab only) exists from block 6. The full README is block 9.

## Lessons from Sam's OSINT project, built into the interface (added 8 November 2026, approved by Sam)

- The page is launched with `share=False`, `server_name="0.0.0.0"`, `inline=False`, `prevent_thread_lock=True` and `ssr_mode=False`, and shown inside the notebook with `google.colab.output.serve_kernel_port_as_iframe`. No public link.
- Re-running the launch cell closes the old server first.
- The launch function returns nothing, so Colab does not print the Blocks object.
- Every agent run has a hard total time limit, set in config.
- All requirements are pinned to exact versions.
- The notebook's first markdown cell has a troubleshooting section: third-party cookies, fresh runtime, re-running only the launch cell, the key secret with notebook access, VPN access errors.
