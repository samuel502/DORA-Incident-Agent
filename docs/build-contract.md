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

- Runs locally and in Google Colab from the same code
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
6. Gradio interface with trace view.
7. Security tests and automated checks.
8. Full test run, results recorded.
9. README and repo cleanup.

## Definition of done

- Rules engine passes every hand-checked case in the library
- Agent picks different tool paths for different incidents, shown in tests
- All security tests pass, including prompt injection hidden in tickets and logs
- No secrets in the repo (scanner clean)
- Runs locally and in Colab with the documented steps
- README states measured results, how to run it, and its limits
- Sam has reviewed and approved every block

## Lessons from the previous project, built in

- Scope is locked here first. Changes go through this file.
- No dependence on outside websites that can block or rate-limit us.
- "Works" is defined by tests with known answers.
- The README is written last, from what actually works.
