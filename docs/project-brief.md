# Project brief: DORA Incident Classification Agent

## The problem

DORA is an EU law that makes banks and other financial companies keep working when their IT breaks or gets attacked. It applies since 17 January 2025.

When a bank has an IT incident, DORA forces it to:

1. Decide quickly if the incident is "major" under fixed criteria
2. If it is major, report it to its regulator within hours (in Germany that's BaFin)
3. Be able to prove later why it classified the incident that way

In practice this is hard. The facts are spread across tickets, logs, monitoring tools and people's heads. The rules have several criteria that combine in a specific way. And it all happens under time pressure. Banks risk classifying wrong, reporting late, or not being able to explain their decision.

## What the tool does

You give it a short note about an incident. It gives back a classification with reasons and a draft report, ready for a human to approve.

1. The user pastes an incident note, or picks a sample incident.
2. The agent pulls the facts out of the text.
3. It sees what's missing and looks it up in the bank's (simulated) systems. If it can't find something, it asks the user.
4. Once the facts are in, the rules engine decides: major or not major.
5. The tool shows the decision, the reason for each part, and the DORA article behind it.
6. If major, it drafts the initial notification.
7. A human approves or corrects it. Nothing is sent anywhere.

## Two kinds of information

1. **Facts about this incident.** These come from the bank's systems: which service was hit, whether it's critical, how many clients were affected, how long it was down, which countries, whether data was lost or stolen, public attention, costs.
2. **The DORA rulebook.** The same for every incident. It lives in two places:
   - In the rules engine, as code. This makes the decision.
   - In the agent's instructions, as a checklist of which facts to look for. This guides the search. It decides nothing.

## The role of the AI

The AI does what plain code is bad at:

- Reading messy text and turning it into clean facts
- Working out which facts are missing and where to find them
- Asking clear questions
- Writing the draft report

The AI does not decide whether the incident is major. Fixed rules do that, so the answer is the same every time and an auditor can check it.

## The agentic part

The agent has one goal: collect enough facts to classify the incident. It has a toolbox and decides on its own which tool to use next, based on what it knows and what's missing.

| Tool | What it gives the agent |
|---|---|
| Service list | Is this service critical? |
| Monitoring | When it went down and came back |
| Client data | How many clients and payments were hit |
| Security alerts | Signs of hacking or stolen data |
| Supplier register | Which outside company runs the system |
| Ask the human | Anything the systems can't answer |
| Run the rules | The decision, once enough facts are in |
| Draft notification | Only if the result is major |

Different incidents take different paths. Examples:

- **"Online banking down since 9:10, customers can't log in."** Service list (critical), client data, monitoring, security alerts (nothing), run the rules. Major.
- **"HR portal is slow this morning."** Service list (not critical), security alerts (no successful access on record), one question to the human (was there a successful malicious access?), run the rules. Not major, about four steps. It can't stop after the service list, because a malicious access would pass the gate even for a non-critical service, and only a human may rule that out: a missing security alert alone is never enough.
- **"SOC flagged a large data transfer at 2 a.m."** Security alerts first, then service list, then supplier register, then asks the human if customer data left the bank.

A fixed script would run every step every time. The agent skips, digs deeper or asks, depending on the incident. The screen shows a trace of every step and why the agent took it.

## The simulated bank

Rheinbank has small fake versions of real bank systems. Each is a data file plus a lookup function the agent calls through a connector.

| Fake system | Real-world equivalent |
|---|---|
| Service list | CMDB, e.g. ServiceNow |
| Monitoring | Monitoring tools, e.g. Dynatrace |
| Client data | Core banking system |
| Security alerts | SIEM, e.g. Splunk or Sentinel |
| Supplier register | DORA's register of ICT third-party providers |

**The connector** works like a waiter. The agent asks a question. The connector knows where the answer lives and brings it back. Today it reads our fake files. In a real bank, it would read the real systems instead, and the agent would not change. The connector is also a security wall: the agent can only ask allowed questions and can only read.

## Scenarios and test cases

Scenarios are based on real, documented incidents wherever possible: regulator notices (e.g. the FCA final notice on TSB's 2018 IT migration), the ESAs' 2025 report on major ICT incidents under DORA, and well-documented outages and breaches. Each real case is mapped to DORA by hand, with sources and article numbers. From each real case we make variations (missing facts, different numbers, confusing wording) to get a large test set.

We do not train or fine-tune a model. The real cases are used to:

1. Test the tool against known correct answers
2. Create variations for broader testing
3. Give the agent a few examples of good handling (kept separate from the test set)

## What the user sees

- The facts found, each marked with its source (ticket, a system, or the user)
- The decision with reasons and article numbers
- A draft initial notification, if major
- The step-by-step trace

## Why use this instead of a general AI chat

A chat only knows what you paste in, can answer differently each time, and leaves no reliable record of how it decided. This tool pulls facts from the bank's systems, decides with fixed and tested rules, and records every step for the auditor.

## Who it's for

- **Users:** incident managers and compliance staff at a bank
- **Portfolio audience:** PwC Germany roles in GenAI & Agentic AI Financial Services, GRC Technology and IT Compliance

## What it shows

- Working knowledge of DORA incident classification
- Agent design: tools, loop, stop rules, human approval
- Knowing when to use AI and when to use fixed rules
- Testing an AI system against known answers
- Security: prompt injection defense, read-only tools, data minimization
- Explaining a technical system to a business audience

## What it is not

- Not a production system
- Not legal advice
- Not connected to any real bank or regulator
