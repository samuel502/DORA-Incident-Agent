"""Scenario briefings for the sample cases, like a tabletop exercise (Sam, 16 November 2026).

When a person picks a sample on the page, they play the incident manager. The briefing tells them what that
person knows: plain sentences built from the case's human_answers in cases/scenarios/index.json.

How the answer key stays away from the agent:
- Only this module reads the index, and only when a developer runs it:
      python -m dora_agent.evaluation.briefings
  It writes cases/briefings.json. The page reads that file, never the index (block 6 plan, section 1).
- The briefing file holds the briefing sentences only: no expected result, no reasons, no real case names,
  no service ID. A test checks this, and that the file matches the index.
- The affected service is named by its plain name from the (synthetic) service list, for example
  "The affected service is Online banking." (Sam, 16 November 2026), so the person can answer the service
  question when several services match.
- The briefing is for the person only. It is never given to the AI, the tools or the decision log.
  Tests check that no briefing sentence appears in any AI request or in the decision log.

The sentences are fixed here, one pair per fixed question (agent/questions.py). Each sentence says what the
person knows, in the sense of that question's answer. A test checks every question has its sentences.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from dora_agent.config import PROJECT_ROOT
from dora_agent.connectors import get_service

INDEX_PATH = PROJECT_ROOT / "cases" / "scenarios" / "index.json"
BRIEFINGS_PATH = PROJECT_ROOT / "cases" / "briefings.json"

ROLE = "Your role: incident manager at Rheinbank. What you know so far:"
CLOSING = "Anything not listed: answer unsure. For a number or a time, leave the box empty."
ABOUT = ("SYNTHETIC DATA. Scenario briefings for the sample cases, for the person using the page only. Generated "
         "by `python -m dora_agent.evaluation.briefings` from the human_answers in cases/scenarios/index.json. "
         "No expected results, no reasons, no real case names. Never given to the AI, the tools or the decision "
         "log. Do not edit by hand: a test checks this file against the index.")

# Yes/no questions: (sentence for "yes", sentence for "no"), in the sense of the fixed question's wording.
YES_NO: dict[str, tuple[str, str]] = {
    "planned_and_announced": ("This downtime was planned and announced to clients in advance.",
                              "This downtime was not planned and announced to clients in advance."),
    "critical_or_important": ("The service supports a critical or important function of Rheinbank.",
                              "The service does not support a critical or important function of Rheinbank."),
    "regulated_service": ("The service is a financial service that needs authorisation or registration, or is "
                          "supervised.",
                          "The service is not a financial service that needs authorisation or registration, and "
                          "it is not supervised."),
    "malicious_access": ("It is confirmed that someone got in: a successful, malicious and unauthorised access.",
                         "No one got in: there was no successful, malicious and unauthorised access."),
    "access_on_own_systems": ("Rheinbank's own systems were accessed.",
                              "Only a supplier's systems were accessed, not Rheinbank's own systems."),
    # The question is "Can you rule out that data could have been affected by this access?"
    "access_may_cause_data_loss": ("You can rule out that data could have been affected by this access.",
                                   "You cannot rule out that data could have been affected by this access."),
    "relevant_parties_affected": ("Clients or financial counterparts that Rheinbank has marked as relevant were "
                                  "affected.",
                                  "No clients or financial counterparts that Rheinbank has marked as relevant were "
                                  "affected."),
    "media_coverage": ("The incident has been reported in the media.",
                       "The incident has not been reported in the media."),
    "repeated_complaints": ("Different clients or counterparts have complained repeatedly about it.",
                            "There have been no repeated complaints from different clients or counterparts."),
    "regulatory_requirements_impact": ("Because of this incident, Rheinbank cannot meet, or likely cannot meet, a "
                                       "regulatory requirement.",
                                       "The incident does not stop Rheinbank from meeting its regulatory "
                                       "requirements."),
    "client_loss_impact": ("Rheinbank will lose, or likely lose, clients or counterparts because of this incident, "
                           "with a material impact on its business.",
                           "Rheinbank does not expect to lose clients or counterparts because of this incident."),
    "data_availability_impact": ("Data became temporarily or permanently inaccessible or unusable.",
                                 "No data became inaccessible or unusable."),
    "data_authenticity_impact": ("The trustworthiness of a data source was compromised.",
                                 "The trustworthiness of data sources was not compromised."),
    "data_integrity_impact": ("Data was changed without authorisation, so it is now inaccurate or incomplete.",
                              "No data was changed without authorisation."),
    "data_confidentiality_impact": ("Data was accessed by or disclosed to an unauthorised party or system.",
                                    "No data was accessed by or disclosed to an unauthorised party or system."),
    "data_impact_adverse": ("This data impact has hurt, or will hurt, Rheinbank's business objectives or its "
                            "ability to meet regulatory requirements.",
                            "This data impact does not hurt Rheinbank's business objectives or its ability to meet "
                            "regulatory requirements."),
}


def _number(value: Any) -> str:
    return f"{value:,}" if isinstance(value, int) and not isinstance(value, bool) else str(value)


# Number and time questions: the sentence for a given value. "estimate" adds "about" and "(an estimate)".
VALUES: dict[str, Callable[[str], str]] = {
    "costs_eur": lambda v: f"Costs and losses so far are {v} euros, counted gross.",
    "affected_clients": lambda v: f"{v} clients were affected.",
    "affected_counterparts": lambda v: f"{v} financial counterparts with a contract with Rheinbank were affected.",
    "resolved_at": lambda v: f"The incident was resolved, or is expected to be resolved, at {v}.",
}


class BriefingProblem(ValueError):
    """The index has an answer the briefing can't put in a sentence. Plain message."""


def sentence(fact_name: str, entry: Any) -> str:
    """One briefing sentence for one human answer from the index."""
    answer, estimate = (entry.get("answer"), bool(entry.get("estimate"))) if isinstance(entry, dict) else (entry, False)
    if fact_name in YES_NO:
        if answer not in ("yes", "no"):
            raise BriefingProblem(f"{fact_name}: a briefing answer must be yes or no, not {answer!r}")
        return YES_NO[fact_name][0 if answer == "yes" else 1]
    if fact_name in VALUES:
        text = VALUES[fact_name](("about " if estimate else "") + _number(answer))
        return text[:-1] + " (an estimate)." if estimate else text
    raise BriefingProblem(f"{fact_name}: no briefing sentence for this answer")


def service_sentence(service_id: str) -> str:
    """The affected service by its plain name from the service list, never its ID."""
    found = get_service(service_id)
    if not found.found:
        raise BriefingProblem(f"{service_id!r} is not in the service list")
    return f"The affected service is {found.service.name}."


def briefing_lines(human_answers: dict[str, Any], service_id: str) -> list[str]:
    """The briefing for one case: role, the affected service, one line per answer (in the index's order),
    closing line."""
    return [ROLE, f"- {service_sentence(service_id)}",
            *(f"- {sentence(name, entry)}" for name, entry in human_answers.items()), CLOSING]


def build(index_path: Path = INDEX_PATH) -> dict[str, Any]:
    index = json.loads(index_path.read_text(encoding="utf-8"))
    return {"about": ABOUT,
            "briefings": {s["scenario_id"]: briefing_lines(s.get("human_answers") or {}, s["service_id"])
                          for s in index["scenarios"]}}


def write(path: Path = BRIEFINGS_PATH, index_path: Path = INDEX_PATH) -> None:
    path.write_text(json.dumps(build(index_path), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    write()
    print(f"Wrote {BRIEFINGS_PATH.relative_to(PROJECT_ROOT).as_posix()}")
