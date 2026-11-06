"""The fixed questions the agent may put to a human, and how each answer becomes a fact.

The wording is fixed here in code. The LLM only chooses WHICH question to ask, never what it says,
so a hostile ticket cannot change a question (security framework, prompt injection), and the
same situation always gets the same question.

Every judgment call in docs/dora-rules.md section 7 has a question here, plus a few facts the
systems may not hold (costs, estimates, an unknown service rating).
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from dora_agent.agent.values import ValueProblem, parse_value
from dora_agent.rules.facts import HUMAN_CONFIRMED

YesNoUnsure = Literal["yes", "no", "unsure"]


class Question(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    fact_name: str  # also the question's id
    text: str  # shown to the human exactly like this
    basis: str  # rule sheet section and article, shown next to the question
    # For yes/no questions: what each answer means for the fact. None = stays unknown.
    meaning: dict[str, bool | None] | None = None
    allows_estimate: bool = False


def _yes_no(fact_name, text, basis) -> Question:
    # Default: yes -> true, no -> false, unsure -> stays unknown (section 7: never guessed).
    return Question(fact_name=fact_name, text=text, basis=basis,
                    meaning={"yes": True, "no": False, "unsure": None})


QUESTIONS: dict[str, Question] = {
    q.fact_name: q
    for q in [
        # Step 0: is it an incident at all? (DORA Art. 3(8), open question 5)
        _yes_no("planned_and_announced",
                "Was this downtime planned and announced to clients in advance?",
                "Open question 5, DORA Art. 3(8)"),
        # Gate (section 2)
        _yes_no("critical_or_important",
                "Does this service support a critical or important function of Rheinbank?",
                "Section 2, G-a, RTS-C Art. 6(a)"),
        _yes_no("regulated_service",
                "Is this a financial service that needs authorisation or registration, or is supervised?",
                "Section 2, G-b, RTS-C Art. 6(b)"),
        _yes_no("malicious_access",
                "Is it confirmed that someone got in: a successful, malicious and unauthorised access "
                "(not just a blocked attempt)?",
                "Section 2, G-c, and T5-b, RTS-C Art. 6(c), Art. 9(5)(b)"),
        _yes_no("access_on_own_systems",
                "Were Rheinbank's own systems accessed (not only a supplier's systems)?",
                "Open question 4, RTS-C Art. 6(c)"),
        # T5-b: wording agreed with Sam. "Can rule it out" means the access cannot lead to data losses.
        # "No" or "unsure" means it can't be ruled out, so the access MAY result in data losses.
        Question(fact_name="access_may_cause_data_loss",
                 text="Can you rule out that data could have been affected by this access?",
                 basis="Section 3, T5-b, RTS-C Art. 9(5)(b): 'may result in data losses'",
                 meaning={"yes": False, "no": True, "unsure": True}),
        # T1-f
        _yes_no("relevant_parties_affected",
                "Were any clients or financial counterparts affected that Rheinbank has marked as relevant?",
                "Section 3, T1-f, RTS-C Art. 1(3)"),
        # T2 (all four points)
        _yes_no("media_coverage", "Has the incident been reported in the media?",
                "Section 3, T2-a, RTS-C Art. 9(2), Art. 2"),
        _yes_no("repeated_complaints",
                "Have different clients or counterparts complained repeatedly about it?",
                "Section 3, T2-b, RTS-C Art. 9(2), Art. 2"),
        _yes_no("regulatory_requirements_impact",
                "Because of this incident, can Rheinbank not meet, or likely not meet, a regulatory requirement?",
                "Section 3, T2-c, RTS-C Art. 9(2), Art. 2"),
        _yes_no("client_loss_impact",
                "Will Rheinbank lose, or likely lose, clients or counterparts because of this incident, "
                "with a material impact on its business?",
                "Section 3, T2-d, RTS-C Art. 9(2), Art. 2"),
        # T5-a
        _yes_no("data_availability_impact",
                "Did data become temporarily or permanently inaccessible or unusable?",
                "Section 3, T5-a, RTS-C Art. 5 (availability)"),
        _yes_no("data_authenticity_impact",
                "Was the trustworthiness of a data source compromised?",
                "Section 3, T5-a, RTS-C Art. 5 (authenticity)"),
        _yes_no("data_integrity_impact",
                "Was data changed without authorisation, so it is now inaccurate or incomplete?",
                "Section 3, T5-a, RTS-C Art. 5 (integrity)"),
        _yes_no("data_confidentiality_impact",
                "Was data accessed by or disclosed to an unauthorised party or system?",
                "Section 3, T5-a, RTS-C Art. 5 (confidentiality)"),
        _yes_no("data_impact_adverse",
                "Has this data impact hurt, or will it hurt, Rheinbank's business objectives or its ability "
                "to meet regulatory requirements?",
                "Section 3, T5-a, RTS-C Art. 9(5)(a)"),
        # Numbers the systems may not have. Estimates are allowed and marked (open question 2).
        Question(fact_name="costs_eur",
                 text="What are the costs and losses so far, in euros? Count them gross, without subtracting "
                      "recoveries. An estimate is fine.",
                 basis="Section 3, T6, RTS-C Art. 9(6), Art. 7", allows_estimate=True),
        Question(fact_name="affected_clients",
                 text="How many clients were affected? An estimate from comparable periods is fine.",
                 basis="Section 3, T1, RTS-C Art. 1(5)", allows_estimate=True),
        # Block 5 step 5: needed to rule out T1-c when client data has no counterpart count (cases N03, N06).
        Question(fact_name="affected_counterparts",
                 text="How many financial counterparts with a contract with Rheinbank were affected? "
                      "Answer 0 if none. An estimate from comparable periods is fine.",
                 basis="Section 3, T1-c, RTS-C Art. 9(1)(c), Art. 1(2), Art. 1(5)", allows_estimate=True),
        Question(fact_name="resolved_at",
                 text="When was the incident resolved, or when do you expect it to be? "
                      "Give date, time and time zone. An estimate is fine.",
                 basis="Section 3, T3-a, RTS-C Art. 3(1)", allows_estimate=True),
    ]
}


class AnswerProblem(ValueError):
    """The answer does not fit the question. Plain message, safe to show."""


def question_for(fact_name: str) -> Question:
    if fact_name not in QUESTIONS:
        raise AnswerProblem(f"there is no fixed question for {fact_name[:60]!r}")
    return QUESTIONS[fact_name]


def interpret_answer(fact_name: str, answer: Any) -> Any:
    """The fact value an answer stands for, or None if the answer leaves it unknown ("unsure")."""
    question = question_for(fact_name)
    if question.meaning is not None:
        if answer not in question.meaning:
            raise AnswerProblem(f"answer to {fact_name} must be one of: yes, no, unsure")
        return question.meaning[answer]
    try:
        return parse_value(fact_name, answer)
    except ValueProblem as problem:
        raise AnswerProblem(str(problem)) from None


def missing_judgment_questions() -> set[str]:
    """Section 7 judgment calls that have no fixed question (should always be empty; a test checks)."""
    return set(HUMAN_CONFIRMED) - set(QUESTIONS)
