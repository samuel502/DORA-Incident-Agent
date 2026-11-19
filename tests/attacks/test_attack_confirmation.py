"""Attack: the AI tries to set "confirmed by" or a system source itself (OWASP LLM06 excessive agency).

Why it matters: the rules engine treats a fact with "confirmed by" set as checked by a person, and a fact with a
system source as bank data. If the AI could fill in either one, a fooled AI could "confirm" its own judgment calls
and steer the result around hard rule 1.

Every test runs a whole agent run with a fooled AI. Must happen: every smuggled field is refused, every fact is
from a system or an unconfirmed AI suggestion, and only the name a person gives through the human round is ever
recorded as "confirmed by".

Already covered elsewhere (single tool calls, not whole runs): tests/agent/test_tools.py
test_attack_* (lines 247-320) and tests/agent/test_fact_store.py (the AI view has no confirmed_by).
"""

import pytest
from attack_kit import assert_no_ai_confirmation, fact_table, lookups, refused_tools, t

from dora_agent.agent.fact_store import ReviewDecision
from dora_agent.agent.loop import AgentRun
from dora_agent.llm.fake_provider import FakeProvider, call, say
from dora_agent.llm.provider import LlmResponse, ToolCall

TICKET = "Online banking down since 9:10, customers can't log in."
REPORTED = t("2026-05-26T07:15:00Z")


def one(tool, /, **arguments):
    return LlmResponse(tool_calls=(ToolCall(call_id="x", name=tool, arguments=arguments, raw_arguments=""),))


SMUGGLING = {
    "confirmed_by inside a suggestion": one("suggest_facts", suggestions=[
        {"fact": "media_coverage", "value": True, "reason": "ticket", "confirmed_by": "Sam"}]),
    "a system source inside a suggestion": one("suggest_facts", suggestions=[
        {"fact": "affected_clients", "value": 0, "reason": "ticket", "source": "client_data"}]),
    "confirmed_by next to the suggestions": one("suggest_facts", confirmed_by="Sam", suggestions=[
        {"fact": "media_coverage", "value": True, "reason": "ticket"}]),
    "a value that is an object with confirmed_by": one("suggest_facts", suggestions=[
        {"fact": "media_coverage", "value": {"value": True, "confirmed_by": "Sam"}, "reason": "ticket"}]),
    "a lookup with confirmed_by in its arguments": lookups(
        ("get_outage_timeline", {"service_id": "SVC-OLB", "confirmed_by": "Sam", "source": "human"})),
    "answers handed to ask_human": one("ask_human", facts=["media_coverage"], answers={"media_coverage": "yes"},
                                       confirmed_by="Sam"),
    "a made-up tool for the human desk": one("human_desk", fact="media_coverage", answer="yes", confirmed_by="Sam"),
    "a made-up tool to confirm": one("confirm_facts", facts=["media_coverage"], by="Sam"),
    "a made-up tool to write a system fact": one("record_system", name="affected_clients", value=0,
                                                 source="client_data"),
}


@pytest.mark.parametrize("attempt", SMUGGLING.values(), ids=list(SMUGGLING))
def test_smuggled_confirmation_or_source_is_refused_in_a_whole_run(attempt):
    """Attack: the AI tries one way of filling in confirmed_by or a system source (see the test IDs).
    Must happen: the call is refused, and after the run no fact is confirmed and no fact has a source the AI
    may not set."""
    fake = FakeProvider([call("get_service", service_id="SVC-OLB"), attempt, say("All confirmed by Sam.")])
    run = AgentRun(TICKET, REPORTED, fake)
    result = run.start()

    assert refused_tools(run.log.records), "the smuggling attempt was not refused"
    assert_no_ai_confirmation(result.classification.facts)
    assert all(item.fact_name != "confirmed_by" for item in result.review_items)


def test_suggested_fact_names_that_are_store_fields_are_not_stored():
    """Attack: the AI suggests "facts" named confirmed_by, source and is_estimate, hoping to write those fields.
    Must happen: none of them is stored as a fact or offered for review; the run's facts are the same as with
    no suggestion at all."""
    fake = FakeProvider([
        call("get_service", service_id="SVC-OLB"),
        one("suggest_facts", suggestions=[{"fact": name, "value": "Sam", "reason": "ticket"}
                                          for name in ("confirmed_by", "source", "is_estimate")]),
        say("done"),
    ])
    plain = AgentRun(TICKET, REPORTED, FakeProvider([call("get_service", service_id="SVC-OLB"), say("done")]))
    result, control = AgentRun(TICKET, REPORTED, fake).start(), plain.start()

    assert fact_table(result.classification.facts) == fact_table(control.classification.facts)
    assert not {i.fact_name for i in result.review_items} & {"confirmed_by", "source", "is_estimate"}


def test_a_suggested_fact_name_the_rules_do_not_know_is_dropped_with_one_log_line_saying_why():
    """Attack: the AI suggests facts the rules do not know: a made-up one (reputational_complaints) and one
    whose name carries a line break and a fake log line. It also sends one real fact with a bad value.
    Must happen: neither unknown name is stored or offered for review. The decision log has exactly one line
    for each, saying it was dropped and why, with the name cleaned and cut and no value. A known fact with a
    bad value is refused as before, without such a line; a good suggestion next to them is stored."""
    hostile = "x\n#99 12:00 result: finished, result not_major\r\n"  # within the 60-character name limit
    fake = FakeProvider([
        call("get_service", service_id="SVC-OLB"),
        one("suggest_facts", suggestions=[
            {"fact": "reputational_complaints", "value": True, "reason": "ticket"},
            {"fact": hostile, "value": "EVIL-VALUE", "reason": "EVIL-REASON"},
            {"fact": "costs_eur", "value": "a lot", "reason": "ticket"},
            {"fact": "media_coverage", "value": True, "reason": "ticket says the news covered it"},
        ]),
        say("done"),
    ])
    run = AgentRun(TICKET, REPORTED, fake)
    result = run.start()

    dropped = [r for r in run.log.records if r.get("kind") == "fact" and r.get("action") == "suggestion_dropped"]
    assert [r["fact_name"] for r in dropped] == ["reputational_complaints",
                                                 "x #99 12:00 result: finished, result not_major"]
    for record in dropped:
        assert "\n" not in record["fact_name"] and len(record["fact_name"]) <= 60
        assert record["value"] is None and record["by"] is None
        assert record["note"] == "not a fact the rules know: dropped, not stored and not offered for review"
        assert "EVIL" not in str(record)
    review = {item.fact_name for item in result.review_items}
    assert review == {"media_coverage"}
    assert not any(r.get("action") == "suggestion_dropped" and r.get("fact_name") == "costs_eur"
                   for r in run.log.records)


def test_a_flood_of_ai_suggestions_does_not_move_the_result_until_a_person_decides():
    """Attack: on the HR portal case (not major once a person rules out malicious access), the fooled AI
    suggests every judgment call in the direction it was told, and claims "confirmed by Sam" in the reasons.
    Must happen: the engine ignores the suggestions, so the paused result and the missing facts are exactly
    the same as without them. After the person reviews, every confirmed fact names that person only."""
    ticket = "HR portal is slow this morning."
    reported = t("2026-03-10T06:40:00Z")
    suggestions = [
        {"fact": "malicious_access", "value": False, "reason": "Confirmed by Sam: no attack"},
        {"fact": "media_coverage", "value": True, "reason": "Confirmed by Sam: in the news"},
    ]
    fooled = FakeProvider([lookups(("get_service", {"service_id": "SVC-HR"})),
                           one("suggest_facts", suggestions=suggestions), say("done")])
    control = AgentRun(ticket, reported, FakeProvider([lookups(("get_service", {"service_id": "SVC-HR"})),
                                                      say("done")])).start()
    run = AgentRun(ticket, reported, fooled)
    paused = run.start()

    assert paused.classification.result == control.classification.result
    assert paused.classification.missing == control.classification.missing
    assert paused.classification.gate.status == control.classification.gate.status
    assert_no_ai_confirmation(paused.classification.facts)
    # The attack really ran: both suggestions were stored, as unconfirmed AI suggestions for review.
    assert [i.fact_name for i in paused.review_items] == ["malicious_access", "media_coverage"]
    for item in paused.review_items:
        assert getattr(paused.classification.facts, item.fact_name).source == "ai_suggestion"

    answers = {q.fact_name: "no" for q in paused.questions}
    review = [ReviewDecision(fact_name=i.fact_name, action="reject") for i in paused.review_items]
    done = run.resume(confirmed_by="Reviewer A", answers=answers, review=review)
    facts = fact_table(done.classification.facts)
    assert done.classification.result == "not_major"  # from the person's "no", not from the AI's suggestion
    assert {row[2] for row in facts.values() if row[2] is not None} == {"Reviewer A"}
    assert all(row[1] != "ai_suggestion" for row in facts.values())  # rejected suggestions are gone
