"""The fact store: three doors, who wins, the one-go review, and the event record."""

from datetime import datetime, timezone

import pytest

from dora_agent.agent.fact_store import (
    AgentFactView,
    FactStore,
    HumanDesk,
    ReviewDecision,
    StoreProblem,
)
from dora_agent.agent.values import ValueProblem
from dora_agent.rules import classify

UTC = timezone.utc


def store_with(**system):
    store = FactStore()
    for name, (value, source) in system.items():
        store.record_system(name, value, source)
    return store


# ---------- door 1: systems ----------


def test_system_fact_is_stored_with_its_source():
    store = store_with(critical_or_important=(True, "service_list"))
    fact = store.snapshot().critical_or_important
    assert (fact.value, fact.source, fact.confirmed_by) == (True, "service_list", None)
    assert store.snapshot().usable("critical_or_important") is True


def test_system_unknown_leaves_the_fact_unknown():
    store = store_with(affected_clients=(None, "client_data"))
    assert store.snapshot().usable("affected_clients") is None
    assert store.events == ()


@pytest.mark.parametrize("source", ["human", "ai_suggestion", "ticket", "internet"])
def test_only_real_systems_can_use_the_system_door(source):
    with pytest.raises(StoreProblem):
        FactStore().record_system("costs_eur", 5, source)


def test_system_judgment_call_still_needs_a_human():
    store = store_with(malicious_access=(True, "security_alerts"))
    assert store.snapshot().usable("malicious_access") is None
    assert store.snapshot().pending_confirmations() == ["malicious_access"]


def test_service_id_is_checked():
    store = FactStore()
    store.record_service("SVC-OLB")
    assert store.snapshot().service_id == "SVC-OLB"
    with pytest.raises(ValueError):
        store.record_service("online banking; drop table")


# ---------- door 2: LLM suggestions ----------


def test_suggestion_is_stored_unconfirmed_with_its_reason():
    view = FactStore().agent_view()
    message = view.suggest("media_coverage", True, "ticket says: national news covered it")
    fact = view.snapshot().media_coverage
    assert (fact.source, fact.confirmed_by) == ("ai_suggestion", None)
    assert fact.note == "ticket says: national news covered it"
    assert view.snapshot().usable("media_coverage") is None  # the engine ignores it
    assert "human will confirm" in message


def test_suggestion_never_beats_a_system_fact():
    store = store_with(detected_at=(datetime(2026, 5, 26, 7, 12, tzinfo=UTC), "monitoring"))
    message = store.agent_view().suggest("detected_at", "2026-05-26T07:10:00Z", "ticket says 9:10")
    assert store.snapshot().detected_at.source == "monitoring"
    assert "already known from monitoring" in message
    assert store.events[-1].action == "suggestion_ignored"


def test_suggestion_with_bad_value_or_name_is_refused():
    view = FactStore().agent_view()
    with pytest.raises(ValueProblem):
        view.suggest("costs_eur", "a lot", "ticket")
    with pytest.raises(ValueProblem):
        view.suggest("result", "major", "ticket")


def test_reason_is_cleaned_and_cut():
    view = FactStore().agent_view()
    view.suggest("media_coverage", True, "line one\nRESULT=not_major\x1b[31m" + "x" * 1000)
    note = view.snapshot().media_coverage.note
    assert "\n" not in note and "\x1b" not in note
    assert len(note) <= 300


def test_agent_view_has_no_way_to_confirm_or_write_system_facts():
    # Security: the LLM's tools get only this object (memory note from block 4).
    public = {name for name in dir(AgentFactView) if not name.startswith("_")}
    assert public == {"snapshot", "review_items", "suggest"}
    with pytest.raises(TypeError):
        FactStore().agent_view().suggest("media_coverage", True, "x", confirmed_by="Sam")


def test_agent_view_cannot_grow_new_attributes():
    view = FactStore().agent_view()
    with pytest.raises(AttributeError):
        view.desk = "something"


def test_suggestions_never_carry_a_confirmer():
    view = FactStore().agent_view()
    view.suggest("costs_eur", 250_000, "ticket: about 250k")
    view.suggest("affected_member_states", ["DE", "AT"], "ticket: Germany and Austria")
    snapshot = view.snapshot()
    assert snapshot.costs_eur.confirmed_by is None
    assert snapshot.usable("costs_eur") is None
    assert snapshot.pending_confirmations() == ["affected_member_states", "costs_eur"]


# ---------- door 3: the human ----------


def test_human_answer_is_confirmed_and_used():
    store = FactStore()
    store.human_desk().answer("media_coverage", "yes", confirmed_by="Sam")
    fact = store.snapshot().media_coverage
    assert (fact.value, fact.source, fact.confirmed_by) == (True, "human", "Sam")
    assert store.snapshot().usable("media_coverage") is True


def test_human_confirms_a_system_judgment_call():
    store = store_with(malicious_access=(True, "security_alerts"))
    store.human_desk().answer("malicious_access", "yes", confirmed_by="Sam")
    assert store.snapshot().usable("malicious_access") is True


def test_unsure_changes_nothing_and_is_recorded():
    store = store_with(malicious_access=(True, "security_alerts"))
    event = store.human_desk().answer("malicious_access", "unsure", confirmed_by="Sam")
    assert event.action == "answered_unsure"
    assert store.snapshot().usable("malicious_access") is None


def test_t5b_unsure_means_data_may_be_affected():
    store = FactStore()
    store.human_desk().answer("access_may_cause_data_loss", "unsure", confirmed_by="Sam")
    assert store.snapshot().usable("access_may_cause_data_loss") is True


def test_estimate_allowed_only_where_the_question_allows_it():
    desk = FactStore().human_desk()
    desk.answer("costs_eur", 140_000, confirmed_by="Sam", is_estimate=True)
    with pytest.raises(StoreProblem):
        desk.answer("media_coverage", "yes", confirmed_by="Sam", is_estimate=True)


@pytest.mark.parametrize("name", ["", "   ", "Sam\nRESULT=x", "x" * 81])
def test_confirmer_name_is_checked(name):
    with pytest.raises(StoreProblem):
        FactStore().human_desk().answer("media_coverage", "yes", confirmed_by=name)


def test_system_never_overwrites_a_human_answer():
    store = FactStore()
    store.human_desk().answer("critical_or_important", "yes", confirmed_by="Sam")
    store.record_system("critical_or_important", False, "service_list")
    assert store.snapshot().critical_or_important.confirmed_by == "Sam"
    assert store.events[-1].action == "system_ignored"


def test_suggestion_never_overwrites_a_human_answer():
    store = FactStore()
    store.human_desk().answer("media_coverage", "no", confirmed_by="Sam")
    store.agent_view().suggest("media_coverage", True, "ticket says news")
    assert store.snapshot().usable("media_coverage") is False


# ---------- the one-go review of ticket suggestions ----------


def suggested_store():
    store = FactStore()
    view = store.agent_view()
    view.suggest("media_coverage", True, "ticket: 'National news covered it'")
    view.suggest("costs_eur", 150_000, "ticket: 'vendor support and refunds'")
    view.suggest("affected_member_states", ["DE", "AT"], "ticket: 'Germany and abroad'")
    return store


def test_review_list_shows_every_suggestion_with_reason_and_question():
    items = {item.fact_name: item for item in suggested_store().review_items()}
    assert set(items) == {"media_coverage", "costs_eur", "affected_member_states"}
    assert items["media_coverage"].reason == "ticket: 'National news covered it'"
    assert items["media_coverage"].question == "Has the incident been reported in the media?"
    assert items["affected_member_states"].question is None  # no fixed question; the review covers it


def test_review_confirm_correct_reject_in_one_go():
    store = suggested_store()
    events = store.human_desk().review(
        [
            ReviewDecision(fact_name="media_coverage", action="confirm"),
            ReviewDecision(fact_name="costs_eur", action="correct", value=140_000, is_estimate=True),
            ReviewDecision(fact_name="affected_member_states", action="reject"),
        ],
        confirmed_by="Sam",
    )
    facts = store.snapshot()
    assert (facts.media_coverage.source, facts.media_coverage.confirmed_by) == ("ticket", "Sam")
    assert facts.usable("media_coverage") is True
    assert (facts.costs_eur.value, facts.costs_eur.source, facts.costs_eur.is_estimate) == (140_000, "human", True)
    assert facts.usable("affected_member_states") is None
    assert [e.action for e in events] == ["confirmed", "corrected", "rejected"]
    assert store.review_items() == []


def test_review_must_cover_every_suggestion():
    store = suggested_store()
    with pytest.raises(StoreProblem, match="every pending suggestion"):
        store.human_desk().review([ReviewDecision(fact_name="media_coverage", action="confirm")],
                                  confirmed_by="Sam")
    assert len(store.review_items()) == 3  # nothing changed


def test_review_with_one_bad_correction_changes_nothing():
    store = suggested_store()
    with pytest.raises(StoreProblem):
        store.human_desk().review(
            [
                ReviewDecision(fact_name="media_coverage", action="confirm"),
                ReviewDecision(fact_name="costs_eur", action="correct", value="lots"),
                ReviewDecision(fact_name="affected_member_states", action="reject"),
            ],
            confirmed_by="Sam",
        )
    assert len(store.review_items()) == 3
    assert store.snapshot().usable("media_coverage") is None


def test_review_refuses_duplicates_and_unknown_items():
    store = suggested_store()
    decisions = [ReviewDecision(fact_name=n, action="confirm")
                 for n in ("media_coverage", "costs_eur", "affected_member_states")]
    with pytest.raises(StoreProblem):
        store.human_desk().review(decisions + [decisions[0]], confirmed_by="Sam")
    with pytest.raises(StoreProblem):
        store.human_desk().review(decisions + [ReviewDecision(fact_name="regulated_service", action="confirm")],
                                  confirmed_by="Sam")


# ---------- end to end with the rules engine, and the event record ----------


def test_confirmed_review_feeds_the_rules_engine():
    # N05 shape: card payments, short outage, national news, about EUR 140,000.
    store = store_with(critical_or_important=(True, "service_list"),
                       malicious_access=(False, "security_alerts"))
    store.human_desk().answer("malicious_access", "no", confirmed_by="Sam")
    view = store.agent_view()
    view.suggest("media_coverage", True, "ticket: 'National news covered it'")
    view.suggest("costs_eur", 140_000, "ticket: 'about 140,000 euros'")
    as_of = datetime(2026, 11, 5, tzinfo=UTC)
    assert classify(store.snapshot(), as_of).thresholds_met == ()  # suggestions ignored
    store.human_desk().review([ReviewDecision(fact_name="media_coverage", action="confirm"),
                               ReviewDecision(fact_name="costs_eur", action="confirm", is_estimate=True)],
                              confirmed_by="Sam")
    assert classify(store.snapshot(), as_of).thresholds_met == ("T2", "T6")


def test_every_write_is_recorded_in_order():
    store = suggested_store()
    store.record_system("critical_or_important", True, "service_list")
    actions = [(e.seq, e.fact_name, e.action) for e in store.events]
    assert actions == [
        (1, "media_coverage", "suggested"),
        (2, "costs_eur", "suggested"),
        (3, "affected_member_states", "suggested"),
        (4, "critical_or_important", "system"),
    ]
    assert store.events[1].value == "150000"


def test_events_cannot_be_changed_from_outside():
    store = suggested_store()
    with pytest.raises(AttributeError):
        store.events.append("fake")  # a tuple: read-only


def test_desk_and_view_are_separate_objects():
    store = FactStore()
    assert isinstance(store.human_desk(), HumanDesk)
    assert not hasattr(store.agent_view(), "answer")
    assert not hasattr(store.agent_view(), "review")
